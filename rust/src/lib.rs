//! Rust port of `napqes.py` — v6 authenticated EpiCypher.
//!
//! Wire format (binary): nonce(16) || masked_blob || hmac_sha256_tag(32)
//! where masked_blob = varint_blob XOR varint_keystream(key_bytes, nonce, len).
//! String wrapper: base64(binary).
//!
//! All HMAC derivations (noise positions, real-token addends, noise chars,
//! noise-token addends, noise probability, padding codepoints, varint
//! keystream, and auth tag) match the reference Python implementation
//! byte-for-byte, so ciphertexts are interoperable between languages when
//! the same key, nonce, and AAD are used.
//!
//! # Key ordering is a security parameter
//!
//! `[k0, k1, …]` and `[k1, k0, …]` are **distinct** keys that produce
//! non-interoperable ciphertexts.  Callers must preserve element order
//! when storing or transmitting key material.

pub mod self_test;
pub mod kem;
pub mod kem_exchange;
pub mod ot_frame;
pub mod protocols;
pub mod vale;
#[cfg(test)]
mod kat_cross_check;

use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

pub const NONCE_SIZE: usize = 16;
pub const TAG_SIZE: usize = 32;

/// Width of the AAD length prefix in the v8 block-mode domains `0x03`
/// (auth tag) and `0x0A` (synthetic nonce).
const AAD_LEN_WIDTH_V8: usize = 8;
/// Legacy v7 AAD length-prefix width, kept for byte compatibility.
const AAD_LEN_WIDTH_V7: usize = 4;

// ─── CRNG conditional self-test ──────────────────────────────────────────────

static PREV_NONCE: Mutex<Option<[u8; NONCE_SIZE]>> = Mutex::new(None);

/// Generate a cryptographically random 16-byte nonce, verifying it differs
/// from the previous one (FIPS 140-3 continuous RNG test, SP 800-140B §4.9.2).
fn generate_nonce_with_crng_check() -> Result<[u8; NONCE_SIZE], String> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut prev = PREV_NONCE.lock().map_err(|_| "CRNG mutex poisoned".to_string())?;
    if let Some(prev_nonce) = *prev {
        if ct_eq_bytes(&nonce, &prev_nonce) {
            return Err("CRNG failure: consecutive identical nonces — DRBG may be compromised".into());
        }
    }
    *prev = Some(nonce);
    Ok(nonce)
}

// ─── Primes ──────────────────────────────────────────────────────────────────

/// Lower bound of the normative prime interval
/// `P = [MIN_KEY_PRIME, MAX_KEY_PRIME]`.
pub const MIN_KEY_PRIME: u64 = 1_000_000;

/// Upper bound of the normative prime interval, per
/// `docs/napseq-eprint-v3.tex` §Notation. `P` contains exactly 579_947
/// primes (verified by sieve), giving `P(579_947, 10) = 2^191.46` ordered
/// 10-tuples (`2^95.73` post-Grover).
///
/// This bound constrains key *generation* only. Validation and decryption
/// accept any prime `>= MIN_KEY_PRIME`, so keys generated before this bound
/// was tightened remain usable. Matches `napqes.py::MAX_KEY_PRIME` and
/// `C/napqes.h::NAPQES_MAX_KEY_PRIME`.
pub const MAX_KEY_PRIME: u64 = 9_900_000;

pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    let mut i: u64 = 3;
    while i.saturating_mul(i) <= n {
        if n % i == 0 {
            return false;
        }
        i += 2;
    }
    true
}

/// Generate `count` distinct primes drawn uniformly from `[min_val, max_val]`.
pub fn generate_prime_numbers(count: usize, min_val: u64, max_val: u64) -> Vec<u64> {
    assert!(max_val > min_val);
    let mut rng = rand::thread_rng();
    let span = max_val - min_val + 1;
    let max_attempts = span.saturating_mul(4);
    let mut primes: Vec<u64> = Vec::with_capacity(count);
    let mut attempts: u64 = 0;
    while primes.len() < count && attempts < max_attempts {
        let num = min_val + (rng.next_u64() % span);
        if is_prime(num) && !primes.contains(&num) {
            primes.push(num);
        }
        attempts += 1;
    }
    if primes.len() < count {
        panic!(
            "Could not find {} distinct primes in [{}, {}] — widen the range.",
            count, min_val, max_val
        );
    }
    primes
}

// ─── HMAC helpers ────────────────────────────────────────────────────────────

fn key_bytes(key: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() * 5);
    for &k in key {
        let b = k.to_be_bytes(); // 8 bytes
        out.extend_from_slice(&b[3..8]); // low 5 bytes, big-endian
    }
    out
}

fn hmac_digest(kb: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(kb).expect("hmac");
    mac.update(data);
    let r = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fn be5(n: u64) -> [u8; 5] {
    let b = n.to_be_bytes();
    let mut out = [0u8; 5];
    out.copy_from_slice(&b[3..8]);
    out
}

fn u64_from_be8(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_be_bytes(a)
}

/// Big-endian length prefix of `width` bytes (`width <= 8`).
fn be_len_prefix(n: usize, width: usize) -> Vec<u8> {
    (n as u64).to_be_bytes()[8 - width..].to_vec()
}

fn u32_from_be4(b: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[..4]);
    u32::from_be_bytes(a)
}

const TWO_POW_64: f64 = 18446744073709551616.0_f64;

fn is_noise_pos(kb: &[u8], nonce: &[u8], ct_pos: u64, noise_p: f64) -> bool {
    let mut buf = Vec::with_capacity(1 + nonce.len() + 5);
    buf.push(0x00);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&be5(ct_pos));
    let d = hmac_digest(kb, &buf);
    let v = u64_from_be8(&d[..8]) as f64 / TWO_POW_64;
    v < noise_p
}

fn derive_addend(kb: &[u8], nonce: &[u8], real_idx: u64, key_element: u64) -> u64 {
    let mut buf = Vec::with_capacity(1 + nonce.len() + 5);
    buf.push(0x01);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&be5(real_idx));
    let d = hmac_digest(kb, &buf);
    (u32_from_be4(&d[..4]) as u64 % (key_element - 1)) + 1
}

fn derive_noise_char(kb: &[u8], nonce: &[u8], ct_pos: u64) -> u64 {
    let mut buf = Vec::with_capacity(1 + nonce.len() + 5);
    buf.push(0x04);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&be5(ct_pos));
    let d = hmac_digest(kb, &buf);
    (u32_from_be4(&d[..4]) as u64 % 96) + 32
}

fn derive_noise_token_addend(kb: &[u8], nonce: &[u8], ct_pos: u64, key_element: u64) -> u64 {
    let mut buf = Vec::with_capacity(1 + nonce.len() + 5);
    buf.push(0x05);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&be5(ct_pos));
    let d = hmac_digest(kb, &buf);
    (u32_from_be4(&d[..4]) as u64 % (key_element - 1)) + 1
}

fn derive_noise_p(kb: &[u8], nonce: &[u8]) -> f64 {
    let mut buf = Vec::with_capacity(1 + nonce.len());
    buf.push(0x02);
    buf.extend_from_slice(nonce);
    let d = hmac_digest(kb, &buf);
    let t = u64_from_be8(&d[..8]) as f64 / TWO_POW_64;
    0.75 + t * (0.99 - 0.75)
}

/// Endpoints of the v8 noise-threshold interval, as fixed-width 64-bit
/// integers (docs/napseq-eprint-v3.tex, Section "Noise Probability").
const THETA_MIN: u64 = ((75u128 << 64) / 100) as u64;
const THETA_MAX: u64 = ((99u128 << 64) / 100) as u64;

/// Reject a prime tuple that is empty, composite, undersized or repeating.
///
/// The correctness argument recovers `c` from `c * k + a` by exact division,
/// which needs `gcd(a, k) = 1` for every addend `a` in `[1, k - 1]` -- true
/// only when `k` is prime. Called from both v8 entry points so that a caller
/// supplying a malformed key gets an error here rather than a silently
/// undecryptable ciphertext, matching `_validate_key` in the Python port.
fn validate_key(key: &[u64]) -> Result<(), String> {
    if key.is_empty() {
        return Err("Key must be a non-empty list of primes.".into());
    }
    for (i, &k) in key.iter().enumerate() {
        if !is_prime(k) {
            return Err(format!("Key element at index {} ({}) is not prime.", i, k));
        }
        if k < MIN_KEY_PRIME {
            return Err(format!(
                "Key element at index {} ({}) is below the minimum of {}.",
                i, k, MIN_KEY_PRIME
            ));
        }
        if key[..i].contains(&k) {
            return Err(format!(
                "Key element {} at index {} is a duplicate; all elements must be distinct.",
                k, i
            ));
        }
    }
    Ok(())
}

/// Return the v8 noise threshold `theta(N)`.
///
/// The integer counterpart of [`derive_noise_p`], and the normative form for
/// the v8 block format:
///
/// ```text
/// theta(N) = theta_min + floor(tau * (theta_max - theta_min) / 2^64)
/// ```
///
/// Division by `2^64` is exactly the high half of the 128-bit product, so the
/// derivation carries no rounding mode, no excess precision and no compiler
/// licence to contract the expression -- the three defects that made the
/// IEEE-754 form only conditionally reproducible across languages and
/// platforms. The legacy v7 path keeps [`derive_noise_p`] and stays
/// byte-compatible.
fn derive_noise_threshold_v8(kb: &[u8], nonce: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(1 + nonce.len());
    buf.push(0x02);
    buf.extend_from_slice(nonce);
    let d = hmac_digest(kb, &buf);
    let tau = u64_from_be8(&d[..8]) as u128;
    THETA_MIN + ((tau * (THETA_MAX - THETA_MIN) as u128) >> 64) as u64
}

/// Integer-arithmetic counterpart of [`is_noise_pos`] for v8.
fn is_noise_pos_v8(kb: &[u8], nonce: &[u8], ct_pos: u64, theta: u64) -> bool {
    let mut buf = Vec::with_capacity(1 + nonce.len() + 5);
    buf.push(0x00);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&be5(ct_pos));
    let d = hmac_digest(kb, &buf);
    u64_from_be8(&d[..8]) < theta
}

// CVF2 fix: unified domain-first layout `d || N || ctx` shared by every
// domain in the schedule, with `ctx = be(len(aad)) || aad || masked_blob`.
// `payload` is `nonce || masked_blob`; it is split here so the nonce
// occupies the fixed byte 1..=16 offset used by every other domain.
//
// `aad_len_width` is 8 for v8 block mode (third-round audit finding CVF1)
// and 4 for the legacy v7 format, which stays byte-compatible.
fn compute_auth_tag(kb: &[u8], aad: &[u8], payload: &[u8], aad_len_width: usize) -> [u8; 32] {
    let (nonce, masked_blob) = payload.split_at(NONCE_SIZE);
    let mut buf =
        Vec::with_capacity(1 + nonce.len() + aad_len_width + aad.len() + masked_blob.len());
    buf.push(0x03);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&be_len_prefix(aad.len(), aad_len_width));
    buf.extend_from_slice(aad);
    buf.extend_from_slice(masked_blob);
    hmac_digest(kb, &buf)
}

// ─── Padding ─────────────────────────────────────────────────────────────────

/// Exponent range of the reachable block sizes `{2^4, ..., 2^16}`.
///
/// Every padding profile takes values in this same 13-element set, so the set
/// of legal token counts is profile-independent and a decryptor never needs to
/// know which profile the sender used.
pub const PAD_MIN_EXP: u32 = 4;
pub const PAD_MAX_EXP: u32 = 16;

/// The map from plaintext codepoint count to padded block size `B`
/// (docs/napseq-eprint-v3.tex, Section "Padding Profiles").
///
/// This map is the *only* source of NAPQES's length-hiding property
/// (Theorem `lh-ind-cpa`); the token expansion factor contributes none, since
/// `|C| = 48 + 160(B+2)` is a public injective function of `B`
/// (Proposition `expansion-neutral`).
///
/// The profile is a sender-side deployment parameter agreed out of band. It is
/// never transmitted and [`decrypt_bytes_v8`] is profile-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadProfile {
    /// Default: smallest power of two strictly above `n`, floored at 16.
    /// 13 reachable sizes, leaking at most `log2(13) ~= 3.70` bits of length.
    Bucket,
    /// [`PadProfile::Bucket`] thinned by a stride `g` dividing 12, leaving
    /// `12 / g + 1` reachable sizes.
    Coarse(u32),
    /// Every message padded to the single size `F`, leaking exactly zero bits.
    /// Requires `n < F`.
    Frame(u32),
}

fn bit_length(n: usize) -> u32 {
    usize::BITS - n.leading_zeros()
}

/// Padded block size under the default profile. Total for every `n`, which is
/// why the v7 padding path needs no error branch.
fn bucket_block_size(n: usize) -> usize {
    1usize << bit_length(n).max(PAD_MIN_EXP)
}

impl PadProfile {
    /// Padded block size `B` for an `n`-codepoint message under this profile.
    pub fn block_size(self, n: usize) -> Result<usize, String> {
        let e = bit_length(n).max(PAD_MIN_EXP);
        match self {
            PadProfile::Bucket => Ok(bucket_block_size(n)),
            PadProfile::Coarse(g) => {
                let span = PAD_MAX_EXP - PAD_MIN_EXP;
                if g == 0 || span % g != 0 {
                    return Err(format!(
                        "coarse stride g={} must divide {}.",
                        g, span
                    ));
                }
                let steps = (e - PAD_MIN_EXP + g - 1) / g; // ceil division
                Ok(1usize << (PAD_MIN_EXP + g * steps))
            }
            PadProfile::Frame(f) => {
                if !f.is_power_of_two()
                    || f.trailing_zeros() < PAD_MIN_EXP
                    || f.trailing_zeros() > PAD_MAX_EXP
                {
                    return Err(format!(
                        "frame size F={} must be a power of two in [{}, {}].",
                        f,
                        1u32 << PAD_MIN_EXP,
                        1u32 << PAD_MAX_EXP
                    ));
                }
                if n >= f as usize {
                    return Err(format!(
                        "frame({}) profile admits messages of at most {} \
                         codepoints; got {}. Use a larger frame.",
                        f,
                        f - 1,
                        n
                    ));
                }
                Ok(f as usize)
            }
        }
    }
}

/// HMAC-derived padding — domain byte 0x06 (matches Python `_pad_message`).
/// Each padding codepoint is in [32, 126], matching the reference exactly.
fn pad_message(msg: &[u32], kb: &[u8], nonce: &[u8]) -> Vec<u32> {
    let n = msg.len();
    assert!(n <= 0xFFFF, "Message too long for 2-byte length prefix");
    pad_to_block(msg, kb, nonce, bucket_block_size(n))
}

/// Padding body shared by every profile; `block_size` must exceed `msg.len()`,
/// which [`PadProfile::block_size`] guarantees for the profiles it accepts.
fn pad_to_block(msg: &[u32], kb: &[u8], nonce: &[u8], block_size: usize) -> Vec<u32> {
    let n = msg.len();
    debug_assert!(block_size > n, "padding block must exceed the message");
    let pad_len = block_size - n;
    let mut out = Vec::with_capacity(2 + block_size);
    out.push(((n >> 8) & 0xFF) as u32);
    out.push((n & 0xFF) as u32);
    out.extend_from_slice(msg);
    for i in 0..pad_len {
        let mut buf = Vec::with_capacity(1 + nonce.len() + 4);
        buf.push(0x06);
        buf.extend_from_slice(nonce);
        buf.extend_from_slice(&(i as u32).to_be_bytes());
        let d = hmac_digest(kb, &buf);
        out.push((u32_from_be4(&d[..4]) % 95) + 32); // [32, 126]
    }
    out
}

/// HMAC-CTR keystream for masking the varint blob — domain byte 0x07.
///
/// Each 32-byte block is `HMAC(key_bytes, 0x07 || nonce || uint32_be(block))`.  
/// XOR-masking the raw LEB128 blob eliminates the 3:1 MSB continuation-bit
/// bias that otherwise causes systematic NIST SP 800-22 failures.
fn varint_keystream(kb: &[u8], nonce: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut block: u32 = 0;
    while out.len() < length {
        let mut buf = Vec::with_capacity(1 + nonce.len() + 4);
        buf.push(0x07);
        buf.extend_from_slice(nonce);
        buf.extend_from_slice(&block.to_be_bytes());
        out.extend_from_slice(&hmac_digest(kb, &buf));
        block += 1;
    }
    out.truncate(length);
    out
}

/// Recover the original message from a padded codepoint buffer.
///
/// V3-CVF8: the 2-codepoint big-endian length prefix `n` is attacker-chosen
/// in the sense that it is recovered from the decrypted blob, so it must be
/// validated against the buffer actually present: a well-formed padded buffer
/// always satisfies `2 + n <= padded.len()`. Slicing without this check
/// panics on an out-of-range index. Matches `napqes.py::_unpad_message` and
/// the `2 + orig_n > padded_n` guard in `C/napqes.c`.
fn unpad_message(padded: &[u32]) -> Result<Vec<u32>, String> {
    if padded.len() < 2 {
        return Err("Padded message too short to contain length prefix.".into());
    }
    let n = ((padded[0] as usize) << 8) | (padded[1] as usize);
    if 2 + n > padded.len() {
        return Err(format!(
            "Length prefix ({}) exceeds available data ({} codepoints).",
            n,
            padded.len() - 2
        ));
    }
    Ok(padded[2..2 + n].to_vec())
}

// ─── Core encrypt / decrypt ──────────────────────────────────────────────────

pub fn encrypt(message: &[u32], key: &[u64]) -> ([u8; NONCE_SIZE], Vec<u64>) {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, &nonce);
    let padded = pad_message(message, &kb, &nonce);
    let kk = key.len() as u64;

    let mut cypher: Vec<u64> = Vec::new();
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;

    for &c in &padded {
        loop {
            if is_noise_pos(&kb, &nonce, ct_pos, noise_p) {
                let k = key[(real_idx % kk) as usize];
                let noise_c = derive_noise_char(&kb, &nonce, ct_pos);
                let noise_add = derive_noise_token_addend(&kb, &nonce, ct_pos, k);
                cypher.push(noise_c * k + noise_add);
                ct_pos += 1;
            } else {
                let k = key[(real_idx % kk) as usize];
                let addend = derive_addend(&kb, &nonce, real_idx, k);
                cypher.push(c as u64 * k + addend);
                ct_pos += 1;
                real_idx += 1;
                break;
            }
        }
    }
    (nonce, cypher)
}

/// Shared core of [`decrypt`] and the v8 (`decrypt_bytes_v8`) path, taking
/// the domain-derivation HMAC key `kb` explicitly instead of computing it
/// from `key` internally. v7 passes `kb = key_bytes(key)`; v8 passes the
/// independently-sampled `sk` (see "V8 key schedule" below, CVF8/CVF13 fix).
fn decrypt_core(nonce: &[u8], cypher: &[u64], key: &[u64], kb: &[u8]) -> Vec<u32> {
    let noise_p = derive_noise_p(kb, nonce);
    let kk = key.len() as u64;
    let mut padded: Vec<u32> = Vec::new();
    let mut real_idx: u64 = 0;
    for (ct_pos, &token) in cypher.iter().enumerate() {
        if !is_noise_pos(kb, nonce, ct_pos as u64, noise_p) {
            let k = key[(real_idx % kk) as usize];
            let addend = derive_addend(kb, nonce, real_idx, k);
            padded.push(((token - addend) / k) as u32);
            real_idx += 1;
        }
    }
    // v7 low-level API: signature is `-> Vec<u32>`, so a malformed padded
    // buffer panics here exactly as it did before V3-CVF8. The v8 path
    // (`decrypt_core_v8`) returns the error instead.
    unpad_message(&padded).expect("v7 decrypt: malformed padded buffer")
}

pub fn decrypt(nonce: &[u8], cypher: &[u64], key: &[u64]) -> Vec<u32> {
    let kb = key_bytes(key);
    decrypt_core(nonce, cypher, key, &kb)
}

/// v8-only decrypt core: bounded, `MAX_NOISE_RUN`-capped, lock-step with
/// `encrypt_bytes_v8`'s emission loop, and aware of the fixed per-bucket
/// token ceiling (V2-CVF2 fix). Unlike the shared, v7-only [`decrypt_core`]
/// (which classifies every token position independently and consumes the
/// whole `cypher` slice), this recovers the real-token count directly from
/// `cypher.len()` up front — since `encrypt_bytes_v8` always pads to
/// exactly `real_count * (MAX_NOISE_RUN + 1)` tokens — and stops as soon as
/// that many real tokens have been extracted, discarding any trailing
/// filler tokens rather than feeding them through the noise/real decision.
fn decrypt_core_v8(nonce: &[u8], cypher: &[u64], key: &[u64], kb: &[u8]) -> Result<Vec<u32>, String> {
    let ceiling_unit = MAX_NOISE_RUN + 1;
    let n_tokens = cypher.len() as u64;
    if n_tokens % ceiling_unit != 0 {
        return Err(
            "Malformed v8 ciphertext: token count is not a multiple of the padding ceiling; \
             expected exactly real_token_count * (MAX_NOISE_RUN + 1) tokens.".into(),
        );
    }
    let real_count = n_tokens / ceiling_unit;

    // V3-CVF8: `real_count` must be `B + 2` for one of the 13 reachable
    // padded block sizes `B` in `{2^PAD_MIN_EXP, ..., 2^PAD_MAX_EXP}`.
    // Divisibility by `ceiling_unit` alone does not imply this. Reached only
    // after the tag has verified (see `decrypt_bytes_v8`), so this rejects a
    // malformed ciphertext, never an unauthenticated attacker input.
    let legal_real_count = real_count
        .checked_sub(2)
        .map(|b| {
            b.is_power_of_two()
                && b.trailing_zeros() >= PAD_MIN_EXP
                && b.trailing_zeros() <= PAD_MAX_EXP
        })
        .unwrap_or(false);
    if !legal_real_count {
        return Err(format!(
            "Malformed v8 ciphertext: real-token count {} is not B + 2 for any \
             reachable padded block size B in [{}, {}].",
            real_count,
            1u64 << PAD_MIN_EXP,
            1u64 << PAD_MAX_EXP
        ));
    }

    let noise_theta = derive_noise_threshold_v8(kb, nonce);
    let kk = key.len() as u64;
    let mut padded: Vec<u32> = Vec::new();
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    while real_idx < real_count {
        let mut noise_run: u64 = 0;
        while noise_run < MAX_NOISE_RUN
            && ct_pos < n_tokens
            && is_noise_pos_v8(kb, nonce, ct_pos, noise_theta)
        {
            ct_pos += 1;
            noise_run += 1;
        }
        if ct_pos >= n_tokens {
            return Err(
                "Truncated v8 ciphertext: token stream ended mid noise-run before the \
                 expected real token.".into(),
            );
        }
        let k = key[(real_idx % kk) as usize];
        let addend = derive_addend(kb, nonce, real_idx, k);
        let token = cypher[ct_pos as usize];
        // A genuine real token is exactly c * k + addend with addend in
        // [1, k - 1]. Checking that explicitly, rather than subtracting and
        // dividing, keeps the three ports in lock-step: the bare subtraction
        // panics here in debug builds and wraps in release builds and in C.
        if token < addend || (token - addend) % k != 0 {
            return Err(format!(
                "Malformed v8 ciphertext: token at position {} is not of the form \
                 codepoint * k + addend for key element {}.",
                ct_pos, k
            ));
        }
        let cp = (token - addend) / k;
        if cp > 0x10FFFF || char::from_u32(cp as u32).is_none() {
            return Err(format!(
                "Malformed v8 ciphertext: recovered value {} at position {} is not a \
                 Unicode scalar value.",
                cp, ct_pos
            ));
        }
        padded.push(cp as u32);
        ct_pos += 1;
        real_idx += 1;
    }
    unpad_message(&padded)
}

// ─── Constant-time tag comparison ────────────────────────────────────────────

/// Compare two equal-length byte slices in constant time.
///
/// Three properties together prevent LLVM from generating an early-exit loop:
///
/// 1. `#[inline(never)]` — the function is opaque to the caller; LLVM cannot
///    sink the caller's branch into this function body.
/// 2. `read_volatile` on every byte — volatile reads cannot be eliminated or
///    reordered, so all bytes are unconditionally loaded.
/// 3. `write_volatile` to `diff` after every XOR — the store is an observable
///    side-effect; skipping any loop iteration would change it, which LLVM is
///    forbidden to do.  This forces every iteration to run, preventing LLVM
///    from restructuring the loop into a `cmpb + jne` early-exit sequence.
///
/// The resulting assembly is a fixed-count loop: `jne` branches only on the
/// loop counter (always 32 iterations), never on the tag data.
#[inline(never)]
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        unsafe {
            diff |= std::ptr::read_volatile(x) ^ std::ptr::read_volatile(y);
            // The volatile write forces this accumulated value to be
            // materialised every iteration; LLVM cannot skip iterations.
            std::ptr::write_volatile(&mut diff, diff);
        }
    }
    diff == 0
}

// ─── Base-128 varint (retired for new ciphertexts — see CVF1 fix below) ──────
// The variable-length LEB128 encoding gave each token a byte-length that grew
// with its magnitude (token = codepoint * key_element + addend), so the
// serialised blob length leaked plaintext content even between messages of
// equal padded length, breaking the IND-CPA hiding argument (audit finding
// CVF1). `encrypt_bytes`/`encrypt_raw` now use `fixed_encode_tokens` instead.
// The encoder is removed since nothing in this crate produces LEB128
// ciphertexts anymore; the decoder is kept only for potential legacy-format
// tooling and is currently unused by the public API.

#[allow(dead_code)]
fn b128_decode_tokens(data: &[u8]) -> Result<Vec<u64>, String> {
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if i >= data.len() {
                return Err("varint: truncated encoding".into());
            }
            if shift >= 64 {
                return Err("varint: shift overflow (overlong encoding)".into());
            }
            let b = data[i];
            i += 1;
            value |= ((b & 0x7F) as u64) << shift;
            if (b & 0x80) == 0 {
                break;
            }
            shift += 7;
        }
        tokens.push(value);
    }
    Ok(tokens)
}

// ─── Fixed-width token encoding (v7 — CVF1 fix) ──────────────────────────────
// Every token is serialised as a constant-width (`TOKEN_WIDTH` bytes),
// big-endian unsigned field, so the encoded blob length is exactly
// `tokens.len() * TOKEN_WIDTH` — a function of the *number* of tokens only,
// never of their magnitude. Token count is itself a function of the padded
// codepoint count and the HMAC-derived (content-independent) noise
// schedule, so masked_blob length no longer depends on plaintext content.
// See docs/CAVEATS.md (CVF1) and SPEC.md for the full rationale.

/// Width in bytes of each fixed-width token field, sized to comfortably hold
/// the largest realistic token (codepoint * key_element + addend).
const TOKEN_WIDTH: usize = 8;

fn fixed_encode_tokens(tokens: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tokens.len() * TOKEN_WIDTH);
    for &n in tokens {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out
}

fn fixed_decode_tokens(data: &[u8]) -> Result<Vec<u64>, String> {
    if data.len() % TOKEN_WIDTH != 0 {
        return Err(format!(
            "fixed-width token blob length ({}) is not a multiple of {}",
            data.len(),
            TOKEN_WIDTH
        ));
    }
    let mut tokens = Vec::with_capacity(data.len() / TOKEN_WIDTH);
    for chunk in data.chunks_exact(TOKEN_WIDTH) {
        let mut buf = [0u8; TOKEN_WIDTH];
        buf.copy_from_slice(chunk);
        tokens.push(u64::from_be_bytes(buf));
    }
    Ok(tokens)
}

// ─── Binary / string wrappers (v7 authenticated — CVF1 fix) ──────────────────


pub fn encrypt_bytes(message: &str, key: &[u64], aad: &[u8]) -> Result<Vec<u8>, String> {
    if message.is_empty() {
        return Ok(Vec::new());
    }
    let nonce = generate_nonce_with_crng_check()?;
    let codepoints: Vec<u32> = message.chars().map(|c| c as u32).collect();
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, &nonce);
    let padded = pad_message(&codepoints, &kb, &nonce);
    let kk = key.len() as u64;
    let mut cypher: Vec<u64> = Vec::new();
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    for &c in &padded {
        loop {
            if is_noise_pos(&kb, &nonce, ct_pos, noise_p) {
                let k = key[(real_idx % kk) as usize];
                let nc = derive_noise_char(&kb, &nonce, ct_pos);
                let na = derive_noise_token_addend(&kb, &nonce, ct_pos, k);
                cypher.push(nc * k + na);
                ct_pos += 1;
            } else {
                let k = key[(real_idx % kk) as usize];
                let addend = derive_addend(&kb, &nonce, real_idx, k);
                cypher.push(c as u64 * k + addend);
                ct_pos += 1;
                real_idx += 1;
                break;
            }
        }
    }
    let blob = fixed_encode_tokens(&cypher);
    let ks = varint_keystream(&kb, &nonce, blob.len());
    let masked: Vec<u8> = blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mut payload = Vec::with_capacity(NONCE_SIZE + masked.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&masked);
    let tag = compute_auth_tag(&kb, aad, &payload, AAD_LEN_WIDTH_V7);
    payload.extend_from_slice(&tag);
    Ok(payload)
}

/// Encrypt with a caller-supplied nonce — for deterministic KAT verification
/// and the FIPS power-on self-test (`self_test::run_power_on_self_tests`)
/// only.
///
/// **Not part of the public API (CVF3 fix, 2026-07-06).** Explicit,
/// caller-chosen nonces are a key-recovery hazard for NAPQES: every internal
/// value (noise positions, addends, keystream) is a deterministic function
/// of `(key, nonce)` alone, so a reused nonce is catastrophic, not merely
/// confidentiality-losing (see `docs/CAVEATS.md`, CVF3). This function is
/// therefore `pub(crate)` — reachable only from the self-test module and the
/// in-crate KAT cross-check (`kat_cross_check`), never from external
/// consumers of this crate. Production callers must use [`encrypt_bytes`],
/// which always generates a fresh CSPRNG nonce internally.
pub(crate) fn encrypt_bytes_with_nonce(
    message: &str,
    key: &[u64],
    nonce: [u8; NONCE_SIZE],
    aad: &[u8],
) -> Vec<u8> {
    if message.is_empty() {
        return Vec::new();
    }
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, &nonce);
    let codepoints: Vec<u32> = message.chars().map(|c| c as u32).collect();
    let padded = pad_message(&codepoints, &kb, &nonce);
    let kk = key.len() as u64;
    let mut cypher: Vec<u64> = Vec::new();
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    for &c in &padded {
        loop {
            if is_noise_pos(&kb, &nonce, ct_pos, noise_p) {
                let k = key[(real_idx % kk) as usize];
                let nc = derive_noise_char(&kb, &nonce, ct_pos);
                let na = derive_noise_token_addend(&kb, &nonce, ct_pos, k);
                cypher.push(nc * k + na);
                ct_pos += 1;
            } else {
                let k = key[(real_idx % kk) as usize];
                let addend = derive_addend(&kb, &nonce, real_idx, k);
                cypher.push(c as u64 * k + addend);
                ct_pos += 1;
                real_idx += 1;
                break;
            }
        }
    }
    let blob = fixed_encode_tokens(&cypher);
    let ks = varint_keystream(&kb, &nonce, blob.len());
    let masked: Vec<u8> = blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mut payload = Vec::with_capacity(NONCE_SIZE + masked.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&masked);
    let tag = compute_auth_tag(&kb, aad, &payload, AAD_LEN_WIDTH_V7);
    payload.extend_from_slice(&tag);
    payload
}

pub fn decrypt_bytes(ciphertext: &[u8], key: &[u64], aad: &[u8]) -> Result<String, String> {
    if ciphertext.is_empty() {
        return Ok(String::new());
    }
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(format!(
            "Ciphertext too short: {} bytes; header+tag require at least {}.",
            ciphertext.len(),
            NONCE_SIZE + TAG_SIZE
        ));
    }
    let kb = key_bytes(key);
    let split = ciphertext.len() - TAG_SIZE;
    let payload = &ciphertext[..split];
    let recv_tag = &ciphertext[split..];
    let calc_tag = compute_auth_tag(&kb, aad, payload, AAD_LEN_WIDTH_V7);
    if !ct_eq_bytes(recv_tag, calc_tag.as_ref()) {
        return Err("Authentication failed: invalid HMAC tag.".into());
    }
    let nonce = &payload[..NONCE_SIZE];
    let masked = &payload[NONCE_SIZE..];
    let ks = varint_keystream(&kb, nonce, masked.len());
    let blob: Vec<u8> = masked.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let tokens = fixed_decode_tokens(&blob)
        .map_err(|e| format!("varint decode error: {}", e))?;
    let codepoints = decrypt(nonce, &tokens, key);
    let s: String = codepoints.into_iter().filter_map(char::from_u32).collect();
    Ok(s)
}

pub fn encrypt_str(message: &str, key: &[u64], aad: &[u8]) -> Result<String, String> {
    if message.is_empty() {
        return Ok(String::new());
    }
    Ok(STANDARD.encode(encrypt_bytes(message, key, aad)?))
}

pub fn decrypt_str(cypher: &str, key: &[u64], aad: &[u8]) -> Result<String, String> {
    if cypher.is_empty() {
        return Ok(String::new());
    }
    let bytes = STANDARD
        .decode(cypher.as_bytes())
        .map_err(|e| format!("base64 decode error: {}", e))?;
    decrypt_bytes(&bytes, key, aad)
}

// ─── Raw-bytes encrypt / decrypt (for binary PDU data) ───────────────────────

/// Encrypt arbitrary binary data.
///
/// Each byte is treated as a codepoint in [0, 255].  Produces the same
/// NAPQES v6 wire format as `encrypt_bytes`, with the provided AAD bound
/// into the authentication tag.  Intended for OT PDU framing where the
/// payload is not valid UTF-8 text.
pub fn encrypt_raw(data: &[u8], key: &[u64], aad: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let nonce = generate_nonce_with_crng_check()?;
    let codepoints: Vec<u32> = data.iter().map(|&b| b as u32).collect();
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, &nonce);
    let padded = pad_message(&codepoints, &kb, &nonce);
    let kk = key.len() as u64;
    let mut cypher: Vec<u64> = Vec::new();
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    for &c in &padded {
        loop {
            if is_noise_pos(&kb, &nonce, ct_pos, noise_p) {
                let k = key[(real_idx % kk) as usize];
                let nc = derive_noise_char(&kb, &nonce, ct_pos);
                let na = derive_noise_token_addend(&kb, &nonce, ct_pos, k);
                cypher.push(nc * k + na);
                ct_pos += 1;
            } else {
                let k = key[(real_idx % kk) as usize];
                let addend = derive_addend(&kb, &nonce, real_idx, k);
                cypher.push(c as u64 * k + addend);
                ct_pos += 1;
                real_idx += 1;
                break;
            }
        }
    }
    let blob = fixed_encode_tokens(&cypher);
    let ks = varint_keystream(&kb, &nonce, blob.len());
    let masked: Vec<u8> = blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mut payload = Vec::with_capacity(NONCE_SIZE + masked.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&masked);
    let tag = compute_auth_tag(&kb, aad, &payload, AAD_LEN_WIDTH_V7);
    payload.extend_from_slice(&tag);
    Ok(payload)
}

/// Decrypt binary data previously encrypted with [`encrypt_raw`].
///
/// Verifies the HMAC tag (constant-time) before decrypting.  Returns
/// `Err` on authentication failure — the caller must never use the
/// ciphertext for any purpose if this returns an error.
pub fn decrypt_raw(ciphertext: &[u8], key: &[u64], aad: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(format!(
            "Ciphertext too short: {} bytes; header+tag require at least {}.",
            ciphertext.len(),
            NONCE_SIZE + TAG_SIZE
        ));
    }
    let kb = key_bytes(key);
    let split = ciphertext.len() - TAG_SIZE;
    let payload = &ciphertext[..split];
    let recv_tag = &ciphertext[split..];
    let calc_tag = compute_auth_tag(&kb, aad, payload, AAD_LEN_WIDTH_V7);
    if !ct_eq_bytes(recv_tag, calc_tag.as_ref()) {
        return Err("Authentication failed: invalid HMAC tag.".into());
    }
    let nonce = &payload[..NONCE_SIZE];
    let masked = &payload[NONCE_SIZE..];
    let ks = varint_keystream(&kb, nonce, masked.len());
    let blob: Vec<u8> = masked.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let tokens = fixed_decode_tokens(&blob)
        .map_err(|e| format!("varint decode error: {}", e))?;
    let codepoints = decrypt(nonce, &tokens, key);
    Ok(codepoints.into_iter().map(|c| (c & 0xFF) as u8).collect())
}

// ─── V8 key schedule + synthetic nonce (CVF3 / CVF8 / CVF13 fix) ────────────
//
// v7 (and every earlier wire format) keys *every* domain derivation with
// `kb = key_bytes(primes)` — the serialisation of the same prime tuple used
// for the token arithmetic (`c*k+a`) — and draws the nonce from a CSPRNG
// independent of the message. Three audit findings trace back to that one
// design choice:
//
//   - **CVF3.** Because every derived value (noise positions, addends,
//     keystream) is a deterministic function of `(kb, N)` alone, a repeated
//     nonce reproduces an identical keystream and identical addends; combined
//     with the exact affine token map `c ↦ c*k+a`, two ciphertexts sharing a
//     nonce let an attacker solve `k = (t1-t2)/(c1-c2)` from as little as one
//     known plaintext codepoint at the same position in each message —
//     catastrophic key recovery, not merely a confidentiality loss. A random
//     128-bit nonce only makes *accidental* collision a ~2^64 birthday event;
//     it does nothing to prevent DRBG failure, VM/container snapshot replay,
//     or any other reuse route.
//   - **CVF8.** `key_bytes(primes)` has only `H_inf(k) ≈ log2(|P|!/(|P|-K)!)`
//     bits of min-entropy — a structured, non-uniform HMAC key, which is a
//     different (and non-standard) hypothesis from the textbook uniform-key
//     HMAC-SHA256 PRF assumption every theorem bound otherwise cites.
//   - **CVF13.** The IND-CPA/INT-CTXT reductions must simulate the token
//     arithmetic (which requires knowing the actual primes) while forwarding
//     every domain-derivation HMAC call to an external PRF oracle keyed by a
//     hidden secret. Because that hidden secret is `key_bytes(primes)` — the
//     very same primes the reduction must already know to run the
//     arithmetic — the reduction implicitly already knows the "hidden"
//     oracle key, and the PRF hop it is supposed to justify is vacuous.
//
// The v8 key schedule closes all three by decoupling the two roles the prime
// tuple previously played into two **independently sampled** secrets:
//
//   - `primes: Vec<u64>` — the arithmetic-layer key (`c*k+a`), sampled
//     exactly as before via [`generate_prime_numbers`].
//   - `sk: [u8; SK_SIZE]` — a freshly CSPRNG-sampled, uniformly random
//     256-bit secret, drawn independently of `primes` (never derived from it
//     by any function), that keys *every* domain derivation (`0x00`-`0x0A`)
//     in place of `key_bytes(primes)`.
//
// Because `sk` is independent of `primes`, a reduction can sample its own
// `primes'` locally to run the arithmetic layer while forwarding every
// domain-derivation call to an external oracle keyed by the real, hidden
// `sk` — closing CVF13's simulation gap — and the standard uniform-key
// HMAC-SHA256 PRF assumption applies to `sk` directly (`H_inf(sk) = 256`
// bits), closing CVF8's non-standard-assumption residual.
//
// The nonce is also no longer a fresh CSPRNG draw: it is a **synthetic IV**
// (à la RFC 5297 SIV / AES-GCM-SIV), computed as a keyed digest of the AAD
// and message under domain `0x0A`:
//
//   N = Derive_synth(sk_fmt, aad, message) = HMAC(sk_fmt, 0x0A || be8(|aad|) || aad || message)[0:16]
//
// where `sk_fmt = HMAC(sk, 0x0B || format_id)` is the format subkey of
// domain `0x0B`, which binds every v8 derivation to one specific wire
// format so a ciphertext or tag produced under one format can never verify
// under another that shares the same `(primes, sk)`.
//
// Because the nonce is now a PRF of `(sk, aad, message)`, two *different*
// `(aad, message)` pairs share a nonce only if they collide under
// HMAC-SHA256 — cryptographically negligible — so the CVF3 key-recovery
// route (which requires two distinct known plaintexts under one *reused*
// nonce) is closed by construction, not merely made statistically unlikely.
// This is the standard, well-known misuse-resistance trade-off (MRAE): v8
// encryption is deterministic for a fixed `(sk, primes, aad, message)`, so
// re-encrypting the *same* message under the *same* key reveals only that
// the two ciphertexts are equal — never a key-recovery or confidentiality
// break. Callers who require probabilistic ciphertexts (semantic security
// even for repeated identical messages) should continue to use the v7
// random-nonce API ([`encrypt_bytes`]) instead.
//
// The wire-format byte layout is unchanged (`N || masked_blob || tag`); v7
// and v8 ciphertexts are byte-compatible in shape but **not**
// interoperable with each other, since they are keyed and nonce-derived
// differently. Per the existing format-selection philosophy established for
// CVF7 (no in-band discriminator byte, since an unauthenticated
// discriminator would need to be trusted before verification), callers MUST
// agree out-of-band on whether a given key/ciphertext pair uses the v7 or
// v8 schedule.
//
// See `docs/napseq-eprint-preprint.tex` (new subsection, "V8 Key Schedule
// and Synthetic Nonce") and `docs/CAVEATS.md` (CVF3/CVF8/CVF13 follow-ups)
// for the full specification and updated security argument.

/// Size in bytes of the v8 independently-sampled HMAC subkey `sk`.
pub const SK_SIZE: usize = 32;

/// Hard cap on consecutive noise tokens emitted before a real token in the
/// v8 token-emission loop (never applied to v7, matching `napqes.py` /
/// `C/napqes.c`). As of the V2-CVF2 fix, this cap also fixes the *total*
/// per-real-token budget: every v8 ciphertext is padded with additional
/// filler tokens up to a deterministic per-bucket ceiling of
/// `real_token_count * (MAX_NOISE_RUN + 1)` tokens (see
/// `encrypt_bytes_v8` / `decrypt_core_v8`). Without this, the *natural*
/// token count varies with the message-derived synthetic nonce even for a
/// fixed padding bucket, letting an observer who collects several
/// ciphertexts of one message under varying AAD average out the noise and
/// reliably recover the padding bucket (`docs/CAVEATS.md`, V2-CVF2). After
/// this fix, v8 ciphertext length is a deterministic function of the
/// padding bucket alone, at the cost of always paying the worst-case ~20x
/// expansion instead of the ~13.4x average case.
pub const MAX_NOISE_RUN: u64 = 19;

/// Domain `0x0B` format-subkey identifier for v8 block mode.
pub const FORMAT_BLOCK_V8: u8 = 0x01;
/// Domain `0x0B` format-subkey identifier for the v8 streaming-AE format.
pub const FORMAT_STREAM_AE_V8: u8 = 0x02;

/// Domain `0x0B`: derive a format-specific HMAC subkey from `sk`.
///
/// Every v8 derivation is keyed by this subkey rather than by `sk` itself,
/// so a ciphertext or tag produced under one v8 wire format can never
/// verify under another format's effective key even though both share the
/// same `(primes, sk)` material. Matches `napqes.py::_derive_format_subkey`
/// and `C/napqes.c::derive_format_subkey`.
fn derive_format_subkey(sk: &[u8], format_id: u8) -> [u8; 32] {
    hmac_digest(sk, &[0x0B, format_id])
}

/// Generate a v8 key pair: an arithmetic-layer prime tuple and an
/// independently-sampled, uniformly random 256-bit HMAC subkey.
///
/// The two components MUST be generated independently (never one derived
/// from the other) for the CVF8/CVF13 security argument above to hold, and
/// MUST both be treated as secret key material.
pub fn generate_v8_key(count: usize, min_val: u64, max_val: u64) -> (Vec<u64>, [u8; SK_SIZE]) {
    let primes = generate_prime_numbers(count, min_val, max_val);
    let mut sk = [0u8; SK_SIZE];
    rand::thread_rng().fill_bytes(&mut sk);
    (primes, sk)
}

/// Synthetic IV (SIV-style) nonce derivation — domain byte `0x0A`.
///
/// Deterministic in `(sk_fmt, aad, message)`: encrypting the same message
/// under the same key and AAD always reproduces the same nonce (and hence
/// the same ciphertext), which is the standard MRAE trade-off. Encrypting
/// any *different* `(aad, message)` pair produces a nonce that collides
/// with a previous one only with HMAC-SHA256-collision probability.
fn synthetic_nonce(sk_fmt: &[u8], aad: &[u8], message: &[u8]) -> [u8; NONCE_SIZE] {
    let mut buf = Vec::with_capacity(1 + AAD_LEN_WIDTH_V8 + aad.len() + message.len());
    buf.push(0x0A);
    buf.extend_from_slice(&be_len_prefix(aad.len(), AAD_LEN_WIDTH_V8));
    buf.extend_from_slice(aad);
    buf.extend_from_slice(message);
    let d = hmac_digest(sk_fmt, &buf);
    let mut n = [0u8; NONCE_SIZE];
    n.copy_from_slice(&d[..NONCE_SIZE]);
    n
}

/// Misuse-resistant v8 encryption: synthetic nonce (CVF3 fix) plus a
/// domain-derivation key (`sk`) independent of the arithmetic-layer primes
/// (CVF8/CVF13 fix). See the module-level "V8 key schedule" documentation
/// above for the full security argument.
///
/// Uses the default [`PadProfile::Bucket`] padding profile; see
/// [`encrypt_bytes_v8_with_profile`] to select another.
pub fn encrypt_bytes_v8(
    message: &str,
    primes: &[u64],
    sk: &[u8; SK_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    encrypt_bytes_v8_with_profile(message, primes, sk, aad, PadProfile::Bucket)
}

/// [`encrypt_bytes_v8`] with an explicit padding profile
/// (docs/napseq-eprint-v3.tex, Section "Padding Profiles").
///
/// The profile governs how much plaintext length the ciphertext size reveals:
/// [`PadProfile::Bucket`] leaks at most ~3.70 bits, [`PadProfile::Frame`]
/// exactly zero. It is a sender-side parameter, never transmitted;
/// [`decrypt_bytes_v8`] needs no matching argument.
pub fn encrypt_bytes_v8_with_profile(
    message: &str,
    primes: &[u64],
    sk: &[u8; SK_SIZE],
    aad: &[u8],
    pad_profile: PadProfile,
) -> Result<Vec<u8>, String> {
    let sk_fmt = derive_format_subkey(sk, FORMAT_BLOCK_V8);
    let nonce = synthetic_nonce(&sk_fmt, aad, message.as_bytes());
    let codepoints: Vec<u32> = message.chars().map(|c| c as u32).collect();
    if codepoints.len() > 0xFFFF {
        return Err("Message too long for 2-byte length prefix.".into());
    }
    validate_key(primes)?;
    let noise_theta = derive_noise_threshold_v8(&sk_fmt, &nonce);
    let block_size = pad_profile.block_size(codepoints.len())?;
    let padded = pad_to_block(&codepoints, &sk_fmt, &nonce, block_size);
    let kk = primes.len() as u64;
    let mut cypher: Vec<u64> = Vec::new();
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    for &c in &padded {
        let mut noise_run: u64 = 0;
        loop {
            if noise_run < MAX_NOISE_RUN && is_noise_pos_v8(&sk_fmt, &nonce, ct_pos, noise_theta) {
                let k = primes[(real_idx % kk) as usize];
                let nc = derive_noise_char(&sk_fmt, &nonce, ct_pos);
                let na = derive_noise_token_addend(&sk_fmt, &nonce, ct_pos, k);
                cypher.push(nc * k + na);
                ct_pos += 1;
                noise_run += 1;
            } else {
                let k = primes[(real_idx % kk) as usize];
                let addend = derive_addend(&sk_fmt, &nonce, real_idx, k);
                cypher.push(c as u64 * k + addend);
                ct_pos += 1;
                real_idx += 1;
                break;
            }
        }
    }
    // V2-CVF2 fix: pad up to the fixed, bucket-only ceiling so ciphertext
    // length never depends on the message-derived nonce's noise realisation.
    let ceiling = (padded.len() as u64) * (MAX_NOISE_RUN + 1);
    while (cypher.len() as u64) < ceiling {
        let k = primes[(real_idx % kk) as usize];
        let nc = derive_noise_char(&sk_fmt, &nonce, ct_pos);
        let na = derive_noise_token_addend(&sk_fmt, &nonce, ct_pos, k);
        cypher.push(nc * k + na);
        ct_pos += 1;
    }
    let blob = fixed_encode_tokens(&cypher);
    let ks = varint_keystream(&sk_fmt, &nonce, blob.len());
    let masked: Vec<u8> = blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mut payload = Vec::with_capacity(NONCE_SIZE + masked.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&masked);
    let tag = compute_auth_tag(&sk_fmt, aad, &payload, AAD_LEN_WIDTH_V8);
    payload.extend_from_slice(&tag);
    Ok(payload)
}

/// Misuse-resistant v8 decryption — inverse of [`encrypt_bytes_v8`].
pub fn decrypt_bytes_v8(
    ciphertext: &[u8],
    primes: &[u64],
    sk: &[u8; SK_SIZE],
    aad: &[u8],
) -> Result<String, String> {
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(format!(
            "Ciphertext too short: {} bytes; header+tag require at least {}.",
            ciphertext.len(),
            NONCE_SIZE + TAG_SIZE
        ));
    }
    validate_key(primes)?;
    let sk_fmt = derive_format_subkey(sk, FORMAT_BLOCK_V8);
    let split = ciphertext.len() - TAG_SIZE;
    let payload = &ciphertext[..split];
    let recv_tag = &ciphertext[split..];
    let calc_tag = compute_auth_tag(&sk_fmt, aad, payload, AAD_LEN_WIDTH_V8);
    if !ct_eq_bytes(recv_tag, calc_tag.as_ref()) {
        return Err("Authentication failed: invalid HMAC tag.".into());
    }
    let nonce = &payload[..NONCE_SIZE];
    let masked = &payload[NONCE_SIZE..];
    let ks = varint_keystream(&sk_fmt, nonce, masked.len());
    let blob: Vec<u8> = masked.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let tokens = fixed_decode_tokens(&blob).map_err(|e| format!("varint decode error: {}", e))?;
    let codepoints = decrypt_core_v8(nonce, &tokens, primes, &sk_fmt)?;
    // `decrypt_core_v8` has already rejected any non-scalar value, so this
    // maps every recovered codepoint rather than silently dropping some.
    let s: String = codepoints
        .into_iter()
        .map(|c| {
            char::from_u32(c)
                .ok_or_else(|| format!("Malformed v8 plaintext: {} is not a Unicode scalar value.", c))
        })
        .collect::<Result<String, String>>()?;
    Ok(s)
}

/// Securely erase a v8 HMAC subkey by overwriting it with zero.
pub fn zeroize_sk(sk: &mut [u8; SK_SIZE]) {
    for x in sk.iter_mut() {
        unsafe { std::ptr::write_volatile(x, 0u8) };
    }
}

// ─── Key zeroization ─────────────────────────────────────────────────────────

/// Securely erase key material by overwriting each element with zero.
///
/// Uses `ptr::write_volatile` to prevent the compiler from eliding the writes
/// as dead-code optimisations, consistent with the `ct_eq_bytes` approach.
/// Call this as soon as the key is no longer needed.
///
/// Reference: FIPS 140-3 / SP 800-57 Part 1 Rev 5 §8.3 (key destruction).
pub fn zeroize_key(key: &mut [u64]) {
    for x in key.iter_mut() {
        unsafe { std::ptr::write_volatile(x, 0u64) };
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u64> {
        // 10 fixed 7-digit primes — deterministic for tests.
        vec![
            1_000_003, 1_000_033, 1_000_037, 1_000_039, 1_000_081, 1_000_099,
            1_000_117, 1_000_121, 1_000_133, 1_000_151,
        ]
    }

    #[test]
    fn roundtrip_bytes() {
        let k = test_key();
        let msg = "Hello, EpiCypher!";
        let ct = encrypt_bytes(msg, &k, b"").unwrap();
        let pt = decrypt_bytes(&ct, &k, b"").unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn roundtrip_str_with_aad() {
        let k = test_key();
        let msg = "Authenticated payload";
        let aad = b"hdr=1";
        let ct = encrypt_str(msg, &k, aad).unwrap();
        let pt = decrypt_str(&ct, &k, aad).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn wrong_aad_fails() {
        let k = test_key();
        let ct = encrypt_bytes("secret", &k, b"good").unwrap();
        assert!(decrypt_bytes(&ct, &k, b"bad").is_err());
    }

    #[test]
    fn tamper_fails() {
        let k = test_key();
        let mut ct = encrypt_bytes("secret", &k, b"").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt_bytes(&ct, &k, b"").is_err());
    }

    #[test]
    fn empty_message_roundtrip() {
        let k = test_key();
        assert_eq!(decrypt_str(&encrypt_str("", &k, b"").unwrap(), &k, b"").unwrap(), "");
    }

    #[test]
    fn zeroize_key_clears_memory() {
        let mut k = test_key();
        zeroize_key(&mut k);
        assert!(k.iter().all(|&x| x == 0));
    }

    #[test]
    fn primes_are_prime() {
        let ps = generate_prime_numbers(10, MIN_KEY_PRIME, MAX_KEY_PRIME);
        assert_eq!(ps.len(), 10);
        for p in &ps {
            assert!(is_prime(*p));
        }
    }

    // ─── V8 key schedule + synthetic nonce (CVF3/CVF8/CVF13 fix) ───────────

    fn test_sk() -> [u8; SK_SIZE] {
        [0x42u8; SK_SIZE]
    }

    #[test]
    fn v8_roundtrip() {
        let primes = test_key();
        let sk = test_sk();
        let msg = "Hello, misuse-resistant EpiCypher!";
        let ct = encrypt_bytes_v8(msg, &primes, &sk, b"aad").unwrap();
        let pt = decrypt_bytes_v8(&ct, &primes, &sk, b"aad").unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn v8_wrong_aad_fails() {
        let primes = test_key();
        let sk = test_sk();
        let ct = encrypt_bytes_v8("secret", &primes, &sk, b"good").unwrap();
        assert!(decrypt_bytes_v8(&ct, &primes, &sk, b"bad").is_err());
    }

    #[test]
    fn v8_tamper_fails() {
        let primes = test_key();
        let sk = test_sk();
        let mut ct = encrypt_bytes_v8("secret", &primes, &sk, b"").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt_bytes_v8(&ct, &primes, &sk, b"").is_err());
    }

    /// CVF3: encrypting the same (aad, message) twice under the same key
    /// must reproduce the identical nonce and ciphertext (deterministic
    /// synthetic IV) — the standard, disclosed MRAE trade-off.
    #[test]
    fn v8_same_message_is_deterministic() {
        let primes = test_key();
        let sk = test_sk();
        let ct1 = encrypt_bytes_v8("repeat me", &primes, &sk, b"aad").unwrap();
        let ct2 = encrypt_bytes_v8("repeat me", &primes, &sk, b"aad").unwrap();
        assert_eq!(ct1, ct2);
    }

    /// CVF3: distinct messages must not share a nonce (the property that
    /// closes the affine-cancellation key-recovery route).
    #[test]
    fn v8_distinct_messages_have_distinct_nonces() {
        let primes = test_key();
        let sk = test_sk();
        let ct1 = encrypt_bytes_v8("message one", &primes, &sk, b"aad").unwrap();
        let ct2 = encrypt_bytes_v8("message two", &primes, &sk, b"aad").unwrap();
        assert_ne!(&ct1[..NONCE_SIZE], &ct2[..NONCE_SIZE]);
    }

    /// V2-CVF2 fix: ciphertext length must be a deterministic function of
    /// the padding bucket alone, never of the message-derived synthetic
    /// nonce's noise realisation. Encrypt the SAME message under many
    /// distinct keys and AAD values and confirm every ciphertext has
    /// EXACTLY the same length -- the property whose absence let an
    /// observer average out noise across varied-AAD ciphertexts of one
    /// message to recover the padding bucket reliably.
    #[test]
    fn v8_ciphertext_length_is_deterministic_across_varied_aad() {
        let mut lengths = std::collections::HashSet::new();
        for i in 0..50u32 {
            let (primes, sk) = generate_v8_key(10, MIN_KEY_PRIME, MAX_KEY_PRIME);
            let aad = format!("aad-{}", i);
            let ct = encrypt_bytes_v8("fixed target message", &primes, &sk, aad.as_bytes())
                .unwrap();
            lengths.insert(ct.len());
        }
        assert_eq!(lengths.len(), 1, "expected one deterministic length, got {:?}", lengths);
    }

    #[test]
    fn v8_zeroize_sk_clears_memory() {
        let mut sk = test_sk();
        zeroize_sk(&mut sk);
        assert!(sk.iter().all(|&x| x == 0));
    }

    #[test]
    fn v8_key_generation_is_independent() {
        let (primes, sk) = generate_v8_key(10, MIN_KEY_PRIME, MAX_KEY_PRIME);
        assert_eq!(primes.len(), 10);
        // sk must not be derivable from key_bytes(primes) via the v7 KDF —
        // spot-check it does not equal the v7 HMAC key material shape.
        assert_ne!(sk.to_vec(), key_bytes(&primes));
    }

    /// The `Bucket` profile must reproduce the pre-V3-CVF2 hard-wired ladder
    /// exactly, or every existing KAT breaks.
    #[test]
    fn pad_profile_bucket_matches_legacy_ladder() {
        for n in 0..2048usize {
            let legacy = if n == 0 {
                16usize
            } else {
                let bl = 64 - (n as u64).leading_zeros() as usize;
                (1usize << bl).max(16)
            };
            assert_eq!(PadProfile::Bucket.block_size(n).unwrap(), legacy, "n={}", n);
        }
    }

    /// Every profile must land in the same 13-element set `{2^4, ..., 2^16}`,
    /// which is what lets a decryptor stay profile-agnostic.
    #[test]
    fn pad_profiles_share_one_reachable_set() {
        let legal: std::collections::HashSet<usize> =
            (PAD_MIN_EXP..=PAD_MAX_EXP).map(|e| 1usize << e).collect();
        assert_eq!(legal.len(), 13);
        for n in (0..0xFFFFusize).step_by(97) {
            for p in [
                PadProfile::Bucket,
                PadProfile::Coarse(2),
                PadProfile::Coarse(3),
                PadProfile::Coarse(12),
            ] {
                let b = p.block_size(n).unwrap();
                assert!(legal.contains(&b), "profile {:?} produced B={} for n={}", p, b, n);
                assert!(b > n, "profile {:?} produced B={} <= n={}", p, b, n);
            }
        }
    }

    #[test]
    fn pad_profile_coarse_stride_must_divide_twelve() {
        assert!(PadProfile::Coarse(5).block_size(3).is_err());
        assert!(PadProfile::Coarse(0).block_size(3).is_err());
        for g in [1u32, 2, 3, 4, 6, 12] {
            assert!(PadProfile::Coarse(g).block_size(3).is_ok());
        }
        // Stride 3 thins {2^4..2^16} to {2^4, 2^7, 2^10, 2^13, 2^16}.
        assert_eq!(PadProfile::Coarse(3).block_size(200).unwrap(), 1 << 10);
    }

    #[test]
    fn pad_profile_frame_is_constant_and_range_checked() {
        for n in [0usize, 1, 100, 511] {
            assert_eq!(PadProfile::Frame(512).block_size(n).unwrap(), 512);
        }
        assert!(PadProfile::Frame(512).block_size(512).is_err()); // n must be < F
        assert!(PadProfile::Frame(1000).block_size(1).is_err()); // not a power of two
        assert!(PadProfile::Frame(8).block_size(1).is_err()); // below 2^4
        assert!(PadProfile::Frame(1 << 17).block_size(1).is_err()); // above 2^16
    }

    /// The default profile must be byte-identical to the un-profiled entry
    /// point, and `Frame` must make ciphertext length independent of the
    /// plaintext length -- the V3-CVF2 property, measured rather than argued.
    #[test]
    fn v8_frame_profile_hides_length_and_round_trips() {
        let (primes, sk) = generate_v8_key(10, MIN_KEY_PRIME, MAX_KEY_PRIME);

        let plain = "short";
        let default_ct = encrypt_bytes_v8(plain, &primes, &sk, b"").unwrap();
        let bucket_ct =
            encrypt_bytes_v8_with_profile(plain, &primes, &sk, b"", PadProfile::Bucket).unwrap();
        assert_eq!(default_ct, bucket_ct, "Bucket must be the default");

        let mut framed_lengths = std::collections::HashSet::new();
        for n in [1usize, 5, 40, 200, 511] {
            let msg = "a".repeat(n);
            let ct =
                encrypt_bytes_v8_with_profile(&msg, &primes, &sk, b"", PadProfile::Frame(512))
                    .unwrap();
            framed_lengths.insert(ct.len());
            // Decryption is profile-agnostic: no matching argument is passed.
            assert_eq!(decrypt_bytes_v8(&ct, &primes, &sk, b"").unwrap(), msg);
        }
        assert_eq!(
            framed_lengths.len(),
            1,
            "frame(512) must collapse every length to one, got {:?}",
            framed_lengths
        );

        // The same messages under the default profile do NOT collapse.
        let mut bucket_lengths = std::collections::HashSet::new();
        for n in [1usize, 5, 40, 200, 511] {
            let msg = "a".repeat(n);
            bucket_lengths.insert(encrypt_bytes_v8(&msg, &primes, &sk, b"").unwrap().len());
        }
        assert!(bucket_lengths.len() > 1);
    }

    #[test]
    fn v8_frame_profile_rejects_oversized_message() {
        let (primes, sk) = generate_v8_key(10, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "a".repeat(600);
        assert!(
            encrypt_bytes_v8_with_profile(&msg, &primes, &sk, b"", PadProfile::Frame(512)).is_err()
        );
    }
}
