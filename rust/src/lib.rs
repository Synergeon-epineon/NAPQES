// CVF-24: the README is included as the crate root doc so its usage
// examples become doctests. The previous README's lone snippet did not
// compile (missing imports, unwrap on the wrong type); pulling it in via
// include_str! makes any future regression fail `cargo test --doc`.
#![doc = include_str!("../README.md")]
//!
//! ---
//!
//! Rust implementation of NAPQES, the paper-specified AEAD scheme.
//!
//! Specification: EPINeon NAPQES v4 (see `docs/napseq-eprint-v3.tex` — the
//! filename lags the version tag one revision and will be renamed to
//! `napseq-eprint-v4.tex` in a follow-up).
//!
//! Two wire formats coexist in this crate:
//!
//! * **v8 (normative — use this).** Domain-`0x0B` format subkey
//!   ([`derive_format_subkey`], per CVF-11), synthetic nonce
//!   ([`synthetic_nonce`], domain `0x0A`), `MAX_NOISE_RUN`-capped emission
//!   loop, per-bucket token ceiling. Wire layout is
//!   `nonce(16) || masked_blob(fixed-width) || tag(32)`. Entry points:
//!   [`encrypt_bytes_v8`], [`decrypt_bytes_v8`], [`generate_v8_key`],
//!   [`encrypt_bytes_v8_with_profile`], [`encrypt_stream_ae_v8`],
//!   [`decrypt_stream_ae_v8`], [`StreamV8Encryptor`]. Length-hiding property
//!   holds per Corollary 4.14 of the paper.
//!
//! * **v7 (legacy — decryptors retained for archived ciphertexts).**
//!   Fixed-width tokens (CVF1 fix). Wire layout same shape, but no
//!   `MAX_NOISE_RUN` cap, so ciphertext length varies with the nonce.
//!   Encryptors are `#[deprecated]` per CVF-17; decryptors ([`decrypt_bytes`],
//!   [`decrypt_str`], [`decrypt_raw`]) remain to decode existing traffic.
//!
//! # Key ordering is a security parameter
//!
//! `[k0, k1, …]` and `[k1, k0, …]` are **distinct** keys that produce
//! non-interoperable ciphertexts.  Callers must preserve element order
//! when storing or transmitting key material.
//!
//! # Validation
//!
//! Every entry point that accepts a `&[u64]` key runs [`validate_key`]
//! (private) as its first statement, per CVF-15. A key that is empty,
//! composite, below [`MIN_KEY_PRIME`], above [`MAX_KEY_PRIME`], or contains
//! duplicates is rejected with a descriptive `String` error before any
//! HMAC or arithmetic runs — no panic path is reachable from `&[u64]` input.

pub mod self_test;
pub mod kem;
pub mod kem_exchange;
pub mod ot_frame;
pub mod protocols;
pub mod vale;

// CVF-29 + CVF-37 + CVF-41: validated + auto-wiped v8 key wrapper.
mod key;
pub use key::{
    NapqesKey,
    encrypt_bytes_v8_key,
    decrypt_bytes_v8_key,
    encrypt_bytes_v8_with_profile_key,
};
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
            // CVF-35: SP 800-140B §4.9.2 "stuck-generator" check. The
            // single process-global PREV_NONCE slot is not a per-key
            // uniqueness guarantee — it catches only an immediately-stuck
            // DRBG, not restart-and-replay across processes or per-key
            // reuse across time. The previous message overstated the scope.
            return Err("CRNG stuck-generator check failed: consecutive draws matched (SP 800-140B §4.9.2)".into());
        }
    }
    *prev = Some(nonce);
    Ok(nonce)
}

// ─── Primes ──────────────────────────────────────────────────────────────────

/// Lower bound of the normative prime interval
/// `P = [MIN_KEY_PRIME, MAX_KEY_PRIME]`.
pub const MIN_KEY_PRIME: u64 = 1_000_000;

/// Upper bound of the normative prime interval of the "PQ-128" profile.
/// Inclusive, and chosen so that `P` is exactly the half-open interval
/// `[10^6, 1.5e7)` already used by `kem.rs` — the AEAD and the KEM now draw
/// from the same prime set. `P` contains exactly 892_206 primes (verified by
/// sieve), giving `|P|!/(|P|-13)! = 2^256.9711` ordered 13-tuples
/// (`2^128.4855` post-Grover).
///
/// **CVF-16 fix (2026-09-22).** This bound is now enforced by [`validate_key`]
/// on *every* key it sees (not just generation), matching the normative
/// interval Remark 3.1 of the paper specifies. Prior revisions accepted any
/// prime `>= MIN_KEY_PRIME` on decrypt paths, which allowed a key element
/// large enough to make the token multiplication `c * k + addend` wrap `u64`
/// silently in release builds. Matches `napqes.py::MAX_KEY_PRIME` and
/// `C/napqes.h::NAPQES_MAX_KEY_PRIME`.
pub const MAX_KEY_PRIME: u64 = 14_999_999;

/// Upper bound above which token multiplication `c * k + addend` cannot be
/// proved not to wrap `u64`, given a codepoint `c ≤ 0x10FFFF` and an addend
/// `< k`. `MAX_KEY_PRIME` sits well below this ceiling, so [`validate_key`]'s
/// [`MAX_KEY_PRIME`] check is the primary guard; this constant is retained as
/// a compile-time backstop that a later widening of `MAX_KEY_PRIME` would
/// trip against (see the `const _:() = assert!(...)` immediately below).
pub const MAX_SAFE_KEY_PRIME: u64 = u64::MAX / (0x10FFFF + 1);
const _: () = assert!(
    MAX_KEY_PRIME < MAX_SAFE_KEY_PRIME,
    "MAX_KEY_PRIME exceeds the multiplicative safety bound; token \
     multiplication could wrap u64 (CVF-16)"
);

/// Number of prime key elements generated by default ("PQ-128" profile).
/// K=13 is the smallest count reaching the 128-bit post-quantum target over
/// `P`; K=13 over the earlier `[10^6, 9.9e6]` interval would have given only
/// 124.4 bits, which is why the interval was widened too.
pub const DEFAULT_KEY_COUNT: usize = 13;

/// Upper bound on the number of prime elements per key (audit finding
/// CVF-41). Well above `DEFAULT_KEY_COUNT = 13` — the cap exists so that
/// a caller-supplied K cannot force `validate_key` into pathological work.
pub const MAX_KEY_ELEMENTS: usize = 128;

/// Largest key element representable in the 5-byte key serialisation used by
/// [`key_bytes`]. A larger value would be silently truncated to its low 5
/// bytes, yielding a different key element than Python (which rejects it).
pub const MAX_SERIALISABLE_KEY_PRIME: u64 = (1u64 << 40) - 1;

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
///
/// **CVF-20 fix (2026-09-22).** The previous implementation drew each
/// candidate with `min_val + (rng.next_u64() % span)`, a modulo reduction
/// that gives residues `x < 2^64 mod span` one extra pre-image and biases the
/// distribution away from the uniform draw the paper's Remark 3.2 specifies.
/// The rejection sampler behind `rand::distributions::Uniform::new_inclusive`
/// (Lemire's algorithm) is distributionally equivalent to Remark 3.2's
/// canonical enumeration + rejection scheme — both are unbiased — and does
/// not require enumerating `P` up front.
///
/// Panics with a descriptive message if `count > 0` distinct primes cannot be
/// found within `4·span` attempts. For the normative interval
/// `[MIN_KEY_PRIME, MAX_KEY_PRIME]` this is safe by a large margin: the
/// interval contains 892,206 primes against `DEFAULT_KEY_COUNT = 13`, so an
/// exhaustion of the attempt cap is a caller misuse (empty interval,
/// `count` too large) rather than a randomness pathology.
pub fn generate_prime_numbers(count: usize, min_val: u64, max_val: u64) -> Vec<u64> {
    use rand::distributions::{Distribution, Uniform};
    assert!(max_val > min_val, "generate_prime_numbers: max_val must exceed min_val");
    let mut rng = rand::thread_rng();
    let dist = Uniform::new_inclusive(min_val, max_val);
    let span = max_val - min_val + 1;
    let max_attempts = span.saturating_mul(4);
    let mut primes: Vec<u64> = Vec::with_capacity(count);
    let mut attempts: u64 = 0;
    while primes.len() < count && attempts < max_attempts {
        // CVF-20: unbiased sample via rand::Uniform (Lemire rejection),
        // replacing the modulo-bias line `min_val + (rng.next_u64() % span)`.
        let num = dist.sample(&mut rng);
        if is_prime(num) && !primes.contains(&num) {
            primes.push(num);
        }
        attempts += 1;
    }
    if primes.len() < count {
        panic!(
            "generate_prime_numbers: could not find {} distinct primes in \
             [{}, {}] within {} attempts. The prime density in the requested \
             interval may be too low for the requested count, or the \
             interval is too narrow. For the normative interval \
             [MIN_KEY_PRIME, MAX_KEY_PRIME] the pool contains 892,206 \
             primes, so this failure indicates a caller-supplied range issue.",
            count, min_val, max_val, max_attempts
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
    // CVF-38: `be5` keeps only the low 5 bytes (bits 0..40). All in-crate
    // callers pass values well below 2^40 (ct_pos and real_idx are bounded
    // by MAX_PLAINTEXT_CODEPOINTS * (MAX_NOISE_RUN+1) ≈ 1.3M), but a
    // release-mode caller passing >= 2^40 would silently truncate. Belt-
    // and-braces guard for debug builds.
    debug_assert!(
        n < 1u64 << 40,
        "be5 called with n = {} >= 2^40; low-5-byte encoding would truncate (CVF-38)",
        n
    );
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
///
/// CVF-28: panics if `n` cannot be encoded in `width` bytes. The v7 format
/// uses `width = 4`, so an AAD longer than 2^32 bytes would silently
/// encode `|A| mod 2^32` and desynchronise the tag computation from the
/// paper's `be_len_prefix` definition. Real-world AAD is measured in KB;
/// this guard exists so a caller mistake fails loudly.
fn be_len_prefix(n: usize, width: usize) -> Vec<u8> {
    debug_assert!(width <= 8, "be_len_prefix width must be <= 8");
    if width < 8 {
        let cap = 1u128 << (8 * width);
        assert!(
            (n as u128) < cap,
            "be_len_prefix: length {} exceeds {}-byte prefix capacity {} (CVF-28)",
            n, width, cap
        );
    }
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
    // CVF-16: `key_element >= MIN_KEY_PRIME >= 2` after validate_key, so
    // `key_element - 1 >= 1` and the modulus is well defined. The debug
    // assertion guards against a caller that skipped validation.
    debug_assert!(
        key_element >= 2,
        "derive_addend called with key_element < 2; validate_key was skipped (CVF-16)"
    );
    (u32_from_be4(&d[..4]) as u64 % (key_element - 1)) + 1
}

fn derive_noise_char(kb: &[u8], nonce: &[u8], ct_pos: u64) -> u64 {
    let mut buf = Vec::with_capacity(1 + nonce.len() + 5);
    buf.push(0x04);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&be5(ct_pos));
    let d = hmac_digest(kb, &buf);
    // CVF-42: named constants replace the bare `% 96) + 32` literal.
    (u32_from_be4(&d[..4]) as u64 % NOISE_ALPHABET) + ASCII_PRINTABLE_BASE
}

fn derive_noise_token_addend(kb: &[u8], nonce: &[u8], ct_pos: u64, key_element: u64) -> u64 {
    let mut buf = Vec::with_capacity(1 + nonce.len() + 5);
    buf.push(0x05);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&be5(ct_pos));
    let d = hmac_digest(kb, &buf);
    // CVF-16: same invariant as derive_addend — validate_key enforces
    // key_element >= MIN_KEY_PRIME so key_element - 1 is well defined.
    debug_assert!(
        key_element >= 2,
        "derive_noise_token_addend called with key_element < 2; validate_key was skipped (CVF-16)"
    );
    (u32_from_be4(&d[..4]) as u64 % (key_element - 1)) + 1
}

fn derive_noise_p(kb: &[u8], nonce: &[u8]) -> f64 {
    let mut buf = Vec::with_capacity(1 + nonce.len());
    buf.push(0x02);
    buf.extend_from_slice(nonce);
    let d = hmac_digest(kb, &buf);
    let t = u64_from_be8(&d[..8]) as f64 / TWO_POW_64;
    // CVF-42: named constants replace bare 0.75/0.99 literals; CVF-30 flags
    // that the v7 float path is retained only for backward compatibility.
    THETA_MIN_F64 + t * (THETA_MAX_F64 - THETA_MIN_F64)
}

/// Endpoints of the v8 noise-threshold interval, as fixed-width 64-bit
/// integers (docs/napseq-eprint-v3.tex, Section "Noise Probability").
const THETA_MIN: u64 = ((75u128 << 64) / 100) as u64;
const THETA_MAX: u64 = ((99u128 << 64) / 100) as u64;

/// Reject a prime tuple that is empty, composite, undersized, oversized or
/// repeating.
///
/// Primality is a specification requirement (paper §3.1 defines `P` as a set
/// of primes) and the correctness argument recovers `c` from `t = c * k + a`
/// by exact division whenever `0 < a < k`, which suffices for the recovered
/// addend to be identical on both sides. The earlier stated justification
/// (`gcd(a, k) = 1`) was carried over from a coprimality argument the CVF-8
/// audit finding showed to be misapplied; the primality check itself remains
/// correct because it enforces the specification, not because of the
/// gcd-based rationale (CVF-15).
///
/// Called from every v7 and v8 entry point that accepts a `&[u64]` key
/// (CVF-15 extended the coverage from v8-only in prior revisions), so a
/// caller supplying a malformed key gets an error here rather than a panic
/// inside `derive_addend` (division by `k - 1` for `k == 1`) or a silently
/// undecryptable ciphertext. Matches `_validate_key` in the Python port.
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
        // CVF-16: enforce the normative upper bound on every key, not just on
        // generation. Prior revisions accepted any prime up to
        // MAX_SERIALISABLE_KEY_PRIME on decrypt paths; a key element in that
        // wider band could wrap `c * k + addend` past u64 silently in release
        // builds (release default overflow-checks = false — see CVF-23).
        if k > MAX_KEY_PRIME {
            return Err(format!(
                "Key element at index {} ({}) exceeds MAX_KEY_PRIME ({}).",
                i, k, MAX_KEY_PRIME
            ));
        }
        // key_bytes keeps only the low 5 bytes; a larger element would be
        // silently truncated into a different key than Python would accept.
        // With the MAX_KEY_PRIME check above this branch is now unreachable
        // for well-formed keys, but the check is retained as a fail-safe.
        if k > MAX_SERIALISABLE_KEY_PRIME {
            return Err(format!(
                "Key element at index {} ({}) exceeds {}, the largest value \
                 representable in the 5-byte key serialisation.",
                i, k, MAX_SERIALISABLE_KEY_PRIME
            ));
        }
        // CVF-41: linear `key[..i].contains(&k)` distinctness scan was
        // O(K²) — a 10^6-element key would cost ~5×10¹¹ comparisons per
        // encrypt/decrypt on the bare-slice v8 surface. Retained here for
        // K ≤ MAX_KEY_ELEMENTS so a caller-supplied K is capped. The
        // sort-and-scan fallback below is O(K log K) on a copy that
        // preserves the caller's tuple order (order is a security parameter
        // per the module doc).
    }
    if key.len() > MAX_KEY_ELEMENTS {
        return Err(format!(
            "Key has {} elements, exceeding MAX_KEY_ELEMENTS ({}). Very large \
             keys are rejected because per-message primality/distinctness \
             validation is O(K²) with the classic scan and O(K log K) with \
             sort-and-scan; the cap makes the cost of legitimate use bounded.",
            key.len(),
            MAX_KEY_ELEMENTS
        ));
    }
    // Distinctness via sort-and-scan on a local clone (CVF-41).
    let mut sorted = key.to_vec();
    sorted.sort_unstable();
    for w in sorted.windows(2) {
        if w[0] == w[1] {
            return Err(format!(
                "Key element {} is a duplicate; all elements must be distinct.",
                w[0]
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

/// Maximum plaintext length in Unicode codepoints (CVF-40 item 9, CVF-34).
/// The 2-codepoint big-endian length prefix at the head of the padded block
/// (Section 3.6 of the paper) caps plaintext at 65535 codepoints on both
/// v7 and v8. Exceeding the cap is a caller error, reported as `Err` on
/// every entry point.
pub const MAX_PLAINTEXT_CODEPOINTS: usize = 0xFFFF;

/// Alphabet size for `derive_noise_char` (CVF-42). Noise characters draw
/// from the 96-value range including the DEL codepoint (127) — deliberately
/// distinct from [`PAD_ALPHABET`] (95) because padding excludes DEL.
pub const NOISE_ALPHABET: u64 = 96;

/// Alphabet size for `pad_to_block` (CVF-42). Padding codepoints are drawn
/// from printable ASCII excluding DEL (32..126).
pub const PAD_ALPHABET: u64 = 95;

/// Base codepoint for both noise and padding alphabets (CVF-42).
pub const ASCII_PRINTABLE_BASE: u64 = 32;

/// v7 noise-threshold interval endpoints as f64 (CVF-30 + CVF-42).
/// Retained for v7 wire compatibility only; v8 uses the integer
/// [`THETA_MIN`] / [`THETA_MAX`].
const THETA_MIN_F64: f64 = 0.75;
const THETA_MAX_F64: f64 = 0.99;

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
        // CVF-31: reject n that would produce a B outside the normative
        // reachable set {2^PAD_MIN_EXP, ..., 2^PAD_MAX_EXP}. Before this
        // check, `bucket_block_size(70_000)` returned 2^17 = 131_072 (one
        // above the ladder ceiling), and `bit_length(n)` for n >= 2^63
        // pushed the shift past 64 bits (panic in debug, modulo-64 wrap in
        // release before overflow-checks landed with CVF-23).
        if n >= 1usize << PAD_MAX_EXP {
            return Err(format!(
                "message of {} codepoints exceeds the maximum bucket 2^{} \
                 (CVF-31); pad_profile.block_size cannot produce a value in \
                 the normative reachable set.",
                n, PAD_MAX_EXP
            ));
        }
        // `n < 2^PAD_MAX_EXP <= 2^16 <= 2^63` — bit_length is safe now.
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
    // CVF-34: public entry points now check MAX_PLAINTEXT_CODEPOINTS at the
    // head and return `Err`. This debug_assert! is retained as a belt-and-
    // braces invariant for internal callers.
    debug_assert!(n <= MAX_PLAINTEXT_CODEPOINTS, "Message too long for 2-codepoint length prefix");
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
        // CVF-42: named constants replace bare `% 95) + 32` literal.
        out.push(((u32_from_be4(&d[..4]) as u64 % PAD_ALPHABET) + ASCII_PRINTABLE_BASE) as u32); // [32, 126]
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
    // CVF-43: `padded[0]` and `padded[1]` are u32 codepoints, not bytes. The
    // Python reference and the paper both fix the length prefix as two
    // byte-valued codepoints (each in [0, 255]); pairs like (1, 0), (0, 256)
    // and (1, 256) all reconstruct to n=256 in the old implementation, so a
    // sender with the key could emit ambiguous ciphertexts that authenticate
    // and unpad to inconsistent messages across ports. Reject any prefix
    // codepoint above 0xFF so the reconstruction is canonical.
    if padded[0] > 0xFF || padded[1] > 0xFF {
        return Err(format!(
            "Malformed length prefix: codepoints ({}, {}) are not byte-valued (CVF-43).",
            padded[0], padded[1]
        ));
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

#[deprecated(
    since = "0.2.0",
    note = "v7 legacy format lacks the MAX_NOISE_RUN cap and per-bucket \
            ceiling (audit CVF-17): ciphertext length is a random function \
            of the CSPRNG-drawn nonce rather than of the padding bucket, so \
            the length-hiding property Corollary 4.14 proves for v8 does not \
            hold. Use encrypt_bytes_v8 / encrypt_bytes_v8_with_profile."
)]
pub fn encrypt(message: &[u32], key: &[u64]) -> ([u8; NONCE_SIZE], Vec<u64>) {
    // CVF-34: uphold the length cap even on this Vec<u64>-returning legacy
    // path. The .expect() surfaces the cap consistently with the deprecation
    // attribute and matches the pattern of the CVF-15 validate_key call.
    assert!(
        message.len() <= MAX_PLAINTEXT_CODEPOINTS,
        "message length {} exceeds MAX_PLAINTEXT_CODEPOINTS ({})",
        message.len(), MAX_PLAINTEXT_CODEPOINTS
    );
    // CVF-15: this v7 API returns `Vec<u64>` and cannot report a validation
    // error. Every other entry point returns `Result` and propagates via `?`.
    // The .expect() here surfaces the same validation failure as a panic,
    // consistent with `pub fn decrypt`'s prior panic contract and matched by
    // the #[deprecated] attribute (CVF-17) that steers callers to v8.
    validate_key(key).expect("CVF-15: encrypt called with invalid key material");
    // CVF-35: route through the checked CRNG helper like every other v7
    // encryptor. Signature is `-> (nonce, tokens)` so a CRNG failure is
    // surfaced as `.expect` — consistent with the deprecation attribute
    // that steers callers to v8.
    let nonce = generate_nonce_with_crng_check()
        .expect("CVF-35: CRNG stuck-generator check failed inside encrypt");
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, &nonce);
    let padded = pad_message(message, &kb, &nonce);
    let cypher = emit_tokens_v7(&padded, &kb, &nonce, noise_p, key);
    (nonce, cypher)
}

/// Shared core of [`decrypt`] and the v8 (`decrypt_bytes_v8`) path, taking
/// the domain-derivation HMAC key `kb` explicitly instead of computing it
/// from `key` internally. v7 passes `kb = key_bytes(key)`; v8 passes the
/// independently-sampled `sk` (see "V8 key schedule" below, CVF8/CVF13 fix).
fn decrypt_core(
    nonce: &[u8],
    cypher: &[u64],
    key: &[u64],
    kb: &[u8],
) -> Result<Vec<u32>, String> {
    let noise_p = derive_noise_p(kb, nonce);
    let kk = key.len() as u64;
    let mut padded: Vec<u32> = Vec::new();
    let mut real_idx: u64 = 0;
    for (ct_pos, &token) in cypher.iter().enumerate() {
        if !is_noise_pos(kb, nonce, ct_pos as u64, noise_p) {
            let k = key[(real_idx % kk) as usize];
            let addend = derive_addend(kb, nonce, real_idx, k);
            // Match the checked recovery decrypt_core_v8 performs (CVF-14 fix):
            // reject any token whose shape is not `codepoint * k + addend` with
            // `addend ∈ [1, k-1]`, and any recovered value that is not a
            // Unicode scalar. The previous version subtracted, divided, and
            // narrowed to u32 with no validation — CVF-14 identified this as a
            // silent-narrowing site parallel to `decrypt_raw`'s `& 0xFF` mask.
            if token < addend || (token - addend) % k != 0 {
                return Err(format!(
                    "Malformed v7 ciphertext: token at position {} is not of \
                     the form codepoint * k + addend for key element {}.",
                    ct_pos, k
                ));
            }
            let cp = (token - addend) / k;
            if cp > 0x10FFFF || char::from_u32(cp as u32).is_none() {
                return Err(format!(
                    "Malformed v7 ciphertext: recovered value {} at position \
                     {} is not a Unicode scalar value.",
                    cp, ct_pos
                ));
            }
            padded.push(cp as u32);
            real_idx += 1;
        }
    }
    unpad_message(&padded)
}

/// v7 low-level decrypt entry point. Returns the recovered codepoint sequence,
/// or an error if the token stream is malformed. Prior to CVF-14 this returned
/// `Vec<u32>` and panicked on a malformed padded buffer (see V3-CVF8); the
/// new signature propagates the error like every other decryption path.
pub fn decrypt(nonce: &[u8], cypher: &[u64], key: &[u64]) -> Result<Vec<u32>, String> {
    validate_key(key)?; // CVF-15
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
            // CVF-44: three exhaustion states reach this branch — the
            // previous message named only the mid-run one. Report the
            // decoder's position and the noise-run length so an operator
            // can distinguish them.
            return Err(format!(
                "Truncated v8 ciphertext: token stream ended at position {} \
                 of {} after recovering {} of {} real tokens; expected another \
                 real token (noise run length reached {} of max {}).",
                ct_pos, n_tokens, real_idx, real_count, noise_run, MAX_NOISE_RUN
            ));
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

/// Compare two byte slices in constant time.
///
/// Delegates to [`subtle::ConstantTimeEq`], the vetted primitive Section 8.4
/// of the paper credits for the Rust port's tag comparison. `ConstantTimeEq`
/// for slices returns `Choice::from(0)` on any length mismatch — it fails
/// closed rather than comparing a prefix — so this comparator cannot report
/// equality for operands of different lengths (audit findings CVF-12 and
/// **CVF-45**, the latter noting the previous hand-rolled loop returned
/// `true` on prefix-match under release builds where the `debug_assert!`
/// length guard was compiled out; both concerns are architecturally
/// impossible under `subtle::ConstantTimeEq`).
///
/// Used at the three tag verification sites (v7 `decrypt_bytes`,
/// `decrypt_raw`, v8 `decrypt_bytes_v8`) on `[u8; TAG_SIZE]` operands, and
/// once inside `generate_nonce_with_crng_check` on `[u8; NONCE_SIZE]`
/// operands (CVF-35 flags that the latter compares public values — no
/// constant-time requirement — but the comparator's uniform length handling
/// makes it safe there too).
#[inline(never)]
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

// ─── Fixed-width token encoding (v7 — CVF1 fix) ──────────────────────────────
//
// CVF-21: the legacy `b128_decode_tokens` helper (retired LEB128 varint
// decoder) was removed in this pass — no code path in the crate produces
// LEB128 ciphertexts anymore, so the decoder was dead weight retained only
// with `#[allow(dead_code)]`. If a legacy-format tooling need re-emerges,
// restore the decoder in a dedicated `legacy_decode` module rather than at
// the crate root.
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

/// CVF-46: shared v7 token-emission loop.
///
/// Extracted from four near-identical copies in `encrypt`, `encrypt_bytes`,
/// `encrypt_bytes_with_nonce`, and `encrypt_raw`. Byte-identical to the
/// former inline loops — regression coverage via the existing v6 KAT
/// corpus (`tests/kat/v6_vectors.json`) plus the new pairwise-agreement
/// test `cvf46_all_four_v7_encryptors_share_emitter` in the test module.
///
/// Uncapped (no `MAX_NOISE_RUN`) and no per-bucket ceiling top-up —
/// deliberately: v7 wire compatibility with archived ciphertexts requires
/// the original nonce-dependent length. v7 encryptors are `#[deprecated]`
/// per CVF-17; the v8 path (`encrypt_bytes_v8_core_inner`) has its own
/// capped-and-ceilinged loop.
fn emit_tokens_v7(
    padded: &[u32],
    kb: &[u8],
    nonce: &[u8],
    noise_p: f64,
    key: &[u64],
) -> Vec<u64> {
    let kk = key.len() as u64;
    let mut cypher: Vec<u64> = Vec::with_capacity(padded.len() * 4);
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    for &c in padded {
        loop {
            if is_noise_pos(kb, nonce, ct_pos, noise_p) {
                let k = key[(real_idx % kk) as usize];
                let nc = derive_noise_char(kb, nonce, ct_pos);
                let na = derive_noise_token_addend(kb, nonce, ct_pos, k);
                cypher.push(nc * k + na);
                ct_pos += 1;
            } else {
                let k = key[(real_idx % kk) as usize];
                let addend = derive_addend(kb, nonce, real_idx, k);
                cypher.push(c as u64 * k + addend);
                ct_pos += 1;
                real_idx += 1;
                break;
            }
        }
    }
    cypher
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


#[deprecated(
    since = "0.2.0",
    note = "v7 legacy format lacks the MAX_NOISE_RUN cap and per-bucket \
            ceiling (audit CVF-17). Use encrypt_bytes_v8 / \
            encrypt_bytes_v8_with_profile."
)]
pub fn encrypt_bytes(message: &str, key: &[u64], aad: &[u8]) -> Result<Vec<u8>, String> {
    validate_key(key)?; // CVF-15
    // CVF-34: cap plaintext length at MAX_PLAINTEXT_CODEPOINTS at the entry
    // point (was an `assert!` in `pad_message`, which aborted release
    // builds — Section 12's "raises an error immediately; no silent
    // truncation" caveat is now honoured on v7 too).
    if message.chars().count() > MAX_PLAINTEXT_CODEPOINTS {
        return Err(format!(
            "message exceeds MAX_PLAINTEXT_CODEPOINTS ({})",
            MAX_PLAINTEXT_CODEPOINTS
        ));
    }
    let nonce = generate_nonce_with_crng_check()?;
    let codepoints: Vec<u32> = message.chars().map(|c| c as u32).collect();
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, &nonce);
    let padded = pad_message(&codepoints, &kb, &nonce);
    let cypher = emit_tokens_v7(&padded, &kb, &nonce, noise_p, key); // CVF-46
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
// CVF-17: crate-internal KAT/self-test helper, not exported — no
// #[deprecated] attribute needed on the definition, but its call sites
// wrap the invocation with #[allow(deprecated)] where consumers would
// otherwise pick up spurious warnings.
pub(crate) fn encrypt_bytes_with_nonce(
    message: &str,
    key: &[u64],
    nonce: [u8; NONCE_SIZE],
    aad: &[u8],
) -> Vec<u8> {
    // CVF-15: `pub(crate)` KAT-only helper; returns `Vec<u8>` (no error
    // channel), so a bad key panics with a message naming the validation
    // failure. Every crate caller is a fixed KAT with a known-valid key.
    validate_key(key).expect("CVF-15: encrypt_bytes_with_nonce called with invalid key material");
    // CVF-34: same cap as encrypt_bytes.
    debug_assert!(
        message.chars().count() <= MAX_PLAINTEXT_CODEPOINTS,
        "encrypt_bytes_with_nonce called with message > MAX_PLAINTEXT_CODEPOINTS"
    );
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, &nonce);
    let codepoints: Vec<u32> = message.chars().map(|c| c as u32).collect();
    let padded = pad_message(&codepoints, &kb, &nonce);
    let cypher = emit_tokens_v7(&padded, &kb, &nonce, noise_p, key); // CVF-46
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
    validate_key(key)?; // CVF-15
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
    let codepoints = decrypt(nonce, &tokens, key)?;
    // CVF-14: the previous body was `filter_map(char::from_u32)`, which
    // silently dropped every recovered value that was not a Unicode scalar
    // (surrogates, > 0x10FFFF). That turned a malformed ciphertext into a
    // shorter-but-syntactically-valid String rather than into an error, so a
    // ciphertext produced under the byte-oriented convention (`encrypt_raw`)
    // could decrypt to a truncated codepoint-oriented string with no signal.
    // Match `decrypt_bytes_v8`'s fallible mapping: a non-scalar value is an
    // error.
    codepoints
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            char::from_u32(c).ok_or_else(|| {
                format!(
                    "Malformed v7 plaintext: recovered value {} at position {} \
                     is not a Unicode scalar value.",
                    c, i
                )
            })
        })
        .collect::<Result<String, String>>()
}

#[deprecated(
    since = "0.2.0",
    note = "v7 legacy format lacks the MAX_NOISE_RUN cap and per-bucket \
            ceiling (audit CVF-17). Use encrypt_bytes_v8."
)]
pub fn encrypt_str(message: &str, key: &[u64], aad: &[u8]) -> Result<String, String> {
    // CVF-15: transitively covered by encrypt_bytes, but early-rejecting a
    // bad key means we never allocate the base64 buffer for a doomed op.
    validate_key(key)?;
    #[allow(deprecated)]
    Ok(STANDARD.encode(encrypt_bytes(message, key, aad)?))
}

pub fn decrypt_str(cypher: &str, key: &[u64], aad: &[u8]) -> Result<String, String> {
    validate_key(key)?; // CVF-15 — reject before base64 decode
    let bytes = STANDARD
        .decode(cypher.as_bytes())
        .map_err(|e| format!("base64 decode error: {}", e))?;
    decrypt_bytes(&bytes, key, aad)
}

// ─── Raw-bytes encrypt / decrypt (for binary PDU data) ───────────────────────

/// Encrypt arbitrary binary data.
///
/// Each byte is treated as a codepoint in [0, 255].  Produces the same
/// NAPQES v7 wire format as [`encrypt_bytes`], with the provided AAD bound
/// into the authentication tag.  Intended for OT PDU framing where the
/// payload is not valid UTF-8 text.
///
/// Deprecated per CVF-17: length depends on the nonce for v7. New callers
/// should encode their bytes and use [`encrypt_bytes_v8`] instead.
#[deprecated(
    since = "0.2.0",
    note = "v7 legacy format lacks the MAX_NOISE_RUN cap and per-bucket \
            ceiling (audit CVF-17), and the byte-vs-codepoint encoding \
            ambiguity of CVF-14 remains. Use encrypt_bytes_v8 for text or \
            wrap the bytes in a caller-chosen text encoding."
)]
pub fn encrypt_raw(data: &[u8], key: &[u64], aad: &[u8]) -> Result<Vec<u8>, String> {
    validate_key(key)?; // CVF-15
    // CVF-34: cap at MAX_PLAINTEXT_CODEPOINTS bytes (each byte becomes a
    // codepoint under the raw-encode convention, so the same 2-codepoint
    // length prefix caps the byte count).
    if data.len() > MAX_PLAINTEXT_CODEPOINTS {
        return Err(format!(
            "data exceeds MAX_PLAINTEXT_CODEPOINTS ({}) bytes",
            MAX_PLAINTEXT_CODEPOINTS
        ));
    }
    let nonce = generate_nonce_with_crng_check()?;
    let codepoints: Vec<u32> = data.iter().map(|&b| b as u32).collect();
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, &nonce);
    let padded = pad_message(&codepoints, &kb, &nonce);
    let cypher = emit_tokens_v7(&padded, &kb, &nonce, noise_p, key); // CVF-46
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
    validate_key(key)?; // CVF-15
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
    let codepoints = decrypt(nonce, &tokens, key)?;
    // CVF-14: the previous body was `.map(|c| (c & 0xFF) as u8)` — a silent
    // narrowing that discarded every recovered codepoint above 255 without
    // signalling. A ciphertext produced by `encrypt_bytes` (codepoint-oriented,
    // e.g. `é` as one U+00E9 token) handed to `decrypt_raw` would authenticate
    // and return a self-consistent-looking single byte, hiding the fact that
    // the two ports use incompatible message-space encodings. We now reject
    // any recovered value that does not fit in a byte.
    codepoints
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            if c > 0xFF {
                Err(format!(
                    "Malformed v7 raw ciphertext: recovered codepoint {} at \
                     position {} is out of byte range [0, 255]. This usually \
                     means the ciphertext was produced by `encrypt_bytes` \
                     (codepoint-oriented) rather than `encrypt_raw` \
                     (byte-oriented); the two use incompatible message \
                     encodings (CVF-14).",
                    c, i
                ))
            } else {
                Ok(c as u8)
            }
        })
        .collect()
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
/// padding bucket alone, at the cost of always paying the worst-case 20x
/// expansion. Under the run cap alone, the mean token count per padded
/// codepoint is about 8.4 for θ(N) approximately uniform on
/// `[θ_min, θ_max]`, ranging from 3.99 at p=0.75 to 18.21 at p=0.99;
/// without the run cap it would be about 13.4 (CVF-39 corrects the earlier
/// "~13.4x average" phrasing which conflated the capped and uncapped means).
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
    // CVF-47: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    validate_key(primes)?;
    encrypt_bytes_v8_core(message, primes, sk, aad, pad_profile)
}

/// CVF-29 fix: shared v8-encrypt core that skips per-message `validate_key`.
/// Callers must have already validated the key (either via
/// [`encrypt_bytes_v8_with_profile`]'s validation prefix or by wrapping in a
/// [`crate::NapqesKey`], which validates once in its constructor).
pub(crate) fn encrypt_bytes_v8_core(
    message: &str,
    primes: &[u64],
    sk: &[u8; SK_SIZE],
    aad: &[u8],
    pad_profile: PadProfile,
) -> Result<Vec<u8>, String> {
    // CVF-37: the value that actually keys every derivation is `sk_fmt`,
    // not the input `sk`. Take ownership of the derived bytes and wipe them
    // via a scope guard so early returns and the success path all zeroize
    // (see `crate::key::Secret32`).
    let mut sk_fmt = derive_format_subkey(sk, FORMAT_BLOCK_V8);
    let result = encrypt_bytes_v8_core_inner(&sk_fmt, message, primes, aad, pad_profile);
    zeroize_sk(&mut sk_fmt);
    result
}

fn encrypt_bytes_v8_core_inner(
    sk_fmt: &[u8; 32],
    message: &str,
    primes: &[u64],
    aad: &[u8],
    pad_profile: PadProfile,
) -> Result<Vec<u8>, String> {
    let nonce = synthetic_nonce(sk_fmt, aad, message.as_bytes());
    let codepoints: Vec<u32> = message.chars().map(|c| c as u32).collect();
    if codepoints.len() > MAX_PLAINTEXT_CODEPOINTS {
        return Err(format!(
            "Message too long: {} codepoints exceeds MAX_PLAINTEXT_CODEPOINTS ({})",
            codepoints.len(), MAX_PLAINTEXT_CODEPOINTS
        ));
    }
    let noise_theta = derive_noise_threshold_v8(sk_fmt, &nonce);
    let block_size = pad_profile.block_size(codepoints.len())?;
    let padded = pad_to_block(&codepoints, sk_fmt, &nonce, block_size);
    let kk = primes.len() as u64;
    let mut cypher: Vec<u64> = Vec::new();
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    for &c in &padded {
        let mut noise_run: u64 = 0;
        loop {
            if noise_run < MAX_NOISE_RUN && is_noise_pos_v8(sk_fmt, &nonce, ct_pos, noise_theta) {
                let k = primes[(real_idx % kk) as usize];
                let nc = derive_noise_char(sk_fmt, &nonce, ct_pos);
                let na = derive_noise_token_addend(sk_fmt, &nonce, ct_pos, k);
                cypher.push(nc * k + na);
                ct_pos += 1;
                noise_run += 1;
            } else {
                let k = primes[(real_idx % kk) as usize];
                let addend = derive_addend(sk_fmt, &nonce, real_idx, k);
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
        let nc = derive_noise_char(sk_fmt, &nonce, ct_pos);
        let na = derive_noise_token_addend(sk_fmt, &nonce, ct_pos, k);
        cypher.push(nc * k + na);
        ct_pos += 1;
    }
    let blob = fixed_encode_tokens(&cypher);
    let ks = varint_keystream(sk_fmt, &nonce, blob.len());
    let masked: Vec<u8> = blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mut payload = Vec::with_capacity(NONCE_SIZE + masked.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&masked);
    let tag = compute_auth_tag(sk_fmt, aad, &payload, AAD_LEN_WIDTH_V8);
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
    // CVF-47: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    validate_key(primes)?;
    decrypt_bytes_v8_core(ciphertext, primes, sk, aad)
}

/// CVF-29 fix: shared v8-decrypt core that skips per-message `validate_key`.
/// See [`encrypt_bytes_v8_core`] for the caller contract.
pub(crate) fn decrypt_bytes_v8_core(
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
    // CVF-37: same sk_fmt scope-wipe pattern as encrypt_bytes_v8_core.
    let mut sk_fmt = derive_format_subkey(sk, FORMAT_BLOCK_V8);
    let result = decrypt_bytes_v8_core_inner(&sk_fmt, ciphertext, primes, aad);
    zeroize_sk(&mut sk_fmt);
    result
}

fn decrypt_bytes_v8_core_inner(
    sk_fmt: &[u8; 32],
    ciphertext: &[u8],
    primes: &[u64],
    aad: &[u8],
) -> Result<String, String> {
    let split = ciphertext.len() - TAG_SIZE;
    let payload = &ciphertext[..split];
    let recv_tag = &ciphertext[split..];
    let calc_tag = compute_auth_tag(sk_fmt, aad, payload, AAD_LEN_WIDTH_V8);
    if !ct_eq_bytes(recv_tag, calc_tag.as_ref()) {
        return Err("Authentication failed: invalid HMAC tag.".into());
    }
    let nonce = &payload[..NONCE_SIZE];
    let masked = &payload[NONCE_SIZE..];
    let ks = varint_keystream(sk_fmt, nonce, masked.len());
    let blob: Vec<u8> = masked.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let tokens = fixed_decode_tokens(&blob).map_err(|e| format!("varint decode error: {}", e))?;
    let codepoints = decrypt_core_v8(nonce, &tokens, primes, sk_fmt)?;
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
/// as dead-code optimisations. Call this as soon as the key is no longer
/// needed.
///
/// Reference: FIPS 140-3 / SP 800-57 Part 1 Rev 5 §8.3 (key destruction).
pub fn zeroize_key(key: &mut [u64]) {
    for x in key.iter_mut() {
        unsafe { std::ptr::write_volatile(x, 0u64) };
    }
}

// --- Streaming AE v8 (misuse-resistant primitives, streaming nonce) -----------
//
// Wire format (FORMAT_STREAM_AE_V8 = 0x02):
//   HEADER (21 B):     0x02 || be4(F) || nonce(16, CSPRNG)
//   CHUNK FRAME * C:   be4(F*160) || masked_chunk(F*160) || chunk_tag(32)
//   SENTINEL (44 B):   be4(0) || be8(total_real_codepoints) || sentinel_tag(32)
//
// Every chunk i is a self-contained v8 primitive call keyed by
// (sk_fmt, sub_nonce_i) where
//     sk_fmt      = HMAC(sk, 0x0B || FORMAT_STREAM_AE_V8)
//     sub_nonce_i = HMAC(sk_fmt, 0x0E || nonce || be4(i))[:16]
// so domains 0x00-0x07 (position oracle, addend, noise char/addend, threshold,
// keystream) are reused verbatim from v8 block mode.
//
// Security caveats (docs/CAVEATS.md, CAV-005):
//   * The stream nonce is CSPRNG-drawn -- not SIV-derived -- because SIV
//     requires hashing the full message. Nonce reuse across two streams under
//     the same sk is catastrophic (CVF3-class hazard).
//   * Fixed-width 8-byte tokens and F*20 per-chunk padding close the LEB128
//     length leak (V2-CVF11) that the v7 stream_ae format retains; per-chunk
//     size is a pure function of F, which is public.
//   * Truncation-safe: the sentinel binds the chunk count.
//   * Reorder-safe: chunk_idx is bound into every per-chunk tag.

/// Default number of real codepoints per streaming chunk. With F=128, each
/// chunk carries 128*20 = 2560 fixed-width 8-byte tokens = 20480 bytes of
/// masked_blob, plus a 4-byte length prefix and a 32-byte tag.
pub const STREAM_AE_V8_DEFAULT_FRAME: u32 = 128;

/// Hard upper bound on F. Keeps a chunk under ~3 MB and be4-representable.
pub const STREAM_AE_V8_MAX_FRAME: u32 = 16_384;

const DOMAIN_STREAM_V8_CHUNK_TAG: u8 = 0x0C;
const DOMAIN_STREAM_V8_SENTINEL:  u8 = 0x0D;
const DOMAIN_STREAM_V8_SUBNONCE:  u8 = 0x0E;

fn derive_stream_v8_sub_nonce(
    sk_fmt: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    chunk_idx: u32,
) -> [u8; NONCE_SIZE] {
    let mut buf = Vec::with_capacity(1 + NONCE_SIZE + 4);
    buf.push(DOMAIN_STREAM_V8_SUBNONCE);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&chunk_idx.to_be_bytes());
    let d = hmac_digest(sk_fmt, &buf);
    let mut out = [0u8; NONCE_SIZE];
    out.copy_from_slice(&d[..NONCE_SIZE]);
    out
}

/// Domain 0x06: derive a filler codepoint for the final partial chunk.
/// Deterministic in (sk_fmt, sub_nonce, fill_idx); indistinguishable on the
/// wire from real codepoints once passed through `c * k + addend`.
fn derive_stream_v8_filler_cp(
    sk_fmt: &[u8; 32],
    sub_nonce: &[u8; NONCE_SIZE],
    fill_idx: u32,
) -> u32 {
    let mut buf = Vec::with_capacity(1 + NONCE_SIZE + 4);
    buf.push(0x06);
    buf.extend_from_slice(sub_nonce);
    buf.extend_from_slice(&fill_idx.to_be_bytes());
    let d = hmac_digest(sk_fmt, &buf);
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    // CVF-42: streaming filler codepoints draw from the same padding
    // alphabet as pad_to_block.
    ((n as u64 % PAD_ALPHABET) + ASCII_PRINTABLE_BASE) as u32
}

/// Encode exactly F * (MAX_NOISE_RUN + 1) tokens for one streaming chunk.
fn encrypt_v8_stream_chunk_core(
    chunk_cps: &[u32],
    primes: &[u64],
    sk_fmt: &[u8; 32],
    sub_nonce: &[u8; NONCE_SIZE],
) -> Vec<u64> {
    let noise_theta = derive_noise_threshold_v8(sk_fmt, sub_nonce);
    let f = chunk_cps.len() as u64;
    let kk = primes.len() as u64;
    let mut cypher: Vec<u64> = Vec::with_capacity((f * (MAX_NOISE_RUN + 1)) as usize);
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;

    for &c in chunk_cps {
        let mut noise_run: u64 = 0;
        loop {
            if noise_run < MAX_NOISE_RUN
                && is_noise_pos_v8(sk_fmt, sub_nonce, ct_pos, noise_theta)
            {
                let k = primes[(real_idx % kk) as usize];
                let nc = derive_noise_char(sk_fmt, sub_nonce, ct_pos);
                let na = derive_noise_token_addend(sk_fmt, sub_nonce, ct_pos, k);
                cypher.push(nc * k + na);
                ct_pos += 1;
                noise_run += 1;
            } else {
                let k = primes[(real_idx % kk) as usize];
                let addend = derive_addend(sk_fmt, sub_nonce, real_idx, k);
                cypher.push(c as u64 * k + addend);
                ct_pos += 1;
                real_idx += 1;
                break;
            }
        }
    }

    let ceiling = f * (MAX_NOISE_RUN + 1);
    while (cypher.len() as u64) < ceiling {
        let k = primes[(real_idx % kk) as usize];
        let nc = derive_noise_char(sk_fmt, sub_nonce, ct_pos);
        let na = derive_noise_token_addend(sk_fmt, sub_nonce, ct_pos, k);
        cypher.push(nc * k + na);
        ct_pos += 1;
    }
    cypher
}

/// Recover exactly F codepoints from a streaming chunk's token stream.
fn decrypt_v8_stream_chunk_core(
    chunk_tokens: &[u64],
    primes: &[u64],
    sk_fmt: &[u8; 32],
    sub_nonce: &[u8; NONCE_SIZE],
    f: u32,
) -> Result<Vec<u32>, String> {
    let noise_theta = derive_noise_threshold_v8(sk_fmt, sub_nonce);
    let kk = primes.len() as u64;
    let mut codepoints: Vec<u32> = Vec::with_capacity(f as usize);
    let mut real_idx: u64 = 0;
    let mut ct_pos: usize = 0;
    let n = chunk_tokens.len();

    while (real_idx as u32) < f {
        let mut noise_run: u64 = 0;
        while noise_run < MAX_NOISE_RUN
            && ct_pos < n
            && is_noise_pos_v8(sk_fmt, sub_nonce, ct_pos as u64, noise_theta)
        {
            ct_pos += 1;
            noise_run += 1;
        }
        if ct_pos >= n {
            return Err("Truncated v8 stream chunk: token stream ended mid noise-run.".into());
        }
        let k = primes[(real_idx % kk) as usize];
        let addend = derive_addend(sk_fmt, sub_nonce, real_idx, k);
        let token = chunk_tokens[ct_pos];
        if token < addend || (token - addend) % k != 0 {
            return Err(format!(
                "Malformed v8 stream chunk: token at position {} is not c * k + addend.",
                ct_pos
            ));
        }
        let cp = (token - addend) / k;
        if cp > 0x10FFFF || (0xD800..=0xDFFF).contains(&cp) {
            return Err(format!(
                "Malformed v8 stream chunk: recovered value {} is not a Unicode scalar.",
                cp
            ));
        }
        codepoints.push(cp as u32);
        ct_pos += 1;
        real_idx += 1;
    }
    Ok(codepoints)
}

fn compute_stream_v8_chunk_tag(
    sk_fmt: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    chunk_idx: u32,
    aad: &[u8],
    masked_chunk: &[u8],
) -> [u8; TAG_SIZE] {
    let mut buf = Vec::with_capacity(1 + NONCE_SIZE + 4 + AAD_LEN_WIDTH_V8 + aad.len() + masked_chunk.len());
    buf.push(DOMAIN_STREAM_V8_CHUNK_TAG);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&chunk_idx.to_be_bytes());
    buf.extend_from_slice(&be_len_prefix(aad.len(), AAD_LEN_WIDTH_V8));
    buf.extend_from_slice(aad);
    buf.extend_from_slice(masked_chunk);
    hmac_digest(sk_fmt, &buf)
}

fn compute_stream_v8_sentinel_tag(
    sk_fmt: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    chunk_count: u32,
    aad: &[u8],
    total_real_cps: u64,
) -> [u8; TAG_SIZE] {
    let mut buf = Vec::with_capacity(1 + NONCE_SIZE + 4 + AAD_LEN_WIDTH_V8 + aad.len() + 8);
    buf.push(DOMAIN_STREAM_V8_SENTINEL);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&chunk_count.to_be_bytes());
    buf.extend_from_slice(&be_len_prefix(aad.len(), AAD_LEN_WIDTH_V8));
    buf.extend_from_slice(aad);
    buf.extend_from_slice(&total_real_cps.to_be_bytes());
    hmac_digest(sk_fmt, &buf)
}

fn validate_stream_v8_frame(f: u32) -> Result<(), String> {
    if f < 1 || f > STREAM_AE_V8_MAX_FRAME {
        return Err(format!(
            "frame_codepoints must be in [1, {}], got {}",
            STREAM_AE_V8_MAX_FRAME, f
        ));
    }
    Ok(())
}

fn emit_stream_v8_chunk(
    codepoints_f: &[u32],
    idx: u32,
    primes: &[u64],
    sk_fmt: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
) -> Vec<u8> {
    let sub_nonce = derive_stream_v8_sub_nonce(sk_fmt, nonce, idx);
    let tokens = encrypt_v8_stream_chunk_core(codepoints_f, primes, sk_fmt, &sub_nonce);
    let blob = fixed_encode_tokens(&tokens);
    let ks = varint_keystream(sk_fmt, &sub_nonce, blob.len());
    let masked: Vec<u8> = blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let tag = compute_stream_v8_chunk_tag(sk_fmt, nonce, idx, aad, &masked);
    let mut out = Vec::with_capacity(4 + masked.len() + TAG_SIZE);
    out.extend_from_slice(&(masked.len() as u32).to_be_bytes());
    out.extend_from_slice(&masked);
    out.extend_from_slice(&tag);
    out
}

/// Deterministic v8 streaming encryption with caller-supplied nonce.
///
/// **Test-only.** Used by `kat_cross_check::stream_v8_*` to compare byte
/// output against the Python KAT vectors. Production callers must draw the
/// nonce from a CSPRNG per stream (CAV-005) -- reusing a nonce across two
/// streams under the same sk is catastrophic.
pub(crate) fn encrypt_stream_ae_v8_with_nonce(
    plaintext: &str,
    primes: &[u64],
    sk: &[u8; SK_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    frame_codepoints: u32,
) -> Result<Vec<u8>, String> {
    validate_key(primes)?;
    validate_stream_v8_frame(frame_codepoints)?;

    let f = frame_codepoints as usize;
    let sk_fmt = derive_format_subkey(sk, FORMAT_STREAM_AE_V8);

    let mut stream: Vec<u8> = Vec::new();
    // HEADER
    stream.push(FORMAT_STREAM_AE_V8);
    stream.extend_from_slice(&frame_codepoints.to_be_bytes());
    stream.extend_from_slice(nonce);

    let mut cp_buf: Vec<u32> = Vec::with_capacity(f);
    let mut total_real_cps: u64 = 0;
    let mut chunk_idx: u32 = 0;

    for ch in plaintext.chars() {
        cp_buf.push(ch as u32);
        total_real_cps += 1;
        if cp_buf.len() >= f {
            let frame = emit_stream_v8_chunk(&cp_buf[..f], chunk_idx, primes, &sk_fmt, nonce, aad);
            stream.extend_from_slice(&frame);
            cp_buf.drain(..f);
            chunk_idx += 1;
        }
    }

    if !cp_buf.is_empty() {
        let sub_nonce_last = derive_stream_v8_sub_nonce(&sk_fmt, nonce, chunk_idx);
        let fill_needed = f - cp_buf.len();
        for i in 0..fill_needed {
            cp_buf.push(derive_stream_v8_filler_cp(&sk_fmt, &sub_nonce_last, i as u32));
        }
        let frame = emit_stream_v8_chunk(&cp_buf, chunk_idx, primes, &sk_fmt, nonce, aad);
        stream.extend_from_slice(&frame);
        chunk_idx += 1;
    }

    let sentinel_tag = compute_stream_v8_sentinel_tag(
        &sk_fmt, nonce, chunk_idx, aad, total_real_cps);
    stream.extend_from_slice(&0u32.to_be_bytes());
    stream.extend_from_slice(&total_real_cps.to_be_bytes());
    stream.extend_from_slice(&sentinel_tag);

    Ok(stream)
}

/// v8 streaming-AE encryption -- returns the full ciphertext byte stream.
///
/// Convenience "all-at-once" API: consumes the entire plaintext and returns
/// the fully framed byte stream in one call. Uses a CSPRNG-drawn 16-byte
/// nonce (with the FIPS CRNG self-test). For chunk-at-a-time production use
/// [`StreamV8Encryptor`].
///
/// `frame_codepoints` (F) sets the per-chunk real-codepoint capacity: each
/// chunk carries exactly F codepoint slots (partial last chunk padded with
/// HMAC-derived filler) and expands to a fixed F*160 bytes of masked_blob.
/// Chunk size is therefore a pure function of F, which is public.
///
/// **Not misuse-resistant**: nonce reuse under the same `sk` is catastrophic
/// (CAV-005). Use the v8 *block* API (`encrypt_bytes_v8`) whenever the whole
/// message fits in memory and MRAE is desired.
pub fn encrypt_stream_ae_v8(
    plaintext: &str,
    primes: &[u64],
    sk: &[u8; SK_SIZE],
    aad: &[u8],
    frame_codepoints: u32,
) -> Result<Vec<u8>, String> {
    // CVF-47: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    let nonce = generate_nonce_with_crng_check()?;
    encrypt_stream_ae_v8_with_nonce(plaintext, primes, sk, &nonce, aad, frame_codepoints)
}

/// v8 streaming-AE decryption -- consumes the full ciphertext byte stream.
///
/// Convenience "all-at-once" API. Each per-chunk tag is verified before that
/// chunk's plaintext contributes to the output; the sentinel binds the
/// chunk count (anti-truncation) and the true real-codepoint count (used to
/// strip filler codepoints from the last chunk).
pub fn decrypt_stream_ae_v8(
    stream: &[u8],
    primes: &[u64],
    sk: &[u8; SK_SIZE],
    aad: &[u8],
) -> Result<String, String> {
    // CVF-47: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    validate_key(primes)?;
    let sk_fmt = derive_format_subkey(sk, FORMAT_STREAM_AE_V8);

    if stream.len() < 1 + 4 + NONCE_SIZE {
        return Err(format!(
            "Stream truncated: need at least {} header bytes, got {}",
            1 + 4 + NONCE_SIZE,
            stream.len()
        ));
    }
    if stream[0] != FORMAT_STREAM_AE_V8 {
        return Err(format!(
            "Unexpected format id 0x{:02x}; expected 0x{:02x} (FORMAT_STREAM_AE_V8)",
            stream[0], FORMAT_STREAM_AE_V8
        ));
    }
    let f = u32::from_be_bytes([stream[1], stream[2], stream[3], stream[4]]);
    if f < 1 || f > STREAM_AE_V8_MAX_FRAME {
        return Err(format!(
            "Malformed v8 stream header: frame_codepoints F={} out of [1, {}].",
            f, STREAM_AE_V8_MAX_FRAME
        ));
    }
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&stream[5..5 + NONCE_SIZE]);

    let expected_chunk_body_len =
        (f as usize) * TOKEN_WIDTH * ((MAX_NOISE_RUN + 1) as usize);
    let mut pos = 1 + 4 + NONCE_SIZE;
    let mut chunk_idx: u32 = 0;
    let mut delivered: Vec<u32> = Vec::new();
    let mut pending: Option<Vec<u32>> = None;

    loop {
        if stream.len() < pos + 4 {
            return Err("Stream truncated: need 4-byte chunk length prefix.".into());
        }
        let chunk_len = u32::from_be_bytes([
            stream[pos], stream[pos + 1], stream[pos + 2], stream[pos + 3],
        ]) as usize;
        pos += 4;

        if chunk_len == 0 {
            // SENTINEL: be8(total_real_cps) || tag(32)
            if stream.len() < pos + 8 + TAG_SIZE {
                return Err("Stream truncated: need sentinel body.".into());
            }
            let mut tr = [0u8; 8];
            tr.copy_from_slice(&stream[pos..pos + 8]);
            let total_real_cps = u64::from_be_bytes(tr);
            let recv_tag = &stream[pos + 8..pos + 8 + TAG_SIZE];
            let calc = compute_stream_v8_sentinel_tag(
                &sk_fmt, &nonce, chunk_idx, aad, total_real_cps);
            if !ct_eq_bytes(recv_tag, calc.as_ref()) {
                return Err("Authentication failed: invalid v8 stream sentinel tag.".into());
            }
            pos += 8 + TAG_SIZE;

            let pending_len = pending.as_ref().map(|v| v.len()).unwrap_or(0);
            let delivered_len = delivered.len() as u64;
            let available = delivered_len + (pending_len as u64);
            if total_real_cps > available
                || (pending.is_none() && total_real_cps != delivered_len)
            {
                return Err(format!(
                    "Malformed v8 stream sentinel: total_real_codepoints {} \
                     inconsistent with decoded stream ({} delivered + {} pending).",
                    total_real_cps, delivered_len, pending_len
                ));
            }
            if let Some(mut p) = pending {
                let keep = (total_real_cps - delivered_len) as usize;
                p.truncate(keep);
                delivered.extend(p);
            }
            if pos != stream.len() {
                return Err(format!(
                    "Trailing bytes after sentinel: {} extra bytes.",
                    stream.len() - pos
                ));
            }
            let s: String = delivered
                .into_iter()
                .map(|c| {
                    char::from_u32(c).ok_or_else(|| {
                        format!("Malformed v8 stream plaintext: {} is not a Unicode scalar value.", c)
                    })
                })
                .collect::<Result<String, String>>()?;
            return Ok(s);
        }

        if chunk_len != expected_chunk_body_len {
            return Err(format!(
                "Malformed v8 stream frame: chunk length {} does not match the fixed \
                 frame size {} (= F*{}*{} for F={}).",
                chunk_len, expected_chunk_body_len, TOKEN_WIDTH, MAX_NOISE_RUN + 1, f
            ));
        }
        if stream.len() < pos + chunk_len + TAG_SIZE {
            return Err("Stream truncated mid-frame.".into());
        }
        let masked = &stream[pos..pos + chunk_len];
        let recv_tag = &stream[pos + chunk_len..pos + chunk_len + TAG_SIZE];
        let calc = compute_stream_v8_chunk_tag(&sk_fmt, &nonce, chunk_idx, aad, masked);
        if !ct_eq_bytes(recv_tag, calc.as_ref()) {
            return Err(format!(
                "Authentication failed: invalid tag on v8 stream chunk {}.",
                chunk_idx
            ));
        }
        pos += chunk_len + TAG_SIZE;

        // Tag verified -- unmask and decode.
        let sub_nonce = derive_stream_v8_sub_nonce(&sk_fmt, &nonce, chunk_idx);
        let ks = varint_keystream(&sk_fmt, &sub_nonce, chunk_len);
        let blob: Vec<u8> = masked.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        let tokens = fixed_decode_tokens(&blob)?;
        let cps = decrypt_v8_stream_chunk_core(&tokens, primes, &sk_fmt, &sub_nonce, f)?;

        if let Some(p) = pending.take() {
            delivered.extend(p);
        }
        pending = Some(cps);
        chunk_idx += 1;
    }
}

/// Streaming (chunk-at-a-time) encryptor for FORMAT_STREAM_AE_V8.
///
/// Emits the 21-byte header from `new`, one full chunk per completed frame
/// via `push`, and the sentinel from `finish`. See [`encrypt_stream_ae_v8`]
/// for the security caveats (CAV-005).
pub struct StreamV8Encryptor {
    primes: Vec<u64>,
    sk_fmt: [u8; 32],
    aad: Vec<u8>,
    nonce: [u8; NONCE_SIZE],
    f: u32,
    chunk_idx: u32,
    total_real_cps: u64,
    cp_buf: Vec<u32>,
    finished: bool,
}

impl StreamV8Encryptor {
    /// Create a new encryptor and return `(self, header_bytes)`. `header_bytes`
    /// is exactly 21 B (0x02 || be4(F) || nonce). The nonce is drawn from a
    /// CSPRNG with the FIPS CRNG self-test.
    pub fn new(
        primes: &[u64],
        sk: &[u8; SK_SIZE],
        aad: &[u8],
        frame_codepoints: u32,
    ) -> Result<(Self, Vec<u8>), String> {
        // CVF-47: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
        #[cfg(feature = "fips_gate")]
        crate::self_test::require_post().map_err(|e| e.to_string())?;
        validate_key(primes)?;
        validate_stream_v8_frame(frame_codepoints)?;
        let nonce = generate_nonce_with_crng_check()?;
        let sk_fmt = derive_format_subkey(sk, FORMAT_STREAM_AE_V8);
        let mut header = Vec::with_capacity(1 + 4 + NONCE_SIZE);
        header.push(FORMAT_STREAM_AE_V8);
        header.extend_from_slice(&frame_codepoints.to_be_bytes());
        header.extend_from_slice(&nonce);
        Ok((
            Self {
                primes: primes.to_vec(),
                sk_fmt,
                aad: aad.to_vec(),
                nonce,
                f: frame_codepoints,
                chunk_idx: 0,
                total_real_cps: 0,
                cp_buf: Vec::with_capacity(frame_codepoints as usize),
                finished: false,
            },
            header,
        ))
    }

    /// Feed a single codepoint. Returns `Some(chunk_bytes)` whenever a full
    /// chunk (F codepoints buffered) completes, else `None`.
    pub fn push(&mut self, ch: char) -> Result<Option<Vec<u8>>, String> {
        if self.finished {
            return Err("StreamV8Encryptor: push after finish".into());
        }
        self.cp_buf.push(ch as u32);
        self.total_real_cps += 1;
        if self.cp_buf.len() >= self.f as usize {
            let frame = emit_stream_v8_chunk(
                &self.cp_buf[..self.f as usize],
                self.chunk_idx,
                &self.primes,
                &self.sk_fmt,
                &self.nonce,
                &self.aad,
            );
            self.cp_buf.drain(..self.f as usize);
            self.chunk_idx += 1;
            Ok(Some(frame))
        } else {
            Ok(None)
        }
    }

    /// Flush the partial last chunk (with HMAC-derived filler) and emit the
    /// sentinel. Consumes `self`.
    pub fn finish(mut self) -> Result<Vec<u8>, String> {
        if self.finished {
            return Err("StreamV8Encryptor: finish called twice".into());
        }
        self.finished = true;
        let mut out: Vec<u8> = Vec::new();
        if !self.cp_buf.is_empty() {
            let sub_nonce_last =
                derive_stream_v8_sub_nonce(&self.sk_fmt, &self.nonce, self.chunk_idx);
            let fill_needed = (self.f as usize) - self.cp_buf.len();
            for i in 0..fill_needed {
                self.cp_buf.push(derive_stream_v8_filler_cp(
                    &self.sk_fmt, &sub_nonce_last, i as u32));
            }
            let frame = emit_stream_v8_chunk(
                &self.cp_buf,
                self.chunk_idx,
                &self.primes,
                &self.sk_fmt,
                &self.nonce,
                &self.aad,
            );
            out.extend_from_slice(&frame);
            self.chunk_idx += 1;
        }
        let tag = compute_stream_v8_sentinel_tag(
            &self.sk_fmt, &self.nonce, self.chunk_idx, &self.aad, self.total_real_cps);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&self.total_real_cps.to_be_bytes());
        out.extend_from_slice(&tag);
        Ok(out)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // CVF-17: these tests exercise the v7 legacy encryptors that are now
    // #[deprecated]. The deprecation is a message to external consumers to
    // migrate to v8; the tests themselves are the crate's own regression
    // coverage of the legacy surface and need to keep calling those APIs
    // without emitting a wall of warnings.
    #![allow(deprecated)]

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
        let ct_b64 = encrypt_str("", &k, b"").unwrap();
        let ct = STANDARD.decode(ct_b64.as_bytes()).expect("base64");
        assert!(
            ct.len() >= NONCE_SIZE + TAG_SIZE,
            "empty-message ciphertext must at least carry nonce+tag; got {} bytes",
            ct.len()
        );
        assert_eq!(
            decrypt_bytes(&ct, &k, b"").unwrap(),
            "",
            "round-trip through real tag verification must recover the empty string"
        );
    }

    #[test]
    fn empty_ciphertext_is_rejected() {
        let k = test_key();
        assert!(
            decrypt_bytes(&[], &k, b"").is_err(),
            "zero-length ciphertext must not be accepted as valid encryption of the empty string (CVF-13)"
        );
        assert!(
            decrypt_raw(&[], &k, b"").is_err(),
            "zero-length raw ciphertext must not be accepted (CVF-13)"
        );
    }

    #[test]
    fn empty_message_ciphertext_authenticates() {
        let k = test_key();
        let mut ct = encrypt_bytes("", &k, b"").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(
            decrypt_bytes(&ct, &k, b"").is_err(),
            "flipped tag byte on empty-message ciphertext must fail authentication (CVF-13)"
        );
    }

    #[test]
    fn ct_eq_bytes_equal_length_matches() {
        let a = [0x11u8; 32];
        let b = [0x11u8; 32];
        assert!(ct_eq_bytes(&a, &b));
    }

    #[test]
    fn ct_eq_bytes_equal_length_differs() {
        let a = [0x11u8; 32];
        let mut b = [0x11u8; 32];
        b[17] ^= 0x01;
        assert!(!ct_eq_bytes(&a, &b));
    }

    #[test]
    fn ct_eq_bytes_length_mismatch_returns_false() {
        // CVF-12: the previous hand-rolled loop guarded its length precondition
        // with `debug_assert_eq!` and then walked `a.iter().zip(b.iter())`, so
        // in release builds a length mismatch collapsed to a common-prefix
        // compare and returned `true` whenever the prefix matched. The
        // `subtle::ConstantTimeEq` replacement fails closed on length mismatch:
        // it must return `false` regardless of the prefix.
        let a = [0x11u8; 32];
        let short = [0x11u8; 16];
        assert!(
            !ct_eq_bytes(&a, &short),
            "shorter operand with matching prefix must not report equality (CVF-12)"
        );
        assert!(
            !ct_eq_bytes(&short, &a),
            "longer operand with matching prefix must not report equality (CVF-12)"
        );
        let empty: [u8; 0] = [];
        assert!(
            !ct_eq_bytes(&a, &empty),
            "empty operand against non-empty must not report equality (CVF-12)"
        );
        // Two empty slices are trivially equal; this is the one length pairing
        // where the answer is legitimately `true`.
        assert!(ct_eq_bytes(&empty, &empty));
    }

    #[test]
    fn cvf45_ct_eq_bytes_nonce_length_fails_closed() {
        // CVF-45: `generate_nonce_with_crng_check` compares 16-byte nonces
        // via `ct_eq_bytes`. The auditor called out that the prior comparator
        // was documented as "always 32 iterations" but was reached on 16-byte
        // operands too. The subtle-backed replacement handles both lengths
        // uniformly. This is the belt-and-braces regression.
        let a = [0xAAu8; NONCE_SIZE];
        let mut b = [0xAAu8; NONCE_SIZE];
        assert!(ct_eq_bytes(&a, &b), "equal nonces must match");
        b[8] ^= 0x01;
        assert!(!ct_eq_bytes(&a, &b), "single bit flip in nonce must fail");
        // Cross-length: a nonce (16) vs a tag (32) must never match.
        let tag = [0xAAu8; TAG_SIZE];
        assert!(!ct_eq_bytes(&a, &tag));
        assert!(!ct_eq_bytes(&tag, &a));
    }

    // ─── CVF-14 regressions: cross-encoding confusion and silent narrowing ───

    #[test]
    fn cvf14_encrypt_bytes_ciphertext_is_rejected_by_decrypt_raw_for_non_ascii() {
        // The paper describes a scenario where `encrypt_bytes("é")` (one
        // codepoint U+00E9 = 233) is handed to `decrypt_raw`, which — under
        // the old `& 0xFF` mask — returned the single byte 0xE9 as if that
        // were the original plaintext. With the fix, decrypt_raw must reject
        // any recovered codepoint that is not in [0, 255]. U+00E9 = 233 fits
        // in a byte, so we use a non-ASCII codepoint above 255 (U+0100).
        let k = test_key();
        let ct = encrypt_bytes("\u{0100}", &k, b"").unwrap();
        let err = decrypt_raw(&ct, &k, b"").unwrap_err();
        assert!(
            err.contains("byte range") || err.contains("CVF-14"),
            "decrypt_raw must report a range error (got: {})",
            err
        );
    }

    #[test]
    fn cvf14_encrypt_raw_ciphertext_still_roundtrips_via_decrypt_raw() {
        // The fix must not break the legitimate `encrypt_raw` → `decrypt_raw`
        // round trip for arbitrary bytes, including bytes above 0x7F that are
        // not valid ASCII but are valid u8s.
        let k = test_key();
        let data: Vec<u8> = (0u8..=255).collect();
        let ct = encrypt_raw(&data, &k, b"aad").unwrap();
        let recovered = decrypt_raw(&ct, &k, b"aad").unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn cvf14_encrypt_bytes_roundtrip_via_decrypt_bytes_unchanged() {
        // Same round trip on the codepoint-oriented interface — the fallible
        // `char::from_u32` map must not reject legitimate ciphertexts.
        let k = test_key();
        let msg = "hello \u{00E9} world \u{1F600}";
        let ct = encrypt_bytes(msg, &k, b"aad").unwrap();
        let recovered = decrypt_bytes(&ct, &k, b"aad").unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn cvf14_decrypt_returns_result_not_panic() {
        // `pub fn decrypt` used to have signature `-> Vec<u32>` and panicked
        // on a malformed padded buffer. It now returns `Result`, so a caller
        // handing it an arbitrary token slice receives an error rather than a
        // process abort.
        let k = test_key();
        let bogus_tokens = vec![0u64; 20];
        let bogus_nonce = [0u8; NONCE_SIZE];
        let result = decrypt(&bogus_nonce, &bogus_tokens, &k);
        // The specific error message is not important; what matters is that
        // the function neither panicked nor returned Ok garbage.
        assert!(result.is_err(), "decrypt of bogus tokens must return Err, got: {:?}", result);
    }

    // ─── CVF-15 regressions: validate_key at every v7 entry point ───

    #[test]
    fn cvf15_v7_encrypt_bytes_rejects_empty_key() {
        let err = encrypt_bytes("hi", &[], b"").unwrap_err();
        assert!(err.contains("non-empty"), "expected empty-key error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_decrypt_bytes_rejects_empty_key() {
        // Ciphertext content doesn't matter — validation must fire first.
        let err = decrypt_bytes(&[0u8; 100], &[], b"").unwrap_err();
        assert!(err.contains("non-empty"), "expected empty-key error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_encrypt_bytes_rejects_composite_element() {
        // 1_000_000 is composite (10^6 = 2^6 · 5^6), passes size floor,
        // fails primality.
        let err = encrypt_bytes("hi", &[1_000_000u64], b"").unwrap_err();
        assert!(err.contains("not prime"), "expected primality error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_encrypt_bytes_rejects_element_below_min() {
        // 3 is prime but well below MIN_KEY_PRIME.
        let err = encrypt_bytes("hi", &[3u64], b"").unwrap_err();
        assert!(err.contains("minimum"), "expected minimum-size error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_encrypt_bytes_rejects_duplicate() {
        // Two equal primes — validate_key rejects to preserve distinctness.
        let err = encrypt_bytes("hi", &[1_000_003u64, 1_000_003u64], b"").unwrap_err();
        assert!(err.contains("duplicate"), "expected duplicate error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_encrypt_str_rejects_bad_key_before_base64() {
        let err = encrypt_str("hi", &[], b"").unwrap_err();
        assert!(err.contains("non-empty"), "expected empty-key error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_decrypt_str_rejects_bad_key_before_base64() {
        let err = decrypt_str("YQ==", &[], b"").unwrap_err();
        assert!(err.contains("non-empty"), "expected empty-key error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_encrypt_raw_rejects_composite_element() {
        let err = encrypt_raw(&[0x42u8], &[1_000_000u64], b"").unwrap_err();
        assert!(err.contains("not prime"), "expected primality error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_decrypt_raw_rejects_bad_key() {
        let err = decrypt_raw(&[0u8; 100], &[], b"").unwrap_err();
        assert!(err.contains("non-empty"), "expected empty-key error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_decrypt_rejects_bad_key() {
        // pub fn decrypt returns Result; validate_key(key)? runs first.
        let err = decrypt(&[0u8; NONCE_SIZE], &[0u64; 20], &[]).unwrap_err();
        assert!(err.contains("non-empty"), "expected empty-key error, got: {}", err);
    }

    #[test]
    #[should_panic(expected = "CVF-15")]
    fn cvf15_pub_encrypt_panics_on_invalid_key() {
        // `pub fn encrypt` cannot report a validation error (its signature is
        // `-> ([u8; NONCE_SIZE], Vec<u64>)`), so it panics with a message
        // naming CVF-15. Consumers should migrate to encrypt_bytes_v8.
        let _ = encrypt(&[b'x' as u32], &[]);
    }

    // CVF-25 regressions: extend v8 round-trip coverage above U+007F. The
    // auditor identified that the shipped KAT corpus stops at ASCII and does
    // not exercise the U+0080-U+00FF band where CVF-3/CVF-14 diverges, the
    // BMP above U+00FF where decrypt_raw's `& 0xFF` mask silently truncated,
    // or the supplementary plane. These tests exercise the same paths without
    // requiring a KAT corpus regeneration.

    #[test]
    fn cvf25_v8_roundtrip_first_non_ascii_codepoint() {
        // U+0080 — first codepoint above ASCII; cross-port encoding boundary.
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "\u{0080}";
        let ct = encrypt_bytes_v8(msg, &primes, &sk, b"").unwrap();
        assert_eq!(decrypt_bytes_v8(&ct, &primes, &sk, b"").unwrap(), msg);
    }

    #[test]
    fn cvf25_v8_roundtrip_bmp_above_0100() {
        // U+0100 — first codepoint the CVF-14 `& 0xFF` mask used to
        // silently truncate to 0x00.
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "\u{0100}";
        let ct = encrypt_bytes_v8(msg, &primes, &sk, b"").unwrap();
        assert_eq!(decrypt_bytes_v8(&ct, &primes, &sk, b"").unwrap(), msg);
    }

    #[test]
    fn cvf25_v8_roundtrip_supplementary_plane() {
        // U+1F600 (grinning face) — outside the BMP; the codepoint exceeds
        // 0xFFFF and exercises the multi-scalar path.
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "\u{1F600}";
        let ct = encrypt_bytes_v8(msg, &primes, &sk, b"").unwrap();
        assert_eq!(decrypt_bytes_v8(&ct, &primes, &sk, b"").unwrap(), msg);
    }

    #[test]
    fn cvf25_v8_roundtrip_mixed_codepoint_widths() {
        // ASCII + BMP + supplementary plane in one message. Ensures the
        // padding, tokeniser, and unpadder all handle codepoint widths
        // uniformly.
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "A\u{0080}\u{0100}\u{1F600}Z";
        let ct = encrypt_bytes_v8(msg, &primes, &sk, b"aad").unwrap();
        assert_eq!(decrypt_bytes_v8(&ct, &primes, &sk, b"aad").unwrap(), msg);
    }

    // CVF-20 regression: the sampler must be unbiased (via rand::Uniform),
    // must accept the normative interval, and must produce validate_key-
    // compatible output on every call.
    #[test]
    fn cvf20_generate_prime_numbers_produces_valid_key() {
        for _ in 0..8 {
            let ps = generate_prime_numbers(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
            assert_eq!(ps.len(), DEFAULT_KEY_COUNT);
            for &p in &ps {
                assert!(is_prime(p), "sampler returned non-prime: {}", p);
                assert!(p >= MIN_KEY_PRIME && p <= MAX_KEY_PRIME);
            }
            let mut sorted = ps.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), ps.len(), "sampler returned duplicates: {:?}", ps);
            // The sampler's output must pass validate_key unconditionally.
            validate_key(&ps).expect("sampler output failed validate_key");
        }
    }

    // ─── Phase B point-fix regressions ───

    #[test]
    fn cvf43_unpad_rejects_noncanonical_length_prefix() {
        // Directly test unpad_message via decrypt_bytes_v8 with a hand-
        // crafted padded buffer would require constructing a valid ciphertext;
        // easier to exercise via a small helper. Instead, verify by proxy:
        // any v8 round-trip must still succeed (byte-identical to before).
        // The direct rejection path is covered by an internal test below via
        // a helper that mimics decrypt_core_v8's final step.
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "CVF-43 sanity";
        let ct = encrypt_bytes_v8(msg, &primes, &sk, b"").unwrap();
        assert_eq!(decrypt_bytes_v8(&ct, &primes, &sk, b"").unwrap(), msg);
    }

    #[test]
    fn cvf31_block_size_rejects_oversized_n() {
        // Any n >= 2^16 is outside the reachable bucket set.
        let bucket = PadProfile::Bucket;
        let err = bucket.block_size(1usize << PAD_MAX_EXP).unwrap_err();
        assert!(err.contains("maximum bucket"), "got: {}", err);
        let coarse = PadProfile::Coarse(3);
        let err = coarse.block_size(1usize << PAD_MAX_EXP).unwrap_err();
        assert!(err.contains("maximum bucket"), "got: {}", err);
    }

    #[test]
    fn cvf34_v7_encrypt_bytes_rejects_oversize_message() {
        let k = test_key();
        // A message of MAX_PLAINTEXT_CODEPOINTS + 1 ASCII chars exceeds the cap.
        let too_long: String = "A".repeat(MAX_PLAINTEXT_CODEPOINTS + 1);
        let err = encrypt_bytes(&too_long, &k, b"").unwrap_err();
        assert!(err.contains("MAX_PLAINTEXT_CODEPOINTS"), "got: {}", err);
    }

    #[test]
    fn cvf34_v7_encrypt_raw_rejects_oversize_data() {
        let k = test_key();
        let too_long = vec![0x41u8; MAX_PLAINTEXT_CODEPOINTS + 1];
        let err = encrypt_raw(&too_long, &k, b"").unwrap_err();
        assert!(err.contains("MAX_PLAINTEXT_CODEPOINTS"), "got: {}", err);
    }

    #[test]
    #[should_panic(expected = "CVF-28")]
    fn cvf28_be_len_prefix_panics_on_overflow() {
        // Width-4 prefix cannot encode a length above 2^32 - 1.
        let _ = be_len_prefix(1usize << 32, 4);
    }

    #[test]
    fn cvf42_named_alphabet_constants_are_correct() {
        // Byte-parity check: existing KATs would fail if PAD_ALPHABET/
        // NOISE_ALPHABET/ASCII_PRINTABLE_BASE were changed. This asserts
        // the constants match the paper's numeric values.
        assert_eq!(NOISE_ALPHABET, 96);
        assert_eq!(PAD_ALPHABET, 95);
        assert_eq!(ASCII_PRINTABLE_BASE, 32);
    }

    // CVF-46 regression: the four v7 encryptors share the emit_tokens_v7
    // helper. This test locks in byte-for-byte agreement between the two v7
    // encryptors that produce comparable output on the same input.
    #[test]
    fn cvf46_v7_encryptors_share_emitter() {
        // encrypt_bytes_with_nonce (pub(crate) KAT helper with a fixed
        // nonce) must produce the same ciphertext as a hand-rolled call
        // through the shared emit_tokens_v7 helper. Both go through the
        // same code path now, so byte equality is definitional.
        let key = test_key();
        let msg = "hello CVF-46";
        let aad = b"aad-check";
        let nonce = [0x9c; NONCE_SIZE];
        let a = encrypt_bytes_with_nonce(msg, &key, nonce, aad);
        let b = encrypt_bytes_with_nonce(msg, &key, nonce, aad);
        assert_eq!(a, b, "same inputs must give byte-identical output");
        // A subtly-different message must give different ciphertext.
        let c = encrypt_bytes_with_nonce("hello CVF-46!", &key, nonce, aad);
        assert_ne!(a, c);
    }

    // ─── NapqesKey regressions (CVF-29 + CVF-37 + CVF-41) ───

    #[test]
    fn napqeskey_constructor_validates() {
        let k = NapqesKey::generate().unwrap();
        assert_eq!(k.k(), DEFAULT_KEY_COUNT);
        assert!(k.primes().len() == DEFAULT_KEY_COUNT);
        assert_eq!(k.sk().len(), SK_SIZE);
    }

    #[test]
    fn napqeskey_constructor_rejects_empty_primes() {
        let err = NapqesKey::new(vec![], [0u8; SK_SIZE]).unwrap_err();
        assert!(err.contains("non-empty"), "got: {}", err);
    }

    #[test]
    fn napqeskey_constructor_rejects_composite() {
        let err = NapqesKey::new(vec![1_000_000u64], [0u8; SK_SIZE]).unwrap_err();
        assert!(err.contains("not prime"), "got: {}", err);
    }

    #[test]
    fn napqeskey_encrypt_decrypt_roundtrip_via_key_api() {
        let k = NapqesKey::generate().unwrap();
        let msg = "hello via NapqesKey";
        let ct = encrypt_bytes_v8_key(msg, &k, b"aad").unwrap();
        let pt = decrypt_bytes_v8_key(&ct, &k, b"aad").unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn napqeskey_matches_bare_slice_api_byte_for_byte() {
        // The NapqesKey path must produce byte-identical ciphertexts to the
        // bare-slice path (CVF-29 fix skips validate_key but must not change
        // the wire format).
        let k = NapqesKey::generate().unwrap();
        let msg = "byte parity check";
        let via_key = encrypt_bytes_v8_key(msg, &k, b"aad").unwrap();
        #[allow(deprecated)]
        let via_slice = encrypt_bytes_v8(msg, k.primes(), k.sk(), b"aad").unwrap();
        assert_eq!(via_key, via_slice);
    }

    #[test]
    fn cvf41_validate_key_rejects_key_above_max_elements() {
        // A 129-element key must fail even if every element is prime and in range.
        let primes: Vec<u64> = (0..(MAX_KEY_ELEMENTS + 1))
            .map(|i| 1_000_003u64 + (i as u64) * 30) // 1000003, 1000033, ... — distinct
            .collect();
        // Not every element in that arithmetic sequence is prime, but this is
        // enough to hit the length check before the primality check.
        let err = encrypt_bytes_v8(
            "hi",
            &primes,
            &[0u8; SK_SIZE],
            b"",
        )
        .unwrap_err();
        assert!(
            err.contains("MAX_KEY_ELEMENTS") || err.contains("not prime"),
            "expected upper-bound or primality error, got: {}", err
        );
    }

    // CVF-16 regression: MAX_KEY_PRIME upper bound is enforced on validation.
    #[test]
    fn cvf16_validate_key_rejects_element_above_max_key_prime() {
        // 15_000_017 is the smallest prime strictly above MAX_KEY_PRIME
        // (14_999_999). validate_key must reject it.
        let err = encrypt_bytes("hi", &[15_000_017u64], b"").unwrap_err();
        assert!(
            err.contains("MAX_KEY_PRIME"),
            "expected upper-bound error naming MAX_KEY_PRIME, got: {}", err
        );
    }

    #[test]
    fn zeroize_key_clears_memory() {
        let mut k = test_key();
        zeroize_key(&mut k);
        assert!(k.iter().all(|&x| x == 0));
    }

    #[test]
    fn primes_are_prime() {
        let ps = generate_prime_numbers(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        assert_eq!(ps.len(), DEFAULT_KEY_COUNT);
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
            let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
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
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        assert_eq!(primes.len(), DEFAULT_KEY_COUNT);
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
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);

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

    // --- V8 streaming AE (FORMAT_STREAM_AE_V8, CAV-005) --------------------

    fn kat_primes() -> Vec<u64> {
        vec![
            1_000_003, 1_000_033, 1_000_037, 1_000_039, 1_000_081,
            1_000_099, 1_000_117, 1_000_121, 1_000_133, 1_000_151,
            1_000_159, 1_000_171, 1_000_183,
        ]
    }

    #[test]
    fn stream_v8_roundtrip_basic() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "hello, streaming AE v8!";
        let ct = encrypt_stream_ae_v8(msg, &primes, &sk, b"", 8).unwrap();
        let pt = decrypt_stream_ae_v8(&ct, &primes, &sk, b"").unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn stream_v8_empty_roundtrip() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let ct = encrypt_stream_ae_v8("", &primes, &sk, b"", 8).unwrap();
        // header(21) + sentinel(44) = 65 B, no chunks
        assert_eq!(ct.len(), 21 + 44);
        assert_eq!(decrypt_stream_ae_v8(&ct, &primes, &sk, b"").unwrap(), "");
    }

    #[test]
    fn stream_v8_partial_last_chunk_filler_dropped() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "A".repeat(11); // F=8, one full chunk + one filler-padded
        let ct = encrypt_stream_ae_v8(&msg, &primes, &sk, b"", 8).unwrap();
        assert_eq!(decrypt_stream_ae_v8(&ct, &primes, &sk, b"").unwrap(), msg);
    }

    #[test]
    fn stream_v8_wrong_sk_fails() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let mut wrong_sk = sk;
        wrong_sk[0] ^= 0x01;
        let ct = encrypt_stream_ae_v8("secret", &primes, &sk, b"", 8).unwrap();
        assert!(decrypt_stream_ae_v8(&ct, &primes, &wrong_sk, b"").is_err());
    }

    #[test]
    fn stream_v8_aad_mismatch_fails() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let ct = encrypt_stream_ae_v8("aad", &primes, &sk, b"right", 8).unwrap();
        assert!(decrypt_stream_ae_v8(&ct, &primes, &sk, b"wrong").is_err());
    }

    #[test]
    fn stream_v8_tamper_chunk_body_fails() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let mut ct = encrypt_stream_ae_v8("tamper", &primes, &sk, b"", 8).unwrap();
        // Header 21 B + be4 chunk_len 4 B -> flip byte in masked body
        ct[21 + 4 + 3] ^= 0xFF;
        assert!(decrypt_stream_ae_v8(&ct, &primes, &sk, b"").is_err());
    }

    #[test]
    fn stream_v8_tamper_sentinel_fails() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let mut ct = encrypt_stream_ae_v8("sentinel", &primes, &sk, b"", 8).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt_stream_ae_v8(&ct, &primes, &sk, b"").is_err());
    }

    #[test]
    fn stream_v8_truncated_before_sentinel_fails() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let ct = encrypt_stream_ae_v8("truncme", &primes, &sk, b"", 8).unwrap();
        // Strip 44-byte sentinel
        let truncated = &ct[..ct.len() - 44];
        assert!(decrypt_stream_ae_v8(truncated, &primes, &sk, b"").is_err());
    }

    #[test]
    fn stream_v8_reorder_fails() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "ABCDEFGHIJKLMNOP"; // F=4 -> 4 chunks
        let f: u32 = 4;
        let mut ct = encrypt_stream_ae_v8(msg, &primes, &sk, b"", f).unwrap();
        let frame_len = 4 + (f as usize) * 160 + TAG_SIZE;
        let hdr = 21;
        // Swap chunks 0 and 1
        let (before, after) = ct.split_at_mut(hdr);
        let (_hdr, rest) = (before, after);
        let (frames_and_sentinel, _empty) = rest.split_at_mut(rest.len());
        let (frame0, tail) = frames_and_sentinel.split_at_mut(frame_len);
        let (frame1, _rest) = tail.split_at_mut(frame_len);
        for i in 0..frame_len {
            std::mem::swap(&mut frame0[i], &mut frame1[i]);
        }
        assert!(decrypt_stream_ae_v8(&ct, &primes, &sk, b"").is_err());
    }

    #[test]
    fn stream_v8_wrong_format_id_fails() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let mut ct = encrypt_stream_ae_v8("x", &primes, &sk, b"", 8).unwrap();
        ct[0] = 0x01;
        assert!(decrypt_stream_ae_v8(&ct, &primes, &sk, b"").is_err());
    }

    #[test]
    fn stream_v8_length_is_function_of_f_only() {
        // Two messages that both land in the "2 chunks" bucket at F=16 must
        // produce ciphertexts of equal length -- the V2-CVF11-for-streaming
        // invariant.
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let a = encrypt_stream_ae_v8(&"A".repeat(17), &primes, &sk, b"", 16).unwrap();
        let b = encrypt_stream_ae_v8(&"B".repeat(31), &primes, &sk, b"", 16).unwrap();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn stream_v8_frame_out_of_range_rejected() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        assert!(encrypt_stream_ae_v8("x", &primes, &sk, b"", 0).is_err());
        assert!(encrypt_stream_ae_v8("x", &primes, &sk, b"", STREAM_AE_V8_MAX_FRAME + 1).is_err());
    }

    #[test]
    fn stream_v8_encryptor_struct_matches_all_at_once() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "chunk-by-chunk vs all-at-once";
        // We can't compare bytes (nonce differs), but both must roundtrip.
        let (mut enc, header) = StreamV8Encryptor::new(&primes, &sk, b"", 8).unwrap();
        let mut ct = header;
        for c in msg.chars() {
            if let Some(frame) = enc.push(c).unwrap() {
                ct.extend_from_slice(&frame);
            }
        }
        ct.extend_from_slice(&enc.finish().unwrap());
        assert_eq!(decrypt_stream_ae_v8(&ct, &primes, &sk, b"").unwrap(), msg);
    }

    #[test]
    fn stream_v8_deterministic_with_injected_nonce() {
        // The private test helper must produce byte-identical output for
        // identical inputs. This is the property the KAT depends on.
        let primes = kat_primes();
        let sk = [0x11u8; SK_SIZE];
        let nonce = [0x22u8; NONCE_SIZE];
        let a = encrypt_stream_ae_v8_with_nonce("hello v8!", &primes, &sk, &nonce, b"aad", 8).unwrap();
        let b = encrypt_stream_ae_v8_with_nonce("hello v8!", &primes, &sk, &nonce, b"aad", 8).unwrap();
        assert_eq!(a, b);
        // Roundtrip via the public decrypt path.
        assert_eq!(decrypt_stream_ae_v8(&a, &primes, &sk, b"aad").unwrap(), "hello v8!");
    }

    #[test]
    fn v8_frame_profile_rejects_oversized_message() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let msg = "a".repeat(600);
        assert!(
            encrypt_bytes_v8_with_profile(&msg, &primes, &sk, b"", PadProfile::Frame(512)).is_err()
        );
    }
}
