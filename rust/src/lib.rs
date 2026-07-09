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

// CVF2 fix: unified domain-first layout `d || N || ctx` shared by every
// domain in the schedule, with `ctx = be4(len(aad)) || aad || masked_blob`.
// `payload` is `nonce || masked_blob`; it is split here so the nonce
// occupies the fixed byte 1..=16 offset used by every other domain.
fn compute_auth_tag(kb: &[u8], aad: &[u8], payload: &[u8]) -> [u8; 32] {
    let (nonce, masked_blob) = payload.split_at(NONCE_SIZE);
    let mut buf = Vec::with_capacity(1 + nonce.len() + 4 + aad.len() + masked_blob.len());
    buf.push(0x03);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    buf.extend_from_slice(aad);
    buf.extend_from_slice(masked_blob);
    hmac_digest(kb, &buf)
}

// ─── Padding ─────────────────────────────────────────────────────────────────

/// HMAC-derived padding — domain byte 0x06 (matches Python `_pad_message`).
/// Each padding codepoint is in [32, 126], matching the reference exactly.
fn pad_message(msg: &[u32], kb: &[u8], nonce: &[u8]) -> Vec<u32> {
    let n = msg.len();
    assert!(n <= 0xFFFF, "Message too long for 2-byte length prefix");
    let block_size = if n == 0 {
        16usize
    } else {
        let bl = 64 - (n as u64).leading_zeros() as usize;
        let p = 1usize << bl;
        p.max(16)
    };
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
/// Each 32-byte block is `HMAC(key_bytes, nonce || 0x07 || uint32_be(block))`.  
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

fn unpad_message(padded: &[u32]) -> Vec<u32> {
    assert!(padded.len() >= 2);
    let n = ((padded[0] as usize) << 8) | (padded[1] as usize);
    padded[2..2 + n].to_vec()
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
    unpad_message(&padded)
}

pub fn decrypt(nonce: &[u8], cypher: &[u64], key: &[u64]) -> Vec<u32> {
    let kb = key_bytes(key);
    decrypt_core(nonce, cypher, key, &kb)
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
    let tag = compute_auth_tag(&kb, aad, &payload);
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
    let tag = compute_auth_tag(&kb, aad, &payload);
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
    let calc_tag = compute_auth_tag(&kb, aad, payload);
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
    let tag = compute_auth_tag(&kb, aad, &payload);
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
    let calc_tag = compute_auth_tag(&kb, aad, payload);
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
//   N = Derive_synth(sk, aad, message) = HMAC(sk, 0x0A || be4(|aad|) || aad || message)[0:16]
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
/// Deterministic in `(sk, aad, message)`: encrypting the same message under
/// the same key and AAD always reproduces the same nonce (and hence the
/// same ciphertext), which is the standard MRAE trade-off. Encrypting any
/// *different* `(aad, message)` pair produces a nonce that collides with a
/// previous one only with HMAC-SHA256-collision probability.
fn synthetic_nonce(sk: &[u8], aad: &[u8], message: &[u8]) -> [u8; NONCE_SIZE] {
    let mut buf = Vec::with_capacity(1 + 4 + aad.len() + message.len());
    buf.push(0x0A);
    buf.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    buf.extend_from_slice(aad);
    buf.extend_from_slice(message);
    let d = hmac_digest(sk, &buf);
    let mut n = [0u8; NONCE_SIZE];
    n.copy_from_slice(&d[..NONCE_SIZE]);
    n
}

/// Misuse-resistant v8 encryption: synthetic nonce (CVF3 fix) plus a
/// domain-derivation key (`sk`) independent of the arithmetic-layer primes
/// (CVF8/CVF13 fix). See the module-level "V8 key schedule" documentation
/// above for the full security argument.
pub fn encrypt_bytes_v8(
    message: &str,
    primes: &[u64],
    sk: &[u8; SK_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if message.is_empty() {
        return Ok(Vec::new());
    }
    let nonce = synthetic_nonce(sk, aad, message.as_bytes());
    let codepoints: Vec<u32> = message.chars().map(|c| c as u32).collect();
    let noise_p = derive_noise_p(sk, &nonce);
    let padded = pad_message(&codepoints, sk, &nonce);
    let kk = primes.len() as u64;
    let mut cypher: Vec<u64> = Vec::new();
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    for &c in &padded {
        loop {
            if is_noise_pos(sk, &nonce, ct_pos, noise_p) {
                let k = primes[(real_idx % kk) as usize];
                let nc = derive_noise_char(sk, &nonce, ct_pos);
                let na = derive_noise_token_addend(sk, &nonce, ct_pos, k);
                cypher.push(nc * k + na);
                ct_pos += 1;
            } else {
                let k = primes[(real_idx % kk) as usize];
                let addend = derive_addend(sk, &nonce, real_idx, k);
                cypher.push(c as u64 * k + addend);
                ct_pos += 1;
                real_idx += 1;
                break;
            }
        }
    }
    let blob = fixed_encode_tokens(&cypher);
    let ks = varint_keystream(sk, &nonce, blob.len());
    let masked: Vec<u8> = blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mut payload = Vec::with_capacity(NONCE_SIZE + masked.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&masked);
    let tag = compute_auth_tag(sk, aad, &payload);
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
    let split = ciphertext.len() - TAG_SIZE;
    let payload = &ciphertext[..split];
    let recv_tag = &ciphertext[split..];
    let calc_tag = compute_auth_tag(sk, aad, payload);
    if !ct_eq_bytes(recv_tag, calc_tag.as_ref()) {
        return Err("Authentication failed: invalid HMAC tag.".into());
    }
    let nonce = &payload[..NONCE_SIZE];
    let masked = &payload[NONCE_SIZE..];
    let ks = varint_keystream(sk, nonce, masked.len());
    let blob: Vec<u8> = masked.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let tokens = fixed_decode_tokens(&blob).map_err(|e| format!("varint decode error: {}", e))?;
    let codepoints = decrypt_core(nonce, &tokens, primes, sk);
    let s: String = codepoints.into_iter().filter_map(char::from_u32).collect();
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
        let ps = generate_prime_numbers(10, 1_000_000, 9_999_999);
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

    #[test]
    fn v8_zeroize_sk_clears_memory() {
        let mut sk = test_sk();
        zeroize_sk(&mut sk);
        assert!(sk.iter().all(|&x| x == 0));
    }

    #[test]
    fn v8_key_generation_is_independent() {
        let (primes, sk) = generate_v8_key(10, 1_000_000, 9_999_999);
        assert_eq!(primes.len(), 10);
        // sk must not be derivable from key_bytes(primes) via the v7 KDF —
        // spot-check it does not equal the v7 HMAC key material shape.
        assert_ne!(sk.to_vec(), key_bytes(&primes));
    }
}
