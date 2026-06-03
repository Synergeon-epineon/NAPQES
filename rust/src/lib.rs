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
    let mut buf = Vec::with_capacity(nonce.len() + 1 + 5);
    buf.extend_from_slice(nonce);
    buf.push(0x00);
    buf.extend_from_slice(&be5(ct_pos));
    let d = hmac_digest(kb, &buf);
    let v = u64_from_be8(&d[..8]) as f64 / TWO_POW_64;
    v < noise_p
}

fn derive_addend(kb: &[u8], nonce: &[u8], real_idx: u64, key_element: u64) -> u64 {
    let mut buf = Vec::with_capacity(nonce.len() + 1 + 5);
    buf.extend_from_slice(nonce);
    buf.push(0x01);
    buf.extend_from_slice(&be5(real_idx));
    let d = hmac_digest(kb, &buf);
    (u32_from_be4(&d[..4]) as u64 % (key_element - 1)) + 1
}

fn derive_noise_char(kb: &[u8], nonce: &[u8], ct_pos: u64) -> u64 {
    let mut buf = Vec::with_capacity(nonce.len() + 1 + 5);
    buf.extend_from_slice(nonce);
    buf.push(0x04);
    buf.extend_from_slice(&be5(ct_pos));
    let d = hmac_digest(kb, &buf);
    (u32_from_be4(&d[..4]) as u64 % 96) + 32
}

fn derive_noise_token_addend(kb: &[u8], nonce: &[u8], ct_pos: u64, key_element: u64) -> u64 {
    let mut buf = Vec::with_capacity(nonce.len() + 1 + 5);
    buf.extend_from_slice(nonce);
    buf.push(0x05);
    buf.extend_from_slice(&be5(ct_pos));
    let d = hmac_digest(kb, &buf);
    (u32_from_be4(&d[..4]) as u64 % (key_element - 1)) + 1
}

fn derive_noise_p(kb: &[u8], nonce: &[u8]) -> f64 {
    let mut buf = Vec::with_capacity(nonce.len() + 1);
    buf.extend_from_slice(nonce);
    buf.push(0x02);
    let d = hmac_digest(kb, &buf);
    let t = u64_from_be8(&d[..8]) as f64 / TWO_POW_64;
    0.75 + t * (0.99 - 0.75)
}

fn compute_auth_tag(kb: &[u8], aad: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 4 + aad.len() + payload.len());
    buf.push(0x03);
    buf.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    buf.extend_from_slice(aad);
    buf.extend_from_slice(payload);
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
        let mut buf = Vec::with_capacity(nonce.len() + 1 + 4);
        buf.extend_from_slice(nonce);
        buf.push(0x06);
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
        let mut buf = Vec::with_capacity(nonce.len() + 5);
        buf.extend_from_slice(nonce);
        buf.push(0x07);
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

pub fn decrypt(nonce: &[u8], cypher: &[u64], key: &[u64]) -> Vec<u32> {
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, nonce);
    let kk = key.len() as u64;
    let mut padded: Vec<u32> = Vec::new();
    let mut real_idx: u64 = 0;
    for (ct_pos, &token) in cypher.iter().enumerate() {
        if !is_noise_pos(&kb, nonce, ct_pos as u64, noise_p) {
            let k = key[(real_idx % kk) as usize];
            let addend = derive_addend(&kb, nonce, real_idx, k);
            padded.push(((token - addend) / k) as u32);
            real_idx += 1;
        }
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

// ─── Base-128 varint ─────────────────────────────────────────────────────────

fn b128_encode_tokens(tokens: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    for &n in tokens {
        let mut v = n;
        while v > 0x7F {
            out.push(((v & 0x7F) | 0x80) as u8);
            v >>= 7;
        }
        out.push((v & 0x7F) as u8);
    }
    out
}

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

// ─── Binary / string wrappers (v6 authenticated) ─────────────────────────────


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
    let blob = b128_encode_tokens(&cypher);
    let ks = varint_keystream(&kb, &nonce, blob.len());
    let masked: Vec<u8> = blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mut payload = Vec::with_capacity(NONCE_SIZE + masked.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&masked);
    let tag = compute_auth_tag(&kb, aad, &payload);
    payload.extend_from_slice(&tag);
    Ok(payload)
}

/// Encrypt with a caller-supplied nonce — for deterministic KAT verification.
///
/// Replicates `encrypt_bytes` exactly but accepts an explicit nonce instead of
/// generating a random one.  **Use only for testing.**
pub fn encrypt_bytes_with_nonce(
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
    let blob = b128_encode_tokens(&cypher);
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
    let tokens = b128_decode_tokens(&blob)
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
}
