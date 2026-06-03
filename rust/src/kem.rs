//! FrodoKEM-640-AES + NAPQES key establishment (Rust port of napqes_kem.py).
//!
//! Two-phase protocol:
//!   1. KEM phase   — FrodoKEM-640-AES derives a 16-byte shared secret.
//!   2. Derive phase — HKDF-SHA256 → counter-mode HMAC-SHA256 produces
//!                     a valid NAPQES prime-list key (13 distinct primes from
//!                     [1 000 000, 15 000 000]).
//!
//! All derivation steps use only HMAC-SHA256 and HKDF-SHA256, consistent with
//! NAPQES's single-primitive design philosophy.
//!
//! # Key ordering
//!
//! The derived prime list is ordered (ordering is a NAPQES security parameter).
//! Do not sort or shuffle the returned Vec<u64>.

use std::collections::HashSet;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pqcrypto_frodo::frodokem640aes::{self, Ciphertext, PublicKey, SecretKey};
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};
use sha2::Sha256;

use crate::is_prime;

type HmacSha256 = Hmac<Sha256>;

pub const NAPQES_KEY_COUNT: usize = 13;
pub const MIN_PRIME: u64 = 1_000_000;
pub const MAX_PRIME: u64 = 15_000_000;

const HKDF_SALT: &[u8] = b"NAPQES-v6-FrodoKEM-640-prime-key";
const HKDF_INFO: &[u8] = b"v1";

/// Generate a FrodoKEM-640-AES keypair.
///
/// Returns `(public_key_bytes, secret_key_bytes)`.
/// Publish `public_key_bytes`; keep `secret_key_bytes` confidential.
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = frodokem640aes::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Encapsulate a fresh shared secret to `public_key`.
///
/// Returns `(kem_ciphertext, napqes_key)`.
/// Send `kem_ciphertext` to the key-holder (Alice); use `napqes_key` locally.
///
/// # Errors
///
/// Returns `Err` if `public_key` is not a valid FrodoKEM-640-AES public key.
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u64>), String> {
    let pk = PublicKey::from_bytes(public_key)
        .map_err(|_| "invalid FrodoKEM-640-AES public key".to_string())?;
    let (ss, ct) = frodokem640aes::encapsulate(&pk);
    Ok((ct.as_bytes().to_vec(), derive_napqes_key(ss.as_bytes())))
}

/// Decapsulate `ciphertext` using `secret_key`, recovering the NAPQES key.
///
/// Returns the NAPQES prime-list key that the encapsulator holds.
///
/// # Errors
///
/// Returns `Err` if the ciphertext or secret key are not valid FrodoKEM-640-AES bytes.
pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u64>, String> {
    let ct = Ciphertext::from_bytes(ciphertext)
        .map_err(|_| "invalid FrodoKEM-640-AES ciphertext".to_string())?;
    let sk = SecretKey::from_bytes(secret_key)
        .map_err(|_| "invalid FrodoKEM-640-AES secret key".to_string())?;
    let ss = frodokem640aes::decapsulate(&ct, &sk);
    Ok(derive_napqes_key(ss.as_bytes()))
}

/// Deterministically derive a NAPQES prime-list key from a KEM shared secret.
///
/// Step 1 (Extract): HKDF-SHA256 maps the 16-byte FrodoKEM shared secret to a
///   uniform 32-byte seed using a domain-separation salt.
///
/// Step 2 (Expand): counter-mode HMAC-SHA256(seed, counter) generates a stream
///   of 32-byte digests.  Each digest's first 8 bytes are mapped into the prime
///   range [1 000 000, 15 000 000) via modular reduction, then checked for
///   primality and uniqueness.
///
/// The resulting Vec<u64> is ordered (ordering is a security parameter).
pub fn derive_napqes_key(shared_secret: &[u8]) -> Vec<u64> {
    // Step 1: HKDF-SHA256 extraction into a 32-byte seed.
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
    let mut seed = [0u8; 32];
    hk.expand(HKDF_INFO, &mut seed).expect("32 bytes fits HKDF-SHA256 output");

    // Step 2: counter-mode HMAC-SHA256 → rejection sampling for distinct primes.
    let prime_range = MAX_PRIME - MIN_PRIME;
    let mut primes: Vec<u64> = Vec::with_capacity(NAPQES_KEY_COUNT);
    let mut seen: HashSet<u64> = HashSet::new();
    let mut counter: u32 = 0;

    while primes.len() < NAPQES_KEY_COUNT {
        let mut mac = HmacSha256::new_from_slice(&seed).expect("HMAC accepts any key size");
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();

        let raw = u64::from_be_bytes(digest[..8].try_into().unwrap()) % prime_range + MIN_PRIME;
        counter += 1;

        if !seen.contains(&raw) && is_prime(raw) {
            primes.push(raw);
            seen.insert(raw);
        }
    }
    primes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let (pk, sk) = keygen();
        let (ct, key_bob) = encapsulate(&pk).expect("encapsulate");
        let key_alice = decapsulate(&ct, &sk).expect("decapsulate");
        assert_eq!(key_bob, key_alice);
    }

    #[test]
    fn test_key_count() {
        let (pk, _) = keygen();
        let (_, key) = encapsulate(&pk).expect("encapsulate");
        assert_eq!(key.len(), NAPQES_KEY_COUNT);
    }

    #[test]
    fn test_key_elements_in_range() {
        let (pk, _) = keygen();
        let (_, key) = encapsulate(&pk).expect("encapsulate");
        for &p in &key {
            assert!(p >= MIN_PRIME && p < MAX_PRIME);
        }
    }

    #[test]
    fn test_key_elements_distinct() {
        let (pk, _) = keygen();
        let (_, key) = encapsulate(&pk).expect("encapsulate");
        let unique: HashSet<u64> = key.iter().copied().collect();
        assert_eq!(unique.len(), key.len());
    }

    #[test]
    fn test_key_elements_are_prime() {
        let (pk, _) = keygen();
        let (_, key) = encapsulate(&pk).expect("encapsulate");
        assert!(key.iter().all(|&p| is_prime(p)));
    }

    #[test]
    fn test_derive_is_deterministic() {
        let secret = b"test-shared-secret-16b";
        let key1 = derive_napqes_key(secret);
        let key2 = derive_napqes_key(secret);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_secrets_give_different_keys() {
        let key1 = derive_napqes_key(b"aaaaaaaaaaaaaaaa");
        let key2 = derive_napqes_key(b"bbbbbbbbbbbbbbbb");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_wrong_sk_gives_different_key() {
        let (pk, _sk) = keygen();
        let (ct, key_bob) = encapsulate(&pk).expect("encapsulate");
        let (_, wrong_sk) = keygen();
        let key_wrong = decapsulate(&ct, &wrong_sk).expect("decapsulate with wrong sk");
        assert_ne!(key_wrong, key_bob);
    }

    #[test]
    fn test_key_sizes() {
        let (pk, sk) = keygen();
        let (ct, _) = encapsulate(&pk).expect("encapsulate");
        assert_eq!(pk.len(), 9616);   // FrodoKEM-640-AES spec
        assert_eq!(sk.len(), 19888);  // FrodoKEM-640-AES spec
        assert_eq!(ct.len(), 9720);   // FrodoKEM-640-AES spec
    }

    #[test]
    fn test_derive_cross_language_vector() {
        // Known-answer vector: shared_secret = 0x00 * 16
        // Generated by Python: napqes_kem._derive_napqes_key(bytes(16))
        // Both implementations MUST produce the same ordered prime list.
        let secret = [0u8; 16];
        let key = derive_napqes_key(&secret);
        let expected: Vec<u64> = vec![
            11530619, 13297909, 9920357, 13069411, 5196311,
            6762001, 12497731, 7518361, 12559777, 1531199,
            14203867, 10311841, 13788101,
        ];
        assert_eq!(key, expected, "cross-language derivation mismatch");
    }
}
