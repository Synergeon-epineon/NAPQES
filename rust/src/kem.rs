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
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

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
    expand_seed_to_primes(&seed)
}

/// Counter-mode HMAC-SHA256 expansion of `seed` into `NAPQES_KEY_COUNT`
/// distinct primes.
///
/// Shared by the Frodo-only and the hybrid derivations so that the two differ
/// exactly in their HKDF-Extract inputs (secret material and transcript) and
/// nowhere else.
///
/// The reduction `digest[..8] % prime_range` is not unbiased range sampling,
/// but the bias is bounded by `prime_range / 2^64 < 2^-40` per draw and is
/// therefore negligible; rejection is applied for primality and uniqueness only.
fn expand_seed_to_primes(seed: &[u8; 32]) -> Vec<u64> {
    let prime_range = MAX_PRIME - MIN_PRIME;
    let mut primes: Vec<u64> = Vec::with_capacity(NAPQES_KEY_COUNT);
    let mut seen: HashSet<u64> = HashSet::new();
    let mut counter: u32 = 0;

    while primes.len() < NAPQES_KEY_COUNT {
        let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts any key size");
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

// ─── Hybrid key establishment: FrodoKEM-640-AES + X25519 ─────────────────────
//
// ANSSI's post-quantum doctrine requires that a post-quantum mechanism be
// *hybridised* with a well-understood classical one until the post-quantum
// assumptions have matured: the derived key must stay secure as long as
// *either* component holds. This is achieved by concatenating both shared
// secrets into a single HKDF-Extract input — HKDF-Extract is a PRF keyed by
// the salt, so recovering the seed requires breaking every component.
//
// The X25519 half is ephemeral-static, mirroring the FrodoKEM semantics.
// Byte-for-byte compatible with `napqes_kem.py`; pinned by
// `test_derive_hybrid_cross_language_vector`.

/// Wire sizes of the FrodoKEM-640-AES artefacts, used to split hybrid blobs.
pub const FRODO_PUBLIC_KEY_SIZE: usize = 9_616;
pub const FRODO_SECRET_KEY_SIZE: usize = 19_888;
pub const FRODO_CIPHERTEXT_SIZE: usize = 9_720;

/// X25519 public keys, private scalars and shared secrets are all 32 bytes.
pub const X25519_KEY_SIZE: usize = 32;

/// Hybrid blob sizes. The recipient's FrodoKEM public key is carried inside the
/// hybrid secret key so that the decapsulator can rebuild the same transcript
/// as the encapsulator.
pub const HYBRID_PUBLIC_KEY_SIZE: usize = FRODO_PUBLIC_KEY_SIZE + X25519_KEY_SIZE;
pub const HYBRID_SECRET_KEY_SIZE: usize =
    FRODO_SECRET_KEY_SIZE + X25519_KEY_SIZE + FRODO_PUBLIC_KEY_SIZE;
pub const HYBRID_CIPHERTEXT_SIZE: usize = FRODO_CIPHERTEXT_SIZE + X25519_KEY_SIZE;

/// Domain separation for the hybrid derivation. Distinct from `HKDF_SALT` so a
/// hybrid and a Frodo-only exchange can never derive the same key.
const HYBRID_HKDF_SALT: &[u8] = b"NAPQES-hybrid-FrodoKEM640AES-X25519-prime-key";
const HYBRID_HKDF_INFO_PREFIX: &[u8] = b"v2";

/// Length-prefixed binding of every public value of the exchange, fed to HKDF
/// as `info`. Length prefixes make the concatenation injective.
fn hybrid_transcript(
    pk_pq: &[u8],
    ct_pq: &[u8],
    pk_ec_static: &[u8],
    pk_ec_ephemeral: &[u8],
) -> Vec<u8> {
    let mut out = Vec::from(HYBRID_HKDF_INFO_PREFIX);
    for part in [pk_pq, ct_pq, pk_ec_static, pk_ec_ephemeral] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Derive the NAPQES prime key from both shared secrets and the transcript.
///
/// # Errors
///
/// Returns `Err` if the X25519 output is all-zero, which means the peer sent a
/// small-order point and the classical half would contribute no entropy.
/// RFC 7748 §6.1 leaves this check optional; for a hybrid it is mandatory.
pub fn derive_napqes_key_hybrid(
    ss_pq: &[u8],
    ss_ec: &[u8],
    transcript: &[u8],
) -> Result<Vec<u64>, String> {
    if ss_ec.len() != X25519_KEY_SIZE {
        return Err(format!(
            "X25519 shared secret must be {} bytes, got {}",
            X25519_KEY_SIZE,
            ss_ec.len()
        ));
    }
    if ss_ec.iter().all(|&b| b == 0) {
        return Err("X25519 shared secret is all-zero: the peer supplied a \
                    small-order point, so the classical half of the hybrid \
                    would contribute no entropy"
            .to_string());
    }
    let mut ikm = Vec::with_capacity(ss_pq.len() + ss_ec.len());
    ikm.extend_from_slice(ss_pq);
    ikm.extend_from_slice(ss_ec);

    let hk = Hkdf::<Sha256>::new(Some(HYBRID_HKDF_SALT), &ikm);
    let mut seed = [0u8; 32];
    hk.expand(transcript, &mut seed)
        .expect("32 bytes fits HKDF-SHA256 output");
    Ok(expand_seed_to_primes(&seed))
}

/// Generate a hybrid FrodoKEM-640-AES + X25519 keypair.
///
/// Returns `(public_key, secret_key)` where
/// `public_key = pk_frodo(9 616) || pk_x25519(32)` and
/// `secret_key = sk_frodo(19 888) || sk_x25519(32) || pk_frodo(9 616)`.
pub fn keygen_hybrid() -> (Vec<u8>, Vec<u8>) {
    let (pk_pq, sk_pq) = frodokem640aes::keypair();
    let sk_ec = StaticSecret::random_from_rng(OsRng);
    let pk_ec = X25519PublicKey::from(&sk_ec);

    let mut public_key = Vec::with_capacity(HYBRID_PUBLIC_KEY_SIZE);
    public_key.extend_from_slice(pk_pq.as_bytes());
    public_key.extend_from_slice(pk_ec.as_bytes());

    let mut secret_key = Vec::with_capacity(HYBRID_SECRET_KEY_SIZE);
    secret_key.extend_from_slice(sk_pq.as_bytes());
    secret_key.extend_from_slice(&sk_ec.to_bytes());
    secret_key.extend_from_slice(pk_pq.as_bytes());

    (public_key, secret_key)
}

/// Encapsulate a fresh hybrid shared secret to `public_key`.
///
/// Returns `(ciphertext, napqes_key)` where
/// `ciphertext = ct_frodo(9 720) || pk_x25519_ephemeral(32)`.
///
/// # Errors
///
/// Returns `Err` if `public_key` is malformed or the derivation is rejected.
pub fn encapsulate_hybrid(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u64>), String> {
    if public_key.len() != HYBRID_PUBLIC_KEY_SIZE {
        return Err(format!(
            "Hybrid public key must be {} bytes, got {}",
            HYBRID_PUBLIC_KEY_SIZE,
            public_key.len()
        ));
    }
    let (pk_pq_bytes, pk_ec_static_bytes) = public_key.split_at(FRODO_PUBLIC_KEY_SIZE);
    let pk_pq = PublicKey::from_bytes(pk_pq_bytes)
        .map_err(|_| "invalid FrodoKEM-640-AES public key".to_string())?;
    let (ss_pq, ct_pq) = frodokem640aes::encapsulate(&pk_pq);

    let mut pk_ec_static_arr = [0u8; X25519_KEY_SIZE];
    pk_ec_static_arr.copy_from_slice(pk_ec_static_bytes);
    let pk_ec_static = X25519PublicKey::from(pk_ec_static_arr);

    let eph = StaticSecret::random_from_rng(OsRng);
    let pk_ec_ephemeral = X25519PublicKey::from(&eph);
    let ss_ec = eph.diffie_hellman(&pk_ec_static);

    let transcript = hybrid_transcript(
        pk_pq_bytes,
        ct_pq.as_bytes(),
        pk_ec_static_bytes,
        pk_ec_ephemeral.as_bytes(),
    );
    let key = derive_napqes_key_hybrid(ss_pq.as_bytes(), ss_ec.as_bytes(), &transcript)?;

    let mut ciphertext = Vec::with_capacity(HYBRID_CIPHERTEXT_SIZE);
    ciphertext.extend_from_slice(ct_pq.as_bytes());
    ciphertext.extend_from_slice(pk_ec_ephemeral.as_bytes());
    Ok((ciphertext, key))
}

/// Decapsulate a hybrid `ciphertext`, recovering the same NAPQES key.
///
/// # Errors
///
/// Returns `Err` if either blob is malformed or the derivation is rejected.
pub fn decapsulate_hybrid(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u64>, String> {
    if ciphertext.len() != HYBRID_CIPHERTEXT_SIZE {
        return Err(format!(
            "Hybrid ciphertext must be {} bytes, got {}",
            HYBRID_CIPHERTEXT_SIZE,
            ciphertext.len()
        ));
    }
    if secret_key.len() != HYBRID_SECRET_KEY_SIZE {
        return Err(format!(
            "Hybrid secret key must be {} bytes, got {}",
            HYBRID_SECRET_KEY_SIZE,
            secret_key.len()
        ));
    }
    let (ct_pq_bytes, pk_ec_ephemeral_bytes) = ciphertext.split_at(FRODO_CIPHERTEXT_SIZE);
    let sk_pq_bytes = &secret_key[..FRODO_SECRET_KEY_SIZE];
    let sk_ec_bytes = &secret_key[FRODO_SECRET_KEY_SIZE..FRODO_SECRET_KEY_SIZE + X25519_KEY_SIZE];
    let pk_pq_bytes = &secret_key[FRODO_SECRET_KEY_SIZE + X25519_KEY_SIZE..];

    let ct_pq = Ciphertext::from_bytes(ct_pq_bytes)
        .map_err(|_| "invalid FrodoKEM-640-AES ciphertext".to_string())?;
    let sk_pq = SecretKey::from_bytes(sk_pq_bytes)
        .map_err(|_| "invalid FrodoKEM-640-AES secret key".to_string())?;
    let ss_pq = frodokem640aes::decapsulate(&ct_pq, &sk_pq);

    let mut sk_ec_arr = [0u8; X25519_KEY_SIZE];
    sk_ec_arr.copy_from_slice(sk_ec_bytes);
    let sk_ec = StaticSecret::from(sk_ec_arr);
    let pk_ec_static = X25519PublicKey::from(&sk_ec);

    let mut pk_ec_ephemeral_arr = [0u8; X25519_KEY_SIZE];
    pk_ec_ephemeral_arr.copy_from_slice(pk_ec_ephemeral_bytes);
    let ss_ec = sk_ec.diffie_hellman(&X25519PublicKey::from(pk_ec_ephemeral_arr));

    let transcript = hybrid_transcript(
        pk_pq_bytes,
        ct_pq_bytes,
        pk_ec_static.as_bytes(),
        pk_ec_ephemeral_bytes,
    );
    derive_napqes_key_hybrid(ss_pq.as_bytes(), ss_ec.as_bytes(), &transcript)
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

    // ─── Hybrid FrodoKEM + X25519 ────────────────────────────────────────────

    /// Pinned so the Rust port cannot silently diverge from `napqes_kem.py` on
    /// HKDF salt/info, secret concatenation order, or transcript encoding.
    /// Python: `tests/test_kem.py::TestCrossLanguageVector::
    /// test_derive_known_vector_hybrid`.
    #[test]
    fn test_derive_hybrid_cross_language_vector() {
        let transcript = hybrid_transcript(b"PK-PQ", b"CT-PQ", b"PK-EC-STATIC", b"PK-EC-EPH");
        let expected_transcript = "763200000005504b2d50510000000543542d50510000000c\
                                   504b2d45432d53544154494300000009504b2d45432d455048";
        let hex: String = transcript.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, expected_transcript.replace(['\\', ' ', '\n'], ""));

        let ss_ec: Vec<u8> = (1u8..=32).collect();
        let key = derive_napqes_key_hybrid(&[0u8; 16], &ss_ec, &transcript)
            .expect("hybrid derivation");
        assert_eq!(
            key,
            vec![
                2992559, 2913523, 2740301, 1977709, 5330359, 13077137, 6210319, 11896091,
                14291593, 8698397, 12129883, 1604143, 10450267,
            ]
        );
    }

    #[test]
    fn test_hybrid_roundtrip() {
        let (pk, sk) = keygen_hybrid();
        assert_eq!(pk.len(), HYBRID_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), HYBRID_SECRET_KEY_SIZE);
        let (ct, key_bob) = encapsulate_hybrid(&pk).expect("encapsulate_hybrid");
        assert_eq!(ct.len(), HYBRID_CIPHERTEXT_SIZE);
        let key_alice = decapsulate_hybrid(&ct, &sk).expect("decapsulate_hybrid");
        assert_eq!(key_bob, key_alice);
        assert_eq!(key_bob.len(), NAPQES_KEY_COUNT);
        assert!(key_bob.iter().all(|&p| is_prime(p) && (MIN_PRIME..MAX_PRIME).contains(&p)));
    }

    #[test]
    fn test_hybrid_each_session_is_fresh() {
        let (pk, _) = keygen_hybrid();
        let (_, key1) = encapsulate_hybrid(&pk).expect("encapsulate_hybrid");
        let (_, key2) = encapsulate_hybrid(&pk).expect("encapsulate_hybrid");
        assert_ne!(key1, key2);
    }

    /// Splicing the ephemeral X25519 half of another session must change the
    /// derived key: this is what the HKDF `info` transcript binding buys.
    #[test]
    fn test_hybrid_transcript_binds_the_classical_half() {
        let (pk, sk) = keygen_hybrid();
        let (ct1, key1) = encapsulate_hybrid(&pk).expect("encapsulate_hybrid");
        let (ct2, _) = encapsulate_hybrid(&pk).expect("encapsulate_hybrid");
        let mut spliced = ct1[..FRODO_CIPHERTEXT_SIZE].to_vec();
        spliced.extend_from_slice(&ct2[FRODO_CIPHERTEXT_SIZE..]);
        let derived = decapsulate_hybrid(&spliced, &sk).expect("decapsulate_hybrid");
        assert_ne!(derived, key1);
    }

    #[test]
    fn test_hybrid_rejects_all_zero_x25519_secret() {
        let err = derive_napqes_key_hybrid(&[0u8; 16], &[0u8; 32], b"info")
            .expect_err("all-zero X25519 output must be rejected");
        assert!(err.contains("all-zero"), "unexpected error: {}", err);
    }

    #[test]
    fn test_hybrid_rejects_malformed_blobs() {
        let (pk, sk) = keygen_hybrid();
        let (ct, _) = encapsulate_hybrid(&pk).expect("encapsulate_hybrid");
        assert!(encapsulate_hybrid(&pk[..pk.len() - 1]).is_err());
        assert!(decapsulate_hybrid(&ct[..ct.len() - 1], &sk).is_err());
        assert!(decapsulate_hybrid(&ct, &sk[..sk.len() - 1]).is_err());
    }

    /// The same FrodoKEM secret must never produce the same NAPQES key under
    /// the two schedules (distinct HKDF salts).
    #[test]
    fn test_hybrid_and_frodo_only_are_domain_separated() {
        let ss_pq: Vec<u8> = (0u8..16).collect();
        let ss_ec: Vec<u8> = (1u8..=32).collect();
        let legacy = derive_napqes_key(&ss_pq);
        let hybrid = derive_napqes_key_hybrid(&ss_pq, &ss_ec, b"v2").expect("hybrid");
        assert_ne!(legacy, hybrid);
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
