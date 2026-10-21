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
//!   [`encrypt_bytes_v8_with_profile`]. Length-hiding property holds per
//!   Corollary 4.14 of the paper **for the block format only**. The v8
//!   streaming format (feature-gated, outside the paper's claims) reveals
//!   the chunk count `ceil(n / F)`; its exact codepoint count is masked
//!   (CVF-V5-1).
//!
//! * **v7 (legacy — decryptors retained for archived ciphertexts).**
//!   Fixed-width tokens (CVF1 fix). Wire layout same shape, but no
//!   `MAX_NOISE_RUN` cap, so ciphertext length varies with the nonce.
//!   Encryptors are `#[deprecated]` per CVF-17 and compiled only with the
//!   `legacy-v7` feature (CVF-V5-4); decryptors ([`decrypt_bytes`],
//!   [`decrypt_str`], [`decrypt_raw`]) remain to decode existing traffic
//!   within the compatibility envelope documented on [`decrypt_bytes`]
//!   (CVF-V5-16): keys with an element of 0, 1 or `>= 2^40`, or a repeated
//!   element, and plaintexts containing non-scalar values, are rejected.
//!
//! # Key ordering is a security parameter
//!
//! `[k0, k1, …]` and `[k1, k0, …]` are **distinct** keys that produce
//! non-interoperable ciphertexts.  Callers must preserve element order
//! when storing or transmitting key material.
//!
//! # Validation
//!
//! Every encrypt entry point and every v8 decrypt entry point that accepts a
//! `&[u64]` key runs [`validate_key`] (private) before any arithmetic, per
//! CVF-15. A key that is empty, composite, below [`MIN_KEY_PRIME`], above
//! [`MAX_KEY_PRIME`], contains duplicates or has more than
//! [`MAX_KEY_ELEMENTS`] elements is rejected with a descriptive `String`
//! error. The v7 decryptors apply a relaxed policy once, after the tag has
//! verified (CVF-V5-12, CVF-V5-16; see [`decrypt_bytes`]).

pub mod self_test;
pub mod kem;
pub mod kem_exchange;
pub mod ot_frame;
pub mod protocols;
// CVF-V5-6: the unpublished `vale` module, its feature and the SPHINCS+
// dependency it pulled into every build were removed from this crate.

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
use key::Secret32;
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const NONCE_SIZE: usize = 16;
pub const TAG_SIZE: usize = 32;

/// Width of the AAD length prefix in the v8 block-mode domains `0x03`
/// (auth tag) and `0x0A` (synthetic nonce).
const AAD_LEN_WIDTH_V8: usize = 8;
/// Legacy v7 AAD length-prefix width, kept for byte compatibility.
const AAD_LEN_WIDTH_V7: usize = 4;

/// CVF-28: the v7 tag carries `|A|` in a 4-byte prefix, so longer AAD is an
/// error rather than a silent wraparound.
fn check_v7_aad_len(aad_len: usize) -> Result<(), String> {
    if aad_len as u64 > u32::MAX as u64 {
        return Err(format!(
            "AAD of {} bytes exceeds the v7 4-byte length prefix.",
            aad_len
        ));
    }
    Ok(())
}

// ─── CRNG conditional self-test ──────────────────────────────────────────────

#[cfg(any(test, feature = "legacy-v7", feature = "experimental-stream"))]
static PREV_NONCE: std::sync::Mutex<Option<[u8; NONCE_SIZE]>> = std::sync::Mutex::new(None);

/// Generate a cryptographically random 16-byte nonce, verifying it differs
/// from the previous one (FIPS 140-3 continuous RNG test, SP 800-140B §4.9.2).
#[cfg(any(test, feature = "legacy-v7", feature = "experimental-stream"))]
fn generate_nonce_with_crng_check() -> Result<[u8; NONCE_SIZE], String> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut prev = PREV_NONCE.lock().map_err(|_| "CRNG mutex poisoned".to_string())?;
    #[cfg(feature = "fault_injection")]
    if self_test::fault_injection::CRNG_STUCK.swap(false, std::sync::atomic::Ordering::AcqRel) {
        *prev = Some(nonce);
    }
    if let Some(prev_nonce) = *prev {
        if ct_eq_bytes(&nonce, &prev_nonce) {
            // CVF-35: SP 800-140B §4.9.2 "stuck-generator" check. The
            // single process-global PREV_NONCE slot is not a per-key
            // uniqueness guarantee — it catches only an immediately-stuck
            // DRBG, not restart-and-replay across processes or per-key
            // reuse across time. The previous message overstated the scope.
            // CVF-V5-19: a conditional self-test failure enters the sticky
            // module error state, so every gated entry point refuses until
            // the process restarts — not just this call.
            self_test::enter_error_state();
            return Err("CRNG stuck-generator check failed: consecutive draws matched (SP 800-140B §4.9.2); module entered the error state".into());
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
/// An interoperability default, not a security parameter on v8 (`sk` is the
/// only HMAC key). K=13 over `P` gives 128.49 bits post-Grover for the tuple;
/// the interval was widened to match `kem.rs`, not out of necessity — K=14
/// over the earlier `[10^6, 9.9e6]` interval would also have reached 134
/// bits (CVF-V5-3; paper Remark `rem:pq128`).
pub const DEFAULT_KEY_COUNT: usize = 13;

/// Upper bound on the number of prime elements per key (audit finding
/// CVF-41). Well above `DEFAULT_KEY_COUNT = 13` — the cap exists so that
/// a caller-supplied K cannot force `validate_key` into pathological work.
pub const MAX_KEY_ELEMENTS: usize = 128;

/// Largest key element representable in the 5-byte key serialisation used by
/// [`key_bytes`]. A larger value would be silently truncated to its low 5
/// bytes, yielding a different key element than Python (which rejects it).
pub const MAX_SERIALISABLE_KEY_PRIME: u64 = (1u64 << 40) - 1;

/// Odd primes below 59, tried before the general trial-division loop
/// (CVF-V5-30): they reject about 77% of odd composites with no loop setup.
const SMALL_ODD_PRIMES: [u64; 15] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

/// `floor(sqrt(n))`, exact for every `u64`.
fn isqrt_u64(n: u64) -> u64 {
    let mut r = (n as f64).sqrt() as u64;
    while r.checked_mul(r).map_or(true, |sq| sq > n) {
        r -= 1;
    }
    while (r + 1).checked_mul(r + 1).map_or(false, |sq| sq <= n) {
        r += 1;
    }
    r
}

/// Deterministic primality by trial division. Not constant-time: its running
/// time depends on `n` (see the paper's §8.4 list of non-constant-time
/// operations).
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n % 2 == 0 {
        return n == 2;
    }
    for &p in SMALL_ODD_PRIMES.iter() {
        if n % p == 0 {
            return n == p;
        }
    }
    // CVF-V5-30: the square-root bound is computed once, not per iteration.
    let limit = isqrt_u64(n);
    let mut i: u64 = 59;
    while i <= limit {
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
/// Returns `Err` (CVF-20) if the range is empty or if `count` distinct primes
/// are not found within [`KEYGEN_DRAWS_PER_PRIME`] draws per requested prime,
/// and (CVF-V5-14) if `count` is `0` or above [`MAX_KEY_ELEMENTS`], so it
/// never produces a tuple that `validate_key` would reject for its length.
/// At the normative interval's prime density (about 1 in 16) that cap is
/// roughly 250 times the expected number of draws, so a prime-poor range is
/// diagnosed in milliseconds instead of after `4·span` primality tests.
pub fn generate_prime_numbers(count: usize, min_val: u64, max_val: u64) -> Result<Vec<u64>, String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    use rand::distributions::{Distribution, Uniform};
    // CVF-V5-14: generate only what validate_key will accept.
    if count == 0 || count > MAX_KEY_ELEMENTS {
        return Err(format!(
            "generate_prime_numbers: count {} is outside [1, MAX_KEY_ELEMENTS = {}]",
            count, MAX_KEY_ELEMENTS
        ));
    }
    if max_val <= min_val {
        return Err(format!(
            "generate_prime_numbers: empty range [{}, {}]",
            min_val, max_val
        ));
    }
    let mut rng = rand::thread_rng();
    let dist = Uniform::new_inclusive(min_val, max_val);
    let max_attempts = (count.max(1) as u64).saturating_mul(KEYGEN_DRAWS_PER_PRIME);
    let mut primes: Vec<u64> = Vec::with_capacity(count);
    // CVF-V5-30: membership via binary search in a sorted index instead of a
    // linear `contains` per candidate. The index is key material and is
    // wiped before return (CVF-V5-11).
    let mut sorted: Vec<u64> = Vec::with_capacity(count);
    let mut attempts: u64 = 0;
    while primes.len() < count && attempts < max_attempts {
        // CVF-20: unbiased sample via rand::Uniform (Lemire rejection),
        // replacing the modulo-bias line `min_val + (rng.next_u64() % span)`.
        let num = dist.sample(&mut rng);
        if let Err(pos) = sorted.binary_search(&num) {
            if is_prime(num) {
                sorted.insert(pos, num);
                primes.push(num);
            }
        }
        attempts += 1;
    }
    zeroize_key(&mut sorted);
    if primes.len() < count {
        zeroize_key(&mut primes);
        return Err(format!(
            "generate_prime_numbers: could not find {} distinct primes in \
             [{}, {}] within {} draws; the range is too narrow or too prime-poor \
             for the requested count.",
            count, min_val, max_val, max_attempts
        ));
    }
    Ok(primes)
}

/// Draw budget per requested prime in [`generate_prime_numbers`] (CVF-20).
pub const KEYGEN_DRAWS_PER_PRIME: u64 = 4096;

// ─── HMAC helpers ────────────────────────────────────────────────────────────

/// v7 HMAC key: the 5-byte big-endian serialisation of the prime tuple,
/// wiped on drop (CVF-37).
fn key_bytes(key: &[u64]) -> crate::key::SecretBytes {
    let mut out = Vec::with_capacity(key.len() * 5);
    for &k in key {
        let b = k.to_be_bytes(); // 8 bytes
        out.extend_from_slice(&b[3..8]); // low 5 bytes, big-endian
    }
    crate::key::SecretBytes::new(out)
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
    // Cheap checks first: trial division of an out-of-range u64 costs seconds.
    if key.len() > MAX_KEY_ELEMENTS {
        return Err(format!(
            "Key has {} elements, exceeding MAX_KEY_ELEMENTS ({}). Very large \
             keys are rejected because per-message primality/distinctness \
             validation grows with K; the cap makes the cost of legitimate \
             use bounded.",
            key.len(),
            MAX_KEY_ELEMENTS
        ));
    }
    for (i, &k) in key.iter().enumerate() {
        if k < MIN_KEY_PRIME {
            return Err(format!(
                "Key element at index {} ({}) is below the minimum of {}.",
                i, k, MIN_KEY_PRIME
            ));
        }
        // CVF-16: enforce the normative upper bound on every key, not just on
        // generation.
        if k > MAX_KEY_PRIME {
            return Err(format!(
                "Key element at index {} ({}) exceeds MAX_KEY_PRIME ({}).",
                i, k, MAX_KEY_PRIME
            ));
        }
        // key_bytes keeps only the low 5 bytes; unreachable while
        // MAX_KEY_PRIME < 2^40, retained as a fail-safe.
        if k > MAX_SERIALISABLE_KEY_PRIME {
            return Err(format!(
                "Key element at index {} ({}) exceeds {}, the largest value \
                 representable in the 5-byte key serialisation.",
                i, k, MAX_SERIALISABLE_KEY_PRIME
            ));
        }
    }
    for (i, &k) in key.iter().enumerate() {
        if !is_prime(k) {
            return Err(format!("Key element at index {} ({}) is not prime.", i, k));
        }
    }
    // Distinctness via an in-place pairwise scan (CVF-V5-11): no scratch copy
    // of the key is made, so nothing is left on the heap to wipe. At most
    // MAX_KEY_ELEMENTS*(MAX_KEY_ELEMENTS-1)/2 = 8,128 comparisons, negligible
    // beside the trial division above.
    for i in 0..key.len() {
        for j in (i + 1)..key.len() {
            if key[i] == key[j] {
                return Err(format!(
                    "Key element at index {} duplicates index {}; all elements must be distinct.",
                    j, i
                ));
            }
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
    // CVF-34: public entry points check MAX_PLAINTEXT_CODEPOINTS and return
    // `Err`; this is the release-mode backstop for internal callers.
    assert!(n <= MAX_PLAINTEXT_CODEPOINTS, "Message too long for 2-codepoint length prefix");
    pad_to_block(msg, kb, nonce, bucket_block_size(n))
}

/// Padding body shared by every profile; `block_size` must exceed `msg.len()`,
/// which [`PadProfile::block_size`] guarantees for the profiles it accepts.
fn pad_to_block(msg: &[u32], kb: &[u8], nonce: &[u8], block_size: usize) -> Vec<u32> {
    let n = msg.len();
    // CVF-31: a release build must never reach `block_size - n` with block_size <= n.
    assert!(block_size > n, "padding block must exceed the message");
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

/// HMAC-CTR keystream (domain 0x07) that masks the serialised token blob.
///
/// Each 32-byte block is `HMAC(kb, 0x07 || nonce || uint32_be(block))`.
/// In the current fixed-width format the mask hides the token values, which
/// are otherwise affine in the plaintext codepoints (`c * k + a`) and whose
/// high-order bytes are always zero because tokens are far below 2^64; it
/// is what makes the ciphertext bytes look uniform. (CVF-V5-22: the earlier
/// LEB128 continuation-bit justification referred to a format that no longer
/// exists; the function name keeps its historical `varint_` prefix.)
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

// CVF-V5-4 / CVF-V5-7: v7 encryptors are compiled only with `legacy-v7`.
#[cfg(any(test, feature = "legacy-v7"))]
#[deprecated(
    since = "0.2.0",
    note = "v7 legacy format lacks the MAX_NOISE_RUN cap and per-bucket \
            ceiling (audit CVF-17): ciphertext length is a random function \
            of the CSPRNG-drawn nonce rather than of the padding bucket, so \
            the length-hiding property Corollary 4.14 proves for v8 does not \
            hold; v7 is keyed by the prime tuple, not sk, and no theorem of \
            the paper applies (CVF-28). Use encrypt_bytes_v8 / \
            encrypt_bytes_v8_with_profile."
)]
/// Legacy v7 low-level encryptor: returns the nonce and the raw token vector.
///
/// **Input domain (CVF-V5-17).** `message` must be a sequence of Unicode
/// scalar values (`0..=0x10FFFF` excluding the surrogates `0xD800..=0xDFFF`)
/// of at most [`MAX_PLAINTEXT_CODEPOINTS`] elements, and `key` must pass
/// key validation. Anything else is an `Err`, so every output of `encrypt`
/// is accepted by its inverse [`decrypt`].
pub fn encrypt(message: &[u32], key: &[u64]) -> Result<([u8; NONCE_SIZE], Vec<u64>), String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    if message.len() > MAX_PLAINTEXT_CODEPOINTS {
        return Err(format!(
            "message length {} exceeds MAX_PLAINTEXT_CODEPOINTS ({})",
            message.len(), MAX_PLAINTEXT_CODEPOINTS
        ));
    }
    if let Some((i, &c)) = message.iter().enumerate().find(|(_, &c)| char::from_u32(c).is_none()) {
        return Err(format!(
            "message value {:#x} at position {} is not a Unicode scalar value.",
            c, i
        ));
    }
    validate_key(key)?;
    let nonce = generate_nonce_with_crng_check()?;
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, &nonce);
    let padded = pad_message(message, &kb, &nonce);
    let cypher = emit_tokens_v7(&padded, &kb, &nonce, noise_p, key)?;
    Ok((nonce, cypher))
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

/// Key policy of the v7 **decryptors** (CVF-V5-16): the minimum the
/// arithmetic needs, not the v8 key policy. Non-empty, at most
/// [`MAX_KEY_ELEMENTS`] elements, each in `[2, MAX_SERIALISABLE_KEY_PRIME]`
/// (so `k - 1 >= 1` and `0x10FFFF * k + addend` cannot wrap `u64`), and
/// pairwise distinct. No primality test and no interval check, so keys
/// provisioned outside the current normative interval still open archived
/// v7 ciphertexts, and no trial division runs on the decrypt path.
fn validate_key_v7_decrypt(key: &[u64]) -> Result<(), String> {
    if key.is_empty() {
        return Err("Key must be a non-empty list of primes.".into());
    }
    if key.len() > MAX_KEY_ELEMENTS {
        return Err(format!(
            "Key has {} elements, exceeding MAX_KEY_ELEMENTS ({}).",
            key.len(),
            MAX_KEY_ELEMENTS
        ));
    }
    for (i, &k) in key.iter().enumerate() {
        if !(2..=MAX_SERIALISABLE_KEY_PRIME).contains(&k) {
            return Err(format!(
                "Key element at index {} ({}) is outside [2, {}].",
                i, k, MAX_SERIALISABLE_KEY_PRIME
            ));
        }
        if key[..i].contains(&k) {
            return Err(format!(
                "Key element at index {} duplicates an earlier element; all elements must be distinct.",
                i
            ));
        }
    }
    Ok(())
}

/// v7 low-level decrypt entry point. Returns the recovered codepoint sequence,
/// or an error if the token stream is malformed. Prior to CVF-14 this returned
/// `Vec<u32>` and panicked on a malformed padded buffer (see V3-CVF8); the
/// new signature propagates the error like every other decryption path.
/// Legacy v7: see [`decrypt_bytes`] for the caveats and the compatibility
/// envelope (CVF-V5-16).
pub fn decrypt(nonce: &[u8], cypher: &[u64], key: &[u64]) -> Result<Vec<u32>, String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    validate_key_v7_decrypt(key)?; // CVF-V5-16
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

/// Compare two byte slices in time independent of their contents. Lengths are
/// treated as public: unequal lengths return `false` without comparing
/// (CVF-45).
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
/// Used (CVF-V5-22: list corrected) at every tag verification site — v7
/// `open_v7` (`decrypt_bytes`, `decrypt_str`, `decrypt_raw`), v8
/// `decrypt_bytes_v8_core_inner`, and the v8 streaming chunk and sentinel
/// tags — on `[u8; TAG_SIZE]` operands; by the INT-2 integrity self-test on
/// 32-byte digests; and inside `generate_nonce_with_crng_check` on
/// `[u8; NONCE_SIZE]` operands (CVF-35 flags that the latter compares public
/// values — no constant-time requirement — but the comparator's uniform
/// length handling makes it safe there too).
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

/// Width in bytes of each fixed-width token field. Every token is
/// `c * k + a` with `c <= 0x10FFFF`, `k <= MAX_KEY_PRIME` and `a < k`, so
/// tokens are below 2^44 and always fit (CVF-21).
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
///
/// **Robustness bound (CVF-V5-4).** The loop is no longer unbounded: a run of
/// more than [`V7_NOISE_RUN_GUARD`] consecutive noise positions returns `Err`
/// instead of looping on. With the v7 threshold `p <= 0.99` such a run has
/// probability below `0.99^4096 < 2^-59` per real token, so the bound never
/// changes a ciphertext a v7 decryptor could have to read.
fn emit_tokens_v7(
    padded: &[u32],
    kb: &[u8],
    nonce: &[u8],
    noise_p: f64,
    key: &[u64],
) -> Result<Vec<u64>, String> {
    let kk = key.len() as u64;
    let mut cypher: Vec<u64> = Vec::with_capacity(padded.len() * 4);
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    for &c in padded {
        let mut run: u64 = 0;
        loop {
            // CVF-V5-31: statements common to both branches are hoisted.
            let k = key[(real_idx % kk) as usize];
            let is_noise = is_noise_pos(kb, nonce, ct_pos, noise_p);
            cypher.push(if is_noise {
                noise_token(kb, nonce, ct_pos, k)
            } else {
                c as u64 * k + derive_addend(kb, nonce, real_idx, k)
            });
            ct_pos += 1;
            if !is_noise {
                real_idx += 1;
                break;
            }
            run += 1;
            if run > V7_NOISE_RUN_GUARD {
                return Err(format!(
                    "v7 emission aborted: more than {} consecutive noise positions (CVF-V5-4)",
                    V7_NOISE_RUN_GUARD
                ));
            }
        }
    }
    Ok(cypher)
}

/// Upper bound on consecutive noise positions in the v7 emission loop
/// (CVF-V5-4). See [`emit_tokens_v7`].
const V7_NOISE_RUN_GUARD: u64 = 4096;

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

/// Legacy v7 text encryptor (one token per codepoint).
///
/// **Convention confusion (CVF-14 / CVF-V5-25).** The codepoint convention is
/// not bound into the tag: if every character is at most `U+00FF`, the
/// ciphertext also opens without error under [`decrypt_raw`], which returns
/// one byte per character (`"é"` becomes `[0xE9]`). Decrypt it only with
/// [`decrypt_bytes`] or [`decrypt_str`].
// CVF-V5-4 / CVF-V5-7: v7 encryptors are compiled only with `legacy-v7`.
#[cfg(any(test, feature = "legacy-v7"))]
#[deprecated(
    since = "0.2.0",
    note = "v7 legacy format lacks the MAX_NOISE_RUN cap and per-bucket \
            ceiling (audit CVF-17); v7 is keyed by the prime tuple, not sk, \
            and no theorem of the paper applies (CVF-28). Use \
            encrypt_bytes_v8 / encrypt_bytes_v8_with_profile."
)]
pub fn encrypt_bytes(message: &str, key: &[u64], aad: &[u8]) -> Result<Vec<u8>, String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    validate_key(key)?; // CVF-15
    check_v7_aad_len(aad.len())?;
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
    seal_v7(&codepoints, key, &nonce, aad)
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
    let codepoints: Vec<u32> = message.chars().map(|c| c as u32).collect();
    seal_v7(&codepoints, key, &nonce, aad)
        .expect("v7 KAT emission exceeded the CVF-V5-4 noise-run guard")
}

/// The v7 sealing pipeline shared by every v7 encryptor (CVF-V5-31):
/// pad, emit tokens, fixed-width encode, mask, tag. Callers have validated
/// the key and the length and drawn (or been given) the nonce.
fn seal_v7(
    codepoints: &[u32],
    key: &[u64],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let kb = key_bytes(key);
    let noise_p = derive_noise_p(&kb, nonce);
    let padded = pad_message(codepoints, &kb, nonce);
    let cypher = emit_tokens_v7(&padded, &kb, nonce, noise_p, key)?;
    let blob = fixed_encode_tokens(&cypher);
    let ks = varint_keystream(&kb, nonce, blob.len());
    let mut payload = Vec::with_capacity(NONCE_SIZE + blob.len() + TAG_SIZE);
    payload.extend_from_slice(nonce);
    payload.extend(blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b));
    let tag = compute_auth_tag(&kb, aad, &payload, AAD_LEN_WIDTH_V7);
    payload.extend_from_slice(&tag);
    Ok(payload)
}

/// Shared v7 open path of [`decrypt_bytes`] and [`decrypt_raw`] (CVF-V5-12).
///
/// Order: AAD-length and parse-floor checks, then the tag, and only then key
/// validation and token inversion. `key_bytes` and HMAC are defined for any
/// key, so a forged or truncated input is rejected after one HMAC and never
/// reaches the key-dependent validation, and validation runs once per call
/// (previously two or three times, before authentication).
fn open_v7(ciphertext: &[u8], key: &[u64], aad: &[u8]) -> Result<Vec<u32>, String> {
    check_v7_aad_len(aad.len())?;
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
    validate_key_v7_decrypt(key)?; // CVF-V5-16 relaxed policy, after authentication (CVF-V5-12)
    let nonce = &payload[..NONCE_SIZE];
    let masked = &payload[NONCE_SIZE..];
    let ks = varint_keystream(&kb, nonce, masked.len());
    let blob: Vec<u8> = masked.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let tokens = fixed_decode_tokens(&blob)
        .map_err(|e| format!("varint decode error: {}", e))?;
    decrypt_core(nonce, &tokens, key, &kb)
}

/// Legacy v7 decryptor, kept for archived ciphertexts. v7 keys every
/// derivation by the serialised prime tuple rather than an independent `sk`,
/// and no theorem of the NAPQES v4 paper applies to it (CVF-28).
///
/// # Compatibility envelope (CVF-V5-16)
///
/// Not every v7 ciphertext written by an earlier release decrypts:
///
/// * **Keys.** Accepted: 1 to [`MAX_KEY_ELEMENTS`] pairwise-distinct
///   elements, each in `[2, 2^40 - 1]` — no primality or interval check, so
///   keys provisioned under any earlier interval still work. Rejected: an
///   empty key, more than 128 elements, a repeated element, or an element
///   of 0, 1 or `>= 2^40` (which the 5-byte key serialisation of every
///   release truncated anyway).
/// * **Plaintexts.** A ciphertext whose recovered plaintext contains a value
///   that is not a Unicode scalar value (a surrogate `U+D800..U+DFFF` or a
///   value above `U+10FFFF`) is rejected. Such ciphertexts could be produced
///   by the v4 `encrypt` (any `u32`) and by the Python v7 `encrypt_bytes`
///   (lone surrogates in a `str`); no Rust encryptor of this release
///   produces them. [`decrypt_raw`] additionally rejects values above `0xFF`.
/// * Everything else — every key produced by an in-tree generator of any
///   release, and every scalar-valued plaintext — decrypts as before.
///
/// # Byte/codepoint convention (CVF-14 / CVF-V5-25)
///
/// The v7 tag does not bind the plaintext convention. A ciphertext produced
/// by `encrypt_raw` (feature `legacy-v7`; one token per byte) opens here **without error** and
/// returns the bytes reinterpreted as codepoints `U+0000..U+00FF`
/// (`encrypt_raw(&[0xC3, 0xA9])` decrypts to `"Ã©"`). Decrypt `encrypt_raw`
/// output only with [`decrypt_raw`]. v8 has one normative (codepoint)
/// convention and no such ambiguity.
pub fn decrypt_bytes(ciphertext: &[u8], key: &[u64], aad: &[u8]) -> Result<String, String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    let codepoints = open_v7(ciphertext, key, aad)?;
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

// CVF-V5-4 / CVF-V5-7: v7 encryptors are compiled only with `legacy-v7`.
#[cfg(any(test, feature = "legacy-v7"))]
#[deprecated(
    since = "0.2.0",
    note = "v7 legacy format lacks the MAX_NOISE_RUN cap and per-bucket \
            ceiling (audit CVF-17); v7 is keyed by the prime tuple, not sk, \
            and no theorem of the paper applies (CVF-28). Use encrypt_bytes_v8."
)]
pub fn encrypt_str(message: &str, key: &[u64], aad: &[u8]) -> Result<String, String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    // CVF-15: transitively covered by encrypt_bytes, but early-rejecting a
    // bad key means we never allocate the base64 buffer for a doomed op.
    validate_key(key)?;
    #[allow(deprecated)]
    Ok(STANDARD.encode(encrypt_bytes(message, key, aad)?))
}

/// Legacy v7 decryptor (base64 wrapper over [`decrypt_bytes`]); see that
/// function for the v7 caveats.
pub fn decrypt_str(cypher: &str, key: &[u64], aad: &[u8]) -> Result<String, String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    // CVF-V5-12: no key validation here; decrypt_bytes validates once,
    // after the tag check.
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
/// into the authentication tag.
///
/// **Convention confusion (CVF-14 / CVF-V5-25).** The byte convention is
/// not bound into the tag, so this ciphertext also opens without error under
/// [`decrypt_bytes`], which returns the bytes reinterpreted as codepoints
/// (`[0xC3, 0xA9]` comes back as `"Ã©"`, not `"é"`). Decrypt it only with
/// [`decrypt_raw`].
///
/// Deprecated per CVF-17: length depends on the nonce for v7. New callers
/// should encode their bytes and use [`encrypt_bytes_v8`] instead.
// CVF-V5-4 / CVF-V5-7: v7 encryptors are compiled only with `legacy-v7`.
#[cfg(any(test, feature = "legacy-v7"))]
#[deprecated(
    since = "0.2.0",
    note = "v7 legacy format lacks the MAX_NOISE_RUN cap and per-bucket \
            ceiling (audit CVF-17), and the byte-vs-codepoint encoding \
            ambiguity of CVF-14 remains; v7 is keyed by the prime tuple, not \
            sk, and no theorem of the paper applies (CVF-28). Use \
            encrypt_bytes_v8 for text or wrap the bytes in a caller-chosen \
            text encoding."
)]
pub fn encrypt_raw(data: &[u8], key: &[u64], aad: &[u8]) -> Result<Vec<u8>, String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    validate_key(key)?; // CVF-15
    check_v7_aad_len(aad.len())?;
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
    seal_v7(&codepoints, key, &nonce, aad)
}

/// Decrypt binary data previously encrypted with `encrypt_raw` (feature `legacy-v7`).
///
/// Legacy v7 decryptor, kept for archived ciphertexts; see [`decrypt_bytes`]
/// for the v7 caveats and the compatibility envelope.
///
/// **Use only for ciphertexts produced by `encrypt_raw` (CVF-14 /
/// CVF-V5-25).** v7 binds neither convention into the tag, so a ciphertext
/// produced by `encrypt_bytes` (one codepoint per character) also opens
/// here without error whenever every character is at most `U+00FF`: `"é"`
/// comes back as the single byte `[0xE9]`, not its UTF-8 encoding. Values
/// above `U+00FF` are rejected.
///
/// Verifies the HMAC tag (constant-time) before decrypting.  Returns
/// `Err` on authentication failure — the caller must never use the
/// ciphertext for any purpose if this returns an error.
pub fn decrypt_raw(ciphertext: &[u8], key: &[u64], aad: &[u8]) -> Result<Vec<u8>, String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    let codepoints = open_v7(ciphertext, key, aad)?;
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
// break. Callers who require distinct ciphertexts for repeated identical
// messages should bind a unique value (counter, timestamp) into the AAD,
// which the synthetic nonce covers; the v7 random-nonce API is deprecated
// (CVF-17) and is not a substitute.
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
// See the NAPQES v4 paper (`docs/napseq-eprint-v3.tex`, Sections 3.2-3.3
// and 4) and `docs/CAVEATS.md` (CVF3/CVF8/CVF13 follow-ups) for the full
// specification and security argument.

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
///
/// A fixed protocol constant (CVF-V5-13: the `noise_x10` feature that
/// changed it to 9 without domain separation has been removed).
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
///
/// Returns `Err` (CVF-20) if `[min_val, max_val]` is not a sub-range of the
/// normative interval `[MIN_KEY_PRIME, MAX_KEY_PRIME]` (such a key would fail
/// `validate_key`), if `count` is `0` or above [`MAX_KEY_ELEMENTS`]
/// (CVF-V5-14), or if `count` distinct primes cannot be drawn from it.
///
/// The returned `sk` is `Copy`: wipe every copy (see [`zeroize_sk`]), or use
/// [`crate::NapqesKey::generate`], which owns both components and wipes them
/// on drop.
pub fn generate_v8_key(
    count: usize,
    min_val: u64,
    max_val: u64,
) -> Result<(Vec<u64>, [u8; SK_SIZE]), String> {
    // CVF-V5-8: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    if !(MIN_KEY_PRIME <= min_val && max_val <= MAX_KEY_PRIME) {
        return Err(format!(
            "generate_v8_key: range [{}, {}] lies outside [MIN_KEY_PRIME, MAX_KEY_PRIME]",
            min_val, max_val
        ));
    }
    let primes = generate_prime_numbers(count, min_val, max_val)?;
    let mut sk = [0u8; SK_SIZE];
    rand::thread_rng().fill_bytes(&mut sk);
    Ok((primes, sk))
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
///
/// **Per-call key validation (CVF-29 / CVF-V5-29).** This bare-slice entry
/// point runs full key validation (trial division) on every call, and its
/// running time depends on the secret primes. Construct a [`NapqesKey`] once
/// and use the `_key` variant instead.
#[deprecated(
    since = "0.3.0",
    note = "validates the key by trial division on every call, with timing that \
            depends on the secret primes (CVF-29 / CVF-V5-29); construct a \
            NapqesKey once and use the _key variant"
)]
pub fn encrypt_bytes_v8(
    message: &str,
    primes: &[u64],
    sk: &[u8; SK_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    #[allow(deprecated)]
    encrypt_bytes_v8_with_profile(message, primes, sk, aad, PadProfile::Bucket)
}

/// [`encrypt_bytes_v8`] with an explicit padding profile
/// (docs/napseq-eprint-v3.tex, Section "Padding Profiles").
///
/// The profile governs how much plaintext length the ciphertext size reveals:
/// [`PadProfile::Bucket`] leaks at most ~3.70 bits, [`PadProfile::Frame`]
/// exactly zero. It is a sender-side parameter, never transmitted;
/// [`decrypt_bytes_v8`] needs no matching argument.
///
/// **Per-call key validation (CVF-29 / CVF-V5-29).** This bare-slice entry
/// point runs full key validation (trial division) on every call, and its
/// running time depends on the secret primes. Construct a [`NapqesKey`] once
/// and use the `_key` variant instead.
#[deprecated(
    since = "0.3.0",
    note = "validates the key by trial division on every call, with timing that \
            depends on the secret primes (CVF-29 / CVF-V5-29); construct a \
            NapqesKey once and use the _key variant"
)]
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
    // CVF-37: `sk_fmt` keys every derivation; the guard wipes it on every exit.
    let sk_fmt = Secret32::new(derive_format_subkey(sk, FORMAT_BLOCK_V8));
    encrypt_bytes_v8_core_inner(sk_fmt.as_ref(), message, primes, aad, pad_profile)
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
    let block_size = pad_profile.block_size(codepoints.len())?;
    let padded = pad_to_block(&codepoints, sk_fmt, &nonce, block_size);
    let cypher = emit_tokens_v8(&padded, primes, sk_fmt, &nonce);
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
///
/// **Per-call key validation (CVF-29 / CVF-V5-29).** This bare-slice entry
/// point runs full key validation (trial division) on every call, and its
/// running time depends on the secret primes. Construct a [`NapqesKey`] once
/// and use the `_key` variant instead.
#[deprecated(
    since = "0.3.0",
    note = "validates the key by trial division on every call, with timing that \
            depends on the secret primes (CVF-29 / CVF-V5-29); construct a \
            NapqesKey once and use the _key variant"
)]
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
    // Dec step (3): the token count depends on |C| alone, so reject before the tag.
    let blob_len = ciphertext.len() - NONCE_SIZE - TAG_SIZE;
    if blob_len % (TOKEN_WIDTH * (MAX_NOISE_RUN as usize + 1)) != 0 {
        return Err(
            "Malformed v8 ciphertext: token count is not a multiple of the padding ceiling; \
             expected exactly real_token_count * (MAX_NOISE_RUN + 1) tokens.".into(),
        );
    }
    let sk_fmt = Secret32::new(derive_format_subkey(sk, FORMAT_BLOCK_V8));
    decrypt_bytes_v8_core_inner(sk_fmt.as_ref(), ciphertext, primes, aad)
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

/// Securely erase the v8 master secret `sk` by overwriting it with zero.
///
/// The derived format subkey `sk_fmt` is wiped inside each entry point.
/// `[u8; SK_SIZE]` is `Copy`, so this wipes only the copy passed in; every
/// other copy the caller made must be wiped too (CVF-37).
pub fn zeroize_sk(sk: &mut [u8; SK_SIZE]) {
    for x in sk.iter_mut() {
        unsafe { std::ptr::write_volatile(x, 0u8) };
    }
}

/// v8 block tag over `payload = nonce || masked` under `sk` (used by KAT-6).
pub(crate) fn retag_block_v8(payload: &[u8], sk: &[u8; SK_SIZE], aad: &[u8]) -> [u8; TAG_SIZE] {
    let sk_fmt = Secret32::new(derive_format_subkey(sk, FORMAT_BLOCK_V8));
    compute_auth_tag(sk_fmt.as_ref(), aad, payload, AAD_LEN_WIDTH_V8)
}

/// Fuzzing hook: lets the fuzzer reach post-authentication decode paths.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_retag_block_v8(payload: &[u8], sk: &[u8; SK_SIZE], aad: &[u8]) -> [u8; TAG_SIZE] {
    retag_block_v8(payload, sk, aad)
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

/// Wipe a plaintext codepoint buffer over its whole capacity (live elements
/// and the spare capacity left by earlier `clear`/`drain` calls), then
/// empty it (CVF-V5-11).
#[cfg(any(test, feature = "experimental-stream"))]
fn zeroize_codepoints(buf: &mut Vec<u32>) {
    let cap = buf.capacity();
    buf.resize(cap, 0);
    for x in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(x, 0u32) };
    }
    buf.clear();
}

// --- Streaming AE v8 (EXPERIMENTAL, feature `experimental-stream`) -----------
//
// CVF-V5-2: this format has no security definition or proof in the paper and
// is outside the audited claims. It is NOT misuse-resistant: the per-stream
// nonce is drawn from a CSPRNG (no synthetic nonce), so nonce reuse under one
// sk is catastrophic. Full byte-level specification: SPEC.md section 8.2.
//
// Wire format (FORMAT_STREAM_AE_V8 = 0x02):
//   HEADER (21 B):     0x02 || be4(F) || nonce(16, CSPRNG)
//   CHUNK FRAME * C:   be4(F*160) || masked_chunk(F*160) || chunk_tag(32)
//   SENTINEL (44 B):   be4(0) || be8(total_real_codepoints) XOR count_mask || sentinel_tag(32)
//
// CVF-V5-9: chunk tags, the sentinel tag and count_mask all bind the full
// 21-byte HEADER (format byte, F, nonce), not just the nonce.
// CVF-V5-1: count_mask = HMAC(sk_fmt, 0x0F || HEADER || be4(C))[:8], so the
// exact codepoint count is not sent in clear; the chunk count C (that is,
// ceil(n / F)) remains visible and is the residual length leak.
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

#[cfg(any(test, feature = "experimental-stream"))]
const DOMAIN_STREAM_V8_CHUNK_TAG: u8 = 0x0C;
#[cfg(any(test, feature = "experimental-stream"))]
const DOMAIN_STREAM_V8_SENTINEL:  u8 = 0x0D;
#[cfg(any(test, feature = "experimental-stream"))]
const DOMAIN_STREAM_V8_SUBNONCE:  u8 = 0x0E;
/// CVF-V5-1: domain of the keystream that masks the sentinel's codepoint count.
#[cfg(any(test, feature = "experimental-stream"))]
const DOMAIN_STREAM_V8_COUNT_MASK: u8 = 0x0F;

/// The 21-byte stream header `0x02 || be4(F) || nonce`. CVF-V5-9: it is bound
/// in full into every chunk tag, the sentinel tag and the count mask, so no
/// header byte (in particular `F` of an empty stream) is malleable.
#[cfg(any(test, feature = "experimental-stream"))]
fn stream_v8_header(f: u32, nonce: &[u8; NONCE_SIZE]) -> [u8; 1 + 4 + NONCE_SIZE] {
    let mut h = [0u8; 1 + 4 + NONCE_SIZE];
    h[0] = FORMAT_STREAM_AE_V8;
    h[1..5].copy_from_slice(&f.to_be_bytes());
    h[5..].copy_from_slice(nonce);
    h
}

/// CVF-V5-1: `HMAC(sk_fmt, 0x0F || header || be4(chunk_count))[:8]`, XORed
/// onto `be8(total_real_codepoints)` in the sentinel so the exact length is
/// not sent in clear. Only the chunk count (`ceil(n / F)`) remains visible.
#[cfg(any(test, feature = "experimental-stream"))]
fn stream_v8_count_mask(
    sk_fmt: &[u8; 32],
    f: u32,
    nonce: &[u8; NONCE_SIZE],
    chunk_count: u32,
) -> u64 {
    let mut buf = Vec::with_capacity(1 + 21 + 4);
    buf.push(DOMAIN_STREAM_V8_COUNT_MASK);
    buf.extend_from_slice(&stream_v8_header(f, nonce));
    buf.extend_from_slice(&chunk_count.to_be_bytes());
    u64_from_be8(&hmac_digest(sk_fmt, &buf)[..8])
}

#[cfg(any(test, feature = "experimental-stream"))]
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
#[cfg(any(test, feature = "experimental-stream"))]
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
#[cfg(any(test, feature = "experimental-stream"))]
fn encrypt_v8_stream_chunk_core(
    chunk_cps: &[u32],
    primes: &[u64],
    sk_fmt: &[u8; 32],
    sub_nonce: &[u8; NONCE_SIZE],
) -> Vec<u64> {
    emit_tokens_v8(chunk_cps, primes, sk_fmt, sub_nonce)
}

/// The v8 token-emission loop, shared by the block format and every
/// streaming chunk (CVF-V5-31). `nonce` is the block nonce or the chunk's
/// sub-nonce. Emits exactly `padded.len() * (MAX_NOISE_RUN + 1)` tokens:
/// runs of noise are capped at `MAX_NOISE_RUN`, and the tail is topped up
/// with noise to that fixed ceiling (V2-CVF2) so the length never depends on
/// the noise realisation.
fn emit_tokens_v8(padded: &[u32], primes: &[u64], sk_fmt: &[u8; 32], nonce: &[u8]) -> Vec<u64> {
    let noise_theta = derive_noise_threshold_v8(sk_fmt, nonce);
    let kk = primes.len() as u64;
    let ceiling = (padded.len() as u64) * (MAX_NOISE_RUN + 1);
    let mut cypher: Vec<u64> = Vec::with_capacity(ceiling as usize);
    let mut real_idx: u64 = 0;
    let mut ct_pos: u64 = 0;
    for &c in padded {
        let mut noise_run: u64 = 0;
        loop {
            let k = primes[(real_idx % kk) as usize];
            let is_noise =
                noise_run < MAX_NOISE_RUN && is_noise_pos_v8(sk_fmt, nonce, ct_pos, noise_theta);
            cypher.push(if is_noise {
                noise_token(sk_fmt, nonce, ct_pos, k)
            } else {
                c as u64 * k + derive_addend(sk_fmt, nonce, real_idx, k)
            });
            ct_pos += 1;
            if !is_noise {
                real_idx += 1;
                break;
            }
            noise_run += 1;
        }
    }
    while (cypher.len() as u64) < ceiling {
        let k = primes[(real_idx % kk) as usize];
        cypher.push(noise_token(sk_fmt, nonce, ct_pos, k));
        ct_pos += 1;
    }
    cypher
}

/// A noise token at position `ct_pos`: `noise_char * k + noise_addend`.
fn noise_token(kb: &[u8], nonce: &[u8], ct_pos: u64, k: u64) -> u64 {
    derive_noise_char(kb, nonce, ct_pos) * k + derive_noise_token_addend(kb, nonce, ct_pos, k)
}

/// Recover exactly F codepoints from a streaming chunk's token stream.
#[cfg(any(test, feature = "experimental-stream"))]
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

#[cfg(any(test, feature = "experimental-stream"))]
fn compute_stream_v8_chunk_tag(
    sk_fmt: &[u8; 32],
    f: u32,
    nonce: &[u8; NONCE_SIZE],
    chunk_idx: u32,
    aad: &[u8],
    masked_chunk: &[u8],
) -> [u8; TAG_SIZE] {
    let mut buf = Vec::with_capacity(1 + 21 + 4 + AAD_LEN_WIDTH_V8 + aad.len() + masked_chunk.len());
    buf.push(DOMAIN_STREAM_V8_CHUNK_TAG);
    buf.extend_from_slice(&stream_v8_header(f, nonce)); // CVF-V5-9
    buf.extend_from_slice(&chunk_idx.to_be_bytes());
    buf.extend_from_slice(&be_len_prefix(aad.len(), AAD_LEN_WIDTH_V8));
    buf.extend_from_slice(aad);
    buf.extend_from_slice(masked_chunk);
    hmac_digest(sk_fmt, &buf)
}

#[cfg(any(test, feature = "experimental-stream"))]
fn compute_stream_v8_sentinel_tag(
    sk_fmt: &[u8; 32],
    f: u32,
    nonce: &[u8; NONCE_SIZE],
    chunk_count: u32,
    aad: &[u8],
    total_real_cps: u64,
) -> [u8; TAG_SIZE] {
    let mut buf = Vec::with_capacity(1 + 21 + 4 + AAD_LEN_WIDTH_V8 + aad.len() + 8);
    buf.push(DOMAIN_STREAM_V8_SENTINEL);
    buf.extend_from_slice(&stream_v8_header(f, nonce)); // CVF-V5-9
    buf.extend_from_slice(&chunk_count.to_be_bytes());
    buf.extend_from_slice(&be_len_prefix(aad.len(), AAD_LEN_WIDTH_V8));
    buf.extend_from_slice(aad);
    buf.extend_from_slice(&total_real_cps.to_be_bytes());
    hmac_digest(sk_fmt, &buf)
}

#[cfg(any(test, feature = "experimental-stream"))]
fn validate_stream_v8_frame(f: u32) -> Result<(), String> {
    if f < 1 || f > STREAM_AE_V8_MAX_FRAME {
        return Err(format!(
            "frame_codepoints must be in [1, {}], got {}",
            STREAM_AE_V8_MAX_FRAME, f
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "experimental-stream"))]
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
    let tag = compute_stream_v8_chunk_tag(sk_fmt, codepoints_f.len() as u32, nonce, idx, aad, &masked);
    let mut out = Vec::with_capacity(4 + masked.len() + TAG_SIZE);
    out.extend_from_slice(&(masked.len() as u32).to_be_bytes());
    out.extend_from_slice(&masked);
    out.extend_from_slice(&tag);
    out
}

/// Deterministic v8 streaming encryption with caller-supplied nonce.
///
/// The core of [`encrypt_stream_ae_v8`], which calls it with a fresh CSPRNG
/// nonce, and of the KAT harness (`kat_cross_check::stream_v8_*`), which
/// calls it with fixed nonces (CVF-V5-2: the previous "test-only" label was
/// wrong). It is `pub(crate)` because a caller-chosen nonce is a CVF3-class
/// hazard: reusing a nonce across two streams under the same `sk` is
/// catastrophic (CAV-005).
#[cfg(any(test, feature = "experimental-stream"))]
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

    let sk_fmt = Secret32::new(derive_format_subkey(sk, FORMAT_STREAM_AE_V8));
    encrypt_stream_ae_v8_inner(plaintext, primes, sk_fmt.as_ref(), nonce, aad, frame_codepoints)
}

#[cfg(any(test, feature = "experimental-stream"))]
fn encrypt_stream_ae_v8_inner(
    plaintext: &str,
    primes: &[u64],
    sk_fmt: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    frame_codepoints: u32,
) -> Result<Vec<u8>, String> {
    let f = frame_codepoints as usize;

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
            let next = next_stream_chunk_idx(chunk_idx)?;
            let frame = emit_stream_v8_chunk(&cp_buf[..f], chunk_idx, primes, sk_fmt, nonce, aad);
            stream.extend_from_slice(&frame);
            cp_buf.drain(..f);
            chunk_idx = next;
        }
    }

    if !cp_buf.is_empty() {
        let next = next_stream_chunk_idx(chunk_idx)?;
        let sub_nonce_last = derive_stream_v8_sub_nonce(sk_fmt, nonce, chunk_idx);
        let fill_needed = f - cp_buf.len();
        for i in 0..fill_needed {
            cp_buf.push(derive_stream_v8_filler_cp(sk_fmt, &sub_nonce_last, i as u32));
        }
        let frame = emit_stream_v8_chunk(&cp_buf, chunk_idx, primes, sk_fmt, nonce, aad);
        stream.extend_from_slice(&frame);
        chunk_idx = next;
    }

    let sentinel_tag = compute_stream_v8_sentinel_tag(
        sk_fmt, frame_codepoints, nonce, chunk_idx, aad, total_real_cps);
    let mask = stream_v8_count_mask(sk_fmt, frame_codepoints, nonce, chunk_idx);
    stream.extend_from_slice(&0u32.to_be_bytes());
    stream.extend_from_slice(&(total_real_cps ^ mask).to_be_bytes()); // CVF-V5-1
    stream.extend_from_slice(&sentinel_tag);

    Ok(stream)
}

/// Chunk indices are u32 and bound into every sub-nonce; wrapping would reuse keystream.
#[cfg(any(test, feature = "experimental-stream"))]
fn next_stream_chunk_idx(chunk_idx: u32) -> Result<u32, String> {
    chunk_idx
        .checked_add(1)
        .ok_or_else(|| "v8 stream exceeds the 2^32 - 1 chunk limit.".to_string())
}

/// v8 streaming-AE encryption -- returns the full ciphertext byte stream.
///
/// Convenience "all-at-once" API: consumes the entire plaintext and returns
/// the fully framed byte stream in one call. Uses a CSPRNG-drawn 16-byte
/// nonce (with the FIPS CRNG self-test), not a synthetic one, so it is not
/// misuse-resistant even though it holds the whole message (CVF-V5-10); a
/// synthetic stream nonce would need its own analysis and is not offered.
/// For chunk-at-a-time production use [`StreamV8Encryptor`].
///
/// `frame_codepoints` (F) sets the per-chunk real-codepoint capacity: each
/// chunk carries exactly F codepoint slots (partial last chunk padded with
/// HMAC-derived filler) and expands to a fixed F*160 bytes of masked_blob.
/// Chunk size is therefore a pure function of F, which is public.
///
/// **Not misuse-resistant**: nonce reuse under the same `sk` is catastrophic
/// (CAV-005). Use the v8 *block* API (`encrypt_bytes_v8`) whenever the whole
/// message fits in memory and MRAE is desired.
#[cfg(any(test, feature = "experimental-stream"))]
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

/// [`encrypt_stream_ae_v8`] taking a validated [`NapqesKey`]: no per-call
/// key validation (CVF-V5-29).
#[cfg(any(test, feature = "experimental-stream"))]
pub fn encrypt_stream_ae_v8_key(
    plaintext: &str,
    key: &NapqesKey,
    aad: &[u8],
    frame_codepoints: u32,
) -> Result<Vec<u8>, String> {
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    validate_stream_v8_frame(frame_codepoints)?;
    let nonce = generate_nonce_with_crng_check()?;
    let sk_fmt = Secret32::new(derive_format_subkey(key.sk(), FORMAT_STREAM_AE_V8));
    encrypt_stream_ae_v8_inner(plaintext, key.primes(), sk_fmt.as_ref(), &nonce, aad, frame_codepoints)
}

/// [`decrypt_stream_ae_v8`] taking a validated [`NapqesKey`]: no per-call
/// key validation (CVF-V5-29).
#[cfg(any(test, feature = "experimental-stream"))]
pub fn decrypt_stream_ae_v8_key(stream: &[u8], key: &NapqesKey, aad: &[u8]) -> Result<String, String> {
    #[cfg(feature = "fips_gate")]
    self_test::require_post().map_err(|e| e.to_string())?;
    let sk_fmt = Secret32::new(derive_format_subkey(key.sk(), FORMAT_STREAM_AE_V8));
    decrypt_stream_ae_v8_inner(stream, key.primes(), sk_fmt.as_ref(), aad)
}

/// v8 streaming-AE decryption -- consumes the full ciphertext byte stream.
///
/// **Not incremental (CVF-V5-10).** Rust streaming is incremental on the
/// encrypt side only ([`StreamV8Encryptor`]). This decryptor needs the
/// complete stream in memory — about 160 bytes per plaintext codepoint plus
/// 36 bytes per chunk — and returns nothing until every chunk tag and the
/// sentinel have verified, so it never releases unverified plaintext. A
/// receiver that cannot hold the whole stream must not use this format. The
/// Python port's generator is incremental and releases chunks before the
/// sentinel (CAV-001); the two ports share the wire format, not the release
/// semantics.
///
/// Each per-chunk tag is verified before that chunk is decoded; the sentinel
/// binds the chunk count (anti-truncation) and the true real-codepoint count
/// (used to strip filler codepoints from the last chunk).
#[cfg(any(test, feature = "experimental-stream"))]
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
    let sk_fmt = Secret32::new(derive_format_subkey(sk, FORMAT_STREAM_AE_V8));
    decrypt_stream_ae_v8_inner(stream, primes, sk_fmt.as_ref(), aad)
}

#[cfg(any(test, feature = "experimental-stream"))]
fn decrypt_stream_ae_v8_inner(
    stream: &[u8],
    primes: &[u64],
    sk_fmt: &[u8; 32],
    aad: &[u8],
) -> Result<String, String> {
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
            // SENTINEL: be8(total_real_cps XOR count_mask) || tag(32)
            if stream.len() < pos + 8 + TAG_SIZE {
                return Err("Stream truncated: need sentinel body.".into());
            }
            let total_real_cps =
                u64_from_be8(&stream[pos..pos + 8]) ^ stream_v8_count_mask(sk_fmt, f, &nonce, chunk_idx);
            let recv_tag = &stream[pos + 8..pos + 8 + TAG_SIZE];
            let calc = compute_stream_v8_sentinel_tag(
                sk_fmt, f, &nonce, chunk_idx, aad, total_real_cps);
            if !ct_eq_bytes(recv_tag, calc.as_ref()) {
                return Err("Authentication failed: invalid v8 stream sentinel tag.".into());
            }
            pos += 8 + TAG_SIZE;

            let pending_len = pending.as_ref().map(|v| v.len()).unwrap_or(0);
            let delivered_len = delivered.len() as u64;
            let available = delivered_len + (pending_len as u64);
            // Canonical form: the final chunk carries at least one real codepoint.
            let consistent = match pending {
                Some(_) => total_real_cps > delivered_len && total_real_cps <= available,
                None => total_real_cps == delivered_len,
            };
            if !consistent {
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
        let calc = compute_stream_v8_chunk_tag(sk_fmt, f, &nonce, chunk_idx, aad, masked);
        if !ct_eq_bytes(recv_tag, calc.as_ref()) {
            return Err(format!(
                "Authentication failed: invalid tag on v8 stream chunk {}.",
                chunk_idx
            ));
        }
        pos += chunk_len + TAG_SIZE;
        let next = next_stream_chunk_idx(chunk_idx)?;

        // Tag verified -- unmask and decode.
        let sub_nonce = derive_stream_v8_sub_nonce(sk_fmt, &nonce, chunk_idx);
        let ks = varint_keystream(sk_fmt, &sub_nonce, chunk_len);
        let blob: Vec<u8> = masked.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        let tokens = fixed_decode_tokens(&blob)?;
        let cps = decrypt_v8_stream_chunk_core(&tokens, primes, sk_fmt, &sub_nonce, f)?;

        if let Some(p) = pending.take() {
            delivered.extend(p);
        }
        pending = Some(cps);
        chunk_idx = next;
    }
}

/// Streaming (chunk-at-a-time) encryptor for FORMAT_STREAM_AE_V8.
///
/// Emits the 21-byte header from `new`, one full chunk per completed frame
/// via `push`, and the sentinel from `finish`. See [`encrypt_stream_ae_v8`]
/// for the security caveats (CAV-005).
#[cfg(any(test, feature = "experimental-stream"))]
pub struct StreamV8Encryptor {
    primes: Vec<u64>,
    // CVF-V5-11: boxed so that moving the encryptor never copies sk_fmt.
    sk_fmt: Box<Secret32>,
    aad: Vec<u8>,
    nonce: [u8; NONCE_SIZE],
    f: u32,
    chunk_idx: u32,
    total_real_cps: u64,
    cp_buf: Vec<u32>,
    finished: bool,
}

#[cfg(any(test, feature = "experimental-stream"))]
impl StreamV8Encryptor {
    /// Create a new encryptor and return `(self, header_bytes)`. `header_bytes`
    /// is exactly 21 B (0x02 || be4(F) || nonce). The nonce is drawn from a
    /// CSPRNG with the FIPS CRNG self-test.
    ///
    /// Validates the prime tuple by trial division on every call, with timing
    /// that depends on the secret primes (CVF-V5-29); prefer [`Self::new_key`].
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
        Self::new_validated(primes, sk, aad, frame_codepoints)
    }

    /// [`Self::new`] taking a validated [`NapqesKey`]: no per-call key
    /// validation (CVF-V5-29).
    pub fn new_key(key: &NapqesKey, aad: &[u8], frame_codepoints: u32) -> Result<(Self, Vec<u8>), String> {
        #[cfg(feature = "fips_gate")]
        crate::self_test::require_post().map_err(|e| e.to_string())?;
        Self::new_validated(key.primes(), key.sk(), aad, frame_codepoints)
    }

    fn new_validated(
        primes: &[u64],
        sk: &[u8; SK_SIZE],
        aad: &[u8],
        frame_codepoints: u32,
    ) -> Result<(Self, Vec<u8>), String> {
        validate_stream_v8_frame(frame_codepoints)?;
        let nonce = generate_nonce_with_crng_check()?;
        let sk_fmt = Box::new(Secret32::new(derive_format_subkey(sk, FORMAT_STREAM_AE_V8)));
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
        // CVF-47: a failed POST re-run after construction must stop output.
        #[cfg(feature = "fips_gate")]
        crate::self_test::require_post().map_err(|e| e.to_string())?;
        if self.chunk_idx == u32::MAX {
            return Err("v8 stream exceeds the 2^32 - 1 chunk limit.".into());
        }
        self.cp_buf.push(ch as u32);
        self.total_real_cps += 1;
        if self.cp_buf.len() >= self.f as usize {
            let frame = emit_stream_v8_chunk(
                &self.cp_buf[..self.f as usize],
                self.chunk_idx,
                &self.primes,
                Secret32::as_ref(&self.sk_fmt),
                &self.nonce,
                &self.aad,
            );
            // CVF-V5-11: wipe the consumed plaintext before releasing it.
            zeroize_codepoints(&mut self.cp_buf);
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
        #[cfg(feature = "fips_gate")]
        crate::self_test::require_post().map_err(|e| e.to_string())?;
        self.finished = true;
        let mut out: Vec<u8> = Vec::new();
        if !self.cp_buf.is_empty() {
            let sub_nonce_last =
                derive_stream_v8_sub_nonce(Secret32::as_ref(&self.sk_fmt), &self.nonce, self.chunk_idx);
            let fill_needed = (self.f as usize) - self.cp_buf.len();
            for i in 0..fill_needed {
                self.cp_buf.push(derive_stream_v8_filler_cp(
                    Secret32::as_ref(&self.sk_fmt), &sub_nonce_last, i as u32));
            }
            let frame = emit_stream_v8_chunk(
                &self.cp_buf,
                self.chunk_idx,
                &self.primes,
                Secret32::as_ref(&self.sk_fmt),
                &self.nonce,
                &self.aad,
            );
            out.extend_from_slice(&frame);
            self.chunk_idx += 1;
        }
        let sk_fmt = Secret32::as_ref(&self.sk_fmt);
        let tag = compute_stream_v8_sentinel_tag(
            sk_fmt, self.f, &self.nonce, self.chunk_idx, &self.aad, self.total_real_cps);
        let mask = stream_v8_count_mask(sk_fmt, self.f, &self.nonce, self.chunk_idx);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(self.total_real_cps ^ mask).to_be_bytes()); // CVF-V5-1
        out.extend_from_slice(&tag);
        Ok(out)
    }
}

#[cfg(any(test, feature = "experimental-stream"))]
impl Drop for StreamV8Encryptor {
    fn drop(&mut self) {
        zeroize_key(&mut self.primes);
        zeroize_codepoints(&mut self.cp_buf);
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(deprecated)] // exercises the deprecated bare-slice and v7 entry points
mod tests {
    // CVF-17: these tests exercise the v7 legacy encryptors that are now
    // #[deprecated]. The deprecation is a message to external consumers to
    // migrate to v8; the tests themselves are the crate's own regression
    // coverage of the legacy surface and need to keep calling those APIs
    // without emitting a wall of warnings.
    #![allow(deprecated)]

    use super::*;

    // CVF-20: key generation is fallible; these shadow the glob import for
    // tests that only use the always-valid normative interval.
    fn generate_v8_key(count: usize, min_val: u64, max_val: u64) -> (Vec<u64>, [u8; SK_SIZE]) {
        super::generate_v8_key(count, min_val, max_val).unwrap()
    }

    fn generate_prime_numbers(count: usize, min_val: u64, max_val: u64) -> Vec<u64> {
        super::generate_prime_numbers(count, min_val, max_val).unwrap()
    }

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

    /// A v7 ciphertext whose tag verifies under `key` regardless of whether
    /// `key` passes validation (key_bytes and HMAC are defined for any key).
    fn v7_tagged_under(key: &[u64]) -> Vec<u8> {
        let mut ct = vec![0u8; NONCE_SIZE + 8 * 20];
        let tag = compute_auth_tag(&key_bytes(key), b"", &ct, AAD_LEN_WIDTH_V7);
        ct.extend_from_slice(&tag);
        ct
    }

    #[test]
    fn cvf15_v7_decrypt_bytes_rejects_empty_key() {
        // CVF-V5-12: a forged ciphertext fails the tag before validation runs;
        // a correctly tagged one still reaches validation, which rejects.
        let err = decrypt_bytes(&[0u8; 100], &[], b"").unwrap_err();
        assert!(err.contains("Authentication failed"), "got: {}", err);
        let err = decrypt_bytes(&v7_tagged_under(&[]), &[], b"").unwrap_err();
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
    fn cvf15_v7_decrypt_str_rejects_bad_key() {
        let ct = STANDARD.encode(v7_tagged_under(&[1]));
        let err = decrypt_str(&ct, &[1], b"").unwrap_err();
        assert!(err.contains("outside [2,"), "expected range error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_encrypt_raw_rejects_composite_element() {
        let err = encrypt_raw(&[0x42u8], &[1_000_000u64], b"").unwrap_err();
        assert!(err.contains("not prime"), "expected primality error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_decrypt_raw_rejects_bad_key() {
        let err = decrypt_raw(&[0u8; 100], &[], b"").unwrap_err();
        assert!(err.contains("Authentication failed"), "got: {}", err);
        let err = decrypt_raw(&v7_tagged_under(&[5, 5]), &[5, 5], b"").unwrap_err();
        assert!(err.contains("duplicates"), "expected duplicate error, got: {}", err);
    }

    #[test]
    fn cvf15_v7_decrypt_rejects_bad_key() {
        // pub fn decrypt returns Result; validate_key(key)? runs first.
        let err = decrypt(&[0u8; NONCE_SIZE], &[0u64; 20], &[]).unwrap_err();
        assert!(err.contains("non-empty"), "expected empty-key error, got: {}", err);
    }

    #[test]
    fn cvf15_pub_encrypt_rejects_invalid_key() {
        // CVF-V5-17: `encrypt` now returns Result, so a bad key is an Err.
        let err = encrypt(&[b'x' as u32], &[]).unwrap_err();
        assert!(err.contains("non-empty"), "{}", err);
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

    // CVF-V5-20: this checks that sampler output is always a valid key. It
    // cannot detect the modulo bias CVF-20 removed (that bias is about
    // span / 2^64 per draw, far below any feasible sample size); the CVF-20
    // fix itself - rand::Uniform instead of `% span` - is verified by
    // inspection of generate_prime_numbers.
    #[test]
    fn generate_prime_numbers_output_passes_validate_key() {
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

    // CVF-V5-20: exercises unpad_message directly. Pre-CVF-43 code rejected
    // these prefixes, if at all, only as over-length, so the "byte-valued"
    // assertion fails on v4.
    #[test]
    fn cvf43_unpad_rejects_noncanonical_length_prefix() {
        let mut buf = vec![0x41u32; 18]; // B = 16 plus the 2-codepoint prefix
        for (p0, p1) in [(0u32, 300u32), (1, 256), (0x100, 0)] {
            buf[0] = p0;
            buf[1] = p1;
            let err = unpad_message(&buf[..]).unwrap_err();
            assert!(err.contains("byte-valued"), "({}, {}): {}", p0, p1, err);
        }
        buf[0] = 0;
        buf[1] = 3;
        assert_eq!(unpad_message(&buf).unwrap(), vec![0x41; 3]);
    }

    #[test]
    fn cvf31_block_size_rejects_oversized_n() {
        // Any n >= 2^16 is outside the reachable bucket set, under every profile.
        let n = 1usize << PAD_MAX_EXP;
        for p in [
            PadProfile::Bucket,
            PadProfile::Coarse(3),
            PadProfile::Coarse(12),
            PadProfile::Frame(1u32 << PAD_MAX_EXP),
        ] {
            for m in [n, n + 1, usize::MAX] {
                assert!(p.block_size(m).is_err(), "{:?} accepted n={}", p, m);
            }
        }
        let err = PadProfile::Bucket.block_size(n).unwrap_err();
        assert!(err.contains("maximum bucket"), "got: {}", err);
    }

    #[test]
    #[should_panic(expected = "padding block must exceed the message")]
    fn cvf31_pad_to_block_precondition_is_enforced() {
        let _ = pad_to_block(&[0x41; 16], &[0u8; 32], &[0u8; NONCE_SIZE], 16);
    }

    #[test]
    fn cvf20_keygen_reports_errors_instead_of_panicking() {
        assert!(super::generate_prime_numbers(1, 10, 10).is_err());
        // [24, 28] holds no prime: the draw budget must end the search.
        assert!(super::generate_prime_numbers(1, 24, 28).is_err());
        assert!(super::generate_v8_key(1, 2, 100).is_err());
        assert!(super::generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME + 1).is_err());
        assert!(NapqesKey::generate().is_ok());
    }

    #[test]
    fn cvf28_v7_aad_length_is_checked() {
        assert!(check_v7_aad_len(u32::MAX as usize).is_ok());
        let err = check_v7_aad_len(u32::MAX as usize + 1).unwrap_err();
        assert!(err.contains("4-byte length prefix"), "got: {}", err);
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

    // CVF-V5-20: renamed from cvf42_*; this only pins the constants to the
    // paper's values. The evidence for the CVF-42 refactor is KAT byte parity
    // (kat_cross_check), which would fail if a constant changed.
    #[test]
    fn alphabet_constants_match_paper() {
        assert_eq!(NOISE_ALPHABET, 96);
        assert_eq!(PAD_ALPHABET, 95);
        assert_eq!(ASCII_PRINTABLE_BASE, 32);
    }

    // CVF-46 regression: the four public v7 encryptors share the
    // emit_tokens_v7 helper. Each draws its own CSPRNG nonce, so re-encrypt
    // the same (ASCII) input under that nonce through the fixed-nonce KAT
    // helper (itself pinned to the v6 corpus by kat_cross_check) and require
    // byte-identical output from every entry point.
    #[test]
    fn cvf46_all_four_v7_encryptors_share_emitter() {
        let key = test_key();
        let msg = "hello CVF-46";
        let aad = b"aad-check";
        let nonce_of = |ct: &[u8]| -> [u8; NONCE_SIZE] { ct[..NONCE_SIZE].try_into().unwrap() };

        let ct_b = encrypt_bytes(msg, &key, aad).unwrap();
        assert_eq!(ct_b, encrypt_bytes_with_nonce(msg, &key, nonce_of(&ct_b), aad), "encrypt_bytes");

        let ct_r = encrypt_raw(msg.as_bytes(), &key, aad).unwrap();
        assert_eq!(ct_r, encrypt_bytes_with_nonce(msg, &key, nonce_of(&ct_r), aad), "encrypt_raw");

        let ct_s = STANDARD.decode(encrypt_str(msg, &key, aad).unwrap()).unwrap();
        assert_eq!(ct_s, encrypt_bytes_with_nonce(msg, &key, nonce_of(&ct_s), aad), "encrypt_str");

        // `encrypt` returns the raw token vector: compare it with the tokens
        // the helper serialises under the same nonce.
        let cps: Vec<u32> = msg.chars().map(|c| c as u32).collect();
        let (n_e, tokens) = encrypt(&cps, &key).unwrap();
        let reference = encrypt_bytes_with_nonce(msg, &key, n_e, aad);
        let masked = &reference[NONCE_SIZE..reference.len() - TAG_SIZE];
        let ks = varint_keystream(&key_bytes(&key), &n_e, masked.len());
        let blob: Vec<u8> = masked.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(tokens, fixed_decode_tokens(&blob).unwrap(), "encrypt");
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

    // CVF-V5-20: the NapqesKey path is checked against the corpus (vector
    // W009, non-empty AAD), not against the bare-slice path, which shares
    // its core and so could not disagree with it.
    #[test]
    fn napqeskey_reproduces_v8_corpus_vector() {
        let corpus = crate::kat_cross_check::load_corpus("v8_vectors.json");
        let w = corpus.iter().find(|v| v["id"] == "W009").expect("W009 missing");
        let primes: Vec<u64> = w["key"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
        let sk: [u8; SK_SIZE] = crate::kat_cross_check::hex_decode(w["sk_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let aad = crate::kat_cross_check::hex_decode(w["aad_hex"].as_str().unwrap());
        let k = NapqesKey::new(primes, sk).unwrap();
        let ct = encrypt_bytes_v8_key(w["message"].as_str().unwrap(), &k, &aad).unwrap();
        assert_eq!(ct, crate::kat_cross_check::hex_decode(w["ciphertext_hex"].as_str().unwrap()));
    }

    #[test]
    fn cvf41_validate_key_rejects_key_above_max_elements() {
        let primes: Vec<u64> = (MIN_KEY_PRIME..)
            .filter(|&n| is_prime(n))
            .take(MAX_KEY_ELEMENTS + 1)
            .collect();
        let err = encrypt_bytes_v8("hi", &primes, &[0u8; SK_SIZE], b"").unwrap_err();
        assert!(err.contains("MAX_KEY_ELEMENTS"), "expected length-cap error, got: {}", err);
    }

    // Range must be checked before trial division: a u64 prime took ~3 s to reject.
    #[test]
    fn validate_key_rejects_huge_prime_without_trial_division() {
        let start = std::time::Instant::now();
        let err = encrypt_bytes_v8("hi", &[18_446_744_073_709_551_557u64], &[0u8; SK_SIZE], b"")
            .unwrap_err();
        assert!(err.contains("MAX_KEY_PRIME"), "got: {}", err);
        assert!(start.elapsed() < std::time::Duration::from_millis(200));
    }

    fn forge_stream_sentinel(ct: &mut [u8], sk: &[u8; SK_SIZE], aad: &[u8], chunks: u32, total: u64) {
        let n = ct.len();
        let f = u32::from_be_bytes(ct[1..5].try_into().unwrap());
        let nonce: [u8; NONCE_SIZE] = ct[5..5 + NONCE_SIZE].try_into().unwrap();
        let sk_fmt = derive_format_subkey(sk, FORMAT_STREAM_AE_V8);
        let tag = compute_stream_v8_sentinel_tag(&sk_fmt, f, &nonce, chunks, aad, total);
        let masked = total ^ stream_v8_count_mask(&sk_fmt, f, &nonce, chunks);
        ct[n - TAG_SIZE - 8..n - TAG_SIZE].copy_from_slice(&masked.to_be_bytes());
        ct[n - TAG_SIZE..].copy_from_slice(&tag);
    }

    // A validly-tagged sentinel below the delivered count used to underflow (panic).
    #[test]
    fn stream_sentinel_total_below_delivered_is_rejected() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let mut ct = encrypt_stream_ae_v8("abcdef", &primes, &sk, b"x", 2).unwrap();
        forge_stream_sentinel(&mut ct, &sk, b"x", 3, 1);
        let err = decrypt_stream_ae_v8(&ct, &primes, &sk, b"x").unwrap_err();
        assert!(err.contains("Malformed v8 stream sentinel"), "got: {}", err);
    }

    // A final chunk with zero real codepoints is never produced by the encoder.
    #[test]
    fn stream_sentinel_dropping_final_chunk_is_rejected() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let mut ct = encrypt_stream_ae_v8("abcdef", &primes, &sk, b"x", 2).unwrap();
        forge_stream_sentinel(&mut ct, &sk, b"x", 3, 4);
        let err = decrypt_stream_ae_v8(&ct, &primes, &sk, b"x").unwrap_err();
        assert!(err.contains("Malformed v8 stream sentinel"), "got: {}", err);
    }

    #[test]
    fn stream_chunk_index_limit_is_an_error() {
        assert!(next_stream_chunk_idx(u32::MAX - 1).is_ok());
        assert!(next_stream_chunk_idx(u32::MAX).is_err());
    }

    // Paper Dec step (3) runs before the tag: an illegal length never reaches the HMAC.
    #[test]
    fn v8_illegal_length_is_rejected_before_the_tag() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let err = decrypt_bytes_v8(&[0u8; NONCE_SIZE + TAG_SIZE + 8], &primes, &sk, b"").unwrap_err();
        assert!(err.contains("padding ceiling"), "got: {}", err);
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
            assert!((MIN_KEY_PRIME..=MAX_KEY_PRIME).contains(p));
        }
        let mut sorted = ps.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ps.len(), "generated primes must be distinct");
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

    /// CVF-19: the tag must cover the nonce and the masked blob, not only itself.
    #[test]
    fn v8_nonce_and_blob_tamper_fail() {
        let primes = test_key();
        let sk = test_sk();
        let ct = encrypt_bytes_v8("secret", &primes, &sk, b"").unwrap();
        for i in [0, NONCE_SIZE - 1, NONCE_SIZE, ct.len() / 2, ct.len() - TAG_SIZE - 1] {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            let err = decrypt_bytes_v8(&bad, &primes, &sk, b"").unwrap_err();
            assert!(err.contains("Authentication failed"), "byte {}: {}", i, err);
        }
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
        // CVF-19: test the property, not the shape (a 32-byte sk can never
        // equal the 5K-byte key_bytes). sk must not be any HMAC of the prime
        // material under the v7 or format-subkey schedules, and must be a
        // fresh draw on every call.
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        assert_eq!(primes.len(), DEFAULT_KEY_COUNT);
        let kb = key_bytes(&primes);
        assert_ne!(sk, hmac_digest(&kb, &[]));
        assert_ne!(sk, derive_format_subkey(&kb, FORMAT_BLOCK_V8));
        assert_ne!(sk, derive_format_subkey(&kb, FORMAT_STREAM_AE_V8));
        let (_, sk2) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        assert_ne!(sk, sk2);
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
        // invariant -- AND (CVF-V5-1) the sentinel must not carry the exact
        // codepoint count in clear. Under one fixed nonce the two sentinels'
        // count fields differ only by the masked counts, and neither equals
        // be8(n).
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let nonce = [0x42u8; NONCE_SIZE];
        let a = encrypt_stream_ae_v8_with_nonce(&"A".repeat(17), &primes, &sk, &nonce, b"", 16).unwrap();
        let b = encrypt_stream_ae_v8_with_nonce(&"B".repeat(31), &primes, &sk, &nonce, b"", 16).unwrap();
        assert_eq!(a.len(), b.len());
        let count_field = |ct: &[u8]| ct[ct.len() - TAG_SIZE - 8..ct.len() - TAG_SIZE].to_vec();
        assert_ne!(count_field(&a), 17u64.to_be_bytes().to_vec(), "count sent in clear");
        assert_ne!(count_field(&b), 31u64.to_be_bytes().to_vec(), "count sent in clear");
        // Same (header, chunk count) => same mask, so the XOR of the two
        // fields is exactly 17 ^ 31 and nothing else about n is exposed.
        let xa = u64_from_be8(&count_field(&a));
        let xb = u64_from_be8(&count_field(&b));
        assert_eq!(xa ^ xb, 17 ^ 31);
        assert_eq!(decrypt_stream_ae_v8(&a, &primes, &sk, b"").unwrap(), "A".repeat(17));
    }

    // CVF-V5-9: rewriting F in the header of an empty stream is detected.
    #[test]
    fn stream_v8_empty_stream_header_is_authenticated() {
        let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
        let mut ct = encrypt_stream_ae_v8("", &primes, &sk, b"", 8).unwrap();
        assert_eq!(decrypt_stream_ae_v8(&ct, &primes, &sk, b"").unwrap(), "");
        ct[1..5].copy_from_slice(&9u32.to_be_bytes());
        let err = decrypt_stream_ae_v8(&ct, &primes, &sk, b"").unwrap_err();
        assert!(err.contains("Authentication failed"), "got: {}", err);
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

// --- Round-5 audit regression tests (CVF-V5-*) ------------------------------

#[cfg(test)]
#[allow(deprecated)]
mod v5_tests {
    use super::*;

    // CVF-V5-11: the plaintext buffer is wiped over its whole capacity.
    #[test]
    fn v5_11_zeroize_codepoints_wipes_spare_capacity() {
        let mut buf: Vec<u32> = Vec::with_capacity(8);
        buf.extend_from_slice(&[0x41, 0x42, 0x43, 0x44, 0x45]);
        buf.truncate(2); // stale plaintext now sits in spare capacity
        let cap = buf.capacity();
        zeroize_codepoints(&mut buf);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), cap);
        unsafe { buf.set_len(cap) };
        assert!(buf.iter().all(|&c| c == 0), "stale codepoints survived");
    }

    // CVF-V5-11: duplicate detection no longer needs a sorted scratch copy.
    #[test]
    fn v5_11_validate_key_reports_duplicate_indices() {
        let err = validate_key(&[1_000_003, 1_000_033, 1_000_003]).unwrap_err();
        assert!(err.contains("index 2 duplicates index 0"), "{}", err);
    }

    // CVF-V5-30: the optimised is_prime agrees with a sieve, including
    // squares of primes on both sides of the small-prime table boundary.
    #[test]
    fn v5_30_is_prime_matches_sieve_and_edge_cases() {
        const N: usize = 200_000;
        let mut sieve = vec![true; N];
        sieve[0] = false;
        sieve[1] = false;
        for i in 2..N {
            if sieve[i] {
                let mut j = i * i;
                while j < N {
                    sieve[j] = false;
                    j += i;
                }
            }
        }
        for n in 0..N {
            assert_eq!(is_prime(n as u64), sieve[n], "n = {}", n);
        }
        for &(n, p) in &[
            (53u64 * 53, false), (59 * 59, false), (61 * 61, false),
            (1_000_003 * 1_000_033, false), (14_999_977, true), (14_999_981, true),
            (14_999_999, false), (u64::MAX, false),
        ] {
            assert_eq!(is_prime(n), p, "n = {}", n);
        }
        for n in [0u64, 1, 3, 4, 15, 16, 17, 1 << 32, u64::MAX] {
            let r = isqrt_u64(n);
            assert!(r as u128 * r as u128 <= n as u128 && (r as u128 + 1).pow(2) > n as u128);
        }
    }

    // CVF-V5-16: archived v7 ciphertexts under keys outside the current
    // interval (composite, below 10^6 or above MAX_KEY_PRIME) still open;
    // the relaxed policy rejects only what the arithmetic cannot handle.
    #[test]
    fn v5_16_v7_decryptors_open_out_of_interval_archived_keys() {
        let key: [u64; 3] = [999_983, 1_000_000, 20_000_003]; // <1e6 prime, composite, >1.5e7
        let nonce = [9u8; NONCE_SIZE];
        let kb = key_bytes(&key);
        let msg: Vec<u32> = "archived".chars().map(|c| c as u32).collect();
        let padded = pad_message(&msg, &kb, &nonce);
        let tokens = emit_tokens_v7(&padded, &kb, &nonce, derive_noise_p(&kb, &nonce), &key).unwrap();
        let blob = fixed_encode_tokens(&tokens);
        let ks = varint_keystream(&kb, &nonce, blob.len());
        let mut ct = nonce.to_vec();
        ct.extend(blob.iter().zip(ks.iter()).map(|(a, b)| a ^ b));
        let tag = compute_auth_tag(&kb, b"aad", &ct, AAD_LEN_WIDTH_V7);
        ct.extend_from_slice(&tag);

        assert!(validate_key(&key).is_err(), "the v8 policy must still reject this key");
        assert_eq!(decrypt_bytes(&ct, &key, b"aad").unwrap(), "archived");
        assert_eq!(decrypt_raw(&ct, &key, b"aad").unwrap(), b"archived");
        assert_eq!(decrypt(&nonce, &tokens, &key).unwrap(), msg);

        for bad in [&[][..], &[1][..], &[7, 7][..], &[1u64 << 40][..]] {
            assert!(validate_key_v7_decrypt(bad).is_err(), "{:?} accepted", bad);
        }
    }

    // CVF-V5-25: the documented cross-convention behaviour, pinned.
    #[test]
    #[allow(deprecated)]
    fn v5_25_v7_cross_convention_behaviour_is_as_documented() {
        let key = [1_000_003u64, 1_000_033, 1_000_037, 1_000_039];
        let ct = encrypt_bytes("é", &key, b"").unwrap();
        assert_eq!(decrypt_raw(&ct, &key, b"").unwrap(), vec![0xE9]);
        let ct = encrypt_raw(&[0xC3, 0xA9], &key, b"").unwrap();
        assert_eq!(decrypt_bytes(&ct, &key, b"").unwrap(), "\u{C3}\u{A9}");
        let ct = encrypt_bytes("€", &key, b"").unwrap();
        assert!(decrypt_raw(&ct, &key, b"").is_err());
    }

    // CVF-V5-4: the v7 emission loop is bounded. With a forced threshold of
    // 1.0 every position is noise; the pre-fix loop never terminated.
    #[test]
    fn v5_4_v7_emission_loop_is_bounded() {
        let key = [1_000_003u64, 1_000_033];
        let kb = key_bytes(&key);
        let nonce = [3u8; NONCE_SIZE];
        let err = emit_tokens_v7(&[0x41], &kb, &nonce, 1.0, &key).unwrap_err();
        assert!(err.contains("CVF-V5-4"), "{}", err);
        assert!(emit_tokens_v7(&[0x41], &kb, &nonce, derive_noise_p(&kb, &nonce), &key).is_ok());
    }

    // CVF-V5-29: NapqesKey streaming variants agree with the bare-slice ones
    // and skip per-call validation.
    #[test]
    fn v5_29_stream_key_variants_roundtrip() {
        let key = NapqesKey::generate().unwrap();
        let ct = encrypt_stream_ae_v8_key("stream via NapqesKey", &key, b"a", 4).unwrap();
        assert_eq!(decrypt_stream_ae_v8_key(&ct, &key, b"a").unwrap(), "stream via NapqesKey");
        assert_eq!(decrypt_stream_ae_v8(&ct, key.primes(), key.sk(), b"a").unwrap(), "stream via NapqesKey");
        let (mut enc, mut out) = StreamV8Encryptor::new_key(&key, b"a", 4).unwrap();
        for c in "incremental".chars() {
            if let Some(frame) = enc.push(c).unwrap() {
                out.extend_from_slice(&frame);
            }
        }
        out.extend_from_slice(&enc.finish().unwrap());
        assert_eq!(decrypt_stream_ae_v8_key(&out, &key, b"a").unwrap(), "incremental");
    }

    // CVF-V5-14: key generation refuses counts validate_key would reject.
    #[test]
    fn v5_14_keygen_rejects_zero_and_oversized_count() {
        assert!(generate_prime_numbers(0, MIN_KEY_PRIME, MAX_KEY_PRIME).is_err());
        assert!(generate_prime_numbers(MAX_KEY_ELEMENTS + 1, MIN_KEY_PRIME, MAX_KEY_PRIME).is_err());
        assert!(generate_v8_key(0, MIN_KEY_PRIME, MAX_KEY_PRIME).is_err());
        assert!(generate_v8_key(MAX_KEY_ELEMENTS + 1, MIN_KEY_PRIME, MAX_KEY_PRIME).is_err());
        let ps = generate_prime_numbers(MAX_KEY_ELEMENTS, MIN_KEY_PRIME, MAX_KEY_PRIME).unwrap();
        assert!(validate_key(&ps).is_ok());
    }

    // CVF-V5-17: encrypt rejects exactly what decrypt rejects, so the pair
    // round-trips on every accepted input.
    #[test]
    #[allow(deprecated)]
    fn v5_17_encrypt_rejects_non_scalar_input() {
        let key = [1_000_003u64, 1_000_033, 1_000_037, 1_000_039];
        for bad in [0xD800u32, 0xDFFF, 0x11_0000, u32::MAX] {
            assert!(encrypt(&[0x41, bad], &key).is_err(), "{:#x} accepted", bad);
        }
        let msg: Vec<u32> = "é😀A".chars().map(|c| c as u32).collect();
        let (n, t) = encrypt(&msg, &key).unwrap();
        assert_eq!(decrypt(&n, &t, &key).unwrap(), msg);
    }
}