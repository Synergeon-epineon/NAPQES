//! NapqesKey — validated + auto-wiped key material for v8 (CVF-29 + CVF-37 + CVF-41).
//!
//! The `NapqesKey` newtype pairs the prime tuple with the 256-bit `sk` and
//! runs [`crate::validate_key`] exactly once in its constructor. Every v8
//! entry point taking `&NapqesKey` (the `_key` variants at the crate root)
//! therefore skips per-message validation, closing the CVF-29 timing/perf
//! leak that recomputed `is_prime` on every encrypt and decrypt.
//!
//! On drop, both `primes` and `sk` are wiped via [`crate::zeroize_key`] /
//! [`crate::zeroize_sk`] — closing CVF-37, which observed that the delivered
//! zeroization helpers were never called from anywhere in the library.
//!
//! The bare-slice entry points (`encrypt_bytes_v8(&[u64], &[u8; SK_SIZE])`
//! etc.) are retained for backward compatibility but are `#[deprecated]`
//! since 0.3.0 — new code should construct a `NapqesKey` once and pass it
//! to the `_key`-suffixed entry points.

use std::fmt;

use crate::{
    decrypt_bytes_v8_core, encrypt_bytes_v8_core, validate_key, zeroize_key,
    zeroize_sk, PadProfile, SK_SIZE,
};

/// Validated NAPQES v8 key material with automatic zeroization on drop.
///
/// Constructed once via [`NapqesKey::new`] (fallible — runs `validate_key`)
/// or [`NapqesKey::generate`] (draws fresh key material from CSPRNG).
///
/// # Examples
///
/// ```
/// # use napqes::NapqesKey;
/// let key = NapqesKey::generate().unwrap();
/// let ct = napqes::encrypt_bytes_v8_key("hello", &key, b"aad").unwrap();
/// let pt = napqes::decrypt_bytes_v8_key(&ct, &key, b"aad").unwrap();
/// assert_eq!(pt, "hello");
/// // key is wiped when it goes out of scope.
/// ```
pub struct NapqesKey {
    primes: Vec<u64>,
    sk: [u8; SK_SIZE],
}

impl NapqesKey {
    /// Build a `NapqesKey` from a caller-supplied prime tuple and `sk`.
    ///
    /// Runs [`crate::validate_key`] exactly once; on `Ok`, subsequent v8
    /// entry points that accept `&NapqesKey` bypass per-message validation.
    /// Any of the rejection reasons [`crate::validate_key`] documents (empty
    /// tuple, composite element, out-of-range element, duplicate, more than
    /// [`crate::MAX_KEY_ELEMENTS`] elements) surface here as `Err`.
    pub fn new(primes: Vec<u64>, sk: [u8; SK_SIZE]) -> Result<Self, String> {
        validate_key(&primes)?;
        Ok(Self { primes, sk })
    }

    /// Generate a fresh `NapqesKey` via [`crate::generate_v8_key`] under the
    /// normative `[MIN_KEY_PRIME, MAX_KEY_PRIME]` interval and
    /// `DEFAULT_KEY_COUNT` primes. Never fails for well-formed constants.
    pub fn generate() -> Result<Self, String> {
        let (primes, sk) = crate::generate_v8_key(
            crate::DEFAULT_KEY_COUNT,
            crate::MIN_KEY_PRIME,
            crate::MAX_KEY_PRIME,
        );
        Self::new(primes, sk)
    }

    /// Borrow the validated prime tuple.
    #[inline]
    pub fn primes(&self) -> &[u64] {
        &self.primes
    }

    /// Borrow the 256-bit `sk`.
    #[inline]
    pub fn sk(&self) -> &[u8; SK_SIZE] {
        &self.sk
    }

    /// Length of the prime tuple (`K` in the paper's notation).
    #[inline]
    pub fn k(&self) -> usize {
        self.primes.len()
    }
}

impl Drop for NapqesKey {
    fn drop(&mut self) {
        // CVF-37: the crate previously exposed zeroize_key / zeroize_sk but
        // called neither from any library path. NapqesKey's Drop routes both
        // through the volatile-write helpers unconditionally.
        zeroize_key(&mut self.primes);
        zeroize_sk(&mut self.sk);
    }
}

// Deliberately no Clone, Copy, Debug — accidental duplication or logging of
// key material must be a compile error. If a caller genuinely needs to
// duplicate a key, they can construct a new one from the same `(primes, sk)`.

/// A stack-allocated 32-byte secret with volatile-write zeroization on drop.
///
/// The v8 block-mode encrypt/decrypt cores currently wipe `sk_fmt` via an
/// inline `zeroize_sk` at the outer function's exit path (see
/// `encrypt_bytes_v8_core` / `decrypt_bytes_v8_core` in `lib.rs`); this
/// wrapper is retained for future use in helpers that construct short-lived
/// subkeys of their own without an obvious exit point (e.g. streaming AE's
/// chunk-tag derivations). Marked `#[allow(dead_code)]` until such a caller
/// lands.
#[allow(dead_code)]
pub(crate) struct Secret32(pub [u8; 32]);

#[allow(dead_code)]
impl Secret32 {
    #[inline]
    pub(crate) fn new(bytes: [u8; 32]) -> Self { Self(bytes) }
    #[inline]
    pub(crate) fn as_ref(&self) -> &[u8; 32] { &self.0 }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        // CVF-37: volatile write so the compiler cannot elide these stores.
        for x in self.0.iter_mut() {
            unsafe { std::ptr::write_volatile(x, 0u8) };
        }
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret32(<redacted>)")
    }
}

impl fmt::Debug for NapqesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never leak the key contents into logs or debug prints.
        write!(f, "NapqesKey {{ k = {}, sk = <redacted>, primes = <redacted> }}", self.primes.len())
    }
}

// ─── _key-suffixed v8 API (CVF-29 fix: skips per-message validate_key) ──────

/// v8 encrypt that takes a validated [`NapqesKey`]; skips per-message
/// `validate_key` (CVF-29 fix).
///
/// Byte-identical output to
/// `encrypt_bytes_v8(msg, key.primes(), key.sk(), aad)`; the difference is
/// that this path knows via type that the caller has already run
/// [`crate::validate_key`] (in `NapqesKey::new`), so it calls the
/// `pub(crate)` `_core` function directly and the per-message
/// `is_prime`/sort-and-scan cost the auditor flagged is not paid.
pub fn encrypt_bytes_v8_key(
    message: &str,
    key: &NapqesKey,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    // CVF-47: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    crate::self_test::require_post().map_err(|e| e.to_string())?;
    encrypt_bytes_v8_core(message, &key.primes, &key.sk, aad, PadProfile::Bucket)
}

/// v8 decrypt taking a [`NapqesKey`]. See [`encrypt_bytes_v8_key`].
pub fn decrypt_bytes_v8_key(
    ciphertext: &[u8],
    key: &NapqesKey,
    aad: &[u8],
) -> Result<String, String> {
    // CVF-47: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    crate::self_test::require_post().map_err(|e| e.to_string())?;
    decrypt_bytes_v8_core(ciphertext, &key.primes, &key.sk, aad)
}

/// v8 encrypt with an explicit padding profile, taking a [`NapqesKey`].
pub fn encrypt_bytes_v8_with_profile_key(
    message: &str,
    key: &NapqesKey,
    aad: &[u8],
    pad_profile: PadProfile,
) -> Result<Vec<u8>, String> {
    // CVF-47: FIPS 140-3 gate (opt-in via the `fips_gate` feature).
    #[cfg(feature = "fips_gate")]
    crate::self_test::require_post().map_err(|e| e.to_string())?;
    encrypt_bytes_v8_core(message, &key.primes, &key.sk, aad, pad_profile)
}
