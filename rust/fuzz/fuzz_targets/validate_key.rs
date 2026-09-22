//! Cargo-fuzz target for the CVF-15 / CVF-16 key-validation surface.
//!
//! Rather than the AEAD proper, this target exercises the `Result` returned
//! by every v7 and v8 entry point when the key is bad — the surface the
//! CVF-15 fix wired into all eight legacy entry points. The fuzzer's job is
//! to demonstrate that a caller-supplied `&[u64]` cannot panic *before* the
//! validate_key error is reported: the check must run and reject cleanly,
//! not divide by zero inside derive_addend or wrap `u64` inside a token
//! multiplication.
//!
//! Build and run (nightly required):
//! ```
//! cargo +nightly fuzz run validate_key -- -max_total_time=60
//! ```

#![no_main]
// CVF-17: this fuzz target deliberately exercises the v7 legacy encryptors
// (encrypt_bytes / decrypt_bytes) alongside their v8 replacements, so the
// module-wide allow is scoped narrowly to fuzz coverage of the legacy API.
#![allow(deprecated)]

use libfuzzer_sys::fuzz_target;
use napqes::{decrypt_bytes, decrypt_bytes_v8, encrypt_bytes, encrypt_bytes_v8, SK_SIZE};

fuzz_target!(|data: &[u8]| {
    // Interpret the fuzzer input as an ordered tuple of u64 candidates.
    // 8 bytes per candidate; the empty case exercises the empty-key branch
    // of validate_key. We deliberately allow the tuple to contain zeros,
    // ones, composites, and huge values so the fuzzer explores every
    // rejection path.
    let mut key: Vec<u64> = Vec::new();
    for chunk in data.chunks_exact(8) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        key.push(u64::from_le_bytes(buf));
    }

    // The AEAD parameters below are irrelevant — the fuzzer is only trying
    // to reach a panic from key material. The message and AAD are constants
    // so any difference in behaviour comes from the key.
    let msg = "A";
    let aad: &[u8] = b"";
    let sk = [0x11u8; SK_SIZE];

    // v7 encrypt — must panic-safe on any key.
    let _ = encrypt_bytes(msg, &key, aad);
    // v7 decrypt — must panic-safe on any key with a bogus ciphertext.
    let _ = decrypt_bytes(&[0u8; 100], &key, aad);
    // v8 encrypt — same expectation.
    let _ = encrypt_bytes_v8(msg, &key, &sk, aad);
    // v8 decrypt — same.
    let _ = decrypt_bytes_v8(&[0u8; 100], &key, &sk, aad);
});
