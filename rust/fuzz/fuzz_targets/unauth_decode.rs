//! Cargo-fuzz target for the unauthenticated v7 surface — the token-slice
//! entry point (`pub fn decrypt`) that the CVF-14 pass converted to
//! `Result<Vec<u32>, String>` but which remains reachable with an arbitrary
//! `&[u64]` token slice and no tag check at all. This target verifies that
//! the newly-fallible decrypt path cannot panic even on adversarial token
//! streams.
//!
//! Also fuzzes `decrypt_raw` and `decrypt_str` on arbitrary bytes for the
//! same reason.
//!
//! Build and run (nightly required):
//! ```
//! cargo +nightly fuzz run unauth_decode -- -max_total_time=120
//! ```

#![no_main]
// CVF-17: v7 legacy decrypt entry points are not deprecated (kept for
// archived ciphertexts), but pub fn decrypt at src/lib.rs:624 is the
// low-level entry point the auditor called out; suppression is scoped to
// this fuzz target which specifically targets that surface.
#![allow(deprecated)]

use libfuzzer_sys::fuzz_target;
use napqes::{decrypt, decrypt_raw, decrypt_str};

fn key_for(selector: u8) -> Vec<u64> {
    match selector % 3 {
        0 => vec![1_000_003, 1_000_033, 1_000_037, 1_000_039],
        1 => vec![7_999_993],
        _ => vec![
            1_000_003, 1_000_033, 1_000_037, 1_000_039,
            1_000_081, 1_000_099, 1_000_117, 1_000_121,
            1_000_133, 1_000_151,
        ],
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 18 {
        return; // need selector + 16-byte nonce
    }
    let key = key_for(data[0]);
    let nonce = &data[1..17];
    let rest = &data[17..];

    // Interpret rest as a sequence of u64 tokens (big-endian).
    let mut tokens: Vec<u64> = Vec::new();
    for chunk in rest.chunks_exact(8) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        tokens.push(u64::from_be_bytes(buf));
    }

    // Target 1: pub fn decrypt — unauthenticated token slice + nonce.
    // Result<Vec<u32>, String>; must never panic on any tokens, any key.
    let _ = decrypt(nonce, &tokens, &key);

    // Target 2: decrypt_raw — tag-first (safer surface), fed arbitrary
    // bytes. Should always return Err from the parse floor or the tag
    // check; must never panic.
    let _ = decrypt_raw(data, &key, b"");

    // Target 3: decrypt_str — base64-decode then decrypt_bytes. Should
    // report base64 or auth failure, never panic.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decrypt_str(s, &key, b"");
    }
});
