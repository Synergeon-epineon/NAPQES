//! Cargo-fuzz target for the unauthenticated v7 surface — the token-slice
//! entry point (`pub fn decrypt`) that the CVF-14 pass converted to
//! `Result<Vec<u32>, String>` but which remains reachable with an arbitrary
//! `&[u64]` token slice and no tag check at all. This target verifies that
//! the newly-fallible decrypt path cannot panic even on adversarial token
//! streams.
//!
//! CVF-V5-26: the token stream is structure-aware. A random `u64` is of the
//! form `c * k + a` with probability about 1/k, so random tokens almost never
//! got past the first real-token check. The target now derives a message
//! and nonce from the fuzzer input, builds the valid token stream with the
//! `fuzz_v7_tokens` hook, and then applies one mutation (token +/- delta,
//! bit flip, truncation, duplication, or a codepoint pushed out of range),
//! so later checks (range, scalar, length prefix, unpad) are reached.
//!
//! Also fuzzes `decrypt_raw` and `decrypt_str` on arbitrary bytes.
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
use napqes::{decrypt, decrypt_raw, decrypt_str, fuzz_v7_tokens};

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
    // [key_sel, nonce(16), op, idx_lo, idx_hi, delta(8), ..message bytes..]
    if data.len() < 28 {
        return;
    }
    let key = key_for(data[0]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&data[1..17]);
    let op = data[17];
    let idx = (data[18] as usize) | ((data[19] as usize) << 8);
    let mut delta = [0u8; 8];
    delta.copy_from_slice(&data[20..28]);
    let delta = u64::from_be_bytes(delta);
    // Message: each input byte is a codepoint; every 4th byte pair widens to
    // the BMP so non-ASCII recovery paths are exercised.
    let msg: Vec<u32> = data[28..]
        .iter()
        .take(512)
        .enumerate()
        .map(|(i, &b)| if i % 4 == 3 { 0x100 + u32::from(b) * 7 } else { u32::from(b) })
        .collect();

    // Target 1: pub fn decrypt on structurally valid tokens, then mutated.
    if let Ok(mut tokens) = fuzz_v7_tokens(&msg, &key, &nonce) {
        assert_eq!(decrypt(&nonce, &tokens, &key).as_deref(), Ok(&msg[..]), "v7 token round trip");
        if !tokens.is_empty() {
            let i = idx % tokens.len();
            match op % 6 {
                0 => tokens[i] = tokens[i].wrapping_add(delta % 1_000_000 + 1),
                1 => tokens[i] = tokens[i].wrapping_sub(delta % 1_000_000 + 1),
                2 => tokens[i] ^= 1u64 << (delta % 64),
                3 => tokens.truncate(i),
                4 => tokens.insert(i, tokens[i]),
                _ => tokens[i] = tokens[i].wrapping_add(key[0].wrapping_mul(0x11_0000)),
            }
        }
        let _ = decrypt(&nonce, &tokens, &key);
    }

    // Target 2: decrypt_raw on arbitrary bytes - must never panic.
    let _ = decrypt_raw(data, &key, b"");

    // Target 3: decrypt_str - base64 then decrypt_bytes; never panic.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decrypt_str(s, &key, b"");
    }
});
