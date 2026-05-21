//! Cargo-fuzz target for NAPSEQ v6 decoder paths.
//!
//! Phase 1, workstream 1.6.
//!
//! Targets:
//!   * `decrypt_bytes` — full decode pipeline: auth check → LEB128 varint
//!     decode → plaintext recovery.  Must return `Ok(String)` or `Err(String)`;
//!     must never panic regardless of input.
//!   * Additional AAD variants to exercise the AAD-binding path.
//!
//! Build and run (nightly required):
//! ```
//! cargo +nightly fuzz run decode_bytes -- -max_total_time=300
//! cargo +nightly fuzz run decode_bytes -- -max_total_time=60 -jobs=4
//! ```
//!
//! Corpus seeds are stored in `fuzz/corpus/decode_bytes/` and checked in
//! so that subsequent runs benefit from prior coverage discoveries.
//!
//! Security contract:
//!   `decrypt_bytes` MUST never panic.  Any malformed or adversarial input
//!   must produce `Err(...)`.  A successful `Ok(plaintext)` is only possible
//!   when the fuzzer discovers a valid NAPSEQ v6 ciphertext, which requires
//!   forging an HMAC-SHA256 tag — computationally infeasible.

#![no_main]

use libfuzzer_sys::fuzz_target;
use napqes::decrypt_bytes;

/// Key fixtures — three representative sizes selected by fuzzer byte[0].
fn key_for(selector: u8) -> Vec<u64> {
    match selector % 3 {
        0 => vec![1_000_003, 1_000_033],
        1 => vec![7_999_993],
        _ => vec![
            1_000_003, 1_000_033, 1_000_037, 1_000_039,
            1_000_081, 1_000_099, 1_000_117, 1_000_121,
            1_000_133, 1_000_151,
        ],
    }
}

/// AAD fixtures — selected by fuzzer byte[1].
fn aad_for(selector: u8) -> &'static [u8] {
    match selector % 4 {
        0 => b"",
        1 => b"aad-context",
        2 => b"\x00\xff\x80\x01",
        _ => b"sender=alice;recipient=bob",
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let key = key_for(data[0]);
    let aad = aad_for(data[1]);
    let payload = &data[2..];

    // Target 1: standard decode — must not panic; must return Ok or Err.
    let _ = decrypt_bytes(payload, &key, aad);

    // Target 2: same payload, empty AAD — exercises the AAD-binding check
    // with a different context than what was used during encryption.
    let _ = decrypt_bytes(payload, &key, b"");

    // Target 3: first two key elements swapped — wrong key, auth must fail.
    if key.len() >= 2 {
        let mut bad_key = key.clone();
        bad_key.swap(0, 1);
        let _ = decrypt_bytes(payload, &bad_key, aad);
    }
});
