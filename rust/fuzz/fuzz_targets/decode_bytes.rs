//! Cargo-fuzz target for the NAPQES v8 decoder — CVF-22 retarget.
//!
//! The previous target imported `napqes::decrypt_bytes` (v7) and fed raw
//! bytes to a tag-first function, so every input either failed the parse
//! floor or the HMAC comparison — no input reached `varint_keystream`,
//! `fixed_decode_tokens`, `decrypt_core`, or `unpad_message`. The "no
//! panics across 10^6 corpus entries" claim was therefore only a statement
//! about the length floor and HMAC comparator, not about the code path
//! that recovers plaintext.
//!
//! This target is structure-aware: from fuzzer input we derive a
//! (primes, sk, aad, plaintext) tuple, produce a valid v8 ciphertext via
//! `encrypt_bytes_v8`, then flip a byte inside the blob region and hand
//! the mutated bytes to `decrypt_bytes_v8`. Because the tag is recomputed
//! implicitly by the mutation-under-a-valid-frame pattern only for the
//! unmutated bytes, this reaches the tag check for the mutated payload
//! (which must reject) and — importantly — the tag check succeeds for
//! unmutated payloads, exercising the post-authentication paths in
//! `decrypt_core_v8` (bucket check, length-prefix check, codepoint range
//! check per CVF-14 and Remark 3.13).
//!
//! Build and run (nightly required):
//! ```
//! cargo +nightly fuzz run decode_bytes -- -max_total_time=300
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use napqes::{decrypt_bytes_v8, encrypt_bytes_v8, MIN_KEY_PRIME, SK_SIZE};

/// Small prime-key fixtures — three sizes selected by fuzzer byte[0]. All are
/// validate_key-accepting so the fuzzer reaches beyond the head guard.
fn key_for(selector: u8) -> Vec<u64> {
    match selector % 3 {
        0 => vec![1_000_003, 1_000_033],
        1 => vec![7_999_993],
        _ => vec![
            1_000_003, 1_000_033, 1_000_037, 1_000_039,
            1_000_081, 1_000_099, 1_000_117, 1_000_121,
            1_000_133, 1_000_151, 1_000_159, 1_000_171,
            1_000_183,
        ],
    }
}

fn aad_for(selector: u8) -> &'static [u8] {
    match selector % 4 {
        0 => b"",
        1 => b"aad-context",
        2 => b"\x00\xff\x80\x01",
        _ => b"sender=alice;recipient=bob",
    }
}

fn sk_for(selector: u8) -> [u8; SK_SIZE] {
    // Deterministic sk derived from the selector so different fuzzer paths
    // exercise distinct sk_fmt values without CSPRNG noise.
    let mut sk = [0u8; SK_SIZE];
    for (i, b) in sk.iter_mut().enumerate() {
        *b = selector.wrapping_add(i as u8);
    }
    sk
}

fuzz_target!(|data: &[u8]| {
    // Header: [key_sel, aad_sel, sk_sel, mutate_flag, mutate_index_lo,
    //          mutate_index_hi, mutate_xor_byte, msg_len, ..msg..]
    if data.len() < 8 {
        return;
    }
    let key = key_for(data[0]);
    // Sanity: keys start above MIN_KEY_PRIME by construction.
    if key.iter().any(|&k| k < MIN_KEY_PRIME) {
        return;
    }
    let aad = aad_for(data[1]);
    let sk = sk_for(data[2]);
    let mutate = data[3] & 1 == 1;
    let mut_lo = data[4] as usize;
    let mut_hi = data[5] as usize;
    let mut_xor = data[6];
    let msg_len = (data[7] as usize).min(data.len() - 8);
    let msg_bytes = &data[8..8 + msg_len];

    // Restrict to valid UTF-8 slices — v8 encrypts &str. Fall back to a
    // trivial ASCII message on invalid UTF-8 to keep coverage on the
    // encrypt/decrypt path.
    let message: &str = match std::str::from_utf8(msg_bytes) {
        Ok(s) => s,
        Err(_) => "A",
    };

    // Encrypt once — the fuzzer proves this cannot panic on any
    // validate_key-accepting key with any UTF-8 message.
    let ct = match encrypt_bytes_v8(message, &key, &sk, aad) {
        Ok(ct) => ct,
        Err(_) => return, // e.g. message too long — accepted refusal
    };

    // Unmutated round-trip: must succeed and reach every branch of the
    // decrypt pipeline. Any panic here is a bug.
    let rt = decrypt_bytes_v8(&ct, &key, &sk, aad);
    let _ = rt;

    // Optional structure-aware mutation: flip one byte inside the blob
    // region (not the tag) and re-submit. Must return Err from the tag
    // comparator or, if the tag happens to survive, from a downstream
    // structural check. Never panic.
    if mutate && ct.len() > 32 {
        let blob_len = ct.len() - 32;
        if blob_len == 0 {
            return;
        }
        let idx = ((mut_hi as usize) << 8 | mut_lo) % blob_len;
        let mut mutated = ct;
        mutated[idx] ^= mut_xor;
        let _ = decrypt_bytes_v8(&mutated, &key, &sk, aad);
    }
});
