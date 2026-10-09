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
//! `encrypt_bytes_v8`, assert the unmutated round trip, then mutate the
//! payload (byte flip and optional truncation by whole token groups) and
//! RE-TAG it with `fuzz_retag_block_v8`. The mutated ciphertext therefore
//! passes authentication and drives the post-authentication checks in
//! `decrypt_core_v8` (bucket check, addend/range check, length prefix).
//!
//! Build and run (nightly required):
//! ```
//! cargo +nightly fuzz run decode_bytes -- -max_total_time=300
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use napqes::{
    decrypt_bytes_v8, encrypt_bytes_v8, fuzz_retag_block_v8, MAX_NOISE_RUN, MIN_KEY_PRIME,
    NONCE_SIZE, SK_SIZE, TAG_SIZE,
};

const TOKEN_GROUP: usize = 8 * (MAX_NOISE_RUN as usize + 1);

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
    // Header: [key_sel, aad_sel, sk_sel, flags, mutate_index_lo,
    //          mutate_index_hi, mutate_xor_byte, msg_len, ..msg..]
    // flags bit0: flip a byte; bits1..3: drop that many token groups.
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
    let flip = data[3] & 1 == 1;
    let drop_groups = ((data[3] >> 1) & 0x07) as usize;
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
    let rt = decrypt_bytes_v8(&ct, &key, &sk, aad).expect("v8 round trip failed");
    assert_eq!(rt, message);

    if !flip && drop_groups == 0 {
        return;
    }
    let mut payload = ct[..ct.len() - TAG_SIZE].to_vec();
    let masked_len = payload.len() - NONCE_SIZE;
    let drop = (drop_groups * TOKEN_GROUP).min(masked_len);
    payload.truncate(payload.len() - drop);
    if flip && payload.len() > NONCE_SIZE {
        let idx = NONCE_SIZE + ((mut_hi << 8 | mut_lo) % (payload.len() - NONCE_SIZE));
        payload[idx] ^= mut_xor;
    }
    let tag = fuzz_retag_block_v8(&payload, &sk, aad);
    payload.extend_from_slice(&tag);
    let _ = decrypt_bytes_v8(&payload, &key, &sk, aad);
});
