//! Cargo-fuzz target for the v8 streaming decryptor (CVF-V5-26).
//!
//! Structure-aware: derives (key, sk, aad, F, message, nonce) from the input,
//! encrypts with the deterministic stream core, requires the unmutated round
//! trip, then mutates the stream - header F, nonce, a chunk byte, the masked
//! count, or truncation / duplication of a whole frame - and RE-TAGS every
//! chunk and the sentinel with `fuzz_retag_stream_v8`, so the mutation
//! reaches the post-authentication decode and sentinel-consistency checks.
//!
//! Build and run (nightly required):
//! ```
//! cargo +nightly fuzz run stream_decode -- -max_total_time=300
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use napqes::{
    decrypt_stream_ae_v8_key, fuzz_encrypt_stream_v8_with_nonce, fuzz_retag_stream_v8, NapqesKey,
    SK_SIZE,
};

fn key_for(selector: u8) -> Vec<u64> {
    match selector % 3 {
        0 => vec![1_000_003, 1_000_033],
        1 => vec![7_999_993],
        _ => vec![
            1_000_003, 1_000_033, 1_000_037, 1_000_039, 1_000_081, 1_000_099, 1_000_117,
            1_000_121, 1_000_133, 1_000_151, 9_900_047, 12_000_017, 14_999_981,
        ],
    }
}

fuzz_target!(|data: &[u8]| {
    // [key_sel, sk_sel, f, op, pos_lo, pos_hi, xor, nonce(16), ..aad_len, aad.., msg..]
    if data.len() < 23 {
        return;
    }
    let primes = key_for(data[0]);
    let mut sk = [0u8; SK_SIZE];
    for (i, b) in sk.iter_mut().enumerate() {
        *b = data[1].wrapping_add(i as u8);
    }
    let f = u32::from(data[2] % 16) + 1;
    let op = data[3];
    let pos = (data[4] as usize) | ((data[5] as usize) << 8);
    let xor = data[6] | 1;
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&data[7..23]);
    let rest = &data[23..];
    let aad_len = rest.first().map_or(0, |&b| (b % 8) as usize).min(rest.len().saturating_sub(1));
    let aad = if rest.is_empty() { &[][..] } else { &rest[1..1 + aad_len] };
    let msg_bytes = if rest.is_empty() { &[][..] } else { &rest[1 + aad_len..] };
    let msg = match std::str::from_utf8(msg_bytes) {
        Ok(s) if s.chars().count() <= 64 => s,
        _ => "stream",
    };

    let key = NapqesKey::new(primes.clone(), sk).expect("fixture key is valid");
    let mut ct = match fuzz_encrypt_stream_v8_with_nonce(msg, &primes, &sk, &nonce, aad, f) {
        Ok(ct) => ct,
        Err(_) => return,
    };
    assert_eq!(decrypt_stream_ae_v8_key(&ct, &key, aad).as_deref(), Ok(msg), "stream round trip");

    let frame = 4 + f as usize * 160 + 32;
    match op % 7 {
        0 => ct[1 + pos % 4] ^= xor,                         // header F
        1 => ct[5 + pos % 16] ^= xor,                        // nonce
        2 => {
            let body = ct.len() - 21 - 44;
            if body > 0 {
                ct[21 + pos % body] ^= xor;                  // chunk bytes
            }
        }
        3 => {
            let n = ct.len();
            ct[n - 40 + pos % 8] ^= xor;                     // masked count
        }
        4 => {
            if ct.len() >= 21 + frame + 44 {
                ct.drain(21..21 + frame);                    // drop the first frame
            }
        }
        5 => {
            if ct.len() >= 21 + frame + 44 {
                let first: Vec<u8> = ct[21..21 + frame].to_vec();
                ct.splice(21..21, first);                    // duplicate the first frame
            }
        }
        _ => {
            let keep = 21 + pos % (ct.len() - 21);
            ct.truncate(keep);                               // arbitrary truncation
        }
    }
    fuzz_retag_stream_v8(&mut ct, &sk, aad);
    let _ = decrypt_stream_ae_v8_key(&ct, &key, aad);
});
