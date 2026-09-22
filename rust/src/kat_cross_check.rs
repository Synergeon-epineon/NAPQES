//! Rust KAT cross-check for NAPSEQ v7 (Phase 0, workstream 0.1 / ROADMAP §2.B8).
//!
//! Reads `tests/kat/v6_vectors.json` from the repo root, exercises both the
//! deterministic `encrypt_bytes_with_nonce` API (exact byte comparison) and
//! the `decrypt_bytes` API for positive vectors, and asserts that negative
//! vectors return an `Err`.
//!
//! This module lives inside the crate (rather than as an external
//! `tests/kats.rs` integration test) because `encrypt_bytes_with_nonce` is
//! `pub(crate)`, not part of the public API — see the CVF3 fix in
//! `docs/CAVEATS.md`: an explicit, caller-chosen nonce is a key-recovery
//! hazard for NAPQES, so the deterministic-nonce entry point must not be
//! reachable from outside the crate. Only unit tests compiled with
//! `#[cfg(test)]` (this module) and the FIPS power-on self-test
//! (`crate::self_test`) may call it.
//!
//! Run:
//!   cargo test --lib kat_cross_check -- --nocapture

use crate::{
    decrypt_bytes, decrypt_bytes_v8, encrypt_bytes_v8_with_profile,
    encrypt_bytes_with_nonce, NONCE_SIZE, PadProfile,
};
use serde_json::Value;
use std::path::Path;

fn load_vectors() -> Vec<Value> {
    // Path is relative to the Cargo workspace root (repo root / rust/).
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(manifest_dir)
        .parent()             // repo root
        .unwrap()
        .join("tests/kat/v6_vectors.json");

    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Cannot read {}: {}", path.display(), e));

    let doc: Value = serde_json::from_str(&content)
        .expect("Invalid JSON in v6_vectors.json");

    doc["vectors"]
        .as_array()
        .expect("vectors array missing")
        .clone()
}

fn hex_decode(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// Positive: decrypt_bytes of stored ciphertext must recover the message
// ---------------------------------------------------------------------------

#[test]
fn positive_decrypt_roundtrip() {
    let vectors = load_vectors();
    let mut tested = 0;
    let mut skipped = 0;  // vectors skipped due to empty message

    for vec in vectors
        .iter()
        .filter(|v| v["kind"] == "positive" && v["api"] != "stream_ae")
    {
        let id = vec["id"].as_str().unwrap();
        let message = vec["message"].as_str().unwrap_or("");
        let ct_hex = vec["ciphertext_hex"].as_str().unwrap_or("");
        let aad_hex = vec["aad_hex"].as_str().unwrap_or("");

        // CVF-13: previously we skipped empty-message vectors because encrypt
        // returned an empty ciphertext and there was nothing to decrypt. That
        // is no longer true — empty messages now encrypt through the normal
        // path — so an empty-message vector should carry a real ciphertext_hex
        // and be decrypted like any other. We still skip if the corpus entry
        // has no ciphertext_hex at all, so an under-specified vector doesn't
        // cause a spurious failure.
        if ct_hex.is_empty() {
            skipped += 1;
            eprintln!("[SKIP] {} — no ciphertext_hex in corpus", id);
            continue;
        }

        let key: Vec<u64> = vec["key"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();

        let ct = hex_decode(ct_hex);
        let aad = hex_decode(aad_hex);

        match decrypt_bytes(&ct, &key, &aad) {
            Ok(plaintext) => {
                assert_eq!(
                    plaintext, message,
                    "[{}] decrypt_bytes roundtrip failed: got {:?}",
                    id, plaintext
                );
                eprintln!("[PASS] {}", id);
                tested += 1;
            }
            Err(e) => {
                panic!("[{}] decrypt_bytes returned Err: {}", id, e);
            }
        }
    }

    eprintln!(
        "\nRust KAT positive: {} passed, {} skipped (SKIP-PHASE2)",
        tested, skipped
    );
    // CVF-19: the previous guard was `if tested == 0 && skipped == 0 { panic!(...) }`.
    // Because `skipped` incremented for any vector missing `ciphertext_hex`,
    // a corpus rename that made every field absent left `skipped > 0`,
    // `tested == 0`, and the guard silently accepted the outcome. Match the
    // sibling test `positive_encrypt_bytes_deterministic` (line 183): a
    // positive-decrypt test with no vectors decrypted is a failure regardless
    // of the skip counter.
    assert!(
        tested > 0,
        "positive_decrypt_roundtrip: no vectors were decrypted (skipped: {}) — \
         check vector file path and corpus schema (CVF-19)",
        skipped
    );
}

// ---------------------------------------------------------------------------
// Deterministic encrypt: Rust must produce byte-identical ciphertext to Python
// ---------------------------------------------------------------------------

#[test]
fn positive_encrypt_bytes_deterministic() {
    let vectors = load_vectors();
    let mut tested = 0;

    for vec in vectors
        .iter()
        .filter(|v| v["kind"] == "positive" && v["api"] != "stream_ae")
    {
        let id = vec["id"].as_str().unwrap();
        let message = vec["message"].as_str().unwrap_or("");
        let nonce_hex = vec["nonce_hex"].as_str().unwrap_or("");
        let ct_hex = vec["ciphertext_hex"].as_str().unwrap_or("");
        let aad_hex = vec["aad_hex"].as_str().unwrap_or("");

        // CVF-13: the previous empty-message branch asserted an empty-in / empty-out
        // mapping under an empty key and all-zero nonce. That was the parity harness
        // pinning a universal forgery as if it were correct behaviour. The empty
        // message is now encrypted through the normal path like every other message
        // (producing a full, authenticated v7 ciphertext under the stated key,
        // nonce and AAD), so the special-case branch has been removed. An
        // empty-message v7 KAT vector must supply nonce_hex and ciphertext_hex like
        // any other positive vector; if it does not, we skip it below rather than
        // silently pretending an empty ciphertext is the answer.
        if nonce_hex.is_empty() || ct_hex.is_empty() {
            eprintln!("[SKIP] {} — missing nonce_hex or ciphertext_hex", id);
            continue;
        }

        let key: Vec<u64> = vec["key"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();

        let nonce_bytes = hex_decode(nonce_hex);
        assert_eq!(nonce_bytes.len(), NONCE_SIZE, "[{}] nonce must be {} bytes", id, NONCE_SIZE);
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&nonce_bytes);

        let expected_ct = hex_decode(ct_hex);
        let aad = hex_decode(aad_hex);

        let got_ct = encrypt_bytes_with_nonce(message, &key, nonce, &aad);

        assert_eq!(
            got_ct, expected_ct,
            "[{}] encrypt_bytes_with_nonce produced wrong ciphertext\n  got : {}\n  want: {}",
            id,
            got_ct.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            ct_hex,
        );
        eprintln!("[PASS] {} — deterministic encrypt matches Python KAT", id);
        tested += 1;
    }

    eprintln!("\nRust KAT deterministic encrypt: {} passed", tested);
    assert!(tested > 0, "No vectors were tested");
}

// ---------------------------------------------------------------------------
// Negative: tampered / invalid ciphertexts must return Err
// ---------------------------------------------------------------------------

#[test]
fn negative_returns_err() {
    let vectors = load_vectors();
    let mut tested = 0;

    for vec in vectors
        .iter()
        .filter(|v| v["kind"] == "negative" && v["api"] != "stream_ae")
    {
        let id = vec["id"].as_str().unwrap();
        let tampered_hex = vec["tampered_hex"].as_str().unwrap_or("");
        let aad_hex = vec["aad_hex"].as_str().unwrap_or("");

        if tampered_hex.is_empty() {
            eprintln!("[SKIP] {} — no tampered_hex", id);
            continue;
        }

        let key: Vec<u64> = vec["key"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();

        let ct = hex_decode(tampered_hex);
        let aad = hex_decode(aad_hex);

        let result = decrypt_bytes(&ct, &key, &aad);
        match result {
            Ok(pt) => panic!("[{}] expected Err but got Ok({:?})", id, pt),
            Err(err_text) => {
                // CVF-25: if the corpus supplies an `expected_error_contains`
                // string, check that the error message text contains it —
                // this distinguishes rejection at the tag check from
                // rejection at a post-authentication structural check
                // (Dec step (3), (6), (8)). Vectors that need to reach the
                // structural checks (W-N06/W-N07/W-N08) rely on this
                // discriminator to prove they actually do.
                // Corpus emits `expected_exception` (a substring of the
                // Python ValueError message); the same words also appear in
                // the Rust error text, so we can enforce them cross-port.
                // `expected_error_contains` remains reserved for cases where
                // the two languages diverge.
                if let Some(want) = vec
                    .get("expected_error_contains")
                    .and_then(|v| v.as_str())
                    .or_else(|| vec.get("expected_exception").and_then(|v| v.as_str()))
                {
                    assert!(
                        err_text.contains(want),
                        "[{}] error message did not contain expected \
                         substring {:?}; got: {}",
                        id, want, err_text
                    );
                }
                eprintln!("[PASS] {} — correctly returned Err", id);
                tested += 1;
            }
        }
    }

    eprintln!("\nRust KAT negative: {} passed", tested);
    // CVF-19: a negative-KAT test that never submitted a tampered ciphertext
    // is a hard failure. The previous eprintln! was the auditor's headline
    // example of a test that could not report failure: "Not a hard failure"
    // is exactly the wrong disposition for a rejection-oracle test.
    assert!(
        tested > 0,
        "negative_returns_err: no tampered vectors submitted — the \
         rejection oracle was never exercised (CVF-19)"
    );
}

// ---------------------------------------------------------------------------
// v8 cross-language parity (tests/kat/v8_vectors.json)
//
// v8 encryption is deterministic in `(primes, sk, aad, message)` — the nonce
// is a synthetic IV, so no KAT-only nonce-injection entry point is needed and
// the *public* `encrypt_bytes_v8` is compared byte-for-byte against Python.
//
// These vectors exist because the v7 corpus above does not exercise v8 at
// all, which is how the Rust port's missing domain-0x0B format subkey went
// undetected (docs/CAVEATS.md, V3-CVF1 Residual 4).
// ---------------------------------------------------------------------------

fn load_v8_vectors() -> Vec<Value> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join("tests/kat/v8_vectors.json");

    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Cannot read {}: {}", path.display(), e));

    let doc: Value = serde_json::from_str(&content).expect("Invalid JSON in v8_vectors.json");

    doc["vectors"]
        .as_array()
        .expect("vectors array missing")
        .clone()
}

fn v8_key(vec: &Value) -> Vec<u64> {
    vec["key"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect()
}

fn v8_sk(vec: &Value) -> [u8; crate::SK_SIZE] {
    let bytes = hex_decode(vec["sk_hex"].as_str().unwrap());
    bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("sk_hex must decode to {} bytes, got {}", crate::SK_SIZE, v.len()))
}

/// CVF-32: derive a `PadProfile` from an optional `pad_profile` corpus field.
/// Absent field or the string `"bucket"` maps to `PadProfile::Bucket`,
/// preserving the byte-identical semantics of the twelve W001-W012 vectors
/// that predate the schema extension. `{"coarse": 3}` and `{"frame": 1024}`
/// dispatch to the corresponding profile.
fn pad_profile_from_vec(vec: &Value) -> Result<PadProfile, String> {
    match vec.get("pad_profile") {
        None => Ok(PadProfile::Bucket),
        Some(Value::String(s)) if s == "bucket" => Ok(PadProfile::Bucket),
        Some(Value::Object(map)) => {
            if let Some(g) = map.get("coarse").and_then(|v| v.as_u64()) {
                return Ok(PadProfile::Coarse(g as u32));
            }
            if let Some(f) = map.get("frame").and_then(|v| v.as_u64()) {
                return Ok(PadProfile::Frame(f as u32));
            }
            Err(format!("unrecognised pad_profile object: {:?}", map))
        }
        Some(other) => Err(format!("unrecognised pad_profile value: {:?}", other)),
    }
}

#[test]
fn v8_positive_encrypt_matches_python() {
    let vectors = load_v8_vectors();
    let mut tested = 0;

    for vec in vectors.iter().filter(|v| v["kind"] == "positive") {
        let id = vec["id"].as_str().unwrap();
        let message = vec["message"].as_str().unwrap_or("");
        let expected_ct = hex_decode(vec["ciphertext_hex"].as_str().unwrap());
        let aad = hex_decode(vec["aad_hex"].as_str().unwrap_or(""));
        let sk = v8_sk(vec);
        let key = v8_key(vec);

        // CVF-32: dispatch on the optional `pad_profile` field so a corpus
        // can pin `bucket` (default), `coarse(g)`, or `frame(F)` vectors.
        // Absent field or "bucket" preserves the byte-identical behaviour of
        // the twelve W001-W012 vectors.
        let got_ct = pad_profile_from_vec(vec)
            .and_then(|profile| encrypt_bytes_v8_with_profile(message, &key, &sk, &aad, profile))
            .unwrap_or_else(|e| panic!("[{}] encrypt_bytes_v8_with_profile returned Err: {}", id, e));

        assert_eq!(
            got_ct.len(),
            expected_ct.len(),
            "[{}] v8 ciphertext length differs: got {}, want {}",
            id,
            got_ct.len(),
            expected_ct.len()
        );
        assert!(
            got_ct == expected_ct,
            "[{}] v8 ciphertext differs from the Python KAT (first differing byte at {:?})",
            id,
            got_ct.iter().zip(expected_ct.iter()).position(|(a, b)| a != b)
        );
        eprintln!("[PASS] {} — v8 encrypt matches Python KAT", id);
        tested += 1;
    }

    eprintln!("\nRust v8 KAT encrypt: {} passed", tested);
    assert!(tested > 0, "No v8 positive vectors were tested");
}

#[test]
fn v8_positive_decrypt_roundtrip() {
    let vectors = load_v8_vectors();
    let mut tested = 0;

    for vec in vectors.iter().filter(|v| v["kind"] == "positive") {
        let id = vec["id"].as_str().unwrap();
        let message = vec["message"].as_str().unwrap_or("");
        let ct = hex_decode(vec["ciphertext_hex"].as_str().unwrap());
        let aad = hex_decode(vec["aad_hex"].as_str().unwrap_or(""));
        let sk = v8_sk(vec);
        let key = v8_key(vec);

        let pt = decrypt_bytes_v8(&ct, &key, &sk, &aad)
            .unwrap_or_else(|e| panic!("[{}] decrypt_bytes_v8 returned Err: {}", id, e));
        assert_eq!(pt, message, "[{}] v8 roundtrip failed", id);
        eprintln!("[PASS] {} — v8 decrypt of the Python ciphertext", id);
        tested += 1;
    }

    eprintln!("\nRust v8 KAT decrypt: {} passed", tested);
    assert!(tested > 0, "No v8 positive vectors were tested");
}

#[test]
fn v8_negative_returns_err() {
    let vectors = load_v8_vectors();
    let mut tested = 0;

    for vec in vectors.iter().filter(|v| v["kind"] == "negative") {
        let id = vec["id"].as_str().unwrap();
        let ct = hex_decode(vec["tampered_hex"].as_str().unwrap());
        let aad = hex_decode(vec["aad_hex"].as_str().unwrap_or(""));
        let sk = v8_sk(vec);
        let key = v8_key(vec);

        let result = decrypt_bytes_v8(&ct, &key, &sk, &aad);
        match result {
            Ok(pt) => panic!("[{}] expected Err but got Ok({:?})", id, pt),
            Err(err_text) => {
                // CVF-25: enforce corpus-supplied error-substring where available.
                // Corpus emits `expected_exception` (a substring of the
                // Python ValueError message); the same words also appear in
                // the Rust error text, so we can enforce them cross-port.
                // `expected_error_contains` remains reserved for cases where
                // the two languages diverge.
                if let Some(want) = vec
                    .get("expected_error_contains")
                    .and_then(|v| v.as_str())
                    .or_else(|| vec.get("expected_exception").and_then(|v| v.as_str()))
                {
                    assert!(
                        err_text.contains(want),
                        "[{}] v8 error message did not contain expected \
                         substring {:?}; got: {}",
                        id, want, err_text
                    );
                }
                eprintln!("[PASS] {} — correctly returned Err", id);
            }
        }
        tested += 1;
    }

    eprintln!("\nRust v8 KAT negative: {} passed", tested);
    assert!(tested > 0, "No v8 negative vectors were tested");
}
// ---------------------------------------------------------------------------
// v8 STREAMING cross-language parity (tests/kat/v8_stream_vectors.json)
//
// v8 streaming uses a CSPRNG-drawn nonce per stream (CAV-005), so the KAT
// entry point must inject a fixed nonce. Uses `pub(crate)`
// `encrypt_stream_ae_v8_with_nonce` -- test-only, never reachable from
// external code.
// ---------------------------------------------------------------------------

use crate::{
    decrypt_stream_ae_v8, encrypt_stream_ae_v8_with_nonce, SK_SIZE,
};

fn load_v8_stream_vectors() -> Vec<Value> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join("tests/kat/v8_stream_vectors.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Cannot read {}: {}", path.display(), e));
    let doc: Value = serde_json::from_str(&content)
        .expect("Invalid JSON in v8_stream_vectors.json");
    doc["vectors"].as_array().expect("vectors array missing").clone()
}

fn v8_stream_primes(vec: &Value) -> Vec<u64> {
    vec["primes"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect()
}

fn v8_stream_sk(vec: &Value) -> [u8; SK_SIZE] {
    let bytes = hex_decode(vec["sk_hex"].as_str().unwrap());
    bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        panic!("sk_hex must decode to {} bytes, got {}", SK_SIZE, v.len())
    })
}

fn v8_stream_nonce(vec: &Value) -> [u8; crate::NONCE_SIZE] {
    let bytes = hex_decode(vec["nonce_hex"].as_str().unwrap());
    bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        panic!("nonce_hex must decode to {} bytes, got {}", crate::NONCE_SIZE, v.len())
    })
}

#[test]
fn v8_stream_positive_encrypt_matches_python() {
    let vectors = load_v8_stream_vectors();
    let mut tested = 0;
    for vec in vectors.iter().filter(|v| v["kind"] == "positive") {
        let id = vec["id"].as_str().unwrap();
        let message = vec["message"].as_str().unwrap_or("");
        let aad = hex_decode(vec["aad_hex"].as_str().unwrap_or(""));
        let frame_codepoints = vec["frame_codepoints"].as_u64().unwrap() as u32;
        let expected_ct = hex_decode(vec["ciphertext_hex"].as_str().unwrap());
        let primes = v8_stream_primes(vec);
        let sk = v8_stream_sk(vec);
        let nonce = v8_stream_nonce(vec);

        let got_ct = encrypt_stream_ae_v8_with_nonce(
            message, &primes, &sk, &nonce, &aad, frame_codepoints
        ).unwrap_or_else(|e| panic!("[{}] encrypt returned Err: {}", id, e));

        assert_eq!(
            got_ct.len(), expected_ct.len(),
            "[{}] v8 stream ct length differs: got {} want {}",
            id, got_ct.len(), expected_ct.len()
        );
        assert!(
            got_ct == expected_ct,
            "[{}] v8 stream ct differs from Python KAT (first differing byte at {:?})",
            id,
            got_ct.iter().zip(expected_ct.iter()).position(|(a, b)| a != b),
        );
        eprintln!("[PASS] {} -- v8 stream encrypt matches Python KAT", id);
        tested += 1;
    }
    eprintln!("\nRust v8 stream KAT encrypt: {} passed", tested);
    assert!(tested > 0, "No v8 stream positive vectors were tested");
}

#[test]
fn v8_stream_positive_decrypt_roundtrip() {
    let vectors = load_v8_stream_vectors();
    let mut tested = 0;
    for vec in vectors.iter().filter(|v| v["kind"] == "positive") {
        let id = vec["id"].as_str().unwrap();
        let message = vec["message"].as_str().unwrap_or("");
        let ct = hex_decode(vec["ciphertext_hex"].as_str().unwrap());
        let aad = hex_decode(vec["aad_hex"].as_str().unwrap_or(""));
        let primes = v8_stream_primes(vec);
        let sk = v8_stream_sk(vec);

        let pt = decrypt_stream_ae_v8(&ct, &primes, &sk, &aad)
            .unwrap_or_else(|e| panic!("[{}] decrypt returned Err: {}", id, e));
        assert_eq!(pt, message, "[{}] v8 stream roundtrip failed", id);
        eprintln!("[PASS] {} -- v8 stream decrypt of the Python ciphertext", id);
        tested += 1;
    }
    eprintln!("\nRust v8 stream KAT decrypt: {} passed", tested);
    assert!(tested > 0, "No v8 stream positive vectors were tested");
}
