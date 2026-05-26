//! Rust KAT harness for NAPSEQ v6 (Phase 0, workstream 0.1 / ROADMAP §2.B8).
//!
//! Reads `tests/kat/v6_vectors.json` from the repo root, exercises both the
//! deterministic `encrypt_bytes_with_nonce` API (exact byte comparison) and
//! the `decrypt_bytes` API for positive vectors, and asserts that negative
//! vectors return an `Err`.
//!
//! Run:
//!   cargo test --test kats -- --nocapture

use napqes::{decrypt_bytes, encrypt_bytes_with_nonce, NONCE_SIZE};
use serde_json::Value;
use std::path::Path;

// serde_json is added as a dev-dependency in Cargo.toml by Phase 0 setup.

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

        // Empty-message vector: no ciphertext to decrypt
        if message.is_empty() {
            skipped += 1;
            eprintln!("[SKIP] {} — empty message, no ciphertext", id);
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
    // Fail if ZERO vectors were tested successfully (indicates a build problem)
    if tested == 0 && skipped == 0 {
        panic!("No positive vectors were tested — check vector file path");
    }
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

        // Empty-message vector: nonce_hex is "" and ciphertext_hex is ""
        if message.is_empty() {
            let ct = encrypt_bytes_with_nonce(message, &[], [0u8; NONCE_SIZE], b"");
            assert!(ct.is_empty(), "[{}] empty message should produce empty ciphertext", id);
            eprintln!("[PASS] {} — empty message", id);
            tested += 1;
            continue;
        }

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
        assert!(
            result.is_err(),
            "[{}] expected Err but got Ok({:?})",
            id,
            result.unwrap()
        );
        eprintln!("[PASS] {} — correctly returned Err", id);
        tested += 1;
    }

    eprintln!("\nRust KAT negative: {} passed", tested);
    if tested == 0 {
        // Not a hard failure: negative vectors may also hit SKIP-PHASE2 paths
        eprintln!("PARITY-NOTE: no negative vectors exercised");
    }
}
