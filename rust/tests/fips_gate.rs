//! CVF-V5-8: the FIPS gate must refuse every gated entry point before POST
//! and after a failure, and the failure must be sticky.
//!
//! Run with: `cargo test --features fips_gate,fault_injection --test fips_gate`
//!
//! The POST latch is process-global, so the phases run in one test, in order.
#![allow(deprecated)]

use napqes::self_test::{fault_injection, run_power_on_self_tests, SelfTestError};
use napqes::*;

const PRIMES: &[u64] = &[1_000_003, 1_000_033, 1_000_037, 1_000_039];
const SK: [u8; SK_SIZE] = [7u8; SK_SIZE];

fn refused<T>(name: &str, r: Result<T, String>) {
    match r {
        Ok(_) => panic!("{name}: admitted while the module is not operational"),
        Err(e) => assert!(e.contains("not operational"), "{name}: unexpected error {e}"),
    }
}

/// Every gated public entry point, called with otherwise-valid arguments.
fn assert_all_refused() {
    let key = NapqesKey::new(PRIMES.to_vec(), SK).expect("NapqesKey::new is not gated");
    let (pk, sk_kem) = kem::keygen();
    let (pk_h, sk_h) = kem::keygen_hybrid();

    refused("generate_prime_numbers", generate_prime_numbers(4, MIN_KEY_PRIME, MAX_KEY_PRIME));
    refused("generate_v8_key", generate_v8_key(4, MIN_KEY_PRIME, MAX_KEY_PRIME));
    refused("NapqesKey::generate", NapqesKey::generate());
    refused("encrypt_bytes_v8", encrypt_bytes_v8("m", PRIMES, &SK, b""));
    refused(
        "encrypt_bytes_v8_with_profile",
        encrypt_bytes_v8_with_profile("m", PRIMES, &SK, b"", PadProfile::Bucket),
    );
    refused("decrypt_bytes_v8", decrypt_bytes_v8(&[0u8; 64], PRIMES, &SK, b""));
    refused("encrypt_bytes_v8_key", encrypt_bytes_v8_key("m", &key, b""));
    refused("decrypt_bytes_v8_key", decrypt_bytes_v8_key(&[0u8; 64], &key, b""));
    refused(
        "encrypt_bytes_v8_with_profile_key",
        encrypt_bytes_v8_with_profile_key("m", &key, b"", PadProfile::Bucket),
    );
    refused("encrypt_stream_ae_v8", encrypt_stream_ae_v8("m", PRIMES, &SK, b"", 16));
    refused("decrypt_stream_ae_v8", decrypt_stream_ae_v8(&[0u8; 64], PRIMES, &SK, b""));
    refused("StreamV8Encryptor::new", StreamV8Encryptor::new(PRIMES, &SK, b"", 16));
    refused("encrypt", encrypt(&[0x41], PRIMES));
    refused("decrypt", decrypt(&[0u8; NONCE_SIZE], &[0u64; 20], PRIMES));
    refused("encrypt_bytes", encrypt_bytes("m", PRIMES, b""));
    refused("decrypt_bytes", decrypt_bytes(&[0u8; 64], PRIMES, b""));
    refused("encrypt_str", encrypt_str("m", PRIMES, b""));
    refused("decrypt_str", decrypt_str("AAAA", PRIMES, b""));
    refused("encrypt_raw", encrypt_raw(b"m", PRIMES, b""));
    refused("decrypt_raw", decrypt_raw(&[0u8; 64], PRIMES, b""));
    refused("kem::encapsulate", kem::encapsulate(&pk));
    refused("kem::decapsulate", kem::decapsulate(&[0u8; 16], &sk_kem));
    refused("kem::encapsulate_hybrid", kem::encapsulate_hybrid(&pk_h));
    refused("kem::decapsulate_hybrid", kem::decapsulate_hybrid(&[0u8; 16], &sk_h));
}

#[test]
fn gate_refuses_before_post_and_after_failure_and_failure_is_sticky() {
    // Phase 1: NOT_RUN refuses everything.
    assert_all_refused();

    // Phase 2: a passing POST admits.
    run_power_on_self_tests().expect("POST must pass");
    let ct = encrypt_bytes_v8("ok", PRIMES, &SK, b"").expect("admitted after POST");
    assert_eq!(decrypt_bytes_v8(&ct, PRIMES, &SK, b"").unwrap(), "ok");

    // Phase 3: an injected POST failure enters FAILED and refuses everything.
    fault_injection::fail_next_post();
    assert!(run_power_on_self_tests().is_err());
    assert_all_refused();

    // Phase 4: FAILED is sticky — a clean re-run of POST does not clear it.
    assert_eq!(run_power_on_self_tests(), Err(SelfTestError::NotOperational));
    assert_all_refused();
}
