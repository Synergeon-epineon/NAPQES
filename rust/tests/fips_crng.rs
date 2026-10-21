//! CVF-V5-19: a CRNG continuous-test failure must put the module in the
//! sticky error state, not just fail the current call.
//!
//! Run with: `cargo test --features fips_gate,fault_injection --test fips_crng`
#![allow(deprecated)]

use napqes::self_test::{fault_injection, run_power_on_self_tests, SelfTestError};
use napqes::*;

const PRIMES: &[u64] = &[1_000_003, 1_000_033, 1_000_037, 1_000_039];
const SK: [u8; SK_SIZE] = [7u8; SK_SIZE];

#[test]
fn crng_failure_latches_error_state() {
    run_power_on_self_tests().expect("POST must pass");
    encrypt_bytes("before", PRIMES, b"").expect("admitted after POST");

    fault_injection::force_crng_stuck();
    let err = encrypt_bytes("stuck", PRIMES, b"").unwrap_err();
    assert!(err.contains("CRNG"), "unexpected error: {err}");

    // The next call must not simply draw again and proceed.
    let err = encrypt_bytes("after", PRIMES, b"").unwrap_err();
    assert!(err.contains("not operational"), "unexpected error: {err}");
    let err = encrypt_bytes_v8("after", PRIMES, &SK, b"").unwrap_err();
    assert!(err.contains("not operational"), "unexpected error: {err}");

    // Sticky: re-running POST does not return the module to service.
    assert_eq!(run_power_on_self_tests(), Err(SelfTestError::NotOperational));
}
