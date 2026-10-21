//! Constant-time timing analysis (dudect / TVLA two-class t-test).
//!
//! Two benches (CVF-26, CVF-V5-27):
//!
//! * `bench_ct_eq_bytes` — **the comparator alone.** Times `ct_eq_bytes` on
//!   two equal-length 32-byte inputs that differ in the first byte (Left)
//!   or only in the last byte (Right). An early-exit comparator separates
//!   the classes within a few thousand samples; this is the high-power test
//!   and the one CI gates on.
//! * `bench_positive_control_early_exit` — the same measurement on a naive
//!   early-exit comparator; it must fail, which shows the comparator bench
//!   can detect the leak it is looking for.
//! * `bench_tag_comparison` — the whole `decrypt_bytes_v8_key` call with the
//!   first vs. the last tag byte flipped. The comparator is about 0.1% of
//!   that call (the HMAC over the payload dominates), so a pass here is
//!   low-power, end-to-end evidence only.
//!
//! The key is pinned (fixed primes and `sk`) so runs are reproducible; key
//! validation is not on the measured path (`NapqesKey` validates once).
//!
//! Run (release mode and the `ct_bench` feature are required):
//!   cargo run --release --features ct_bench --example dudect_harness -- --filter bench_ct_eq_bytes
//!   cargo run --release --features ct_bench --example dudect_harness -- --continuous bench_ct_eq_bytes
//!
//! Target: |t| < 4.5 (TVLA threshold, paper Section 8.4).

use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use napqes::{ct_bench_eq, decrypt_bytes_v8_key, encrypt_bytes_v8_key, NapqesKey, TAG_SIZE};
use rand::Rng;
use std::hint::black_box;
use std::sync::OnceLock;

/// Pinned key (vector W002's primes and a fixed sk), validated once.
fn fixed_key() -> &'static NapqesKey {
    static KEY: OnceLock<NapqesKey> = OnceLock::new();
    KEY.get_or_init(|| {
        napqes::self_test::run_power_on_self_tests().expect("dudect: POST failed");
        NapqesKey::new(vec![1_000_003, 1_000_033, 1_000_037, 1_000_039], [0x5a; 32])
            .expect("dudect: pinned key invalid")
    })
}

/// One valid v8 ciphertext produced once at startup. Both classes derive
/// from this by cloning + corrupting one tag byte in-place; allocator
/// typically reuses the same slot, giving both classes similar cache state.
fn base_ct() -> &'static Vec<u8> {
    static CT: OnceLock<Vec<u8>> = OnceLock::new();
    CT.get_or_init(|| {
        encrypt_bytes_v8_key(
            "napqes v8 dudect constant-time timing harness (CVF-26 retarget)",
            fixed_key(),
            b"",
        )
        .expect("dudect: v8 encrypt failed")
    })
}

/// Comparator calls per measurement: one 32-byte comparison is a few
/// nanoseconds, below the timer's resolution, so each sample repeats it.
const CT_EQ_REPS: usize = 100;

fn bench_ct_eq_bytes(runner: &mut CtRunner, rng: &mut BenchRng) {
    let reference = [0xA5u8; TAG_SIZE];
    let mut candidate = reference;
    let run = |a: &[u8; TAG_SIZE], b: &[u8; TAG_SIZE]| {
        for _ in 0..CT_EQ_REPS {
            black_box(ct_bench_eq(black_box(a), black_box(b)));
        }
    };
    if rng.gen::<bool>() {
        candidate[0] ^= 0xFF;
        runner.run_one(Class::Left, || run(&reference, &candidate));
    } else {
        candidate[TAG_SIZE - 1] ^= 0xFF;
        runner.run_one(Class::Right, || run(&reference, &candidate));
    }
}

/// Positive control (CVF-V5-27): the same measurement on a deliberately
/// early-exit comparator. It must FAIL (|t| far above 4.5), which shows the
/// comparator bench has the power to detect a position-dependent leak.
fn bench_positive_control_early_exit(runner: &mut CtRunner, rng: &mut BenchRng) {
    fn early_exit_eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == y)
    }
    let reference = [0xA5u8; TAG_SIZE];
    let mut candidate = reference;
    let run = |a: &[u8; TAG_SIZE], b: &[u8; TAG_SIZE]| {
        for _ in 0..CT_EQ_REPS {
            black_box(early_exit_eq(black_box(a), black_box(b)));
        }
    };
    if rng.gen::<bool>() {
        candidate[0] ^= 0xFF;
        runner.run_one(Class::Left, || run(&reference, &candidate));
    } else {
        candidate[TAG_SIZE - 1] ^= 0xFF;
        runner.run_one(Class::Right, || run(&reference, &candidate));
    }
}

fn bench_tag_comparison(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = fixed_key();
    let base = base_ct();
    let n = base.len();
    // dudect-bencher fixes its crop percentiles from the first batch; warm
    // the caches and clock first (unmeasured) so they reflect steady state.
    static WARM: std::sync::Once = std::sync::Once::new();
    WARM.call_once(|| {
        for _ in 0..20_000 {
            let _ = black_box(decrypt_bytes_v8_key(black_box(base), key, b""));
        }
    });

    let mut ct = base.clone();

    // Left: tag byte 0 wrong  (a hypothetical early-exit comparator would
    // fail immediately). Right: tag byte 31 wrong (would scan all 31 bytes).
    if rng.gen::<bool>() {
        ct[n - TAG_SIZE] ^= 0xFF;
        runner.run_one(Class::Left, || decrypt_bytes_v8_key(&ct, key, b""));
    } else {
        ct[n - 1] ^= 0xFF;
        runner.run_one(Class::Right, || decrypt_bytes_v8_key(&ct, key, b""));
    }
}

ctbench_main!(bench_ct_eq_bytes, bench_positive_control_early_exit, bench_tag_comparison);
