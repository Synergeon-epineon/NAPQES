//! Constant-time timing analysis for `napqes::decrypt_bytes`.
//!
//! Run (release mode required for meaningful timings):
//!   cargo run --example dudect_harness --release -- --continuous bench_tag_comparison
//!
//! The test compares decryption timing when the HMAC-SHA256 tag differs at the
//! FIRST byte (Class::Left) versus the LAST byte (Class::Right).  A naive
//! byte-by-byte comparator would exit early on Left (faster), producing a
//! detectable t-statistic.  A correct constant-time implementation scans all 32
//! bytes unconditionally, so both classes should be timing-indistinguishable.
//!
//! Target: |t| < 4.5 (TVLA threshold per ROADMAP §5 NF-6).
//!
//! Note: allow the benchmark to accumulate at least 2 M measurements before
//! drawing conclusions.  Early batches (n < 200 k) are noisy.
//!
//! ## Design rationale
//!
//! One measurement per bench call, class chosen randomly by `rng`:
//!   - Eliminates the memory-layout confound (single Vec, same allocation each
//!     call because the allocator reuses the freed slot from the previous call).
//!   - Eliminates the within-call measurement-order bias: the second measurement
//!     in a pair always benefits from the first having loaded `ct` into cache.
//!     With one measurement per call each class experiences the same cache state
//!     (the slot was used by the previous call, which was Left or Right equally
//!     often) — the cache warmup advantage averages to zero for both classes.
//!   - The rng branch that picks Left vs Right happens BEFORE the measurement
//!     window (outside run_one), so any branch-predictor artefact from the rng
//!     branch is shared equally by both classes.

use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use napqes::{decrypt_bytes, encrypt_bytes, TAG_SIZE};
use rand::Rng;
use std::sync::OnceLock;

fn fixed_key() -> &'static Vec<u64> {
    static KEY: OnceLock<Vec<u64>> = OnceLock::new();
    KEY.get_or_init(|| {
        vec![
            1_000_003, 1_000_033, 1_000_037, 1_000_039,
            1_000_079, 1_000_081, 1_000_099, 1_000_117,
            1_000_121, 1_000_133,
        ]
    })
}

/// A single valid ciphertext produced once at startup.  Both classes derive
/// from this by cloning (allocator reuses the same heap slot between calls)
/// and corrupting one tag byte in-place.
fn base_ct() -> &'static Vec<u8> {
    static CT: OnceLock<Vec<u8>> = OnceLock::new();
    CT.get_or_init(|| {
        encrypt_bytes(
            "napqes dudect constant-time timing harness",
            fixed_key(),
            b"",
        )
        .expect("dudect: encrypt failed")
    })
}

fn bench_tag_comparison(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = fixed_key();
    let base = base_ct();
    let n = base.len();

    // Clone once — allocator typically reuses the same slot between calls,
    // giving both classes the same cache-line starting state.
    let mut ct = base.clone();

    // Choose Left or Right this call.  Both are equally likely, so any
    // systematic source of bias (cache warmup, branch-predictor state) is
    // applied to Left and Right with equal probability and cancels out.
    if rng.gen::<bool>() {
        // Left: tag byte 0 wrong (early-exit comparator fails immediately)
        ct[n - TAG_SIZE] ^= 0xFF;
        runner.run_one(Class::Left, || decrypt_bytes(&ct, key, b""));
    } else {
        // Right: tag byte 31 wrong (early-exit comparator scans all 31 bytes)
        ct[n - 1] ^= 0xFF;
        runner.run_one(Class::Right, || decrypt_bytes(&ct, key, b""));
    }
    // ct dropped here
}

ctbench_main!(bench_tag_comparison);
