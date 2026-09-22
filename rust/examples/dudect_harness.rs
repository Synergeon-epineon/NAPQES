//! Constant-time timing analysis for the NAPQES v8 decrypt path.
//!
//! **CVF-26 update (2026-09-22).**
//! * Retargeted from the legacy v7 `decrypt_bytes` to `decrypt_bytes_v8_key`
//!   so the harness measures the code path consumers are steered toward.
//! * Doc-comment now states scope accurately: the harness measures the
//!   *whole* `decrypt_bytes_v8_key` call, which includes `derive_format_subkey`
//!   plus `compute_auth_tag` (HMAC-SHA256 over the whole payload) — the
//!   tag-comparison signal (a subtle::ConstantTimeEq call, CVF-12) is buried
//!   inside tens of thousands of cycles per iteration. A tighter harness that
//!   directly measures the comparator is tracked as a follow-up (would require
//!   a `#[cfg(feature = "ct_bench")]` public accessor for `ct_eq_bytes`).
//! * `dudect_bencher` reports a t-statistic per class. Publish the observed
//!   |t|, the platform, compiler flags, and iteration count in
//!   `docs/DUDECT_ATTESTATION.md` alongside the citation of Section 8.4 of
//!   the paper (not the old ROADMAP §5 NF-6 reference).
//!
//! Run (release mode required for meaningful timings):
//!   cargo run --example dudect_harness --release -- --continuous bench_tag_comparison
//!
//! Target: |t| < 4.5 (TVLA threshold, per paper Section 8.4).

use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};
use napqes::{decrypt_bytes_v8_key, encrypt_bytes_v8_key, NapqesKey, TAG_SIZE};
use rand::Rng;
use std::sync::OnceLock;

/// Fresh, validated NapqesKey generated once at startup (CVF-29/37/41 wrapper).
fn fixed_key() -> &'static NapqesKey {
    static KEY: OnceLock<NapqesKey> = OnceLock::new();
    KEY.get_or_init(|| NapqesKey::generate().expect("dudect: NapqesKey::generate failed"))
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

fn bench_tag_comparison(runner: &mut CtRunner, rng: &mut BenchRng) {
    let key = fixed_key();
    let base = base_ct();
    let n = base.len();

    let mut ct = base.clone();

    // Left: tag byte 0 wrong  (a hypothetical early-exit comparator would
    // fail immediately). Right: tag byte 31 wrong (would scan all 31 bytes).
    // With subtle::ConstantTimeEq the two must be timing-indistinguishable.
    if rng.gen::<bool>() {
        ct[n - TAG_SIZE] ^= 0xFF;
        runner.run_one(Class::Left, || decrypt_bytes_v8_key(&ct, key, b""));
    } else {
        ct[n - 1] ^= 0xFF;
        runner.run_one(Class::Right, || decrypt_bytes_v8_key(&ct, key, b""));
    }
}

ctbench_main!(bench_tag_comparison);
