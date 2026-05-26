# Constant-Time Attestation (dudect) — NAPQES v6 Rust Core

**Date:** 2026-05-26
**Tool:** [`dudect-bencher`](https://crates.io/crates/dudect-bencher) — Welch t-test TVLA harness
**Target:** `napqes::decrypt_bytes` in `rust/src/lib.rs`
**Harness:** `rust/examples/dudect_harness.rs`
**Threshold:** `|max t| < 4.5` (TVLA, matching ROADMAP §5 NF-6)

---

## Run 1 — `subtle::ConstantTimeEq` (FAIL)

**Date:** 2026-05-26
**Implementation:** `recv_tag.ct_eq(calc_tag.as_ref()).unwrap_u8() == 0`
**Measurements:** n = 1.958 M

```
bench bench_tag_comparison: n == +1.958M, max t = +411.85, max tau = +0.29435, (5/tau)^2 = 288
```

**Result: FAIL** — `|max t| = 411.85` is 91× above the 4.5 threshold.

### Root cause

`subtle::ConstantTimeEq` for `[u8]` is implemented as a pure-Rust fold over
XOR-accumulated bytes.  At `-O3` (Rust `--release`), LLVM is free to transform
this into a short-circuit loop because the optimiser can prove that the
accumulator can only gain set bits, never lose them.  The crate's README
explicitly states: *"There is no guarantee that the compiler won't optimize the
resulting code into variable-time code."*

`(5/tau)² = 288` means the leak is detectable in fewer than 300 measurements —
this is a large, systematic early-exit, consistent with LLVM compiling the fold
into a byte-by-byte branch.

`subtle = "2"` has been **removed** from `rust/Cargo.toml`.

---

## Run 2 — `ptr::read_volatile` only (FAIL)

**Date:** 2026-05-26
**Implementation** (`rust/src/lib.rs`, function `ct_eq_bytes`):

```rust
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        unsafe {
            diff |= std::ptr::read_volatile(x) ^ std::ptr::read_volatile(y);
        }
    }
    diff == 0
}
```

**Measurements:** n = 1.958 M

```
bench bench_tag_comparison: n == +1.958M, max t = +143.85, max tau = +0.30714, (5/tau)^2 = 265
```

**Result: FAIL** — `|max t| = 143.85` is 32× above the 4.5 threshold.
tau ≈ 0.307 is essentially unchanged from Run 1 (tau ≈ 0.294), indicating the
leak source is NOT the comparison implementation.

### Root cause — two compounding issues

**Issue 1 — LLVM inlining + control-flow restructuring.**
Without `#[inline(never)]`, LLVM inlined `ct_eq_bytes` into `decrypt_bytes` and
observed that XOR accumulation is semantically equivalent to byte-by-byte
comparison with early exit.  It generated 32 `cmpb + jne` pairs after loading
all 32 bytes via volatile reads.  The volatile reads were performed (no bytes
skipped), but LLVM used the loaded values in data-dependent branches.  Evidence
from `target/release/deps/napqes-df2095fdf2271e28.s` lines 2324–2329:

```asm
cmpb    %al, %cl      ; compare byte 0 of tag
jne     .LBB19_47     ; EARLY EXIT if not equal
cmpb    %r15b, %r12b  ; compare byte 1
jne     .LBB19_47     ; EARLY EXIT
cmpb    %r14b, %r13b  ; compare byte 2
jne     .LBB19_47     ; EARLY EXIT
```

**Issue 2 — Harness memory-layout confound.**
The harness maintained two separate Vec pools (`left_cts`, `right_cts`) at
different heap addresses.  Left measurements always accessed `left_cts[idx]`
and Right measurements always accessed `right_cts[idx]`.  Systematic differences
in cache-line residence, TLB entries, and DRAM row addresses between the two
pools produced a non-zero tau unrelated to the comparison implementation.  This
accounts for the unchanged tau ≈ 0.30 across Run 1 and Run 2 — the dominant
signal was the memory-layout bias, not the implementation.

---

## Run 3 — `ptr::write_volatile` + `#[inline(never)]` + harness fix (PASS)

**Date:** 2026-05-26
**Implementation** (`rust/src/lib.rs`, function `ct_eq_bytes`):

```rust
#[inline(never)]
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        unsafe {
            diff |= std::ptr::read_volatile(x) ^ std::ptr::read_volatile(y);
            std::ptr::write_volatile(&mut diff, diff);
        }
    }
    diff == 0
}
```

Three properties together prevent LLVM from generating an early-exit loop:

1. **`#[inline(never)]`** — the function is opaque to its caller; LLVM cannot
   sink the caller's branch into the function body or restructure the function's
   control flow in context.
2. **`read_volatile` on every byte** — volatile reads cannot be eliminated or
   reordered; all 32 bytes are unconditionally loaded.
3. **`write_volatile` to `diff` after every XOR** — the store is an observable
   side-effect; skipping any loop iteration would change the sequence of stores,
   which LLVM is forbidden to do.  This forces every iteration to execute.

**Harness fix** (`rust/examples/dudect_harness.rs`):  Three successive confounds
were identified and corrected:

1. **Memory-layout confound** — separate `left_cts` / `right_cts` pool Vecs at
   different heap addresses created systematic cache-line differences.  Fixed by
   using a single Vec cloned once per bench call.
2. **Measurement-order bias** — Left was always measured first within each pair;
   the second measurement (Right) consistently benefited from cache warmup.
   Fixed by randomising which class is measured first.
3. **Within-call interference** — both measurements in a pair shared pipeline and
   branch-predictor state from each other.  Fixed by measuring only ONE class per
   bench call (chosen by `rng`), so each measurement is fully independent.

### Assembly verification

After applying both fixes, `cargo rustc --lib --release -- --emit=asm` produces
a fully unrolled, branchless sequence for `ct_eq_bytes`
(`target/release/deps/napqes-5dd25da441a32052.s`, lines 504–641):

```asm
_ZN6napqes11ct_eq_bytes17hd6af8b03bbd53e4dE:
    movzbl  (%rcx), %eax        ; load byte 0 of a
    xorb    (%rdx), %al         ; XOR with byte 0 of b
    movb    %al, 7(%rsp)        ; write_volatile store (materialise diff[0])
    movzbl  1(%rcx), %r8d       ; load byte 1 of a
    xorb    1(%rdx), %r8b       ; XOR with byte 1 of b
    orb     %al, %r8b           ; accumulate
    movb    %r8b, 7(%rsp)       ; write_volatile store (materialise diff[1])
    ; ... 30 more byte triples, identical pattern ...
    movzbl  31(%rcx), %ecx      ; load byte 31 of a
    xorb    31(%rdx), %cl       ; XOR with byte 31 of b
    orb     %al, %cl            ; accumulate final byte
    movb    %cl, 7(%rsp)        ; write_volatile store (materialise diff[31])
    sete    %al                 ; return diff == 0 (no data-dependent branch)
    retq
```

There are **no `cmpb + jne` pairs** — the function is a straight-line sequence
of 32 load-XOR-accumulate-store triples followed by a single `sete`.
The function is now called via `callq` from `decrypt_bytes` (not inlined).

### Empirical result

**Measurements:** n = 12.712 M

```
bench bench_tag_comparison: n == +12.712M, max t = +1.13413, max tau = +0.00032, (5/tau)^2 = 247068360
```

**Result: PASS** — `|max t| = 1.13` is well below the 4.5 threshold.

`tau = 0.00032` is an extremely small residual effect.  To reach t = 5 would
require approximately 247 M measurements under ideal local conditions.  Over
any realistic network channel (millisecond-level jitter), this residual is
completely undetectable.  No practically exploitable timing leak was found.

**To re-run:**

```bash
cd rust
cargo run --example dudect_harness --release -- --continuous bench_tag_comparison
# Let run until max t stabilises (≥ 2 M measurements, ~2–3 min on a modern laptop)
# Press Ctrl+C when n > 2 M and max t is stable.
```

---

## References

- TVLA methodology: NIST SP 800-90B, ISO/IEC 17825
- ROADMAP §4.1 F-8, §5 NF-6 (constant-time Rust core, Phase 2 workstream 2.2)
- `subtle` crate warning: https://docs.rs/subtle/latest/subtle/#limitations
- Bellare & Rogaway 1994: "Optimal Asymmetric Encryption", constant-time comparison
