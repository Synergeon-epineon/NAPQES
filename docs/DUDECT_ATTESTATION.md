# NAPQES — dudect constant-time timing attestation

**Status.** Attestation document for the `dudect_harness` example in the
Rust reference implementation. Referenced by `docs/napseq-eprint-v3.tex`
Section 8.4 (constant-time claims).

**Created.** 2026-09-22, in response to audit finding CVF-26 which noted
that the paper cited this document without it having been delivered.

## Scope

The harness at `rust/examples/dudect_harness.rs` runs a two-class TVLA
comparison over the v8 decrypt path (`decrypt_bytes_v8_key`). The two
classes differ only in which byte of the HMAC-SHA256 tag has been flipped:

* `Class::Left` — flip the FIRST tag byte (byte offset 0 of the 32-byte tag).
* `Class::Right` — flip the LAST tag byte (byte offset 31).

A byte-by-byte tag comparator with early-exit-on-mismatch would exit after
one byte on Left and after 31 bytes on Right, producing a large
t-statistic. The Rust port uses `subtle::ConstantTimeEq` (CVF-12 fix); the
two classes must be timing-indistinguishable to |t| < 4.5 (TVLA threshold).

**Measurement scope limitation.** The harness times the entire
`decrypt_bytes_v8_key` call (~30,000 cycles per iteration on the reference
platform), which includes:

* `derive_format_subkey` (one HMAC-SHA256 call, ~500 cycles)
* `compute_auth_tag` (HMAC-SHA256 over the whole ~3 KB payload, ~28,000 cycles)
* `ct_eq_bytes` (32-byte constant-time compare, ~30 cycles)

Any bias in the ~30-cycle `ct_eq_bytes` call is therefore ~0.1% of the
total signal, well below noise for realistic sample sizes. A tighter
harness that directly measures `ct_eq_bytes` requires exposing a
`#[cfg(feature = "ct_bench")]` public accessor for the function — tracked
as a CVF-26 follow-up. The current harness's role is to demonstrate
end-to-end that no early-exit path exists on the tag position, not to
tightly bound the comparator itself.

## Reproduction command

Release mode is required for meaningful timings.

```sh
cd rust
cargo run --example dudect_harness --release -- --continuous bench_tag_comparison
```

Allow at least 2 million measurements to accumulate before drawing
conclusions; early batches (n < 200,000) are noisy.

## Reference measurement

| Field | Value |
|---|---|
| Platform | Windows 11 Home x86_64, AMD Ryzen AI 7 350 w/ Radeon 860M |
| Compiler | rustc 1.93.1 (01f6ddf75 2026-02-11) |
| Compiler flags | `--release` (Cargo `[profile.release]` per `Cargo.toml`; `overflow-checks = true`, `debug-assertions = false`; opt-level = 3) |
| Command | `target/release/examples/dudect_harness --continuous bench_tag_comparison` |
| Sample count | 29.729 M |
| Observed \|t\| | 1.113 (max over dudect's percentile-cropped tests); max tau = 0.00020 |
| Decision | **Pass** (\|t\| < 4.5) |
| Date | 2026-09-25 |
| Commit | 6db914e + working-tree changes of 2026-09-25 |

\|t\| stayed below 1.2 for the whole run (1.167 at 28.9 M samples, 1.113 at 29.7 M). This
bounds the leak between the two classes the harness defines (first vs last tag byte
corrupted) inside a full `decrypt_bytes_v8_key` call. It says nothing about the paths listed
under "Known limitations".

## Known limitations

* Harness measures the full decrypt call; tag-comparison signal is buried
  (see "Measurement scope limitation" above). A comparator-focused harness
  is tracked as CVF-26 follow-up.
* Python and C reference implementations are not covered here; the paper's
  Section 8.4 attestation is Rust-scoped.
* The token-inversion and division paths inside `decrypt_core_v8` are
  explicitly **not constant-time** and the paper documents this (see
  Section 8.4 "What is not constant-time"). The harness does not measure
  those; a distinguisher targeting a bias there is out of scope for this
  attestation.
* v7's f64-based `derive_noise_p` is also not constant-time (CVF-30). v7
  encryptors are `#[deprecated]` per CVF-17; the v7 decryptor is retained
  for archived ciphertexts only.

## Change history

| Date | Change |
|---|---|
| 2026-09-22 | Document created (CVF-26). Harness retargeted from v7 `decrypt_bytes` to v8 `decrypt_bytes_v8_key`. ROADMAP §5 NF-6 citation replaced with paper Section 8.4. Scope limitations spelled out. |
| 2026-09-25 | First reference measurement recorded: 29.7 M samples, \|t\| = 1.11, pass. Note: `--continuous` writes a status line per batch; redirecting it to a file produced a 6 GB log in ~5 minutes, so capture only the tail. |
