# Fuzz Attestation — NAPQES

## Round 5 recorded run (CVF-V5-26) — current targets

This section supersedes the historical v6 material below, which describes
earlier harnesses and is kept only for the record.

| Field | Value |
|---|---|
| Commit | `471501e` (fuzz targets and seed corpus as committed) |
| Date | 2026-10-21 |
| Platform | Windows 11 x86_64, AMD Ryzen AI 7 350 |
| Toolchain | `rustc 1.100.0-nightly (1303417c4 2026-09-21)`, `cargo-fuzz 0.13.2`, libFuzzer with AddressSanitizer (MSVC) |
| Command | `cargo +nightly fuzz run <target> <scratch-corpus> fuzz/corpus/<target> -- -max_total_time=600` |
| Seed corpus | `rust/fuzz/corpus/<target>/` (committed) |

| Target | What it reaches | Executions | Wall-clock | Coverage (cov / ft) | Final corpus | Crashes / panics |
|---|---|---|---|---|---|---|
| `decode_bytes` | v8 block decrypt after **re-tagging**: post-tag bucket check, token guards, scalar check, length prefix; all three padding profiles (with invalid parameters) and nonce mutation | 5,946 | 604 s | 507 / 1,438 | 83 | **0** |
| `stream_decode` | v8 streaming decrypt after re-tagging every chunk and the sentinel: header `F`, nonce, chunk bytes, masked count, dropped / duplicated / truncated frames | 27,973 | 601 s | 657 / 2,404 | 113 | **0** |
| `unauth_decode` | `decrypt` on structurally valid `c * k + a` token streams with one mutation; `decrypt_raw` / `decrypt_str` on raw bytes | 18,810 | 601 s | 599 / 1,332 | 116 | **0** |
| `validate_key` | arbitrary key tuples through every v7 and v8 entry point | 378,097 | 601 s | 572 / 1,389 | 129 | **0** |

Each target also asserts the **unmutated** round trip before mutating, so a
run that never decrypts successfully would abort, not pass silently.

**Limits of this evidence.** Execution rates are low (9-46 exec/s for the
decoders) because every v8 ciphertext is about 160 bytes per padded
codepoint and the targets run under AddressSanitizer; the run is a
10-minute smoke test per target, not a saturation campaign. The four
targets were run concurrently on one machine. CI builds the fuzz crate on
every push (`cargo check --bins` in `rust/fuzz`) but does not run it. The
Python harness `tests/fuzz_atheris.py` targets the legacy decoders and has
no recorded coverage-guided run; it is not cited as evidence for v8.

---

# Historical (v6, 2026-05-28)

**Date:** 2026-05-28
**Harnesses:** `tests/fuzz_atheris.py` (Python), `rust/fuzz/fuzz_targets/decode_bytes.rs` (Rust) — Phase 1, workstream 1.6
**Specification version:** v6 (wire format frozen — see `SPEC.md`)

---

## Run Summary

### Python harness (`tests/fuzz_atheris.py`)

| Mode | Date | Iterations | Wall-clock | Crashes | Unexpected exceptions |
|---|---|---|---|---|---|
| Simple random (seeded PRNG, all platforms) | 2026-05-26 | 10 000 | ~9 s | 0 | 0 |
| Simple random (seeded PRNG, all platforms) | 2026-05-28 | 10 000 | ~9 s | 0 | 0 |
| Coverage-guided atheris (Linux/macOS) | pending Phase 2 | — | — | — | — |

**Result: PASS.** All 10 000 random inputs were handled without crashes or any
exception type other than the documented `ValueError` / `IndexError`.

---

## Targets Exercised

| Entry point | Description |
|---|---|
| `decrypt_bytes(data, key)` | Full v6 decode pipeline: auth check → LEB128 varint decode → unpad → plaintext |
| `_b128_decode_tokens(data)` | LEB128 varint parser in isolation |
| `decrypt_bytes(..., allow_legacy_unauthenticated=True)` | Legacy unauthenticated decode path |

---

## Security Contract Verified

`decrypt_bytes` MUST:
- Return a `str` on success (rare with random data — auth almost always fails).
- Raise `ValueError` on any authentication or format error.
- Never raise any other exception type regardless of input content.

All three properties were upheld across all 10 000 iterations.

---

## Reproducing

Simple mode (no dependencies beyond the repo):
```
python tests/fuzz_atheris.py
```

Coverage-guided mode (requires `pip install atheris` on Linux/macOS):
```
python tests/fuzz_atheris.py -atheris_runs=100000
```

---

## Rust cargo-fuzz harness (`rust/fuzz/fuzz_targets/decode_bytes.rs`)

A libFuzzer-based Rust harness exists and has been checked in. It targets the
Rust `decrypt_bytes` function across three coverage paths:

| Target | Description |
|---|---|
| Target 1 | Full v6 decode with key selected by fuzzer byte[0] |
| Target 2 | Same payload, empty AAD — exercises AAD-binding path |
| Target 3 | Key bytes 0 and 1 swapped — wrong key, auth must fail |

Three key fixtures (1-element, 2-element, 10-element keys) and four AAD fixtures
are driven by fuzzer input bytes, maximising coverage of the key-size and AAD
code paths.

**Run (nightly required):**
```
cargo +nightly fuzz run decode_bytes -- -max_total_time=300
```

A coverage-guided run on a Linux CI machine is a Phase 2 deliverable (workstream
2.2). No crashes or panics were produced in the initial harness bring-up runs.

---

## Roadmap

Phase 2 (workstream 2.2) will add:
- Coverage-guided atheris run (≥ 1 000 000 iterations) on Linux CI.
- Corpus of structured edge cases: minimum-length ciphertext, max-length
  ciphertext (CAV-002 boundary), zero-tag, all-zero nonce.
- Extended `cargo fuzz` CI run (≥ 1 000 000 executions) with corpus check-in.
