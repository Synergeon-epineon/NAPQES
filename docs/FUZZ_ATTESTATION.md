# Fuzz Attestation — NAPQES v6

**Date:** 2026-05-26
**Harness:** `tests/fuzz_atheris.py` (Phase 1, workstream 1.6)
**Specification version:** v6 (wire format frozen — see `SPEC.md`)

---

## Run Summary

| Mode | Iterations | Wall-clock | Crashes | Unexpected exceptions |
|---|---|---|---|---|
| Simple random (seeded PRNG, all platforms) | 10 000 | ~9 s | 0 | 0 |
| Coverage-guided atheris (Linux/macOS) | pending Phase 2 | — | — | — |

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

## Roadmap

Phase 2 (workstream 2.2) will add:
- Coverage-guided atheris run (≥ 1 000 000 iterations) on Linux CI.
- Corpus of structured edge cases: minimum-length ciphertext, max-length
  ciphertext (CAV-002 boundary), zero-tag, all-zero nonce.
- `cargo fuzz` harness for the Rust core (targeting `decrypt_bytes` equivalents).
