# NIST SP 800-22 Rev 1a Attestation — NAPQES v8 Ciphertext Bitstream

**Date:** 2026-09-25 (supersedes the 2026-05-28 v6 run)
**Tool:** Custom Rust implementation — `rust/src/bin/sts.rs`
**Bitstream source:** `napqes::encrypt_bytes_v8` ciphertext output (raw bytes), key `STS_KEY` (10 elements) + pinned `STS_SK`, per-chunk AAD `be8(chunk_index)`
**Bits tested:** 50 000 000
**Elapsed:** 150 650 ms
**Commit:** 6db914e + working-tree changes of 2026-09-25
**Verdict:** **PASS — 40/40 scored tests passed, 0 failed, 0 skipped**

---

## Why the Rust implementation, not `nistrng`

`nistrng` 1.2.3 produces incorrect results (p ≈ 0.000 regardless of input quality, including
`os.urandom`) for at least seven of the fifteen SP 800-22 tests due to `int8` overflow in
internal accumulators under Python 3.13 and modern NumPy:

| Broken test in nistrng | Status here |
|---|---|
| Discrete Fourier Transform | Correctly implemented via in-place Cooley-Tukey FFT |
| Linear Complexity | Correctly implemented via Berlekamp-Massey |
| Serial | Correctly implemented via circular m-gram counting |
| Approximate Entropy | Correctly implemented |
| Non Overlapping Template Matching | Correctly implemented (148 aperiodic 9-bit templates, Bonferroni-corrected) |
| Maurer's Universal | Correctly implemented |
| Random Excursion / Variant | Correctly implemented (J ≥ 500 cycle eligibility enforced) |

All fifteen tests are implemented from scratch in safe Rust using only the standard library and
`f64` special functions (Lanczos log-gamma, regularised incomplete gamma via series and continued
fraction, erfc via complementary error function). No external math library is used.

---

## Full Results

| Test | p-value | Result |
|---|---|---|
| Monobit | 0.849476 | PASS |
| Frequency Within Block | 0.104701 | PASS |
| Runs | 0.279437 | PASS |
| Longest Run Ones In A Block | 0.877425 | PASS |
| Binary Matrix Rank | 0.932195 | PASS |
| Discrete Fourier Transform | 0.145724 | PASS |
| Non Overlapping Template Matching ¹ | 1.000000 | PASS |
| Maurer's Universal | 0.800849 | PASS |
| Linear Complexity | 0.937103 | PASS |
| Serial (del1) | 0.167920 | PASS |
| Serial (del2) | 0.369709 | PASS |
| Approximate Entropy | 0.154327 | PASS |
| Cumulative Sums (fwd) | 0.336417 | PASS |
| Cumulative Sums (bwd) | 0.468873 | PASS |
| Random Excursion (x=−4) | 0.485088 | PASS |
| Random Excursion (x=−3) | 0.500283 | PASS |
| Random Excursion (x=−2) | 0.635162 | PASS |
| Random Excursion (x=−1) | 0.016275 | PASS |
| Random Excursion (x=+1) | 0.109476 | PASS |
| Random Excursion (x=+2) | 0.925194 | PASS |
| Random Excursion (x=+3) | 0.968551 | PASS |
| Random Excursion (x=+4) | 0.434701 | PASS |
| Random Excursion Variant (x=−9) | 0.421338 | PASS |
| Random Excursion Variant (x=−8) | 0.411501 | PASS |
| Random Excursion Variant (x=−7) | 0.299578 | PASS |
| Random Excursion Variant (x=−6) | 0.364981 | PASS |
| Random Excursion Variant (x=−5) | 0.433068 | PASS |
| Random Excursion Variant (x=−4) | 0.456859 | PASS |
| Random Excursion Variant (x=−3) | 0.724734 | PASS |
| Random Excursion Variant (x=−2) | 0.909513 | PASS |
| Random Excursion Variant (x=−1) | 0.455689 | PASS |
| Random Excursion Variant (x=+1) | 0.285907 | PASS |
| Random Excursion Variant (x=+2) | 0.502889 | PASS |
| Random Excursion Variant (x=+3) | 0.492875 | PASS |
| Random Excursion Variant (x=+4) | 0.663802 | PASS |
| Random Excursion Variant (x=+5) | 0.983468 | PASS |
| Random Excursion Variant (x=+6) | 0.550739 | PASS |
| Random Excursion Variant (x=+7) | 0.231938 | PASS |
| Random Excursion Variant (x=+8) | 0.147086 | PASS |
| Random Excursion Variant (x=+9) | 0.164654 | PASS |

¹ Bonferroni-corrected composite p-value over 148 aperiodic 9-bit templates.

**Minimum p-value across all tests: 0.016275 (Random Excursion, x=−1)**, above the 0.01
threshold. With 40 sub-results at α = 0.01, about 0.4 false rejections are expected per run.

### Other runs of the same build (2026-09-25)

| Bits | Result | Note |
|---|---|---|
| 10 000 000 | 14/14 scored pass | Random Excursion / Variant ineligible (< 500 cycles) |
| 20 000 000 | 39/40 scored pass | Random Excursion (x=−1) p = 0.0078 — within the expected false-rejection rate |
| 50 000 000 | 40/40 scored pass | Reported above; committed as `sts_report.json` |

### Harness defect found and fixed

The first v8 runs encrypted every chunk under an empty AAD. The corpus offset
`(480·i) mod 95` repeats every 19 chunks and v8 is deterministic, so identical
ciphertexts recurred in the bitstream; at 2·10⁷ bits DFT, Serial and Approximate
Entropy failed with p ≈ 0. That is a property of the test input, not of the
keystream: a deterministic AEAD encrypting repeated `(A, M)` pairs must repeat its output.
Each chunk now carries AAD `be8(chunk_index)`, which makes every `(A, M)` pair distinct.

---

## Bitstream Construction

The bitstream is the concatenation of raw `encrypt_bytes_v8` output across independent
encrypt calls. Each call encrypts a 480-codepoint slice of printable ASCII (bucket B = 512,
82 288 bytes of ciphertext) under the fixed 10-element key `STS_KEY` and pinned `STS_SK`,
with AAD `be8(chunk_index)`:

- **Nonce bytes** (16 B per message): the synthetic nonce, an HMAC-SHA256 output.
- **Masked token blob**: fixed-width 8-byte tokens XOR-masked with the domain-0x07
  HMAC-CTR keystream.
- **HMAC-SHA256 auth tag** (32 B per message): PRF output.

The unmasked token blob is highly structured (tokens are about 2^44 at most, so the top
~20 bits of every 64-bit field are zero); the passing DFT and serial tests confirm the
keystream hides that structure.

---

## To Reproduce

```bash
cd rust
cargo run --release --bin sts -- --bits 50000000 --out ../sts_report.json
```

The machine-readable report is committed at [`sts_report.json`](../sts_report.json).

---

## References

- NIST SP 800-22 Rev 1a (2010): *A Statistical Test Suite for Random and Pseudorandom Number
  Generators for Cryptographic Applications*
- SPEC.md §3.7: varint keystream masking (domain byte 0x07)
- ROADMAP §3 workstream 1.3 (STS pipeline, Phase 1)
