# NIST SP 800-22 Rev 1a Attestation — NAPQES v6 Ciphertext Bitstream

**Date:** 2026-05-28
**Tool:** Custom Rust implementation — `rust/src/bin/sts.rs`
**Bitstream source:** `napqes::encrypt_bytes` ciphertext output (raw bytes), key `STS_KEY` (10-element, [1M, 15M] default range)
**Bits tested:** 10 000 000
**Elapsed:** 10 595 ms
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
| Monobit | 0.244795 | PASS |
| Frequency Within Block | 0.581273 | PASS |
| Runs | 0.157809 | PASS |
| Longest Run Ones In A Block | 0.856265 | PASS |
| Binary Matrix Rank | 0.101115 | PASS |
| Discrete Fourier Transform | 0.070624 | PASS |
| Non Overlapping Template Matching ¹ | 1.000000 | PASS |
| Maurer's Universal | 0.268581 | PASS |
| Linear Complexity | 0.937859 | PASS |
| Serial (del1) | 0.268556 | PASS |
| Serial (del2) | 0.359956 | PASS |
| Approximate Entropy | 0.242526 | PASS |
| Cumulative Sums (fwd) | 0.314951 | PASS |
| Cumulative Sums (bwd) | 0.268268 | PASS |
| Random Excursion (x=−4) | 0.502106 | PASS |
| Random Excursion (x=−3) | 0.517534 | PASS |
| Random Excursion (x=−2) | 0.860660 | PASS |
| Random Excursion (x=−1) | 0.906870 | PASS |
| Random Excursion (x=+1) | 0.610362 | PASS |
| Random Excursion (x=+2) | 0.692107 | PASS |
| Random Excursion (x=+3) | 0.244603 | PASS |
| Random Excursion (x=+4) | 0.623593 | PASS |
| Random Excursion Variant (x=−9) | 0.784316 | PASS |
| Random Excursion Variant (x=−8) | 0.690649 | PASS |
| Random Excursion Variant (x=−7) | 0.574740 | PASS |
| Random Excursion Variant (x=−6) | 0.435338 | PASS |
| Random Excursion Variant (x=−5) | 0.477060 | PASS |
| Random Excursion Variant (x=−4) | 0.577823 | PASS |
| Random Excursion Variant (x=−3) | 0.644373 | PASS |
| Random Excursion Variant (x=−2) | 0.583526 | PASS |
| Random Excursion Variant (x=−1) | 0.465764 | PASS |
| Random Excursion Variant (x=+1) | 0.449102 | PASS |
| Random Excursion Variant (x=+2) | 0.627906 | PASS |
| Random Excursion Variant (x=+3) | 0.502317 | PASS |
| Random Excursion Variant (x=+4) | 0.438320 | PASS |
| Random Excursion Variant (x=+5) | 0.526698 | PASS |
| Random Excursion Variant (x=+6) | 0.586735 | PASS |
| Random Excursion Variant (x=+7) | 0.606356 | PASS |
| Random Excursion Variant (x=+8) | 0.654354 | PASS |
| Random Excursion Variant (x=+9) | 0.676515 | PASS |

¹ Bonferroni-corrected composite p-value over 148 aperiodic 9-bit templates. Individual
template p-values were all well above the per-template threshold (0.01 / 148 ≈ 6.76 × 10⁻⁵).

**Minimum p-value across all tests: 0.070624 (DFT)** — 7× above the 0.01 threshold.
No test shows marginal or suspicious behaviour.

---

## Bitstream Construction

The bitstream is the concatenation of raw `encrypt_bytes` output across independent encrypt
calls. Each call encrypts a 480-byte slice of printable ASCII characters using a fixed
10-element production-range key (`STS_KEY`, elements in [1M, 15M]). The key is held constant
so the bitstream exercises the full ciphertext surface under a single key:

- **Nonce bytes** (16 B per message): drawn from the CSPRNG — uniformly random.
- **Masked varint blob**: LEB128-encoded tokens XOR-masked with the domain-0x07 HMAC-CTR
  keystream. The masking eliminates the 3:1 MSB continuation-bit bias present in raw varints;
  the STS results confirm the mask is effective.
- **HMAC-SHA256 auth tag** (32 B per message): PRF output — expected to be indistinguishable
  from uniform.

The DFT test (p = 0.070) is the most sensitive probe for periodic structure in the bit
stream. Its passage confirms that the domain-0x07 keystream masking successfully eliminates
the LEB128 structural periodicity documented in SPEC.md §3.7.

---

## To Reproduce

```bash
cd rust
cargo run --release --bin sts -- --bits 10000000 --out ../sts_report.json
```

The machine-readable report is committed at [`sts_report.json`](../sts_report.json).

---

## References

- NIST SP 800-22 Rev 1a (2010): *A Statistical Test Suite for Random and Pseudorandom Number
  Generators for Cryptographic Applications*
- SPEC.md §3.7: varint keystream masking (domain byte 0x07)
- ROADMAP §3 workstream 1.3 (STS pipeline, Phase 1)
