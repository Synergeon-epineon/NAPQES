# Constant-Time Attestation (dudect) — NAPQES v6 Rust Core

**Date:** pending (run before review kickoff)
**Tool:** [dudect](https://github.com/oreparaz/dudect) — constant-time behavioural testing
**Target:** `napqes::decrypt_bytes` in `rust/src/lib.rs`
**Trigger:** P1-3 switch from hand-rolled XOR-accumulate to `subtle::ConstantTimeEq`

---

## Status

`subtle = "2"` is now declared in `rust/Cargo.toml`. The tag comparison call at
`decrypt_bytes` (previously `constant_time_eq()`, lines 316–325 of the old lib.rs)
has been replaced with `recv_tag.ct_eq(calc_tag.as_ref()).unwrap_u8() == 0`.

The `subtle` crate guarantees constant-time comparison by:
1. Using `#[inline(never)]` and volatile reads to prevent LLVM DCE.
2. Implementing the `ConstantTimeEq` trait in a way that is audited and reviewed
   by the broader Rust cryptographic ecosystem (RustCrypto project).

---

## Dudect Run (to be completed before review kickoff)

To generate this attestation, run dudect on the Rust binary:

```bash
# Install dudect (requires CMake + gcc/clang)
git clone https://github.com/oreparaz/dudect /tmp/dudect
cd /tmp/dudect && cmake . && make

# Build a dudect harness wrapper for napqes::decrypt_bytes
# (see rust/benches/dudect_harness.rs once added in Phase 2)
```

Expected output format (fill in after running):
```
meas:  N M, max t = X.XXX, max tau = Y.YYY, (5/tau)^2 = ZZZZ
DUDECT_LEAKAGE_FOUND / DUDECT_NO_LEAKAGE_EVIDENCE_SO_FAR
```

**Threshold:** t < 4.5 (TVLA threshold, matching ROADMAP §5 NF-6).

---

## References

- `subtle` crate: https://docs.rs/subtle/latest/subtle/
- RustCrypto audit: https://github.com/RustCrypto/utils/tree/master/subtle
- TVLA methodology: NIST SP 800-90B, ISO/IEC 17825
- ROADMAP §4.1 F-8, §5 NF-6 (constant-time Rust core, Phase 2 workstream 2.2)
