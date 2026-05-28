# NAPQES CAVP Algorithm Validation Evidence

**Version:** 0.1  
**Date:** 2026-05-28  
**Status:** DRAFT — pending CMVP lab review  
**References:** NIST CAVP (https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program),
[`docs/PRIMITIVES_ATTESTATION.md`](../PRIMITIVES_ATTESTATION.md),
[`docs/fips/SECURITY_POLICY.md`](SECURITY_POLICY.md)

---

## 1. Overview

FIPS 140-3 (ISO/IEC 19790:2012, SP 800-140) requires that every approved
security function used by a cryptographic module be validated through the
NIST Cryptographic Algorithm Validation Program (CAVP) or obtained from a
CAVP-validated provider.

The NAPQES Cryptographic Module uses **HMAC-SHA256** and **SHA-256** as its
sole approved security functions. These algorithms are provided by the `hmac`
and `sha2` Rust crates, which are pure-Rust implementations of the NIST
standards.

---

## 2. CAVP Strategy

**Strategy: Validated-provider chain.**

The NAPQES module does not seek independent CAVP certificates for its Rust
implementations of HMAC-SHA256 and SHA-256. Instead, the module is designed
to support deployment in environments where the HMAC-SHA256 and SHA-256
operations are ultimately executed by a CAVP-validated provider:

| Deployment environment | HMAC-SHA256 / SHA-256 provider | CAVP status |
|---|---|---|
| Windows (FIPS mode) | Windows CNG (`BCryptHashData`) | CAVP-validated (see §3.1) |
| Linux (FIPS mode, e.g. RHEL) | OpenSSL 3.x FIPS provider | CAVP-validated (see §3.2) |
| macOS | Apple CoreCrypto | FIPS 140-3 validated (see §3.3) |
| Generic Linux / embedded | `sha2` + `hmac` Rust crates (pure Rust) | Not CAVP-validated (see §4) |

**Implication:** For FIPS 140-3 validation, the NAPQES module MUST be
submitted as a module that delegates HMAC-SHA256 to a CAVP-validated
provider. The pure-Rust `sha2` + `hmac` crates MUST be replaced (or
conditionally compiled to call) the OS-validated provider.

This is a Phase 4 implementation item (workstream 4.1). The current
pre-attestation phase documents the required provider chain.

---

## 3. CAVP-Validated Provider References

### 3.1 Windows CNG

Windows Cryptography Next Generation (CNG) algorithm provider implements
HMAC-SHA256 and SHA-256 as CAVP-validated algorithms.

| Property | Value |
|---|---|
| Provider | Microsoft Windows CNG |
| Algorithm | SHA-2 family (SHA-256), HMAC-SHA-256 |
| Standard | FIPS 180-4 (SHA-256), FIPS 198-1 (HMAC) |
| CAVP program | Hash algorithms, MAC algorithms |
| Windows version | Windows 10 and later, Windows Server 2016 and later |
| How to obtain certificates | Search NIST CAVP at https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=12 |

To use Windows CNG from Rust: link against `ring` crate with CNG backend,
or use the `windows` crate to call `BCryptHashData` / `BCryptCreateHash` directly.

### 3.2 OpenSSL 3.x FIPS Provider (Linux)

OpenSSL 3.0+ includes a FIPS provider module (`fips.so`) that is CAVP-validated
and can be activated in FIPS mode.

| Property | Value |
|---|---|
| Provider | OpenSSL 3.x FIPS provider (`fips.so`) |
| Algorithm | SHA-2 family, HMAC |
| Standard | FIPS 180-4, FIPS 198-1 |
| CAVP Certificate | OpenSSL 3.0 FIPS: CMVP #4282 (example; check NIST CMVP for current) |
| Rust integration | `openssl` crate with `vendored` feature; or system OpenSSL in FIPS mode |

### 3.3 Apple CoreCrypto (macOS / iOS)

Apple CoreCrypto is an Apple-provided cryptographic library that is FIPS 140-3
validated across Apple platforms.

| Property | Value |
|---|---|
| Provider | Apple CoreCrypto |
| Algorithm | SHA-2 family, HMAC |
| Standard | FIPS 180-4, FIPS 198-1 |
| CMVP Certificate | Apple CoreCrypto CMVP #3856 (check NIST CMVP for current) |
| Rust integration | Not directly accessible via stable Rust API; typically accessed via Apple Security framework |

---

## 4. Current Rust Crate Status (Non-CAVP)

The current NAPQES Rust implementation uses:

| Crate | Version | Checksum (Cargo.lock) | CAVP status |
|---|---|---|---|
| `sha2` | 0.10.9 | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` | Not CAVP-validated |
| `hmac` | 0.12.1 | `6c49c37c09c17a53d937dfbb742eb3a961d65a994e6bcdcf37e7399d0cc8ab5e` | Not CAVP-validated |
| `digest` | 0.10.7 | `9ed9a281f7bc9b7576e61468ba615a66a5c8cfdff42420a70aa82701a3b1e292` | Not CAVP-validated |

These crates implement correct FIPS 198-1 / FIPS 180-4 algorithms but do not
hold CAVP certificates. Their use constitutes an "unvalidated implementation"
in FIPS 140-3 terms.

**For pre-attestation documentation purposes:** NAPQES's use of `sha2` and
`hmac` crates can be described as implementing FIPS-approved algorithms in
an unvalidated software implementation. The module's security posture statement
(PRIMITIVES_ATTESTATION.md §3) explicitly states it is not FIPS 140-3 validated.

**For CMVP submission:** The `sha2` / `hmac` crates MUST be replaced or
wrapped with calls to a CAVP-validated provider. Two implementation paths:

1. **Conditional compilation:** Feature-gate the algorithm implementations
   so that FIPS builds call the OS provider (CNG / OpenSSL FIPS).
2. **Ring crate:** The `ring` crate uses BoringSSL's FIPS-mode implementations
   on supported platforms, providing CAVP-compatible HMAC-SHA256 and SHA-256.

---

## 5. NAPQES AEAD — Not Submitted to CAVP

The NAPQES AEAD construction (the combination of the token cipher, noise
injection, padding, and HMAC-SHA256 tag) is **not a NIST-approved algorithm**
and has not been submitted to CAVP. CAVP only covers NIST-standardised
algorithms.

This is documented in `docs/SECURITY_TARGET.md §6.2` and
`docs/PRIMITIVES_ATTESTATION.md §3`.

**Implication for CMVP:** NAPQES AEAD will be listed as a non-approved
security function in the CMVP Security Policy. The approved security
functions are HMAC-SHA256 and SHA-256, used within the non-approved AEAD
construction.

For customers requiring a FIPS 140-3 validated AEAD: use AES-256-GCM from
a validated module for the primary AEAD layer and treat NAPQES as an
additional confidentiality layer on top.

---

## 6. Algorithm Self-Test (KAT) Evidence

Per SP 800-140B §4.9.1, the module must perform a known-answer test for
each approved security function at power-on. KAT vectors for HMAC-SHA256
(as used in NAPQES derivation functions and authentication) are included in
the module's power-on self-test (`rust/src/self_test.rs`).

KAT source vectors: `tests/kat/v6_vectors.json` (V002: key = [1000003, 1000033,
1000037, 1000039], message = "A", nonce = 9c6c0b921a83849cdbf2fe7efb743fe9).

The KAT exercises `encrypt_bytes_with_nonce` → `decrypt_bytes` → tamper-reject
cycle, which internally exercises HMAC-SHA256 in all 8 domain roles.

---

## 7. Phase 4 Roadmap — CAVP Submission Items

| Item | Action | Owner |
|---|---|---|
| Replace `sha2` / `hmac` with OS-validated provider | Implement CNG / OpenSSL FIPS backend | Engineering |
| Submit HMAC-SHA256 to CAVP (if not using provider) | Engage NVLAP-accredited test lab | Compliance |
| Submit SHA-256 to CAVP (if not using provider) | Same lab | Compliance |
| CRNG test — submit DRBG health-test evidence | Document DRBG health test | Engineering |
| KAT vectors — confirm alignment with CAVP | Cross-reference v6_vectors.json with HMAC test vectors | Engineering |

---

## 8. Sign-Off Checklist

- [ ] Review by compliance counsel (Phase 4 pre-submission)
- [ ] Confirm CAVP-validated provider is available for each target platform
- [ ] Add specific CAVP certificate numbers for Windows CNG and Apple CoreCrypto
- [ ] Confirm `ring` crate FIPS mode eligibility for Rust CMVP submission
- [ ] Update this document after provider integration is complete
