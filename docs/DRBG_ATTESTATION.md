# NAPQES DRBG & Entropy Source Attestation

**Version:** 0.1  
**Date:** 2026-05-28  
**Status:** DRAFT — pending compliance counsel sign-off  
**References:** NIST SP 800-90A Rev 1, NIST SP 800-90B, NIST SP 800-90C (draft),
[`docs/PRIMITIVES_ATTESTATION.md`](PRIMITIVES_ATTESTATION.md),
[`docs/fips/SECURITY_POLICY.md`](fips/SECURITY_POLICY.md)

> **Scope.** This document maps every source of randomness in the NAPQES
> Cryptographic Module to the applicable NIST standard and documents the
> dependency chain from the module's randomness calls to the OS-provided
> entropy source. It extends `PRIMITIVES_ATTESTATION.md §1.3`.

---

## 1. Randomness Usage Points

The NAPQES Cryptographic Module has two randomness consumption points:

| Call site | Function | Purpose | Bits consumed per call |
|---|---|---|---|
| `encrypt_bytes` | Nonce generation via `rand::thread_rng().fill_bytes(&mut nonce)` | 128-bit random nonce per encryption | 128 |
| `generate_prime_numbers` | Prime candidate selection via `rng.next_u64()` | Uniform random candidate from `[min_val, max_val]` per prime attempt | 64 (expected ~5–10 per prime) |

The `encrypt_bytes_with_nonce` function accepts a caller-supplied nonce and
does **not** consume the DRBG. It is intended for deterministic KAT use only
and MUST NOT be used in production.

---

## 2. DRBG Dependency Chain

The module uses the `rand = "0.8"` Rust crate, which delegates to
`rand_core = "0.6"`, which delegates to `getrandom = "0.2"`.

`getrandom` maps each platform's call to the OS-provided DRBG:

```
NAPQES module
  └── rand::thread_rng() [rand 0.8.6]
        └── OsRng / getrandom [getrandom 0.2.17]
              ├── Linux ≥ 3.17   : getrandom(2) syscall → CSPRNG (ChaCha20-based DRBG)
              ├── Linux < 3.17   : /dev/urandom read (fallback)
              ├── Windows ≥ Vista: BCryptGenRandom (Windows CNG)
              ├── macOS ≥ 10.12  : getentropy(2)
              └── WASI           : random_get
```

---

## 3. Platform-Specific DRBG Analysis

### 3.1 Linux — `getrandom(2)` syscall

The Linux kernel CSPRNG is seeded from multiple entropy sources (hardware
interrupts, CPU timing jitter, RDRAND/RDSEED if available) and implemented
as a ChaCha20-based DRBG (merged in Linux 5.17, backported). It satisfies
NIST SP 800-90B entropy requirements when the system has sufficient
initial entropy.

| Property | Value |
|---|---|
| Algorithm | ChaCha20-based DRBG (Linux 5.17+) |
| Standard | SP 800-90B (entropy source) |
| Block until seeded | Yes (getrandom blocks until /dev/urandom is initialised) |
| Reseed | Automatic, continuous |
| Validation status | No CAVP certificate (OS-provided, not a FIPS module) |

**FIPS-mode Linux:** On RHEL/CentOS/Ubuntu with FIPS mode enabled (`fips=1`
kernel parameter), the kernel CSPRNG is replaced by an SP 800-90A CTR_DRBG
that is NIST-validated. Modules deployed on FIPS-mode Linux therefore use
a CAVP-validated DRBG automatically.

### 3.2 Windows — `BCryptGenRandom` (CNG)

Windows CNG provides `BCryptGenRandom` backed by the CNG DRBG, which is
an SP 800-90A CTR_DRBG. The CNG DRBG is CAVP-validated under Windows CNG
algorithm provider certificates.

| Property | Value |
|---|---|
| Algorithm | SP 800-90A CTR_DRBG |
| Standard | SP 800-90A Rev 1 |
| Validation status | CAVP-validated (Windows CNG algorithm provider) |
| CAVP Certificate | Varies by Windows version; see NIST CAVP database for current CNG certs |

### 3.3 macOS — `getentropy(2)`

macOS `getentropy` is backed by the Apple CoreCrypto DRBG, which is an
SP 800-90A AES-256 CTR_DRBG. Apple CoreCrypto is FIPS 140-2/140-3 validated.

| Property | Value |
|---|---|
| Algorithm | SP 800-90A CTR_DRBG (AES-256) |
| Standard | SP 800-90A Rev 1 |
| Validation status | FIPS 140-3 validated (Apple CoreCrypto, CMVP certificate #3856 and successors) |

---

## 4. Entropy Adequacy Analysis

### 4.1 Nonce entropy

Each NAPQES nonce is 128 bits drawn from the OS DRBG. Under standard
SP 800-90A assumptions, the DRBG output is computationally indistinguishable
from uniform random bits. The 128-bit nonce provides:

- ≥ 128 bits of entropy per nonce.
- Probability of nonce collision across up to 2^64 encryptions: < 2^-64
  (birthday bound with 128-bit nonce space).

The CRNG conditional self-test (see `docs/fips/SECURITY_POLICY.md §8.2`)
detects catastrophic DRBG failures by verifying successive nonces differ.

### 4.2 Key entropy

For a K = 10 element key over [1 000 000, 15 000 000], the key space is
C(1 120 066, 10) × 10! permutations ≈ 2^196.6 bits. The prime-selection
loop draws candidates from the OS DRBG until K distinct primes are found.
The quality of the key entropy is bounded by the quality of the OS DRBG.

---

## 5. Embedded Targets (Gap)

For embedded deployments (Cortex-M, RISC-V RV32), the OS DRBG is not
available. The module currently assumes an OS-provided entropy source. Before
deploying on embedded targets:

1. Identify the available hardware entropy source (TRNG peripheral, CPU jitter).
2. Implement an SP 800-90B-compliant entropy source driver.
3. Implement an SP 800-90A CTR_DRBG seeded from the entropy source.
4. Replace `rand::thread_rng()` calls with the embedded DRBG API.
5. Document the specific DRBG and entropy source for each embedded target
   in a platform-specific addendum to this document.

This is a roadmap item (Phase 3 workstream 3.3 / Phase 4 workstream 4.2).

---

## 6. DRBG Self-Test Requirements

Per FIPS 140-3 (SP 800-140B §4.9.2), the module is required to perform:

1. **Health tests on the entropy source** (at start-up and on-demand).
2. **DRBG health tests** (known-answer test on the DRBG output).

For the software module, the DRBG is OS-provided. The module's CRNG
conditional self-test (successive-nonce comparison) provides the minimum
required evidence of DRBG health. Full SP 800-90B health testing is
delegated to the OS.

A note for the CMT lab: if the OS DRBG is not CAVP-validated (e.g., on
Linux without FIPS mode), the NAPQES module should be documented as operating
in a "non-FIPS operational environment" for nonce and key generation. In this
mode the module uses a non-validated entropy source; modules deployed on
FIPS-mode Windows or macOS use a validated DRBG automatically.

---

## 7. Sign-Off Checklist

- [ ] Review by compliance counsel (target: Phase 3 completion)
- [ ] Confirm OS entropy source classification for each supported platform
- [ ] Add CAVP certificate references for Windows CNG and Apple CoreCrypto
- [ ] Define embedded-target entropy source requirements (Phase 4)
- [ ] Confirm FIPS-mode Linux DRBG substitution is transparent to the module
- [ ] Verify `getrandom` crate version aligns with current DRBG sources
      (getrandom 0.2.17 as of 2026-05-28)
