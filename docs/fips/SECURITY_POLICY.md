# NAPQES Non-Proprietary Security Policy

**Module name:** NAPQES Cryptographic Module  
**Module version:** 0.1 (Rust core, `napqes` crate v0.1.0)  
**FIPS 140-3 security level:** Level 1 (software)  
**Date:** 2026-05-28  
**Status:** DRAFT — pending CMVP lab review

---

## 1. Module Overview

The NAPQES Cryptographic Module is a software library implementing a symmetric
Authenticated Encryption with Associated Data (AEAD) scheme. All cryptographic
operations — token derivation, noise injection, deterministic padding, and
authentication — use HMAC-SHA256 (FIPS 198-1 / FIPS 180-4) as the sole primitive.

The module provides:

- Authenticated encryption and decryption of short-to-medium messages.
- HMAC-SHA256-derived key-stream masking of the token blob.
- A 256-bit authentication tag that binds ciphertext to optional Associated Data (AAD).

The module is intended for use in environments where pre-shared symmetric keys
are already established and message confidentiality, integrity, and authenticity
are required.

---

## 2. Module Boundary

**Module type:** Software module (dynamically linked library)

**Boundary:** The compiled Rust library object `libnapqes.so` (Linux),
`napqes.dll` (Windows), or `libnapqes.dylib` (macOS), produced from
`rust/src/lib.rs`. The module boundary is the public API surface defined by
the library's exported symbols.

**Inside the boundary:**

| Function | Purpose |
|---|---|
| `encrypt_bytes` | Authenticated encryption (random nonce) |
| `encrypt_bytes_with_nonce` | Authenticated encryption (caller-supplied nonce; test use only) |
| `decrypt_bytes` | Authenticated decryption |
| `encrypt_str` | Authenticated encryption, base64 output |
| `decrypt_str` | Authenticated decryption, base64 input |
| `generate_prime_numbers` | Key generation (uses OS DRBG) |
| `is_prime` | Deterministic primality test |
| `zeroize_key` | Secure erasure of key material |
| `run_power_on_self_tests` | Power-on known-answer tests |
| Internal HMAC helpers | `hmac_digest`, `key_bytes`, domain derivation functions |
| Self-test engine | `self_test::run_power_on_self_tests`, integrity check |

**Outside the boundary:**

- Key transport / key agreement protocols.
- Entity authentication / digital signatures.
- Network transport (TLS, QUIC).
- Application logic, session management.
- The operating system's DRBG / entropy source (consumed via `rand::thread_rng`, which delegates to the OS).

See [MODULE_BOUNDARY.md](MODULE_BOUNDARY.md) for a detailed boundary diagram and
description.

---

## 3. Approved Security Functions

| Function | Standard | Mode | Status |
|---|---|---|---|
| HMAC-SHA256 | FIPS 198-1, FIPS 180-4 | PRF (keyed derivation + authentication tag) | Approved |
| SHA-256 | FIPS 180-4 | Used exclusively inside HMAC | Approved (via HMAC) |
| DRBG (OS-provided) | SP 800-90A (platform-dependent) | Random nonce and key-element generation | Approved (see §6) |

### Non-Approved Functions

| Function | Status | Note |
|---|---|---|
| NAPQES AEAD construction | Non-approved algorithm | Built from FIPS-approved sub-primitives; the AEAD mode itself is not NIST-standardised |
| Prime generation (`is_prime`) | Non-security function | Deterministic computation; not a cryptographic primitive |

The NAPQES module uses FIPS-approved sub-primitives in approved modes. The
AEAD construction built on top of these primitives has not been standardised
by NIST. This is documented in `docs/PRIMITIVES_ATTESTATION.md` §3.

---

## 4. Roles and Services

The module supports two roles:

### 4.1 Crypto Officer (CO)

The Crypto Officer is responsible for:
- Generating key material via `generate_prime_numbers`.
- Securely distributing keys to Users.
- Invoking `run_power_on_self_tests` and verifying that self-tests pass before
  deploying the module in production.
- Zeroizing key material via `zeroize_key` when the key is no longer needed.
- Monitoring for error outputs from the module (authentication failures, self-test
  failures) and taking corrective action.

### 4.2 User

The User is an application that calls `encrypt_bytes` / `decrypt_bytes`
(or the string variants) with a pre-established key to encrypt or decrypt
messages. The User does not generate or manage key material directly.

### Service table

| Service | Role | Description |
|---|---|---|
| Encrypt | User | Encrypt a plaintext with authentication |
| Decrypt | User | Decrypt and verify an authenticated ciphertext |
| Key generation | CO | Generate a prime-tuple key |
| Key zeroization | CO | Securely erase key material |
| Power-on self-test | CO | Run KATs and integrity check |

---

## 5. Physical Security

This is a software module at Level 1. No physical security requirements apply.
The operational environment security (OS isolation, process memory protection)
is the responsibility of the deploying organisation.

---

## 6. Entropy and Random Number Generation

The module uses the operating system's cryptographically secure random number
generator for:
- Generating the 128-bit nonce per encryption call (`encrypt_bytes`).
- Generating key elements via `generate_prime_numbers`.

Platform-specific DRBG sources:

| Platform | Entropy source | SP 800-90A/B status |
|---|---|---|
| Linux ≥ 3.17 | `getrandom()` | SP 800-90B compliant when seeded from `/dev/urandom` |
| Windows ≥ Vista | `BCryptGenRandom` | SP 800-90A CTR_DRBG (CNG, CAVP-validated) |
| macOS ≥ 10.12 | `getentropy()` | SP 800-90B compliant |

The `rand::thread_rng()` Rust API delegates to `getrandom`, which maps to the
above sources. See [DRBG_ATTESTATION.md](../DRBG_ATTESTATION.md) for the full
entropy source documentation.

---

## 7. Key Management

Full key management policy is documented in [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md).
Summary:

- **Key type:** Ordered tuple of K distinct prime integers in [1 000 000, 15 000 000].
- **Key serialisation:** `key_bytes = be5(key[0]) || ... || be5(key[K-1])`, K × 5 bytes.
- **Minimum key length:** K = 7 (35 bytes, 280 bits > FIPS 198-1 §3 minimum of 256 bits).
- **Recommended key:** K = 10 (50 bytes, 400 bits), ≈2^197.67 key space.
- **Key generation:** CSPRNG via `generate_prime_numbers`; caller may also supply externally generated primes.
- **Key entry/output:** In-memory only; the module provides no key serialisation or wrapping service.
- **Key zeroization:** Call `zeroize_key(&mut key)` when the key is no longer needed. Uses `ptr::write_volatile` to prevent compiler elision.
- **Key storage:** The module does not store keys. Persistence is the caller's responsibility.

---

## 8. Self-Tests

### 8.1 Power-On Self-Tests (POST)

The function `run_power_on_self_tests()` MUST be called by the CO before
production use. It executes:

1. **KAT — encrypt:** Encrypt a fixed plaintext with a fixed key and nonce;
   compare to a known reference ciphertext.
2. **KAT — decrypt:** Decrypt the known ciphertext; compare to the original
   plaintext.
3. **KAT — authentication failure:** Attempt to decrypt a tampered ciphertext
   (one tag byte flipped); verify that authentication fails.
4. **Software integrity test:** Compute HMAC-SHA256 over the module's text and
   data sections and compare to a reference digest embedded at compile time.

The function returns `Ok(())` on all-pass. On any failure it returns
`Err(SelfTestError)`. The CO must halt or refuse to encrypt/decrypt if
`run_power_on_self_tests()` returns an error.

KAT vectors are derived from `tests/kat/v6_vectors.json` (V001, V002, N001).

### 8.2 Conditional Self-Tests

**Continuous RNG test (CRNG):** Before each encryption call, the module
verifies that the generated 128-bit nonce differs from the previous nonce.
A repeated nonce causes the encryption to fail with an error. This protects
against catastrophic DRBG failure modes.

---

## 9. Mitigation of Other Attacks

### 9.1 Timing side-channels

The authentication tag comparison in `decrypt_bytes` is performed by
`ct_eq_bytes`, a constant-time function verified by empirical TVLA:

- `|max t| = 1.13` at n = 12.712 M measurements (threshold: 4.5).
- Assembly confirmed branchless: 32 load-XOR-accumulate-store triples, no
  data-dependent branches.

See [DUDECT_ATTESTATION.md](../DUDECT_ATTESTATION.md) for the full run history.

The noise-position oracle (`is_noise_pos`) and other HMAC derivation functions
are **not** claimed constant-time. Constant-time guarantees for the full
decrypt path are a roadmap item (Phase 2, workstream 2.2).

### 9.2 Side-channels not mitigated

Power analysis, electromagnetic analysis, and acoustic side-channels are out
of scope for Level 1 software module validation. Callers requiring physical
side-channel resistance must use a hardware security module (HSM).

---

## 10. Non-Claims

The following are **not** claimed by this module:

- FIPS 140-3 validated status (this document describes the module *preparing*
  for CMVP submission, not a validated module).
- NIST-standardised AEAD algorithm (see `SECURITY_TARGET.md §6.2`).
- Post-quantum key encapsulation or digital signatures.
- Resistance to all timing side-channels in the full decrypt path.
- Key agreement or key transport.

---

## 11. References

| Document | Location |
|---|---|
| Wire format specification | `SPEC.md` |
| Security target and adversary model | `docs/SECURITY_TARGET.md` |
| FIPS primitive mapping | `docs/PRIMITIVES_ATTESTATION.md` |
| Module boundary | `docs/fips/MODULE_BOUNDARY.md` |
| Key management | `docs/fips/KEY_MANAGEMENT.md` |
| DRBG & entropy | `docs/DRBG_ATTESTATION.md` |
| CAVP evidence | `docs/fips/CAVP_EVIDENCE.md` |
| Known caveats | `docs/CAVEATS.md` |
| Constant-time attestation | `docs/DUDECT_ATTESTATION.md` |
| Fuzz attestation | `docs/FUZZ_ATTESTATION.md` |
| FIPS 198-1 (HMAC) | https://csrc.nist.gov/publications/detail/fips/198/1/final |
| FIPS 180-4 (SHA) | https://csrc.nist.gov/publications/detail/fips/180/4/final |
| SP 800-90A (DRBG) | https://csrc.nist.gov/publications/detail/sp/800/90/a/rev-1/final |
| SP 800-90B (Entropy) | https://csrc.nist.gov/publications/detail/sp/800/90/b/final |
| ISO/IEC 19790:2012 | FIPS 140-3 base standard |
