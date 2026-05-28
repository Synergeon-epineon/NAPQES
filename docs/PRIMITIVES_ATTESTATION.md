# NAPQES Approved-Primitives Pre-Attestation

**Version:** 0.2
**Date:** 2026-05-28  
**Status:** Pre-attestation (pending compliance counsel sign-off — see §5 checklist)  
**References:** FIPS 198-1, FIPS 180-4, NIST SP 800-90B, [`SPEC.md`](../SPEC.md),
[`docs/SECURITY_TARGET.md`](SECURITY_TARGET.md),
[`docs/fips/SECURITY_POLICY.md`](fips/SECURITY_POLICY.md),
[`docs/DRBG_ATTESTATION.md`](DRBG_ATTESTATION.md)

> **Scope.** This document enumerates every cryptographic call site in the
> NAPQES Python reference (`napqes.py`) and maps each to the applicable NIST
> standard. It supports a pre-attestation claim that NAPQES uses only
> FIPS-approved sub-primitives in approved modes, **without** asserting that
> the NAPQES module as a whole is FIPS 140-3 validated.
>
> **Non-claim.** NAPQES is NOT FIPS 140-3 validated. This memo documents the
> building blocks only. Full module validation is targeted for Phase 4
> (ROADMAP §6 workstreams 4.1–4.2).

---

## 1. Cryptographic Primitive Inventory

### 1.1 HMAC-SHA256

| Property | Value |
|---|---|
| Standard | FIPS 198-1 (HMAC), FIPS 180-4 (SHA-256) |
| Python module | `import hmac; import hashlib` (Python standard library) |
| Key material | `key_bytes` = concatenation of key elements, each serialised as 5 big-endian bytes |
| MAC output | 32 bytes (256 bits) |
| Usage | Six keyed derivation functions (domain-separated) + authentication tag |

**Call sites (all in `napqes.py`):**

| Domain byte | Function | Approximate line | Purpose | FIPS reference |
|---|---|---|---|---|
| `0x02` | `_derive_noise_p` | L155–165 | Derive per-message noise probability ∈ [0.75, 0.99] | FIPS 198-1 §5 |
| `0x00` | `_is_noise_pos` | L103–113 | Oracle: is ciphertext slot a noise position? | FIPS 198-1 §5 |
| `0x01` | `_derive_addend` | L115–126 | Per-real-token addend ∈ [1, key_element − 1] | FIPS 198-1 §5 |
| `0x04` | `_derive_noise_char` | L128–138 | Noise character codepoint ∈ [32, 127] | FIPS 198-1 §5 |
| `0x05` | `_derive_noise_token_addend` | L140–151 | Per-noise-token addend ∈ [1, key_element − 1] | FIPS 198-1 §5 |
| `0x06` | `_pad_message` | L209–227 | Deterministic padding byte ∈ [32, 126] | FIPS 198-1 §5 |
| `0x03` | `_compute_auth_tag` | L167–174 | AEAD authentication tag | FIPS 198-1 §5 |

**Key length.** For a K-element key where each element is a 7-digit decimal
prime (≤ 24 bits), `key_bytes` is 5K bytes. For the default K = 10,
`key_bytes` = 50 bytes (400 bits). FIPS 198-1 §3 requires the key to be at
least as long as the hash output (256 bits); this requirement is satisfied
for K ≥ 7 (35 bytes > 32 bytes).

**Mode.** HMAC is used in standard PRF mode with a fresh 16-byte nonce
embedded in each message that is bound into all per-message derivations.
HMAC is not used in CMAC or CBC-MAC mode.

### 1.2 SHA-256 (as HMAC inner/outer compression function)

SHA-256 is used exclusively as the hash function inside `hmac.new(..., hashlib.sha256)`. It is not invoked directly. Standard: FIPS 180-4.

### 1.3 Random number generation

| Site | Function | Module | Standard | Purpose |
|---|---|---|---|---|
| Nonce generation | `secrets.token_bytes(16)` | `secrets` (Python ≥ 3.6) | SP 800-90B (entropy source) | 16-byte cryptographically random nonce per encryption call |
| Key generation (if using `generate_prime_numbers`) | `secrets.randbelow(...)` | `secrets` | SP 800-90B | Uniform random selection from prime candidates |

`secrets` uses the operating system CSPRNG (`os.urandom` on POSIX,
`BCryptGenRandom` on Windows). Both sources are SP 800-90B compliant
entropy sources when the OS passes its own entropy self-test.

---

## 2. Primitives NOT Used

The following primitives are **absent** from the NAPQES v6 reference
implementation. This is stated to prevent incorrect assumptions:

| Primitive | Status | Note |
|---|---|---|
| AES (any mode) | **Not used** | By design; NAPQES targets non-AES-hardware environments |
| ECDH / X25519 | **Not used** | Key exchange is out of scope |
| RSA | **Not used** | — |
| Poly1305 / ChaCha20 | **Not used** | — |
| MD5 / SHA-1 | **Not used** | — |
| Bcrypt / Argon2 / scrypt | **Not used** | — |
| ML-KEM / ML-DSA / SLH-DSA | **Not used** (planned) | Hybrid KEM integration is `[roadmap]` Phase 4 |

---

## 3. FIPS Posture Statement

The following statement may be used in customer-facing materials and
procurement responses, subject to counsel sign-off:

> NAPQES v6 uses FIPS-approved cryptographic sub-primitives: HMAC-SHA256
> (FIPS 198-1 / FIPS 180-4) for all keyed derivations and authentication,
> and an OS-provided entropy source conforming to NIST SP 800-90B for nonce
> and key generation.
>
> **The NAPQES module itself is not FIPS 140-3 validated.** FIPS 140-3
> module validation is targeted for Phase 4 of the product roadmap. Until a
> CMVP certificate is awarded, customers with a formal FIPS 140-3 requirement
> (e.g. CMMC Level 2+, FISMA High, FedRAMP Moderate/High) should use a
> validated cryptographic module for the symmetric AEAD layer and treat
> NAPQES as a supplementary layer.

---

## 4. Cross-Reference to BRD §6

| BRD §6 item | This document location |
|---|---|
| "NAPQES is not a NIST-standardised cipher" | §3 FIPS Posture Statement |
| "NAPQES is not a post-quantum KEM or signature" | §2 Primitives NOT Used |
| "External cryptanalysis is pending" | `SECURITY_TARGET.md` §9 |
| "Prototype is pure-Python" | §1.3 (entropy) and `SECURITY_TARGET.md` §6.1 |
| "Padding leaks a power-of-two bucket" | `SPEC.md` §6, `CAVEATS.md` CAV-003 |
| "Streaming API releases plaintext before tag verification" | `CAVEATS.md` CAV-001, `SECURITY_TARGET.md` §4 |

---

## 5. Sign-off Checklist

- [ ] Review by compliance counsel (target: Phase 3)
- [x] Confirm OS entropy source classification for each supported platform
      — documented in [`docs/DRBG_ATTESTATION.md`](DRBG_ATTESTATION.md)
- [x] Confirm FIPS 198-1 key-length requirement is met for minimum key size
      (K ≥ 7 required; default K = 10 — currently acceptable)
- [x] Document key-derivation path if customers use a KDF to generate
      the prime-key list — documented in [`docs/fips/KEY_MANAGEMENT.md`](fips/KEY_MANAGEMENT.md) §4
- [x] Add platform-specific notes for embedded targets (Cortex-M, RV32)
      — documented as gap in [`docs/DRBG_ATTESTATION.md`](DRBG_ATTESTATION.md) §5
