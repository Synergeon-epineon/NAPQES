# NAPSEQ Security Target — Adversary Model & Claim Boundaries

**Version:** 0.1 (Draft — pending informal cryptographer review)
**Date:** 2026-05-12
**Wire format:** v6 (frozen — see [`SPEC.md`](../SPEC.md))
**Status:** `[DRAFT — not yet reviewed by external cryptographer]`
**Reference:** [`docs/business/BRD.md`](business/BRD.md) §6 (Honest Constraints & Disclaimers)

> This document describes what NAPSEQ v6 is intended to achieve, what it
> explicitly does not claim, and the conditions under which the security
> goals are expected to hold. Every claim in this document must be
> reachable from `napqes.py` line ranges or from `[roadmap]` markers; see
> [`docs/business/README.md`](business/README.md) for the tagging convention.

---

## 1. System Summary

NAPSEQ v6 is a symmetric authenticated encryption scheme with associated
data (AEAD). It is built exclusively from HMAC-SHA256 and is intended for
environments where:
- Symmetric key material is pre-shared (NAPSEQ does not provide key
  establishment).
- Message confidentiality, integrity, and authenticity are required.
- Ciphertext length leakage limited to a power-of-two bucket (see §6.3) is
  acceptable.

The reference implementation is `napqes.py`. Conforming ports must pass the
Known-Answer Tests in [`tests/kat/v6_vectors.json`](../tests/kat/v6_vectors.json).

---

## 2. Adversary Model

### 2.1 Threat classes addressed

| Threat | Addressed | Mechanism |
|---|---|---|
| Passive eavesdropper | Yes | Ciphertext confidentiality via token layer + noise tokens |
| Active attacker: ciphertext modification | Yes | HMAC-SHA256 auth tag verified before plaintext release (block API) |
| Active attacker: AAD substitution | Yes | AAD is bound into the auth tag via `len(aad) \|\| aad` prefix |
| Replay attack | Partial (application layer) | Nonce-bound: different nonces produce different tags; nonce reuse is the caller's responsibility |
| Key-recovery from ciphertext | Yes (computational) | Key elements are not directly encoded; addends are HMAC-derived and computationally unpredictable without the key |
| Frequency / divisibility analysis | Yes | Real and noise tokens share the same formula; noise positions are HMAC-derived |
| Known-plaintext / chosen-plaintext | Yes (under standard HMAC assumptions) | Per-token HMAC-derived addends are computationally unpredictable |

### 2.2 Threat classes NOT addressed

| Threat | Status | Rationale |
|---|---|---|
| Quantum adversary (full Grover / Shor) | Not fully addressed | See §5 (post-quantum considerations) |
| Side-channel (timing, power) | Not addressed in Python ref | Python is not constant-time; see §6.1 |
| Nonce reuse | Semantic security degrades | Standard AEAD limitation; callers must use fresh nonces |
| Key compromise | Not addressed | Key management is out of scope |
| Streaming RUP: release of unverified plaintext | Gated, not fixed | `decrypt_stream` gated behind opt-in flag; see CAV-001 |
| Length information beyond power-of-two bucket | Not addressed | Padding leaks bucket; see CAV-003 and §6.3 |
| Traffic analysis (timing, volume) | Not addressed | Transport-layer concern |

---

## 3. Security Goals (Block API)

The block API (`encrypt_bytes` / `decrypt_bytes`, `napqes.py` approx.
L396–466) targets the following properties under standard computational
assumptions (HMAC-SHA256 is a pseudorandom function):

### 3.1 Ciphertext indistinguishability (IND-CPA)

Given two messages $m_0, m_1$ of the same length bucket, an adversary
without the key cannot distinguish $\text{Enc}(k, m_0)$ from
$\text{Enc}(k, m_1)$ with advantage significantly better than random
guessing. Noise-token insertion and per-token HMAC-derived addends
eliminate frequency and ratio attacks.

**Caveat.** Indistinguishability holds for messages in the same
power-of-two length bucket. Messages in different buckets leak their
bucket (see §6.3).

### 3.2 Ciphertext integrity / authenticity (INT-CTXT, IND-CCA)

Any modification to a v6 ciphertext (nonce, varint blob, or auth tag)
causes `decrypt_bytes` to raise `ValueError` before returning any
plaintext. Tag verification is performed with `hmac.compare_digest` to
resist timing side-channels at the comparison point. (`napqes.py` approx.
L434–440).

No plaintext is released on authentication failure in the block API. This
provides authenticated encryption semantics: INT-CTXT implies
non-malleability and IND-CCA.

### 3.3 AAD binding

The authentication tag commits to both the payload (`nonce || varint_blob`)
and the associated data via the construction:
```
tag = HMAC(key_bytes, b'\x03' || uint32_be(len(aad)) || aad || payload)
```
A ciphertext encrypted with AAD = A cannot be verified under a different
AAD = A′ ≠ A. (`napqes.py` `_compute_auth_tag`, approx. L178–185).

---

## 4. Security Goals (Streaming API)

The streaming API (`encrypt_stream` / `decrypt_stream`, `napqes.py`
approx. L530–715) uses the same wire format and the same auth tag.

**RUP exception.** `decrypt_stream` yields plaintext characters before the
tag is verified (CAV-001). This makes the streaming API unsafe against
active attackers who can inject or truncate the stream. The API is gated
behind `enable_unauthenticated_streaming=True` to require explicit caller
acknowledgement.

`decrypt_stream_strict` (approx. L715–730) buffers all decrypted output and
verifies the tag before returning. It provides the same integrity guarantees
as the block API and is the **recommended** streaming interface until Phase 3
implements online-AE.

---

## 5. Post-Quantum Considerations

NAPSEQ uses only HMAC-SHA256 (a symmetric construction). The relevant
quantum adversary is Grover's algorithm, which provides a quadratic speedup
for brute-force key search.

### 5.1 What NAPSEQ does claim

- Against a Grover adversary, a 10-element key drawn from [1M, 9.9M] primes
  (key-space ≈ 2¹⁹⁶) provides approximately **2⁹⁸ security** after Grover.
- The construction avoids algebraic structures (elliptic curves, lattices,
  integer factorisation) that Shor's algorithm or future algebraic quantum
  attacks might exploit.
- HMAC-SHA256 output tag is 256 bits; Grover reduces tag forgery work to
  ≈ 2¹²⁸ — remaining above the 128-bit security threshold.

### 5.2 What NAPSEQ does NOT claim

- **NAPSEQ is not a post-quantum KEM or signature.** It provides no key
  establishment. Customers requiring FIPS 203 (ML-KEM), 204 (ML-DSA), or
  205 (SLH-DSA) must use those standards.
- **NAPSEQ has not been submitted to any NIST PQC standardisation process.**
- **NAPSEQ's "PQ angle" is narrow.** AES-256 in GCM mode also provides
  ≈ 128-bit post-Grover security and is the NSA CNSA 2.0 symmetric choice
  for NSS. NAPSEQ's advantage is primarily structural (no AES hardware
  dependency, noise-token confidentiality layer) not a superior PQ security
  bound.

---

## 6. Explicit Non-Claims

### 6.1 Constant-time implementation

The Python reference is **not** claimed constant-time. Secret-dependent
branches and memory accesses are present in `_is_noise_pos`,
`_decrypt_with_noise_p`, and the varint decode loop. Constant-time
guarantees are `**[roadmap]**` — gated on the Rust core (Phase 2,
workstream 2.2, TVLA t < 4.5). See `BRD.md` §4.1 F-8, §5 NF-6.

### 6.2 NIST standardisation

NAPSEQ is **not a NIST-standardised cipher.** It uses FIPS-approved
sub-primitives (HMAC-SHA256, SHA-256) but the AEAD construction itself has
not undergone NIST standardisation. See [`docs/PRIMITIVES_ATTESTATION.md`](PRIMITIVES_ATTESTATION.md).

### 6.3 Full length hiding

Padding reveals the power-of-two bucket of the plaintext length:
- Message of 1–16 chars → ciphertext encodes 16 real + padding tokens.
- Message of 17–32 chars → 32 real + padding tokens.
- And so on.

This leaks `⌈log₂(n)⌉` bits of length information. Full length hiding
requires a fixed-frame transport layer (see CAV-003).

### 6.4 FIPS 140-3 module validation

NAPSEQ is **not FIPS 140-3 validated.** It uses FIPS-approved sub-primitives
and is preparing a pre-attestation memo (`[roadmap]` Phase 3 workstream 3.3).
FIPS 140-3 module validation is targeted for Phase 4 (workstream 4.1–4.2).

### 6.5 Formal security proof

As of this revision, no formal symbolic-model or computational proof of
NAPSEQ's IND-CCA security has been published. A security argument and
third-party cryptanalysis engagement are Phase 1 deliverables
(ROADMAP §3 workstreams 1.2, 1.4).

### 6.6 External cryptanalysis

No third-party formal review has been published. The third-party engagement
RFP is a Phase 1 commitment (ROADMAP §3 workstream 1.4). Do not represent
NAPSEQ as externally audited until workstream 1.4 delivers a public report.

---

## 7. Security Assumptions

The security of NAPSEQ v6 depends on:

1. **HMAC-SHA256 is a pseudorandom function (PRF).** Specifically, that it
   is computationally infeasible to distinguish HMAC outputs from random
   bytes without the key, and that HMAC-SHA256 satisfies PRF security under
   the standard compression-function assumptions.

2. **SHA-256 collision resistance.** Tag integrity relies on SHA-256
   collision resistance for the inner compression function. SHA-256 remains
   unbroken as of this writing.

3. **Key confidentiality.** The prime key list is uniformly random and
   secret. Compromise of the key breaks all security properties.

4. **Nonce freshness.** The 128-bit nonce is generated with
   `secrets.token_bytes(16)` (CSPRNG). Nonce reuse weakens semantic
   security (different messages may produce the same noise-position pattern)
   but does not immediately allow tag forgery.

5. **No related-key attacks.** Deriving multiple sub-keys from a single
   master key (e.g. via KDF) is the caller's responsibility; NAPSEQ makes
   no claim about related-key security.

---

## 8. Out-of-Scope Threats

The following are not addressed by NAPSEQ and require separate controls:

- Key exchange / key agreement (use ML-KEM or X25519/X448 + HKDF).
- Entity authentication / identity binding (use digital signatures).
- Transport-layer metadata protection (use TLS or QUIC).
- Message ordering / replay prevention (use sequence numbers or timestamps
  as AAD in the calling application).
- Physical security of key material (use HSM / TPM).

---

## 9. Review Status

| Item | Status |
|---|---|
| Internal author review | Done (2026-05-12) |
| Informal external cryptographer review | **Pending — Phase 1 prerequisite** |
| Third-party engagement (NCC Group / Trail of Bits / Cure53) | **Pending — Phase 1 workstream 1.4** |
| Publication alongside IACR ePrint preprint | **Pending — Phase 1 workstream 1.2** |

This document should be updated when the third-party engagement delivers
findings. Any "must-fix" items that affect the adversary model (§2) or
security goals (§3–4) must be resolved before Phase 5 publication.
