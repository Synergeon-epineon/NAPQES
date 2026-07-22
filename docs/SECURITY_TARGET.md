# NAPQES Security Target — Adversary Model & Claim Boundaries

**Version:** 0.3  
**Date:** 2026-07-06  
**Wire format:** v7 (frozen — see [`SPEC.md`](../SPEC.md)); supersedes v6 as of the CVF1 fix  
**Status:** Pre-release (informal external cryptographer review in progress — see §9)

> This document describes what NAPQES v7 is intended to achieve, what it
> explicitly does not claim, and the conditions under which the security
> goals are expected to hold. Every claim in this document must be
> reachable from `napqes.py` line ranges or from `[roadmap]` markers; see

---

## 1. System Summary

NAPQES v6 is a symmetric authenticated encryption scheme with associated
data (AEAD). It is built exclusively from HMAC-SHA256 and is intended for
environments where:
- Symmetric key material is pre-shared (NAPQES does not provide key
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
| Passive eavesdropper | Yes | Ciphertext confidentiality via the domain-`0x07` HMAC keystream and the domain-`0x03` HMAC tag; the token/noise layer does not contribute additional content confidentiality (audit finding CVF4 — see `docs/audit_mitigation_responses.md`) |
| Active attacker: ciphertext modification | Yes | HMAC-SHA256 auth tag verified before plaintext release (block API) |
| Active attacker: AAD substitution | Yes | AAD is bound into the auth tag via `len(aad) \|\| aad` prefix |
| Replay attack | Partial (application layer) | Nonce-bound: different nonces produce different tags; nonce reuse is the caller's responsibility |
| Key-recovery from ciphertext | Yes (computational), **under a fresh nonce only** | Key elements are not directly encoded; addends are HMAC-derived and computationally unpredictable without the key. **Under a reused nonce this guarantee fails catastrophically — see CVF3 below.** |
| Frequency / divisibility analysis | Yes | Real and noise tokens share the same formula; noise positions are HMAC-derived |
| Known-plaintext / chosen-plaintext | Yes (under standard HMAC assumptions) | Per-token HMAC-derived addends are computationally unpredictable |
| Quantum adversary (full Grover / Shor) | Yes | See §5 (post-quantum considerations) |
| Side-channel (timing, power) | yes | Python is not constant-time; but Rust implementation is |
| Length information beyond power-of-two bucket | partially addressed | Padding leaks bucket but not exact length; see CAV-003 and §6.3 |
### 2.2 Threat classes NOT addressed

| Threat | Status | Rationale |
|---|---|---|
| Nonce reuse | **Catastrophic — full key recovery (CVF3)** | Not a "standard AEAD limitation": every internal value (noise positions, addends, keystream) is a deterministic function of (key, nonce) only, so a reused nonce plus two known-plaintext tokens at the same position yields the key element exactly. Callers must never reuse or explicitly supply a nonce; see `docs/audit_mitigation_responses.md` (CVF3) and `docs/CAVEATS.md`. |
| Key compromise | Not addressed | Key management is out of scope |
| Traffic analysis: message timing / volume over time | Not addressed | Transport-layer concern |
| Traffic analysis: per-message length correlation with content | Yes (mitigated) | Ciphertext byte-length is a function of `(key, nonce, padded length)` only via the noise-position oracle and noise probability (domains `0x00`/`0x02`), independent of codepoint values — see Lemma `lem:tar` in `docs/napseq-eprint-preprint.tex` and audit finding CVF4. This is distinct from, and does not depend on, the content-confidentiality mechanism above. |

---

## 3. Security Goals (Block API)

The block API targets the following properties under standard computational assumptions (HMAC-SHA256 is a pseudorandom function):

### 3.1 Ciphertext indistinguishability (IND-CPA)

Given two messages $m_0, m_1$ of the same length bucket, an adversary
without the key cannot distinguish $\text{Enc}(k, m_0)$ from
$\text{Enc}(k, m_1)$ with advantage significantly better than random
guessing. Noise-token insertion and per-token HMAC-derived addends
eliminate frequency and ratio attacks.

**Caveat.** Indistinguishability holds for messages in the same
power-of-two length bucket. Messages in different buckets leak their
bucket (see §6.3).

**CVF1 (fixed).** Prior to the v7 fixed-width token encoding, this claim
was false even *within* the same length bucket: the legacy v6 LEB128 token
encoding made ciphertext byte-length depend on plaintext codepoint values,
giving an IND-CPA distinguishing advantage ≈ 1 (see `docs/CAVEATS.md`
CVF1 and the erratum in `docs/napseq-eprint-preprint.tex`). The v7
fixed-width encoding makes ciphertext byte-length within a bucket
depend only on the (content-independent) noise schedule, restoring this
claim.

### 3.2 Ciphertext integrity / authenticity (INT-CTXT, IND-CCA)

Any modification to a v7 ciphertext (nonce, token blob, or auth tag)
causes `decrypt_bytes` to raise `ValueError` before returning any
plaintext. Tag verification is performed with `hmac.compare_digest` to
resist timing side-channels at the comparison point. (`napqes.py` approx.
L434–440).

No plaintext is released on authentication failure in the block API. This
provides authenticated encryption semantics: INT-CTXT implies
non-malleability and IND-CCA.

### 3.3 AAD binding

The authentication tag commits to both the payload (`nonce || masked_blob`)
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

NAPQES uses only HMAC-SHA256 (a symmetric construction). The relevant
quantum adversary is Grover's algorithm, which provides a quadratic speedup
for brute-force key search.

### 5.1 What NAPQES does claim

- Against a Grover adversary, a 10-element key drawn from [1M, 15M] primes (key-space ≈ 2¹⁹⁷·⁶⁷) provides approximately **2⁹⁸·⁸⁴ security** after Grover.
- Against a Grover adversary, a 13-element key drawn from [1M, 15M] primes (key-space ≈ 2²⁵⁶·⁹⁷) provides approximately **2¹²⁸·⁵ security** after Grover.
- The construction avoids algebraic structures (elliptic curves, lattices,   integer factorisation) that Shor's algorithm or future algebraic quantum   attacks might exploit.
- HMAC-SHA256 output tag is 256 bits; Grover reduces tag forgery work to  ≈ 2¹²⁸ — remaining above the 128-bit security threshold.

### 5.2 What NAPQES does NOT claim

- **NAPQES is not a post-quantum KEM or signature.** It provides no key  establishment. Customers requiring FIPS 203 (ML-KEM), 204 (ML-DSA), or   205 (SLH-DSA) must use those standards.
- **NAPQES has not not yet been approved by NIST PQC standardisation process.**
---

## 6. Explicit Non-Claims

### 6.1 Constant-time implementation

The Python reference is **not** claimed constant-time, but Rust implementation **Is**. Secret-dependent
branches and memory accesses are present in `_is_noise_pos`,
`_decrypt_with_noise_p`, and the varint decode loop. Constant-time
guarantees are `**[roadmap]**` — gated on the Rust core (Phase 2,
workstream 2.2, TVLA t < 4.5). See `BRD.md` §4.1 F-8, §5 NF-6.

The Rust core (`rust/src/lib.rs`) uses a `ptr::read_volatile` +
`ptr::write_volatile` + `#[inline(never)]` based comparison (`ct_eq_bytes`)
for authentication-tag comparison. An initial attempt using
`subtle::ConstantTimeEq` (v2) was abandoned after a dudect run produced
t = +411.85 (threshold: 4.5) — LLVM optimised the pure-Rust fold into an
early-exit branch at `-O3`. The final implementation was confirmed by:

1. **Assembly inspection** — the compiled function is a straight-line sequence
   of 32 load-XOR-accumulate-store triples with no data-dependent branches.
2. **Empirical TVLA** — dudect re-run at n = 12.712 M measurements produced
   max t = +1.134 (threshold: 4.5), tau = +0.00032.  Detection at t = 5 would
   require ~247 M measurements.

**Conclusion, The rust implementation is constant-time but python isn't**

### 6.2 NIST standardisation

NAPQES is **not a NIST-standardised cipher.** It uses FIPS-approved
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

NAPQES is **not FIPS 140-3 validated.** The FIPS 140-3 pre-attestation
documentation package (Phase 3 workstream 3.3) is in progress and includes:

- [`docs/fips/SECURITY_POLICY.md`](fips/SECURITY_POLICY.md) — Non-Proprietary Security Policy
- [`docs/fips/MODULE_BOUNDARY.md`](fips/MODULE_BOUNDARY.md) — Module boundary specification
- [`docs/fips/KEY_MANAGEMENT.md`](fips/KEY_MANAGEMENT.md) — Key lifecycle documentation
- [`docs/fips/CAVP_EVIDENCE.md`](fips/CAVP_EVIDENCE.md) — CAVP algorithm validation evidence
- [`docs/fips/sbom.cdx.json`](fips/sbom.cdx.json) — CycloneDX Software Bill of Materials
- [`docs/DRBG_ATTESTATION.md`](DRBG_ATTESTATION.md) — DRBG and entropy source attestation

FIPS 140-3 module validation (CMVP submission) is targeted for Phase 4
(workstream 4.1–4.2). Until a CMVP certificate is awarded, customers with a
formal FIPS 140-3 requirement should use a validated cryptographic module
for the symmetric AEAD layer.

### 6.5 Formal security proof

A formal game-hopping IND-CPA proof appears in the companion ePrint preprint
(`docs/napseq-eprint-preprint.tex`, §4.1). The proof reduces IND-CPA security
to the PRF assumption on HMAC-SHA256 via two hybrid games: a PRF-replacement
hop and a one-time-pad argument on the domain-0x07 keystream masking layer.
A quantitative advantage bound of
Adv^PRF + q²/2^128 is established.

A full IND-CCA game-hopping reduction following Bellare & Namprempre 2000 is
in progress and will be added to the companion ePrint preprint prior to final
third-party report publication. The reduction sketch: INT-CTXT holds because
any tag forgery constitutes a PRF distinguisher (Adv^PRF advantage); IND-CCA
then follows from INT-CTXT + IND-CPA via the composition theorem (B&N 2000,
Theorem 3).

A full IND-CCA proof and the third-party cryptanalysis engagement remain
Phase 1 deliverables (ROADMAP §3 workstreams 1.2, 1.4).
A full IND-CCA game-hopping reduction following Bellare & Namprempre 2000 is
in progress and will be added to the companion ePrint preprint prior to final
third-party report publication. The reduction sketch: INT-CTXT holds because
any tag forgery constitutes a PRF distinguisher (Adv^PRF advantage); IND-CCA
then follows from INT-CTXT + IND-CPA via the composition theorem (B&N 2000,
Theorem 3).

A full IND-CCA proof and the third-party cryptanalysis engagement remain
Phase 1 deliverables (ROADMAP §3 workstreams 1.2, 1.4).

### 6.6 External cryptanalysis

No third-party formal review has been published. The third-party engagement
RFP is a Phase 1 commitment (ROADMAP §3 workstream 1.4). Do not represent
NAPQES as externally audited until workstream 1.4 delivers a public report.

---

## 7. Security Assumptions

The security of NAPQES v6 depends on:

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
   `secrets.token_bytes(16)` (CSPRNG). Nonce reuse does **not** merely
   weaken semantic security — it is catastrophic and key-recoverable (see
   CVF3 in `docs/audit_mitigation_responses.md` and `docs/CAVEATS.md`).
   It does not immediately allow tag forgery, but two known-plaintext
   tokens at the same real-token position under a reused nonce recover
   that position's key element exactly.

5. **No related-key attacks.** Deriving multiple sub-keys from a single
   master key (e.g. via KDF) is the caller's responsibility; NAPQES makes
   no claim about related-key security.

---

## 8. Out-of-Scope Threats

The following are not addressed by NAPQES and require separate controls:

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
| FIPS 140-3 pre-attestation docs | Done (2026-05-28) — see §6.4 |
| Informal external cryptographer review | **In progress** |
| Third-party engagement (NCC Group / Trail of Bits / Cure53) | **Pending** |
| Publication alongside IACR ePrint preprint | **In progress** |

This document should be updated when the third-party engagement delivers
findings. Any "must-fix" items that affect the adversary model (§2) or
security goals (§3–4) must be resolved before Phase 5 publication.
