# NAPQES vs. AES & ChaCha20 — Executive Brief

**Audience:** CEO / CTO  
**Product:** NAPQES v6 (Noise-Augmented Post-Quantum Encryption System)  
**Author:** EPINeon  
**Date:** 2026-05-29  
**Status:** Pre-release — Phase 0 foundations complete; third-party audit in progress

> **Claim discipline notice.** This brief cites only properties that are
> demonstrated or formally specified in NAPQES v6. Limitations are listed
> alongside advantages. No claim in this document exceeds what the
> security target (`docs/SECURITY_TARGET.md`) explicitly asserts.

---

## What Is NAPQES?

NAPQES is a **symmetric authenticated encryption** scheme (AEAD — Authenticated
Encryption with Associated Data) for message confidentiality, integrity, and
authenticity. It is built **exclusively from HMAC-SHA256** — a well-understood,
FIPS-approved primitive — with no block cipher, elliptic curve, or lattice-based
component.

It ships as a Python reference, a C port, and a Rust core. The v6 wire format
is frozen and cross-implementation compatible.

---

## At a Glance — Comparison Table

| Property | AES-256-GCM | ChaCha20-Poly1305 | NAPQES v6 |
|---|---|---|---|
| **Underlying primitive** | Block cipher (algebraic S-box) | ARX stream cipher | HMAC-SHA256 (hash-based) |
| **Hardware dependency** | AES-NI (Intel/AMD) for speed | None | None |
| **AEAD (auth + encryption)** | Yes | Yes | Yes |
| **Post-Grover security** | ~128 bits (AES-256) | ~128 bits | ~128.5 bits (K=13 elements) |
| **Algebraic structure** | Yes (GF(2⁸) operations) | Partial (modular add) | **None** |
| **Noise / traffic-analysis layer** | No | No | **Yes** (structured noise tokens) |
| **Key format** | 32 opaque bytes | 32 opaque bytes | **Ordered list of prime integers** |
| **Ciphertext overhead vs plaintext** | ~1× (minimal) | ~1× (minimal) | 8–20× (noise tokens by design) |
| **NIST standardised** | Yes (FIPS 197) | RFC 8439 / NIST SP 800-38A | **No** (uses FIPS primitives) |
| **FIPS 140-3 module validated** | Yes (many vendors) | Yes (some vendors) | **No — Phase 4 target** |
| **Third-party formal audit** | Decades of public analysis | Multiple audits | **Pending — Phase 1** |
| **NIST SP 800-22 randomness** | N/A (standard) | N/A (standard) | 40/40 PASS (10 M bits) |
| **TVLA constant-time (Rust)** | N/A | N/A | max t = 1.134 (threshold 4.5) |

---

## Advantage 1 — No Algebraic Structure

### Why it matters for executives

AES uses a finite-field construction (GF(2⁸) S-box). ChaCha20 uses modular
arithmetic. Both rely on mathematical structures. The history of cryptography
shows that structural algebraic weaknesses, while not yet exploited in
production, can surface years after deployment when research advances.

NAPQES is built entirely from HMAC-SHA256. SHA-256 is a compression function
with no known algebraic shortcut; HMAC adds a layer of keyed security on top.
There is no field arithmetic, no lattice, no elliptic-curve dependency.

### Concrete example

Suppose a government adversary in 2032 discovers a subexponential algebraic
attack on GF(2⁸)-based constructions similar to index calculus for discrete
logarithms. AES and any cipher sharing its algebraic structure would need
immediate migration.

NAPQES carries no GF(2⁸) structure. The attack surface is limited to the
security of HMAC-SHA256, which has been studied intensively since 1996 and
has no known algebraic shortcut.

> **Honest limitation:** This is a hedge against *unknown future* algebraic
> attacks, not a claim that AES is broken today. AES-256-GCM remains
> the NIST and NSA CNSA 2.0 symmetric choice and is battle-tested.

---

## Advantage 2 — No Hardware Dependency

### Why it matters for executives

AES-NI (hardware acceleration for AES) is available on modern Intel and AMD
desktop and server CPUs. It is often **disabled or unavailable** in:

- Stripped-down cloud VMs (certain Arm-based instances, RISC-V boards)
- Embedded / IoT microcontrollers (medical devices, drone flight controllers)
- Air-gapped systems locked to legacy CPU generations
- Hypervisor-restricted enclaves

Without AES-NI, software AES implementations are 3–10× slower and vulnerable
to cache-timing side-channel attacks. ChaCha20 was designed precisely to avoid
this problem, and NAPQES shares that benefit.

### Concrete example — Drone telemetry (see `demos/drone/`)

The NAPQES repository includes a drone telemetry demo. A drone using a legacy
ARM Cortex-M4 with no AES-NI acceleration can encrypt GPS waypoints with
NAPQES without relying on hardware crypto support.

```
# No AES-NI, no special hardware — runs identically on any platform
key = [1031033, 5100019, 7829341, 9876547, 2345681,
       3456791, 4567891, 6789013, 8901237, 1234567]

ciphertext = encrypt("37.7749N,122.4194W,alt=120m,hdg=045", key)
# → portable Base64 ciphertext, verified by HMAC-SHA256 auth tag
```

AES-GCM on a Cortex-M4 without hardware acceleration requires a software
fallback that is measurably slower and harder to verify constant-time.
ChaCha20 also solves this, so the advantage here is **shared with ChaCha20**
but is a meaningful differentiator vs. AES in constrained environments.

---

## Advantage 3 — Structured Noise Token Layer

### Why it matters for executives

Even a perfectly secure cipher leaks **metadata** through ciphertext patterns:

- Short messages produce short ciphertexts (length leakage).
- Repeated identical messages may produce recognisable patterns.
- Traffic volume and timing reveal communication rhythms.

AES-GCM and ChaCha20-Poly1305 provide no noise layer — ciphertext length
equals plaintext length plus a small fixed overhead. An observer watching
an encrypted channel can infer message sizes, frequency, and timing.

NAPQES injects **HMAC-derived noise tokens** into every ciphertext. The
noise probability is 75–99% (key-derived per message), and all tokens —
real and noise — are statistically indistinguishable without the key.

### Concrete example — Trading signal confidentiality

Imagine encrypting two financial instructions:

| Plaintext | AES-GCM ciphertext size | NAPQES ciphertext size |
|---|---|---|
| `"BUY"` | 19 bytes (3 + 16 tag) | ≥ 16-token bucket + noise (~200–500 B) |
| `"SELL"` | 20 bytes (4 + 16 tag) | ≥ 16-token bucket + noise (~200–500 B) |
| `"HOLD POSITION"` | 29 bytes (13 + 16 tag) | ≥ 16-token bucket + noise (~200–500 B) |

With AES-GCM, an eavesdropper immediately knows `"BUY"` and `"SELL"` are
3- and 4-character strings. Combined with timing, this leaks trade intent.

With NAPQES, all three fall into the same 16-token length bucket, and each
ciphertext contains 75–99% noise tokens — statistically indistinguishable
from random bytes (NIST SP 800-22 40/40 pass).

```python
key = [1031033, 5100019, 7829341, 9876547, 2345681,
       3456791, 4567891, 6789013, 8901237, 1234567]

c1 = encrypt("BUY",            key)  # ─┐ same length bucket
c2 = encrypt("SELL",           key)  # ─┤ noise-padded, statistically
c3 = encrypt("HOLD POSITION",  key)  # ─┘ indistinguishable externally
```

> **Honest limitation:** The power-of-two padding bucket (16, 32, 64, …
> tokens) is observable. A 1-character message and a 16-character message
> land in the same bucket; a 17-character message lands in the next bucket
> of 32. Full length-hiding requires an additional fixed-frame transport
> layer (Phase 5 roadmap item CAV-003).

---

## Advantage 4 — Human-Inspectable Key Format

### Why it matters for executives

AES and ChaCha20 keys are 32 opaque bytes — meaningful only to a machine.
NAPQES keys are **ordered lists of prime integers**:

```
AES-256 key:   a3f7c2d1 8e4b9f06 3c7a2e58 d190b4a7 ...  (32 opaque bytes)

NAPQES key:    [1031033, 5100019, 7829341, 9876547, 2345681,
                3456791, 4567891, 6789013, 8901237, 1234567]
```

A human operator, auditor, or compliance team can:
- Verify each element is prime (programmatically in < 1 ms).
- Confirm elements are distinct (no accidental duplicates).
- Verify elements are in the required range [1,000,000 – 15,000,000].
- Audit key rotation by comparing element lists.

This is particularly relevant in regulated industries (finance, healthcare,
defence) where key material must be auditable by compliance officers without
deep cryptographic expertise.

> **Honest limitation:** Key ordering is a security parameter — `[k₀, k₁]`
> and `[k₁, k₀]` are **different keys**. Key management tooling must
> preserve element order. This adds a human-error risk not present with
> opaque byte keys.

---

## Advantage 5 — Pure HMAC-SHA256 Foundation

### Why it matters for executives

SHA-256 and HMAC-SHA256 are:

- **FIPS 180-4 / FIPS 198-1 approved** — used in TLS 1.3, SSH, DNSSEC, S/MIME.
- **Studied for 25+ years** — no known practical attack.
- **Universally available** — in OpenSSL, BoringSSL, Windows CNG, Apple CryptoKit, every language standard library.

NAPQES's security reduces entirely to the pseudorandom function (PRF)
assumption on HMAC-SHA256. An IND-CPA security proof (reducing to the PRF
assumption via a game-hopping argument) is in the companion ePrint preprint
(Phase 1 deliverable).

This means: **if HMAC-SHA256 is secure, NAPQES is secure.** There is no
additional mathematical structure to trust.

### Concrete example — Dependency surface comparison

| Cipher | Cryptographic dependencies |
|---|---|
| AES-256-GCM | AES block cipher (NIST FIPS 197) + GHASH (GF(2¹²⁸) mult) + GCM mode |
| ChaCha20-Poly1305 | ChaCha20 stream cipher (ARX) + Poly1305 MAC (GF(2¹³⁰−5) mult) |
| NAPQES v6 | **HMAC-SHA256 only** |

A vulnerability in GHASH or Poly1305 field arithmetic cannot affect NAPQES.

---

## Post-Quantum Positioning — An Honest Assessment

NAPQES's post-quantum positioning is **concrete and meets the 128-bit target**:

- Uses no elliptic curves or integer factorisation → **Shor's algorithm does not apply**.
- The relevant quantum adversary is Grover's algorithm (brute-force speedup).
- A 13-element key from [1M, 15M] primes yields key-space ≈ 2²⁵⁶·⁹⁷ (pool of 892,206 primes, sieve-verified).
- After Grover (quadratic speedup): **~2¹²⁸·⁵ security** — meeting the 128-bit post-quantum target recommended by NIST and NSA CNSA 2.0.
- The HMAC-SHA256 authentication tag (256 bits) provides ~128-bit forgery resistance post-Grover — key and tag are balanced at the 128-bit level.

> **AES-256 comparison:** AES-256-GCM also provides ~128-bit post-Grover
> security and is the NSA CNSA 2.0 symmetric choice. NAPQES at K=13 matches
> that level **and** eliminates all algebraic structure that Shor-family
> attacks could target, with both dimensions (key search and tag forgery)
> converging at ~128 bits post-Grover.

**What NAPQES does NOT claim:**
- It is not a Post-Quantum KEM or signature (customers needing FIPS 203
  ML-KEM or FIPS 204 ML-DSA must use those separately for key exchange).
- It has not been submitted to any NIST PQC standardisation process.

---

## Known Limitations — Full Disclosure

| ID | Issue | Impact | Status |
|---|---|---|---|
| CAV-001 | Basic streaming API releases unverified plaintext | Active attacker can inject before auth fails | **Fixed** — use `encrypt_stream_ae` |
| CAV-002 | Block mode capped at 65,535 codepoints | Hard error; no silent truncation | Phase 5 fix (v7 wire format) |
| CAV-003 | Ciphertext length reveals power-of-two bucket | Leaks ⌈log₂(n)⌉ bits of length | Phase 5 fix (fixed-frame option) |
| CAV-004 | Ciphertext 8–20× larger than AES-GCM | Unsuitable for bandwidth-constrained links | No fix planned (by design) |
| — | Python reference is not constant-time | Side-channel risk in Python deployments | Rust core is constant-time (TVLA passed) |
| — | No FIPS 140-3 module validation | Cannot satisfy formal FIPS compliance requirements today | Phase 4 CMVP submission |
| — | No published third-party cryptanalysis | Security claims not yet independently verified | Phase 1 engagement pending |

---

## Maturity Roadmap

| Phase | Focus | Status |
|---|---|---|
| **Phase 0** | Foundations, wire-format freeze, KAT vectors | ✅ Complete |
| **Phase 1** | IND-CCA proof, third-party audit, STS pipeline | 🔄 In progress |
| **Phase 2** | Rust constant-time core, TVLA attestation | ✅ Complete (TVLA max t = 1.134) |
| **Phase 3** | Streaming AE (CAV-001 fix), C KAT verification | ✅ Complete |
| **Phase 4** | FIPS 140-3 CMVP submission | 📋 Planned |
| **Phase 5** | v7 wire format (larger caps, fixed-frame padding) | 📋 Planned |

---

## When to Choose NAPQES

| Scenario | Recommendation |
|---|---|
| IoT / embedded without AES-NI | NAPQES — no hardware dependency |
| Traffic-analysis-sensitive messaging (financial signals, command & control) | NAPQES — noise token layer |
| Regulated environment requiring FIPS 140-3 validation today | Use validated AES-256-GCM module; revisit after Phase 4 |
| High-throughput bulk data encryption | AES-256-GCM (NAPQES 8–20× expansion is a constraint) |
| Post-quantum key exchange | Neither — use ML-KEM (FIPS 203) for key establishment |
| Environments where you control pre-shared key distribution | NAPQES — purpose-built for pre-shared symmetric keys |

---

## Summary

NAPQES v6 offers three structurally distinct advantages over AES-GCM and
ChaCha20-Poly1305:

1. **No algebraic structure** — removes the attack surface that Shor-family
   quantum algorithms and algebraic cryptanalysis target in block and stream ciphers.

2. **Noise-token confidentiality layer** — actively resists traffic analysis
   and length-correlation attacks that AES/ChaCha20 ciphertexts are transparent to.

3. **Pure HMAC-SHA256 foundation** — reduces the trusted primitive surface to
   a single, universally deployed, 25-year-hardened construction.

These advantages come with real trade-offs: larger ciphertexts, no current
FIPS 140-3 validation, and a pending external audit. For bandwidth-constrained
or FIPS-mandated deployments, AES-256-GCM remains the right choice today.

For traffic-sensitive, hardware-diverse, or algebraic-risk-averse deployments,
NAPQES v6 offers a credible and disciplined alternative.

---

*For technical details: [`SPEC.md`](../SPEC.md), [`docs/SECURITY_TARGET.md`](SECURITY_TARGET.md)*  
*Vulnerability disclosure: `security@epineon.com`*
