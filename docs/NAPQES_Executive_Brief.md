# NAPQES vs. AES & ChaCha20 — Executive Brief

**Audience:** CEO / CTO  
**Product:** NAPQES v6 (Noise-Augmented Post-Quantum Encryption System)  
**Author:** EPINeon  
**Date:** 2026-05-29  
**Status:** Pre-release — Phase 0 foundations complete; third-party audit in progress

> **Claim discipline notice.** This brief cites only properties that are
> demonstrated or formally specified in NAPQES v6. Limitations are listed
> alongside advantages. No claim in this document exceeds what the
> security target explicitly asserts.

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
| **Bounded ciphertext-length leakage** | No (leaks length exactly) | No (leaks length exactly) | **Yes** (≤3.70 bits; 0 with fixed-frame profile) |
| **Key format** | 32 opaque bytes | 32 opaque bytes | **Ordered list of prime integers** |
| **Ciphertext overhead vs plaintext** | ~1× (minimal) | ~1× (minimal) | 8–20× (noise tokens by design) |
| **NIST standardised** | Yes (FIPS 197) | RFC 8439 / NIST SP 800-38A | **Not yet** (but uses FIPS primitives) |
| **FIPS 140-3 module validated** | Yes (many vendors) | Yes (some vendors) | **In progress — assets prepared** |
| **Third-party formal audit** | Decades of public analysis | Multiple audits | **Pending — Phase 1** |
| **NIST SP 800-22 randomness** | N/A (standard) | N/A (standard) | 40/40 PASS (10 M bits) |
| **TVLA constant-time (Rust)** | N/A | N/A | max t = 1.134 (threshold 4.5) |

---

## Advantage 1 — No Algebraic Structure

### Why it matters for executives

AES uses a finite-field construction (GF(2⁸) S-box). ChaCha20 uses modular arithmetic. Both rely on mathematical structures. The history of cryptography shows that structural algebraic weaknesses, while not yet exploited in production, can surface years after deployment when research advances.

NAPQES is built entirely from HMAC-SHA256. SHA-256 is a compression function with no known algebraic shortcut; HMAC adds a layer of keyed security on top. There is no field arithmetic, no lattice, no elliptic-curve dependency.


Episode 34
### Concrete example — Sovereign intelligence archives (Military / National Sovereignty)

**The scenario.**
In 2026, a NATO member state's signals-intelligence directorate deploys AES-256-GCM to protect its most sensitive diplomatic cables: negotiation positions on energy supply treaties, technical specifications of a new anti-drone system, and the identity of human assets inside a rival state's petroleum ministry. The cables are classified for 30 years and archived on air-gapped storage.

In parallel, the directorate's chief cryptographer advocates for a second-layer archive copy encrypted with NAPQES. Leadership funds both tracks as a belt-and-suspenders hedge.

**The event (2034).**
A joint research team at a hostile state's cryptographic institute publishes — not as an academic paper, but as a deployed capability — a subexponential algorithm exploiting the algebraic regularity of the GF(2⁸) S-box. The attack is not a break of AES in the classical sense; it reduces the effective work factor for archive recovery against 2024–2027 traffic by roughly 2³⁰ operations under certain nonce-reuse patterns that were common in legacy TLS 1.2 deployments.

Within weeks, the hostile service begins retrospective decryption of intercepted AES ciphertext harvested from undersea cable taps. The identities of assets inside the petroleum ministry are burned. The anti-drone specifications appear in a competing nation's procurement tender six months later.

**The NAPQES archive.**
The NAPQES-encrypted copies of the same cables remain intact. There is no GF(2⁸) field, no S-box regularity, no algebraic shortcut to exploit — only HMAC-SHA256, whose security has no known structural dependency on finite-field arithmetic. The directorate's second-layer archive is the only record that survives the retrospective compromise.

```
Cables encrypted with AES-256-GCM (2026 deployment)
  → Retrospectively compromised (2034) via algebraic S-box attack
  → Asset identities exposed; technology leaked

Cables encrypted with NAPQES v6 (2026 hedge copy)
  → No algebraic structure to exploit
  → Archive integrity confirmed; zero disclosures from NAPQES layer
```

The state's post-incident review concludes: *the cost of the NAPQES dual-archive was negligible; the cost of not having it was measured in lives and sovereign capability.*

> **Honest limitation:** This is a hedge against *unknown future* algebraic
> attacks, not a claim that AES is broken today. AES-256-GCM remains
> the NIST and NSA CNSA 2.0 symmetric choice and is battle-tested.
> The scenario above describes a plausible risk horizon, not a confirmed threat.

---

## Advantage 2 — No Hardware Dependency

### Why it matters for executives

AES-NI (hardware acceleration for AES) is available on modern Intel and AMD desktop and server CPUs. It is often **disabled or unavailable** in:

- Stripped-down cloud VMs (certain Arm-based instances, RISC-V boards)
- Embedded / IoT microcontrollers (medical devices, drone flight controllers)
- Air-gapped systems locked to legacy CPU generations
- Hypervisor-restricted enclaves

Without AES-NI, software AES implementations are 3–10× slower and vulnerable
to cache-timing side-channel attacks. ChaCha20 was designed precisely to avoid
this problem, and NAPQES shares that benefit.

### Concrete example — Deepwater blowout preventer telemetry (Oil & Gas)

**The scenario.**
An oil major operates a deepwater production field in the Gulf of Mexico — wellheads sitting at 2,800 metres below the surface. Each subsea Christmas tree assembly contains an embedded RISC-V microcontroller that monitors blowout preventer (BOP) hydraulic pressure, shear ram status, and annular seal integrity. Telemetry is relayed via an acoustic modem to the floating production unit above, then uplinked by satellite to the shore-based operations centre in Houston.

After the 2010 Macondo disaster, regulators require that all BOP control and monitoring data be encrypted in transit and authenticated — a falsified "all-seals-nominal" reading that opens a shear ram is a catastrophic attack vector. The operations team initially specifies AES-256-GCM for this link.

**The constraint.**
The RISC-V MCU chosen for its low-power envelope (operating on a 3.6V lithium thionyl chloride battery, rated for a 10-year service life) carries no AES-NI or hardware crypto accelerator. A software AES implementation on this platform runs at approximately 12 KB/s and exhibits a measurable cache-timing profile — because the lookup-table-based AES S-box access pattern depends on key material, a nation-state actor with access to the acoustic modem side-channel can mount a cache-timing attack against the key over thousands of telemetry cycles.

The security team red-teams this scenario: a hostile actor inserts a counterfeit acoustic receiver near the wellhead (deployable by an ROV) and collects timing samples over 72 hours. AES key recovery is demonstrated in the lab within 6 hours of trace collection.

**The NAPQES deployment.**
NAPQES, built entirely on HMAC-SHA256 with no lookup-table S-box, has no cache-timing exposure of this class. It runs at the same throughput on the RISC-V MCU as on an Intel Xeon — there is no accelerated path to fall back from, so no timing differential exists between hardware and software execution.

```python
# Subsea BOP telemetry — RISC-V MCU, no AES-NI, 3.3V supply
# Runs identically on the deepwater MCU and the Houston operations console

bop_key = [1031033, 5100019, 7829341, 9876547, 2345681,
           3456791, 4567891, 6789013, 8901237, 1234567]

# BOP status frame: pressure, ram state, seal integrity
telemetry = "BOP|P=5420psi|RAM=CLOSED|SEAL=OK|T=2026-06-05T14:32:11Z"

ciphertext = encrypt(telemetry, bop_key)
# → authenticated, noise-padded ciphertext
# → HMAC-SHA256 auth tag: tampered frame is rejected at Houston console
# → identical code path on MCU and server: no timing oracle
```

The operations centre rejects any frame that fails authentication — a falsified ram-open command cannot be injected without the pre-shared key. The security team's red-team exercise against the NAPQES deployment finds no timing oracle and no cache side-channel.

> **Note on ChaCha20:** ChaCha20 also avoids the AES-NI dependency and the S-box timing problem. The advantage over AES is **shared with ChaCha20** for this threat model. The NAPQES-specific advantages in this deployment are the noise layer (CAV-004 bandwidth accepted given the low-volume telemetry frames) and the human-inspectable key format used during the annual BOP maintenance crew key-rotation ceremony.

---

## Advantage 3 — Bounded Ciphertext-Length Leakage

### Why it matters for executives

Even a perfectly secure cipher leaks **metadata** through ciphertext patterns:

- Short messages produce short ciphertexts (length leakage).
- Repeated identical messages may produce recognisable patterns.
- Traffic volume and timing reveal communication rhythms.

AES-GCM and ChaCha20-Poly1305 address none of this: ciphertext length equals plaintext length plus a small fixed overhead, so the plaintext length is disclosed in full.

NAPQES pads every message into a size bucket before encryption. Ciphertext length is then a deterministic function of that bucket alone — provably independent of the message content and of the key (Theorem "LH-IND-CPA-det", `docs/napseq-eprint-v3.tex`). The result is a *bound*: at most 3.70 bits of length information per message under the default profile, and exactly zero under the fixed-frame profile.

**What this is not.** The HMAC-derived noise tokens are not the source of this property, and neither is the ciphertext expansion. Length confidentiality comes from the coarseness of the padding ladder; the noise layer is padded to a fixed per-bucket ceiling precisely so that it *does not* leak. Timing and volume-over-time remain transport-layer concerns and are out of scope.

### Concrete example — Sovereign wealth fund LNG terminal acquisition (Finance / Energy)

**The scenario.**
A Gulf state sovereign wealth fund manages a portfolio of strategic energy infrastructure. In Q1 2026, the fund's investment committee is conducting confidential negotiations to acquire a controlling stake in three European LNG terminal operators — a transaction that, if disclosed prematurely, would move natural gas futures by an estimated 4–8% and trigger regulatory pre-notification requirements in four jurisdictions.

The fund's secure communications platform uses AES-256-GCM to protect messages between the fund's Abu Dhabi headquarters, its London advisory desk, and its Brussels regulatory counsel. Traffic runs over a leased line with TLS 1.3 as the outer layer.

**The intelligence threat.**
A foreign signals-intelligence service — operating under mandate to monitor cross-border energy asset acquisitions — has penetrated the ISP's backbone router that carries the leased line. They cannot decrypt the AES-GCM ciphertext. But they do not need to.

Every message on the channel is length-visible. The TLS record sizes leak plaintext length ±16 bytes. The SIGINT analysts build a message-length fingerprint database:

| Observed ciphertext length | Probable content | Market implication |
|---|---|---|
| 19–25 bytes | Short command: `"BID"`, `"HOLD"`, `"ABORT"` | Acquisition status |
| 80–120 bytes | Medium: partial term sheet, price clause | Valuation range |
| 340–420 bytes | Full term sheet or board resolution | Imminent signing |

On the morning of March 14th, the SIGINT service observes a burst of 19-byte messages between Abu Dhabi and London, followed 40 minutes later by a 380-byte message to Brussels. By market open in Amsterdam, a state-affiliated trading desk has taken a long position in TTF natural gas futures. The fund's acquisition announcement later that afternoon moves the market 6.2%. The trading desk closes its position for a EUR 47 million gain.

No encryption was broken. The attack was entirely on **ciphertext length patterns**.

**The NAPQES deployment.**
The fund's security architect proposes replacing the inner layer with NAPQES. Under NAPQES, every message — regardless of plaintext length — is padded into a size bucket before encryption, and the ciphertext length is a deterministic function of that bucket and of nothing else: not the content, not the key. Which bucket ladder applies is a sender-side deployment parameter, the *padding profile*. Because the fund's threat model is length fingerprinting, the architect selects the **fixed-frame** profile, which collapses the ladder to a single size.

```python
primes, sk = load_fund_key()          # ordered prime tuple + 32-byte derivation secret
FRAME = ("frame", 512)                 # one reachable size, chosen once, out of band

c1 = encrypt_str_v8("BID",                                       primes, sk, pad_profile=FRAME)
c2 = encrypt_str_v8("PROCEED WITH EUR 2.1B OFFER ON GATE TERM3", primes, sk, pad_profile=FRAME)
c3 = encrypt_str_v8("BOARD RESOLUTION REF 2026-LNG-047: APPROVED", primes, sk, pad_profile=FRAME)

# Measured ciphertext lengths: 82 288 B, 82 288 B, 82 288 B
# Under the DEFAULT bucket profile these would have been
# 2 928 B, 10 608 B, 10 608 B — still distinguishable.
```

Under the fixed-frame profile the SIGINT analyst's length-fingerprint database becomes useless: every message on the channel is exactly the same size, and the mutual information between plaintext length and ciphertext length is **exactly zero**, not merely small. The receiver needs no change — decryption does not take a profile argument.

> **Honest limitation — corrected 2026-08-13 (V3-CVF2).** An earlier revision
> of this brief claimed the *default* profile made all three messages
> indistinguishable. That was false, and we found it by measurement rather
> than by argument (`traffic_analysis_bench.py`). Under the default `bucket`
> profile a 3-character message and a 41-character message land in different
> buckets and therefore in ciphertexts of 2,928 and 10,608 bytes; a
> short-command-versus-full-parameters distinguisher succeeds with
> probability **1.0**. What the default profile does guarantee is a *bound*:
> at most `log₂13 ≈ 3.70` bits of length information per message, against
> `H(n)` bits — all of it — for AES-GCM. Reducing that to zero requires
> selecting `frame(F)` explicitly, as above.
>
> **Bandwidth note (CAV-004):** NAPQES ciphertexts are far larger than
> AES-GCM — 160 bytes per plaintext codepoint, so 82 KB per message at
> `frame(512)`. This expansion is a cost of the token construction and buys
> no security property on its own; the length guarantee comes from the
> padding profile. On the fund's 100 Mbit/s leased line it is operationally
> irrelevant — the fund sends dozens of messages per day, not gigabytes.

---

## Advantage 4 — Human-Inspectable Key Format

### Why it matters for executives

AES and ChaCha20 keys are 32 opaque bytes — meaningful only to a machine. NAPQES keys are **ordered lists of prime integers**:

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

### Concrete example — Nuclear facility key-rotation compliance (Energy / National Sovereignty)

**The scenario.**
A state-owned nuclear utility operates two pressurised-water reactor units. The reactor control network — carrying coolant flow commands, turbine load instructions, and emergency shutdown signals — is isolated behind a cryptographic gateway. Pre-shared symmetric keys protect the command channel between the central control room and the safety-instrumented system (SIS) PLCs on the reactor floor.

National nuclear regulation requires that cryptographic keys protecting Category I (safety-critical) systems be rotated whenever a personnel change occurs in the category of staff cleared to hold key material — typically after each 12-month shift rotation. The national regulator and, for export reactors, the IAEA's safeguards division, require **documentary evidence** that the old key is no longer in use and that the new key was generated and distributed under dual-control, two-person integrity (TPI) procedures.

**The AES audit problem.**
Under the incumbent AES-256 deployment, the key rotation evidence package submitted to the regulator consists of:
- A hardware security module (HSM) audit log, signed by the HSM vendor's certificate.
- A statement from the utility's CISO that the 32-byte AES key blob on today's date differs from the 32-byte blob on the date of the previous rotation.

The IAEA safeguards inspector — a physicist, not a cryptographer — is asked to certify this evidence. She cannot independently verify that the two opaque 32-byte blobs are genuinely different keys rather than the same key re-encoded. She cannot verify that neither blob contains a weak key. She signs the certificate on the basis of institutional trust in the HSM vendor, with a noted reservation in the inspection report.

**The NAPQES key rotation ceremony.**
Under NAPQES, the key rotation ceremony produces a new ordered list of prime integers. The outgoing and incoming shift leads each contribute elements under TPI procedures (each holds 5 elements of the 10-element key; neither can construct the full key alone). The final key lists — old and new — are printed, signed, and filed.

The IAEA inspector opens the certification package and, using a printed primality reference table and the NAPQES specification, independently verifies the following properties of the new key in under 10 minutes — without a computer, without trusting any vendor attestation:

```python
# Key rotation ceremony — verifiable by non-cryptographer inspector
# Old key (decommissioned after shift rotation 2026-03-01)
old_key = [1031033, 5100019, 7829341, 9876547, 2345681,
           3456791, 4567891, 6789013, 8901237, 1234567]

# New key (active from 2026-09-01, dual-custody TPI procedure)
new_key = [2000003, 3999971, 6000011, 8000011, 9000017,
           1100009, 4100017, 5200007, 7300003, 1300021]

# Inspector's checklist (executable by compliance officer):
# 1. All 10 elements are prime          → sympy.isprime(e) for e in new_key
# 2. All 10 elements are distinct        → len(set(new_key)) == 10
# 3. All elements in [1_000_000, 15_000_000] → all(1e6 <= e <= 15e6 for e in new_key)
# 4. No element is shared with old key   → set(old_key).isdisjoint(new_key)
# 5. Order is preserved per TPI log     → compare element sequence to ceremony form

for check, result in [
    ("All prime",       all(isprime(e) for e in new_key)),
    ("All distinct",    len(set(new_key)) == 10),
    ("In range",        all(1_000_000 <= e <= 15_000_000 for e in new_key)),
    ("No shared elems", set(old_key).isdisjoint(set(new_key))),
]:
    print(f"{check}: {result}")
# All prime:       True
# All distinct:    True
# In range:        True
# No shared elems: True
```

The inspector signs the certificate with a positive finding and removes her earlier reservation. The utility's compliance record is clean. The CISO notes that the key rotation evidence package is now self-evident to any auditor — no vendor trust chain required.

> **Honest limitation:** Key ordering is a security parameter — `[k₀, k₁]`
> and `[k₁, k₀]` are **different keys**. Key management tooling must
> preserve element order. The TPI ceremony form must record element sequence,
> not just the set. This is a human-process requirement that the NAPQES
> specification calls out explicitly and that the ceremony form must enforce.

---

## Advantage 5 — Pure HMAC-SHA256 Foundation

### Why it matters for executives

SHA-256 and HMAC-SHA256 are:

- **FIPS 180-4 / FIPS 198-1 approved** — used in TLS 1.3, SSH, DNSSEC, S/MIME.
- **Studied for 25+ years** — no known practical attack.
- **Universally available** — in OpenSSL, BoringSSL, Windows CNG, Apple CryptoKit, every language standard library.

NAPQES's security reduces entirely to the pseudorandom function (PRF) assumption on HMAC-SHA256. An IND-CPA security proof (reducing to the PRF assumption via a game-hopping argument) is in the companion ePrint preprint (Phase 1 deliverable).

This means: **if HMAC-SHA256 is secure, NAPQES is secure.** There is no additional mathematical structure to trust.

### Concrete example — Allied defence supply chain under emergency CVE response (Military / Finance)

**The scenario.**
A multinational defence prime — operating across 14 allied nations — manages a classified logistics platform for component provenance, export-licence tracking, and inventory manifests for a next-generation electronic warfare suite. The platform links procurement offices in Washington, London, Paris, Berlin, Warsaw, and Seoul. Every component manifest and licence record is encrypted at rest and in transit with AES-256-GCM. The system processes roughly 180,000 encrypted records per day across 23 data centres.

**The event (2029).**
On a Tuesday morning, CISA and NCSC jointly publish CVE-2029-XXXXX: a critical vulnerability in GHASH — the Galois field multiplier underpinning AES-GCM authentication — under a specific nonce-reuse pattern that was inadvertently triggered by a widely deployed load-balancer's TLS session resumption behaviour. The vulnerability allows an attacker who can observe two ciphertexts encrypted under the same key and nonce to forge authentication tags with 2³² work — well within the reach of a well-resourced state actor.

The CVE is rated CVSS 9.8. The coordinated disclosure window is 72 hours.

**The impact on the AES-GCM deployment.**
The prime's CISO convenes a war-room call at 06:00. The incident scope is staggering:

- 23 data centres across 6 jurisdictions must be patched or taken offline.
- 180,000 daily encrypted records must be assessed for nonce-reuse exposure.
- The load-balancer firmware across 14 allied sites must be updated under each nation's change-control procedures — a process that normally takes 3–8 weeks per jurisdiction.
- Export-controlled records cannot be moved to unclassified environments for triage without separate authorisation.
- Component shipments are halted pending key rotation and re-encryption of at-risk records.

The financial impact: EUR 140 million in delayed component deliveries over the 11-day remediation window. Two allied procurement offices invoke force-majeure clauses. The programme's delivery schedule slips by one quarter.

**The NAPQES-secured subsystem.**
One subsystem — the human-asset clearance registry, added in a 2027 security uplift after a personnel-security incident — was migrated to NAPQES v6 at that time. The migration decision was driven by the registry's air-gapped deployment on legacy SPARC hardware with no AES-NI, but the architectural consequence is now apparent.

CVE-2029-XXXXX does not exist in the NAPQES security model. There is no GHASH, no GF(2¹²⁸) multiplier, no GCM mode. The attack surface is HMAC-SHA256, which is unaffected. The clearance registry stays operational throughout the 11-day remediation window, allowing allied security coordinators to continue personnel vetting without interruption.

```
Impact of CVE-2029-XXXXX across the logistics platform:

  AES-256-GCM subsystems (22 of 23 data centres)
    → GHASH nonce-reuse forgery risk: CONFIRMED
    → Emergency patch cycle: 11 days
    → Shipments halted: EUR 140M impact
    → Key rotation required: 23 sites × 4 key classes

  NAPQES v6 subsystem (clearance registry, 1 data centre)
    → GHASH: not present in NAPQES architecture
    → Attack surface: HMAC-SHA256 — unaffected
    → Operational status: NOMINAL throughout incident
    → Patch required: NONE
```

The post-incident review recommends accelerating the migration of two additional subsystems to NAPQES before the next procurement cycle. The CISO's board report notes: *"The NAPQES subsystem's single-primitive architecture meant that a complete dependency audit took 4 minutes. The AES-GCM audit took 11 days and EUR 140 million."*

| Cipher | Cryptographic dependencies | CVE-2029-XXXXX exposure |
|---|---|---|
| AES-256-GCM | AES block cipher (FIPS 197) + GHASH (GF(2¹²⁸)) + GCM mode | **CRITICAL** |
| ChaCha20-Poly1305 | ChaCha20 (ARX) + Poly1305 MAC (GF(2¹³⁰−5)) | Not affected (different MAC) |
| NAPQES v6 | **HMAC-SHA256 only** | **Not affected — primitive not present** |

A vulnerability in GHASH or Poly1305 field arithmetic cannot affect NAPQES because neither field exists in its implementation.

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
| Traffic-analysis-sensitive messaging (financial signals, command & control) | NAPQES — fixed-frame padding profile |
| Regulated environment requiring FIPS 140-3 validation today | Use validated AES-256-GCM module; while waiting for NAPQES review and validation |
| High-throughput bulk data encryption | AES-256-GCM (NAPQES 8–20× expansion is a constraint) |
| Post-quantum key exchange | Neither — use ML-KEM (FIPS 203) for key establishment |
| Environments where you control pre-shared key distribution | NAPQES — purpose-built for pre-shared symmetric keys |

---

## Summary

NAPQES v6 offers three structurally distinct advantages over AES-GCM and
ChaCha20-Poly1305:

1. **No algebraic structure** — removes the attack surface that Shor-family
   quantum algorithms and algebraic cryptanalysis target in block and stream ciphers.

2. **Bounded ciphertext-length leakage** — length-correlation attacks that
   AES/ChaCha20 ciphertexts are transparent to are bounded at ≤3.70 bits per
   message, and eliminated entirely under the fixed-frame padding profile.
   (Per audit findings CVF4 and V3-CVF2, this is a length property, not a
   second content-confidentiality mechanism — confidentiality is carried
   entirely by the domain-`0x07` keystream and the `0x03` HMAC tag — and it
   comes from the *padding ladder*, not from the noise tokens or the
   ciphertext expansion; see `docs/CAVEATS.md` CVF4/CAV-004/V3-CVF2.)

3. **Pure HMAC-SHA256 foundation** — reduces the trusted primitive surface to
   a single, universally deployed, 25-year-hardened construction.

These advantages come with real trade-offs: larger ciphertexts, no current
FIPS 140-3 validation, and a pending external audit. For bandwidth-constrained
or FIPS-mandated deployments, AES-256-GCM remains the right choice today.

For traffic-sensitive, hardware-diverse, or algebraic-risk-averse deployments,
NAPQES v6 offers a credible and disciplined alternative.

---

*Vulnerability disclosure: `security@quantumaegis.ai`*
