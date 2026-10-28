# NAPQES — Independent Security Audit Summary

*For stakeholders, distributors and customers · Epineon · October 2026*

> **In short.** NAPQES, Epineon's encryption scheme, was independently
> reviewed by **ABDK Consulting** in **four review rounds** between July and
> October 2026. The rounds covered both the published specification and the
> reference software. The findings dropped in severity from round to round:
> the final round reported **no critical and no major issues**. The
> auditors concluded that *"the v8 encryption path is sound, and we found no
> way to break it from outside."* The protocol described in the
> specification is the one Epineon implements and ships.

---

## 1. What NAPQES is

NAPQES (*Noise-Augmented Post-Quantum Encryption Scheme*) protects data in
two ways at once:

- **Confidentiality.** Only the holder of the key can read the data.
- **Integrity.** Any change to the protected data, even a single bit, is
  detected, and the data is rejected.

Schemes that provide both are known as *authenticated encryption*. This is
the property modern standards such as TLS 1.3 require.

**One well-studied building block.** NAPQES is built entirely on
**HMAC-SHA256**, a standardised and widely deployed cryptographic function
(NIST FIPS 198-1 and FIPS 180-4). It does not depend on the mathematical
problems behind RSA or elliptic-curve cryptography, which a large quantum
computer is expected to break. Symmetric schemes keyed with 256-bit secrets,
like NAPQES, are generally considered to remain robust against quantum
attacks.

**How it works, in plain terms:**

1. **Two independent secrets.** Each key has two parts that are generated
   separately: a set of large prime numbers and a 256-bit secret. All
   security guarantees for the current format rest on the 256-bit secret.
2. **A unique fingerprint per message.** A message-specific value is
   derived from the message and its context, instead of relying on a random
   number that must never repeat. An observer can tell when exactly the same
   message is sent twice under the same key and context. In exchange,
   accidental misuse is far less dangerous than in many common schemes.
3. **Hiding in noise.** Each character becomes a large number, mixed with
   secret-derived decoy values ("noise"), and the whole stream is then
   masked.
4. **Hiding the length.** Messages are padded to fixed size bands, so an
   observer learns at most the band. A stricter profile hides the length
   entirely.
5. **Seal before open.** Every encrypted message carries a cryptographic
   seal. The seal is checked **before** any decryption takes place, so
   tampered data is rejected without revealing anything.

**Implementations.** Epineon maintains three implementations: Rust (the
reference implementation), Python and C. All three produce identical
outputs, and this is checked automatically against shared test vectors.

---

## 2. Who audited it

**ABDK Consulting** is an independent security firm established in 2016.
Its team has conducted more than 300 audits and co-designed widely used
cryptographic primitives such as the Poseidon hash function. The NAPQES
reviews were led by **Dmitry Khovratovich**, a cryptographer who
co-designed the Argon2 password-hashing standard (RFC 9106).

---

## 3. The review rounds

| Round | Date | What was reviewed | Outcome |
|---|---|---|---|
| 1 | July 2026 | Specification (research paper), version 1 | 32 findings: 2 critical, 14 high, 16 moderate or low. Epineon revised the specification in response. |
| 2 | July 2026 | Specification, version 2 | 27 of the 32 earlier findings fixed, 3 partly fixed, 2 kept by design. 14 new, mostly low-severity findings. |
| 3 | August 2026 | Specification, version 3 | 18 of 19 carried-over findings fixed, 1 partly fixed, none unresolved. The auditors found that version 3 *"repairs every soundness defect the previous rounds identified in the security analysis"*. |
| 4 | Sept.–Oct. 2026 | **Reference software (Rust)**, checked against the specification, version 4 | 37 findings in the initial code. After Epineon's fixes, 25 were fully and 12 partly resolved, with none left unresolved and none worse. The follow-up review of the fixed code found **no critical or major issues**. **Final report v1.0: 27 October 2026.** |

After the final review, Epineon addressed every remaining follow-up item.
The fixes were published openly, one change per item. ABDK's final report
includes Epineon's response to each item, and Epineon publishes a
point-by-point record of these fixes alongside the report.

---

## 4. What the auditors concluded

From the final report (ABDK Consulting, v1.0, 27 October 2026):

> *"The v8 encryption path is sound, and we found no way to break it from
> outside."*

> *"Overall, the implementation is careful and close to the construction
> that the paper describes, and the client's fixes resolved most of the
> problems we found."*

> *"The specification now describes the scheme that the code computes: a
> re-implementation from the updated specification reproduced all
> twenty-two positive v8 test vectors."*

---

## 5. What we ship is what was audited

- **Specification and software match.** The auditors wrote their own
  implementation from the specification alone. It reproduced the outputs
  of Epineon's reference software byte for byte.
- **Three implementations, one behaviour.** The Python and C
  implementations are tested against the same test vectors as the audited
  Rust reference and must match it exactly.
- **Safe defaults.** A standard build exposes only the audited format
  (v8). The legacy format, kept only for reading archived data, and an
  experimental streaming mode are switched off unless explicitly enabled.

**Further evidence, beyond the audit:**

- start-up self-tests modelled on FIPS 140-3;
- automated fuzz testing with malformed inputs;
- statistical timing tests that check the seal comparison does not leak
  information;
- the NIST SP 800-22 randomness tests applied to encrypted output.

---

## 6. Scope and limits — please read

- **An audit is a snapshot, not a guarantee.** In ABDK's words, an audit
  is *"not a guarantee of absolute security but rather a snapshot of the
  system's security posture at a specific point in time."*
- **What was covered.** ABDK reviewed the NAPQES specification in rounds 1
  to 3 and the Rust reference implementation in round 4. The Python and C
  implementations were not delivered to ABDK; they match the reference
  through the shared test vectors.
- **What was not covered.** Integration components, such as key exchange,
  the industrial gateway and the protocol adapters, were outside the audit
  scope.
- **The last round of fixes is self-reported.** ABDK has not verified the
  fixes Epineon made after the final review, nor the latest specification
  revision (4.2). Both are documented publicly so that anyone can check
  them.
- **No certification is implied.** NAPQES has not been certified under
  FIPS 140-3 or any other scheme. As a recent design, it benefits from
  continued independent review.

---

## 7. Documents and contact

| Document | Audience |
|---|---|
| ABDK final audit report v1.0 (`docs/review/epineon-napqes-v4-public-report-v1.0.pdf`) | Technical, full detail |
| Epineon post-audit addendum (`docs/review/epineon-napqes-v4-post-audit-addendum.md`) | Technical, fix-by-fix record |
| NAPQES specification, revision 4.2 (`docs/napseq-eprint-v4.tex`) | Technical, cryptographers |
| Source code: <https://github.com/Synergeon-epineon/NAPQES> | Engineers |

Security questions: **security@epineon.com**

---

*This summary was prepared by Epineon. It is not an ABDK Consulting
document and has not been reviewed or endorsed by ABDK. Quotations are from
ABDK's public report v1.0. If this summary and that report differ, the
report prevails.*
