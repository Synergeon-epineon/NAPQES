# NAPSEQ Known Caveats — Issue Triage

**Status:** Phase 0 baseline (2026-05-12)
**Wire format:** v6 (frozen — see [`SPEC.md`](../SPEC.md))
**Owner placeholders:** replace with GitHub username when repo is published.

This file serves as the issue-tracker stand-in until the repository moves to
a public host with native issue tracking. Migrate each entry to a GitHub issue
at that point and update this file to reference the issue number.

---

## CAV-001 — Streaming API releases unverified plaintext (RUP)

| Field | Value |
|---|---|
| **ID** | CAV-001 |
| **Severity** | High (API misuse could propagate attacker-controlled data before auth fails) |
| **Affects** | `decrypt_stream` (napqes.py L519–651) |
| **Introduced** | v5 streaming API |
| **Owner** | TBD |
| **Target phase** | Phase 3 (workstream 3.6) — replace with online-AE semantics where decrypt never releases plaintext before tag verify |
| **Risk retired** | R9 |

**Description.** `decrypt_stream` yields plaintext characters to the caller
before the HMAC-SHA256 authentication tag at the end of the stream has been
verified. An active attacker who can truncate or modify the stream causes
partial plaintext to be emitted before the `ValueError` is raised.

**Current mitigation.** `decrypt_stream` now requires
`enable_unauthenticated_streaming=True` (keyword-only, default `False`).
Calling without the flag raises `ValueError` with a message directing the
caller to `decrypt_stream_strict`. `decrypt_stream_strict` (napqes.py L653–)
buffers all decrypted characters and only returns after successful tag
verification — no plaintext escapes on auth failure.

**Phase 3 fix.** Implement online authenticated encryption (e.g. segment-level
tags or a sponge construction) so that the streaming decrypt path never holds
unverified plaintext, allowing true streaming without buffering. Design doc
in ROADMAP.md §5 step 3.6.

---

## CAV-002 — 16-bit plaintext length cap (65535 codepoints)

| Field | Value |
|---|---|
| **ID** | CAV-002 |
| **Severity** | Low (hard error; no silent truncation) |
| **Affects** | `_pad_message` (napqes.py L174–195); `encrypt_bytes`, `encrypt_str` |
| **Owner** | TBD |
| **Target phase** | Phase 3 step 3.7 (v7 wire-format design); Phase 5 step 5.4 (ship) |
| **Risk retired** | R10 (partial) |

**Description.** The v6 padding scheme stores the plaintext length as a
2-byte big-endian integer (`len_hi, len_lo`) at the head of the padded
block. This caps block-mode plaintext at `MAX_PLAINTEXT_CODEPOINTS = 0xFFFF`
(65535) codepoints. Exceeding the cap raises `ValueError` immediately —
there is no silent truncation.

**Current mitigation.** Named constant `napqes.MAX_PLAINTEXT_CODEPOINTS`
exported at module level; error message references it and `docs/CAVEATS.md`.
Callers needing larger messages must split at the application layer.

**Phase 3/5 fix.** v7 wire format raises the length prefix to 4 bytes
(cap 2³²). v6 wire format remains the compliance anchor; v7 ships behind a
feature flag only after ≥ 2 customers are blocked by the current cap.

---

## CAV-003 — Padding length-bucket leakage

| Field | Value |
|---|---|
| **ID** | CAV-003 |
| **Severity** | Low (deliberate design trade-off; documented in datasheets) |
| **Affects** | `_pad_message` (napqes.py L174–195); all block-mode callers |
| **Owner** | TBD |
| **Target phase** | Phase 5 step 5.4 (v7 fixed-frame option) — or never if no customer demand |
| **Risk retired** | R10 |

**Description.** `_pad_message` pads plaintext to the next power-of-two
block size (minimum 16). A passive observer seeing ciphertext length can
therefore infer which power-of-two bucket `{16, 32, 64, …, 65536}` the
plaintext length falls into, disclosing up to `⌈log₂(n)⌉` bits of length
information.

**Current mitigation.** Leakage is disclosed in BRD.md §6 item 5,
module docstring (napqes.py L11–14), and SPEC.md §6. Customers requiring
full length-hiding must layer a fixed-frame transport.

**Phase 5 option.** v7 wire format includes a documented fixed-frame
padding option that hides plaintext length entirely. Ship only if customers
request it.

---

## CAV-004 — Ciphertext expansion bound

| Field | Value |
|---|---|
| **ID** | CAV-004 |
| **Severity** | Informational (no security impact; relevant to bandwidth-constrained deployments) |
| **Affects** | `encrypt_bytes`, `encrypt_str`; token-layer expansion |
| **Owner** | TBD |
| **Target phase** | Documented in SPEC.md; no fix planned |
| **Risk retired** | None |

**Description.** Each plaintext codepoint is encrypted as one integer token
encoded as a base-128 varint. Token values are of order `char × key_element`
where `key_element ∈ [1 000 000, 9 999 999]` by default, producing values in
roughly `[32 × 10⁶, 127 × 10⁷]` — typically 3–4 varint bytes per token.
Noise tokens (HMAC-derived probability ∈ [0.75, 0.99]) inflate ciphertext
further. Plus 16-byte nonce + 32-byte tag overhead.

Compared to AES-GCM the expansion is substantial (typically 8–20×). This is
by design — noise tokens are a confidentiality feature, not compression.
The v6 binary format is ~53% smaller than the legacy v3 hex encoding.

**No fix planned.** Expansion is a core property of the design. Document
the expansion bound explicitly in all datasheets.
