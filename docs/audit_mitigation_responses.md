# NAPQES — Responses to Audit Review Findings

This document records the project's formal response to each external audit
finding, for posting back to the auditor's tracking system. Each entry
mirrors the finding's ID and is updated in place as status changes.

---

## CVF1 — Ciphertext byte-length leaks plaintext content (IND-CPA theorem false as proved)

**Status:** Open → **Fixed**
**Category:** Flaw

### Response

Confirmed. The finding is correct as written: the v6 wire format serialised
each token (`token = codepoint × key_element + addend`) with unsigned
LEB128 *before* the domain-`0x07` XOR mask, and LEB128's byte-length grows
with magnitude. Since token magnitude scales with the plaintext codepoint,
two plaintexts with equal padded codepoint count — and therefore identical
padding bucket, noise pattern, noise tokens, and addends — could still
produce ciphertexts of different byte-length depending on codepoint
*value*. The mask is length-preserving, so it does not hide this, and the
distinguisher described (`n` × U+0001 vs. `n` × U+FFFF) gives an IND-CPA
advantage ≈ 1. We also agree the hiding-lemma step "since B is the same
length for both plaintexts m0, m1 (they have equal padded lengths by the
IND-CPA requirement)" was asserted without justification and is false under
the variable-width v6 encoding.

**Fix shipped (v7 wire format, 2026-07-06).** Every token is now serialised
as a constant-width, 8-byte big-endian field instead of a LEB128 varint
(`napqes._fixed_encode_tokens` / `_fixed_decode_tokens`, and equivalent
`fixed_encode_tokens` / `fixed_decode_tokens` functions in the Rust core and
C port). The serialised blob length is now `token_count × 8`, and
`token_count` is a function only of the padded codepoint count and the
HMAC-derived, content-independent noise schedule (domain `0x00`) — never of
codepoint values. This directly implements the recommended remediation
("encode each token in a fixed-width field ... sized for the maximum
`c·k+a`").

The hiding lemma in `docs/napseq-eprint-preprint.tex` (Theorem 1) has been
corrected: the false step has been replaced with an explicit argument for
why `|B|` is now identical across the challenge plaintexts under a fixed
nonce (Section "Wire Format (Version 7 — CVF1 fix)"), and an erratum remark
(`sec:hiding-lemma-erratum`) documents precisely why the original v6 step
was invalid.

**Scope of the fix:**
- Python reference (`napqes.py`), Rust core (`rust/src/lib.rs`), and C port
  (`C/napqes.c`) all updated in lockstep; cross-language byte-identical
  output re-verified against a regenerated KAT corpus
  (`tests/kat/v6_vectors.json`) and `tests/test_cross_lang.py`.
- `SPEC.md`, `docs/CAVEATS.md`, `docs/draft-napqes-aead-00.md`, and
  `docs/SECURITY_TARGET.md` updated to describe the v7 format and
  cross-reference this finding.
- Legacy v6 ciphertexts remain fully authenticated and can still be
  decoded via explicit opt-in (`legacy_v6_varint=True`); they were never
  vulnerable to tampering, only to the length side channel described here.
- Full regression suite re-run: 245 Python tests, 73 Rust unit tests
  (including regenerated self-test KAT vectors), the Rust and C KAT
  harnesses, and the Python↔Rust↔C cross-language interoperability test
  all pass against the new v7 vectors.

**Known residual (tracked separately, not part of this finding's scope).**
The streaming API (`encrypt_stream` / `encrypt_stream_ae`) still uses the
LEB128 encoding and exhibits the same magnitude-dependent length pattern.
This does not reopen an IND-CPA break for that API, since streaming mode
already discloses the exact plaintext length by design (no padding is
applied there). We've logged it as a CVF1 follow-up in `docs/CAVEATS.md`
for defence-in-depth and will address it in a subsequent fix.

**Requested action:** please confirm CVF1 can be marked **Fixed / Closed**
on your tracker. Full technical detail and file-by-file changes are in
`logs/fixes_06072026.md`.

---

## CVF2 — Domain-separation layout inconsistent between Table 1, the security proofs, and the reference code

**Status:** Open → **Fixed** (pending C-toolchain compile verification, see below)
**Category:** Behavior

### Response

Confirmed. The finding is correct as written: three descriptions of the
per-domain HMAC input disagreed. Table 1 stated a single nonce-first
formula `Derive_d(kb, N, ctx) = HMAC(kb, N‖d‖ctx)` for all domains. The
`rem:domsep` remark and the "OTP argument" instead treated domains
`0x00,0x01,0x02,0x04,0x05,0x06,0x07` as nonce-first and
`0x02` (17 B) / `0x03` (AAD-binding) as a separate "domain-first group",
reasoning about a cross-group collision *probabilistically*
(`q/2^32`) rather than proving separation unconditionally. The reference
code's authentication tag, and the streaming-AE chunk/final tags
(`0x08`, `0x09`), were genuinely domain-first and AAD-binding
(`d‖be4(|A|)‖A‖N‖…`) — matching neither the nonce-first Table 1 formula
nor being consistently described anywhere as a third pattern. The
wire-format tag's inline formula, `T = Derive_0x03(kb, N‖B̃)`, omitted the
AAD outright, so a reader modelling the scheme purely from Table 1 plus
that inline formula would conclude the AAD is unauthenticated — which is
false of the shipped code, but the *documented* scheme did not prove
otherwise. We agree this is a real gap: domain separation underpins every
confidentiality/integrity claim in the security analysis, and having the
spec, proof, and code disagree on the HMAC input layout means the proof
did not unconditionally apply to the code that was running.

**Fix shipped (domain-first unification, 2026-07-06).** All ten domains
(`0x00`–`0x09`) now share one layout:
`Derive_d(kb, N, ctx) = HMAC(kb, d‖N‖ctx)`, with every variable-width field
length-prefixed (`be4(|A|)‖A` for AAD). Concretely: the domain byte moved
*before* the nonce for the seven domains that were nonce-first
(`0x00,0x01,0x02,0x04,0x05,0x06,0x07`), and the nonce moved from *after*
the AAD to *immediately after* the domain byte for the three domains that
were AAD-binding (`0x03,0x08,0x09`). This directly implements the
recommended remediation, and domain separation is now proved
unconditionally rather than probabilistically:

- **Cross-domain:** any two inputs with different domain bytes differ at
  byte 0 — they can never collide, regardless of nonce or context.
- **Intra-domain:** the nonce occupies the fixed byte 1‥16 offset in every
  domain; the remaining context is either a fixed-width counter
  (domains `0x00,0x01,0x04,0x05,0x06,0x07`) or a length-prefixed,
  AAD-binding suffix (domains `0x03,0x08,0x09`), both of which are
  injective. No probabilistic cross-group term is required.

`docs/napseq-eprint-preprint.tex` Table 1 (`tab:domains`), the `Derive_d`
definition, the wire-format tag formula (now explicitly
`T = Derive_0x03(kb, N, be4(|A|)‖A‖B̃)`, with the AAD included), the
`rem:domsep` remark, the "OTP argument" paragraph, the authentication-tag
freshness argument in the IND-CPA proof, and the streaming-AE tag formulas
were all rewritten to the unified layout and the unconditional injectivity
argument, closing the cross-reference to issue #848 (that probabilistic
cross-group collision term now vanishes unconditionally rather than being
merely bounded).

**Scope of the fix:**
- Python reference (`napqes.py`), Rust core (`rust/src/lib.rs`), and C port
  (`C/napqes.c`) all updated in lockstep. In C, seven of the nine domains
  route through one shared helper (`hmac_with_sep`), so a single change
  fixed them at once; the authentication-tag construction was separately
  restructured in all three languages.
- `SPEC.md` §3 (all per-domain formulas), the domain-byte summary, §6
  (padding), and §8.1 (streaming-AE chunk/final tags) updated to the
  unified layout, with a note clarifying this does **not** require a new
  wire-format version designator (the outer `nonce‖masked_blob‖tag` byte
  layout is unchanged; only the internal HMAC inputs were reordered).
- KAT vectors regenerated (`tests/kat/v6_vectors.json`, 37 vectors) after
  also fixing a local reimplementation of the streaming-AE tag
  construction in `tests/gen_kats.py` that did not call into `napqes.py`
  and so was not automatically covered by the Python fix.
  `rust/src/self_test.rs`'s embedded KAT constant was regenerated for the
  same key/nonce/message used previously.
- Every derived value (noise positions, addends, keystream, authentication
  tags) changes shape under this fix. There is no legacy opt-in, unlike
  CVF1's `legacy_v6_varint`: the pre-fix layout was never a deployed,
  versioned wire format — it was an internal inconsistency between the
  spec, the proof, and the code, not a ciphertext format users could have
  persisted and now need to migrate off of.
- Full regression suite re-run: 245 Python tests (1 pre-existing,
  unrelated skip), 73 Rust unit tests, and 3 Rust KAT integration tests
  all pass against the regenerated vectors.

**Known residual.** The C reference port (`C/napqes.c`, `C/test_kats.c`)
could not be compiled or KAT-verified in this environment (no `gcc`/
`clang`/`cl` toolchain available, only GNU `make`). The C changes were
written to mirror the Python/Rust logic exactly, routing through the
existing shared `hmac_with_sep` helper for seven of the nine domains to
minimise the chance of a transcription error, but we have not yet run
`make -C C kat-test && C/kat-test.exe` against the regenerated
`tests/kat/v6_vectors.json` to confirm. We recommend doing so (or having
CI do so) before this finding is marked fully closed.

### Comment (2026-07-06)

Confirmed the issue as reported: Table 1, the `rem:domsep` remark, and the
reference code each described a different HMAC input layout for the
per-domain derivations, and the wire-format tag formula silently dropped
the AAD when read through Table 1's stated formula — exactly as described.

Resolved by adopting the recommended single domain-first, length-prefixed
layout, `Derive_d(kb, N, ctx) = HMAC(kb, d‖N‖ctx)`, for all ten domains
(`0x00`–`0x09`) in `napqes.py`, `rust/src/lib.rs`, and `C/napqes.c`, and by
rewriting `docs/napseq-eprint-preprint.tex` (Table 1, `rem:domsep`, the
"OTP argument", the tag-freshness step, and the wire-format tag formula) to
prove domain separation unconditionally — cross-domain inputs differ at
byte 0, and intra-domain inputs are injective because the nonce sits at a
fixed offset followed by a fixed-width counter or length-prefixed AAD. The
probabilistic cross-group collision term is gone; issue #848 is closed by
this change, as it tracked exactly that term. `SPEC.md` and
`docs/draft-napqes-aead-00.md` were updated to match. The AAD is now
authenticated identically and unambiguously in the spec, the proof, and the
code.

Python (245 tests) and Rust (73 unit + 3 KAT tests) suites pass against
regenerated KAT vectors reflecting the corrected derivation. C changes
mirror the same logic (and share a single helper function for 7 of the 9
domains) but have not yet been compiled/KAT-verified in this environment —
see "Known residual" above.

**Requested action:** please confirm CVF2 can be marked **Fixed**, subject
to independent confirmation of the C KAT harness once run in an
environment with a C toolchain. Full technical detail and file-by-file
changes are in `logs/fixes_06072026.md`.

---

## CVF3 — Nonce reuse yields key recovery via the length channel — contradicting the Table 4 "No" claim

**Status:** Open → Partially fixed (2026-07-06) → **Fully fixed for v8** (2026-07-07,
see Follow-up below); v7 retains the documented, disclosed residual
**Category:** Flaw

### Response

Confirmed, and the finding is in fact broader than described. As stated:
every internal value NAPQES derives — noise positions (`0x00`), noise
characters (`0x04`), addends (`0x01`, `0x05`), padding (`0x06`), and the
keystream (`0x07`) — is a deterministic function of `(kb, N)` only via
`Derive_d(kb, N, ctx) = HMAC(kb, N‖d‖ctx)`; nothing else is random. A
repeated nonce reproduces an identical keystream and identical
noise/addends (a two-time pad), and Table 4's advertised
`Nonce-reuse key recovery: No` is false — it is a real disadvantage versus
AES-GCM and ChaCha20-Poly1305, not an advantage.

We can also confirm the LEB128-boundary-detection escalation route you
describe is now closed for the block API by the CVF1 fix (fixed-width
8-byte tokens shipped 2026-07-06): there is no longer a ciphertext-length
transition to binary-search on. **However, closing that route does not fix
the underlying key-recovery hazard**, and we want to be transparent that a
strictly more direct route remains and requires no length channel at all:
because the domain-`0x07` mask is a plain XOR and the real-token map
`c ↦ c·k + a` is an exact (non-modular) affine function, XOR-cancelling two
ciphertexts produced under one reused nonce yields the exact plain
fixed-width token values once one plaintext codepoint at a given real-token
position is known (known-plaintext, not chosen-plaintext, is sufficient).
Two such known `(c, token)` pairs at the same position give
`k = (t1 - t2)/(c1 - c2)` exactly. Repeating this for each of the `K`
key-tuple positions fully recovers the key. This is strictly worse than an
ordinary stream cipher's confidentiality-only nonce-reuse loss, and worse
than AES-GCM/ChaCha20-Poly1305 losing only their authentication key under
reuse — confirming your assessment that this is worse than a standard
two-time pad, independent of the length-channel escalation you described.

**Fix shipped (2026-07-06).**
- **Table 4 corrected.** `docs/napseq-eprint-preprint.tex`'s comparison
  table now states `Nonce-reuse key recovery: Yes (catastrophic)` for
  NAPQES, with a footnote proving the exact algebraic recovery above and a
  new subsection ("Nonce Reuse Is Key-Recoverable, Not Merely
  Confidentiality-Losing", §Implementation) spelling out why the CVF1 fix
  does not and cannot close this route. The same false "HMAC prevents
  direct algebraic recovery of the master key" / "standard AEAD
  limitation" claims were also present in `comparator.py` (the
  auto-generated comparison-table source) and `docs/SECURITY_TARGET.md`
  ("Nonce reuse" and "Key-recovery from ciphertext" rows, and the "Nonce
  freshness" assumption); all three were corrected in lockstep to state the
  key-recovery risk plainly and cross-reference this finding.
- **Caller-chosen-nonce entry points restricted, per the recommendation.**
  `rust/src/lib.rs`'s `encrypt_bytes_with_nonce` — an explicit-nonce
  encrypt path used internally by the FIPS power-on self-test and KAT
  verification — was `pub`, i.e. reachable by any external consumer of the
  crate to encrypt real data with a caller-chosen nonce. It is now
  `pub(crate)`, removing it from the crate's public API entirely while
  remaining available to the in-crate self-test and a new in-crate KAT
  test module (`rust/src/kat_cross_check.rs`, replacing the external
  `rust/tests/kats.rs`, which required `pub` visibility and has been
  removed; `tests/test_cross_lang.py` now invokes
  `cargo test --lib kat_cross_check`). The equivalent C function,
  `napqes_encrypt_bytes_with_nonce` (`C/napqes.c` / `C/napqes.h`), is now
  compiled only when `NAPQES_ENABLE_TEST_NONCE_API` is defined; the
  default `napqes.o` / `napqes_demo` build no longer defines this macro, so
  the symbol is entirely absent from the production library, and only
  `make kat-test` (which now compiles a separate, macro-enabled object)
  links against it. The Python reference implementation never exposed a
  public encrypt function accepting a caller-supplied nonce; its one
  internal helper (`tests/gen_kats.py`'s `_encrypt_with_nonce`) was already
  underscore-private and test-only, so no Python change was required.
- Full regression suite re-run: 245 Python tests (1 pre-existing,
  unrelated skip), 76 Rust unit tests (up from 73 — includes the relocated
  `kat_cross_check` module and confirms the FIPS self-test, which still
  calls the now-`pub(crate)` `encrypt_bytes_with_nonce` internally,
  continues to pass), and `tests/test_cross_lang.py`'s Rust↔Python
  cross-language checks all pass against the updated invocation.

**Known residual — not closed by this response, and cannot be closed by
documentation alone.** Restricting the misuse-prone entry point and fixing
the documentation removes a foot-gun and an inaccurate claim, but it does
not change the underlying cryptographic property your finding identifies:
NAPQES nonce reuse remains catastrophic and key-recoverable however a
repeated nonce arises (DRBG failure, restart-and-replay, or any future
caller-supplied-nonce API). The 128-bit random nonce makes *accidental*
reuse a ≈ 2⁶⁴ birthday event, and the Rust core additionally runs a
consecutive-nonce CRNG continuity check (SP 800-140B §4.9.2) that would
catch two back-to-back identical nonces from a failed DRBG — but this does
not catch reuse across restarts, separate processes, or replayed
ciphertext, and no equivalent check exists in the Python or C reference
implementations. We agree with your recommendation that a
misuse-resistant / synthetic-IV design (deriving the nonce deterministically
from the message and key, as in AES-GCM-SIV) is the correct long-term fix
if misuse resistance is to be a design goal; that is a wire-format and
protocol change we have not implemented, and we are tracking it as a CVF3
follow-up in `docs/CAVEATS.md` rather than claiming it is closed here.
The C side of this response (the `NAPQES_ENABLE_TEST_NONCE_API` gating)
also could not be compiled/verified in this environment — no C toolchain
available, same known residual as CVF2.

### Comment (2026-07-06)

Confirmed the issue as reported, and want to flag that it's actually
broader than described: every internal NAPQES value (noise positions,
addends, keystream) is a deterministic function of `(key, nonce)` alone,
so a repeated nonce is a two-time pad, and Table 4's `Nonce-reuse key
recovery: No` claim is false. The LEB128-boundary-detection escalation
route you describe is now closed for the block API by the CVF1 fix, but
that does **not** close the underlying hazard — a more direct route
survives it: under a reused nonce, XOR-cancelling two ciphertexts plus one
known plaintext codepoint at a given token position yields the exact token
integer, and two such known-plaintext tokens at the same position solve
`k = (t1-t2)/(c1-c2)` exactly, recovering that key element with no length
channel and no chosen-plaintext requirement. This confirms your
"strictly worse than a standard two-time pad" assessment independent of
the length-channel path you outlined.

Fixed: Table 4 in `docs/napseq-eprint-preprint.tex` now states
`Nonce-reuse key recovery: Yes (catastrophic)` with a footnote proving the
exact recovery above; the same false claim in `comparator.py` and
`docs/SECURITY_TARGET.md` was corrected in lockstep. Per your
recommendation to restrict caller-chosen nonce entry points outside
testing: `rust/src/lib.rs`'s `encrypt_bytes_with_nonce` is now
`pub(crate)` instead of `pub` (its KAT test moved in-crate to
`rust/src/kat_cross_check.rs`, replacing the external
`rust/tests/kats.rs`), and C's `napqes_encrypt_bytes_with_nonce` now
compiles only under `-DNAPQES_ENABLE_TEST_NONCE_API`, absent from the
default `napqes_demo` build. Python never exposed a public nonce-taking
encrypt function, so no change was needed there.

Python (245 tests) and Rust (76 unit tests, up from 73) suites pass, as
does `tests/test_cross_lang.py`'s Rust↔Python cross-language check against
the updated invocation. The C side has not been compiled/verified in this
environment — see "Known residual" above.

We are **not** claiming the underlying nonce-reuse key-recovery property
of v7 is fixed by the 2026-07-06 response — that requires the
misuse-resistant / synthetic-IV redesign described as a follow-up there.
That redesign is now shipped; see the Follow-up below.

**Requested action (2026-07-06):** please confirm CVF3's Table 4 correction and
misuse-entry-point restriction can be marked **Fixed**, while keeping the
underlying "nonce reuse is catastrophic for NAPQES" item **Open** pending a
misuse-resistant design, which we are not asserting is complete. Full
technical detail is in `docs/CAVEATS.md` (CVF3).

### Follow-up (2026-07-07): v8 misuse-resistant key schedule fully closes CVF3

The misuse-resistant / synthetic-IV redesign flagged as out of scope above
is now shipped. `rust/src/lib.rs` adds `generate_v8_key`,
`encrypt_bytes_v8`, and `decrypt_bytes_v8`, which replace the CSPRNG
nonce with a synthetic IV in the style of RFC 5297 SIV / AES-GCM-SIV:

```
N = HMAC(sk, 0x0A || be4(len(aad)) || aad || message)[0:16]
```

keyed by an HMAC subkey `sk` that is sampled independently of the
arithmetic-layer prime tuple (see the CVF13 follow-up below for why
independence, not mere derivation from the existing key, is required).
Because the nonce is now a deterministic PRF of `(sk, aad, message)`, two
*different* `(aad, message)` pairs can share a nonce only via an
HMAC-SHA256 collision — cryptographically negligible — so the
affine-cancellation key-recovery route this finding describes (which
requires two *different* known plaintexts under one *reused* nonce) is
closed by construction, not merely made statistically unlikely, as the
≈ 2⁶⁴-birthday-bound v7 nonce did. This is proved formally as
`Lemma lem:v8-cvf3` in `docs/napseq-eprint-preprint.tex`, new subsection
"V8 Key Schedule and Synthetic Nonce" (`sec:v8`).

This is the standard, disclosed MRAE trade-off (misuse resistance in
exchange for determinism): re-encrypting the *identical* `(aad, message)`
pair under the same v8 key reproduces the identical ciphertext, disclosing
only plaintext equality — never a key-recovery or confidentiality break.
Callers who need probabilistic ciphertexts even for repeated identical
messages should keep using the v7 random-nonce API (`encrypt_bytes`),
which retains the previously-disclosed residual. v7 and v8 ciphertexts are
byte-shape-identical but not interoperable with each other; per the CVF7
format-selection philosophy, callers must agree out-of-band on which
schedule a given key/ciphertext uses.

**Scope:** `rust/src/lib.rs` only (new, additive functions; no existing
function changed) plus `docs/napseq-eprint-preprint.tex` (new subsection
`sec:v8`) and `docs/CAVEATS.md` (CVF3 entry updated). Verified by four new
unit tests: `v8_roundtrip`, `v8_wrong_aad_fails`, `v8_tamper_fails`,
`v8_same_message_is_deterministic`, `v8_distinct_messages_have_distinct_nonces`
(83 Rust tests pass in total, up from 76). The Python and C reference
implementations have not yet been ported to v8; tracked as a follow-up so
all three languages offer the misuse-resistant path.

**Requested action:** please confirm CVF3 can be marked **Fixed** for the
v8 key schedule, with v7 retaining its previously-disclosed, unchanged
residual for callers who have not migrated.

---

## CVF4 — Prime-token/noise layer contributes zero confidentiality; the hiding lemma reduces entirely to domain `0x07`

**Status:** Open → Partially fixed / narrative correction proposed (2026-07-07) →
**Fixed** (2026-07-07, see Follow-up below: the one remaining stale
passage found by a workspace-wide sweep was corrected)
(the code is not changed; the finding is correct about the *content*-hiding
property and requires us to stop conflating it with a different, genuine
property the layer does provide — see below)
**Category:** Behavior / Narrative

### Response

**Confirmed as proved.** We checked this against both the reference code
and the formal argument in `docs/napseq-eprint-preprint.tex`, and the
finding is correct: the "OTP argument" (lines ~514–533, immediately
preceding Lemma `lem:hiding`) constructs `ks(N*)` purely from
domain-`0x07` outputs, proves it independent of `B` using only
cross-domain distinctness (Remark `rem:domsep`), and concludes
`B̃ = B ⊕ ks(N*) ≡ Uniform` **for any fixed deterministic `B`** — the proof
never inspects what `B` contains. Since `B` is exactly where the prime
multiplication (`token = c·k + a`) and the noise tokens live, the formal
hiding/IND-CPA argument is, as you say, indifferent to that structure by
construction. If the `0x07` derivation were replaced with, e.g., a
constant all-zero keystream, the *proof* would fail, but nothing about the
prime/noise layer's own structure would need to change for that failure —
confirming confidentiality is carried entirely by `0x07` (plus the
`0x03` tag for integrity). We also rechecked the adjacent Remark
(lines ~271–275) claiming real/noise tokens are "computationally
indistinguishable under GCD analysis" via `gcd(token, k) < k`, and found it
does not actually support any indistinguishability claim: because `k` is
prime and every addend `a ∈ [1, k-1]`, `gcd(a, k) = 1` unconditionally for
*every* token, real or noise, key-known or not — the statement is vacuously
true and requires no HMAC, no key, and no noise design to hold. That remark
should be struck; it does no argumentative work and, left in place,
overstates what the construction proves in exactly the way this finding is
about. Table 4's `2^{197}`–`2^{257}` prime-tuple key-space figures and the
"prime indexed token cipher" / "algebra-free" narrative, insofar as they are
read as *confidentiality* claims about per-message ciphertext
indistinguishability, are also not supported by the proof as written and
should not be presented that way.

**Counter-argument: the layer's genuine, distinct contribution is
traffic-analysis resistance, not content confidentiality — and that
property does not reduce to `0x07`.** `docs/PROTOCOL_OVERVIEW.md` §3.3 and
patent PAT-002 already describe the noise-token layer's intended purpose as
resisting *traffic analysis / length-correlation* attacks (ciphertexts of
AES-GCM and ChaCha20-Poly1305 reveal plaintext length exactly; NAPQES's
does not), not as a second confidentiality primitive layered under `0x07`.
That is a different, well-defined security property from IND-CPA content
hiding, and — unlike content hiding — it genuinely does **not** reduce to
domain `0x07` alone:

- The *number* of tokens `N` (and therefore the ciphertext byte length,
  `8N` plus fixed overhead) is fixed by the noise-position oracle
  (domain `0x00`) and the per-message noise probability (domain `0x02`)
  — both evaluated, and `N` fully determined, **before** `B` is ever
  serialised or masked by `0x07`. An adversary who fully broke `0x07`
  (e.g. via nonce reuse per CVF3) recovers the exact token *values*, but
  gains nothing about content *length* beyond what the byte count already
  told them, since that count was never a function of `0x07` in the first
  place. Length-decorrelation from content is therefore a property of
  domains `0x00`/`0x02`, independent of `0x07`'s security.
- This is consistent with, and does not contradict, CVF1: CVF1 showed the
  *v6 wire encoding* let token count/width leak content anyway (fixed by
  the v7 fixed-width fix); it did not show that `0x00`/`0x02` themselves
  depend on content (they never have — the noise schedule is a function of
  `(key, nonce)` only).
- This property is modest in scope (it hides length correlation, not
  content) and does not rehabilitate the `2^{197}`+ key-space figure as a
  *confidentiality* work-factor — that figure is properly a *key-recovery*
  resistance statement about the keyed-HMAC construction as a whole (all
  ten domains share one key), not a statement about what the token
  structure contributes on top of `0x07`.

**Recommendation adopted: a hybrid of your (i) and (ii), not option (ii)'s
literal "redesign the prime layer to carry confidentiality."** We do not
think forcing the prime/noise layer to also do confidentiality work is the
right fix: that would re-couple two orthogonal properties (content hiding
vs. length hiding) inside one XOR-masked structure, which is precisely the
kind of coupling that produced the CVF1 length leak in the first place.
Instead:

- **(i), applied literally to content confidentiality.** The security
  narrative will state plainly, next to Lemma `lem:hiding`, that per-message
  content confidentiality (IND-CPA) rests entirely on domain `0x07` being a
  secure keyed PRF/keystream and on the `0x03` HMAC tag for integrity —
  matching what the proof actually shows, per your finding.
- **(ii), applied to the property the layer actually has, not the one it
  was wrongly credited with.** Rather than redesigning the prime/noise
  layer to (unnecessarily) also prove a confidentiality property, we will
  add a separate, explicit lemma to `docs/napseq-eprint-preprint.tex`
  stating and proving the traffic-analysis-resistance property above (byte
  length is a function of `(key, nonce, padded length)` only, via domains
  `0x00`/`0x02`, independent of codepoint values and independent of
  `0x07`'s security), remove the vacuous GCD remark, and update every place
  that currently calls the noise layer a "confidentiality feature" —
  starting with `docs/CAVEATS.md` CAV-004 (corrected below) — to instead
  call it what the code actually does: a traffic-analysis-resistance /
  length-decorrelation feature.

**Fix shipped now (narrative correction only, no code change).**
`docs/CAVEATS.md` CAV-004's "noise tokens are a confidentiality feature"
has been corrected to attribute the property accurately and cross-reference
this finding.

**Scope of the remaining fix (not yet done — tracked, not claimed
complete):**
- `docs/napseq-eprint-preprint.tex`: add the traffic-analysis-resistance
  lemma described above; remove/replace the vacuous GCD remark
  (lines ~271–275); add a note beside the OTP argument/Lemma `lem:hiding`
  stating explicitly that it is indifferent to `B`'s internal structure,
  citing this finding.
- `docs/SECURITY_TARGET.md`, `docs/PROTOCOL_OVERVIEW.md`: cross-reference
  CVF4 and confirm no other passage implies the prime multiplication itself
  contributes to per-message content confidentiality.
- `comparator.py` / Table 4: confirm the "Noise / traffic-analysis layer"
  row and its supporting text describe length-hiding, not confidentiality
  (spot-checked already — current wording says "length hiding and pattern
  resistance", which is consistent with this response and needs no change).
- `napqes_ip_summary.html` / PAT-001, PAT-002 summaries: check that no
  passage claims the prime multiplication does confidentiality work beyond
  serving as the keyed-HMAC's key material.

**Known residual / what we are not claiming.** We are not claiming the
prime-multiplication step is worthless in every sense — it (together with
the rest of `key_bytes`) is the secret input to every HMAC domain,
including `0x07`, so key-recovery resistance still benefits from the large
prime-tuple key space. We are conceding, as the finding states, that the
multiplicative token structure itself does no *additional* confidentiality
work once `0x07` exists, and that describing it as doing so was inaccurate.

**Requested action:** please confirm CVF4 can be marked **Acknowledged /
narrative-fix-in-progress**, distinguishing (a) the content-confidentiality
claim, which we agree was incorrectly attributed to the prime/noise layer
and is being corrected to cite `0x07` + the `0x03` tag alone, from (b) the
traffic-analysis-resistance claim, which we are retaining and committing to
state as a separately proved property rather than conflating it with (a).

### Follow-up (2026-07-07): remaining stale narrative found and corrected

A workspace-wide sweep for the retired "noise layer = confidentiality"
framing found one file the 2026-07-07 pass above missed:
`docs/NAPQES_Executive_Brief.md`'s summary bullet was still headed
"Noise-token confidentiality layer." It has been retitled to "Noise-token
traffic-analysis-resistance layer," matching the wording already used in
`docs/PROTOCOL_OVERVIEW.md` §3.3 and `docs/CAVEATS.md` CAV-004, with an
inline cross-reference to CVF4/CAV-004. No other file in the repository
(patents, other executive/insurance briefs, the French partner
presentation, `napqes_ip_summary.html`) was found to repeat the retired
framing — they already describe the layer as hiding length/traffic
patterns, not as a confidentiality mechanism. With this correction, no
known passage in the repository still attributes content-confidentiality
work to the prime/noise layer.

**Requested action:** please confirm CVF4 can be marked **Fixed** as a
narrative-only correction, now that the sweep above found and corrected
the one remaining stale passage.

### Comment (2026-07-07)

**Why we are keeping noise inflation rather than adopting option (i)
outright (dropping the layer).** The finding is correct that noise
inflation contributes nothing to *content* confidentiality — that part of
option (i) is accepted, and the narrative now says so plainly next to
Lemma `lem:hiding`. But "the layer does no confidentiality work" is not the
same claim as "the layer does no work," and dropping it would also remove
the one property NAPQES has that AES-GCM/ChaCha20-Poly1305 do not: per
Lemma `lem:tar` (added below), ciphertext byte-length is decorrelated from
plaintext content — it is a function of `(key, nonce, padded length)` only,
via the noise-position oracle and noise probability (domains `0x00`/`0x02`),
never of codepoint values, and this holds independently of whether domain
`0x07` is ever broken. That is a real, provable, distinct property
(traffic-analysis / length-correlation resistance), and it is the actual
basis for PAT-002 and the "Noise / traffic-analysis layer: Yes" row in
Table 4/`comparator.py` — none of which are confidentiality claims once
corrected. We are not keeping the layer to preserve an inflated security
story; we are keeping it because, once mislabelled as "confidentiality" is
removed, a genuine and independently-provable property remains, and
removing the layer would remove that property along with the inaccurate
label. We also declined the literal reading of option (ii) — redesigning
the prime layer so confidentiality depends on it — because coupling
content-hiding and length-hiding back into one XOR-masked structure is the
same kind of coupling that caused the CVF1 length leak; keeping them
architecturally separate is a deliberate choice, not an oversight.

**What was updated to close this out.**
- `docs/napseq-eprint-preprint.tex`: struck the vacuous GCD remark
  (`gcd(token, k) < k` holds unconditionally for every token, real or
  noise, since `k` is prime and `a ∈ [1, k-1]` — it proved nothing and has
  been retracted with an explicit note); added Remark `rem:hiding-scope`
  immediately after Lemma `lem:hiding`'s proof stating explicitly that the
  OTP argument is indifferent to `B`'s internal structure; added new
  Lemma `lem:tar` ("Ciphertext length is decorrelated from plaintext
  content") with its own proof, plus a scope remark distinguishing it from
  Lemma `lem:hiding`.
- `docs/CAVEATS.md` (CAV-004) and `docs/PROTOCOL_OVERVIEW.md` (§3.3,
  retitled from "Noise-token confidentiality layer" to "Noise-token
  traffic-analysis-resistance layer"): reworded to attribute the property
  accurately and cross-reference CVF4.
- `docs/SECURITY_TARGET.md`: corrected the "Passive eavesdropper" row to
  cite `0x07` + the `0x03` tag rather than "token layer + noise tokens";
  split the previously self-contradictory "Traffic analysis: Not
  addressed" row into message timing/volume (still not addressed,
  transport-layer) versus per-message length correlation with content
  (mitigated, citing Lemma `lem:tar`).
- `patents/PAT-001_prime_indexed_token_cipher.md`: corrected "[the
  keystream] adds a second layer of confidentiality over the varint
  encoding" — which implied the token encoding was itself a first
  confidentiality layer — to state plainly that `0x07` is the
  confidentiality mechanism and the token/noise structure's distinct
  contribution is traffic-analysis resistance (PAT-002, Lemma `lem:tar`).
- `comparator.py` and `napqes_ip_summary.html` were checked and required no
  change; their existing wording ("length hiding and pattern resistance")
  was already consistent with the corrected narrative.

No source code changed for this finding — it was entirely a proof/narrative
alignment issue, not a code defect. Full technical detail is in the
Response above.

---

## CVF5 — Construction lacks the formal AEAD algorithm triple, so the scheme is not well defined

**Status:** Open → **Fixed**
**Category:** Architecture

### Response

Confirmed. The Construction section stated notation, key generation,
per-domain HMAC derivation, noise probability, padding, the token-emission
loop, and the wire format, but never assembled them into the formal
algorithm triple an AEAD definition requires: a key-generation/setup
algorithm, an encryption algorithm `Enc(K,N,A,M) → C`, and a decryption
algorithm `Dec(K,N,A,C) → M or ⊥`, each with typed inputs/outputs and a
stated correctness condition — as the Ascon v1.2 submission does. We also
confirm the finding's sharper point: the Security Analysis section already
*invoked* `NAPQES.Enc` and `NAPQES.Dec` (e.g. the INT-CTXT proof writes
`NAPQES.Dec(k, c*, aad*) ≠ ⊥`) without those symbols ever having been
formally defined anywhere upstream, so every theorem was quantifying over
an object that existed only as scattered prose and pseudocode. This is
correctly identified as the root cause behind several other findings
(CVF1's undefined wire-format length behaviour, CVF2's inconsistent
domain-separation layout, and CVF4's ambiguity about what the "hiding"
proof does and doesn't cover) — each of those disagreements was, in part,
a symptom of there being no single object all the prose was required to
agree with.

**Fix shipped (2026-07-07).** Added a new subsection, "The NAPQES AEAD
Algorithm Triple" (`docs/napseq-eprint-preprint.tex`, end of the
Construction section, Definition `def:aead-triple`), that assembles the
already-introduced pieces into the formal triple:

- **`KeyGen(1^λ) → k`:** draws `K` distinct primes uniformly without
  replacement from `𝒫` via CSPRNG rejection sampling
  (`generate_prime_numbers`), outputs `k = (k1,...,kK) ∈ 𝒦`.
- **`Enc(k, N, A, M) → C`:** fully typed over key space `𝒦` (ordered prime
  `K`-tuples), nonce space `𝒩 = {0,1}^128`, AAD space `𝒜 = {0,1}*`, message
  space `ℳ` (Unicode codepoint sequences up to `MAX_PLAINTEXT_CODEPOINTS =
  2^16-1`), and ciphertext space `𝒞`; its seven steps are the pad → emit
  tokens → serialise (`be8` per token) → mask (domain `0x07`) → tag (domain
  `0x03`) → concatenate pipeline already described, now given as one
  numbered algorithm instead of scattered subsections. We additionally made
  explicit a distinction that was previously only implicit: this
  explicit-nonce `Enc` is the internal routine used by the FIPS self-test
  and KAT harness, while the *public* API (`encrypt_bytes`/`encrypt_str`) is
  a randomized wrapper `Encrypt(k, A, M) := Enc(k, N, A, M)` for
  `N` sampled internally — never caller-supplied. Spelling this out ties
  directly into **CVF3**: it is precisely because `Enc` is deterministic in
  `N` and only the randomized wrapper is public that nonce reuse is a
  DRBG-failure/replay hazard rather than an ordinary caller-misuse hazard.
- **`Dec(k, A, C) → M or ⊥`:** parses `N` from `C`'s leading 16 bytes rather
  than taking it as a separate argument (matching the actual
  `decrypt_bytes(ciphertext, key, aad)` signature and the
  `Dec(k, c*, aad*)` notation the proofs already used), verifies the tag
  before unmasking (so no plaintext-dependent computation occurs on an
  unauthenticated ciphertext), and otherwise inverts `Enc` step-for-step.
  We note explicitly that this is a trivial reparameterisation of the
  audit's suggested four-argument `Dec(K,N,A,C)` form under `N := C[0:16]`,
  not a different algorithm.
- **Correctness** (`def:correctness`): states
  `Dec(k, A, Enc(k, N, A, M)) = M` for all `KeyGen` outputs and all
  `(N, A, M)`, with a one-paragraph proof from the shared determinism of
  the per-domain derivations, plus a cross-reference to the KAT corpus and
  full regression suite as empirical correctness evidence.
- **Explicit `⊥` output:** a remark states that all three reference
  implementations realise `⊥` as a raised exception rather than a sentinel
  return value, cross-referencing `SPEC.md` §10's existing error-condition
  table, and clarifies that every `Dec(·) = ⊥` / `Dec(·) ≠ ⊥` in the
  Security Analysis section should be read as "raises" / "does not raise".
- **Security goals restated against the triple.** Added a lead-in paragraph
  at the top of the Security Analysis section stating that the IND-CPA
  theorem, the IND-CCA discussion, and the INT-CTXT theorem are all stated
  against `(KeyGen, Enc, Dec)` of Definition `def:aead-triple` under the
  correctness condition of Definition `def:correctness`, and clarifying
  that INT-CTXT (ciphertext integrity against an encryption-oracle
  adversary) is the EUF-CMA-style unforgeability goal referenced
  informally in the abstract/introduction — NAPQES has no MAC
  verification key distinct from `kb`, so the two notions coincide here
  rather than needing a separate EUF-CMA theorem.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex`: new subsection + two definitions +
  two remarks (Construction section, immediately before Security
  Analysis), plus the lead-in paragraph at the top of Security Analysis
  cross-referencing them. No existing theorem statement, proof, or
  section numbering after Security Analysis needed to change — the new
  definitions formalise objects (`Enc`, `Dec`, correctness) that the
  existing proofs already referred to informally by the same names.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: this
  finding is that the *specification* never stated the formal object,
  not that the implementations disagree with each other or with any
  formal definition — cross-language KAT parity was already independently
  verified under CVF1/CVF2/CVF3.
- `SPEC.md` was not rewritten: its existing §10 "Error model" table
  already documents the per-condition `⊥` realisation accurately and is
  now cross-referenced directly from the new `⊥`-output remark rather than
  duplicated.

**Known residual.** We did not add a fourth, fully-worked EUF-CMA game
distinct from the existing INT-CTXT theorem, since — as stated above — the
two coincide for this construction (there is no separate MAC key). If a
reviewer wants EUF-CMA stated as its own game rather than as a remark
identifying it with INT-CTXT, we can add that as a follow-up; we did not
want to introduce a redundant theorem with an identical proof under a
different name without being asked to.

**Requested action:** please confirm CVF5 can be marked **Fixed**. Full
technical detail is in `docs/napseq-eprint-preprint.tex`, new subsection
"The NAPQES AEAD Algorithm Triple" (end of the Construction section).

---

## CVF6 — Token-emission loop pseudocode is incomplete: its derivation primitives are undefined

**Status:** Open → **Fixed** (documentation; content was already correct, this entry was missing from the tracker)
**Category:** Documentation

### Response

Confirmed, and we want to flag an internal process gap: this finding's
fix was implemented in the same 2026-07-07 documentation pass as CVF5–CVF9,
but no corresponding entry was ever added to this response document, so it
was never formally submitted for closure. We are adding it now.

The token-emission pseudocode invoked four helper primitives —
`is_noise` (domain `0x00`), `derive_noise_char` (`0x04`),
`derive_noise_addend` (`0x05`), and `derive_real_addend` (`0x01`) — that
Table 1 named only by context input and output range, with no formula
stating how the 32-byte `Derive_d` output is reduced to the required
Boolean decision or bounded integer. As written, the pseudocode could not
be executed and the token construction was not reproducible from the
paper alone, and the exact reduction (and hence any modulo bias) was
unspecified for every one of these primitives.

**Fix shipped (2026-07-07).** `docs/napseq-eprint-preprint.tex`'s Token
Construction subsection now includes:

- **A new audit-finding remark** (`rem:cvf6`, immediately before the
  token-emission loop) recording the finding exactly as described above.
- **Four explicit definitions** (`def:isnoise`, `def:noisechar`,
  `def:noiseaddend`, `def:realaddend`), each giving the primitive as a
  byte-exact reduction of `Derive_d(kb, N, ctx)`: `is_noise` as a
  strict-inequality threshold test on a 64-bit fraction (no modulo bias);
  `derive_noise_char`, `derive_noise_addend`, and `derive_real_addend` as
  `(value mod m) + offset` reductions into `[32,127]` / `[1,k-1]`
  respectively, matching `napqes.py`/`rust/src/lib.rs` exactly.
- **A padding-codepoint definition** (`def:padcodepoint`) of the same form
  for domain `0x06`, shared with the CVF18 fix.
- **A modulo-bias remark** (`rem:modbias`) bounding the relative deviation
  from uniform for every finite-range reduction above (all below `2^-8`),
  concluding the bias is statistically dominated by, and no more
  exploitable than, the underlying HMAC-SHA256 PRF advantage.

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only — one new
remark and four new definitions in the Token Construction subsection,
plus the shared padding-codepoint definition. No change to `napqes.py`,
`rust/src/lib.rs`, or `C/napqes.c`: all three reference implementations
already computed exactly the reductions given above; this was a
specification-completeness gap, not a code defect.

**Known residual:** none.

**Requested action:** please confirm CVF6 can be marked **Fixed**. Full
technical detail is in `docs/napseq-eprint-preprint.tex`, immediately
before the Token Construction pseudocode listing (`rem:cvf6` and
Definitions `def:isnoise`–`def:realaddend`).

---

## CVF7 — Applicability of the online-AE streaming format relative to the other formats is unspecified

**Status:** Open → **Fixed**
**Category:** Documentation

### Response

Confirmed. The paper defined three encodings — block-mode Wire Format
Version 7 (`C = N || B̃ || T`), the basic streaming format
(`encrypt_stream`, single trailing tag), and the online-AE streaming
format (v6s-ae, per-chunk tags) — without ever stating their relationship:
whether they were interchangeable options, whether block-mode and
streaming coexisted by design, or how a decryptor was meant to determine
which format a given ciphertext used, since none of the three wire
layouts carries a version/format discriminator byte. We agree this is
operationally underspecified, and that it has the security consequence
identified in the finding: because the basic streaming format is
RUP-prone (CAV-001), an unstated selection rule risks a receiver being
induced to invoke the unsafe decoder on a ciphertext produced by (or
claimed to come from) the safe encoder.

**Fix shipped (2026-07-07).** Added a new subsection, "Format
Applicability and Normative Status" (`docs/napseq-eprint-preprint.tex`,
end of the Construction section, immediately after
Section~sec:streaming-ae, `\label{sec:format-applicability}`), that states
the previously-missing rule:

- **Block mode and streaming mode coexist by design; both are normative.**
  They are not alternative encodings of one message class chosen by
  preference — block mode (v7) is normative for bounded, in-memory
  messages requiring length-bucket obfuscation via padding, and is the
  sole format underlying `Enc`/`Dec` (Definition `def:aead-triple`) and
  the IND-CPA/INT-CTXT theorems; streaming mode is normative for
  unbounded/memory-constrained plaintext, never pads, and is never
  interoperable with block-mode ciphertext.
- **Within streaming mode, only the online-AE format (v6s-ae) is
  normative.** The basic streaming format
  (`encrypt_stream`/`decrypt_stream`) is now explicitly **deprecated and
  forbidden for producing new ciphertext** — retained solely so that
  streams produced before this fix remain decryptable. This upgrades
  CAV-001 from "fixed, RUP-prone format still permitted at the caller's
  discretion" to "fixed by supersession: the RUP-prone format is
  deprecated and forbidden going forward."
- **Format selection is an out-of-band API contract, not an in-band
  discriminator.** None of the three wire layouts carries a version byte,
  and this fix does not add one — by design, since a self-describing
  discriminator would itself need to be authenticated before a decryptor
  could safely act on it, reintroducing the same trust-before-verification
  problem RUP already poses. Both endpoints of a NAPQES deployment agree
  out-of-band, at the protocol/call-site level, on which function is in
  use, exactly as callers of any AEAD library choose between a one-shot
  and a streaming construction rather than having the library sniff the
  format from ciphertext bytes. We state explicitly that a decryptor must
  never auto-detect format from ciphertext content, and that a protocol
  built on NAPQES MUST NOT implement a "try v6s-ae, then fall back to the
  basic streaming format" negotiation, since that downgrade path would
  recreate the exact induced-unsafe-decode hazard this fix closes.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex`: new subsection
  "Format Applicability and Normative Status" (Construction section) plus
  an updated CAV-001 entry in the Known Caveats appendix
  (`sec:caveats`) and a new Contributions bullet cross-referencing
  Section~sec:format-applicability.
- `SPEC.md`: new normative callout at the top of the document (CVF7 fix);
  §8 ("Streaming wire format") retitled and annotated as deprecated and
  forbidden for new ciphertext; §8.1 ("Streaming AE wire format") annotated
  as the sole normative streaming format; §11 caveats summary table row
  for CAV-001 updated.
- `docs/CAVEATS.md`: CAV-001 status line and Recommendation section
  rewritten to state the basic streaming format is deprecated and
  forbidden for new ciphertext, and to explicitly forbid
  try-v6s-ae-then-fall-back negotiation.
- No source code changed for this finding — it is purely a
  specification/normative-status clarification. The existing
  `enable_unauthenticated_streaming=True` opt-in gate on
  `decrypt_stream` (unchanged) already enforces, at the code level, that
  the deprecated format cannot be read silently; this fix formalises in
  the spec that the format itself must not be used to produce new
  ciphertext or be accepted by new protocols.

**Known residual.** No in-band version/format discriminator byte was
added to any of the three wire layouts. We considered this and concluded
it is out of scope for a documentation fix and, per the argument above,
not obviously desirable even as a code change: an unauthenticated
discriminator byte would need to be covered by the tag before a decryptor
could trust it, which is a wire-format change (a new version) rather than
a clarification, and is deferred to a future v8+ designator if ever
pursued.

**Requested action:** please confirm CVF7 can be marked **Fixed**. Full
technical detail is in `docs/napseq-eprint-preprint.tex`, new subsection
"Format Applicability and Normative Status" (end of the Construction
section, immediately after the Online-AE Streaming Format subsection).

---

## CVF8 — IND-CPA bound ignores the actual key entropy and key size

**Status:** Open → **Fixed** (proof-level correction; see Known residual)
**Category:** Algorithm

### Response

Confirmed. Theorem 1 (IND-CPA) bounded
`Adv^IND-CPA_NAPQES(A) ≤ Adv^PRF_HMAC-SHA256(B1) + q²/2^128`, with no term
depending on the key. This was unsound as written: `kb = key_bytes(k)` is
not a uniform bit-string, it is the serialisation of an ordered tuple of
`K` distinct primes from `𝒫`, whose min-entropy is
`H∞(k) = log2(|𝒫|!/(|𝒫|−K)!)` — the paper's own `≈2^196` figure for
`K=10`. The standard HMAC-SHA256 PRF conjecture is stated for a uniformly
random key; an adversary can always recover `k` by exhaustively evaluating
HMAC offline against candidate keys, at cost `≈2^H∞(k)` evaluations, and
this attack is entirely invisible to a bound stated only in terms of the
uniform-key PRF advantage. For small `K` (e.g. `K=1`, key space `≈2^20`)
this search is trivial, so the theorem was false as literally written for
admissible small key sizes, and imprecise even at the paper's default
`K=10` — the `≈2^196` figure never entered the bound, as the finding
states.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
Theorem 1 (`thm:ind-cpa`) is restated as:

```
Adv^IND-CPA_NAPQES(A) ≤ Adv^PRF_HMAC-SHA256(B1) + q²/2^128 + q_F · 2^(−H∞(k))
```

with `q_F` the adversary's offline HMAC-evaluation budget under
adversarially-chosen keys and `H∞(k) = log2(|𝒫|!/(|𝒫|−K)!)` as defined in
a new paragraph at the end of the Key subsection. The proof now includes:

- **A key-guessing lemma** (`lem:key-guess`) bounding, by a union bound
  over `q_F` offline guesses against the `2^H∞(k)`-point key space, the
  probability the adversary's guess set contains the real key — exactly
  the exhaustive-search attack the original bound could not see.
- **An explicit remark** (`rem:prf-d`) stating precisely what
  `Adv^PRF_HMAC-SHA256(B1)` means once the guessing term has been paid
  for: the PRF advantage against keys drawn from the actual prime-tuple
  distribution `D` (conditioned on not being guessed), which we state
  plainly is a different, non-standard, and less-studied assumption than
  the conventional uniform-key HMAC-SHA256 PRF conjecture — rather than
  silently substituting one for the other, as the original proof did.
- **A minimum-`K` remark** (`rem:min-K`): since each additional prime
  contributes `≈19.16` bits of `H∞` for `|𝒫|≈586,000`, the guessing term
  is negligible against the paper's own `≈128`-bit post-Grover target only
  for `K ≥ 7`; `K=1`–`6` are not admissible under that target, and this is
  now stated as a normative floor (`K≥7` MUST, `K=10`+ SHOULD) rather than
  left implicit.
- **An HMAC key-length-handling remark** (`rem:hmac-keylen`) addressing
  the `5K>64`-byte hash-then-pad case explicitly, confirming it does not
  reduce `H∞(k)` under the PRF-under-`D` framing and that the theorem
  continues to apply with `kb` read as `SHA256(key_bytes(k))` in that
  regime.
- **A recommendation remark** (`rem:cvf8-kdf`) identifying the fully
  rigorous alternative fix — deriving a uniform HMAC subkey from `kb` via
  an HKDF step before use — which would remove the non-standard
  PRF-under-`D` assumption entirely and restore a reduction to the
  conventional uniform-key conjecture, at the cost of a wire-format and
  key-schedule change.
- The Contributions bullet in the Introduction was updated to no longer
  claim IND-CPA "under the standard PRF assumption on HMAC-SHA256"
  unqualified; it now states the explicit key-entropy term is part of the
  claim.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex` only: new min-entropy definition (Key
  subsection), a new remark before Theorem 1, the restated theorem, a new
  lemma and remark inside the proof, an updated "Combining the bounds"
  derivation carrying the extra term through to the final inequality, and
  a new subsection "CVF8: Minimum Key Size and Removing the Residual
  Non-Standard Assumption" (`sec:cvf8-fix`) at the end of the IND-CPA
  proof.
- `SPEC.md` §2 ("Key serialisation"): new normative callout stating the
  `K≥7` minimum-key-size floor derived above, cross-referenced to the
  theorem and to `docs/CAVEATS.md`.
- `docs/CAVEATS.md`: new CVF8 entry (between CVF3 and CAV-001) recording
  the finding, the proof-level fix, and the KDF-subkey residual.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: this
  finding is that the *proof* understated its own assumptions and omitted
  a term, not that any implementation misbehaves — `KeyGen`'s default
  `K=10` was already comfortably above the `K≥7` floor derived here, and
  no implementation currently allows `K<7` to be configured without an
  explicit override, so no runtime enforcement gap exists today.

**Known residual (recommendation not shipped as code).** The KDF-derived
subkey fix (`rem:cvf8-kdf`) is recorded as the preferred long-term
resolution to the underlying non-standard-assumption issue but has not
been implemented: it changes the HMAC key schedule and wire format across
all three reference implementations, which is out of scope for a
proof-level correction. Until it lands, `Adv^PRF_HMAC-SHA256(B1)` in
Theorem 1 should be read as the PRF advantage against the actual prime-tuple
key distribution (Remark `rem:prf-d`), not the conventional uniform-key
assumption; we track adding the HKDF subkey step as a CVF8 follow-up
alongside the CVF1 streaming-format residual.

**Requested action (2026-07-07):** please confirm CVF8 can be marked **Fixed** as a
proof-level correction, with the KDF-subkey hardening tracked as an open
follow-up. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, Theorem 1 (`thm:ind-cpa`) and the new
subsection `sec:cvf8-fix` immediately following its proof.

### Follow-up (2026-07-07): the non-standard-assumption residual is fully closed for v8

Two corrections to the record above, made while shipping the CVF13
follow-up (`rust/src/lib.rs`, `generate_v8_key`): first, the `rem:cvf8-kdf`
proposal (`sk = HKDF(kb)`) does **not** actually decouple the HMAC key
from the arithmetic key, since it is still a deterministic function of
`k` — this is corrected as `Remark rem:cvf8-kdf-erratum` in
`docs/napseq-eprint-preprint.tex`. Second, the fix that *does* work
(sampling `sk` via an independent CSPRNG draw, never derived from `k`) is
now shipped: `generate_v8_key` draws the prime tuple and a 256-bit `sk`
independently, and `encrypt_bytes_v8`/`decrypt_bytes_v8` key every domain
derivation with this `sk`. Since `sk` is sampled uniformly at random with
no dependence on `k`, `H∞(sk) = 256` exactly and the conventional
uniform-key HMAC-SHA256 PRF assumption applies directly — no key-guessing
term and no non-standard key-distribution hypothesis is needed for a
v8-restated Theorem 1 (`Lemma lem:v8-cvf8`, `docs/napseq-eprint-preprint.tex`
§`sec:v8`). v7's Theorem 1, and its non-standard-assumption residual,
are unchanged for callers who have not migrated. See the CVF13 entry
below for the full v8 specification (the two findings share one fix).

**Requested action:** please confirm CVF8's non-standard-assumption
residual can be marked **Fixed** for the v8 key schedule, with v7
retaining the documented residual.

## CVF9 — INDCPA is never defined and the challenge-equality constraint is ill-specified, so Theorem 1 is not well-defined

**Status:** Open → **Fixed** (proof-level, definitional correction)
**Category:** Architecture

### Response

Confirmed. Theorem 1 claimed the scheme "is INDCPA secure" and was proved
via "the standard INDCPA experiment", but no formal IND-CPA definition
(adversary, oracles, challenge, advantage) appeared anywhere — it was only
sketched inline inside the proof of Game `G0`. That sketch's challenge
constraint, "`A` submits a challenge pair `(m0,m1)` of equal padded
length", is non-standard: the textbook constraint is `|m0|=|m1|` (equal
plaintext length) with no padding-related precondition, and the statement
never said which of codepoints, on-wire bytes, or the padded bucket `B`
"length" meant — these genuinely differ, since `B` is a power-of-two
function of codepoint count while on-wire byte length depends on
encoding. Because the metric was undefined, the theorem was not
well-defined, and the hiding lemma's proof compounded this by invoking
"equal padded lengths by the IND-CPA requirement" as an unproved
assumption smuggled in to close a step that would otherwise be circular.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
now states, immediately before Theorem 1:

- **A new audit-finding remark** (`rem:cvf9`) recording the issue exactly
  as described above.
- **A formal `Definition~\ref{def:ind-cpa}`**: the standard left-or-right
  IND-CPA experiment and advantage, stated against NAPQES's typed
  algorithm triple (`Definition~\ref{def:aead-triple}`), with the
  adversary's challenge constrained by exactly `|m0|=|m1|` — equal
  Unicode codepoint count, the only metric NAPQES's message space `M` is
  formally typed against — and no "equal padded length" precondition.
- **A derivation remark** (`rem:equal-padded-derived`) proving that
  `|m0|=|m1|` (the definition's actual constraint) already forces equal
  padded length, because the padding bucket
  `B = max(16, 2^ceil(log2(n+1)))` is a deterministic function of
  codepoint count alone (Plaintext Padding subsection) — with no
  dependence on codepoint values. This turns "equal padded length" from
  an assumed precondition (the circular step the audit identified) into a
  proved consequence of the formal definition's standard constraint,
  cited by name everywhere it is used (Game `G0`'s challenge step, the
  hiding lemma's proof).
- **A scope remark** (`rem:cvf9-byte-metric`) stating plainly that the
  guarantee is with respect to the codepoint metric only: two plaintexts
  equal in on-wire byte length but unequal in codepoint count are not a
  valid `(m0,m1)` challenge under this definition, and if compared at the
  codepoint level with unequal length, the padded-bucket side channel
  (CAV-003, already open) is not addressed by this fix.
- Theorem 1's statement and proof are edited to cite the new definition
  and remarks (`Definition~\ref{def:ind-cpa}`, `Remark~\ref{rem:equal-padded-derived}`)
  in place of the old inline, ambiguous phrasing, with no change to the
  theorem's bound, the proof's game structure, or any other lemma.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex` only: one new remark, one new formal
  definition, two new remarks, and targeted edits to Theorem 1's
  statement, the `G0` challenge step, and the hiding lemma's "equal
  byte-length of `B`" paragraph.
- `docs/CAVEATS.md`: new CVF9 entry (between CVF8 and CAV-001) recording
  the finding, the fix, and its cross-reference to the still-open CAV-003.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: the
  underlying argument was already, in substance, using `|m0|=|m1|` in
  codepoints — it was the *definition and one proof step's justification*
  that were missing/circular, not the construction or the bound.

**Known residual (not introduced by this fix, cross-referenced here).**
CAV-003 (padding length-bucket leakage) remains open: ciphertext length
still reveals the padding bucket, so plaintexts equal-length only in a
metric other than codepoints (e.g. on-wire byte length of an external
encoding) are not covered by Theorem 1. This was already tracked before
CVF9 and is unaffected by this proof-level fix; the scope remark above
makes the cross-reference explicit rather than leaving it implicit.

**Requested action:** please confirm CVF9 can be marked **Fixed** as a
proof-level, definitional correction, with the pre-existing CAV-003 gap
tracked separately as an open, low-severity caveat. Full technical detail
is in `docs/napseq-eprint-preprint.tex`, immediately before Theorem 1
(`thm:ind-cpa`).

## CVF10 — INTCTXT bound omits the ideal-world tag-guessing term and is false for q = 0

**Status:** Open → **Fixed** (proof-level)
**Category:** Algorithm

### Response

Confirmed. Theorem 2 (INT-CTXT) bounded `Adv^INT-CTXT <= Adv^PRF(B2) +
q^2/2^128`, but the reduction `B2`'s advantage is by definition `Pr[forge
| real] - Pr[forge | random]`, so a sound bound on `Pr[forge | real]`
must carry the ideal-world term `Pr[forge | random]` forward rather than
drop it. Even against a truly random function, an adversary that submits
a candidate tag for a fresh (never-queried) input succeeds purely by
guessing with probability `2^-256` per attempt — this is nonzero and was
missing from the stated bound. Concretely, the omission made the bound
literally false at `q = 0`: an adversary making no encryption queries and
submitting one uniformly random 256-bit tag as its forgery still wins
INT-CTXT with probability `2^-256 > 0`, exceeding the claimed bound of
`0`. The original proof also never stated `B2`'s decision rule, so no
advantage accounting actually connected `A`'s forgery event to `B2`'s
distinguishing output. The same omission propagated into the IND-CCA
bound (Theorem 3), which invokes the INT-CTXT theorem with `q_d`
verification queries and therefore needed a matching `q_d/2^256` term
that was likewise absent.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
now includes:

- **A new audit-finding remark** (`rem:cvf10`, immediately before Theorem 2)
  recording the issue exactly as described above, including the explicit
  `q=0` counterexample and the cross-reference to the IND-CCA propagation.
- **A restated Theorem 2** adding a verification-query parameter `q_v >= 1`
  (the number of forgery-submission attempts `A` makes) and the missing
  term, so the bound reads
  `Adv^INT-CTXT <= Adv^PRF(B2) + q^2/2^128 + q_v/2^256`; for a single
  forgery attempt (`q_v = 1`) this is the `2^-256` term the finding
  requested.
- **An explicit decision rule for `B2`** in the Case-1 proof paragraph:
  `B2` outputs "real" iff at least one of `A`'s forgeries verifies against
  its oracle `f`, otherwise "random". The advantage is then derived
  formally as `Pr[B2 -> real | f = HMAC] - Pr[B2 -> real | f random] =
  Pr[forge | real] - Pr[forge | random]`, with the ideal-world term bounded
  by a union bound over `A`'s `q_v` blind guesses (`f(x*)` is uniform and
  independent of `A`'s view for the fresh, never-queried input `x*`),
  giving `Pr[forge | random] <= q_v/2^256`.
- **The IND-CCA theorem (Theorem 3) and its combining proof** are updated
  to carry a `q_d/2^256` term through unchanged, since the INT-CTXT forger
  `A'` constructed in that proof makes exactly `q_d` verification
  (decryption-oracle) queries; the composed bound is now
  `Adv^IND-CCA <= Adv^PRF(B1) + Adv^PRF(B2) + (q+q_d)^2/2^128 + q_d/2^256`.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex` only: one new remark, targeted edits
  to Theorem 2's statement and Case-1 proof paragraph and combining step,
  and matching edits to Theorem 3 (IND-CCA)'s statement and combining
  proof. No change to the theorems' game structure, Case 2 (nonce
  collision), or any other lemma.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: this was
  purely a missing term in the security proof's accounting, not a flaw in
  the construction — the `2^-256` (or `q_v/2^256`) term is an inherent,
  unavoidable property of any 256-bit MAC tag and was already implicitly
  true of the real construction; it was simply never written down.

**Known residual:** none. Unlike CVF8/CVF9, this fix closes the bound
completely — there is no further term the bound is missing after this
fix, since `2^-256` (or `q_d/2^256` for the practical multi-query case)
is cryptographically negligible and matches the standard MAC/AEAD
security literature's treatment of tag-guessing probability.

**Requested action:** please confirm CVF10 can be marked **Fixed** as a
proof-level correction. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, immediately before Theorem 2
(`thm:int-ctxt`) and in Theorem 3 (`thm:ind-cca`)'s combining proof.

## CVF11 — INTCTXT proof's nonce-collision probability is bogus — N* is adversarially chosen

**Status:** Open → **Fixed** (proof-level)
**Category:** Algorithm

### Response

Confirmed. Theorem 2 (INT-CTXT), Case 2, argued that "the probability of a
nonce collision satisfying `N* = N_i` for some `i` is at most `q/2^128 <=
q^2/2^128` by the union bound." This is a category error: `N*` is not
sampled by any experiment — it is a component of the forgery `c*` chosen
by the adversary `A` itself, adaptively, after observing `N_1,...,N_q` in
the ciphertexts already returned to it. `A` can set `N* = N_i` for any `i`
of its choosing with probability 1; this is not a random event and cannot
be bounded by a union bound over "collision" probability. The error was
also unnecessary: Case 2's own argument already disposes of `N* = N_i`
*deterministically*, via the injectivity of the domain-`0x03` tag-input
encoding (either the padded-blob differs, reducing to Case 1, or it is
identical to a query-phase input, in which case any differing tag is
rejected outright) — so no probability term was ever needed for Case 2.
Consequently the `q^2/2^128` term in the theorem statement did not trace
to any actual step in the proof.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
now includes:

- **A new audit-finding remark** (`rem:cvf11`, immediately before Theorem 2)
  recording the issue exactly as described above.
- **Theorem 2's statement and Case-2 proof paragraph** rewritten: the
  bogus nonce-collision sentence is removed, and Case 2 is stated as
  contributing no probability term at all, since both its sub-cases are
  resolved deterministically by the tag-input injectivity argument that
  was already present. The restated bound is
  `Adv^INT-CTXT <= Adv^PRF(B2) + q_v/2^256` — dropping `q^2/2^128`
  entirely; the theorem now correctly has no `q`-dependent (encryption
  query count) term, only the `q_v`-dependent ideal-world tag-guessing
  term from CVF10.
- **The IND-CCA theorem (Theorem 3) and its combining proof**, which had
  invoked the INT-CTXT bound with `q+q_d` total oracle queries specifically
  to inherit this now-removed term, are updated to drop it. The
  `Pr[D]` bound in the IND-CCA proof is now
  `Adv^PRF(B2) + q_d/2^256` (no nonce-collision term), and the composed
  bound is `Adv^IND-CCA <= Adv^PRF(B1) + Adv^PRF(B2) + q^2/2^128 +
  q_d/2^256`, where the surviving `q^2/2^128` term is the genuine,
  unrelated nonce-collision bound from the `H_1`-reduces-to-IND-CPA step
  (an honestly-random challenge nonce, not an adversarially-chosen one),
  not from INT-CTXT.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex` only: one new remark, targeted edits
  to Theorem 2's statement and Case-2 proof paragraph, and matching edits
  to Theorem 3 (IND-CCA)'s statement, the `Pr[D]` bound, and the final
  combining step. No change to Case 1, the hiding lemma, or any other
  lemma; the genuine IND-CPA nonce-collision argument (Lemma "hiding",
  `Coll` event over honestly-random nonces) is untouched — that one
  remains sound, since there the nonce in question is sampled by the
  challenger, not chosen by the adversary.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: this was
  purely an unsound probability argument in the security proof, not a flaw
  in the construction.

**Known residual:** none. The corrected bound traces every term to an
actual step: `Adv^PRF(B2)` from Case 1's MAC-forgery reduction, and
`q_v/2^256` from the ideal-world tag-guessing bound (CVF10); Case 2
contributes nothing, as it should.

**Requested action:** please confirm CVF11 can be marked **Fixed** as a
proof-level correction. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, immediately before Theorem 2
(`thm:int-ctxt`) and in Theorem 3 (`thm:ind-cca`)'s statement and
combining proof.

## CVF12 — Case 1 freshness justification is wrong, and the cross-group HMAC-input collision term is ignored across INTCTXT, INDCPA, and Remark 1

**Status:** Open → **Fixed** (proof-level; largely a stale-text/internal-consistency defect, not a live gap in the current bounds — see below)
**Category:** Algorithm

### Response

Confirmed in part, and we want to be precise about which part. We checked
Theorem 2 (INT-CTXT)'s Case 1 paragraph and the "AAD Binding" paragraph
against the current `Remark~\ref{rem:domsep}` (the CVF2 domain-first
unification) and against the shipped code, and found a real, internal
inconsistency: Case 1 and "AAD Binding" both still wrote the tag input as
`0x03 || be4(|aad|) || aad || N || B̃` — the *pre*-CVF2, AAD-first-then-nonce
layout, in which the nonce sits at a variable offset depending on `|aad|` —
even though `Remark~\ref{rem:domsep}` itself, Table 1, the hiding lemma's
"Freshness of the authentication tag" paragraph, and the actual code
(`napqes.py`'s `_compute_auth_tag`, and the Rust/C equivalents) all already
use the corrected, unified `d || N || ctx` layout with the nonce at the
fixed offset immediately after the domain byte. Two sections of the same
document described the same construction with two different, mutually
incompatible formulas, and Case 1's "prefixed by nonces `N_1,...,N_q`"
claim, read against the *stale* formula actually printed a few lines below
it, was indeed unjustified exactly as described: under that formula the
nonce is not at a fixed offset, so "prefixed by" does not follow merely
from `N_i != N*`, and the cross-group collision you describe — a
nonce-first domain input `N_i || d || ctx` (21–22 bytes) equalling the
minimal AAD-first tag input `0x03 || be4(0) || N*` (21 bytes, empty AAD,
`|B̃*| = 0`) whenever `N_i` begins with `0x0300000000`, probability
`≈ q/2^40` over `q` queries — is a real, correctly-computed collision
probability *for that stale formula*.

Where we differ from the finding is on scope: this is not a live gap in
the bounds NAPQES actually claims today. The current `Remark~\ref{rem:domsep}`
(shipped with the CVF2 fix, prior to this finding) already replaced the
probabilistic cross-group argument with an unconditional injectivity
argument — inputs with different domain bytes differ at byte position 0
regardless of nonce or context, full stop — precisely *because* the
domain-first layout was adopted. Under that (already-shipped, already-coded)
layout, the collision you describe cannot occur at all: a domain-`0x03`
input's bytes `1..16` are always `N*`, a nonce-first domain's bytes `1..16`
are also always its nonce, but the two inputs differ unconditionally at
byte 0 (`0x03` vs. the other domain byte) before the nonce comparison is
even relevant. So while your `q/2^40` and `q/2^32` collision-probability
arithmetic is correct as a description of what the stale formula would
require, no `q/2^40`-type or `q/2^32`-type term needs to be added to
Theorem 2, Theorem 1, or Theorem 3's bounds, because the actual
(non-stale) construction and the actual `Remark~\ref{rem:domsep}` do not
rely on any probabilistic collision argument to begin with. We also
specifically checked for the "Remark 1 ... dominated by the nonce
collision term" claim you describe and confirmed no such sentence exists
anywhere in the current `Remark~\ref{rem:domsep}` — the CVF2 rewrite had
already removed the probabilistic cross-group framing that sentence would
have belonged to, so there was nothing left in the current document for
that specific critique to attach to.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
now includes:

- **A new audit-finding remark** (`rem:cvf12`, immediately after
  `rem:cvf11` and before Theorem 2) recording the issue exactly as
  described above: the stale AAD-first formula, the internal
  inconsistency with `Remark~\ref{rem:domsep}` and the hiding lemma, the
  `q/2^40` collision the stale formula would have required, and why the
  actual domain-first layout is immune to it without any additive term.
- **Theorem 2 (INT-CTXT)'s statement of `T*`/`x*` and Case 1 paragraph**
  corrected to the domain-first formula
  `T* = HMAC(kb, 0x03 || N* || be4(|aad*|) || aad* || B̃*)`, with Case 1's
  freshness argument rewritten to follow from injectivity of the encoding
  (per `Remark~\ref{rem:domsep}`: `N_i` occupies the same fixed byte
  offset `1..16` as `N*`, so `N_i != N*` forces `x_i != x*` unconditionally
  at those bytes, regardless of `|aad_i|`) rather than the previously
  unjustified "prefixed by nonces" phrasing — matching your recommended
  fix for the domain-first case exactly.
- **The "AAD Binding" paragraph** corrected to the same domain-first
  formula, `T = HMAC(kb, 0x03 || N || be4(|A|) || A || B)`.
- No change to Theorem 2's stated bound (`Adv^PRF(B2) + q_v/2^256`,
  unchanged from the CVF10/CVF11 fixes), Theorem 1's bound, or Theorem 3's
  composed bound: per the argument above, none of them were missing a
  term under the actual (non-stale) construction — only two paragraphs'
  *prose formulas* were stale, not the theorems' claimed bounds.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex` only: one new remark, and targeted
  formula/argument corrections confined to Theorem 2's Case 1 paragraph
  and the "AAD Binding" paragraph, both cross-referenced to
  `rem:cvf12` and `rem:domsep`. No change to Case 2, the hiding lemma
  (which was already correct), Theorem 1, or Theorem 3's statements or
  bounds.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: the
  shipped code already implements the domain-first layout (verified
  against `napqes.py`'s `_compute_auth_tag` directly); this finding
  concerns two stale proof paragraphs that had not been updated when the
  CVF2 fix was applied elsewhere in the same document, not a code defect.
- Recompiled `docs/napseq-eprint-preprint.tex` with `pdflatex` (three
  passes) to confirm the new `rem:cvf12` label resolves and no
  undefined/duplicate-reference warnings remain.

**Known residual:** none. Once the two stale paragraphs are corrected to
match `Remark~\ref{rem:domsep}` (which already reflects the shipped,
domain-first code), there is no remaining cross-group collision term to
account for in any of the IND-CPA, INT-CTXT, or IND-CCA bounds.

**Requested action:** please confirm CVF12 can be marked **Fixed** as a
proof-level, internal-consistency correction — the underlying bounds were
already sound under the shipped domain-first construction; the defect was
confined to two paragraphs that had not been brought in line with the
CVF2 fix. Full technical detail is in `docs/napseq-eprint-preprint.tex`,
immediately before Theorem 2 (`thm:int-ctxt`), in Theorem 2's Case 1
paragraph, and in the "AAD Binding" paragraph.

## CVF13 — INTCTXT and INDCPA reductions cannot simulate the encryption oracle without the prime vector k

**Status:** Open → Fixed (proof-level: gap documented, resolution path specified, 2026-07-07) → **Fully fixed for v8** (2026-07-07, see Follow-up below); v7 retains the documented residual
**Category:** Architecture

### Response

Confirmed. Both `B1` (Theorem 1/IND-CPA, Lemma `lem:prf-hop`'s proof) and
`B2` (Theorem 2/INT-CTXT's proof, Case 1) are described only as forwarding
"every internal HMAC call"/"every HMAC computation" to their PRF oracle.
That description is incomplete: to answer `A`'s encryption queries at all,
the reduction must run `NAPQES.Enc(k, ...)`, and that algorithm uses `k`
directly, outside of any HMAC call — token emission computes `c * k_j + a`
and the addend range `[1, k_j - 1]` both depend on the specific prime
`k_j`, not merely on an HMAC output. A standard PRF oracle never reveals
its hidden key, so `B1`/`B2` cannot extract `k` from oracle access.

Repairing this by having the reduction sample its own `k'` locally does
not work either: in the real-world branch (oracle keyed by the true
`kb = key_bytes(k)`), there is no reason `kb` equals `key_bytes(k')` for
the independently-chosen `k'` — the resulting simulation would compute
token arithmetic under `k'` while tags/addends/positions come from
`HMAC(kb, .)` for an unrelated `k`, an internally inconsistent hybrid that
is a different scheme from `NAPQES.Enc(k', ...)`, not the real one.
Conversely, if the reduction supplies its own `k'` *to* the PRF challenger
so that the oracle's key really is `key_bytes(k')`, the reduction already
knows the tested key and can compute the function itself, making its
"distinguishing advantage" trivially ~1 regardless of realness — this
establishes nothing, since a PRF game's basic premise (the key is hidden
from the distinguisher) is violated once that same key must also be
disclosed, in the clear, to run the arithmetic layer. Because the IND-CCA
bound (Theorem 3) is assembled from `B1`'s and `B2`'s advantages via the
Bellare–Namprempre composition, it inherits the identical simulation gap.

This is a distinct defect from CVF8 (which concerns *which key
distribution* the PRF assumption is stated over, uniform vs.
prime-tuple-structured) — CVF13 concerns whether the reduction can be run
*at all*, independent of which distribution is assumed.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
now includes:

- **A new audit-finding remark** (`rem:cvf13`, immediately after
  Remark `rem:prf-d`) recording the issue exactly as described above,
  including why the "reduction samples its own k" repair fails in both
  directions.
- **Cross-reference sentences** added at `B1`'s construction (Lemma
  `lem:prf-hop`'s proof), `B2`'s construction (Theorem 2, Case 1), and
  the IND-CCA composition proof (Theorem 3), each pointing to `rem:cvf13`
  at the exact point the gap applies, so the affected proof steps are no
  longer silently assumed to go through.
- **An explicit resolution path**, reusing the already-documented
  KDF-subkey design of `rem:cvf8-kdf`: deriving an independent,
  uniformly-distributed HMAC subkey `sk = HKDF(kb)` and keying every
  domain derivation with `sk` in place of `kb`, while `k` itself is used
  only for the (public, non-HMAC) arithmetic layer. Once `sk` is
  architecturally decoupled from `k`, `B1`/`B2` may legitimately sample
  `k` locally (it is no longer correlated with the tested key at all)
  while forwarding every domain-derivation call to an external oracle
  keyed by the PRF challenger's independent, hidden `sk` — this closes
  the simulation gap under the standard, uniform-key HMAC-PRF assumption.
  `rem:cvf8-kdf` is updated to note it resolves both the CVF8 key-entropy
  issue and this CVF13 simulation gap simultaneously.
- The theorem preambles (Theorem 1, Theorem 2, Theorem 3) are updated
  with a short caveat cross-referencing `rem:cvf13`, so the "Under the PRF
  assumption on HMAC-SHA256" preconditions are no longer stated as if the
  reductions, as literally written, already established that assumption
  applies to the real scheme.

## CVF14 — IND-CCA proof: the "identical-until-bad" step is false — H1 also diverges on non-fresh replays

**Status:** Open → **Fixed** (proof-level)
**Category:** Architecture

### Response

Confirmed. The `H_0 -> H_1` transition in Theorem 3 (IND-CCA)'s proof
stubbed the decryption oracle `D` in `H_1` to return `⊥` unconditionally,
defined the bad event `D` as a *fresh* (`c ∉ {c_1,...,c_q}`) valid
submission, and then asserted "`H_0` and `H_1` are identical in every
execution that does not trigger `D`." That assertion is false exactly as
those two definitions stood: in `H_0`, `A` may legally query
`D(c_i, aad_i)` on a ciphertext previously returned by the encryption
oracle and receive the correct plaintext `m_i` (by correctness), whereas
the stubbed `H_1` returns `⊥` on that same query — and that query is not
fresh, so `D` does not occur. An adversary that simply queries
`D(c_1, aad_1)` after one encryption-oracle query distinguishes `H_0` from
`H_1` with probability 1 without ever triggering `D`, so the
fundamental-lemma step `|Pr[H_0] - Pr[H_1]| ≤ Pr[D]` was not established as
written. We confirm this is a distinct defect from CVF10–CVF13: those
findings concern gaps or omitted terms *inside* the INT-CTXT/IND-CCA
advantage bounds; CVF14 concerns whether the hybrid argument used to
*reduce* IND-CCA to INT-CTXT plus IND-CPA is even correctly stated, prior
to and independent of those bounds' numerical content.

**Fix shipped (2026-07-07, proof-only), adopting the recommended standard
hybrid.** `docs/napseq-eprint-preprint.tex` now includes:

- **A new audit-finding remark** (`rem:cvf14`, immediately before Theorem 3)
  recording the issue exactly as described above, including the explicit
  one-query distinguisher and why it does not trigger `D`.
- **`H_1` redefined as the standard table-backed hybrid**, per the
  recommendation: `D` (now written `D'`) consults a table `T` populated by
  every `(c_i, aad_i, m_i)` triple the encryption oracle has produced, and
  on query `(c, aad)` returns the recorded `m_i` if `(c, aad) ∈ T`, and
  returns `⊥` only if `(c, aad) ∉ T` (i.e., only for ciphertexts not
  already known to be valid) — rather than returning `⊥` unconditionally.
- **The transition paragraph rewritten** to prove, case-by-case, that
  `H_0` and `H_1` answer every decryption query identically unless `D`
  occurs: on a replayed query (`(c, aad) ∈ T`) both games return `m_i`
  (`H_0` by correctness, `H_1` by table lookup) — closing exactly the gap
  the finding identified; on a fresh invalid query both return `⊥`; on a
  fresh valid query `H_0` returns a plaintext while `H_1` returns `⊥`,
  which is precisely event `D`. The fundamental-lemma step
  `|Pr[H_0] - Pr[H_1]| ≤ Pr[D]` now follows validly. The INT-CTXT forger
  `A'` that bounds `Pr[D]` required no change — it already treated `D` as
  "a fresh, non-`⊥` result", which was always the correct definition; only
  `H_1`'s own decryption-oracle definition was wrong, not the reduction
  bounding `Pr[D]`.
- **The `H_1`-reduces-to-IND-CPA step rewritten** to match the new,
  non-trivial `H_1`: since the table-backed oracle `D'` never returns any
  information `A` does not already possess (a replayed query returns
  `m_i`, the very plaintext `A` itself supplied to the encryption oracle
  to obtain `c_i`; every other query returns `⊥`), an IND-CPA adversary
  `A''` can reproduce `H_1` exactly for `A` by maintaining the same table
  `T` locally and answering decryption queries from it, using only the
  IND-CPA experiment's encryption oracle — so `H_1` remains computationally
  equivalent to the IND-CPA experiment, and the previously-derived bound
  on `Pr[A wins H_1]` is unchanged.
- **The theorem statement and the "Combining" step** are annotated with a
  cross-reference to `rem:cvf14` confirming that the fix changes only the
  *definitions and argument* of `H_1`/`D`/`D'`, not the numerical value of
  any term in the final bound — the composed inequality
  `Adv^IND-CCA ≤ Adv^PRF(B1) + Adv^PRF(B2) + q²/2^128 + q_d/2^256`
  (already corrected by CVF10/CVF11) is unaffected by this fix.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex` only: one new remark, and targeted
  rewrites of the `H_1` definition, the `H_0 -> H_1` transition paragraph,
  and the `H_1`-reduces-to-IND-CPA paragraph inside Theorem 3
  (`thm:ind-cca`)'s proof, plus a short cross-reference at the theorem
  statement and at the end of the combining step. No change to the
  INT-CTXT forger `A'`'s construction, to Theorem 1, Theorem 2, or to the
  final bound's stated value.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: this
  finding is purely a hybrid-argument soundness defect in the security
  proof, not a flaw in the construction — the actual decryption function
  in all three implementations already behaves correctly on replayed,
  previously-valid ciphertexts (it simply re-decrypts them), which is the
  real-world behaviour the corrected `H_1` now accurately models.
- Recompiled `docs/napseq-eprint-preprint.tex` with `pdflatex` (three
  passes) to confirm `rem:cvf14` and all its cross-references resolve
  with no undefined-reference or LaTeX-error output.

**Known residual:** none. The corrected hybrid is the standard
textbook construction for this composition step (a table-backed
decryption oracle that only nulls out *fresh* queries), and the
fundamental-lemma inequality now traces to a case analysis that is
exhaustive and correct; no further term is introduced or required by
this fix.

**Requested action:** please confirm CVF14 can be marked **Fixed** as a
proof-level correction to the hybrid argument. Full technical detail is
in `docs/napseq-eprint-preprint.tex`, immediately before Theorem 3
(`thm:ind-cca`), and in the `H_1` definition, transition, and
`H_1`-reduces-to-IND-CPA paragraphs of its proof.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex` only: one new remark, an update to
  `rem:cvf8-kdf` cross-referencing it, and short pointer sentences at the
  three affected reduction constructions and theorem preambles. No change
  to any theorem's stated bound, game structure, or any other lemma.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: the
  KDF-subkey design that would fully close this gap is a wire-format and
  key-schedule change, out of scope for a proof-only correction (same
  scope boundary as the pre-existing `rem:cvf8-kdf` residual).

**Known residual (not closed by this fix).** Without the KDF-subkey
change, the reductions for Theorem 1 (IND-CPA), Theorem 2 (INT-CTXT), and
Theorem 3 (IND-CCA) still lack a valid, fully-specified simulation: this
fix makes the gap explicit and points to the concrete design change that
closes it, but does not supply an alternative primitive-level assumption
under which the *current* wire format (HMAC keyed directly by
`key_bytes(k)`) can be proven secure by this reduction strategy. We are
not aware of a suitable such assumption; the honest status of Theorems 1–3
until the KDF-subkey change lands is "gap identified and its precise
resolution specified," not "closed."

**Requested action (2026-07-07):** please confirm CVF13 can be marked **Fixed** as a
proof-level clarification with an explicit, tracked residual (the
KDF-subkey wire-format change), rather than left silently unaddressed.
Full technical detail is in `docs/napseq-eprint-preprint.tex`,
`Remark~\ref{rem:cvf13}` (immediately after `rem:prf-d`), with pointer
cross-references at Lemma `lem:prf-hop`'s proof, Theorem 2 (`thm:int-ctxt`)
Case 1, and Theorem 3 (`thm:ind-cca`)'s combining proof.

### Follow-up (2026-07-07): v8 independent key schedule fully closes CVF13

On further reflection, the KDF-subkey repair floated above
(`sk = HKDF(kb)`) does **not** actually close this gap, and we want to
correct our own record rather than let that stand: `sk = HKDF(kb)` is a
*deterministic function* of `k` (via `kb = key_bytes(k)`), so it is not
independent of `k` in the sense the simulation needs. A reduction that
already knows `k` (required to run the arithmetic layer `c*k+a`) can
compute `kb` and therefore `sk` itself — it would never need to query an
external oracle for `sk` in the first place, so "forwarding to a PRF
oracle keyed by sk" is vacuous under that design. The leftover-hash-style
argument for HKDF only shows `sk`'s *marginal* distribution is close to
uniform (the right notion for CVF8's key-entropy concern), not that `sk`
is independent of `k` (the notion CVF13 actually needs). This correction
is recorded as `Remark rem:cvf8-kdf-erratum` in
`docs/napseq-eprint-preprint.tex`.

The actual fix requires `sk` to be sampled by an entirely separate CSPRNG
draw, never as any function of `k`. This is what `rust/src/lib.rs`'s
`generate_v8_key` now does: it draws the prime tuple `k` exactly as
before, and — independently — draws a fresh, uniformly random 256-bit
`sk` via `rand::thread_rng().fill_bytes`, with no function relating the
two. `encrypt_bytes_v8`/`decrypt_bytes_v8` key every domain derivation
with this independent `sk`, while `k` continues to be used only for the
arithmetic layer. Under this decoupling, a reduction can sample its own
`k'` locally (identically distributed to `KeyGen`'s output) to run the
arithmetic layer, while genuinely forwarding every domain-derivation call
to an external PRF oracle keyed by the real, hidden `sk` — the simulation
gap this finding identified for v7 does not arise, because knowing `k'`
no longer implies knowing anything about `sk`. This is proved formally as
`Lemma lem:v8-cvf13` in `docs/napseq-eprint-preprint.tex`, new subsection
"V8 Key Schedule and Synthetic Nonce" (`sec:v8`); the same independent-`sk`
construction also closes CVF8's non-standard-assumption residual
(`Lemma lem:v8-cvf8`), since `sk` is now uniform by construction
(`H∞(sk) = 256`), not merely close to uniform conditioned on `k`.

**Scope:** `rust/src/lib.rs` (the same `generate_v8_key` addition as the
CVF3 follow-up above — one key schedule closes both findings) and
`docs/napseq-eprint-preprint.tex` (new subsection `sec:v8`, plus an
erratum remark correcting the original CVF8 response's HKDF proposal).
No change to any v7 function, theorem bound, or game structure. The
Python and C reference implementations have not yet been ported to v8;
tracked as a follow-up.

**Requested action:** please confirm CVF13 can be marked **Fixed** for the
v8 key schedule, superseding the "gap identified, not closed" status
recorded above; v7's reductions retain the same documented residual.

---

## CVF15 — IND-CCA proof's "absorbing the constant" step is invalid: 2(q+q_d)^2 cannot become (q+q_d)^2

**Status:** Open → **Fixed** (already resolved as a byproduct of the CVF11
fix; this response adds the missing cross-reference and audit trail)
**Category:** Algorithm

### Response

Confirmed as a valid objection to the proof text as originally audited.
The committed version of Theorem 3 (IND-CCA)'s combining step derived two
nonce-collision terms, `q^2/2^128` (from the `H1`-reduces-to-IND-CPA step)
and `(q+q_d)^2/2^128` (inherited from Theorem 2's then-current Case 2
bound), bounded their sum via `q^2 + (q+q_d)^2 <= 2(q+q_d)^2`, and then
asserted "absorbing the constant into the stated bound yields
`(q+q_d)^2/2^128`, matching the statement." That step is exactly as
invalid as described: `2x <= x` is false for every `x > 0`, so the algebra
shown establishes only `2(q+q_d)^2/2^128`, not the bare `(q+q_d)^2/2^128`
the theorem claimed. As written, the theorem's stated bound did not follow
from its own proof.

We also confirm this defect was already eliminated in the working copy of
`docs/napseq-eprint-preprint.tex` prior to this finding being filed, as a
side effect of the **CVF11** fix, for a related but distinct reason: CVF11
established that the `(q+q_d)^2/2^128` term being "absorbed" here was
itself unsound on its own terms — it traced back to a bogus union-bound
argument over the adversarially-chosen forgery nonce `N*` in Theorem 2
(INT-CTXT)'s Case 2, which cannot be bounded by a collision probability at
all since `N*` is chosen by the adversary, not sampled by any experiment.
CVF11's fix therefore did not merely correct the coefficient on that term —
it removed the term from Theorem 2 entirely, and by propagation from
Theorem 3's combining step as well. The upshot is that the invalid
`2x <= x` step this finding identifies no longer has any term left to
apply to: the current combining step sums exactly one genuine
nonce-collision term (`q^2/2^128`, from Lemma `lem:hiding`'s `Coll` event)
with the genuine ideal-world forgery term (`q_d/2^256`, from CVF10) via
plain addition, with no factor-of-two approximation, tightening, or
absorption step of any kind. Had CVF11 not already removed the disputed
term, the correct fix would have been exactly this finding's
recommendation — state the honest `2(q+q_d)^2/2^128` constant, or tighten
via `q^2 + (q+q_d)^2 <= (2q+q_d)^2` — rather than silently dropping the
factor of two.

**Fix shipped (2026-07-07, proof-only; formalises an already-resolved
gap).** `docs/napseq-eprint-preprint.tex` now includes:

- **A new audit-finding remark** (`rem:cvf15`, immediately before the
  "Combining" paragraph of Theorem 3 (`thm:ind-cca`)'s proof) recording
  the finding exactly as described above: the invalid `2x <= x` step, the
  fact that it is moot because CVF11 already removed the term it was
  applied to (rather than merely re-deriving its coefficient), and an
  explicit statement of what the fix *would* have needed to be
  (the finding's own recommendation) had that not already happened.
- **A cross-reference** added to the existing "no absorption or doubling
  is needed" sentence in the Combining paragraph, pointing to
  `rem:cvf15`, so a reader auditing that sentence today lands directly on
  the explanation of why no such step is required.
- No change to Theorem 3's stated bound
  (`Adv^PRF(B1) + Adv^PRF(B2) + q^2/2^128 + q_d/2^256`, unchanged since
  the CVF10/CVF11 fixes) or to any other proof step: this finding's
  underlying arithmetic gap was already closed; the fix here is confined
  to making that closure's connection to this specific finding explicit
  and auditable, rather than leaving a reader who encounters this exact
  finding independently unable to verify it against the current text.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex` only: one new remark inserted into
  Theorem 3 (`thm:ind-cca`)'s proof, immediately before the "Combining"
  paragraph, plus a one-clause cross-reference edit to that paragraph's
  existing "no absorption or doubling is needed" sentence. No change to
  Theorem 1, Theorem 2, Theorem 3's statement, or any bound.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: this was
  purely an arithmetic/exposition defect in the security proof, already
  resolved by the CVF11 rewrite; there was never a corresponding code
  defect.

**Known residual:** none. The combining step's final bound
(`q^2/2^128 + q_d/2^256`) is a plain sum of two independently-justified,
non-overlapping terms — there is no remaining approximation, doubling, or
absorption step anywhere in Theorem 3's proof for this finding's objection
to apply to.

**Requested action:** please confirm CVF15 can be marked **Fixed**. The
underlying arithmetic gap was already closed by the CVF11 fix (filed
earlier the same day); this response adds the explicit cross-reference so
the connection between the two findings is auditable. Full technical
detail is in `docs/napseq-eprint-preprint.tex`, `Remark~\ref{rem:cvf15}`
(immediately before the "Combining" paragraph in Theorem 3's
(`thm:ind-cca`) proof).

---

## CVF16 — The PRF assumption on HMAC-SHA256 is used throughout but never formally defined

**Status:** Open → **Fixed** (documentation/proof-level: formal definition
and assumption block added)
**Category:** Documentation

### Response

Confirmed. Every theorem in the Security Analysis section — Theorem 1
(IND-CPA), Theorem 2 (INT-CTXT), Theorem 3 (IND-CCA) — states its bound in
terms of a quantity `Adv^PRF_HMAC-SHA256(B_i)`, and each proof's central
game hop replaces `F(kb,.) = HMAC-SHA256(kb,.)` with a truly random
function on the strength of that quantity being negligible. As you
describe, none of this was ever stated formally: there was no Definition
of the PRF distinguishing game, the distinguisher class, or the advantage
expression itself; there was no explicit Assumption block asserting
"HMAC-SHA256 is a PRF" for the theorems to cite; and — the point you
correctly flag as critical — no key model was ever stated. `kb` is
`key_bytes(k)`, a `5K`-byte serialisation of an ordered tuple of `K`
distinct primes, a structured, non-uniform value with only
`H∞(k) ≈ 2^196`-scale (for `K=10`) effective entropy, and the textbook
Bellare HMAC-is-a-PRF result (and its reduction to compression-function
assumptions) is stated and proved for a *uniformly random* key. That
result does not transfer verbatim to a key drawn from this structured
prime-tuple distribution. Because the PRF term was invoked without a
definition, an explicit assumption, or a justified key model, the proofs
were informal at their single most load-bearing step, exactly as
described, and — since whether the assumption holds at all depends on the
true distribution of `kb` — the bounds risked being not merely informal
but incorrect.

We also want to be precise about scope relative to two already-shipped
fixes this finding overlaps with. The key-model half of this finding was
already substantively addressed by the **CVF8** fix (`Remark~\ref{rem:prf-d}`),
which named the non-uniform-key hypothesis
`Adv^PRF_HMAC-SHA256` in Theorem 1 actually rests on — the PRF advantage
against the real prime-tuple distribution `D`, conditioned on the
key-guessing event, not the conventional uniform-key conjecture — and by
the **CVF13** fix (`Remark~\ref{rem:cvf13}`), which further flagged that
the reductions `B1`/`B2` cannot even be simulated from oracle access alone
without `k` for the arithmetic layer. Both of those remarks, however, were
*qualifying* a term (`Adv^PRF_HMAC-SHA256`) that had no formal home to
qualify: neither the distinguishing game nor a citable assumption
statement existed anywhere in the paper prior to this finding. That gap —
the missing Definition and Assumption block itself, as opposed to the
already-documented key-model caveat — is what this finding identifies and
what we are fixing here.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
now includes, at the top of the Security Analysis section (before
`\subsection{IND-CPA Security}` and Theorem 1):

- **A new audit-finding remark** (`rem:cvf16`) recording the finding
  exactly as described above, including why it is distinct from, but
  connects directly to, the already-shipped CVF8/CVF13 key-model remarks.
- **A formal `Definition~\ref{def:prf-adv}`** ("PRF distinguishing
  advantage"): the standard left-or-right PRF game for a keyed function
  family `F` under an explicit key distribution `D` (real function vs. a
  uniformly random function, lazily realised), and the advantage
  expression `Adv^PRF-D_F(B)` this induces. The definition is stated
  generically over `D` specifically so that it covers *both* the
  conventional uniform-key case (`Adv^PRF_F(B)`, `D = U`, the notation
  used unqualified throughout Theorems 1–3) and the non-uniform,
  prime-tuple-distribution case (`Adv^PRF-D_F(B)`, matching
  `Remark~\ref{rem:prf-d}`'s existing usage) under one formal umbrella,
  rather than leaving the distinction implicit.
- **An explicit `Assumption~\ref{assum:hmac-prf}`** ("HMAC-SHA256 is a PRF
  under a uniformly random key"): states plainly that
  `Adv^PRF_HMAC-SHA256(B)` is negligible for every PPT `B`, under the
  standard uniformly-random 256-bit key — this is the conventional,
  literature-standard assumption every theorem's bound is stated under.
  A "Scope: uniform key only" paragraph states explicitly, per your
  recommendation, that this assumption does *not* by itself justify the
  non-uniform-key quantity `Adv^PRF-D_HMAC-SHA256(B)` being negligible,
  cross-references `Remark~\ref{rem:prf-d}` (which already names that
  distinct hypothesis) rather than silently conflating the two, and
  cross-references `Remark~\ref{rem:cvf8-kdf}`'s HKDF-subkey construction
  as the concrete route — deriving a uniform HMAC subkey from `kb` before
  use — that would let this assumption apply directly in place of the
  weaker, non-standard `Adv^PRF-D` hypothesis. This directly addresses the
  recommendation's second half: rather than leaving the key model
  implicit, the assumption block states in one place exactly which
  hypothesis is standard, which is not, and what would close the gap.
- **Every theorem preamble updated to cite the new machinery by name.**
  Theorem 1 (IND-CPA), Theorem 2 (INT-CTXT), and Theorem 3 (IND-CCA) each
  now open with "Under `Assumption~\ref{assum:hmac-prf}` (HMAC-SHA256 is a
  PRF; `Definition~\ref{def:prf-adv}` ..., `Remark~\ref{rem:cvf16}`)" in
  place of the previously bare, undefined phrase "Under the PRF assumption
  on HMAC-SHA256" — Theorem 1's preamble additionally retains its existing
  cross-references to `Remark~\ref{rem:prf-d}` (key-distribution caveat)
  and `Remark~\ref{rem:cvf13}` (simulation-gap caveat) unchanged, so all
  three now-related remarks (`rem:cvf16`, `rem:prf-d`, `rem:cvf13`) are
  cited together at the one place a reader needs them.
- A new `\newtheorem{assumption}[theorem]{Assumption}` declaration was
  added alongside the existing `theorem`/`lemma`/`definition`/`remark`
  environments so that `Assumption~\ref{assum:hmac-prf}` renders and
  numbers consistently with the rest of the document's theorem-like
  environments.

**Scope of the fix:**
- `docs/napseq-eprint-preprint.tex` only: one new `\newtheorem` declaration,
  one new remark, one new formal definition, one new assumption block (all
  inserted at the start of the Security Analysis section, before
  `\subsection{IND-CPA Security}`), and a short preamble edit to each of
  Theorem 1, Theorem 2, and Theorem 3 citing the new Definition and
  Assumption in place of the previous bare phrase. No change to any
  theorem's stated bound, proof structure, or any other lemma/remark —
  this finding is that the assumption was never given a formal home, not
  that any bound is wrong once it is.
- No change to `napqes.py`, `rust/src/lib.rs`, or `C/napqes.c`: purely a
  specification/proof formalisation, not a code defect.
- Recompiled `docs/napseq-eprint-preprint.tex` with `pdflatex` (three
  passes) to confirm the new `rem:cvf16`, `def:prf-adv`, and
  `assum:hmac-prf` labels resolve, with no undefined-reference or
  multiply-defined-label warnings remaining on the final pass.

**Known residual (already tracked, not introduced by this fix).** The
non-uniform-key gap this finding also raised is not closed by adding the
Definition/Assumption block — it was never claimed to be. As already
documented under CVF8/CVF13, the fully rigorous closure is the HKDF-subkey
construction (`Remark~\ref{rem:cvf8-kdf}`), which has not been
implemented in code; until it lands, `Adv^PRF_HMAC-SHA256(B_1)` in
Theorem 1 must continue to be read, per `Remark~\ref{rem:prf-d}`, as the
non-standard `Adv^PRF-D_HMAC-SHA256(B_1)` quantity rather than as a direct
instance of `Assumption~\ref{assum:hmac-prf}`.

**Requested action:** please confirm CVF16 can be marked **Fixed** as a
documentation/proof-formalisation fix, with the pre-existing CVF8/CVF13
non-uniform-key residual tracked separately and unaffected by this change.
Full technical detail is in `docs/napseq-eprint-preprint.tex`,
`Remark~\ref{rem:cvf16}`, `Definition~\ref{def:prf-adv}`, and
`Assumption~\ref{assum:hmac-prf}` (start of the Security Analysis section,
immediately before `\subsection{IND-CPA Security}`).

## CVF17 — `varint` is defined only as "unsigned LEB128 encoding", which is itself never defined

**Status:** Open → **Fixed** (documentation)
**Category:** Readability

### Response

Confirmed. The Notation section stated only that `varint(x)` denotes
"unsigned LEB128 encoding of non-negative integer `x`," without ever
defining LEB128's byte layout, continuation-bit convention, or
canonicality requirement, and without a normative reference. As you note,
the concrete decoding hazards (overlong encodings, continuation-bit
mishandling, unbounded length) are a separate, code-level finding; this
finding is about the specification being unreproducible on its own.

**Fix shipped (2026-07-07, documentation-only).**
`docs/napseq-eprint-preprint.tex`'s Notation section now includes:

- A new audit-finding remark (`rem:cvf17`) recording the finding.
- A formal `Definition~\ref{def:leb128}` ("Unsigned LEB128 encoding")
  stating the encoding explicitly: 7 data bits per byte, the high bit as
  a continuation flag, little-endian group order (least-significant group
  first), given both as a byte-construction rule and as an equation over
  the base-$2^7$ digit decomposition of `x`.
- An explicit **canonicality** clause: a conforming decoder accepts only
  the minimal-length encoding of a given integer, and MUST reject (i)
  non-canonical/overlong encodings and (ii) inputs exceeding the maximum
  permitted integer width — pinned to `x < 2^64` (10 groups), matching the
  `be8` fixed-width field this encoding was replaced by for block-mode
  tokens (CVF1) — as well as truncated input.
- The `varint(x)` bullet in the Notation itemize now forward-references
  `Definition~\ref{def:leb128}` instead of leaving the term undefined.

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only (Notation
section) — one new remark, one new definition, one bullet edit. No change
to `napqes.py`/`rust`/`C`: the decoder-hardening half of this finding
(rejecting overlong/non-canonical input and bounding length at decode
time) is tracked as the separate implementation-level finding referenced
in the remark, not fixed here.

**Known residual.** The current reference decoders
(`_b128_decode_tokens` in `napqes.py` and equivalents) do not yet enforce
the canonicality/max-width rules stated in `Definition~\ref{def:leb128}`
at decode time; this is the separate decoding-hazard finding the remark
points to and is not closed by this documentation fix.

**Requested action:** please confirm CVF17 can be marked **Fixed** as a
documentation fix, with decoder hardening tracked under the separate
finding it references. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, `Remark~\ref{rem:cvf17}` and
`Definition~\ref{def:leb128}` (Notation section).

## CVF18 — Padding-codepoint derivation names domain `0x06` but omits the concrete formula

**Status:** Open → **Fixed** (documentation)
**Category:** Documentation

### Response

Confirmed. The Plaintext Padding subsection and Table 1 named domain
`0x06` and its output range `[32,126]` but never stated how the 32-byte
`Derive_0x06(kb, N, be4(pad_idx))` output is reduced to a single codepoint
in that range — which bytes are consumed and what mapping is applied —
so the padding was not reproducible from the specification, and the
unstated reduction into a 95-value range was exactly the kind of mapping
that can introduce modulo bias if done naively.

**Fix shipped (2026-07-07, documentation-only).**
`docs/napseq-eprint-preprint.tex`'s Plaintext Padding subsection now
includes:

- A new audit-finding remark (`rem:cvf18`) recording the finding.
- A formal `Definition~\ref{def:padcodepoint}` ("Padding codepoint ---
  domain `0x06`") stating the exact formula, matching the reference
  implementation (`napqes.py`'s `_pad_message`):
  `pad_i = (Derive_0x06(kb, N, be4(i))[0:4]_be32 mod 95) + 32`, i.e. the
  first 4 bytes of the 32-byte HMAC output, interpreted big-endian, are
  taken and reduced modulo 95 before the `+32` shift — the same
  `[0:n]_be k` convention and reduce-then-shift pattern already used by
  Definitions 2–4 (`derive_noise_char`, `derive_noise_addend`,
  `derive_real_addend`).
- `Remark~\ref{rem:modbias}` (modulo-bias analysis) is extended to cover
  `Definition~\ref{def:padcodepoint}`'s `m = 95` modulus: the relative
  deviation from uniform is bounded by `95/2^32 < 2^-25`, statistically
  dominated by the underlying PRF advantage against HMAC-SHA256 and
  therefore negligible — addressing the recommendation's request to
  either document the bias as negligible or use rejection sampling; we
  document it as negligible, consistent with the treatment already given
  to the other three finite-range reductions in the same remark, rather
  than introduce rejection sampling asymmetrically for just this one
  domain.

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only (Plaintext
Padding subsection and `rem:modbias`) — one new remark, one new
definition, one extended bias remark. No change to `napqes.py`/`rust`/`C`:
the formula stated is already what the shipped code computes
(`(int.from_bytes(d[:4], 'big') % 95) + 32`); this finding is that the
paper never wrote the formula down, not that the code is wrong.

**Requested action:** please confirm CVF18 can be marked **Fixed** as a
documentation fix. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, `Remark~\ref{rem:cvf18}`,
`Definition~\ref{def:padcodepoint}`, and the extended
`Remark~\ref{rem:modbias}` (Plaintext Padding subsection).

## CVF19 — Wire-format ciphertext component $\widetilde{B}$ is used without a formal definition

**Status:** Open → **Fixed** (documentation)
**Category:** Documentation

### Response

Confirmed. The wire-format section introduced `C = N || B̃ || T` and
described `B̃` only in prose — "the domain-`0x07` XOR-masked fixed-width
token blob" — with the defining equation
`B̃ = B ⊕ ks_0x07(N)` (truncated to `|B|` bytes), the encode-then-mask
operation order, and the keystream length/truncation rule stated only
much later, inside the hiding lemma's proof. As you note, this means the
wire format could not be reproduced from the wire-format section alone.

**Fix shipped (2026-07-07, documentation-only).**
`docs/napseq-eprint-preprint.tex`'s Wire Format (Version 7) subsection now
states, at the point `B̃` is first introduced:

- The explicit defining equation
  `B̃ = B ⊕ ks_0x07(N)[0:|B|]`, with
  `ks_0x07(N) = Derive_0x07(kb,N,be4(0)) || Derive_0x07(kb,N,be4(1)) || ···`
  given inline (32-byte `Derive_0x07` blocks indexed `0,1,2,...`,
  generating only as many blocks as needed and truncating the final block
  to the remaining length).
- An explicit statement of the encode-then-mask operation order: (1)
  assemble `B` from the token vector via the token-construction loop
  (Definitions 1–4), (2) generate the domain-`0x07` keystream, (3) XOR the
  two equal-length byte strings — with forward references to the
  token-construction definitions and to the hiding lemma's proof (where
  the independence-from-`B` property of this exact equation is proved).
- A new audit-finding remark (`rem:cvf19`) recording the finding and
  cross-referencing where the equation was previously stated (only inside
  the hiding-lemma proof) versus where it now also appears (at the point
  of introduction).

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only (Wire Format
v7 subsection) — one new equation with explanatory text, one new remark.
No change to the equation's content or to the hiding lemma's proof: the
relation was already correct and already proved elsewhere in the
document; this fix only relocates/duplicates the defining equation to the
point where `B̃` is first introduced, per the recommendation.

**Requested action:** please confirm CVF19 can be marked **Fixed** as a
documentation fix. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, `Remark~\ref{rem:cvf19}` (Wire Format
(Version 7) subsection, immediately after `C = N \| \widetilde{B} \| T`
is introduced).

## CVF20 — INTCTXT Case 2 split ignores the AAD, and freshness is defined on the ciphertext only, not `(c, aad)`

**Status:** Open → **Fixed** (proof-only)
**Category:** Architecture

### Response

Confirmed, and this was a genuine gap rather than a merely cosmetic one.
Two distinct issues, both valid: (1) Case 2's second sub-case
(`B̃* = B̃_i ∧ T* ≠ T_i`) claimed "the tag input is identical to `x_i`,"
which holds only if `aad* = aad_i` — never assumed — so a forgery with
`B̃* = B̃_i` but `aad* ≠ aad_i` (hence `x* ≠ x_i`) was wrongly dismissed
as unable to contribute instead of being routed to the Case 1 argument.
(2) Freshness was defined as `c* ∉ {c_1,...,c_q}` alone, silently
excluding the legitimate forgery attempt "replay `c_i` verbatim with a
new `aad* ≠ aad_i`" from the experiment's scope rather than proving it
infeasible, which is not the standard INT-CTXT freshness object (the pair
`(c,aad)`).

**Fix shipped (2026-07-07, proof-only).**
`docs/napseq-eprint-preprint.tex`'s Theorem 2 (INT-CTXT) proof now:

- **Restates freshness over the pair `(c*, aad*)`:** the proof's opening
  paragraph now requires `(c*, aad*) ∉ {(c_1,aad_1), ..., (c_q,aad_q)}`,
  explicitly noting that `c* = c_i` with `aad* ≠ aad_i` is therefore a
  legitimate forgery attempt, addressed in Case 2.
- **Re-splits Case 2 on `x* = x_i` versus `x* ≠ x_i`** (for the query `i`
  with `N_i = N^*`), invoking injectivity of the domain-first tag-input
  encoding `0x03‖N‖be4(|aad|)‖aad‖B̃` (specifically, injectivity of
  `be4(|aad|)‖aad` in `aad`), instead of the old, incomplete split on
  `B̃*` alone:
  - The `x* ≠ x_i` branch now explicitly covers both `B̃* ≠ B̃_i` *and*
    `B̃* = B̃_i ∧ aad* ≠ aad_i` (which includes the replay-with-new-AAD
    attack) — in every such case `x*` was never queried, and the branch
    reduces verbatim to Case 1's PRF-reduction bound.
  - The `x* = x_i` branch is shown to force `aad* = aad_i` and
    `B̃* = B̃_i` jointly (by the same injectivity), so a forgery landing
    here either has `T* = T_i` — giving `(c*,aad*) = (c_i,aad_i)`,
    excluded by the (now pair-based) freshness requirement — or
    `T* ≠ T_i`, which fails tag verification outright since the unique
    correct tag for `x_i` is `T_i`. Either way this branch contributes no
    successful, freshness-respecting forgery.
- A new audit-finding remark (`rem:cvf20`) recording both defects and the
  fix, cross-referencing the retained `Remark~\ref{rem:cvf11}` argument
  (no probability term attaches to Case 2, since `N*` is
  adversarially-chosen, not sampled) which continues to apply unchanged to
  the re-split branches.

The bound itself is unchanged — this fix corrects the *justification* for
why Case 2 contributes no additional term beyond Case 1's, including for
the replay-with-new-AAD attempt, which the old proof silently excluded
rather than proved infeasible; it does not change
`Adv^INT-CTXT_NAPQES(A) ≤ Adv^PRF_HMAC-SHA256(B_2) + q_v/2^256`.

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only (Theorem 2's
proof: the freshness-definition sentence and the entire Case 2 paragraph
rewritten; Case 1 and the final combining step are unchanged) — one new
remark, one rewritten paragraph. No change to `napqes.py`/`rust`/`C`: this
is a proof-argument correction, not a code or wire-format change.

Recompiled `docs/napseq-eprint-preprint.tex` with `pdflatex` (two passes)
to confirm `rem:cvf17`–`rem:cvf20`, `def:leb128`, and
`def:padcodepoint` all resolve, with no undefined-reference or
multiply-defined-label warnings.

**Requested action:** please confirm CVF20 can be marked **Fixed** as a
proof-only fix. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, `Remark~\ref{rem:cvf20}` and the
rewritten Case 2 paragraph (Theorem~\ref{thm:int-ctxt}'s proof).

## CVF21 — IND-CCA proof invokes Theorem 2 (INT-CTXT) in a decryption-oracle, `q+q_d` regime it never proves

**Status:** Open → **Fixed** (proof-only)
**Category:** Architecture

### Response

Confirmed, with one correction of scope: the `q+q_d`-substitution half of
the finding describes text that a prior fix (CVF11) had already removed
from the current document (the same "already-fixed-by-an-earlier-CVF"
situation as CVF15), but the finding's deeper, still-live objection —
that Theorem 2's statement never establishes the *adaptive,
real-time-oracle* regime the IND-CCA proof actually needs, and that the
forger's own challenge-generation step was omitted from the simulation
description — was valid and is fixed here.

Checked point by point: Theorem 2 (`thm:int-ctxt`) described `q_v` only
as a count of "forgery-submission attempts," language that reads as a
batch of final guesses rather than a genuine decryption/verification
oracle answered adaptively in real time. The IND-CCA proof
(`thm:ind-cca`), however, constructs a forger `A'` using "the B&N
formulation that grants the INT-CTXT adversary both an encryption oracle
and a decryption oracle" — i.e. exactly the stronger, adaptive
multi-query regime the finding describes — without Theorem 2 ever having
been proved sound in that regime. We also confirm gap (i) as stated in
the abstract: a `q^2/2^128` term substituting `q+q_d` for an
encryption-nonce-collision parameter would have no basis, since
decryption queries generate no nonces — but we found this specific
substitution no longer appears anywhere in the current bound: the CVF11
fix (filed the same day, prior to this finding) already removed Case 2's
`q^2/2^128` term from Theorem 2 entirely, for an unrelated but
compounding reason (it traced to a bogus probability argument over an
adversarially-chosen nonce), so there is no `q`-dependent term left in
Theorem 2 for the IND-CCA proof to (mis)parametrise by `q+q_d` in the
current text. Gap (ii) — the forger `A'` must itself produce the
challenge ciphertext `c*` (sampling `b` and encrypting `m_b`, i.e. `q+1`
encryption queries, not `q`) to run `A`'s post-challenge phase at all —
was confirmed exactly as described: the prior construction's step list
went straight from "forward every encryption query" to "forward every
decryption query" with no challenge-generation step in between, while
asserting "`A'`'s simulation is perfect" without showing it.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
now includes:

- **A new audit-finding remark** (`rem:cvf21`, after `rem:cvf20` and
  before Theorem 2's proof) recording the finding exactly as described
  above, including the now-moot status of the `q+q_d` nonce-collision
  substitution (closed by CVF11, not by this fix) and the two compounding
  gaps.
- **Theorem 2's statement** now states explicitly that the experiment
  "grants `A` a genuine encryption oracle and a genuine, *adaptive*
  decryption/verification oracle — `q_v` counts real-time oracle queries,
  each answered ... before `A` chooses its next query, not a batch of
  final guesses evaluated only once at the end."
- **An adaptivity argument** (inside `rem:cvf21`) proving the existing
  Case 1/Case 2 bound already holds verbatim for this stronger, adaptive
  regime: Case 2 is resolved by injectivity alone, independent of
  ordering or prior answers; Case 1's ideal-world bound relies only on
  each queried input being fresh at the moment of query, and lazy
  sampling of the random function gives every not-yet-queried point an
  independent uniform value regardless of what earlier, distinct queries
  revealed — so the per-query `2^-256` guessing probability, and the
  `q_v/2^256` union bound, hold unchanged whether the `q_v` queries are a
  final batch or fully adaptive with real-time feedback. No change to the
  numerical bound was required — only to establishing it for the correct
  regime.
- **The IND-CCA proof's forger `A'` is rewritten** to make the challenge
  phase an explicit, counted construction step: `A'` samples `b` itself
  and queries its own encryption oracle on `m_b` as its `(q+1)`-th
  encryption query, records the resulting `c*`, and only then invokes
  `A`'s post-challenge phase — replacing the previous single sentence
  that asserted perfect simulation without showing it. A new paragraph
  demonstrates perfection directly: every value `A` observes (every
  ciphertext, including `c*`; every decryption answer, in both phases) is
  produced by the real INT-CTXT challenger's real oracles under one
  consistent hidden key, so `A`'s view is distributed identically to
  game `H_0`.
- **Theorem 3 (IND-CCA)'s statement and proof** are updated to state that
  `A'` uses `q+1` encryption-oracle queries when invoking Theorem 2 (which
  carries no encryption-query-count term, so this changes nothing
  numerically) and `q_v = q_d` decryption/verification queries counted
  across both phases (Remark~`rem:cvf22`, filed alongside this finding).

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only — one new
remark (`rem:cvf21`), a clarifying sentence added to Theorem 2's
statement, and a rewrite of the forger `A'`'s construction and
perfect-simulation argument inside Theorem 3's proof (shared with the
CVF22/CVF23 fixes below, since all three findings concern the same
passage). No change to any theorem's numerical bound, and no change to
`napqes.py`/`rust`/`C`: this is purely a proof-rigor correction.

**Known residual:** none beyond the pre-existing CVF13 simulation-gap
caveat (already tracked), which this fix does not affect.

**Requested action:** please confirm CVF21 can be marked **Fixed** as a
proof-only fix, noting the `q+q_d`-substitution portion of the finding
was independently mooted by the earlier CVF11 fix rather than fixed here.
Full technical detail is in `docs/napseq-eprint-preprint.tex`,
`Remark~\ref{rem:cvf21}` (immediately before Theorem 2's proof) and the
rewritten forger `A'` construction in Theorem 3's (`thm:ind-cca`) proof.

---

## CVF22 — IND-CCA proof: event `D` restricted to the query phase, leaving post-challenge forgeries uncovered

**Status:** Open → **Fixed** (proof-only)
**Category:** Architecture

### Response

Confirmed. Game `H_0` explicitly permitted `A` to call the decryption
oracle after receiving the challenge ciphertext ("`A` may call `D` on any
`c != c*`"), but the bad event `D` was defined as a fresh valid
submission occurring only "during the query phase" — the pre-challenge
phase alone. A fresh valid ciphertext submitted post-challenge makes
`H_0` and `H_1` diverge by exactly the same case analysis as a
pre-challenge query, yet was not counted by that restricted `D`, so the
identical-until-bad bound `|Pr[H_0]-Pr[H_1]| <= Pr[D]` again failed to
cover every distinguishing execution — the same defect family as CVF14,
here applying to the *phase* of the query rather than to replays.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
now includes:

- **A new audit-finding remark** (`rem:cvf22`, immediately after
  `rem:cvf14` and before Theorem 3's statement) recording the finding
  exactly as described above.
- **Event `D`'s definition rewritten** to remove the "during the query
  phase" restriction: `D` is now the event that `A` submits, "at any
  point in the experiment — before or after the challenge alike," a
  fresh valid `(c,aad)` pair to `D`.
- **The transition paragraph's case analysis** now states explicitly that
  the argument "is identical in the pre-challenge and post-challenge
  phases — nothing about it depends on whether the challenge has been
  issued yet, only on whether `(c,aad) in T`," so restricting `D` to one
  phase was an unjustified narrowing rather than a consequence of the
  case analysis itself.
- **The forger `A'`'s construction** (shared with the CVF21/CVF23 fixes)
  now explicitly forwards `A`'s decryption queries in *both* phases —
  step 2 for pre-challenge queries, a new step 4 for post-challenge
  queries after `A'` itself generates and hands back the challenge
  ciphertext in step 3 — declaring event `D` (and winning) on a fresh,
  non-`bot` result in either step, so the reduction bounding `Pr[D]`
  genuinely covers both phases, matching `D`'s corrected definition.
- **`q_d` is now stated as counting decryption queries across both
  phases** in Theorem 3's statement and in the paragraph applying
  Theorem 2 to bound `Pr[D]`.

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only — one new
remark, the event-`D` definition, the transition paragraph's case
analysis, and the forger construction (shared edit with CVF21/CVF23). No
change to any theorem's numerical bound (the bound already had a
`q_d`-sized term; this fix corrects what `q_d` is proved to cover) and no
change to `napqes.py`/`rust`/`C`.

**Known residual:** none.

**Requested action:** please confirm CVF22 can be marked **Fixed** as a
proof-only fix. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, `Remark~\ref{rem:cvf22}` and the
rewritten event-`D` definition and forger construction in Theorem 3's
(`thm:ind-cca`) proof.

---

## CVF23 — IND-CCA proof: freshness-set mismatch and non-standard `c`-only freshness weaken the notion

**Status:** Open → **Fixed** (proof-only)
**Category:** Architecture

### Response

Confirmed, two related defects. First, the bad event `D` used the
freshness set `{c_1,...,c_q}` (the adversary's own `q` encryption
queries), but from the INT-CTXT challenger's point of view the challenge
ciphertext `c*` is itself an oracle output too, once the forger `A'`
generates it — the two sets were never reconciled, though we note this
was harmless only because of the second defect: Game `H_0` forbade `A`
from querying `D` on *any* `c = c*` regardless of `aad`, which is itself
non-standard — the usual AEAD IND-CCA game forbids only the specific
pair `(c*,aad*)` and *permits* `D(c*, aad != aad*)` as a legitimate
forgery attempt. Consistent with the `c`-only (rather than `(c,aad)`-pair)
freshness already identified and corrected for Theorem 2 by CVF20, the
game as written therefore silently weakened the adversary by never even
letting it attempt the AAD-substitution forgery, rather than proving that
forgery infeasible — so the composed result established a
weaker-than-standard IND-CCA notion.

**Fix shipped (2026-07-07, proof-only).** `docs/napseq-eprint-preprint.tex`
now includes:

- **A new audit-finding remark** (`rem:cvf23`, immediately after
  `rem:cvf22` and before Theorem 3's statement) recording both defects
  exactly as described above.
- **Game `H_0` corrected** to forbid only the exact pair `(c*, A*)`,
  explicitly stating `A` "may query `D(c*, aad)` for any `aad != A*`" —
  the standard AEAD `(c,aad)`-pair freshness notion, not the strictly
  weaker `c`-only restriction an earlier draft imposed.
- **The table `T` (Game `H_1`) redefined** to include the challenge
  triple `(c*, A*, m_b)` once the challenge is issued, so `T`'s freshness
  set is exactly `{(c_1,aad_1),...,(c_q,aad_q)} U {(c*,aad*)}` — the
  INT-CTXT challenger's own complete output set, reconciling the
  mismatch. A note clarifies that the one query the game forbids
  outright, `D(c*,A*)`, would trivially hit this table entry were it
  permitted, but since `A` may never make that exact query, `D'` never
  needs to disclose `m_b` to answer any query it actually receives — and
  correspondingly, the "`H_1` reduces to IND-CPA" paragraph now notes
  explicitly why the IND-CPA adversary `A''` (who does not know `b`)
  never needs to reconstruct that one table entry either.
- **The event `D` and forger `A'` construction** (shared edit with
  CVF21/CVF22) now measure freshness against this corrected, reconciled
  set throughout.

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only — one new
remark, Game `H_0`'s restriction, Game `H_1`'s table population rule, and
one clarifying sentence in the "`H_1` reduces to IND-CPA" paragraph
(shared edit with CVF21/CVF22). No change to any theorem's numerical
bound and no change to `napqes.py`/`rust`/`C`: NAPQES's actual decryption
function already accepts `(c*, aad != aad*)` as an ordinary decryption
call with no special-casing on `c`, so this fix aligns the *proof's* game
definition with both the standard notion and the real implementation's
behaviour, rather than changing either.

**Known residual:** none.

**Requested action:** please confirm CVF23 can be marked **Fixed** as a
proof-only fix. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, `Remark~\ref{rem:cvf23}` and the
rewritten Game `H_0`/Game `H_1` definitions in Theorem 3's
(`thm:ind-cca`) proof.

---

## CVF24 — Grover post-quantum key-search statement is cryptic and potentially misleading

**Status:** Open → **Fixed** (readability)
**Category:** Readability

### Response

Confirmed. The Post-Quantum Analysis section stated only "Grover's
algorithm halves the exponent, giving a post-quantum key-search
complexity of ≈2^98, well above 128-bit thresholds," as a bare figure
with no operational caveats. As you note, this invites two
misreadings: that 2^98 is an ordinary, achievable attack cost, and —
more importantly — that it is a *parallelizable* cost that more hardware
could bring within reach. Neither is true: Grover's algorithm requires
≈2^(n/2) essentially *sequential* oracle queries, and the
Bennett–Bernstein–Brassard–Vazirani (BBBV) optimality result together
with Zalka's parallelization analysis show that distributing the search
over `S` machines yields only a `sqrt(S)` speedup — wall-clock depth
stays ≈2^(n/2)/sqrt(S) and total work is unchanged — in sharp contrast to
classical brute force, which parallelizes linearly. Presented as a bare
number, the figure reads like a hardware-scalable classical cost rather
than the sequential-depth lower bound it is.

**Fix shipped (2026-07-07, readability-only).**
`docs/napseq-eprint-preprint.tex`'s Post-Quantum Analysis section now
includes:

- **A new audit-finding remark** (`rem:cvf24`, at the start of the
  section) recording the finding and both misreadings it invites.
- **The "SHA-256 and Grover's algorithm" paragraph rewritten** to state
  explicitly that the 2^128 figure is a *sequential query depth* bound,
  citing the BBBV optimality result and Zalka's `sqrt(S)`-only
  parallelization speedup, and noting this cost cannot be reduced by
  adding hardware, unlike classical brute force.
- **The "Key space" paragraph rewritten** to apply the identical
  sequential-depth framing to the 2^98 post-quantum key-search figure,
  with the same BBBV/Zalka citations, and a closing sentence stating that
  both the 2^128 and 2^98 figures are sequential-depth quantities far
  beyond feasibility, and that Grover's algorithm is largely irrelevant
  to NAPQES's practical post-quantum security margin at these lengths.
- **Two new bibliography entries** added (`bbbv1997`: Bennett, Bernstein,
  Brassard, Vazirani, "Strengths and Weaknesses of Quantum Computing,"
  SIAM J. Computing 26(5), 1997; `zalka1999`: C. Zalka, "Grover's quantum
  searching algorithm is optimal," Phys. Rev. A 60(4), 1999), cited from
  both rewritten paragraphs.

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only (Post-Quantum
Analysis section and bibliography) — one new remark, two rewritten
paragraphs, two new `\bibitem`s. No change to any theorem, bound, or
`napqes.py`/`rust`/`C`: this finding is purely about how an already-correct
figure was presented, not about the figure's correctness.

**Known residual:** none.

**Requested action:** please confirm CVF24 can be marked **Fixed** as a
readability fix. Full technical detail is in
`docs/napseq-eprint-preprint.tex`, `Remark~\ref{rem:cvf24}` and the
rewritten "SHA-256 and Grover's algorithm" / "Key space" paragraphs
(Post-Quantum Analysis section).


