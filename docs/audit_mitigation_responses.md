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

> **Superseded in part by V3-CVF2 (third-round audit, 2026-08-08).** The
> argument above for keeping the noise layer rests on Lemma `lem:tar`. That
> lemma was retired in V2-CVF2 (its "same nonce" hypothesis is unsatisfiable
> under v8's message-derived synthetic nonce) and does not exist in
> `docs/napseq-eprint-v3.tex`; every citation of it in this entry is
> therefore dangling and is retained only as a historical record. The
> replacement property is Theorem `thm:lh-ind-cpa` (LH-IND-CPA-det) with
> Corollary `cor:length-leak`. Critically, the *attribution* above is also
> now known to be wrong: ciphertext length is a function of the padding
> bucket alone, so the property belongs to the padding ladder, not to the
> noise tokens, the prime map, or the ciphertext expansion
> (Proposition `prop:expansion-neutral`). The conclusion — keep the layer —
> stands, but on patent and interoperability grounds rather than on a
> security property. See V3-CVF2 below.

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

---

# Second-Round Audit (ABDK Consulting, "NAPQES v2 — AEAD Scheme Audit," 2026-07-19)

The findings below are from the second-round report reviewing
`docs/napseq-eprint-v2.tex`. The report reuses low finding IDs (CVF1–CVF14)
that are independent of, and unrelated to, the first-round CVF1–CVF24
entries above (which concern `docs/napseq-eprint-preprint.tex`). To avoid
ID collisions, each second-round finding is recorded here under a
`V2-CVFn` prefix.

## V2-CVF1 — The v8 IND-CPA theorem is false as stated, because v8 is a deterministic scheme while the notion it is proved against lets the adversary query the challenge message

**Status:** Open → **Fixed** (proof/definition correction; no code change)
**Category:** Flaw
**Severity:** Major

### Response

Confirmed. `Theorem~\ref{thm:ind-cpa-v8}` was proved against
`Definition~\ref{def:ind-cpa}`'s unrestricted left-or-right IND-CPA game
verbatim, describing `Encrypt_v8` as "already randomized, via the
synthetic nonce." That description is wrong: the synthetic nonce
`N = HMAC(sk, 0x0A‖be4(|A|)‖A‖M)` is a deterministic function of `(A,M)`
and contributes no randomness, so `Encrypt_v8` is a pure function of its
input. Because the unrestricted game lets the adversary query the
encryption oracle on either challenge message, the distinguisher the
finding describes (query `y = Encrypt_v8(A*, m0)`, submit the challenge,
guess `b'=0` iff `c* = y`) wins with advantage ≈ 1/2 against a claimed
bound of `Adv^PRF + q²/2^128`. We also agree on the exact location of the
unsoundness: the proof's freshness step invoked
`Lemma~\ref{lem:v8-cvf3}` (which bounds collisions only between *distinct*
`(A,M)` pairs) to argue the challenge nonce is fresh, but said nothing
about the case where the challenge pair is itself among the adversary's
own oracle queries — in which case the challenge nonce coincides with a
prior nonce with probability *one*, not the claimed birthday bound. Since
`Corollary~\ref{cor:v8-security}`'s IND-CCA bound composes on top of the
same IND-CPA claim, it inherits the identical defect, as the finding
notes.

**Fix shipped (proof/definition-level, 2026-07-21).**
`docs/napseq-eprint-v2.tex`:

- **New audit-finding remark** (`rem:cvf25`, immediately before
  `Theorem~\ref{thm:ind-cpa-v8}`) records the finding, the explicit
  distinguisher, and the exact unsound proof step, matching the analysis
  above.
- **New formal definition**, `Definition~\ref{def:ind-cpa-det}`
  ("Restricted IND-CPA for deterministic/misuse-resistant AE"), placed
  alongside `Definition~\ref{def:ind-cpa}` in the Security Analysis
  section. This is the recommended remediation: rather than making
  `Encrypt_v8` genuinely randomized (which would reopen the
  nonce-misuse-resistance property it is specifically designed to
  provide), it restates the standard left-or-right IND-CPA game with the
  two restrictions standard for deterministic/misuse-resistant AE
  (Rogaway and Shrimpton, Eurocrypt 2006): (i) no repeated
  `(A,M)` encryption-oracle queries, and (ii) no encryption-oracle query,
  in either phase, on either challenge message `(A*,m0)`/`(A*,m1)`.
  Restriction (ii) is precisely what rules out the finding's distinguisher.
- **`Theorem~\ref{thm:ind-cpa-v8}` retitled "IND-CPA-det, v8"** and
  restated against `Definition~\ref{def:ind-cpa-det}` instead of the
  unrestricted `Definition~\ref{def:ind-cpa}`; the false "already
  randomized" description is removed. The proof's freshness argument is
  corrected: restriction (ii) guarantees every oracle query `(Ai,Mi)` is
  distinct from the challenge pair `(A*,mb)` regardless of which message
  the challenger encrypted, so `Lemma~\ref{lem:v8-cvf3}`'s collision bound
  now validly applies to every compared pair, restoring the `q²/2^128`
  term legitimately (rather than by the previously-unsound assertion).
- **`Corollary~\ref{cor:v8-security}`** retitled "INT-CTXT and
  IND-CCA-det, v8": the IND-CCA bound is now stated as `IND-CCA-det`,
  with a new remark (`rem:cvf25-cca`) explaining that the IND-CCA
  experiment has the identical left-or-right challenge step (hence the
  identical trivial distinguisher) and so inherits Definition
  \ref{def:ind-cpa-det}'s restrictions (i)–(ii) on the adversary's
  encryption-oracle queries; the INT-CTXT bound is unaffected (no
  left-or-right challenge, so the determinism issue does not apply to
  it).
- The "Scope and residual" remark (`rem:v8-scope`) now lists this
  second-round CVF1 finding among those `Theorem~\ref{thm:ind-cpa-v8}`/
  `Corollary~\ref{cor:v8-security}` close, noting explicitly that (unlike
  CVF3/CVF8/CVF13) this fix changed *which* security notion is proved,
  not merely the bound's constant — no unrestricted-IND-CPA/IND-CCA claim
  is sound for a deterministic scheme.

**Scope of the fix:** `docs/napseq-eprint-v2.tex` only (one new
definition, one new theorem-preamble remark, one new corollary-scoped
remark, and the corresponding theorem/proof/corollary rewrites). No
change to `Enc_v8`/`Dec_v8` in any language (Rust/Python/C): as the
finding's own recommendation notes, this is a correction to the security
definition and its proof, not to the construction. Verified via a 3-pass
`pdflatex` compile (exit 0 each pass, zero undefined-reference /
multiply-defined-label warnings on the final pass).

**Known residual:** none. The restricted-query notion
(`Definition~\ref{def:ind-cpa-det}`) is the standard, sound notion for a
deterministic/misuse-resistant AEAD scheme (the same family AES-GCM-SIV
is analysed under), and both `Theorem~\ref{thm:ind-cpa-v8}` and
`Corollary~\ref{cor:v8-security}` are now proved against it without gaps.

**Requested action:** please confirm V2-CVF1 can be marked **Fixed /
Closed** on your tracker.

---

## V2-CVF2 — The v8 ciphertext length depends on plaintext content and, under chosen associated data, reliably reveals the plaintext length bucket


**Status:** Open → **Fixed**
**Category:** Flaw
**Severity:** Major

### Response

Confirmed. `Theorem~\ref{thm:ind-cpa-v8}`'s proof incorrectly asserted that
the traffic-analysis lemma (`Lemma~\ref{lem:tar}`, "ciphertext length is
decorrelated from plaintext content") "applies verbatim ... only on it
being fresh" once `kb` is replaced by `sk`. As the finding shows,
`Lemma~\ref{lem:tar}`'s hypothesis — both compared plaintexts encrypted
under the *same* nonce `N` — holds for v7 (the IND-CPA challenger samples
`N*` independently of which message is encrypted) but can never hold for
two distinct messages under v8, because the synthetic nonce
`N = HMAC(sk, 0x0A‖be4(|A|)‖A‖M)` is itself a function of the message.
Since the noise-token count is pseudorandom in the nonce, v8 ciphertext
length depends on message content beyond the padding bucket, and — as the
finding demonstrates — an adversary who can obtain several ciphertexts of
one fixed target message under varying associated data (a mild capability,
since AAD is ordinarily unauthenticated routing metadata rather than a
secret) can average out the noise and recover the padding bucket reliably,
strengthening the pre-existing, single-shot CAV-003 leak into a dependable
oracle. We agree this is a real, previously-undocumented residual specific
to v8, separate from the deterministic-equality issue.

**Fix shipped (proof + code, 2026-07-21).** `docs/napseq-eprint-v2.tex`:

- The false citation of `Lemma~\ref{lem:tar}` has been removed from
  `Theorem~\ref{thm:ind-cpa-v8}`'s proof. The proof now states only that
  the hiding argument (`Lemma~\ref{lem:hiding}`) carries over to v8 (it
  depends solely on the nonce being fresh, not on how it is generated);
  length-independence of `|c*|` is instead established separately, by
  construction, via the code fix below.
- A new remark, `rem:cvf2-v2-tar-scope`, added immediately after
  `Lemma~\ref{lem:tar}`'s existing scope remark, explains precisely why the
  lemma's "same nonce" hypothesis is satisfiable for v7 but never for v8.
- A new remark, `rem:v8-length-oracle`, added in the v8 construction
  section, formalises the averaging attack the finding describes (samples
  `N_tok,i = R + W_i` sharing a common `R` but independent `W_i`; averaging
  recovers the bucket `B`), states precisely what is and is not recovered
  (bucket, not exact codepoint count), and documents the shipped fix below.
- The "Scope and residual" remark for the v8 construction
  (`rem:v8-scope`) now records that CVF2 required a dedicated fix to the
  token-emission schedule, distinct from CVF3/CVF8/CVF13's synthetic-nonce
  fix (which, on its own, strengthens rather than closes CVF2).
- The CAV-003 entry (Section~\ref{sec:caveats} and `docs/CAVEATS.md`) is
  updated to record the fix and cross-reference this finding as `V2-CVF2`.

**Code fix shipped, all three reference implementations (2026-07-21).**
The v8 token-emission loop now pads the emitted token count up to a fixed,
bucket-only ceiling of `real_token_count * (MAX_NOISE_RUN + 1)` tokens
(`MAX_NOISE_RUN = 19`, the same constant already used to bound worst-case
expansion), using additional filler tokens structurally identical to
genuine noise tokens, so ciphertext length is once again a deterministic
function of the padding bucket alone — never of the message-derived
nonce's noise realisation:

- `napqes.py`: `_encrypt_v8_core` pads to the ceiling; `_decrypt_v8_core`
  now recovers the real-token count directly from the total token count
  instead of consuming until the blob is exhausted, and stops once that
  many real tokens are extracted (any trailing filler is discarded).
- `rust/src/lib.rs`: gained the same `MAX_NOISE_RUN` cap (previously
  absent — Rust's v8 loop was unbounded) plus ceiling padding in
  `encrypt_bytes_v8`; a new `decrypt_core_v8` (separate from the shared,
  v7-only `decrypt_core`) mirrors the Python decoder logic.
- `C/napqes.c`: `encrypt_core_det_v8` / `decrypt_core_v8` updated
  identically. Not compile-verified in this environment (no C toolchain
  available), mirrored carefully against the Python/Rust logic — flagged
  as a residual verification gap consistent with prior C-only changes.

**Verification.** `tmp/test_v8_smoke.py` extended with a direct check:
200 trials encrypting one fixed message under distinct keys and AAD values
now produce ciphertexts of exactly one length (previously varied). A new
Rust unit test, `v8_ciphertext_length_is_deterministic_across_varied_aad`
(50 trials), asserts the same property. All pre-existing tests continue to
pass: 245 Python `pytest` tests (1 pre-existing, unrelated skip), and 84
Rust `cargo test` tests (up from 83, the one addition being the new test
above).

**Trade-off (disclosed).** v8 now always pays the worst-case
`MAX_NOISE_RUN + 1 = 20x` ciphertext expansion (previously the average
case was `~13.4x`). v7 is completely unaffected and keeps its original,
uncapped-ceiling behaviour; this trade-off is v8-only and is the
documented cost of closing the oracle.

**Scope of the fix:** `docs/napseq-eprint-v2.tex`, `docs/CAVEATS.md`,
`napqes.py`, `rust/src/lib.rs`, `C/napqes.c`, `tmp/test_v8_smoke.py`
(ad-hoc, not the permanent suite), and `rust/src/lib.rs`'s test module.

**Requested action:** please confirm V2-CVF2 can be marked **Fixed**.

---

## V2-CVF3 — Key-space and min-entropy figures are numerically wrong and internally contradictory

**Status:** Open → **Fixed**
**Category:** Algorithm
**Severity:** Moderate

### Response

Confirmed. The Key subsection stated the ordered 10-tuple key space as
`|P|!/(|P|-10)! ≈ 1.1×10^58 ≈ 2^196` and `H_∞(k) ≈ 196` bits for `K=10`
(`≈19` bits for `K=1`). With the paper's own `|P| ≈ 586,000`
(`log2|P| ≈ 19.16`), these figures were computed from an incorrect
`≈19.6–19.7`-bits-per-prime coefficient rather than `19.16`; the correct
values are `≈4.8×10^57 ≈ 2^191.6` and `H_∞ ≈ 191.6` bits for `K=10`. We
also agree this was internally contradictory: `Remark~\ref{rem:min-K}`
("Minimum K for a target security level") already used the correct
`19.16·K` formula and computed `191.6` bits for the same `K=10`, directly
conflicting with the `196`-bit figure stated just above it. The error
propagated to two further locations the finding did not explicitly list
but which use the same key-space figure: the traffic-analysis lemma's
scope remark (`2^197`–`2^257` prime-tuple range, for `K=10`–`13`) and the
Post-Quantum Analysis section's classical/post-Grover key-search figures
(`2^196`/`2^98`).

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`: all five stale
figures are corrected using the paper's own `19.16` bits/prime coefficient:

- Key subsection: `1.1×10^58 ≈ 2^196` → `4.8×10^57 ≈ 2^191.6`; the
  parenthetical `(≈196 bits for K=10, ≈19 bits for K=1)` → `(≈191.6 bits
  for K=10, ≈19.16 bits for K=1)`.
- `Remark~\ref{rem:min-K}`: `K=10 (H_∞≈196 bits)` → `K=10 (H_∞≈191.6
  bits)`, reconciling it with its own already-correct `19.16·K` formula.
- Traffic-analysis lemma's scope remark: `2^197`–`2^257` → `2^191.6`–
  `2^249.1` (the `K=10`–`13` range, recomputed with `19.16`; the `K=13`
  boundary matches the pre-existing `K≥13` HMAC-key-length remark).
- Post-Quantum Analysis, "Key space" paragraph: `≈2^196` → `≈2^191.6`;
  `≈2^98` (both occurrences) → `≈2^95.8`. The `K≥7` minimum-security-level
  floor and the `≈128`-bit post-Grover target already used the correct
  coefficient and are unaffected — only the reported numbers change, the
  security margin holds as before.
- A new remark, `rem:v2cvf3`, added immediately after the Key subsection's
  min-entropy paragraph, records the finding, the root cause (the wrong
  `19.6`–`19.7` coefficient), and points to all five corrected locations.

**Verification.** Recompiled with `pdflatex` (3 passes): exit 0 every
pass, zero undefined-reference/multiply-defined-label warnings on the
final pass.

**Scope of the fix:** `docs/napseq-eprint-v2.tex` only (five numeric
corrections plus one new remark). No code change — this was a pure
arithmetic/write-up error; the underlying `|P|` and `K` values, and every
implementation that depends on them, were never wrong.

**Known residual:** none.

**Requested action:** please confirm V2-CVF3 can be marked **Fixed**.

---

## V2-CVF4 — Ciphertext-expansion range 4–20x is inconsistent with the noise-probability ceiling of 0.99

**Status:** Open → **Fixed for v8** (recommended default); **documented residual for legacy v7**
**Category:** Algorithm
**Severity:** Moderate

### Response

Confirmed as originally stated. An uncapped geometric noise run has
expected length `1/(1-p)`, which is `4×` at `p=0.75` and `20×` only at
`p=0.95` — at the paper's own stated ceiling `p=0.99` the expected run
length is `100×`, not `20×`, and the "primary trade-off" paragraph's claim
that the `4–20×` range is "mitigated ... by the noise-probability ceiling
of 0.99" had the direction of the argument backwards, since `p=0.99` is
precisely the worst case, not a mitigant.

We can report that the recommended v8 default already closes this
exactly, via a fix shipped alongside V2-CVF2 (above): the v8
token-emission loop caps consecutive noise tokens at
`MAX_NOISE_RUN=19` in all three reference implementations (`napqes.py`
`_encrypt_v8_core`; `rust/src/lib.rs` `encrypt_bytes_v8`; `C/napqes.c`
`encrypt_core_det_v8`), which turns the probabilistic ceiling into a
hard, deterministic worst case of exactly `MAX_NOISE_RUN+1 = 20×` per
real codepoint, regardless of `p`. That code fix predates this write-up
(it was shipped specifically to close this inconsistency), but the paper's
prose, comparison table, and CAV-004 caveat were never updated to
describe it accurately — that gap is what this entry closes.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`:

- The "primary trade-off" paragraph (preceding
  `Table~\ref{tab:comparison}`) is rewritten: it now states the uncapped
  expectation (`4×` at `p=0.75`, `100×` at `p=0.99`), explains that v8's
  `MAX_NOISE_RUN=19` cap turns the worst case into an exact `20×`
  regardless of `p`, and explicitly corrects the backwards "mitigated by
  the ceiling of 0.99" framing — `p=0.99` is the case the cap is sized
  against, not something that mitigates the expansion.
- A new remark, `rem:v2cvf4`, records the finding, the exact
  inconsistency, and the fix, and clarifies that the `MAX_NOISE_RUN` cap
  is deliberately **not** applied to the legacy v7 construction, so
  previously-issued v7 ciphertexts remain decodable exactly as originally
  produced; v7's expansion therefore remains bounded only in expectation,
  with an uncapped tail as `p→0.99`.
- The in-paper `CAV-004` caveat entry is updated to state the corrected,
  v8-exact / v7-residual split instead of a single unqualified `4–20×`
  claim.
- `Table~\ref{tab:comparison}`'s `4–20×` figure is unchanged (it is now
  accurate for v8, the recommended default) but its accompanying prose no
  longer misdescribes why.

**Verification.** Recompiled with `pdflatex` (3 passes): exit 0 every
pass, zero undefined-reference/multiply-defined-label warnings on the
final pass. No code changes were needed in this pass — `MAX_NOISE_RUN`'s
behavior was already verified as part of V2-CVF2 (200 Python trials / 50
Rust trials).

**Trade-off / residual (disclosed).** Legacy v7 has no noise-run cap and
its expansion is bounded only in expectation (`≈13.4×` mean at typical
`p`, uncapped tail as `p→0.99`). This is an accepted residual of the
backward-compatibility-only construction (v7 is no longer recommended for
new deployments as of this revision) and is documented in `CAV-004`
(`docs/napseq-eprint-v2.tex` and `docs/CAVEATS.md`).

**Scope of the fix:** `docs/napseq-eprint-v2.tex` (documentation-only in
this pass) and `docs/CAVEATS.md`. No further changes to `napqes.py`,
`rust/src/lib.rs`, or `C/napqes.c` — the `MAX_NOISE_RUN=19` cap that
closes this for v8 was already shipped as part of the V2-CVF2 fix.

**Requested action:** please confirm V2-CVF4 can be marked **Fixed for
v8, with the v7 residual accepted and documented**.

## V2-CVF5 — Domain-separation remark does not formally cover the synthetic-nonce domain 0x0A

**Status:** Open → **Fixed** (documentation only; no code/proof change)
**Category:** Procedural
**Severity:** Minor

### Response

Confirmed. `Remark~\ref{rem:domsep}` ("Domain Separation of HMAC Inputs")
was stated only for `d ∈ {0x00,...,0x09}` with the single uniform input
shape `d‖N‖ctx` and the nonce fixed at byte offset `1..16`. The v8
synthetic-nonce domain `0x0A` (`Definition~\ref{def:synthnonce}`) is keyed
under `sk` rather than `kb` and has a different input shape,
`0x0A‖be4(|A|)‖A‖M` — it produces the nonce rather than consuming one at
bytes `1..16`. As the finding notes, there is no attack: cross-domain
distinctness is unconditional regardless of input shape (it only compares
byte position 0), and intra-domain injectivity for `0x0A` already holds
via the `be4(|A|)` length-prefix argument used for domains 3/8/9. This was
a formal-coverage gap in the remark's stated scope, not a soundness gap.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`,
`Remark~\ref{rem:domsep}`: added a "Domain 0x0A" paragraph extending the
domain set to `{0x00,...,0x0A}`, explicitly restating cross-domain
distinctness and intra-domain injectivity for `0x0A`.

**Known residual:** none.

**Requested action:** please confirm V2-CVF5 can be marked **Fixed**.

## V2-CVF6 — Abstract and Contribution 1 state a non-injective synthetic-nonce formula (missing the AAD length prefix)

**Status:** Open → **Fixed**
**Category:** Readability
**Severity:** Minor

### Response

Confirmed. The abstract and Contribution 1 wrote the synthetic nonce as
`N = HMAC(sk, 0x0A‖A‖M)`, omitting the `be4(|A|)` length prefix that the
normative `Definition~\ref{def:synthnonce}` includes. As written,
`0x0A‖A‖M` is not injective in `(A,M)` — e.g. `(A,M)=(x,y)` and
`(ε,xy)` collide — so an adversary controlling the AAD/message split could
force a deterministic nonce collision across distinct `(A,M)` pairs. The
normative definition was always correct; only the two abbreviated,
informal restatements were wrong.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`: corrected both
occurrences (abstract and Contribution 1) to
`N = HMAC(sk, 0x0A‖be4(|A|)‖A‖M)`, matching `Definition~\ref{def:synthnonce}`
exactly, with a cross-reference back to the normative definition.

**Known residual:** none.

**Requested action:** please confirm V2-CVF6 can be marked **Fixed**.

## V2-CVF7 — The symbol N is overloaded: 16-byte nonce versus real-plus-noise token count

**Status:** Open → **Fixed**
**Category:** Naming
**Severity:** Minor

### Response

Confirmed. The Wire Format (Version 7) subsection and
`Definition~\ref{def:aead-triple}`'s ciphertext-space bullet reused the
letter `N` both for the 16-byte nonce and for the real-plus-noise token
count of a message (e.g. "`|B| = 8N` where `N` (real + noise tokens)..."
immediately followed by "`N` is a 16-byte random nonce"). The
traffic-analysis lemma (`Lemma~\ref{lem:tar}`) already avoided this by
writing `N_tok`; the normative wire-format text and the algorithm-triple
definition did not, creating a reproducibility ambiguity.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`: renamed the
token count to `N_tok` throughout Section~\ref{sec:wire-format-v7} and
`Definition~\ref{def:aead-triple}`'s ciphertext-space bullet, and in the
one stray reuse inside `Lemma~\ref{lem:hiding}`'s proof ("Equal
byte-length of B..." paragraph), reserving `N` exclusively for the nonce.
Added `Remark~\ref{rem:v2cvf7}` recording the rename. No formula,
encoding, or byte layout changed — this is a pure notational fix.

**Known residual:** none.

**Requested action:** please confirm V2-CVF7 can be marked **Fixed**.

## V2-CVF8 — LEB128 canonicality rule does not fully enforce x < 2^64

**Status:** Open → **Fixed** (specification only)
**Category:** Behavior
**Severity:** Minor

### Response

Confirmed. `Definition~\ref{def:leb128}`'s canonicality rule required a
decoder to reject "any input requiring more than `⌈64/7⌉ = 10` groups" and
claimed the resulting map is a bijection on `[0, 2^64)`. A full 10-group
LEB128 encoding carries up to 70 bits (`g_9` contributes bits 63–69), so
canonical 10-group encodings can represent integers up to `2^70 - 1`,
including values in `[2^64, 2^70)` that the same definition simultaneously
declared out of range — the group-count check alone does not enforce
`x < 2^64`, so the claimed bijection did not hold as stated.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`,
`Definition~\ref{def:leb128}`: added a top-group bound — a conforming
decoder must additionally reject any 10-group encoding whose
most-significant group `g_9 ∉ {0,1}` (equivalently, only bit 63, the
low-order bit of `g_9`, may be set). This restores the bijection on
`[0, 2^64)` the definition already claimed. Added `Remark~\ref{rem:v2cvf8}`
recording the fix; the encoder side and every wire-format byte layout are
unchanged.

**Known residual (disclosed, out of scope for this fix):** this audit
reviews `docs/napseq-eprint-v2.tex`, not the reference implementations.
`napqes.py`'s streaming-mode LEB128 decoder (`_b128_decode_tokens`) does
not currently enforce *any* canonicality or maximum-width check — stricter
scrutiny than even the pre-fix specification rule — and is flagged as a
residual implementation-hardening item for a future code-focused pass, not
addressed here.

**Requested action:** please confirm V2-CVF8 can be marked **Fixed for
the specification**, with the noted implementation-hardening item tracked
separately.

## V2-CVF9 — The HMAC-SHA256 PRF advantage is never formally defined, and its use on truncated outputs is not justified

**Status:** Open → **Fixed**
**Category:** Documentation
**Severity:** Minor

### Response

Confirmed. Every theorem in Section~\ref{sec:security} bounded an
adversary's advantage in terms of
`Adv^PRF_HMAC-SHA256(B)` without a formal PRF-advantage definition (oracle,
distinguisher, advantage) ever being stated in this document (unlike the
first-round `docs/napseq-eprint-preprint.tex`, a different file). In
addition, several load-bearing values are *truncated* HMAC outputs — the
v8 synthetic nonce uses `[0:16]` (128 bits) and the v7 derivation
primitives use `[0:4]`/`[0:8]` — and the paper invoked the full-output PRF
advantage without justifying that a fixed truncation of a PRF is itself a
PRF with the same advantage.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`, inserted before
`Subsection~\ref{sec:security}`'s "IND-CPA Security" subsection: a new
`Definition~\ref{def:prf-adv}` (`HMAC-SHA256 PRF advantage`) stating the
standard oracle/distinguisher/advantage game, parameterized by a key
distribution `D` (covering both the uniform-key case and the non-uniform
prime-tuple case `Remark~\ref{rem:prf-d}` already discusses for v7); and a
new `Remark~\ref{rem:v2cvf9}` proving that for any fixed truncation length
`τ`, `Adv^PRF_{trunc_τ∘F}(B) = Adv^PRF_F(B)` (a distinguisher can truncate
its own oracle's answers and run unmodified), explicitly covering every
truncated derivation in this paper (nonce `[0:16]`, addend/char `[0:4]`,
threshold `[0:8]`) under the single already-stated assumption on
full-output HMAC-SHA256.

**Known residual:** none — this closes the gap without introducing any
new assumption.

**Requested action:** please confirm V2-CVF9 can be marked **Fixed**.

## V2-CVF10 — "Minimum valid ciphertext length is 48 bytes" understates the true minimum

**Status:** Open → **Fixed**
**Category:** Documentation
**Severity:** Minor

### Response

Confirmed. The v7 decryptor rejects `|C| < 48` (16-byte nonce plus 32-byte
tag) and the text called 48 the "minimum valid ciphertext length." But
every message, including the empty string, pads to at least `B=16`
codepoints plus the 2-codepoint length prefix, i.e. at least `R=18` real
tokens, so `|B̃| ≥ 8·18 = 144` bytes and the true minimum length of a
well-formed ciphertext is `≈ 16+144+32 = 192` bytes (larger once noise
tokens are added). 48 bytes is a necessary parse-time rejection floor, not
the minimum length a well-formed ciphertext can actually have.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`: reworded the
Wire Format (Version 7) passage and `Definition~\ref{def:aead-triple}`'s
ciphertext-space bullet to distinguish the two figures explicitly — 48
bytes is labelled the parse-time rejection floor, and `≈192` bytes
(`16+8·18+32`) is stated as the true minimum length of a well-formed v7
ciphertext.

**Known residual:** none.

**Requested action:** please confirm V2-CVF10 can be marked **Fixed**.

## V2-CVF11 — Streaming format retains the CVF1 codepoint-length leak (by design) but does not document it

**Status:** Open → **Fixed** (documentation); **residual retained by design**
**Category:** Documentation
**Severity:** Minor

### Response

Confirmed. The online-AE streaming format masks a `varint(·)` (LEB128)
blob, not the fixed-width `be8` encoding that the first-round CVF1 fix
introduced for block mode (Section~\ref{sec:wire-format-v7}), so a
token's serialised byte-length in streaming mode still grows with the
plaintext codepoint value — the exact channel CVF1 closed for block mode.
This is not a new confidentiality break: a streaming ciphertext already
discloses the exact plaintext length by construction (each chunk's
`be4(ℓ_i)` length prefix is sent in the clear), so the finer-grained
per-token variation adds no further leakage on top of what streaming mode
already concedes. The paper never stated this scoping explicitly, risking
a reader wrongly assuming the CVF1 fix applies universally.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`,
Section~\ref{sec:streaming-ae}: added `Remark~\ref{rem:v2cvf11}` stating
the streaming format deliberately retains the CVF1 codepoint-length leak
and explaining why this is acceptable (streaming already discloses exact
length).

**Known residual (accepted, by design):** streaming-mode ciphertexts leak
codepoint-level length information beyond the chunk-length prefix already
disclosed; this is a deliberate trade-off, not a defect, since streaming
mode's threat model already concedes exact plaintext length. Documented in
`docs/CAVEATS.md` (new entry, cross-referencing `CAV-003`/first-round
`CVF1`).

**Requested action:** please confirm V2-CVF11 can be marked **Fixed
(documentation), with the by-design residual accepted**.

## V2-CVF12 — Legacy v7 is retained with security theorems the paper itself flags as conditional or unproven

**Status:** Open → **Fixed** (hardened wording; construction retained, see V2-CVF13)
**Category:** Procedural
**Severity:** Minor

### Response

Confirmed. The legacy v7 theorems (`Theorem~\ref{thm:ind-cpa}`,
`Theorem~\ref{thm:int-ctxt}`, `Theorem~\ref{thm:ind-cca}`) were stated as
ordinary, unconditional theorems, even though this paper's own remarks
concede two open v7-specific gaps: `Remark~\ref{rem:cvf13}` (the reduction
cannot simulate `NAPQES.Enc` from oracle access alone, since the
arithmetic layer uses `k` directly, outside any HMAC call) and
`Remark~\ref{rem:prf-d}`/`Remark~\ref{rem:cvf8}` (the PRF advantage
invoked is against a non-standard, non-uniform key distribution). Only
`Theorem~\ref{thm:ind-cpa}` previously surfaced this caveat inline; the
INT-CTXT and IND-CCA theorems did not, despite depending on the same
reductions.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`:

- Added `Remark~\ref{rem:v2cvf12-13}` immediately before
  Section~\ref{sec:security}'s "IND-CPA Security" subsection, stating
  plainly that every v7 theorem in this section is conditional on the two
  gaps above, and that only v8 (`Theorem~\ref{thm:ind-cpa-v8}`,
  `Corollary~\ref{cor:v8-security}`) carries unconditional guarantees.
- `Theorem~\ref{thm:int-ctxt}` and `Theorem~\ref{thm:ind-cca}`'s own
  preambles now state the same conditional caveat directly (not only via
  a separately-linked remark), matching `Theorem~\ref{thm:ind-cpa}`'s
  existing wording.

**Known residual:** the underlying gaps (`Remark~\ref{rem:cvf13}`,
`Remark~\ref{rem:cvf8}`) remain open for v7 by design — this finding asks
only that the conditionality be stated prominently, not that the gaps be
closed (closing them would require the KDF-subkey wire-format change
already tracked as a residual against CVF8/CVF13, first round). See
V2-CVF13 below for the companion "should v7 be removed" finding.

**Requested action:** please confirm V2-CVF12 can be marked **Fixed**.

## V2-CVF13 — The paper should drop the legacy v7 construction entirely rather than carry two parallel schemes

**Status:** Open → **Acknowledged; decision recorded (v7 retained)**
**Category:** Architecture
**Severity:** Minor

### Response

Confirmed as a valid structural observation: carrying both a fully
specified, fully proved legacy v7 construction (with the conditional
theorems V2-CVF12 addresses) and the recommended v8 construction side by
side roughly doubles the specification and proof surface, and risks a
reader either deploying v7 or carrying its (conditional) theorems over to
v8 by association.

**Decision.** We considered removing the legacy v7 construction entirely,
as recommended, and decided to retain it, unmodified, for backward
compatibility with existing v7 ciphertexts and deployments. v7 is already
explicitly retitled as legacy-only (`Section~\ref{sec:algorithm-triple}`,
"backward compatibility only") and is no longer the recommended default.
Removing a wire format that deployed systems may already depend on is a
breaking change out of proportion to a documentation/architecture
finding, and is inconsistent with this project's established
backward-compatibility posture for prior wire formats (v1–v6 remain
readable via explicit legacy opt-ins elsewhere in the codebase). V2-CVF12's
hardened conditional-theorem wording, plus the prominent "only v8 is
unconditional" statement in `Remark~\ref{rem:v2cvf12-13}`, is the
mitigation actually shipped in response to this finding, rather than
removal.

**Fix shipped (2026-07-21).** `docs/napseq-eprint-v2.tex`:
`Remark~\ref{rem:v2cvf12-13}` records this finding and the decision above
alongside V2-CVF12's fix (the two findings share one combined remark
since they concern the same passage and the same underlying gaps).

**Known residual (accepted, by decision):** the legacy v7 construction,
and its conditional security proofs, remain part of the normative
document. Documented in `docs/CAVEATS.md` (combined entry with V2-CVF12,
cross-referencing the existing first-round CAV entries for CVF8/CVF13).

**Requested action:** please confirm V2-CVF13 can be marked **Acknowledged,
with the decision to retain v7 recorded**, rather than Fixed-by-removal.

## V2-CVF14 — The audit-response and revision-history remarks should be moved out of the normative text into a separate companion document

**Status:** Open → **Acknowledged; not actioned this round**
**Category:** Readability
**Severity:** Minor

### Response

Confirmed as a valid readability observation: this document interleaves
~25 "Audit finding CVFn" / "Erratum" / "Retracted" remark blocks and ~90
inline cross-references with the normative construction and proofs, which
does make the current-design text harder to isolate from the
revision-history narrative, and does create a mild confirmation-bias risk
for a reader who accepts "this was fixed" assertions without independently
re-checking the current text.

**Decision.** We are not restructuring the document this round. The
in-text remark convention is a deliberate choice, applied consistently
across every one of the ~38 findings resolved so far (both the first and
second audit rounds, `docs/audit_mitigation_responses.md`), specifically
*for* full auditability: each remark sits next to the exact passage it
corrects and carries its own label, so a reviewer (or a future audit
round) can verify a fix in place without cross-referencing a separate
changelog. Extracting ~25 remark blocks and ~90 references into a
companion document now would be a large, high-risk diff across the entire
paper, out of proportion to a single Minor/readability finding, and would
have to be re-applied consistently to both audit rounds' findings to avoid
leaving the document in a half-migrated state. We consider this a
reasonable candidate for a dedicated future cleanup pass, done in one
sweep once no findings are in flight, rather than as an incremental part
of this response round.

**Fix shipped:** none (by decision — see above). No `.tex` change.

**Known residual:** the readability cost the finding identifies remains
present. Not tracked in `docs/CAVEATS.md` (this is a documentation
style/structure choice, not a security residual).

**Requested action:** please confirm V2-CVF14 can be marked
**Acknowledged, deferred to a future dedicated cleanup pass**, rather than
Fixed.



# Third-Round Audit (ABDK Consulting, "NAPQES v3 — AEAD Scheme Audit," 2026-08-08)

The findings below are from the third-round report (Report 0.2) reviewing
`docs/napseq-eprint-v3.tex`. The report again reuses low finding IDs
(CVF1-CVF25) that are independent of the first-round `CVFn` and
second-round `V2-CVFn` entries above. To avoid ID collisions, each
third-round finding is recorded here under a `V3-CVFn` prefix.

## V3-CVF1 — Encryption and decryption disagree on the AAD length-prefix width, breaking correctness and INT-CTXT

**Status:** Open -> **Fixed** (paper + code)
**Category:** Behavior
**Severity:** Major

### Response

Confirmed as a specification defect. `docs/napseq-eprint-v3.tex` computed
the tag over `be8(|A|)` in `Enc` step (6), the derivation table (domain
`0x03`), the wire-format section, and the domain-separation lemma, but over
`be4(|A|)` in `Dec` step (4) (line 574) and in the INT-CTXT proof's forgery
tag input `x*` (line 847). As literally specified, no honest ciphertext
verifies, and the mismatch is exploitable: querying the encryption oracle
on any `A_j` with `|A_j| = 156 (mod 160)` and then submitting `(empty AAD,
N_j || B~* || T_j)` with `B~*` = the low 4 bytes of `be8(|A_j|)`, followed
by `A_j || B~_j`, makes the decryptor rebuild a byte-identical tag input
and accept, with one encryption query and one verification query.

We agree with the auditor that the fix must **widen, not narrow**: `be8` is
what the encryptor emits, what domain `0x0A` consumes, and what
`Lemma "Domain separation"` proves injective; narrowing to 4 bytes would
break that lemma for `|A| >= 2^32` and contradict the declared AAD space
`|A| < 2^64`.

**Answer to the auditor's item (4) — which width the implementations use.**
We checked all three reference implementations before choosing. Prior to
this fix, Python, Rust and C all used a **4-byte** prefix on *both* the
encryption and the decryption side, in both domain `0x03` and domain
`0x0A`. They were therefore internally consistent and **not vulnerable to
the forgery above**; only a decryptor written literally from the v3
document would have been. The defect was a spec/code divergence introduced
when the paper was widened from `be4` to `be8` between v2 and v3 (see
V2-CVF6) without a matching code change. The normative answer we are
publishing is the auditor's: **8 bytes**, and the code has been moved to
match rather than the document being narrowed to match the code.

**Fix shipped (2026-08-13).**

`docs/napseq-eprint-v3.tex`:

- New `Definition "Tag input"` states the tag input once as a named
  quantity, `TagIn(A, B~) = be8(|A|) || A || B~`, with the full domain-
  `0x03` HMAC input written as `0x03 || N || TagIn(A, B~)`. The derivation
  table (row `0x03`), the wire-format tag equation, `Enc` step (6), `Dec`
  step (4), the domain-separation lemma and the INT-CTXT proof all now
  refer to that one name, so encryptor and decryptor can no longer diverge
  in the width of the length prefix (auditor's item 2).
- `Dec` step (4) and the INT-CTXT forgery input `x*` were changed from
  `be4` to `be8` (auditor's item 1). Theorem "INT-CTXT" is now true as
  stated, bound included: Case 1 and Case 2 both rely on the injectivity
  established by the domain-separation lemma for the same encoding the
  construction actually uses.
- Correctness was restated as `Proposition "Correctness"` (it was a
  `definition` immediately followed by a `proof`), and its proof now
  *begins* by checking that the two tag inputs coincide, instead of
  assuming `T = T'` (auditor's item 3). The proof also no longer claims the
  nonce is "deterministically re-derivable once M is recovered" — `N` is
  read from the ciphertext, not re-derived — and the appeal to the
  empirical KAT corpus was moved out of the proof into the Known-Answer
  Tests section.

Implementations (v8 block mode only):

- `napqes.py`: `_compute_auth_tag` takes an `aad_len_width` parameter
  (default 4); `encrypt_bytes_v8`/`decrypt_bytes_v8` pass
  `_AAD_LEN_WIDTH_V8 = 8`, and `_synthetic_nonce` (domain `0x0A`, v8-only)
  now emits an 8-byte prefix.
- `rust/src/lib.rs`: `compute_auth_tag` takes an `aad_len_width` argument;
  `encrypt_bytes_v8`/`decrypt_bytes_v8` pass `AAD_LEN_WIDTH_V8 = 8`, the
  five v7 call sites pass `AAD_LEN_WIDTH_V7 = 4`, and `synthetic_nonce`
  emits 8 bytes.
- `C/napqes.c`: `compute_auth_tag` takes an `aad_len_width` argument
  (v7 call sites pass 4, v8 call sites pass 8) and `synthetic_nonce` emits
  8 bytes, via a new `be_len_prefix` helper.

### Scope of the fix

Only the **v8 block-mode** domains `0x03` and `0x0A` were widened. Legacy
v7 block mode and the streaming-AE domains `0x08`/`0x09` keep the 4-byte
prefix and remain byte-compatible; the v3 paper does not specify them, and
per the CVF7 format-selection philosophy callers already agree out-of-band
on which schedule a ciphertext uses. `tests/kat/v6_vectors.json` covers v7
and streaming vectors only and regenerates byte-identically
(`python tests/gen_kats.py --check` passes), which is also the regression
evidence that v7 was left untouched. `python -m pytest tests` (245 passed,
1 skipped) and `cargo test --lib` (84 passed) are green.

### Known residual

- **v8 ciphertexts produced before this change no longer verify.** The tag
  and the synthetic nonce both change, so every v8 ciphertext byte changes.
  There is no version discriminator inside a v8 ciphertext, so old and new
  v8 ciphertexts are distinguishable only by a failed authentication.
- ~~The C change is not compile-verified in the maintainer environment.~~
  **Resolved 2026-08-14** — see the follow-up section below.
- ~~Pre-existing, unrelated: the Rust v8 path does not implement the
  domain-`0x0B` format subkey.~~ **Resolved 2026-08-14** — see the
  follow-up section below.

**Requested action:** please confirm V3-CVF1 can be marked **Fixed**, and
confirm that 8 bytes is accepted as the normative AAD length-prefix width
for v8, with v7 and streaming-AE explicitly excluded as unchanged legacy
formats.

## V3-CVF1 follow-up — Rust and C v8 brought to byte parity with the Python reference

**Status:** Fixed (2026-08-14) · **Category:** Behavior / cross-implementation
consistency · **Severity:** self-reported, not an auditor finding

### What we found

Verifying the V3-CVF1 fix required comparing the three implementations
byte-for-byte, which surfaced two v8 divergences. Neither was introduced by
V3-CVF1; both predate it. Both were invisible to the test suite because the
KAT corpus (`tests/kat/v6_vectors.json`) covered only v7 block mode and
streaming-AE — v8 had **no** cross-language coverage at all.

1. **Rust never derived the domain-`0x0B` format subkey.**
   `rust/src/lib.rs` keyed every v8 derivation with `sk` directly, while
   `napqes.py` and `C/napqes.c` first derive
   `sk_fmt = HMAC(sk, 0x0B ‖ FORMAT_BLOCK_V8)`. Rust v8 ciphertexts had the
   correct length but the wrong bytes and were not decryptable by any other
   implementation. The omission did not weaken v8 in isolation (`sk` is a
   uniformly random 256-bit HMAC key), but it removed the cross-format
   binding domain `0x0B` exists to provide: a v8 block-mode tag and a
   streaming-AE tag under the same `(primes, sk)` shared one effective key.

2. **Rust and C short-circuited the empty message.**
   `encrypt_bytes_v8("")` returned empty bytes in Rust, and
   `napqes_encrypt_bytes_v8` / `napqes_encrypt_str_v8` returned an empty
   buffer in C, while `napqes.py` pads the empty string through the normal
   path to the documented 2928-byte v8 minimum. The shortcut emitted an
   unauthenticated, trivially forgeable "ciphertext" and made the empty
   message the one input whose length leaked exactly. The matching decrypt
   shortcuts accepted a zero-byte ciphertext as a valid encryption of the
   empty string — a trivial forgery.

### Fix shipped 2026-08-14

- `rust/src/lib.rs`: added `FORMAT_BLOCK_V8` / `FORMAT_STREAM_AE_V8` and
  `derive_format_subkey(sk, format_id) = HMAC(sk, 0x0B ‖ format_id)`;
  `encrypt_bytes_v8` and `decrypt_bytes_v8` now thread `sk_fmt` through the
  synthetic nonce, `derive_noise_p`, `pad_message`, `is_noise_pos`,
  `derive_noise_char`, both addend domains, `varint_keystream`,
  `compute_auth_tag` and `decrypt_core_v8`. Both empty-input shortcuts were
  removed, and an explicit `> 0xFFFF` codepoint check replaces the panic
  that `pad_message`'s assertion would otherwise raise.
- `C/napqes.c`: removed the empty-message and empty-ciphertext shortcuts
  from `napqes_encrypt_bytes_v8`, `napqes_decrypt_bytes_v8`,
  `napqes_encrypt_str_v8` and `napqes_decrypt_str_v8`, so the v8 wrappers
  delegate unconditionally exactly as `napqes.py` does.
- `tests/gen_kats_v8.py` (new) generates `tests/kat/v8_vectors.json` (new):
  12 positive and 5 negative v8 vectors produced directly from the public
  `encrypt_bytes_v8` API. v8 is deterministic in
  `(primes, sk, aad, message)`, so unlike the v7 generator this needs no
  KAT-only nonce-injection entry point. `W001` pins the padded
  empty-message behaviour; `W011` pins the 8-byte AAD length prefix.
- `tests/test_kats.py`: v8 positive (byte-exact encrypt + roundtrip),
  negative, empty-message and `--check` regeneration tests.
- `rust/src/kat_cross_check.rs`: `v8_positive_encrypt_matches_python`,
  `v8_positive_decrypt_roundtrip` and `v8_negative_returns_err` read the
  same JSON corpus, so any future Rust/Python v8 divergence fails the build.

### Verification

- `python -m pytest tests` — 276 passed, 1 skipped (was 245/1).
- `cd rust; cargo test --lib` — 87 passed, 0 failed (was 84/0), including
  byte-exact agreement with Python on all 12 v8 positive vectors.
- `python tests/gen_kats.py --check` — OK, 37 v7 vectors byte-identical
  (the regression proof that v7 was not touched).
- **C is now compile-verified.** MSVC 14.44 (Visual Studio 2022) was
  located in the maintainer environment; `C/napqes.c` compiles clean at
  `/W3 /O2` and at `/W4 /Od /RTC1`, and its output was compared directly
  against the Python reference: v7 vector V002 and v8 vectors
  W001 / W003 / W012 all match byte-for-byte and round-trip.

### Known residual

- **`C/test_kats.c` does not run correctly on Windows/MSVC.** The C library
  is byte-exact (verified directly, above), but the C KAT *harness* reports
  41 spurious failures: the `ciphertext_hex` / `nonce_hex` values it
  recovers from the JSON belong to the previous vector and are truncated,
  so every positive vector fails while all eight negative vectors pass. The
  hand-rolled JSON reader is the suspect; the defect is not in
  `C/napqes.c`, is not caught by `/RTC1`, and a build from the pre-fix
  `HEAD` fails identically.
  `tests/test_cross_lang.py::test_c_kat_harness_passes` skips when no
  compiler is on `PATH`, which is why this was never observed. The harness
  needs a real JSON parser before any Windows-hosted audit relies on it.

## V3-CVF2 — The traffic-analysis justification for K is unsupported by the lemma it cites

**Status:** Open -> **Fixed** (paper + code)
**Category:** Documentation / Algorithm
**Severity:** Medium

### Response

Confirmed in full, and the finding is sharper than it first appears. There
were two defects layered on top of each other.

1. **The citation is not merely weak, it points at counter-evidence.**
   `Lemma "Ciphertext length is a deterministic function of the padding
   bucket"` (`lem:length-det`) proves that `|C|` depends on the message
   *only* through `B(|M|)` — never through `k`, never through `K`. It is
   therefore the strongest available statement that the multi-prime layer
   contributes nothing to length behaviour, and citing it as the basis of a
   `K`-dependent traffic-analysis benefit inverted its meaning.

2. **The citation was repointed rather than reworked.** In v2 the same
   sentence cited `lem:tar` ("ciphertext length is decorrelated from
   plaintext content"). V2-CVF2 established that `lem:tar`'s hypothesis —
   two plaintexts under the *same nonce* — is never satisfiable under the
   message-derived synthetic nonce, and v3 correctly deleted the lemma. The
   remark on key roles was then updated by moving its reference to
   `lem:length-det` instead of by re-deriving what, if anything, still held.
   That is the immediate cause of the defect the auditor found.

We took the auditor's second branch — state and prove a property against a
defined adversary — **and** shipped the comparison subsection requested in
the first branch, because the comparison is the part a reader deciding
whether to deploy actually needs, and it costs little once the property is
stated correctly.

**On the auditor's parenthetical, "which theorems change (none, by our
reading)": we agree, and we now prove it.** `Proposition "The theorems are
indifferent to the arithmetic layer"` states that IND-CPA-det, INT-CTXT,
IND-CCA-det and the new LH-IND-CPA-det all hold for the construction with
the arithmetic layer deleted, with identical statements and identical
bounds, by the same proofs. The reading was correct.

### The property we can state and prove

The honest analysis is that a real traffic-analysis property exists, but it
belongs to the **padding bucket**, not to the noise tokens, the prime map,
or `K`. The load-bearing observation is that

    |C| = 48 + 160(B+2)

is a *public, injective* function of the padding bucket. An observer inverts
it exactly as easily as it inverts `B + 48`. Multiplying a leak by a public
constant does not reduce the leak; only the *many-to-one* map `n -> B(n)`
does. So the 160x expansion — the entire cost of the construction — buys
precisely **zero** bits of length confidentiality, and the property that
does exist survives deletion of the arithmetic layer untouched.

### Fix shipped (2026-08-13)

`docs/napseq-eprint-v3.tex`:

- **`Remark "The role of k and sk are not symmetric"`** — the offending
  sentence is deleted. The remark now states plainly that `K` is never
  transmitted, appears nowhere in the wire format, does not influence `|C|`,
  makes no contribution to length hiding, and that no traffic-analysis claim
  anywhere in the paper rests on `K`, on `H_inf(k)`, or on the multi-prime
  structure. `K` is now described as an interoperability default rather than
  a security parameter, with its permitted range (`K >= 1`) stated, and the
  `K >= 7` implementation warning explained as inherited from the v7
  single-secret schedule. We believe this also resolves V3-CVF18.
- **`Definition "LH-IND-CPA-det security"`** — the defined adversary the
  auditor asked for. Identical to IND-CPA-det including both restrictions,
  except the challenge condition `|m0| = |m1|` is weakened to
  `B(|m0|) = B(|m1|)`: the messages may differ in length.
- **`Theorem "LH-IND-CPA-det"`** — NAPQES satisfies it at the *same* bound
  as IND-CPA-det, with no additional term. The proof is short because the
  existing proof of IND-CPA-det uses `|m0| = |m1|` in exactly one place,
  the appeal to `Lemma "Equal padded length is derived"`, whose only role is
  to supply the shared bucket that the new definition supplies as a
  hypothesis.
- **`Proposition "Separation from AES-GCM and ChaCha20-Poly1305"`** — the
  notion is not vacuous: a zero-query adversary performing one integer
  comparison achieves the maximum possible advantage of 1/2 against any
  scheme with `|C| = |M| + 16`.
- **`Corollary "Quantified length leakage"`** — `I(n; |C|) <= log2(beta)`
  for a profile with `beta` reachable block sizes, and `<= m log2(beta)`
  over a sequence of `m` messages with no independence assumption. Under the
  default profile that is `log2(13) ~= 3.70` bits. This replaces the
  `ceil(log2 n)` figure in the caveats, which was quantified backwards; we
  believe it also resolves V3-CVF11.
- **`Proposition "Expansion is length-neutral"`** and
  **`Remark "Coarsening, not inflation, is what hides length"`** — the
  attribution result above, stated and proved. This is the paper asking the
  question the auditor observed it had never asked.
- **New `Section "Padding Profiles"`** — the padding map is promoted from a
  hard-wired constant to a specified parameter: `bucket` (default, 13
  reachable sizes), `coarse(g)` for `g | 12`, and `frame(F)` (one reachable
  size, **zero** bits leaked). All three take values in the same 13-element
  set, so the set of legal token counts is profile-independent and a
  decryptor needs no knowledge of the sender's profile. This matters for
  V3-CVF8: any well-formedness check on `R` added there remains a check
  against the same fixed set and will not break the new profiles.
- **New `Section "What the Arithmetic Layer Does and Does Not Buy"`** —
  separated into what is proved (the `MAX_NOISE_RUN` cap and ceiling make
  the noise layer length-*neutral*, which is the removal of a leak the layer
  would otherwise create, not an improvement on a construction without one),
  what is argued but explicitly not proved (degradation under nonce
  collision yields an affine residue with `k` unknown rather than a plain
  two-time pad — recorded as strictly more work for the adversary and as
  nothing more), and what is not claimed at all (no content confidentiality,
  no length hiding, no dependence on `K` or `H_inf(k)`).
- **New `Section "The Construction Without the Arithmetic Layer"`** — the
  comparison the auditor requested. NAPQES-L is specified precisely, marked
  non-normative, and tabulated against the specified construction. The
  expansion becomes `48 + 3(B+2)` bytes against `48 + 160(B+2)`; the minimum
  ciphertext becomes **102 bytes against 2928**, a factor of ~53. No theorem
  changes.
- Abstract, contributions, comparison table and prose, caveats and
  conclusion updated to match. The comparison table's expansion row read
  `20x`; it is 20 *tokens* of 8 bytes each, so the row now reads `160x` and
  a length-leakage row has been added.

`traffic_analysis_bench.py` (new): measures realised leakage by encryption
rather than asserting it — `I(n;|C|)`, MAP recovery of `n` from `|C|`, and a
two-class distinguisher — for each profile and for AES-GCM and
ChaCha20-Poly1305. Its output is reproduced in the paper.

`napqes.py`: `_padding_bucket()` implements the three profiles; `pad_profile`
is threaded through `_pad_message`, `_encrypt_v8_core`, `encrypt_bytes_v8`
and `encrypt_str_v8`, defaulting to `bucket` so that every existing KAT and
all cross-language parity is unchanged. Decryption takes no profile argument
and needs none. The stale `MIN_KEY_COUNT` rationale, which still claimed
`K < 7` was "NOT conformant with NAPQES's IND-CPA security claim", has been
corrected — that was the same wrong belief about `K` in the code.

### A correction we are self-reporting

Running the new harness produced a result we had not expected and which the
auditor did not raise. Under the default `bucket` profile the two-class
distinguisher — short command (12-20 codepoints) versus full parameter set
(300-500), the canonical traffic-analysis scenario used in our own briefing
material — succeeds with probability **1.0**, because the two classes land
in buckets 16 and 512 and therefore in ciphertexts of 2,928 and 82,288
bytes. `coarse(3)` does not help. Only `frame(F)` with `F` above the longer
class reduces it to a coin flip (measured: 50.0%).

Our commercial and protocol documentation asserted that this scenario was
mitigated. It was not, under the default profile. The paper now states this
explicitly next to the measurement table, with the observation that a small
average-case `I(n;|C|)` does not imply resistance to a specific
distinguisher, and the supporting documents have been corrected to cite
`frame(F)` rather than the noise layer.

### Known residual

The 160x expansion is retained and buys no theorem. That is now stated in
the paper rather than justified by a false citation, and is recorded in
`docs/CAVEATS.md` as V3-CVF2. The beyond-model nonce-collision argument in
`Section "What the Arithmetic Layer Does and Does Not Buy"` is explicitly
labelled as not a security property and admits no bound we are able to
state; we are not claiming it as one.

`coarse` and `frame` are implemented in the Python reference only. The
default `bucket` profile is unchanged and remains byte-identical across
Python, Rust and C, so no KAT or cross-language test is affected, but Rust
and C do not yet accept a profile argument. Tracked as follow-up.
**Update (2026-08-14): closed.** All three profiles are now implemented in
all three languages:

| Language | Entry point | Profile type |
|---|---|---|
| Python | `encrypt_bytes_v8(..., pad_profile=)`, `encrypt_str_v8(..., pad_profile=)` | `"bucket"` / `("coarse", g)` / `("frame", F)` |
| Rust | `encrypt_bytes_v8_with_profile(...)` (`encrypt_bytes_v8` delegates with `Bucket`) | `PadProfile::{Bucket, Coarse(g), Frame(F)}` |
| C | `napqes_encrypt_bytes_v8_profiled(...)`, `napqes_encrypt_str_v8_profiled(...)` (NULL profile = `bucket`) | `napqes_pad_profile_t { napqes_pad_kind_t kind; uint32_t param; }` |

The profile is a sender-side deployment parameter, never appears in the wire
format, and requires no decoder change: every profile draws B from the same
13-element set `{2^4, ..., 2^16}`, so the set of legal token counts is
profile-independent. Invalid profiles (a `coarse` stride not dividing 12, a
`frame` size that is not a power of two in `[16, 65536]`, or a message that
does not fit the requested frame) are rejected at encryption time rather
than silently clamped, in all three languages.

Verification after the port: 276 Python tests pass / 1 skipped; 93 Rust
tests pass (up from 87, including the cross-language KAT checks in
`rust/src/kat_cross_check.rs`); 33 C KATs pass / 5 skipped, with a new
`[PASS] PAD` case in `C/test_kats.c` asserting that `frame(512)` collapses
five distinct plaintext lengths to one ciphertext length while `bucket` does
not, and that decryption succeeds without a profile argument. The default
`bucket` path is byte-identical to the previous behaviour, so
`tests/kat/v8_vectors.json` did not need regeneration.

**Requested action:** confirm that stating LH-IND-CPA-det against the
length-observing adversary, together with the attribution result and the
minus-the-arithmetic-layer comparison, discharges this finding; and confirm
whether the auditor wishes `frame(F)` promoted from an optional profile to
the recommended default for traffic-analysis-sensitive deployments.

## V3-CVF3 — Ciphertext expansion understated

**Status:** Open -> **Fixed** (paper)
**Category:** Documentation / accuracy
**Severity:** Moderate

### Response

Confirmed. The bulk of this finding was already discharged in the V3-CVF2
pass, which corrected every `20x` expansion figure to the true `160 bytes
per padded codepoint`. Two residues remained: one sentence still wrote
"the `20x` token ..." without naming the unit, and the paper never stated
the closed form for `|C|` — only the structural `16 + 8R(MAX_NOISE_RUN+1)
+ 32`, which a reader must unfold before it means anything.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- The ambiguous phrase now reads "fixed 20-tokens-per-real-token ceiling",
  which names the unit explicitly.
- The closed form `|C| = 48 + 160(B(|M|) + 2)` bytes is now stated in two
  places: next to the ciphertext-space bullet, and next to the discussion
  of the 2,928-byte minimum, where it is instantiated for any message of at
  most 15 codepoints.

### Scope of the fix

Documentation only. No behaviour changed; the wire format is unaffected.

### Known residual

None. The expansion factor is inherent to the construction and is stated
plainly; the `frame(F)` and `coarse(g)` padding profiles shipped under
V3-CVF2 do not change it.

**Requested action:** please confirm V3-CVF3 can be marked **Fixed**.

## V3-CVF4 — IND-CPA-det restrictions over-attributed to Rogaway-Shrimpton; DAE comparison overstated

**Status:** Open -> **Fixed** (paper)
**Category:** Soundness of claim
**Severity:** Moderate

### Response

Confirmed on both counts. The definition described *both* of its query
restrictions as "standard for deterministic / misuse-resistant AE
[Rogaway-Shrimpton]". Only restriction (ii) — equal-length challenge
messages — is standard in that sense. Restriction (i), which forbids the
adversary from re-querying a message it has already queried, is not
inherited from that line of work; it is an artefact of determinism in this
particular game and had to be justified on its own terms. Separately, the
paper's comparisons to AES-GCM-SIV implied a DAE-strength claim that the
proved notion does not support.

We chose to **narrow the prose rather than prove the stronger notion**. The
auditor notes that indistinguishability-from-random-bits under adaptive
queries is reachable via a union bound at the cost of the `q^2/2^128` term
the bound already carries; we agree, but that is a new theorem, and we
prefer to ship an honest statement of what is proved now and record the
stronger result as future work.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- The prose before `def:ind-cpa-det` now attributes only restriction (ii)
  to Rogaway-Shrimpton. Restriction (i) is justified in place, w.l.o.g., by
  a caching argument (a deterministic oracle's repeated answers carry no
  information the adversary did not already hold), and restriction (ii) is
  attributed to determinism.
- A new `Remark "Scope: this is not a DAE claim"` (`rem:dae-scope`) states
  explicitly that the proved notion is a single-challenge restricted game,
  that full DAE security in the sense of Rogaway-Shrimpton is **not**
  established, and where the gap lies.
- Every AES-GCM-SIV / SIV comparison now points at `rem:dae-scope` and
  cites RFC 5297 and RFC 8452 (see V3-CVF17).
- The conclusion records the stronger indistinguishability-from-random-bits
  theorem as future work.

### Scope of the fix

Documentation only.

### Known residual

**The stronger notion is not proved.** Readers who need DAE security in the
sense of [Rogaway-Shrimpton 2006] should treat NAPQES as unproved for that
purpose. `rem:dae-scope` says so.

**Requested action:** please confirm that narrowing the claim discharges
V3-CVF4, or state that the stronger theorem is required for the round to
close.

## V3-CVF5 — IND-CCA-det theorem stated without a definition; Bellare-Namprempre invoked as a black box

**Status:** Open -> **Fixed** (paper)
**Category:** Soundness of proof
**Severity:** Moderate

### Response

Confirmed. The paper asserted an IND-CCA-det theorem without ever defining
the notion, and discharged it with a `[Proof sketch]` that appealed to
Bellare-Namprempre generic composition. That appeal is not sound as stated:
the Bellare-Namprempre result composes *standard* IND-CPA and INT-CTXT, and
this construction proves *restricted* variants of both, so the black-box
citation does not apply without argument.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- A new `Definition "IND-CCA-det security"` (`def:ind-cca-det`) states the
  notion in full: encryption oracle plus adaptive decryption oracle, with
  only the exact challenge pair `(c*, A*)` forbidden, restrictions (i)-(ii)
  binding across both phases, and the advantage parameterised by the query
  counts.
- `thm:ind-cca` is restated against that definition.
- The proof sketch was **replaced with a full proof**: Game `H_0` / Game
  `H_1`, the transition, a bound on the bad event `D` (the adversary
  submits a decryption query on a fresh pair that does not decrypt to
  bottom), and a bound on `|Pr[H_1 = 1] - 1/2|`. The key step is that the
  INT-CTXT forger `A'` built from `A` needs only the verification oracle's
  single bit, so it simulates `A`'s decryption oracle perfectly up to the
  first occurrence of `D`. Bellare-Namprempre is cited for context and
  explicitly **not** invoked as a black box.

### Scope of the fix

Documentation only.

### Known residual

The composition inherits the scope limitation of V3-CVF4: it is
IND-CCA-det against the restricted game, not DAE.

**Requested action:** please confirm V3-CVF5 can be marked **Fixed**.

## V3-CVF6 — Message space under-specified; surrogates admitted; token-fit obligation not discharged

**Status:** Open -> **Fixed** (paper + code)
**Category:** Specification completeness
**Severity:** Moderate

### Response

Confirmed on all three points. The message space was written as "Unicode
codepoints", which admits the surrogate range U+D800-U+DFFF; the paper said
"x is assumed to fit" in the 8-byte token field without a calculation; and
the byte-oriented entry points' behaviour on input that does not decode was
unstated.

The auditor's preferred resolution was to redefine the message space as
arbitrary byte strings. We checked the three reference implementations
first, and that option turned out to be inapplicable: `napqes.py` iterates
`ord(c)` over a `str` and `rust/src/lib.rs` iterates `chars()`, so both are
genuinely **codepoint**-oriented, not byte-oriented. Redefining the domain
in bytes would have been a wire-format change. We therefore took the
fallback: keep the codepoint domain and specify it precisely.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- The message-space bullet now reads **Unicode scalar values**, i.e.
  codepoints excluding U+D800-U+DFFF, and justifies the exclusion from the
  UTF-8 nonce derivation (a surrogate has no UTF-8 encoding, so the
  synthetic nonce is undefined on it).
- A new `Remark "The token field is wide enough for the whole of M"`
  (`rem:token-fit`) discharges the fit obligation with an explicit
  worst-case computation: with `c = 0x10FFFF` and the largest admissible
  prime `k_j = 9,899,999`, the largest token is `11,029,707,685,887`, about
  `2^43.33`, leaving a factor of more than `1.6 x 10^6` of headroom in the
  64-bit field.
- A new `Remark "Implementation domains"` (`rem:impl-domain`) records that
  the C port is byte-oriented where Python and Rust are codepoint-oriented.

`napqes.py`:

- New `_validate_message_domain(message)` raises `ValueError` on any
  surrogate codepoint; it is called from `encrypt_bytes_v8` immediately
  after the `sk` length check, so the failure is explicit rather than a
  downstream UTF-8 encoding error.

### Scope of the fix

The domain narrowed to what was already reachable in practice; no
previously-encryptable message became unencryptable except surrogates,
which could not have produced a well-defined nonce anyway.

### Known residual

**The C port diverges from Python and Rust above U+007F.** `C/napqes.c`
maps each *byte* of the input to a token, whereas Python and Rust map each
*codepoint*. The three implementations therefore agree byte-for-byte only
on ASCII input. We have deliberately **not** changed this: aligning the C
port would change the wire format for non-ASCII plaintext and invalidate
every deployed ciphertext. It is documented in `rem:impl-domain`, in a new
`Known Caveats` entry, and in `docs/CAVEATS.md`.

**Requested action:** please confirm that the codepoint domain with
surrogates excluded is acceptable, and advise whether the C port's
byte-oriented divergence should be scheduled as a breaking change or left
documented.

## V3-CVF7 — FIPS row in the comparison table conflates approved primitives with approved modes

**Status:** Open -> **Fixed** (paper)
**Category:** Accuracy of claim
**Severity:** Moderate

### Response

Confirmed. A single row labelled "FIPS-approved" with a bolded **Yes** for
NAPQES conflated two distinct questions: whether the *primitives* used are
approved (they are — HMAC-SHA256 alone), and whether the *mode* is approved
(it is not, and no unapproved mode can sit inside a FIPS 140-3
cryptographic boundary).

### Fix shipped

`docs/napseq-eprint-v3.tex`, `tab:comparison`:

- The row was split in two: **FIPS-approved primitives only** (NAPQES Yes /
  AES-GCM Yes / ChaCha20-Poly1305 No / Ascon Yes) and **Approved as a mode
  or algorithm** (NAPQES No / AES-GCM Yes / ChaCha20-Poly1305 No / Ascon
  Yes, citing SP 800-232).
- The bolding was dropped throughout the row group.
- A new caption paragraph states plainly that NAPQES is an unapproved mode
  and would fall outside an approved-mode boundary in a FIPS 140-3
  validation, whatever the status of its primitives.

### Scope of the fix

Documentation only.

### Known residual

None. NAPQES remains an unapproved mode; that is now stated rather than
implied away.

**Requested action:** please confirm V3-CVF7 can be marked **Fixed**.

## V3-CVF8 — Decoder accepts structurally impossible ciphertexts after tag verification

**Status:** Open -> **Fixed** (paper + code, all three languages)
**Category:** Robustness / specification completeness
**Severity:** Moderate

### Response

Confirmed. `Dec` step (3) checked only that the token count was divisible
by `MAX_NOISE_RUN + 1`. That is necessary but not sufficient: the real-token
count `R` recovered from `|C|` must additionally equal `B + 2` for some
reachable padding bucket `B` in `{2^4, ..., 2^16}`, and the 2-codepoint
length prefix `n` recovered from the decrypted buffer must satisfy
`n <= R - 2`. Neither was specified, and the implementations diverged in
what they enforced.

These checks are reachable only *after* the tag verifies, so no adversary
without `sk` can trigger them and they play no part in the INT-CTXT
argument. They matter because the decoding step is not total without them:
a key holder can trivially produce a validly tagged but structurally
malformed ciphertext, and the decoder must reject it rather than
mis-parsing, over-reading, or allocating against an attacker-chosen count.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- `Dec` was renumbered from six steps to nine. The bucket-membership check
  is now step (6) and the length-prefix check is step (8), both explicitly
  after the constant-time tag comparison in step (5).
- A new `Remark "The post-authentication structural checks"`
  (`rem:dec-structural`) explains why they are specified despite being
  unreachable by an outside adversary, and notes that divisibility does not
  imply bucket membership (`R = 20` passes step (3) and fails step (6)).
- The correctness proof was renumbered to match and now shows explicitly
  that an honest ciphertext passes both new checks.

Implementations:

- `napqes.py`: new `_LEGAL_REAL_TOKEN_COUNTS` frozenset; `_decrypt_v8_core`
  rejects any `real_count` outside it. `_unpad_message` already carried the
  `2 + n > len(padded)` guard.
- `rust/src/lib.rs`: `decrypt_core_v8` performs the same bucket check.
  **`unpad_message` was additionally converted from a panicking `Vec<u32>`
  return to `Result<Vec<u32>, String>`** — see the residual below.
- `C/napqes.c`: `decrypt_core_v8` performs the same bucket check. Both v7
  and v8 unpad paths already carried the length-prefix guard.

Negative KAT vectors `W-N06`, `W-N07`, `W-N08` were added to
`tests/gen_kats_v8.py` and `tests/kat/v8_vectors.json`. All three are
**validly tagged**, so they exercise the new checks rather than the tag
comparison: a token count that is not a multiple of `MAX_NOISE_RUN + 1`; a
real-token count of 20, which is such a multiple but is not `B + 2` for any
reachable `B`; and a length prefix claiming more codepoints than the padded
buffer holds. They are consumed automatically by `tests/test_kats.py` and
`rust/src/kat_cross_check.rs`.

### Scope of the fix

Rejection of inputs that no conforming encryptor can produce. No honest
ciphertext changes, and no honest ciphertext is newly rejected. v7 paths
are untouched and `python tests/gen_kats.py --check` still passes
byte-identically.

### Known residual

**A genuine latent defect was found while implementing this, and is now
fixed.** The Rust `unpad_message` sliced `padded[2..2 + n]` with no bounds
check, so a validly tagged but malformed v8 ciphertext caused an
index-out-of-range **panic** rather than an error return. Python and C both
already had the guard; only Rust did not. Vector `W-N08` now pins this in
all three languages. We report it because it was reachable by any key
holder and would have been a denial-of-service vector in any Rust service
decrypting on behalf of multiple key holders.

**Requested action:** please confirm V3-CVF8 can be marked **Fixed**, and
confirm that the thirteen-value bucket set `{18, 34, 66, ..., 65538}` is
accepted as the normative set of legal real-token counts.

## V3-CVF9 — Dec does not re-derive N; ciphertext uniqueness never addressed

**Status:** Open -> **Fixed** (paper)
**Category:** Specification completeness
**Severity:** Low

### Response

Partly discharged already: the V3-CVF1 pass replaced the claim that the
nonce is "deterministically re-derivable once M is recovered" with the
correct statement that `N` is **read from the ciphertext, not re-derived**,
so no circularity arises. The residual the auditor identified is that the
paper never drew the consequence: because `Dec` does not check `N` against
a re-derivation from `(A, M)`, valid ciphertexts are **not unique** per
`(A, M)`.

We chose **not** to add the re-derivation check. Adding it would give
ciphertext uniqueness and make the RFC 5297 analogy exact, but at the cost
of making `Dec` depend on the plaintext it is recovering, plus an extra
HMAC over the recovered plaintext and a decoder change in three languages.
The property it would buy is not required by any theorem in the paper.

### Fix shipped

`docs/napseq-eprint-v3.tex`: a new `Remark "Valid ciphertexts are not
unique per (A, M)"` (`rem:not-unique`) after the correctness proof. It
states that a holder of `sk` can pick an arbitrary `N' != N`, rebuild the
masked blob and tag under it, and obtain a second equally valid ciphertext
for the same plaintext; that `Enc` is a function but `Dec` is **not**
injective on valid ciphertexts; that NAPQES is therefore **not tidy** in
the sense of Namprempre-Rogaway-Shrimpton; and that ciphertext equality
must not be used as a proxy for plaintext equality by any protocol built on
it. It also explains why this costs nothing in the analysis: INT-CTXT
measures freshness over the submitted pair `(c, A)`, not over the
underlying plaintext, so an alternative encoding of an already-queried
message is a legitimate forgery attempt and is counted as one.

### Scope of the fix

Documentation only. No code change, by decision.

### Known residual

**NAPQES is not tidy.** Protocols that rely on ciphertext equality implying
plaintext equality — deduplication, replay detection by ciphertext hash,
equality-preserving storage — must not be built on NAPQES without an
external mechanism. `rem:not-unique` says so.

**Requested action:** please confirm that documenting the behaviour is
acceptable, or state that the re-derivation check is required.

## V3-CVF10 — Truncation lemma states an equality between the same adversary in two different games; units confused

**Status:** Open -> **Fixed** (paper)
**Category:** Soundness of proof
**Severity:** Moderate

### Response

Confirmed on both points.

1. The lemma asserted `Adv^PRF_{trunc_t o F}(B) = Adv^PRF_F(B)` for a
   single adversary `B`. That is not well-formed: `B` plays against a
   truncated oracle in one game and an untruncated one in the other, and
   the two games have different oracle output lengths. The reduction has to
   name a **derived** adversary.
2. The truncation length was written `t <= 256`, suggesting bits, but the
   truncation itself was written `x[0:t]` with output space `{0,1}^{8t}`,
   i.e. bytes. The two are inconsistent; the correct bound is `t <= 32`.
   The symbol also collided with the 64-bit noise-threshold draw `tau` used
   in the definition of `theta(N)`.

### Fix shipped

`docs/napseq-eprint-v3.tex`, `lem:trunc-prf`:

- Restated as: for every adversary `B` against `trunc_l o F` there is an
  adversary `B'` against `F`, making the same number of queries and running
  in essentially the same time, with equal advantage. The proof now
  constructs `B'` explicitly (run `B`, forward its queries, truncate each
  32-byte answer to `l` bytes before returning it, output whatever `B`
  outputs), verifies both worlds, and closes with an explicit note on the
  direction of the reduction.
- The truncation length is now named `l`, stated in **bytes**, bounded
  `1 <= l <= 32`, and the three instantiations are given in the same unit
  (nonce `l = 16`, addend and padding codepoint `l = 4`, noise threshold
  `l = 8`).
- A closing sentence states that `l` is local to the lemma and unrelated to
  the noise-threshold draw `tau`.
- The balancedness step (truncating a uniform random function yields a
  uniform random function, independently across inputs) is now written out
  rather than asserted.

### Scope of the fix

Documentation only. The lemma was true in substance; its statement and
proof were not.

### Known residual

None.

**Requested action:** please confirm V3-CVF10 can be marked **Fixed**.

## V3-CVF11 — Padding-bucket length leak understated

**Status:** **Already fixed** (verified, no new work)
**Category:** Accuracy
**Severity:** Low

### Response

This was discharged in the V3-CVF2 pass. We re-verified rather than
re-fixing: the figure `log_2 13 ~ 3.70` bits is now used consistently at
all five sites in `docs/napseq-eprint-v3.tex` (abstract, padding section,
wire format, comparison table, conclusion). The thirteen reachable padding
buckets are `{2^4, ..., 2^16}`, so `log_2 13` is exact for the leak through
ciphertext length.

Note that V3-CVF24 identifies a *timing* channel that can in principle
reveal more than 3.70 bits about the message length; that is tracked
separately and is now documented in the constant-time subsection and in the
caveats.

**Requested action:** please confirm V3-CVF11 was correctly closed in the
previous round.

## V3-CVF12 — Prime-set cardinality wrong, and the paper disagrees with the code

**Status:** Open -> **Fixed** (paper + code, all languages)
**Category:** Accuracy / spec-code divergence
**Severity:** Moderate

### Response

Confirmed, and worse than reported. The paper stated
`|P| ~ 586,000` for the interval `[10^6, 9.9 x 10^6]`. That figure is in
fact `pi(10^7) - pi(10^6) = 586,081` — the count for the **wrong upper
bound**. Every figure derived from it was therefore also wrong.

While checking this we found a three-way divergence that the audit did not
report:

| Artefact | Interval | Claimed cardinality |
|---|---|---|
| `docs/napseq-eprint-v3.tex` | `[10^6, 9.9 x 10^6]` | `~586,000` (wrong) |
| `napqes.py` defaults | `[10^6, 1.5 x 10^7]` | `892,206` in the docstring |
| `rust/src/lib.rs`, `C/test_kats.c` call sites | `[10^6, 9,999,999]` | — |

We sieved all three intervals before deciding:

| Upper bound | `pi(hi) - pi(10^6)` | `log_2 P(c,10)` | post-Grover | key space |
|---|---|---|---|---|
| 9,900,000 | **579,947** | **191.4555** | **95.7278** | **4.304e57** |
| 10,000,000 | 586,081 | 191.6073 | 95.8036 | 4.781e57 |
| 15,000,000 | 892,206 | 197.6701 | 98.8351 | 3.196e59 |

Per the plan's decision 2, the **paper's** interval is normative: it is the
audited artefact and two prior rounds already recomputed entropy figures
against it.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- The `P` bullet now states `|P| = 579,947` as an exact normative constant,
  says how it was obtained (sieve; both endpoints are composite), and adds
  "Implementations MUST use this interval".
- All four derived figures were recomputed: `19.16 K` -> `19.1456 K`;
  `191.6` -> `191.46`; `4.8 x 10^57` -> `4.30 x 10^57`; `2^191.6` /
  `2^95.8` -> `2^191.46` / `2^95.73`; and the caveats section's
  trial-division search space `~586,000` -> `579,947`.

Code, all unified at `[1,000,000, 9,900,000]`:

- `napqes.py`: new `MAX_KEY_PRIME = 9_900_000`; `generate_prime_numbers`
  and `generate_v8_key` defaults changed from `15_000_000`; the
  `generate_prime_numbers` docstring's `892,206` / `2^197.67` claims
  corrected to `579,947` / `2^191.46` (`2^95.73` post-Grover).
- `rust/src/lib.rs`: new `pub const MIN_KEY_PRIME` / `MAX_KEY_PRIME`, used
  at every call site (previously the literal `9_999_999`).
  `rust/src/main.rs` and `rust/README.md` updated to match.
- `C/napqes.h`: new `NAPQES_MIN_KEY_PRIME` / `NAPQES_MAX_KEY_PRIME` macros;
  `C/test_kats.c` uses them.
- `tests/test_streaming_and_primes.py`: the range assertion now uses the
  constants, and a new `test_default_range_matches_normative_interval`
  pins their values so the paper and the code cannot drift apart again.
- `docs/fips/KEY_MANAGEMENT.md` section 2.1 rewritten to name the interval.

### Scope of the fix

**Generation only.** Per the compatibility guard in our plan,
`_validate_key` and the decryption paths still accept any prime
`>= MIN_KEY_PRIME`, so keys generated under the old wider bound — holding
primes in `(9.9 x 10^6, 1.5 x 10^7]` — keep working. The wire format is
unaffected and no KAT vector changed.

### Known residual

- **Keys generated before this change may contain out-of-interval primes.**
  They still decrypt. Their entropy is *higher*, not lower, so this is not
  a security regression, but such keys are not conformant to the normative
  interval and will not be reproduced by the current generator. Recorded in
  `docs/CAVEATS.md`.
- **`napqes_kem.py` and `rust/src/kem.rs` deliberately retain
  `[10^6, 1.5 x 10^7]` with `K = 13`.** That is a separate v6 FrodoKEM
  component, out of scope for this paper, and internally consistent. We did
  not touch it. If the auditor wants a single global interval, that is a
  larger change and should be scheduled explicitly.

**Requested action:** please confirm `|P| = 579,947` and the four
recomputed figures, and confirm that narrowing generation while keeping
validation permissive is the right compatibility posture.

## V3-CVF13 — Known-Answer Test section describes the wrong corpus

**Status:** Open -> **Fixed** (paper)
**Category:** Documentation / accuracy
**Severity:** Low

### Response

Confirmed. The section described `tests/kat/v6_vectors.json`, which covers
the **v7** block mode and streaming AE — not the scheme this paper
specifies. It also claimed coverage of "multiple nonces for the same
message", which is unreachable for a synthetic-nonce scheme: the nonce is a
function of `(A, M)`, so there is exactly one nonce per message and AAD.

### Fix shipped

`docs/napseq-eprint-v3.tex`, `Known-Answer Tests`, rewritten:

- The corpus for this paper's scheme is named as
  `tests/kat/v8_vectors.json`, with its exact composition — now **20
  vectors: 12 positive (`W001`-`W012`) and 8 negative
  (`W-N01`-`W-N08`)** — and what each positive vector covers (empty
  message, single character, the block boundaries at 15, 16 and 32
  codepoints, 1-element and 10-element prime tuples, empty / binary /
  64-byte AAD pinning the `be8` prefix from V3-CVF1, mixed-case
  punctuation).
- The negative vectors are split by what they exercise:
  `W-N01`-`W-N05` authentication and the 48-byte parse floor;
  `W-N06`-`W-N08` the post-authentication structural checks from V3-CVF8.
- The "multiple nonces for the same message" claim was **deleted**. The
  section now says instead that no nonce field appears in a vector and none
  is needed, because `Enc` is a pure function of its inputs.
- `v6_vectors.json` (37 vectors) is described as the **v7** corpus and
  explicitly marked out of scope for this paper. Per repo convention the
  file name is kept for path stability; the paper's description and label
  were corrected instead, and the paper says so.
- The generator and both consumers (`tests/gen_kats_v8.py`,
  `tests/test_kats.py`, `rust/src/kat_cross_check.rs`) are named.

### Scope of the fix

Documentation only, plus the three new vectors shipped under V3-CVF8.

### Known residual

Corpus digests are not published in the paper. The generator is
deterministic and `--check` verifies regeneration byte-for-byte, so a
digest would add little; we can add one on request.

**Requested action:** please confirm V3-CVF13 can be marked **Fixed**, and
say whether corpus digests should be printed in the paper.

## V3-CVF14 — "Constant-time considerations" covers only the tag comparison

**Status:** Open -> **Fixed** (paper)
**Category:** Documentation / threat model
**Severity:** Moderate

### Response

Confirmed. The subsection was three lines long, named two library calls,
and stopped. It gave a reader no way to tell which values are secret-
dependent, which operations touch them, or what a local-timing adversary is
assumed not to have. Worse, its brevity combined with the phrase "compared
in constant time" in `Dec` step (5) to imply a whole-algorithm property
that does not hold.

### Fix shipped

`docs/napseq-eprint-v3.tex`, `Constant-Time Considerations`, rewritten into
four parts:

- **Threat model.** Every claim in the security section is black-box; side
  channels are explicitly outside it and no theorem in the paper says
  anything about them. The phrase in `Dec` step (5) describes exactly one
  operation, not the algorithm.
- **What is constant-time.** Tag comparison, in all three languages, with
  the honest caveat that the C accumulator is not declared `volatile` and
  so is not formally protected against a compiler reintroducing an early
  exit.
- **What is not**, itemised: the noise-dependent iteration count; integer
  division by a key element; the padding loop's `B - n` derivations (see
  V3-CVF24); the Python reference implementation's complete lack of timing
  guarantees; and the new structural checks from V3-CVF8, which reject at
  different points but are reachable only by a key holder.
- **What an attacker gets.** A timing channel may reveal something about
  the noise realisation and hence about `theta(N)` and indirectly `N`;
  since `N` is transmitted in the clear this particular leak is not by
  itself a break, but no bound is offered on what else such a channel
  exposes.

A new `Known Caveats` entry, `Timing side channels`, repeats the essentials
and directs deployments with a measurable timing channel to treat this as
unresolved.

### Scope of the fix

Documentation only. No timing-hardening work was performed.

### Known residual

**NAPQES is not constant-time outside the tag comparison, and we do not
claim it is.** `docs/DUDECT_ATTESTATION.md` covers the tag comparison only.
A TVLA or dudect study of the full encode/decode path remains future work
and is stated as such in both the paper and `docs/CAVEATS.md`.

**Requested action:** please confirm that an explicit threat statement plus
a caveat is the right disposition, or state that timing-hardened reference
implementations are required for the round to close.

## V3-CVF15 — Shor exposure claimed as a differentiator

**Status:** Open -> **Fixed** (paper)
**Category:** Accuracy of claim
**Severity:** Moderate

### Response

Confirmed. The abstract and introduction implied that AES-GCM and
ChaCha20-Poly1305 are exposed to Shor's algorithm and NAPQES is not. That
is false — no symmetric AEAD has Shor-applicable structure, and the paper's
own comparison table already said so (`Shor-applicable structure: No / No /
No / No`). The claim contradicted the table two pages later.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- The `No Shor-applicable structure` paragraph now states that this is a
  property **shared** by every symmetric AEAD, not a differentiator, and
  points at the table row that shows it.
- The abstract and introduction were rewritten around three defensible
  claims instead: a single approved primitive; no polynomial or field
  authenticator, hence no exposure to the AES-GCM forbidden attack; and a
  post-quantum posture governed by Grover, identically for all symmetric
  schemes.
- The bolding was dropped from the Shor row in `tab:comparison`.

### Scope of the fix

Documentation only.

### Known residual

None.

**Requested action:** please confirm V3-CVF15 can be marked **Fixed**.

## V3-CVF16 — NIST 112-bit guidance misstated

**Status:** Open -> **Fixed** (paper)
**Category:** Accuracy of citation
**Severity:** Low

### Response

Confirmed. The paper wrote "the 112-bit minimum NIST recommends for
post-2030 systems". NIST SP 800-131A Rev. 2 does the opposite: it
**deprecates** 112-bit security after 2030 and sets **128 bits** as the
minimum from that point. As written, the sentence understated the
requirement the construction actually meets.

### Fix shipped

`docs/napseq-eprint-v3.tex`: the sentence now cites SP 800-131A, states
that 112-bit security is deprecated after 2030 and 128 bits is the minimum
from that point, and observes that a `2^128` sequential-depth bound
therefore *meets* the post-2030 minimum rather than merely exceeding a
112-bit floor. `sp800-131a` was added to the bibliography.

### Scope of the fix

Documentation only.

### Known residual

None.

**Requested action:** please confirm V3-CVF16 can be marked **Fixed**.

## V3-CVF17 — Bibliography errors: misattributed nonce-reuse reference, obsoleted RFC, missing SIV references, stale Ascon status

**Status:** Open -> **Fixed** (paper)
**Category:** Citation hygiene
**Severity:** Low

### Response

Confirmed on all four sub-items.

- **(a)** The `joux-nonce` key was attached to Iwata-Ohashi-Minematsu, and
  the key name implied Joux authored the proof-repair paper. Both the
  attribution and the claim it supported were wrong.
- **(b)** `rfc7539` is obsoleted by RFC 8439.
- **(c)** Ascon was described as "not yet in a FIPS-approved family". NIST
  standardised it as SP 800-232 in 2025.
- **(d)** RFC 5297 (AES-SIV) and RFC 8452 (AES-GCM-SIV) were absent from
  the bibliography despite the SIV analogy being drawn three times.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- `joux-nonce` renamed to `iwata2012` with the correct attribution, and the
  nonce-reuse claim it was attached to repointed.
- `rfc7539` replaced by `rfc8439` at every site. Confirmed zero surviving
  occurrences of either `joux-nonce` or `rfc7539`.
- `sp800-232` added; the Related Work paragraph and `tab:comparison` now
  say Ascon is standardised by NIST as SP 800-232.
- `rfc5297` and `rfc8452` added and cited at all three SIV-analogy sites,
  each of which now also points at `rem:dae-scope` (see V3-CVF4).
- The AES-GCM forbidden attack is now described correctly in Related Work.

### Scope of the fix

Documentation only.

### Known residual

None.

**Requested action:** please confirm V3-CVF17 can be marked **Fixed**.

## V3-CVF18 — Key size stated as a lower bound; K range unspecified

**Status:** Open -> **Fixed** (paper)
**Category:** Specification completeness
**Severity:** Low

### Response

Confirmed for the table cell. The comparison table gave `Key size: >= 82
bytes`, which is a floor rather than a value and does not say what it
scales with.

The second half — the permitted range of `K` — turned out to be **already
discharged**: existing prose in the key-roles discussion already states
that `K = 10` is an interoperability default and not a security parameter,
that any `K >= 1` is permitted, and that both parties must agree on `K` out
of band since it does not appear in the ciphertext. We verified this rather
than rewriting it.

### Fix shipped

`docs/napseq-eprint-v3.tex`, `tab:comparison`: the key-size cell now reads
`5K + 32` bytes (`k` + `sk`), instantiated as `82` at the default `K = 10`,
so the scaling rule and the concrete value are both visible.

### Scope of the fix

Documentation only.

### Known residual

`K` is not carried in the ciphertext, so a `K` mismatch surfaces as an
authentication failure rather than a distinguishable error. That is the
existing V3-CVF7-round format-selection philosophy (callers agree out of
band) and is stated in the paper.

**Requested action:** please confirm V3-CVF18 can be marked **Fixed**.

## V3-CVF19 — Abstract defects: truncation omitted from the nonce formula, scrambled contribution references, unsupported performance promise

**Status:** Open -> **Fixed** (paper)
**Category:** Documentation
**Severity:** Low

### Response

Confirmed on all three.

- **(a)** The abstract's nonce formula omitted the `[0:16]` truncation, so
  as written it produced a 32-byte nonce.
- **(b)** The third contribution bullet's cross-references did not point at
  the results they claimed, and ended with a dangling reference.
- **(c)** The abstract promised "performance measurements" that the paper
  does not contain; the conclusion simultaneously placed performance
  evaluation in future work.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- The abstract's nonce formula now ends `... || A || M)[0:16]`.
- The contribution bullets were repaired so each claimed result points at
  the theorem that proves it, and the dangling reference was deleted.
- The performance-measurements promise was **deleted** from the abstract,
  per decision 6, rather than manufacturing a benchmark table. The
  conclusion already places performance evaluation in future work, and now
  does so without contradiction.

### Scope of the fix

Documentation only.

### Known residual

**The paper contains no performance evaluation.** That is now stated
consistently in both places rather than promised in one and deferred in the
other.

**Requested action:** please confirm that deleting the promise is
acceptable, or state that measured throughput figures are required.

## V3-CVF20 — Conclusion credits empirical activities with establishing security

**Status:** Open -> **Fixed** (paper)
**Category:** Soundness of claim
**Severity:** Moderate

### Response

Confirmed. The conclusion said the construction "has been validated
against" the KAT corpus, SP 800-22 and fuzzing. None of those establishes a
security property. A KAT corpus establishes cross-implementation byte
agreement; SP 800-22 is a statistical sanity check on the keystream
implementation and would pass equally for a broken cipher with good
statistics; fuzzing establishes decoder robustness.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- The conclusion was rewritten so each activity is credited with exactly
  what it establishes, and closes with the sentence that **none of them is
  evidence for a security claim**. "Validated" is now reserved for the
  theorems.
- The same qualification was added to the SP 800-22 section.
- The abstract's framing was aligned.

### Scope of the fix

Documentation only.

### Known residual

None.

**Requested action:** please confirm V3-CVF20 can be marked **Fixed**.

## V3-CVF21 — Nonce-collision term described as "not a birthday bound"

**Status:** Open -> **Fixed** (paper)
**Category:** Accuracy of claim
**Severity:** Moderate

### Response

Confirmed. The comparison section described the nonce-collision event as a
"negligible HMAC-SHA256-collision event rather than a birthday-bound
event", while the paper's own IND-CPA and IND-CCA theorems carry an
explicit `q^2 / 2^128` term. Synthetic nonce derivation removes the
*caller-error* and *DRBG-failure* routes to nonce reuse; it does not remove
the birthday bound over a 128-bit nonce, and the paper should not have
implied otherwise.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- A new paragraph in the comparison section, immediately after the
  nonce-reuse paragraph, states plainly that `q^2 / 2^128` **is** an
  ordinary birthday term and that NAPQES therefore has a data-complexity
  limit of roughly `2^64` encryptions per key, the same order as any
  128-bit-nonce AEAD. The offending clause was removed.
- A new `Known Caveats` entry, `Per-key data limit`, recommends an
  operational cap of `q <= 2^48` encryptions per `(k, sk)` pair, at which
  the term is `2^-32`, followed by rekeying.

### Scope of the fix

Documentation only.

### Known residual

**The cap is not enforced.** Neither the reference implementations nor the
wire format count encryptions or refuse to continue past a threshold; it is
a deployment obligation. Recorded in the paper's caveats and in
`docs/CAVEATS.md`.

**Requested action:** please confirm V3-CVF21 can be marked **Fixed**, and
say whether an enforced counter is wanted in the reference implementations.

## V3-CVF22 — INT-CTXT bounded without a definition; domain-separation lemma cited out of scope

**Status:** Open -> **Fixed** (paper)
**Category:** Soundness of proof
**Severity:** Moderate

### Response

Confirmed on both halves.

1. `thm:int-ctxt` bounded `Adv^INT-CTXT` without the notion ever being
   defined: the verification oracle's output behaviour, the freshness
   condition, whether the experiment halts on a successful forgery, and the
   query-count parameterisation were all unstated.
2. The proof's Case 1 applied the domain-separation lemma to an
   **adversary-chosen** forgery input `x*`, but the lemma was stated only
   over "the queries this construction makes" — a strictly smaller domain.
   The citation was therefore out of scope.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- A new `Definition "INT-CTXT security"` (`def:int-ctxt`) states the notion
  in full: a **bit-only** verification oracle (it returns accept/reject,
  never the plaintext), freshness evaluated over the **pair** `(c, A)`
  rather than over `c` alone, an experiment that does **not** halt on a
  successful forgery, and an advantage parameterised by both query counts.
- `lem:domsep` was restated over the **entire argument domain**, including
  adversarially chosen tuples. Its existing positional-structure proof
  generalises unchanged, which we verified line by line. Case 1 of the
  INT-CTXT proof is now within the lemma's scope.

The bit-only verification oracle is also what makes the IND-CCA-det proof
in V3-CVF5 go through, since the derived forger needs nothing more.

### Scope of the fix

Documentation only.

### Known residual

None.

**Requested action:** please confirm V3-CVF22 can be marked **Fixed**.

## V3-CVF23 — Modulo-bias remark uses an inverted domination argument and wrongly exempts theta(N)

**Status:** Open -> **Fixed** (paper)
**Category:** Soundness of argument
**Severity:** Moderate

### Response

Confirmed on both halves, and we agree the first is the more serious.

1. The remark dismissed the residue bias as "statistically dominated by the
   underlying PRF advantage against HMAC-SHA256". That comparison is not
   meaningful in either direction: a small PRF advantage says nothing about
   the uniformity of a reduced output, and the two quantities are not
   commensurable. The conclusion (no rejection sampling needed) happens to
   be right, but the argument given for it was not.
2. `theta(N)` was declared "exempt ... no residue bias applies to it at
   all". That is wrong. It uses no modulo reduction, but it *is* a
   fixed-point rescaling of a 64-bit draw onto a smaller range, and that
   carries a **larger** non-uniformity than any of the reductions the
   remark was worried about.

We computed the actual figure rather than asserting one. `theta(N)` maps
`2^64` equally likely draws of `tau` onto approximately `0.24 x 2^64`
outputs, about `4.17` preimages per output; since each output receives
either 4 or 5 preimages, individual outputs deviate from uniform on the
range by up to **+20%** in relative terms, with total variation distance
**~0.033** from uniform on `[theta_min, theta_max]`.

### Fix shipped

`docs/napseq-eprint-v3.tex`, `rem:modbias`, rewritten:

- The bias is now quantified exactly: writing `2^32 = am + r`, exactly `r`
  residues occur with probability `(a+1)/2^32` and `m - r` with `a/2^32`,
  so the statistical distance is at most `m / 2^32` — below `2^-25` for the
  padding codepoint and noise character, below `2^-8` for the addends.
- The domination sentence was **removed** and replaced with the correct
  justification: no result in the security section requires any of these
  values to be uniform. Confidentiality rests entirely on the one-time
  keystream `ks(N)` masking the serialised blob and integrity entirely on
  the tag; these values are computed *underneath* that mask and are never
  observed by the adversary in the clear. The one correctness property that
  depends on them, `gcd(a, k) = 1`, follows from the range and holds for
  every draw regardless of bias.
- The remark now says explicitly that no rejection sampling is required
  "not because the bias is negligible relative to some other quantity, but
  because nothing is claimed that it could invalidate".
- A new paragraph corrects the `theta(N)` exemption with the `+20%` /
  `TV ~ 0.033` figures, explains why it is nonetheless harmless (the only
  property required of `theta(N)` is that it land in the public interval,
  which it does by construction, and that `Dec` recompute it identically,
  which it does), and states that it should not be described as exempt.
- A closing paragraph states the **boundary of the argument**: any variant
  that exposes a reduced value before it is masked, drops the keystream
  mask, or reuses a nonce makes these biases immediately relevant, and the
  analysis would then have to be redone with explicit bias terms.
- The prime-index sampling of `rem:sampling` is confirmed genuinely
  bias-free, by rejection.

### Scope of the fix

Documentation only. No sampling behaviour changed.

### Known residual

**`theta(N)` is not uniform on its range** and is now documented as such.
This is a property of the construction, not a defect we intend to fix: the
noise rate only needs to land in the public interval.

**Requested action:** please confirm V3-CVF23 can be marked **Fixed**, and
confirm the `TV ~ 0.033` figure.

## V3-CVF24 — Decoder inversion under-specified; running time depends on more than the paper concedes

**Status:** Open -> **Fixed** (paper)
**Category:** Specification completeness / threat model
**Severity:** Moderate

### Response

Confirmed on both halves.

1. `Dec` said only "invert the token-emission loop using the same
   `(sk, N)`-derived noise-position oracle and addends". That does not name
   the state the inversion actually needs: which prime is used at which
   index, and the replicated consecutive-run cap without which the
   inversion is ambiguous.
2. The paper conceded a `log_2 13 ~ 3.70`-bit length leak through
   ciphertext length, but running time depends on more than that.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- `Dec` step (7) (formerly part of step (6)) now names the full inversion
  state: skip at most `MAX_NOISE_RUN` consecutive noise positions, then
  read one real token `t` and recover the padded codepoint as
  `(t - a) / k[(real_idx mod K) + 1]`, where `a` is the `real_idx`-th
  addend from domain `0x01` and `real_idx` counts real tokens from 0 —
  explicitly the same prime and addend `Enc` used at that index.
- The `Constant-Time Considerations` subsection (see V3-CVF14) now itemises
  the padding loop's `B - n` derivations, so encryption time depends on the
  **exact** codepoint count `n`, not merely on its padding bucket `B`, and
  states that a timing channel can in principle recover more than the 3.70
  bits that ciphertext length leaks.
- The variable decryption phase runs only **after** tag verification, so no
  forgery timing oracle arises for an adversary without `sk`; this is
  stated in `rem:dec-structural` and in the constant-time subsection.

### Scope of the fix

Documentation only.

### Known residual

Shared with V3-CVF14: the encode and decode loops are not timing-hardened,
and the exact-length timing dependence is documented rather than removed.

**Requested action:** please confirm V3-CVF24 can be marked **Fixed**.

## V3-CVF25 — Advantage functionals not parameterised by the scheme; PRF advantage spelled inconsistently

**Status:** Open -> **Fixed** (paper)
**Category:** Notation
**Severity:** Low

### Response

Confirmed. `Adv^IND-CPA-det(A)`, `Adv^INT-CTXT(A)` and
`Adv^IND-CCA-det(A)` carried no scheme subscript, which is ambiguous in a
paper that also discusses a generic scheme in the length-hiding separation
result. The PRF advantage was spelled `Adv^PRF_{HMAC-SHA256}` in some
places and `Adv^PRF_F` in others, including inside proofs.

### Fix shipped

`docs/napseq-eprint-v3.tex`:

- `Def "AEAD triple"` now names the scheme once — "NAPQES is the triple
  `Pi = (KeyGen, Enc, Dec)` ... The symbol `Pi` denotes this scheme, and
  only this scheme, throughout the security section."
- Every advantage functional is now subscripted `_Pi`, and every theorem
  opens by naming the scheme it concerns.
- The local generic scheme in `prop:lh-separation` was renamed from `Pi` to
  `Sigma`, removing the collision that made the subscript necessary.
- All PRF advantages are now spelled `Adv^PRF_{HMAC-SHA256}` uniformly,
  including inside proofs. The stray `Adv^PRF_F` occurrences were replaced,
  except in `lem:trunc-prf`, where `F` is the lemma's own bound variable
  and is now declared as such (see V3-CVF10).

### Scope of the fix

Notation only.

### Known residual

None.

**Requested action:** please confirm V3-CVF25 can be marked **Fixed**.

## Third-round verification summary

All work above was verified against the full test suite after each phase:

| Check | Command | Result |
|---|---|---|
| Python | `python -m pytest tests -q` | 280 passed, 1 skipped |
| v7 KAT parity | `python tests/gen_kats.py --check` | OK, 37 vectors, byte-identical |
| v8 KAT parity | `python tests/gen_kats_v8.py --check` | OK, 20 vectors |
| Rust | `cd rust; cargo test --lib` | 93 passed, 0 failed |
| Rust binaries | `cd rust; cargo build` | clean |
| C | MSVC build + `kat-test` | 33 passed, 0 failed, 5 skipped |
| Paper | `pdflatex` x3 | exit 0, zero undefined or multiply-defined references |

The five skipped C KATs are a pre-existing streaming-field gap in the
`C/test_kats.c` JSON reader, unrelated to this round and explicitly out of
scope.


