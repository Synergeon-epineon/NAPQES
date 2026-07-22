# NAPQES Known Caveats — Issue Triage

**Status:** Phase 0 baseline (2026-05-12)
**Wire format:** v7 (frozen — see [`SPEC.md`](../SPEC.md)); supersedes v6 as of the CVF1 fix (2026-07-06)
**Owner placeholders:** replace with GitHub username when repo is published.

This file serves as the issue-tracker stand-in until the repository moves to
a public host with native issue tracking. Migrate each entry to a GitHub issue
at that point and update this file to reference the issue number.

---

## CVF1 — Ciphertext byte-length leaks plaintext content (IND-CPA theorem false)

| Field | Value |
|---|---|
| **ID** | CVF1 |
| **Category** | Flaw |
| **Severity** | Critical (IND-CPA distinguishing advantage ≈ 1) |
| **Affects** | `encrypt_bytes` / `decrypt_bytes` / `encrypt_str` / `decrypt_str` (napqes.py block mode); `docs/napseq-eprint-preprint.tex` Theorem 1 (IND-CPA) |
| **Introduced** | v6 (LEB128 token encoding) |
| **Owner** | TBD |
| **Status** | **Fixed** (v7 wire format, 2026-07-06) |
| **Risk retired** | — (new finding from external audit review) |

**Description.** Each token is `token = codepoint × key_element + addend`
with `key_element ≈ 10⁶–10⁷` (≈ 2²⁰–2²³). The retired v6 format serialised
tokens with unsigned LEB128 (variable-length) *before* XOR-masking. Because
the LEB128 byte-length of a value grows with its magnitude, and token
magnitude scales with the plaintext codepoint, the serialised token blob's
byte-length — and hence the final ciphertext's byte-length — depended on
plaintext codepoint *values*, not just the padded codepoint *count*. Two
plaintexts of equal padded length (same padding bucket, same
HMAC-derived noise pattern) could still produce ciphertexts of different
byte-length: e.g. `n` copies of U+0001 (token ≈ 2²⁰, ~3 LEB128 bytes) vs.
`n` copies of U+FFFF (token ≈ 2³⁶, ~6 LEB128 bytes). The domain-0x07 XOR
mask is length-preserving, so it does not hide this — the distinguisher
gives an IND-CPA advantage ≈ 1, even under fresh nonces.

This also invalidated a step of the IND-CPA hiding lemma in
`docs/napseq-eprint-preprint.tex` (Theorem 1), which asserted "since $B$ is
the same length for both plaintexts $m_0, m_1$ (they have equal padded
lengths by the IND-CPA requirement)" without justification: equal padded
codepoint count does not imply equal serialised byte-length under a
variable-width encoding.

**Fix (v7 wire format).** Block-mode tokens are now serialised with a
constant-width, 8-byte big-endian field
(`napqes._fixed_encode_tokens` / `_fixed_decode_tokens`) instead of LEB128.
Every token occupies the same number of bytes regardless of magnitude, so
the serialised blob's length is `token_count * 8` — a function only of the
token *count*, which is itself a function of the padded codepoint count and
the HMAC-derived, content-independent noise schedule (domain `0x00`), never
of codepoint values. This restores the hiding-lemma step: for a fixed
challenge nonce, equal padded length now provably implies equal blob
byte-length. See `SPEC.md` §4–§5 and
`docs/napseq-eprint-preprint.tex` (Section "Wire Format (Version 7 —
CVF1 fix)" and the erratum remark on the hiding lemma) for the full
corrected argument.

Legacy v6 ciphertexts remain fully authenticated and readable via explicit
opt-in (`decrypt_bytes(..., legacy_v6_varint=True)`); they were never
vulnerable to tampering, only to this length side channel. The fix has been
applied consistently across the Python reference implementation, the C
port (`C/napqes.c`), and the Rust core (`rust/src/lib.rs`); all three
produce byte-identical v7 ciphertexts (verified via
`tests/kat/v6_vectors.json`, regenerated under the new encoding, and
`tests/test_cross_lang.py`).

**Not fixed (tracked as a CVF1 follow-up).** `encrypt_stream` /
`encrypt_stream_ae` (napqes.py streaming API) still serialise tokens as
LEB128 varints and therefore exhibit the same magnitude-dependent
byte-length pattern. This does not break an IND-CPA claim for streaming
mode specifically, because streaming mode already discloses the exact
plaintext length (no padding is applied there) — but the pattern is present
and should be closed in a future fix for defence in depth.

---

## CVF3 — Nonce reuse yields key recovery via the length channel (and, more directly, via the affine token structure alone)

| Field | Value |
|---|---|
| **ID** | CVF3 |
| **Category** | Flaw |
| **Severity** | Critical (key recovery under nonce reuse) |
| **Affects** | `napqes.py`, `rust/src/lib.rs`, `C/napqes.c` (all block-mode encrypt paths); `docs/napseq-eprint-preprint.tex` Table 4 ("Nonce-reuse key recovery" row) |
| **Introduced** | v1 (affine token construction: `token = codepoint * key_element + addend`) |
| **Owner** | TBD |
| **Status** | **Fully closed for v8** (misuse-resistant synthetic-IV key schedule shipped 2026-07-07, `encrypt_bytes_v8`/`decrypt_bytes_v8`, `rust/src/lib.rs`) — v7's random-nonce API keeps the documented residual below for callers who have not migrated |
| **Risk retired** | — (new finding from external audit review) |

**Description.** Every internal value NAPQES derives — noise positions
(domain `0x00`), noise characters (`0x04`), addends (`0x01`, `0x05`),
padding (`0x06`), and the XOR keystream (`0x07`) — is a deterministic
function of `(key_bytes, nonce)` alone via
`Derive_d(kb, N, ctx) = HMAC(kb, d‖N‖ctx)`; nothing else is random. A
repeated nonce therefore reproduces an identical keystream and identical
noise/addends (a two-time pad). `docs/napseq-eprint-preprint.tex` Table 4
advertised `Nonce-reuse key recovery: No` as an advantage over AES-GCM and
ChaCha20-Poly1305 — this was false.

The audit finding describes one escalation route: under a fixed nonce,
varying a real-plaintext codepoint `c` at a chosen position and watching
the (pre-CVF1) LEB128 ciphertext-length channel for the boundary transition
recovers `k_j` via a binary search, without ever attacking the mask. Since
the CVF1 fix (fixed-width 8-byte token encoding), this exact length-boundary
route is closed for the block API — but a strictly more direct route
remains, and does **not** depend on the length channel at all: the
domain-`0x07` mask is a plain XOR, so under a reused nonce, XOR-cancelling
two ciphertexts recovers the plain XOR of their fixed-width token fields
exactly; combined with one known plaintext codepoint at a given real-token
position, this yields the *exact* integer token value at that position for
a second, unknown codepoint. Two such known-plaintext tokens at the same
position give two equations `t = c*k + a` in the two unknowns `k, a`,
solved exactly by ordinary linear algebra (`k = (t1-t2)/(c1-c2)`). This
needs only known-plaintext, not chosen-plaintext, and is unaffected by the
CVF1 fix. Recovering `k_j` for each of the `K` key-tuple positions (cycled
via `real_idx mod K`) fully recovers the key. This is strictly worse than
an ordinary stream cipher's nonce-reuse confidentiality loss, and worse
than AES-GCM/ChaCha20-Poly1305 losing only their authentication key under
nonce reuse.

**Fix shipped (2026-07-06).**
- **Table 4 corrected.** `docs/napseq-eprint-preprint.tex` now states
  `Nonce-reuse key recovery: Yes (catastrophic)` for NAPQES, with a footnote
  proving the exact algebraic recovery above, and a new subsection
  ("Nonce Reuse Is Key-Recoverable, Not Merely Confidentiality-Losing")
  explaining why this is worse than a standard two-time pad and why the
  CVF1 fix does not (and cannot) close it. `comparator.py`'s
  "Nonce-reuse consequence" row and `docs/SECURITY_TARGET.md`'s "Nonce
  reuse" / "Key-recovery from ciphertext" rows were corrected to match —
  they previously repeated the same false "HMAC prevents direct algebraic
  recovery" / "standard AEAD limitation" claims.
- **Caller-chosen-nonce entry points restricted.** `rust/src/lib.rs`'s
  `encrypt_bytes_with_nonce` (an explicit-nonce encrypt used only by the
  FIPS power-on self-test and KAT verification) was `pub`, i.e. part of the
  crate's public API — any external consumer could call it in production
  with an attacker-influenced or accidentally-reused nonce. It is now
  `pub(crate)`; the external `rust/tests/kats.rs` integration test (which
  required `pub` visibility) was moved in-crate as
  `rust/src/kat_cross_check.rs` (a `#[cfg(test)]` unit-test module), and
  `tests/test_cross_lang.py` was updated to invoke
  `cargo test --lib kat_cross_check` instead of `cargo test --test kats`.
  Similarly, C's `napqes_encrypt_bytes_with_nonce` (`C/napqes.c` /
  `C/napqes.h`) is now compiled only when `NAPQES_ENABLE_TEST_NONCE_API` is
  defined; the default `napqes.o` / `napqes_demo` build does not define it,
  so the symbol is absent from the production library, and only the
  `make kat-test` target (which defines the macro) compiles and links it.
  The Python reference (`napqes.py`) never exposed a public encrypt
  function accepting a caller-supplied nonce — its one internal nonce-taking
  helper (`tests/gen_kats.py`'s `_encrypt_with_nonce`) was already
  underscore-private and test-only, so no change was needed there.
- Full regression suite re-run after these changes: 245 Python tests (1
  pre-existing, unrelated skip), 76 Rust unit tests (including the moved
  `kat_cross_check` module and the FIPS self-test, which still exercises
  the now-`pub(crate)` `encrypt_bytes_with_nonce` internally), and
  `tests/test_cross_lang.py`'s Rust↔Python cross-language checks all pass.
  The C side could not be compiled/verified in this environment (no C
  toolchain available — same known residual as CVF2).

**Not fixed for v7 — tracked as future work for callers who do not migrate.**
Correcting the documentation and removing the public misuse entry point
did not, by itself, change the underlying cryptographic property of the
*v7* wire format: NAPQES v7 nonce reuse remains catastrophic and
key-recoverable whenever a nonce is reused, by whatever means (DRBG
failure, restart-and-replay, a future caller-supplied-nonce API, etc.).
The 128-bit random nonce makes *accidental* reuse a ≈ 2⁶⁴ birthday event,
and the Rust core additionally runs a consecutive-nonce CRNG check
(`generate_nonce_with_crng_check`, SP 800-140B §4.9.2) that catches
back-to-back identical nonces from a failed DRBG — but this catches only
the immediately-previous nonce, not reuse across restarts, processes, or
replayed ciphertext, and no equivalent check exists in the Python or C
reference implementations.

**Fully closed (2026-07-07) via the v8 key schedule.** `rust/src/lib.rs`
now ships `generate_v8_key`/`encrypt_bytes_v8`/`decrypt_bytes_v8`, which
replace the CSPRNG nonce with a synthetic IV (RFC 5297/AES-GCM-SIV style):
`N = HMAC(sk, 0x0A‖be4(|aad|)‖aad‖message)[0:16]`, keyed by the
independently-sampled `sk` introduced by the same fix (see CVF8/CVF13
below). Because the nonce is now a deterministic PRF of `(sk, aad,
message)`, two *different* `(aad, message)` pairs can only share a nonce
via an HMAC-SHA256 collision (cryptographically negligible) — the
affine-cancellation key-recovery route above requires two *different*
known plaintexts under one *reused* nonce, which the v8 schedule makes
infeasible by construction rather than merely improbable. This is the
standard MRAE trade-off (misuse resistance in exchange for determinism):
re-encrypting the *identical* `(aad, message)` pair under the same v8 key
reproduces the identical ciphertext, which discloses only plaintext
equality — never a key-recovery or confidentiality break. See
`docs/napseq-eprint-preprint.tex`, "V8 Key Schedule and Synthetic Nonce",
for the full specification and updated security argument.

Callers who need probabilistic ciphertexts even for repeated identical
messages (rather than misuse resistance) should keep using the v7
random-nonce API (`encrypt_bytes`), which retains the residual described
above. The v7 and v8 wire-layouts are byte-shape-identical but **not**
interoperable with each other (different key schedule, different nonce
derivation); per the CVF7 format-selection philosophy, callers must agree
out-of-band on which schedule a given key/ciphertext uses. The Python and
C reference implementations have not yet been ported to the v8 schedule;
this is tracked as a follow-up so all three languages offer the
misuse-resistant path.

---

## CVF8 — IND-CPA bound ignores the actual key entropy and key size

| Field | Value |
|---|---|
| **ID** | CVF8 |
| **Category** | Algorithm |
| **Severity** | Critical for small `K` (theorem false as stated for `K` below the derived floor); imprecise (non-standard assumption) for the default `K=10` |
| **Affects** | `docs/napseq-eprint-preprint.tex` Theorem 1 (IND-CPA, `thm:ind-cpa`) |
| **Introduced** | Original theorem statement (no key-entropy term) |
| **Owner** | TBD |
| **Status** | Proof-level correction shipped 2026-07-07; **residual non-standard-assumption fully closed for v8** (2026-07-07, `generate_v8_key`/independent `sk`, `rust/src/lib.rs`) — see "Not fixed" below for v7's remaining scope |
| **Risk retired** | — (new finding from external audit review) |

**Description.** Theorem 1 bounded the adversary's IND-CPA advantage by
`Adv^PRF_HMAC-SHA256(B1) + q²/2^128`, with no term depending on `K` or
`|𝒫|`. The HMAC key `kb = key_bytes(k)` is not a uniform bit-string — its
min-entropy is `H∞(k) = log2(|𝒫|!/(|𝒫|−K)!)` (≈196 bits for `K=10`, ≈20
bits for `K=1`) — so the standard uniform-key HMAC-SHA256 PRF conjecture
does not, by itself, rule out an adversary that recovers `k` by offline
exhaustive search at cost `≈2^H∞(k)`. For small `K` this search is cheap,
making the original theorem false as stated for admissible small key
sizes, and the `≈2^196` key-space figure never entered the bound even at
the paper's own default `K=10`.

**Fix (proof-level).** Theorem 1 is restated with an explicit key-guessing
term `q_F·2^(−H∞(k))`, proved via a new key-guessing lemma. A new remark
states precisely that, once the guessing term is paid for, the residual
PRF advantage is against the *actual* prime-tuple key distribution — a
non-standard, weaker assumption than the conventional uniform-key
conjecture — rather than silently treating the two as equivalent. A
minimum-key-size remark derives `K≥7` as the floor required for the
guessing term to be negligible against the paper's own ≈128-bit
post-Grover target, and states it as a normative requirement. See
`docs/napseq-eprint-preprint.tex`, Theorem 1 and the subsection
"CVF8: Minimum Key Size and Removing the Residual Non-Standard
Assumption" (`sec:cvf8-fix`), for the full corrected argument.

**Not fixed for v7 (tracked as a CVF8 follow-up).** The v7 theorem still
rests on a non-standard "PRF under the prime-tuple key distribution"
assumption rather than the conventional uniform-key one, for callers who
have not migrated to v8. `KeyGen`'s default `K=10` already exceeds the
derived `K≥7` floor with margin, and no reference implementation
currently permits configuring `K<7`, so there is no known exploitable gap
at default v7 settings today.

**Fully closed (2026-07-07) via the v8 key schedule.** The fully rigorous
fix anticipated above — an HMAC subkey independent of the prime-tuple
entropy — is now shipped: `rust/src/lib.rs`'s `generate_v8_key` samples a
256-bit `sk` via CSPRNG *independently* of the prime tuple (not derived
from it by any function, unlike an HKDF-over-`kb` design, which would
remain correlated with `k` and would not by itself close CVF13's
simulation gap below). `encrypt_bytes_v8`/`decrypt_bytes_v8` key every
domain derivation with this independent `sk`, so `H∞(sk) = 256` exactly
and the conventional uniform-key HMAC-SHA256 PRF assumption applies
directly — no key-guessing term, and no non-standard key-distribution
hypothesis, is needed for v8. See `docs/napseq-eprint-preprint.tex`, "V8
Key Schedule and Synthetic Nonce", for the restated theorem under the v8
schedule. The Python and C reference implementations have not yet been
ported to v8; this is tracked as a follow-up.

---

## CVF9 — INDCPA was never formally defined, and the challenge-equality constraint was ill-specified

| Field | Value |
|---|---|
| **ID** | CVF9 |
| **Category** | Architecture |
| **Severity** | Theorem 1 was not well-defined (no formal notion, ambiguous length metric, circular use of an unproved precondition) |
| **Affects** | `docs/napseq-eprint-preprint.tex` Theorem 1 (IND-CPA, `thm:ind-cpa`) and its proof |
| **Introduced** | Original theorem statement (informal, inline experiment sketch only) |
| **Owner** | TBD |
| **Status** | **Fixed** (proof-level correction, 2026-07-07) |
| **Risk retired** | — (new finding from external audit review) |

**Description.** The paper claimed the scheme "is IND-CPA secure" and
proved it via "the standard IND-CPA experiment", but no formal IND-CPA
definition (adversary, oracles, challenge, advantage) appeared anywhere —
the experiment was only sketched inline inside the proof. The sketch's
challenge constraint, "`A` submits a challenge pair `(m0,m1)` of equal
padded length", is non-standard (the textbook constraint is `|m0|=|m1|`,
equal plaintext length, with no padding precondition) and never states
which of three genuinely different quantities — codepoint count, on-wire
byte length, or the padded bucket `B` — "length" refers to. Because the
metric was undefined, the theorem was not well-defined, and the hiding
lemma's proof later invoked "equal padded lengths by the IND-CPA
requirement" as an unproved assumption to close a step that would
otherwise be circular.

**Fix (proof-level).** `docs/napseq-eprint-preprint.tex` now states a
formal `Definition~\ref{def:ind-cpa}` (adversary, encryption oracle,
challenge, advantage) immediately before Theorem 1, using the standard
constraint `|m0|=|m1|` measured in Unicode codepoints — the only metric
NAPQES's algorithm triple (`Definition~\ref{def:aead-triple}`) is typed
against — with no "equal padded length" precondition imposed on the
adversary. A new remark (`rem:equal-padded-derived`) then *derives* equal
padded length as a consequence of `|m0|=|m1|`, from the padding formula
`B = max(16, 2^ceil(log2(n+1)))` being a deterministic function of
codepoint count alone: this closes the circularity, since the fact the
proof needs is now proved from the definition rather than assumed
alongside it. Every subsequent occurrence of "equal padded length" in
Game `G0`'s challenge step and the hiding lemma's proof now cites this
derived fact instead of an unproved requirement. A further remark
(`rem:cvf9-byte-metric`) states the residual scope limitation explicitly:
the guarantee is with respect to `M`'s codepoint metric only, and does not
extend to external byte-string encodings of unequal codepoint count but
equal on-wire byte length — that scenario is cross-referenced to CAV-003
(padding length-bucket leakage), which was already open and is not
resolved by this fix.

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only — a new
audit-finding remark, a new formal `Definition~\ref{def:ind-cpa}`, two new
remarks deriving equal padded length and stating the codepoint/byte scope
limit, and small edits to Theorem 1's statement and proof (Game `G0`'s
challenge step, the hiding lemma's "equal byte-length of `B`" paragraph)
to cite the new definition and remarks instead of the old inline,
ambiguous phrasing. No change to `napqes.py`, `rust/src/lib.rs`, or
`C/napqes.c`, and no change to the theorem's bound or proof structure:
this finding is that the security *notion* and one proof step's
justification were underspecified, not that the underlying argument
(once the definition is fixed) fails to go through — `|m0|=|m1|` in
codepoints was already, in substance, what the original argument needed,
it was just never stated as the formal constraint and was instead
re-derived informally and circularly at the point of use.

**Not fixed (residual, tracked as a CVF9/CAV-003 cross-reference).** The
fix formalizes the definition and metric for NAPQES's own message space
(Unicode codepoint sequences) but does not address CAV-003 (padding
length-bucket leakage) itself: ciphertext length still reveals the padding
bucket, so two plaintexts that are equal-length only when measured in
some other metric (e.g. on-wire byte length of an external encoding) than
the codepoint metric NAPQES's IND-CPA definition uses are not covered by
Theorem 1. This is the same open, low-severity gap already tracked as
CAV-003, now explicitly cross-referenced from the theorem's proof.

**Requested action:** please confirm CVF9 can be marked **Fixed** as a
proof-level, definitional correction, with the pre-existing CAV-003
length-bucket gap remaining open and tracked separately.

---

## CVF13 — INTCTXT and INDCPA reductions cannot simulate the encryption oracle without the prime vector k

| Field | Value |
|---|---|
| **ID** | CVF13 |
| **Category** | Architecture |
| **Severity** | Theorem 1 (IND-CPA), Theorem 2 (INT-CTXT), and Theorem 3 (IND-CCA)'s reductions are not established for the real scheme as written — a simulation gap, not a false bound |
| **Affects** | `docs/napseq-eprint-preprint.tex` Lemma `lem:prf-hop` (B1), Theorem 2 (`thm:int-ctxt`, B2, Case 1), Theorem 3 (`thm:ind-cca`, composed) |
| **Introduced** | Original reduction sketches ("forward all HMAC calls to their own PRF oracle") |
| **Owner** | TBD |
| **Status** | Proof-level gap documented 2026-07-07; **fully closed for v8** (2026-07-07, decoupled `sk`/`k`, `rust/src/lib.rs`) — v7's reductions retain the documented simulation gap below |
| **Risk retired** | — (new finding from external audit review) |

**Description.** `B1` and `B2` are described as simulating NAPQES
encryption for the adversary by forwarding every HMAC call to their PRF
oracle. This is incomplete: `NAPQES.Enc` also uses the prime vector `k`
directly, outside of any HMAC call — token emission computes
`c * k_j + a`, and the addend range `[1, k_j - 1]` depends on the specific
prime `k_j`. A PRF oracle never reveals its hidden key, so the reduction
cannot extract `k` from oracle access and cannot run this arithmetic as
written. Sampling an independent `k'` locally does not repair this: in
the real-world branch there is no reason the oracle's true key equals
`key_bytes(k')` for that unrelated `k'`, so the simulation would compute
arithmetic under `k'` while tags/addends come from an oracle keyed by a
different, true `k` — an inconsistent hybrid, not the real scheme.
Conversely, supplying `k'` to the PRF challenger so the two match means
the reduction already knows the tested key, trivializing (and thus
invalidating) its "distinguishing advantage." Since the IND-CCA bound
composes `B1` and `B2`'s advantages (Bellare–Namprempre), it inherits the
same gap.

**Fix (proof-level).** `docs/napseq-eprint-preprint.tex` adds a new
remark (`rem:cvf13`) spelling out the gap and both failed repairs, with
cross-reference pointers at `B1`'s construction, `B2`'s construction, and
the IND-CCA composition proof. It specifies the concrete resolution:
reusing the KDF-subkey design already recorded as a residual under CVF8
(`rem:cvf8-kdf`) — deriving an independent, uniformly-distributed HMAC
subkey `sk = HKDF(kb)` and keying every domain derivation with `sk`
instead of `kb`, while `k` is used only for the public arithmetic layer.
Once `sk` is decoupled from `k`, the reduction may legitimately sample `k`
locally (no longer correlated with the tested key) while genuinely
forwarding domain-derivation calls to an oracle keyed by the PRF
challenger's independent, hidden `sk`, closing the gap under the standard
uniform-key HMAC-PRF assumption.

**Scope of the fix:** `docs/napseq-eprint-preprint.tex` only — one new
remark, an updated cross-reference in `rem:cvf8-kdf`, and short pointer
sentences at the three affected proof steps. No change to any theorem's
stated bound or game structure. No change to `napqes.py`,
`rust/src/lib.rs`, or `C/napqes.c`: the KDF-subkey change that would fully
close this gap is a wire-format and key-schedule change, out of scope for
a proof-only correction (same boundary as the CVF8 residual).

**Not fixed for v7 (residual, shared with the CVF8 residual above).**
Without the key-schedule change, v7's Theorems 1–3 reductions still lack
a valid, fully-specified simulation, for callers who have not migrated.

**Fully closed (2026-07-07) via the v8 key schedule.** `generate_v8_key`
now samples the arithmetic-layer prime tuple `k` and the HMAC subkey `sk`
**independently** — `sk` is fresh CSPRNG output, never a function of `k` or
`key_bytes(k)`. Under this decoupling, a reduction can sample its own
`k'` locally (identically distributed to `KeyGen`'s output, and never
required to equal the real `k`, since the CVF4 hiding lemma already shows
the masked blob is independent of the token structure's content) to run
the arithmetic layer, while genuinely forwarding every domain-derivation
call to an external PRF oracle keyed by the real, hidden `sk` — the
simulation the audit finding showed was impossible under v7's single-key
schedule. See `docs/napseq-eprint-preprint.tex`, "V8 Key Schedule and
Synthetic Nonce", for the restated reductions under the v8 schedule. The
Python and C reference implementations have not yet been ported to v8;
this is tracked as a follow-up.

**Requested action:** please confirm CVF13 can be marked **Fixed** for
the v8 key schedule, with v7 retaining the previously-disclosed residual
for callers who have not migrated.

---

## CAV-001 — Streaming API releases unverified plaintext (RUP)

| Field | Value |
|---|---|
| **ID** | CAV-001 |
| **Severity** | High (API misuse could propagate attacker-controlled data before auth fails) |
| **Affects** | `decrypt_stream` (napqes.py) |
| **Introduced** | v5 streaming API |
| **Owner** | TBD |
| **Status** | **Fixed — basic streaming format deprecated and forbidden for new ciphertext (CVF7)**; use `encrypt_stream_ae` / `decrypt_stream_ae` |
| **Risk retired** | R9 |

**Description.** `decrypt_stream` yields plaintext characters to the caller
before the HMAC-SHA256 authentication tag at the end of the stream has been
verified. An active attacker who can truncate or modify the stream causes
partial plaintext to be emitted before the `ValueError` is raised.

**Interim mitigation (still in place).** `decrypt_stream` requires
`enable_unauthenticated_streaming=True` (keyword-only, default `False`).
Calling without the flag raises `ValueError` with a message directing the
caller to `decrypt_stream_strict`. `decrypt_stream_strict` buffers all
decrypted characters and only returns after successful tag verification — no
plaintext escapes on auth failure.

**Phase 3 fix (implemented).** `encrypt_stream_ae` / `decrypt_stream_ae` in
`napqes.py` implement a v6s-ae wire format with per-chunk HMAC-SHA256 tags.
Each chunk (default 1024 bytes of masked_blob) carries its own
authentication tag computed as:

```
chunk_tag = HMAC(key_bytes,
    b'\x08' || uint32_be(len(aad)) || aad || nonce || uint32_be(chunk_idx) || masked_chunk)
```

`decrypt_stream_ae` verifies the chunk tag before yielding any plaintext from
that chunk — no unverified plaintext is ever released. A final sentinel tag
(domain `0x09`) authenticates the total chunk count, preventing silent
truncation at a chunk boundary. See SPEC.md §8.1 for the full wire format.

**Recommendation.** New code MUST use `encrypt_stream_ae` /
`decrypt_stream_ae`; as of the CVF7 fix (see
`docs/napseq-eprint-preprint.tex` §sec:format-applicability and
`SPEC.md` §8), the basic streaming format is **deprecated and forbidden**
for producing new ciphertext — `encrypt_stream` / `decrypt_stream` are
retained solely to decrypt streams produced before this fix. No protocol
may be designed to accept the basic streaming format for new traffic, and
no application should implement a "try v6s-ae, then fall back to
`decrypt_stream`" negotiation: the wire layout carries no version/format
discriminator byte, so such a fallback would recreate the exact
induced-unsafe-decode hazard this fix closes. Format selection (block vs.
streaming, v6s-ae vs. the deprecated basic format) is an out-of-band API
contract agreed by both endpoints, not something inferred from ciphertext
bytes.

---

## CAV-002 — 16-bit plaintext length cap (65535 codepoints)

| Field | Value |
|---|---|
| **ID** | CAV-002 |
| **Severity** | Low (hard error; no silent truncation) |
| **Affects** | `_pad_message` (napqes.py L174–195); `encrypt_bytes`, `encrypt_str` |
| **Owner** | TBD |
| **Target phase** | Deferred; requires a future wire-format bump (v8+) |
| **Risk retired** | R10 (partial) |

**Description.** The padding scheme stores the plaintext length as a
2-byte big-endian integer (`len_hi, len_lo`) at the head of the padded
block. This caps block-mode plaintext at `MAX_PLAINTEXT_CODEPOINTS = 0xFFFF`
(65535) codepoints. Exceeding the cap raises `ValueError` immediately —
there is no silent truncation. This is unrelated to and unaffected by the
v7/CVF1 token-encoding fix, which changed token serialisation width, not
the length-prefix width.

**Current mitigation.** Named constant `napqes.MAX_PLAINTEXT_CODEPOINTS`
exported at module level; error message references it and `docs/CAVEATS.md`.
Callers needing larger messages must split at the application layer.

**Future fix.** A future wire-format version could raise the length prefix
to 4 bytes (cap 2³²), shipped behind a feature flag only after ≥ 2
customers are blocked by the current cap.

---

## CAV-003 — Padding length-bucket leakage

| Field | Value |
|---|---|
| **ID** | CAV-003 |
| **Severity** | Low for v7 (deliberate design trade-off; documented in datasheets); **fixed for v8** (see V2-CVF2 below) |
| **Affects** | `_pad_message` (napqes.py L174–195); all block-mode callers |
| **Owner** | TBD |
| **Target phase** | Phase 5 step 5.4 (v7 fixed-frame option) — or never if no customer demand |
| **Risk retired** | R10 |

**Description.** `_pad_message` pads plaintext to the next power-of-two
block size (minimum 16). A passive observer seeing ciphertext length can
therefore infer which power-of-two bucket `{16, 32, 64, …, 65536}` the
plaintext length falls into, disclosing up to `⌈log₂(n)⌉` bits of length
information. This is a distinct, deliberate leak from **CVF1** (fixed): CVF1
was about ciphertext length leaking codepoint *values* even *within* the
same bucket; CAV-003 is about the bucket boundary itself, which is an
accepted design trade-off for v7.

**v8 escalation, since fixed (V2-CVF2, second-round audit, 2026-07-19).**
Under v8, the synthetic nonce is derived from the message itself
(`N = HMAC(sk, 0x0A‖be4(|A|)‖A‖M)`), so the noise-token count — and hence
ciphertext length — used to vary with message content, not just the
padding bucket, letting an observer who obtains several ciphertexts of one
fixed target message under varying associated data average out the noise
and recover the padding bucket *reliably* instead of merely
probabilistically. This is now fixed by padding the v8 token count up to a
fixed per-bucket ceiling (see "V2-CVF2" below).

**Current mitigation.** Leakage is disclosed in BRD.md §6 item 5,
module docstring (napqes.py L11–14), and SPEC.md §6. Customers requiring
full length-hiding must layer a fixed-frame transport (this residual
applies equally to v7 and the now-fixed v8: both still disclose the
padding bucket itself, exactly as documented here — only the *additional*
v8 oracle amplification is what V2-CVF2 closes).

**Future option.** A future wire format could include a documented
fixed-frame padding option that hides the padding bucket itself entirely.
Ship only if customers request it.

---

## V2-CVF2 — v8's message-derived nonce turns the padding-bucket leak into a reliable oracle under varied AAD

| Field | Value |
|---|---|
| **ID** | V2-CVF2 (second-round ABDK Consulting audit, 2026-07-19, "NAPQES v2 — AEAD Scheme Audit"; internal doc label `rem:v8-length-oracle`, `docs/napseq-eprint-v2.tex`) |
| **Category** | Flaw |
| **Severity** | Major |
| **Affects** | v8 synthetic nonce (`Definition~\ref{def:synthnonce}`); `Theorem~\ref{thm:ind-cpa-v8}`'s proof; CAV-003; v8 token-emission loop in `napqes.py`, `rust/src/lib.rs`, `C/napqes.c` |
| **Owner** | TBD |
| **Status** | **Fixed** (2026-07-21, code fix shipped in all three reference implementations) |
| **Risk retired** | — (new finding) |

**Description.** The v8 IND-CPA proof asserted that the traffic-analysis
lemma ("ciphertext length is decorrelated from plaintext content",
`Lemma~\ref{lem:tar}`) "applies verbatim ... only on it being fresh" once
`kb` is replaced by `sk`. This is incorrect: `Lemma~\ref{lem:tar}` requires
both compared plaintexts to be encrypted under *the same nonce* `N`, which
holds for v7 (the challenger samples `N*` independently of which message is
encrypted) but can never hold for two distinct messages under v8, since
`N = HMAC(sk, 0x0A‖be4(|A|)‖A‖M)` is itself a function of `M`. Because the
noise-token count is pseudorandom in the nonce, and the nonce differs per
message under v8, v8 ciphertext length depends on plaintext content beyond
the padding bucket. Concretely, an observer who can obtain several
ciphertexts of one fixed target message `M` under varying associated data
`A` (mild, since AAD is ordinarily unauthenticated routing metadata) gets
independent noise-count samples that all share the same real-token count;
averaging them recovers `M`'s padding bucket with confidence approaching
certainty, turning the single-shot CAV-003 leak into a reliable oracle for
an otherwise-passive observer. It does not recover the exact codepoint
count, only the power-of-two bucket.

**Fix (proof + code, 2026-07-21).** `docs/napseq-eprint-v2.tex`: the false
citation of `Lemma~\ref{lem:tar}` has been removed from
`Theorem~\ref{thm:ind-cpa-v8}`'s proof, which now states only that the
hiding argument (`Lemma~\ref{lem:hiding}`) carries over to v8 (it depends
only on the nonce being fresh, not on how it is generated). A new scope
remark (`rem:cvf2-v2-tar-scope`) explains why `Lemma~\ref{lem:tar}`'s
"same nonce" hypothesis fails for v8, and a new remark
(`rem:v8-length-oracle`) formalises the averaging attack described above
and documents the code fix below. The "Scope and residual" remark for the
v8 construction now records that CVF2 required a dedicated fix to the
token-emission schedule, distinct from CVF3/CVF8/CVF13's synthetic-nonce
fix.

**Code fix shipped, all three languages (2026-07-21).** The v8
token-emission loop now pads the emitted token count up to a fixed,
bucket-only ceiling of `real_token_count * (MAX_NOISE_RUN + 1)` tokens
(`MAX_NOISE_RUN = 19`, the same constant already used to bound worst-case
expansion), using additional filler tokens structurally identical to
genuine noise tokens:

- `napqes.py`: `_encrypt_v8_core` pads to the ceiling; `_decrypt_v8_core`
  now recovers the real-token count directly from the total token count
  (`n_tokens // (MAX_NOISE_RUN + 1)`) instead of consuming until the blob
  is exhausted, and stops once that many real tokens are extracted.
- `rust/src/lib.rs`: `encrypt_bytes_v8` gained the same
  `MAX_NOISE_RUN`-capped loop plus ceiling padding (Rust's v8 previously
  had no noise-run cap at all); a new `decrypt_core_v8` (separate from the
  shared, v7-only `decrypt_core`) mirrors the Python decoder logic.
- `C/napqes.c`: `encrypt_core_det_v8` and `decrypt_core_v8` updated
  identically (encode-side ceiling loop; decode-side upfront `real_count`
  derivation). Not compile-verified in this environment (no C toolchain
  available), mirrored carefully against the Python/Rust logic.

Because the ceiling depends only on the real-token count (hence only on
the padding bucket), every v8 ciphertext of a given bucket now has
*exactly* the same length regardless of key, AAD, or message content
within that bucket — verified by `tmp/test_v8_smoke.py` (200 trials, one
fixed message, distinct keys/AAD, single resulting length) and a new Rust
unit test (`v8_ciphertext_length_is_deterministic_across_varied_aad`, 50
trials). All existing tests continue to pass (245 Python `pytest` tests,
84 Rust `cargo test` tests).

**Trade-off.** v8 now always pays the worst-case `MAX_NOISE_RUN + 1 = 20x`
ciphertext expansion (previously the average case was `~13.4x`); v7 is
unaffected and keeps its original, uncapped-ceiling behaviour.

**Requested action:** confirm V2-CVF2 can be marked **Fixed**.

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
by design — noise tokens are a **traffic-analysis-resistance / ciphertext
length-decorrelation feature, not a content-confidentiality feature**, and
not compression. Per-message content confidentiality (IND-CPA) rests
entirely on the domain-`0x07` keystream and the domain-`0x03` HMAC tag; the
noise/prime-token layer's genuine, distinct contribution is that ciphertext
byte length is a function of `(key, nonce, padded length)` only — via the
noise-position oracle (`0x00`) and noise probability (`0x02`) — and does
not correlate with plaintext content. See `docs/audit_mitigation_responses.md`
(CVF4) for the full analysis; this line previously overstated the layer's
role as a confidentiality primitive, which the audit correctly flagged.
The v6 binary format is ~53% smaller than the legacy v3 hex encoding.

**No fix planned.** Expansion is a core property of the design. Document
the expansion bound explicitly in all datasheets.

---

## V2-CVF4 — Ciphertext-expansion range 4–20x was inconsistent with the 0.99 noise-probability ceiling

| Field | Value |
|---|---|
| **ID** | V2-CVF4 (second-round ABDK Consulting audit, 2026-07-19, "NAPQES v2 — AEAD Scheme Audit"; internal doc label `rem:v2cvf4`, `docs/napseq-eprint-v2.tex`) |
| **Category** | Algorithm |
| **Severity** | Moderate |
| **Affects** | `Table tab:comparison`'s ciphertext-expansion row; the "primary trade-off" paragraph; `CAV-004` above; v8 token-emission loop (already capped) |
| **Owner** | TBD |
| **Status** | **Fixed for v8** (2026-07-21, documentation only — the code fix already shipped as part of V2-CVF2); **open residual for legacy v7** (by design) |
| **Risk retired** | — (documentation correction; v8's underlying risk was already retired by the pre-existing `MAX_NOISE_RUN` cap) |

**Description.** An uncapped geometric noise run has expected length
`1/(1-p)`: `4×` at `p=0.75`, but `100×` — not `20×` — at the paper's own
stated ceiling `p=0.99`, with no upper bound on any single run. The
paper's "primary trade-off" paragraph claimed the `4–20×` range was
"mitigated ... by the noise-probability ceiling of 0.99," which has the
argument backwards: `p=0.99` is the worst case, not a mitigant.

**Resolution.** The v8 token-emission loop (`napqes.py`
`_encrypt_v8_core`; `rust/src/lib.rs` `encrypt_bytes_v8`; `C/napqes.c`
`encrypt_core_det_v8`) already caps consecutive noise tokens at
`MAX_NOISE_RUN=19` — the same cap shipped for `V2-CVF2` above — which
turns the probabilistic ceiling into a hard, deterministic worst case of
exactly `MAX_NOISE_RUN+1 = 20×` per real codepoint, regardless of `p`.
This makes v8's documented `4–20×` figure accurate. What was missing was
the write-up: the paper's prose, the `CAV-004` entry, and this file did
not previously explain the cap or correct the backwards "mitigated by
0.99" framing. `docs/napseq-eprint-v2.tex` has been updated (new
`rem:v2cvf4` remark, rewritten trade-off paragraph, corrected `CAV-004`
item) to state this accurately.

**Residual (legacy v7, not fixed, by design).** `MAX_NOISE_RUN` is
deliberately **not** applied to the legacy v7 construction, so that
previously-issued v7 ciphertexts remain decodable exactly as originally
produced. v7's ciphertext expansion therefore remains bounded only in
expectation (`≈13.4×` mean at typical `p`), with an uncapped tail as
`p→0.99`. This is an accepted trade-off since v7 is retained for backward
compatibility only and is no longer the recommended construction.

**Requested action:** confirm V2-CVF4 can be marked **Fixed for v8, v7
residual accepted**.

---

## V2-CVF11 — Streaming format retains the codepoint-length leak (CAV-003/first-round CVF1), undocumented

| Field | Value |
|---|---|
| **ID** | V2-CVF11 (second-round ABDK Consulting audit, 2026-07-19, "NAPQES v2 — AEAD Scheme Audit"; internal doc label `rem:v2cvf11`, `docs/napseq-eprint-v2.tex`) |
| **Category** | Documentation |
| **Severity** | Minor |
| **Affects** | Online-AE streaming format (`Section~\ref{sec:streaming-ae}`, `encrypt_stream_ae`/`decrypt_stream_ae`); basic streaming format |
| **Owner** | TBD |
| **Status** | **Fixed (documentation)**; **residual retained by design** |
| **Risk retired** | — (clarifies an existing, accepted trade-off; no new exposure) |

**Description.** Both streaming formats mask a `varint(·)` (LEB128) blob,
not the fixed-width `be8` encoding that the first-round `CVF1` fix
introduced for block mode (`Section~\ref{sec:wire-format-v7}`).
Consequently a token's serialised byte-length in streaming mode still
grows with the plaintext codepoint value — precisely the channel `CVF1`
closed for block mode. This was never a newly introduced defect: a
streaming ciphertext already discloses the exact plaintext length by
construction (each chunk's `be4(ℓ_i)` length prefix is sent in the
clear), so the additional, finer-grained per-token length variation adds
no confidentiality cost beyond what streaming mode already concedes. The
paper simply never stated this scoping explicitly, risking a reader
wrongly assuming the block-mode `CVF1` fix applies universally across
every wire format.

**Fix (documentation only, 2026-07-21).** `docs/napseq-eprint-v2.tex`,
Section~\ref{sec:streaming-ae}: added `Remark~\ref{rem:v2cvf11}` stating
explicitly that the streaming format deliberately retains the codepoint
length leak and why that is acceptable.

**Residual (accepted, by design).** Streaming-mode ciphertexts leak
codepoint-level length information beyond the chunk-length prefix already
disclosed in the clear. This is a deliberate trade-off tied to streaming
mode's threat model (which already concedes exact plaintext length via
`be4(ℓ_i)`), not a defect, and is the same class of residual as
`CAV-003` above, scoped specifically to streaming ciphertexts (block-mode
v7 ciphertexts do not have this residual, per the `CVF1` fix).

**Requested action:** confirm V2-CVF11 can be marked **Fixed
(documentation), with the by-design residual accepted**.

---

## V2-CVF12 / V2-CVF13 — Legacy v7 retained with conditional security proofs; decision recorded against removing it

| Field | Value |
|---|---|
| **ID** | V2-CVF12 and V2-CVF13 (second-round ABDK Consulting audit, 2026-07-19, "NAPQES v2 — AEAD Scheme Audit"; internal doc label `rem:v2cvf12-13`, `docs/napseq-eprint-v2.tex`) |
| **Category** | Procedural (CVF12) / Architecture (CVF13) |
| **Severity** | Minor |
| **Affects** | `Theorem~\ref{thm:ind-cpa}`, `Theorem~\ref{thm:int-ctxt}`, `Theorem~\ref{thm:ind-cca}` (legacy v7); `Section~\ref{sec:algorithm-triple}` |
| **Owner** | TBD |
| **Status** | **Fixed (CVF12, hardened wording)**; **Acknowledged, v7 retained by decision (CVF13)** |
| **Risk retired** | — (same underlying residual as the first-round `CVF8`/`CVF13` entries below; this documents its second-round reaffirmation) |

**Description.** CVF12: the legacy v7 theorems were stated as ordinary,
unconditional theorems even though this paper's own remarks concede two
open v7-specific gaps — the simulation-gap caveat (first-round `CVF13`:
the reduction cannot simulate `NAPQES.Enc` from oracle access alone, since
the arithmetic layer uses `k` directly, outside any HMAC call) and the
non-standard key-distribution caveat (first-round `CVF8`: the PRF
advantage invoked is against a non-uniform, low-min-entropy prime-tuple
distribution, not the standard uniform-key assumption). Only
`Theorem~\ref{thm:ind-cpa}` previously surfaced this inline. CVF13: given
v7 is superseded by v8 as the recommended default, the audit recommends
removing the legacy v7 construction and its proofs from the paper
entirely, rather than carrying two parallel, non-interoperable schemes
with different (v7: conditional, v8: unconditional) guarantees side by
side.

**Fix (CVF12, documentation, 2026-07-21).** `docs/napseq-eprint-v2.tex`:
added `Remark~\ref{rem:v2cvf12-13}` (immediately before the "IND-CPA
Security" subsection) stating plainly that every v7 theorem in
`Section~\ref{sec:security}` is conditional on the two gaps above, and
that only v8 (`Theorem~\ref{thm:ind-cpa-v8}`, `Corollary~\ref{cor:v8-security}`)
carries unconditional guarantees; `Theorem~\ref{thm:int-ctxt}` and
`Theorem~\ref{thm:ind-cca}`'s own preambles now state the same
conditional caveat directly, matching `Theorem~\ref{thm:ind-cpa}`.

**Decision (CVF13, acknowledged, not actioned).** We considered removing
the legacy v7 construction entirely and decided to retain it, unmodified,
for backward compatibility with existing v7 ciphertexts and deployments.
v7 is already explicitly retitled as legacy-only and no longer the
recommended default (`Section~\ref{sec:algorithm-triple}`); removing a
wire format that deployed systems may depend on is a breaking change out
of proportion to a documentation/architecture finding. CVF12's hardened
conditional-theorem wording is the mitigation shipped in response to this
finding, in place of removal.

**Residual (accepted, by decision).** The legacy v7 construction, and its
conditional security proofs (tracked since the first-round audit as
`CVF8` and `CVF13` below), remain part of the normative document. Closing
the underlying gaps for real would require the KDF-subkey wire-format
change already noted as a residual against those first-round entries —
still deferred, not part of this fix.

**Requested action:** confirm V2-CVF12 can be marked **Fixed**, and
V2-CVF13 can be marked **Acknowledged, with the decision to retain v7
recorded**.
