# NAPQES v4 — Round 5: Client Comments for report v1.0

Client responses to the 31 findings of Chapter 6 ("Round 5: Review of Fixes
at Commit f6ced5d") of ABDK's report draft v0.2. Each entry gives the commit
that addresses the finding and a one-paragraph summary, intended to be
pasted into the finding's **Client Comment** box.

**These are client statements; they have not been reviewed by ABDK.**

**Commit identifiers.** Before these fixes, the repository history was
rewritten to remove a committed key tuple (CVF-V5-15). The audited commit
`f6ced5d` is therefore `acbf9d0` in the published history; its tree is
identical to `f6ced5d` except that `meta.json` is absent. All hashes below
are on top of `acbf9d0`. Each commit message is prefixed `fix(CVF-V5-n)`.

Status legend: **Fixed** — the recommendation is implemented; **Partly
fixed** — the core is implemented, the stated remainder is accepted;
**Mitigated** — the risk is removed from the audited surface without the
full recommendation.

| Finding | Status | Commit(s) |
|---|---|---|
| CVF-V5-1 | Fixed | `7a17584` |
| CVF-V5-2 | Mitigated (demoted) | `7199472` |
| CVF-V5-3 | Fixed | `c14e0a0` |
| CVF-V5-4 | Fixed | `23025ed`, `b619dab` |
| CVF-V5-5 | Fixed | `b98bf23` |
| CVF-V5-6 | Partly fixed | `da7e005` |
| CVF-V5-7 | Fixed | `b619dab`, `23025ed` |
| CVF-V5-8 | Partly fixed | `eca82e6` |
| CVF-V5-9 | Fixed | `7a17584` |
| CVF-V5-10 | Fixed (documentation option) | `1716bcd` |
| CVF-V5-11 | Fixed | `476f226` |
| CVF-V5-12 | Fixed | `4eea6fb` |
| CVF-V5-13 | Fixed | `69ed83c` |
| CVF-V5-14 | Fixed | `2b6db30` |
| CVF-V5-15 | Fixed | history rewrite + `e775bd2` |
| CVF-V5-16 | Fixed | `e872c6e` |
| CVF-V5-17 | Fixed | `2086e00` |
| CVF-V5-18 | Fixed | `e8cb86f` |
| CVF-V5-19 | Fixed | `e9489a9` |
| CVF-V5-20 | Fixed | `9c0c93b` |
| CVF-V5-21 | Fixed | `b54ae56` |
| CVF-V5-22 | Fixed | `54c8544` (with `e872c6e`, `2086e00`) |
| CVF-V5-23 | Fixed | `4c96bd8` |
| CVF-V5-24 | Fixed | `24c26bf` |
| CVF-V5-25 | Mitigated | `6fdbec3` (with `23025ed`) |
| CVF-V5-26 | Fixed | `471501e`, `da5da58` |
| CVF-V5-27 | Fixed | `e3ea69d`, `9a2cbec`, `fecb8dd` |
| CVF-V5-28 | Fixed | `db499d4` |
| CVF-V5-29 | Fixed | `b87e98c` |
| CVF-V5-30 | Fixed | `75de8cf` |
| CVF-V5-31 | Fixed | `25310e5` |

---

## Client Comments

**CVF-V5-1 — Fixed in `7a17584`.** The sentinel no longer carries the
codepoint count in clear: it carries `be8(n) XOR HMAC(sk_fmt, 0x0F ||
HEADER || be4(C))[:8]` (new domain `0x0F`), and the sentinel tag still binds
the clear `n`. Only the chunk count `ceil(n/F)` remains visible, which
SPEC.md §8.2 and the README now state. The crate documentation no longer
claims Corollary 4.14 for streaming. The regression test now compares the
sentinel count fields of two equal-chunk-count streams under one nonce.
Python, C and Rust changed together; the stream KAT corpus was regenerated
and all three ports reproduce it.

**CVF-V5-2 — Mitigated in `7199472`.** We took the second option: the
streaming format is no longer normative or recommended. In Rust it compiles
only with the off-by-default `experimental-stream` feature, and it is
labelled everywhere as outside the audited claims, with no security model
or proof. SPEC.md §8.2 was rewritten to determine every byte: 0-based chunk
index, filler index and formula, per-chunk counter reset, `1 <= F <=
16384`, `C <= 2^32-1`, the valid range of `n`, the full decoder check list,
the masked count and header binding. Domains `0x0C`–`0x0F` are in the
paper's domain table. The abstract and §3.3 no longer claim a proved
block/stream separation. CAV-001 is restated per port (Python's generator
releases chunks before the sentinel), CAV-005 counts chunks (`<= 2^48` per
`sk`), the contradictory comments are fixed, and the README states that
streams begin with `0x02`. No proof is offered; that is why the format is
demoted.

**CVF-V5-3 — Fixed in `c14e0a0`.** We keep `P = [10^6, 1.5e7)` and
`K = 13`, and now disclose and version the change. The paper marks the
interval as new in revision 4.1 (parameter set `P2`, versus `P1 = [10^6,
9.9e6]`) and gives the real motive: alignment with the reference KEM
component, which the paper does not specify. The wrong `sec:keygen`
reference is removed. Remark `rem:pq128` is rewritten: K = 14 over `P1`
already gives 134.02 bits; 14,257,301 suffices at K = 13; the post-quantum
figure for `k` matters only for v7. New KAT vectors pin the interval: `W023`
(K = 13 with elements 9,900,047, 12,000,017 and 14,999,981) and `W-E02`
(15,000,017 rejected). The corpus carries a `prime_interval` marker. The
same false claims were corrected in `lib.rs`, `napqes.py`, `napqes.h`,
CAVEATS and the mitigation responses; all figures were re-derived by sieve.

**CVF-V5-4 — Fixed in `23025ed` (gateway migration in `b619dab`).** The
gateway now uses v8 (CVF-V5-7). The four v7 encryptors are compiled only
with the off-by-default `legacy-v7` feature, and the decryptors remain for
archived data. `emit_tokens_v7` returns `Err` after 4,096 consecutive noise
positions (probability below `2^-59` per real token at `p <= 0.99`), so the
loop is bounded. The remediation report's statement about
`encrypt_bytes_with_nonce` is corrected: it was never deprecated and was
already `pub(crate)`.

**CVF-V5-5 — Fixed in `b98bf23`.** INT-2 is a real software-integrity
test: HMAC-SHA256, under a fixed public key, over the executable that
contains the module, compared in constant time with `<executable>.hmac`.
The new `napqes_integrity` tool writes that file after linking; a binary
cannot embed its own digest at compile time, so the `build.rs` description
in the Security Policy and Module Boundary documents is corrected. With the
`fips_integrity` feature a missing reference value also fails. Verified end
to end (unsigned fails, signed passes, a one-byte change fails) and run in
CI. KAT-8 adds primitive known answers:
- FrodoKEM-640-AES decapsulation of a (sk, ct) pair generated by liboqs, an
  independent implementation, cross-checked in the Python tests;
- the RFC 7748 X25519 vector;
- the hybrid combiner on fixed inputs.

The vacuous `integrity_check_passes` test is replaced.

**CVF-V5-6 — Partly fixed in `da7e005`.** Removed:
- the `vale` feature;
- the undeliverable `vale_demo` binary;
- the unconditional `pqcrypto-sphincsplus` dependency (no SPHINCS+ native
  code is built into consumers any more).

Also: `rust-version = "1.88"` is declared and checked in CI, the redundant
`[profile.test]` block and its stale comment are removed, and
`autobins = false` is set. **Not done:** `kem`, `kem_exchange`, `ot_frame`
and `protocols` are still compiled unconditionally; we accept this
remainder.

**CVF-V5-7 — Fixed in `b619dab` (encryptors withdrawn in `23025ed`).**
`ot_frame` now seals every frame with v8 (`encrypt_bytes_v8_key`) under a
validated `NapqesKey`, and PDUs are carried as Latin-1 codepoints. The KEM
derives the v8 `sk` with its own HKDF label (`derive_v8_sk`, matching
Python), so the prime tuple and `sk` are independent outputs of the shared
secret. Pre-shared key stores hold `{primes, sk_hex}`, and keys are
validated once, at load. No in-tree component encrypts with v7; the
paper's §8.2 says so.

**CVF-V5-8 — Partly fixed in `eca82e6`.** Under `fips_gate`, all eight v7
entry points and key generation now require POST, and FAILED is sticky
until the process restarts. The new test-only `fault_injection` feature
(which refuses release builds) drives `rust/tests/fips_gate.rs`. That test
asserts that every gated entry point refuses before POST and after an
injected failure, and that a re-run does not clear FAILED; it runs in CI.
The Cargo.toml comment and the README list exactly what is and is not
gated, and the remediation report's non-existent test names are corrected.
**Not done:** `fips_gate` remains opt-in rather than default-on.

**CVF-V5-9 — Fixed in `7a17584`.** Every chunk tag, the sentinel tag and
the count mask bind the full 21-byte header `0x02 || be4(F) || nonce`, so
`F` of an empty stream is no longer malleable. The new negative vector
`S-N04` rewrites F from 8 to 9 on an empty stream, and there is a Rust unit
test; all three ports reject it.

**CVF-V5-10 — Fixed (documentation option) in `1716bcd`.** The rustdoc and
README state that Rust streaming is incremental on the encrypt side only:
`decrypt_stream_ae_v8` needs the whole stream (about 160 B per codepoint)
and releases nothing before the sentinel verifies. They contrast this with
the Python generator's release semantics (CAV-001), and say that the
all-at-once encryptor uses a random nonce, pointing in-memory messages of up
to 65,535 codepoints to the misuse-resistant block API. No incremental
decryptor and no synthetic stream nonce are added; streaming itself is
experimental (CVF-V5-2).

**CVF-V5-11 — Fixed in `476f226`.**
- `validate_key` uses an in-place pairwise distinctness scan, so no sorted
  copy is made.
- `StreamV8Encryptor` keeps `sk_fmt` in a boxed `Secret32`, and `cp_buf` is
  wiped over its full capacity after every chunk and on Drop.
- `NapqesKey::new` wipes rejected inputs.
- The key-generation scratch index and partial tuples are wiped
  (`75de8cf`).

The remediation report's statement about `Secret32` coverage is superseded
by this commit.

**CVF-V5-12 — Fixed in `4eea6fb`.** `decrypt_bytes`, `decrypt_raw` and
`decrypt_str` share `open_v7`, which runs in this order: AAD-length and
parse checks, the tag, one key validation, then `decrypt_core`. A forged
envelope therefore costs one HMAC and never reaches key validation.
CVF-V5-16 further replaces trial division on this path with a relaxed
check. Paper §8.4 states the order. The gateway's pre-validated path is
`NapqesKey` on v8 (CVF-V5-7), so we add no separate v7 key type.

**CVF-V5-13 — Fixed in `69ed83c`.** The `noise_x10` feature and its `cfg`
branches are removed; `MAX_NOISE_RUN` is a fixed protocol constant.

**CVF-V5-14 — Fixed in `2b6db30`.** `generate_prime_numbers` (and therefore
`generate_v8_key` and `NapqesKey::generate`) returns `Err` for `count == 0`
or `count > MAX_KEY_ELEMENTS` before drawing anything. A test covers 0, 129
and the 128 boundary.

**CVF-V5-15 — Fixed: history rewrite + `e775bd2`.** `meta.json` was
removed from every commit with `git filter-repo`; `f6ced5d` maps to
`acbf9d0`, which differs only by that file. The original history is
archived offline. The tuple is declared compromised in CAVEATS, and any
deployment that used it must rekey. `.gitignore` rules and a gitleaks CI
job, with a NAPQES prime-tuple rule and an `sk` hex rule, prevent a
recurrence.

**CVF-V5-16 — Fixed in `e872c6e`.** The v7 decryptors use a relaxed key
policy: 1–128 distinct elements, each in `[2, 2^40-1]`, with no primality
or interval check. Archived keys from any earlier interval still open, and
no trial division runs on the v7 decrypt path. The exact compatibility
envelope (which keys and plaintexts are rejected) is documented on
`decrypt_bytes`, in the crate header and in the README; the remediation
report's "every v7 ciphertext decrypts" claim is corrected. A test opens a
v7 ciphertext under a key with an element below 10^6, a composite element
and an element above 1.5e7.

**CVF-V5-17 — Fixed in `2086e00`.** `encrypt` now returns `Result` and
rejects surrogates, values above `0x10FFFF`, over-length messages, invalid
keys and CRNG failures. Its rustdoc states the accepted input domain, and a
test checks the rejections and the round trip.

**CVF-V5-18 — Fixed in `e8cb86f`.** With streaming compiled in, POST runs
three new tests on vector S002:
- KAT-9: stream encryption, checked by SHA-256 and length;
- KAT-10: decryption;
- KAT-11: rejection of the stream with its frame removed.

The constants are pinned to S002 by `kat_constants_match_corpus`, and the
README's POST description lists exactly what is tested.

**CVF-V5-19 — Fixed in `e9489a9`.** A CRNG continuous-test failure sets
POST to FAILED under `POST_LOCK`; the state is sticky (CVF-V5-8).
`rust/tests/fips_crng.rs` proves the latch with fault injection, and the
README documents it.

**CVF-V5-20 — Fixed in `9c0c93b`.**
- The CVF-43 test calls `unpad_message` directly on `(0,300)`, `(1,256)`
  and `(0x100,0)` and requires the "byte-valued" rejection, so it fails on
  v4.
- The CVF-42 constant test is renamed; its real evidence is KAT parity.
- The CVF-20 test is renamed with a note that the bias fix is verified by
  inspection.
- The NapqesKey parity test now compares against corpus vector W009.

The remediation report's §7 claim is corrected.

**CVF-V5-21 — Fixed in `b54ae56`.** N009 is no longer skipped, and it gains
`expected_error_contains: "too short"`. Every harness test in
`kat_cross_check.rs` asserts an exact exercised count, and the remaining
skip paths are hard failures. Rust, Python and C pass the regenerated
corpus.

**CVF-V5-22 — Fixed in `54c8544`.** The `ct_eq_bytes` call-site list, the
`varint_keystream` justification (LEB128 removed) and the Cargo.toml
profile comment are corrected. The crate header's "first statement / no
panic path" claim was replaced in `e872c6e`. The `encrypt` comment went
with the `Result` signature in `2086e00`.

**CVF-V5-23 — Fixed in `4c96bd8`.** The paper states "Specification
revision 4.2 — October 2026" and has a revision history that names the
normative changes of 4.0, 4.1 (`f6ced5d`: the interval and K, the Dec step 7
guards) and 4.2. It is renamed `docs/napseq-eprint-v4.tex` (the PDF is
rebuilt), and every pointer outside the historical review documents is
updated. `self_test.rs` now cites `lem:domsep` of the current paper.

**CVF-V5-24 — Fixed in `24c26bf`.**
- The security preamble, the correctness proof (which now also discharges
  the step 7 and step 8 rejection branches) and Lemma nonce-collision (for
  a uniform `sk_fmt`) are stated in terms of `sk_fmt`; Dec gains step (0).
- Remark key-roles gives the per-token probability (about `1/k'`, between
  `2^-23.8` and `2^-19.9`) instead of "negligible".
- "CV-11" is corrected to CVF-11, and the restatement claim is corrected.
- `theta_min` and `theta_max` are given as exact integers, with a warning
  about the IEEE-754 value, which differs by 163.
- The CVF-30 footnote points to existing documentation.
- §9 says 14 tests.

**CVF-V5-25 — Mitigated in `6fdbec3` (with `23025ed`).** `encrypt_raw` (and
every v7 encryptor) is withdrawn behind `legacy-v7`. All four v7 rustdocs
state that the tag does not bind the convention, that cross-convention
decryption succeeds silently for values up to U+00FF (with the two concrete
examples), and that `decrypt_raw` is only for `encrypt_raw` output. A test
pins this behaviour. The convention is not bound into the v7 tag, because
that would break the archived format.

**CVF-V5-26 — Fixed in `471501e` (code) and `da5da58` (recorded run).**
- `unauth_decode` builds structurally valid `c*k+a` token streams and
  mutates them.
- A new `stream_decode` target re-tags every chunk and the sentinel.
- `decode_bytes` covers all three padding profiles and nonce mutation.
- Seed corpora are committed, and CI builds the fuzz crate.

`docs/FUZZ_ATTESTATION.md` records a 600 s ASan run of each of the four
targets at `471501e`: 5,946 to 378,097 executions per target and no
crashes. It also states the limits of that evidence. The paper no longer
claims the Python harness covers v8.

**CVF-V5-27 — Fixed in `e3ea69d`, `9a2cbec` (harness) and `fecb8dd`
(recorded run).** A comparator-only bench times `ct_eq_bytes` on operands
that differ in the first versus the last byte, with a pinned key: |t| =
0.785 over 7.6M samples. A positive control (an early-exit comparator)
reaches |t| = 4,610, which shows the test has the power to detect the leak.
The whole-call bench gives |t| = 1.96 over 13.0M samples, and the paper now
calls it low-power. All runs are on the delivered commits, and CI gates the
comparator bench at |t| < 4.5.

**CVF-V5-28 — Fixed in `db499d4`.** Dec step (7) binds `k` and the reduced
addend before the guards, and names `c` before the scalar check. Remark
`rem:dec-structural` now says totality comes from each step's guards (the
false "steps (6) and (8) make step (7) total" is withdrawn), and its vector
map adds W-N12. The "indifferent to which subset" sentence is deleted, and
§8.4 lists the step (7) checks.

**CVF-V5-29 — Fixed in `b87e98c`.** `encrypt_stream_ae_v8_key`,
`decrypt_stream_ae_v8_key` and `StreamV8Encryptor::new_key` take a
`NapqesKey`. The bare-slice v8 functions are `#[deprecated]`, and their
rustdoc states that they validate on every call by trial division, with
timing that depends on the secret primes.

**CVF-V5-30 — Fixed in `75de8cf`.** `is_prime` first trial-divides by the
odd primes below 59 and computes the square-root bound once; it is checked
against a sieve. Key generation tracks membership by binary search in a
sorted, wiped index, and its count is capped (CVF-V5-14).

**CVF-V5-31 — Fixed in `25310e5`.** `emit_tokens_v8` is the single v8
emission loop for block mode and every stream chunk, and `seal_v7` is the
single v7 sealing pipeline. In both emitters, the statements common to the
noise and real branches are hoisted. Behaviour is unchanged: all three KAT
corpora re-encrypt byte for byte.

---

## Verification at the final commit

- Rust:
  - `cargo test` with default features, with
    `fips_gate,fault_injection,legacy-v7,experimental-stream`, and in
    `--release`: all pass;
  - release build of all targets with every feature: no warnings;
  - `cargo +1.88 check --all-targets` (MSRV): passes;
  - `cargo check --bins` in `rust/fuzz`: passes.
- C (MSVC `/W4 /fp:strict`): the KAT harness passes all three corpora with
  0 failures.
- Python:
  - `gen_kats.py`, `gen_kats_v8.py` and `gen_kats_v8_stream.py --check`
    pass;
  - `pytest tests`: 377 passed and 1 skipped. One pre-existing intermittent
    failure, `TestDecryptStream::test_tampered_body_raises_auth_error` on
    the deprecated v6 basic stream, fails about half the time on the
    audited commit as well and is not related to these changes.
- Paper: `docs/napseq-eprint-v4.tex` builds with no errors or undefined
  references.
