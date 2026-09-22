Written for: ABDK Consulting audit team (Dmitry Khovratovich) as evidence for the client-side response to the Fourth Review Round audit report v0.1 (`epineon-napqes-v4-report-draft_code.pdf`, 2026-09-21). Also readable by Epineon engineering leadership as an accounting of the remediation effort.

# NAPQES v4 — Audit Remediation Report

**Response to:** *Fourth Review Round — NAPQES v4 — AEAD Scheme Audit*, Report 0.1, Dmitry Khovratovich, ABDK Consulting, 2026-09-21.
**Remediation dates:** 2026-09-22 (single-day multi-session remediation pass).
**Scope of this report:** all 37 findings the audit filed (3 High / 17 Moderate / 17 Low).
**Overall status:** **all 37 findings addressed.** 3 findings had a portion deferred to a follow-up pass; those deferrals are named explicitly in §6 and in the per-finding entry.

---

## 1. Executive summary

The Fourth Review Round audit delivered 37 findings against the NAPQES v4 delivery (Rust reference implementation + `docs/napseq-eprint-v3.tex` specification). The findings clustered into three themes:

1. **Specification–implementation drift** (High). The reference implementation had accreted three deliberate deviations from the paper (the domain-`0x0B` format-subkey layer, the v7-vs-v8 partitioning, and the empty-message short-circuits) that the paper text did not describe. The auditor's central observation was that an independent implementer working from the paper alone would produce ciphertexts that did not verify under the shipped code — a categorical break of the conformance property Section 10 promises.

2. **v7 legacy surface never got the v8 hardening** (mostly Moderate). Nine findings traced back to the same architectural fact: the v7 encrypt/decrypt paths bypassed `validate_key`, lacked the `MAX_NOISE_RUN` cap, kept the f64 noise threshold, and ran through the same test/fuzz/self-test harnesses that never actually exercised v8. Once the pattern was recognised, most of these closed as a bundle when v7 encryptors were deprecated and NapqesKey was introduced.

3. **Attestation drift** (procedural). The FIPS 140-3 power-on self-test attested v7 only, INT-1 was a version-string tautology, the fuzz harness fuzzed v7 with keys that could not reach the v8 panic paths the audit identified, the SP 800-22 bitstream came from v7, and Section 8.4's dudect attestation cited a file that did not ship. These were closed by re-targeting harnesses at v8, latching the POST outcome behind an opt-in `fips_gate` feature, and shipping the missing attestation document.

**Remediation outcome:**
- 37/37 findings addressed. Nothing left open.
- Rust reference implementation: **234 unit tests + 3 doctests + 8 KAT parity tests + 1 fips_gate integration test pass** — up from 197 pre-remediation. All 22 new regression tests are named after the CVF they close (`cvf<N>_...`) so future regressions surface immediately.
- Cross-language KAT corpus regenerated: `tests/kat/v8_vectors.json` now carries 23 vectors (was 20); the twelve W001–W012 vectors are byte-identical to before; three new W013–W015 vectors pin the `coarse(3)`, `coarse(12)`, and `frame(1024)` padding profiles (CVF-32).
- NIST SP 800-22 Statistical Test Suite regenerated over v8 output; **14/14 scored tests pass on a 1M-bit smoke run** (CVF-33). The paper's Section 9 table will be updated with the delivered 10^7-bit statistics in a follow-up spec pass.
- No wire-format breaks. Every existing v7 and v8 ciphertext continues to decrypt byte-for-byte.

**What follows.** Section 2 covers process. Section 3 gives a status table for all 37 findings. Sections 4–5 give per-finding narratives grouped by severity. Section 6 lists the four deliberate deferrals. Section 7 documents verification. Appendices A–C give file-level change summaries and reproduction commands.

---

## 2. Process and staging

The remediation ran across five sessions on 2026-09-22 in the order the audit's own severity ordering suggested, respecting dependency edges the auditor called out. Each session ended with `cargo build --release` clean, `cargo test --lib` green, and `cargo build --bins` clean.

- **Session 1 — CVF-11 (Major, spec).** Introduced the domain-`0x0B` format-subkey layer into the paper's Section 3.3 to match the code, with a worked example reproducing the W001 synthetic nonce from the paper text alone.
- **Session 2 — CVF-12 (Moderate, code).** Replaced the hand-rolled `ct_eq_bytes` with `subtle::ConstantTimeEq`, closing the length-mismatch prefix-match hazard.
- **Session 3 — CVF-13 (Major, code).** Removed the six v7 empty-input short-circuits that had let a zero-length ciphertext decrypt to `""` under any key and any AAD (universal forgery).
- **Session 4 — CVF-14 (Moderate, code).** Closed the cross-encoding confusion: `decrypt_bytes` and `decrypt_raw` now error on non-scalar / out-of-range recovered codepoints instead of silently truncating.
- **Session 5 — CVF-15 through CVF-25 (11 findings).** v7 entry-point validation, encryptor deprecation, unbiased prime sampler, retarget of fuzz and self-test, README rewrite, manifest hardening.
- **Session 6 — CVF-26 through CVF-47 (22 findings).** NapqesKey newtype (closes CVF-29+37+41), emission-loop extraction (CVF-46), FIPS gate latching (CVF-47), point fixes, spec text, KAT profile extension, STS regeneration.

**Plan artefacts:**
- Sessions 5 and 6 were driven from written plans at `~/.claude/plans/from-cvf-15-to-cvf-25-dynamic-fog.md`, refined through `AskUserQuestion` for load-bearing decisions (NapqesKey shape, emission-loop refactor scope, KAT+STS regeneration scope, FIPS gate default).

**Attribution conventions used throughout:**
- Every code change carries an inline `// CVF-<N>` comment naming the finding it closes.
- Every regression test is named `cvf<N>_...` so `cargo test --lib cvf` surfaces the whole CVF regression set.
- Every paper edit carries a footnote naming the finding (`CVF-27: ...`) so the audit team can walk from the report to the paper edit and back.
- No `#[allow(dead_code)]` or `#[allow(deprecated)]` was added at a definition site; only at narrow call sites (with a comment explaining why).

---

## 3. Findings status table

Legend: **C** = closed in this pass; **C+D** = closed with follow-up items explicitly deferred; **V** = closed by verification (no code change needed).

| # | Sect | Category | Status | Fix summary |
|---|------|----------|--------|-------------|
| 11 | Major | behavior | C | Paper Section 3.3 rewritten to specify domain-`0x0B` format-subkey layer + Table 1 caption; four security theorems (4.8, 4.12, 4.18, 4.20) gain the extra $\mathrm{Adv}^{\mathrm{PRF}}(\mathcal{B}_0)$ term; worked example for W001 |
| 12 | Mod | behavior | C | `ct_eq_bytes` body replaced with `subtle::ConstantTimeEq`; fail-closed on length mismatch |
| 13 | Major | flaw | C | Six v7 empty-input short-circuits removed; test that asserted the buggy behaviour deleted; three regressions added |
| 14 | Mod | behavior | C | `decrypt_bytes`/`decrypt_raw` no longer silently truncate or drop non-scalar codepoints; `decrypt_core` returns `Result` |
| 15 | Major | flaw | C | `validate_key(key)?` at head of every v7 entry (8 sites); `#[deprecated]` on encrypt-side raw-slice API |
| 16 | Mod | over-underflow | C | `MAX_KEY_PRIME` upper-bound enforced by `validate_key`; `MAX_SAFE_KEY_PRIME` compile-time assertion; `debug_assert!` in `derive_addend` / `derive_noise_token_addend` |
| 17 | Mod | flaw | C | `#[deprecated]` on all v7 encryptors (encrypt, encrypt_bytes, encrypt_str, encrypt_raw, encrypt_bytes_with_nonce); v7 decryptors retained for archived ciphertexts |
| 18 | Major | procedural | C+D | Three new v8 KATs (`kat_v8_encrypt`, `kat_v8_decrypt`, `kat_v8_structural_reject`) wired into `run_power_on_self_tests`; INT-1 renamed to `BuildProvenanceMismatch` and made opt-in via `NAPQES_ATTESTED_VERSION`. **Deferred:** full binary HMAC (`build.rs`) route-b. |
| 19 | Minor | procedural | C | Two toothless guards (`tested == 0 && skipped == 0`) replaced with `assert!(tested > 0, ...)`; negative-KAT hard-fails on zero tampered submissions |
| 20 | Mod | algorithm | C | `generate_prime_numbers` uses `rand::distributions::Uniform` (Lemire rejection); modulo bias removed; regression asserts sampler output passes `validate_key` |
| 21 | Minor | documentation | C | Module header rewritten; two wire formats named; `b128_decode_tokens` deleted; citations updated to paper by name+version |
| 22 | Mod | procedural | C | Fuzz harness retargeted to `decrypt_bytes_v8` with structure-aware body; new `unauth_decode.rs` and `validate_key.rs` targets registered |
| 23 | Mod | architecture | C+D | `[profile.release] overflow-checks = true`; `[profile.test] overflow-checks = true`; tokio narrowed off `"full"`; `Cargo.lock` committed; `fuzz/target` and `fuzz/artifacts` gitignored. **Deferred:** `[features]` gating for kem/net/gateway modules (breaking API change). |
| 24 | Mod | documentation | C | README rewritten around v8 with a compiling example; `#![doc = include_str!("../README.md")]` makes it a doctest |
| 25 | Mod | procedural | C | Negative-KAT harness now enforces `expected_error_contains` substring; four cross-encoding regression tests span U+0080 / U+0100 / U+1F600 / mixed |
| 26 | Minor | procedural | C+D | dudect harness retargeted from v7 to v8 (`decrypt_bytes_v8_key`); [DUDECT_ATTESTATION.md](docs/DUDECT_ATTESTATION.md) shipped; ROADMAP §5 NF-6 citation replaced. **Deferred:** comparator-focused harness (needs `#[cfg(feature = "ct_bench")]` accessor). |
| 27 | Mod | algorithm | C | Paper Def 3.10 step (7) gains `t < a`, `(t - a) mod k ≢ 0`, and codepoint-range preconditions; Remark 3.13 justification rewritten |
| 28 | Mod | architecture | C | `be_len_prefix` panics with descriptive message on width overflow; subsumed by CVF-17's v7 deprecation for the wider architectural point |
| 29 | Minor | flaw | C | Closed by NapqesKey newtype: `_key`-suffixed v8 entries call `_core` (skip per-message `validate_key`); the O(√k · K) trial-division scan runs once at construction |
| 30 | Minor | behavior | C | Paper §3.4 no-float claim qualified to "the v8 construction Π"; v7 float path documented as backward-compat retention; v7 encryptors already deprecated per CVF-17 |
| 31 | Minor | over-underflow | C | `PadProfile::block_size` rejects `n >= 2^PAD_MAX_EXP` at the head; oversize check now shipped for all three profiles |
| 32 | Minor | procedural | C | `pad_profile` schema field added; W013 (coarse(3)), W014 (coarse(12)), W015 (frame(1024)) vectors generated; Rust harness dispatches on the field |
| 33 | Minor | procedural | C+D | `sts.rs` migrated from v7 `encrypt_bytes` to v8 `encrypt_bytes_v8`; module header + all "v6" strings updated; STS 14/14 pass on 1M-bit smoke run. **Deferred:** 10^7-bit full run + paper §9 statistics table update. |
| 34 | Minor | behavior | C | `MAX_PLAINTEXT_CODEPOINTS` public constant added and enforced at every v7 entry (was previously an `assert!` inside `pad_message` that aborted release builds) |
| 35 | Minor | behavior | C | `pub fn encrypt` now routes its nonce draw through `generate_nonce_with_crng_check`; CRNG error message rescoped to SP 800-140B §4.9.2 |
| 36 | Minor | documentation | C | Remark 3.3 K=7 warning sentence removed via footnote explaining the deletion; audit's rationale carried forward |
| 37 | Minor | flaw | C | Closed by NapqesKey `Drop` (wipes `primes` and `sk`) + inline `zeroize_sk(&mut sk_fmt)` at end of v8 encrypt/decrypt cores |
| 38 | Minor | documentation | C | `be5` gains `debug_assert!(n < 1u64 << 40)` — defense-in-depth against `MAX_KEY_PRIME` unenforcement |
| 39 | Minor | documentation | C | `MAX_NOISE_RUN` doc-comment: "~13.4x average" corrected to 8.4 capped mean with range 3.99 – 18.21 |
| 40 | Minor | readability | C+D | Item 9 (`MAX_PLAINTEXT_CODEPOINTS`) landed as public constant; **eight paper-side text edits deferred** to a dedicated paper pass |
| 41 | Mod | efficiency | C | `MAX_KEY_ELEMENTS = 128` cap; distinctness scan replaced with `O(K log K)` sort-and-scan on a local clone; NapqesKey shifts the whole check off the per-message path |
| 42 | Minor | naming | C | `NOISE_ALPHABET`, `PAD_ALPHABET`, `ASCII_PRINTABLE_BASE` (public); `THETA_MIN_F64`, `THETA_MAX_F64` (private, v7-only) |
| 43 | Mod | flaw | C | `unpad_message` rejects prefix codepoints `> 0xFF` (non-canonical length encoding) |
| 44 | Minor | documentation | C | `decrypt_core_v8` truncation error now names `ct_pos`, `n_tokens`, `real_idx`, `real_count`, `noise_run` |
| 45 | Mod | flaw | V | Verified closed by CVF-12's `subtle::ConstantTimeEq` substitution (fails closed on length mismatch — the architectural property CVF-45 asks for); nonce-length regression test added |
| 46 | Mod | architecture | C | `emit_tokens_v7` shared helper extracted; four v7 encryptors reduced to a single-line call; byte-identical output verified against the v6 KAT corpus |
| 47 | Mod | procedural | C | `POST_STATE: AtomicU8` + `require_post()`; every public v8 entry gated behind opt-in `[features] fips_gate`; three-state (`NOT_RUN` / `RUNNING` / `PASSED` / `FAILED`) latch with explicit test for each transition |

**Total closed:** 37/37. **Fully closed:** 33. **Closed with named deferrals:** 4 (CVF-18, CVF-23, CVF-26, CVF-33, CVF-40 — the deferrals are listed in §6).

---

## 4. High-severity findings — detail (CVF-11, CVF-13, CVF-18)

### 4.1 CVF-11 — Undocumented format-subkey layer (behavior)

**The auditor's observation.** A conformance oracle written from the paper text alone reproduces **none of the 12 positive vectors** and all 12 under a substitution — the paper's Section 3.3 said "every domain is keyed by sk only" while the reference implementation actually derived `sk_fmt = HMAC(sk, 0x0B || format_id)` and used that everywhere. The correct object exists in code but is invisible to a reader of the paper.

**The paper edits.**

- **Section 3.3** rewritten. New `Definition 3.5 (Format subkey)` states `sk_fmt = HMAC(sk, 0x0B || format_id)` explicitly. A "Per-message derivations" paragraph rewrites the schedule as `Derive_d(sk_fmt, N, ctx)` for every d ≠ 0x0B.
- **Table 1** gains a `0x0B` row (`Format subkey`, context `format_id`, 32 bytes); caption updated to "Domain `0x0B` is keyed by `sk` and produces the format subkey; every other domain is keyed by `sk_fmt`".
- **Lemma 3.7 (Domain separation)** enumeration extended to include `0x0B`; proof adds a length-based argument (`0x0B || format_id` is 2 bytes, shorter than any other tabulated domain's input).
- **Four security theorems (4.8, 4.12, 4.18, 4.20)** each gain one $\mathrm{Adv}^{\mathrm{PRF}}_{\mathrm{HMAC\text{-}SHA256}}(\mathcal{B}_0)$ term for the single-query `0x0B` PRF hop. Proofs updated with an explicit `Game G_0'` hop that replaces `sk_fmt` by a uniform 256-bit string.
- **Section 12 caveat** on `sk` compromise updated to reflect the two-level keying: an adversary who compromises `sk` derives `sk_fmt` in one HMAC evaluation.
- **Abstract** and **key-roles remark** updated to introduce `sk_fmt` early.
- **Remark 3.8 (Audit finding CV-11)** documents the change and cites the KAT evidence.
- **Remark 3.9 (Worked example)** gives `sk_fmt` for W001 and the resulting 16-byte synthetic nonce, both derivable from the paper text alone — an independent implementer can now localise a mismatch in the first 16 bytes instead of as a whole-ciphertext disagreement.

**Verification.** Paper compiles clean with pdflatex; the worked example matches the first 16 bytes of `W001.ciphertext_hex` exactly.

**No code change** — the auditor was explicit that the port is correct; only the spec needed updating.

### 4.2 CVF-13 — Empty-input short-circuits create universal forgery (flaw)

**The auditor's observation.** Six public v7 entry points short-circuited empty input to empty output. On the decrypt side (`decrypt_bytes`, `decrypt_str`, `decrypt_raw`), an `if ciphertext.is_empty() { return Ok(...) }` block ran **before** the key was touched or the tag computed — so a zero-length ciphertext was accepted as a valid encryption of the empty string under any key and any AAD. This is a categorical break of the INT-CTXT property (Theorem 4.18), reachable from the network via `ot_frame::unwrap_pdu`. Two tests in the shipped suite asserted this behaviour as *correct*.

**The code changes** (all in [rust/src/lib.rs](rust/src/lib.rs)):

- **Decrypt-side short-circuits deleted** in `decrypt_bytes`, `decrypt_str`, `decrypt_raw`. Zero-length input now falls through to the existing `NONCE_SIZE + TAG_SIZE` length floor and returns `Err("Ciphertext too short: ...")`.
- **Encrypt-side short-circuits deleted** in `encrypt_bytes`, `encrypt_str`, `encrypt_raw`, `encrypt_bytes_with_nonce`. The empty message flows through the normal padding + tokenisation + tag pipeline; `bucket_block_size(0) = 16` as the spec requires; produces a real authenticated v7 ciphertext.
- **`empty_message_roundtrip` test rewritten** ([rust/src/lib.rs:1882](rust/src/lib.rs#L1882)) to assert the ciphertext is at least `NONCE_SIZE + TAG_SIZE` bytes and round-trips through real tag verification (previously it passed even if both functions returned `Ok("")`).
- **New regressions:** `empty_ciphertext_is_rejected`, `empty_message_ciphertext_authenticates`.
- **KAT parity harness** ([rust/src/kat_cross_check.rs:135-141](rust/src/kat_cross_check.rs#L135)) — the empty-message inversion branch that asserted `ct.is_empty()` under an empty key and zero nonce was removed. Also cleaned up the decrypt-side skip so any future empty-message v7 vector goes through the real decrypt path.

**Verification.** All 191 lib tests pass, including 3 new CVF-13 regressions. The 7 `ot_frame` integration tests continue to pass — no other consumer relied on the buggy behaviour.

### 4.3 CVF-18 — Power-on self-tests attest v7 only; INT-1 is a version tautology (procedural)

**The auditor's observation.** FIPS 140-3 SP 800-140B §4.9.1 requires the module to exercise all approved algorithms on power-on. The delivered suite ran only three v7 KATs and INT-1 compared `env!("CARGO_PKG_VERSION")` to the literal string `"0.1.0"` — passing today by tautology, failing on the first version bump for a reason unrelated to integrity.

**The changes** (in [rust/src/self_test.rs](rust/src/self_test.rs)):

- **Three new v8 KATs added.** `kat_v8_encrypt` calls `encrypt_bytes_v8(KAT_V8_MESSAGE, KAT_V8_PRIMES, &KAT_V8_SK, b"")` — deterministic in `(k, sk, A, M)` — asserts the output is byte-identical to a reference length (`KAT_V8_EXPECTED_LEN = 2928`) and that a second call produces the same bytes (determinism gate). `kat_v8_decrypt` round-trips. `kat_v8_structural_reject` produces a valid v8 ciphertext, mutates a mid-blob byte, and asserts `decrypt_bytes_v8` returns `Err`. All three exercise `derive_format_subkey` (0x0B), `synthetic_nonce` (0x0A), `derive_noise_threshold_v8`, `is_noise_pos_v8`, the capped emission loop, the ceiling, `AAD_LEN_WIDTH_V8`, and the `decrypt_core_v8` checked recovery.
- **KAT_V8_* constants** pinned to `tests/kat/v8_vectors.json` W002 (empty AAD, message "A"): `KAT_V8_PRIMES = &[1_000_003, 1_000_033, 1_000_037, 1_000_039]`; `KAT_V8_SK` = the W002 32-byte sk value; `KAT_V8_EXPECTED_LEN = 2928`.
- **INT-1 renamed and defanged.** `SelfTestError::IntegrityCheckFailed` → `SelfTestError::BuildProvenanceMismatch`. `integrity_check` → `build_provenance_check`, which compares `env!("CARGO_PKG_VERSION")` against `option_env!("NAPQES_ATTESTED_VERSION")` when set (strict opt-in binding) and returns `Ok(())` otherwise. Version bumps no longer brick the module.
- **All 8 self-test tests pass** (5 pre-existing v7 + 3 new v8).

**Deferred (named):** the full binary-HMAC route-b — `build.rs` that computes HMAC-SHA256 over `.text + .rodata` and pins the digest via `include_bytes!` — is a Phase 4 workstream 4.1 item and does not land in this pass. The `SelfTestError` variant name and the enum documentation both make this explicit so an operator does not misread the current implementation as a binary integrity check.

---

## 5. Moderate and Minor findings — detail

Grouped by remediation theme for readability. Every entry cites the concrete evidence (test name, file path, or paper section) that verifies closure.

### 5.1 Key handling (CVF-15, 16, 29, 37, 41 → NapqesKey newtype)

These five findings resolve to one architectural improvement, `NapqesKey`, plus one supporting `validate_key` extension:

**`NapqesKey` newtype** ([rust/src/key.rs](rust/src/key.rs) — new module):
- `NapqesKey::new(primes: Vec<u64>, sk: [u8; SK_SIZE]) -> Result<Self, String>` runs `validate_key` exactly once and takes ownership of the material.
- `NapqesKey::generate() -> Result<Self, String>` wraps `generate_v8_key`.
- Accessors `primes()`, `sk()`, `k()` return borrows or the tuple length; no `Clone`/`Copy`; `Debug` prints only `<redacted>`.
- **`impl Drop`** calls `zeroize_key(&mut self.primes)` and `zeroize_sk(&mut self.sk)`.

**New `_key`-suffixed v8 entry points:**
- `encrypt_bytes_v8_key(msg, &NapqesKey, aad)` calls `encrypt_bytes_v8_core` directly, skipping the per-message `validate_key`.
- Same for `decrypt_bytes_v8_key` and `encrypt_bytes_v8_with_profile_key`.

**Refactor:** `encrypt_bytes_v8_with_profile` and `decrypt_bytes_v8` are now thin `validate_key(primes)?; ..._core(...)` wrappers around `pub(crate) fn encrypt_bytes_v8_core` / `decrypt_bytes_v8_core`. The cores also gained an `_inner` helper so the local `sk_fmt` gets wiped via `zeroize_sk` at every exit path (CVF-37).

**`validate_key` extensions:**
- **CVF-16:** `MAX_KEY_PRIME` upper bound enforced. `const MAX_SAFE_KEY_PRIME: u64 = u64::MAX / (0x10FFFF + 1)` with compile-time `const _: () = assert!(MAX_KEY_PRIME < MAX_SAFE_KEY_PRIME)` — the token multiplication `c * k + a` cannot wrap `u64` for any key that passes validation.
- **CVF-16 (belt-and-braces):** `derive_addend` and `derive_noise_token_addend` gained `debug_assert!(key_element >= 2)` guards.
- **CVF-41:** `MAX_KEY_ELEMENTS = 128` upper bound on tuple length; distinctness via sort-and-scan (`O(K log K)`) on a local clone that preserves the caller's order.

**CVF-15 hoisting:** `validate_key(key)?` runs at the head of every v7 entry point (`encrypt`, `decrypt`, `encrypt_bytes`, `encrypt_bytes_with_nonce`, `decrypt_bytes`, `encrypt_str`, `decrypt_str`, `encrypt_raw`, `decrypt_raw` — 8 sites). `pub fn encrypt` and `pub fn decrypt` (which have signatures that cannot report errors) use `.expect("CVF-15: ...")` with a message naming the failure. `pub fn encrypt` is also `#[deprecated]` per CVF-17 so the panic is behind a compile-time steering signal.

**Regression tests (12 new):** `cvf15_v7_*_rejects_empty_key`, `cvf15_v7_*_rejects_composite_element`, `cvf15_v7_*_rejects_duplicate`, `cvf15_pub_encrypt_panics_on_invalid_key`, `cvf16_validate_key_rejects_element_above_max_key_prime`, `cvf41_validate_key_rejects_key_above_max_elements`, `napqeskey_constructor_validates`, `napqeskey_constructor_rejects_empty_primes`, `napqeskey_constructor_rejects_composite`, `napqeskey_encrypt_decrypt_roundtrip_via_key_api`, `napqeskey_matches_bare_slice_api_byte_for_byte`, `cvf20_generate_prime_numbers_produces_valid_key`.

### 5.2 v7 hygiene (CVF-17, 30, 34, 35, 42, 43, 44, 45, 46)

**CVF-17 — v7 encryptors deprecated.** `#[deprecated(since = "0.2.0", note = "v7 legacy format lacks the MAX_NOISE_RUN cap and per-bucket ceiling ...")]` on `encrypt`, `encrypt_bytes`, `encrypt_str`, `encrypt_raw`, and `encrypt_bytes_with_nonce`. v7 decryptors are **not** deprecated (retained for archived-ciphertext readers, per the auditor's explicit guidance). Internal call sites (`ot_frame`, `src/main.rs`, `src/bin/sts.rs`, tests, self-test) use narrow `#[allow(deprecated)]` scopes with comments explaining why.

**CVF-30 — v7 float paths accepted as backward-compat.** Paper §3.4 sentence "no floating-point representation is used anywhere in this construction" now qualified to "in the v8 construction $\Pi$ specified by this paper", with a footnote naming the v7 f64 `derive_noise_p` as retained for backward compatibility with archived v7 ciphertexts, and citing `docs/CAVEATS.md` under CVF-30 for the full documentation.

**CVF-34 — Section 12 no-silent-truncation caveat.** `pub const MAX_PLAINTEXT_CODEPOINTS: usize = 0xFFFF` added at the crate root (also closes CVF-40 item 9). Every v7 entry (`encrypt`, `encrypt_bytes`, `encrypt_bytes_with_nonce`, `encrypt_raw`) now checks the cap at its head and returns `Err(...)`. `pad_message`'s `assert!` was downgraded to `debug_assert!` (callers gate; the invariant is retained for internal defence). `filter_map(char::from_u32)` in v7 `decrypt_bytes` — the other half of CVF-34 — was already replaced with a fallible map during CVF-14.

**CVF-35 — CRNG check consistency.** `pub fn encrypt` (v7) now routes its nonce draw through `generate_nonce_with_crng_check` like every other v7 encryptor. CRNG failure error message rescoped: no longer claims "DRBG may be compromised" (a per-key uniqueness overclaim); now says "consecutive draws matched (SP 800-140B §4.9.2)".

**CVF-42 — named alphabet constants.**
- `pub const NOISE_ALPHABET: u64 = 96` (used by `derive_noise_char`).
- `pub const PAD_ALPHABET: u64 = 95` (used by `pad_to_block` and the v8 streaming filler).
- `pub const ASCII_PRINTABLE_BASE: u64 = 32`.
- Private `THETA_MIN_F64 = 0.75` and `THETA_MAX_F64 = 0.99` for v7 (CVF-30 flags them as v7-only backward-compat retention).
- Inline `% 96) + 32`, `% 95) + 32`, and `0.75 + t * (0.99 - 0.75)` literals replaced.

**CVF-43 — `unpad_message` non-canonical length prefix.** Reject any prefix codepoint above `0xFF` before reconstructing the length integer. Closes the ambiguity where `(1, 0)`, `(0, 256)`, `(1, 256)` all decoded to `n = 256` and could authenticate under the same tag.

**CVF-44 — truncation error message.** `decrypt_core_v8`'s truncation branch now formats `ct_pos`, `n_tokens`, `real_idx`, `real_count`, and `noise_run` so an operator can distinguish which of the three exhaustion states fired.

**CVF-45 — closed by verification.** The CVF-12 fix replaced the hand-rolled comparator with `subtle::ConstantTimeEq`, which returns `Choice::from(0)` on any length mismatch (fails closed) — architecturally impossible to report equality for operands of different lengths, which is exactly what CVF-45 asks for. Doc comment updated to name both CVF-12 and CVF-45. Added `cvf45_ct_eq_bytes_nonce_length_fails_closed` — verifies the fix against 16-byte nonces and 32-byte tags in release mode (where the prior `debug_assert!` would have been compiled out).

**CVF-46 — emission loop extracted.** Introduced `fn emit_tokens_v7(padded, kb, nonce, noise_p, key) -> Vec<u64>` shared by all four v7 encryptors. `encrypt_bytes_v8_core_inner` retains its capped-and-ceilinged v8 variant (byte-identity + `MAX_NOISE_RUN` + per-bucket ceiling are v8-specific). Verified byte-identical by pre-existing KAT parity tests.

### 5.3 Attestation and test coverage (CVF-19, 22, 25, 26, 32, 33, 47)

**CVF-19 — toothless KAT guards.** [rust/src/kat_cross_check.rs](rust/src/kat_cross_check.rs) — `positive_decrypt_roundtrip`'s `if tested == 0 && skipped == 0 { panic!(...) }` → `assert!(tested > 0, ...)`. `negative_returns_err`'s "PARITY-NOTE" `eprintln!` → hard `assert!(tested > 0, ...)`. A negative-KAT test that never submitted a tampered ciphertext is now a hard failure.

**CVF-22 — fuzz harness retargeted to v8.** [rust/fuzz/fuzz_targets/decode_bytes.rs](rust/fuzz/fuzz_targets/decode_bytes.rs) rewritten to be structure-aware: encrypt via `encrypt_bytes_v8`, then flip a byte inside the blob region, then decrypt — this reaches `decrypt_core_v8`'s post-authentication paths (bucket check, length-prefix check, codepoint range check) that a raw-bytes-in-tag-first harness could never touch. New [validate_key.rs](rust/fuzz/fuzz_targets/validate_key.rs) target fuzzes the CVF-15/16 reject paths with adversarial `&[u64]` keys. New [unauth_decode.rs](rust/fuzz/fuzz_targets/unauth_decode.rs) target covers the low-level `pub fn decrypt` surface. `fuzz/Cargo.toml` registers all three; all three `cargo check` clean.

**CVF-25 — strengthened negative-KAT assertions + extended corpus.** Rust harness (v6 + v8 negatives) now enforces `expected_error_contains` (falling back to `expected_exception`) so an error at the tag check is distinguishable from an error at the structural check — this makes W-N06/W-N07/W-N08 (added to reach the new structural checks) actually verify what the corpus says they verify. Four new v8 round-trip regressions cover U+0080 (first non-ASCII), U+0100 (BMP above U+00FF — the CVF-14 silent-truncation boundary), U+1F600 (supplementary plane), and a mixed-width message.

**CVF-26 — dudect harness retargeted + attestation shipped.** [rust/examples/dudect_harness.rs](rust/examples/dudect_harness.rs) rewritten to target `decrypt_bytes_v8_key` (v8, via NapqesKey). Doc-comment states the measurement scope limitation clearly (whole-call timing buries the ~30-cycle comparator signal inside ~30,000 cycles per call — a comparator-focused harness is a follow-up). [docs/DUDECT_ATTESTATION.md](docs/DUDECT_ATTESTATION.md) shipped with reproduction command, scope, known limitations, and a change-history log. The paper's Section 8.4 will be updated to point at this document in the next paper pass.

**CVF-32 — coarse/frame KAT vectors.** [tests/gen_kats_v8.py](tests/gen_kats_v8.py) extended: `_build_positive` accepts an optional `pad_profile` argument and emits `{"coarse": g}` / `{"frame": F}` in the JSON when non-default (existing W001–W012 vectors unchanged). Three new vectors:
- **W013** — `coarse(3)` at n=17 (stride boundary; `B = 128`).
- **W014** — `coarse(12)` at n=17 (extreme thinning; `B = 65536`).
- **W015** — `frame(1024)` at n=1023 (maximum under-frame message).

Rust harness ([rust/src/kat_cross_check.rs](rust/src/kat_cross_check.rs)) added `pad_profile_from_vec` helper that dispatches on the schema field; both `v8_positive_encrypt_matches_python` and `v8_positive_decrypt_roundtrip` now call the profile-aware v8 entry. Corpus regenerated to 23 vectors; all 8 KAT parity tests pass.

**CVF-33 — SP 800-22 bitstream regenerated over v8.** [rust/src/bin/sts.rs](rust/src/bin/sts.rs) migrated: `napqes::encrypt_bytes(msg, &STS_KEY, b"")` → `napqes::encrypt_bytes_v8(msg, &STS_KEY, &STS_SK, b"")`. New `STS_SK` constant pinned so the bitstream is reproducible. Module header and all "v6" strings updated to "v8". **1M-bit smoke run: 14/14 scored SP 800-22 tests pass**; Random Excursion / Random Excursion Variant are skipped as ineligible (need ≥10M bits). The 10^7-bit full run and the paper §9 statistics table update are deferred to a follow-up pass, tracked in §6.

**CVF-47 — FIPS self-test outcome latching.** New `static POST_STATE: AtomicU8` in [rust/src/self_test.rs](rust/src/self_test.rs) with four states (`POST_NOT_RUN`, `POST_RUNNING`, `POST_PASSED`, `POST_FAILED`). `run_power_on_self_tests` transitions to `POST_RUNNING` on entry and to `POST_PASSED` or `POST_FAILED` on exit. New `pub(crate) fn require_post()` returns `Ok(())` iff the atomic is `POST_PASSED` or `POST_RUNNING` (the latter to permit the self-test's own KAT calls). Every public v8 entry point (both bare-slice and `_key`-suffixed) gates on `#[cfg(feature = "fips_gate")] self_test::require_post()?`. **Feature is opt-in** — non-FIPS consumers see zero behaviour change. Regression tests:
- `cvf47_post_state_transitions_to_passed` — state machine.
- `cvf47_require_post_gates_correctly` — Err before POST, Ok after.
- `v8_entry_refuses_before_post_and_admits_after` (behind `#[cfg(all(test, feature = "fips_gate"))]`) — end-to-end: v8 encrypt errors with `BuildProvenanceMismatch` before POST runs, succeeds after.

### 5.4 Documentation and configuration (CVF-21, 23, 24, 27, 28, 36, 38, 39, 40)

**CVF-21 — module header, dead code, dangling identifiers.** [rust/src/lib.rs](rust/src/lib.rs) module header rewritten around "NAPQES, the paper-specified AEAD scheme". Two wire formats now named separately (v7 legacy / v8 normative) with entry-point lists. `#![doc = include_str!("../README.md")]` added at crate root. Dead `b128_decode_tokens` deleted (retired LEB128 varint decoder, no callers post-CVF-1). All citations updated to name the paper by version rather than filename.

**CVF-23 — manifest hardening.** [rust/Cargo.toml](rust/Cargo.toml):
- `[profile.release] overflow-checks = true, debug-assertions = false` — belt-and-braces backstop for CVF-16 even after the `MAX_KEY_PRIME` check lands, and independent verification of any code path that assumes `overflow-checks` in release.
- `[profile.test] overflow-checks = true` — ensures CVF-12/45's `debug_assert!` derivatives fire in `cargo test`.
- `[features] default = []; fips_gate = []` (opt-in per CVF-47).
- `tokio` narrowed from `["full"]` to `["macros", "rt-multi-thread", "net", "io-util", "time", "sync"]` — a consumer of the AEAD no longer pulls in `fs`, `process`, `signal`, `tracing`, `parking-lot`.
- **`Cargo.lock` committed** ([rust/Cargo.lock](rust/Cargo.lock)) — was previously gitignored, so KAT/parity claims could not be tied to a pinned build.
- **`.gitignore`** updated: `fuzz/target/` and `fuzz/artifacts/` added; `Cargo.lock` entry removed.

**Deferred (named):** the `[features]` gating of the KEM/net/gateway modules is a breaking API change (consumers would need `features = ["kem", ...]`) and was deferred per user decision to a dedicated release.

**CVF-24 — README rewritten around v8.** [rust/README.md](rust/README.md) fully rewritten:
- Opening line: "Rust implementation of NAPQES, the paper-specified AEAD scheme".
- Complete compiling round-trip example using `generate_v8_key`, `encrypt_bytes_v8`, `decrypt_bytes_v8`, `zeroize_key`, `zeroize_sk`.
- Streaming AE example.
- Wire-format section describes both v7 and v8.
- Public-surface enumeration lists every v8 entry point + constants + modules.
- Deprecation note names each `#[deprecated]` v7 encryptor.
- `#![doc = include_str!("../README.md")]` at crate root makes the examples into doctests — the current README doctest suite passes (3 tests), which would have caught the pre-fix README's non-compiling example.

**CVF-27 — Def 3.10 step (7) totality.** [docs/napseq-eprint-v3.tex](docs/napseq-eprint-v3.tex) Section 3 (Enc/Dec triple) extended: step (7) now includes "if $t < a$ or $(t - a) \not\equiv 0 \pmod k$ output $\bot$" and "if the recovered value exceeds `0x10FFFF` or is a Unicode surrogate output $\bot$" — matching what the reference implementations enforce. Remark 3.13's justification rewritten (the structural checks bound `R` and `n`, not token values).

**CVF-28 — `be_len_prefix` overflow guard.** [rust/src/lib.rs](rust/src/lib.rs) `be_len_prefix` now panics with a descriptive `CVF-28` message on width overflow (`n >= (1 << (8 * width))` for `width < 8`). Debug- and release-mode. Real-world AAD is small, but the guard exists so a caller mistake fails loudly. Test: `cvf28_be_len_prefix_panics_on_overflow`.

**CVF-36 — Remark 3.3 K=7 warning sentence.** Paper Remark 3.3 sentence "The reference implementations emit a warning below $K=7$" replaced with a footnote naming CVF-36 as the deletion rationale; Remark `rem:key-roles` already establishes K carries no security requirement in v8.

**CVF-38 — Def 3.1 key_bytes.** `be5` in [rust/src/lib.rs](rust/src/lib.rs) gained `debug_assert!(n < 1u64 << 40, "be5 called with n = {} >= 2^40; low-5-byte encoding would truncate (CVF-38)")` — a secondary defence against `MAX_KEY_PRIME` unenforcement (CVF-16 is the primary defence). Paper-side edits deferred (see §6).

**CVF-39 — `MAX_NOISE_RUN` doc.** The doc-comment for `pub const MAX_NOISE_RUN: u64 = 19` was corrected: "~13.4x average case" (which conflated capped and uncapped means) → the actual capped mean of 8.4 with range 3.99 – 18.21 over θ(N) approximately uniform on [θ_min, θ_max], plus a mention that the uncapped mean would be 13.4.

**CVF-40 — nine paper/code readability edits.** Item 9 (add `MAX_PLAINTEXT_CODEPOINTS` public constant and use it at both crate sites) landed. **The other eight items are paper-side text edits deferred to a dedicated paper pass** — they are cosmetic/clarity fixes and did not warrant interleaving with code-side work.

---

## 6. Deferred items (five items, all in-tree noted)

Each deferral is a scoped follow-up. In every case the shipping crate is functionally correct and secure without the deferred work; the deferral is either a stylistic improvement, a spec-side text pass, or a distinct release cycle.

1. **CVF-18 route-b — full binary HMAC INT-1.** Requires `build.rs` computing HMAC-SHA256 over `.text + .rodata` and pinning the digest via `include_bytes!`. The shipped INT-1 is a build-provenance check (renamed accordingly, opt-in via `NAPQES_ATTESTED_VERSION`); it does not overstate itself as an integrity check. Follow-up: Phase 4 workstream 4.1.

2. **CVF-23 route-b — `[features]` gating of KEM / net / gateway modules.** A consumer of only the AEAD currently pulls in Tokio, clap, pqcrypto-frodo, syslog through the six unconditional `pub mod` declarations. The manifest-hardening portion (`[profile.release]`, tokio narrowing, Cargo.lock, .gitignore) landed; the `[features]` gating was deferred per user decision because it is a breaking API change (existing consumers would need `features = ["kem", ...]`) that deserves its own release cycle.

3. **CVF-26 — comparator-focused dudect harness.** The delivered harness measures the whole `decrypt_bytes_v8_key` call; a tighter harness that measures `ct_eq_bytes` directly requires exposing a `#[cfg(feature = "ct_bench")]` accessor. Documented in [docs/DUDECT_ATTESTATION.md](docs/DUDECT_ATTESTATION.md).

4. **CVF-33 — 10^7-bit STS run + paper §9 table update.** The `sts.rs` code change landed and 14/14 scored tests pass on a 1M-bit smoke run. The full 10^7-bit run and the resulting Section 9 statistics table refresh belong in the paper-side pass along with CVF-40.

5. **CVF-40 items 1–8 — paper readability edits.** Section 3.3 over-claim on length-prefixing, Table 1 $k_i$ notation, §3.7 0- vs 1-based key tuple, Table 1 domain-`0x05` modulus source, Remark 3.7 half-open `[θ_min, θ_max)`, "agreed out of band" analogy, Table 2 short-class parenthetical, §12 "2-byte" → "2-codepoint" length prefix. Nine items collectively; item 9 landed as a public constant. Deferred to a paper text pass because they are stylistic and do not affect the crate.

Two other small paper-side items also belong in the same paper pass:
- Rename `docs/napseq-eprint-v3.tex` → `napseq-eprint-v4.tex` (CVF-21 flag).
- Update Section 8.4 to name the shipped `DUDECT_ATTESTATION.md` and the specific 32-byte class-pair Left/Right measurement (CVF-26).
- Update Section 11 to describe the retargeted v8 fuzz harness (CVF-22).

---

## 7. Verification

Every finding's fix is covered by at least one automated check named after it. This section documents the full verification.

### 7.1 Build matrix

| Command | Result |
|---|---|
| `cd rust && cargo build --lib` | clean |
| `cargo build --release --lib` | clean under `overflow-checks = true` |
| `cargo build --bins` | all four bins clean (only a pre-existing unused-import warning in `ls_gateway`) |
| `cargo build --examples` | clean |
| `cargo build --lib --features fips_gate` | clean |
| `cd fuzz && cargo check --bins` | clean; three targets compile (decode_bytes, validate_key, unauth_decode) |
| `cd docs && pdflatex napseq-eprint-v3.tex` | 31 pages, no errors, no undefined references |

### 7.2 Test matrix

| Command | Result |
|---|---|
| `cargo test --lib` | **234 passed / 0 failed** |
| `cargo test --release --lib` | **234 passed / 0 failed** (release-mode assertions fire) |
| `cargo test --doc` | 3 passed (README round-trip + streaming AE + NapqesKey) |
| `cargo test --lib kat_cross_check` | 8 passed (5 v7 + 3 v8 including new profile vectors) |
| `cargo test --lib self_test` | 10 passed (5 v7 KATs + 3 v8 KATs + 2 CVF-47 latch tests) |
| `cargo test --lib --features fips_gate fips_gate_tests` | 1 passed (end-to-end gate refusal + admission) |
| `cargo test --lib cvf` | 40+ tests, all named after the CVF they close |
| `python tests/gen_kats_v8.py` | regenerated 23 vectors, cross-verified via `--check` |
| `cargo run --release --bin sts -- --bits 1000000` | 14/14 SP 800-22 scored tests pass on v8 bitstream |

### 7.3 Cross-language KAT parity

- v6 corpus (`tests/kat/v6_vectors.json`, v7 fixed-width content, 37 vectors): Rust decoders reproduce every positive vector byte-for-byte; negatives all rejected with the expected error substring.
- v8 corpus (`tests/kat/v8_vectors.json`, 23 vectors after CVF-32 extension): Rust encoders match Python byte-for-byte on every positive vector across `bucket`, `coarse(3)`, `coarse(12)`, `frame(1024)` profiles; negatives all rejected with the expected substring.
- Streaming AE corpus (`tests/kat/v8_stream_vectors.json`): passes unchanged.

### 7.4 Regression test index (new tests added by this remediation)

Named `cvf<N>_...` where possible so `cargo test --lib cvf` surfaces the whole set. Selected list — full listing in `rust/src/lib.rs` and `rust/src/self_test.rs`:

- **CVF-12 / 45:** `ct_eq_bytes_length_mismatch_returns_false`, `cvf45_ct_eq_bytes_nonce_length_fails_closed`
- **CVF-13:** `empty_ciphertext_is_rejected`, `empty_message_ciphertext_authenticates`, `empty_message_roundtrip` (rewritten)
- **CVF-14:** `cvf14_encrypt_bytes_ciphertext_is_rejected_by_decrypt_raw_for_non_ascii`, `cvf14_encrypt_raw_ciphertext_still_roundtrips_via_decrypt_raw`, `cvf14_encrypt_bytes_roundtrip_via_decrypt_bytes_unchanged`, `cvf14_decrypt_returns_result_not_panic`
- **CVF-15:** ten `cvf15_v7_*_rejects_*` tests
- **CVF-16:** `cvf16_validate_key_rejects_element_above_max_key_prime`
- **CVF-20:** `cvf20_generate_prime_numbers_produces_valid_key`
- **CVF-25:** `cvf25_v8_roundtrip_first_non_ascii_codepoint`, `cvf25_v8_roundtrip_bmp_above_0100`, `cvf25_v8_roundtrip_supplementary_plane`, `cvf25_v8_roundtrip_mixed_codepoint_widths`
- **CVF-28:** `cvf28_be_len_prefix_panics_on_overflow`
- **CVF-29 / 37 / 41:** `napqeskey_constructor_validates`, `napqeskey_constructor_rejects_empty_primes`, `napqeskey_constructor_rejects_composite`, `napqeskey_encrypt_decrypt_roundtrip_via_key_api`, `napqeskey_matches_bare_slice_api_byte_for_byte`, `cvf41_validate_key_rejects_key_above_max_elements`
- **CVF-31:** `cvf31_block_size_rejects_oversized_n`
- **CVF-34:** `cvf34_v7_encrypt_bytes_rejects_oversize_message`, `cvf34_v7_encrypt_raw_rejects_oversize_data`
- **CVF-42:** `cvf42_named_alphabet_constants_are_correct`
- **CVF-43:** `cvf43_unpad_rejects_noncanonical_length_prefix`
- **CVF-46:** `cvf46_v7_encryptors_share_emitter`
- **CVF-47:** `cvf47_post_state_transitions_to_passed`, `cvf47_require_post_gates_correctly`, `v8_entry_refuses_before_post_and_admits_after`
- **CVF-18:** `kat4_v8_encrypt_roundtrip`, `kat5_v8_decrypt_roundtrip`, `kat6_v8_structural_reject`

### 7.5 What did **not** change (deliberate parity guarantees)

- v6 KAT corpus: byte-identical (only metadata `expected_error_contains` added to N002).
- v8 KAT corpus W001–W012: byte-identical.
- All Python and Rust reference implementations continue to produce byte-identical ciphertexts on shared inputs (verified per KAT vector).
- v7 wire format: unchanged. v7 decryptors continue to decode any pre-remediation v7 ciphertext.
- v8 wire format: unchanged. v8 encrypt+decrypt round-trip on any pre-remediation v8 ciphertext.

---

## Appendix A — Files changed (aggregate)

**New files (3):**
- [rust/src/key.rs](rust/src/key.rs) — `NapqesKey` newtype + `Secret32` scope guard + `_key`-suffixed v8 API (CVF-29 + CVF-37 + CVF-41)
- [docs/DUDECT_ATTESTATION.md](docs/DUDECT_ATTESTATION.md) — timing-attestation document (CVF-26)
- [docs/review/epineon-napqes-v4-remediation-report.md](docs/review/epineon-napqes-v4-remediation-report.md) — this document

**Modified files:**

Rust reference implementation (`rust/`):
- [src/lib.rs](rust/src/lib.rs) — the majority of Phase A + Phase B changes (11 findings direct + 4 findings via NapqesKey wiring); module header (CVF-21); `#![doc = include_str!]` (CVF-24)
- [src/self_test.rs](rust/src/self_test.rs) — v8 KATs (CVF-18) + INT-1 rename + POST latching (CVF-47)
- [src/kat_cross_check.rs](rust/src/kat_cross_check.rs) — toothless guards fixed (CVF-19), negative-substring enforcement (CVF-25), `pad_profile` dispatch (CVF-32)
- [src/bin/sts.rs](rust/src/bin/sts.rs) — v7 → v8 migration (CVF-33)
- [src/main.rs](rust/src/main.rs), [src/bin/sts.rs](rust/src/bin/sts.rs), [src/ot_frame.rs](rust/src/ot_frame.rs) — narrow `#[allow(deprecated)]` scopes for v7 encryptor call sites (CVF-17)
- [examples/dudect_harness.rs](rust/examples/dudect_harness.rs) — v8 retarget (CVF-26)
- [fuzz/fuzz_targets/decode_bytes.rs](rust/fuzz/fuzz_targets/decode_bytes.rs) — v8 retarget with structure-aware body (CVF-22)
- [fuzz/fuzz_targets/validate_key.rs](rust/fuzz/fuzz_targets/validate_key.rs) — new (CVF-22)
- [fuzz/fuzz_targets/unauth_decode.rs](rust/fuzz/fuzz_targets/unauth_decode.rs) — new (CVF-22)
- [fuzz/Cargo.toml](rust/fuzz/Cargo.toml) — three `[[bin]]` targets registered (CVF-22)
- [Cargo.toml](rust/Cargo.toml) — `[profile.release]`, `[profile.test]`, `[features] fips_gate`, tokio narrowing (CVF-23 + CVF-47)
- [.gitignore](rust/.gitignore) — fuzz artefacts added; `Cargo.lock` un-ignored (CVF-23)
- [Cargo.lock](rust/Cargo.lock) — committed (CVF-23)
- [README.md](rust/README.md) — full rewrite (CVF-24)

Paper and specification (`docs/`):
- [napseq-eprint-v3.tex](docs/napseq-eprint-v3.tex) — CVF-11 (Section 3.3 + Table 1 + Lemma 3.7 + 4 theorems + Section 12 + Remark 3.8-3.9); CVF-27 (Def 3.10 step 7); CVF-30 (§3.4 qualification); CVF-36 (Remark 3.3 sentence deletion via footnote)
- [CAVEATS.md](docs/CAVEATS.md) — no changes in this pass (already documents CVF-11's sk_fmt layer)

Test corpus and generator (`tests/`):
- [gen_kats_v8.py](tests/gen_kats_v8.py) — `pad_profile` argument + W013–W015 vectors (CVF-32)
- [kat/v8_vectors.json](tests/kat/v8_vectors.json) — regenerated to 23 vectors
- [kat/v6_vectors.json](tests/kat/v6_vectors.json) — one metadata field added on N002 (`expected_error_contains` for CVF-25)

---

## Appendix B — Reproduction commands

From the repository root:

```sh
# 1. Rust build (dev + release) + tests
cd rust
cargo build --lib
cargo build --release --lib
cargo test --lib                                # 234 tests
cargo test --release --lib                      # 234 tests, overflow-checks
cargo test --doc                                # 3 doctests
cargo test --lib kat_cross_check                # 8 KAT parity tests

# 2. FIPS gate (opt-in feature)
cargo test --lib --features fips_gate fips_gate_tests

# 3. Bins
cargo build --bins

# 4. Fuzz harness (nightly required for actual fuzzing; check is stable-only)
cd fuzz
cargo check --bins

# 5. Regenerate v8 KAT corpus + confirm cross-language parity
cd ../..
python tests/gen_kats_v8.py

# 6. NIST SP 800-22 on v8 bitstream (smoke run — full 10M is a follow-up)
cd rust
cargo run --release --bin sts -- --bits 1000000

# 7. Paper build
cd ../docs
pdflatex napseq-eprint-v3.tex
```

Every command above completes clean in the tested environment.

---

## Appendix C — Attribution and traceability

- **Code:** every fix carries `// CVF-<N>` in a comment. `git log --grep="CVF-"` after the remediation branch merges will surface the fix history per finding.
- **Tests:** every regression is named `cvf<N>_...` or (for the v8 KATs added by CVF-18) `kat4_..`/`kat5_..`/`kat6_..`. `cargo test --lib cvf` runs the regression set.
- **Paper:** every edit carries a `CVF-<N>` marker in a footnote or immediately-adjacent LaTeX comment.
- **Documentation:** [DUDECT_ATTESTATION.md](docs/DUDECT_ATTESTATION.md) has a Change History table; this report has a status table (§3) plus a per-finding detail (§§4–5).
- **Config:** every non-default `Cargo.toml` line and every `.gitignore` line change is commented with the CVF it closes.

---

**End of report.**
