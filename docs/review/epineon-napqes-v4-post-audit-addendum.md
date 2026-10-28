# NAPQES v4 — Client Addendum to ABDK Report v1.0

**Issued by:** Epineon (the client)
**Refers to:** ABDK Consulting, *Fourth Review Round — NAPQES v4 AEAD Scheme
Audit*, report version 1.0, 27 October 2026
([`epineon-napqes-v4-public-report-v1.0.pdf`](epineon-napqes-v4-public-report-v1.0.pdf))
**Audited commit:** `acbf9d05bd4ce93a77d91e2d2a5e9a6ed4a302e1` (`acbf9d0`)
**Post-audit fixes:** commits `acbf9d0...a2fbd13` (34 commits, 2026-10-21) —
<https://github.com/Synergeon-epineon/NAPQES/compare/acbf9d0...a2fbd13>

> **Status of this document.** This addendum is a client statement. It is
> **not part of the ABDK report** and does not modify it; the report remains
> authoritative for everything it states. **ABDK has not reviewed the fixes
> described here.** The status ABDK gives each finding reflects commit
> `acbf9d0`; the "Client status" column below reflects commit `a2fbd13`.

---

## 1. Why this addendum exists

Section 6 of the report lists 30 findings (CVF-V5-*n*: 8 moderate, 22
minor, none major or critical) against the fixed code at `acbf9d0`. All 30
are marked *open* because ABDK's review stopped at that commit. The report
reproduces our Client Comment under each finding and notes that "the client
reports one fix per finding, in the commit range acbf9d0...a2fbd13", but it
does not record which commit closes which finding. This addendum records
that mapping, so that a reader of the report can check each fix in the
public repository.

The report also asks us questions about code outside its scope (Section 8)
and about one evidence artifact (Section 9). We answer them in Sections 4
and 5 below.

---

## 2. Finding-by-finding fix record

Legend for the client status: **Fixed** — the recommendation is
implemented; **Partly fixed** — the core is implemented and the stated
remainder is accepted; **Mitigated** — the risk is removed from the
default build or the audited surface without the full recommendation.

Each fix commit's message starts with `fix(CVF-V5-n)` or
`docs(CVF-V5-n)`, so `git log -E --grep "CVF-V5-n[,)]"` lists them.

### 2.1 Moderate (8)

| Finding | ABDK summary (abridged) | ABDK status at `acbf9d0` | Fix commit(s) | Client status at `a2fbd13` |
|---|---|---|---|---|
| CVF-V5-1 | Streaming format reveals the exact message length | open | `7a17584` | Fixed — the count is masked under new domain `0x0F`; only the chunk count remains visible, and this is documented |
| CVF-V5-2 | Streaming offered as recommended, without analysis or a complete specification | open | `7199472` | Mitigated — streaming compiles only with the off-by-default `experimental-stream` feature, is outside the audited claims, and SPEC.md §8.2 now determines every byte |
| CVF-V5-3 | Key-prime interval widened without disclosure or correct justification | open | `c14e0a0` | Fixed — disclosed and versioned as parameter set P2 `[10^6, 1.5·10^7)`, with corrected figures and new KAT vectors |
| CVF-V5-4 | Legacy v7 noise loop unbounded and still used by the gateway | open | `23025ed`, `b619dab` | Fixed — the v7 loop is bounded, the v7 encryptors sit behind the off-by-default `legacy-v7` feature, and the gateway uses v8 |
| CVF-V5-5 | Self-test does not check software integrity | open | `b98bf23` | Fixed — HMAC-SHA256 integrity test over the executable, plus KATs for FrodoKEM, X25519 and the hybrid combiner |
| CVF-V5-6 | Key-exchange, network and gateway code built into every consumer | open | `da7e005` | Partly fixed — `vale`, `vale_demo` and the SPHINCS+ dependency removed; `kem`, `kem_exchange`, `ot_frame` and `protocols` are still compiled unconditionally (accepted) |
| CVF-V5-7 | Legacy v7 single-secret key schedule used for gateway traffic | open | `b619dab`, `23025ed` | Fixed — the gateway seals with v8 under a validated `NapqesKey`, and the KEM derives an independent `sk` |
| CVF-V5-8 | FIPS self-test gate off by default and incomplete | open | `eca82e6` | Partly fixed — every entry point is gated under `fips_gate` and failures are sticky; the gate stays opt-in (accepted) |

### 2.2 Minor (22)

| Finding | ABDK summary (abridged) | ABDK status at `acbf9d0` | Fix commit(s) | Client status at `a2fbd13` |
|---|---|---|---|---|
| CVF-V5-9 | Empty stream does not authenticate the frame size | open | `7a17584` | Fixed — the full stream header is bound into every tag; new negative vector S-N04 |
| CVF-V5-10 | Rust stream decryptor needs the whole stream in memory | open | `1716bcd` | Fixed (documentation option) |
| CVF-V5-11 | New unwiped copies of key material | open | `476f226`, `75de8cf` | Fixed |
| CVF-V5-12 | v7 decryption validates the key before the tag | open | `4eea6fb` | Fixed — the tag is checked first |
| CVF-V5-13 | Demo build option silently changes the format | open | `69ed83c` | Fixed — the option is removed |
| CVF-V5-14 | Key generation accepts invalid sizes | open | `2b6db30` | Fixed |
| CVF-V5-16 | v7 decryptors reject some archived data | open | `e872c6e` | Fixed — relaxed v7 key policy, with the compatibility envelope documented |
| CVF-V5-17 | Deprecated v7 encryptor accepts what its decryptor rejects | open | `2086e00` | Fixed |
| CVF-V5-18 | Self-test does not cover streaming | open | `e8cb86f` | Fixed — KAT-9, KAT-10 and KAT-11 |
| CVF-V5-19 | CRNG continuous-test failure is not latched | open | `e9489a9` | Fixed |
| CVF-V5-20 | Tests named after findings cannot fail | open | `9c0c93b` | Fixed |
| CVF-V5-21 | Empty-ciphertext vector silently skipped | open | `b54ae56` | Fixed |
| CVF-V5-22 | Stale comments | open | `54c8544` (with `e872c6e`, `2086e00`) | Fixed |
| CVF-V5-23 | Specification has no version number | open | `4c96bd8` | Fixed — revision 4.2, `docs/napseq-eprint-v4.tex` |
| CVF-V5-24 | Incomplete specification edits | open | `24c26bf` | Fixed |
| CVF-V5-25 | v7 tag does not bind the text/bytes convention | open | `6fdbec3` (with `23025ed`) | Mitigated — documented, pinned by a test, and withdrawn behind `legacy-v7` |
| CVF-V5-26 | Fuzzing shallow and never recorded as run | open | `471501e`, `da5da58` | Fixed — see `docs/FUZZ_ATTESTATION.md` |
| CVF-V5-27 | Weak constant-time evidence | open | `e3ea69d`, `9a2cbec`, `fecb8dd` | Fixed — see `docs/DUDECT_ATTESTATION.md` |
| CVF-V5-28 | Decryption remark gives a false argument | open | `db499d4` | Fixed |
| CVF-V5-29 | v8 functions validate the key on every call with secret-dependent timing | open | `b87e98c` | Fixed — `NapqesKey` variants added and bare-slice variants deprecated |
| CVF-V5-30 | Prime generation inefficiencies | open | `75de8cf` | Fixed |
| CVF-V5-31 | Token-emission code duplicated | open | `25310e5` | Fixed — single emission loop |

**CVF-V5-15** (a key tuple committed in `meta.json`) appeared in draft v0.2
but not in report v1.0. We removed the file from the entire history with
`git filter-repo`, and `f6ced5d` became `acbf9d0`. The tuple is declared
compromised in `docs/CAVEATS.md`. Commit `e775bd2` adds `.gitignore` rules
and a gitleaks CI job to prevent a recurrence.

The full Client Comment for each finding, as reproduced in the report, is
in [`epineon-napqes-v4-round5-client-comments.md`](epineon-napqes-v4-round5-client-comments.md).

### 2.3 Residual items we accept

These remain open at `a2fbd13` by decision:

- **CVF-V5-6:** `kem`, `kem_exchange`, `ot_frame` and `protocols` are
  still compiled into every build. They were not audited (report §8).
- **CVF-V5-8:** `fips_gate` is opt-in. A default build operates whether or
  not the power-on self-tests have run or passed.
- **CVF-V5-2 / CVF-V5-10:** the streaming format has no security proof and
  is not part of the audited claims. It is not compiled by default.
- **CVF-V5-25:** the v7 tag does not bind the encoding convention.
  Changing this would break the archived v7 format, so v7 encryption is
  withdrawn behind `legacy-v7` instead.

---

## 3. Notes for Users (report §5.1) — current state

The report's Notes for Users describe commit `acbf9d0`. At `a2fbd13`:

| Report note | State at `a2fbd13` |
|---|---|
| Use the block format for protected data | Unchanged advice. Streaming needs `--features experimental-stream`, the length leak (CVF-V5-1) and the header issue (CVF-V5-9) are fixed, and the Python stream decryptor still releases chunks before the stream verifies (CAV-001). |
| Use v7 only to read archived data | The gateway uses v8. The v7 encryptors need `--features legacy-v7`, and the v7 decryptors stay available for archives. |
| Hold keys in `NapqesKey` | `NapqesKey` variants exist for every v8 and stream entry point, and the bare-slice v8 functions are deprecated. |
| Build with `fips_gate` where the self-tests must gate use | Unchanged: `fips_gate` and `fips_integrity` are opt-in and must be enabled by the integrator. Run `napqes_integrity` in the release process. |
| Agree on the key parameters | The interval is parameter set P2, `[10^6, 1.5·10^7)`, K = 13, specified in revision 4.2. Keys generated under P2 are rejected by implementations of earlier revisions (P1). |
| The crate contains code this review did not cover | Unchanged (CVF-V5-6 remainder). |

---

## 4. Answers to report Section 8 (out-of-scope observations)

The report states that these are not audited findings. Our answers are
based on the code at `a2fbd13`.

**Prime interval in `kem.rs`.** `kem.rs` samples from `[10^6, 1.5·10^7)`,
which is now the normative parameter set P2 (CVF-V5-3, `c14e0a0`).
`validate_key` has enforced the upper bound `MAX_KEY_PRIME = 14,999,999`
since `014b31a`, which is part of `acbf9d0`. Every key the KEM produces is
therefore inside the specified interval and accepted by design. The two
interval ends agree: the KEM's half-open `% (MAX_PRIME − MIN_PRIME)`
reduction yields at most 14,999,999. The modulo bias is documented in the
code as below 2⁻⁴⁰ per draw. The search loop has no explicit failure
path. It terminates with overwhelming probability, since about 6% of the
interval is prime, and we leave it as is.

**Replay counter in `ot_frame::unwrap_pdu`.** Fixed in `61f2708`, which is
part of the audited commit `acbf9d0` but not of the baseline `b8c3054`.
The counter advances only after the v8 tag verifies ("Only an
authenticated seq may advance the replay window"). The regression test
`forged_high_seq_does_not_advance_replay_window` injects a forged frame
with `seq = u64::MAX` and checks that genuine frames are still accepted.
The empty-ciphertext bypass is closed twice over: the v7 fix (CVF-13), and
the gateway's move to v8 decryption (`b619dab`).

**The four further observations.**
1. *The transport path has no independent 256-bit secret.* Fixed in
   `b619dab`: `kem::derive_v8_sk` derives `sk` from the KEM shared secret
   under its own HKDF label, separately from the prime tuple, and the
   gateway uses v8.
2. *The file-backed key store.* `FileKeyStore` now loads `{primes, sk_hex}`
   into a `NapqesKey`, which validates the key once and wipes it on drop.
   Protecting the key file at rest remains a deployment responsibility.
3. *The v6 label in a KEM salt.* `HKDF_SALT` still reads
   `NAPQES-v6-FrodoKEM-640-prime-key`. It is a fixed domain-separation
   string and is kept for compatibility with existing peers and the
   cross-language KEM vectors. The v8 `sk` derivation uses its own label.
4. *The Section 9 bitstream generator calls the legacy encryptor.* Fixed
   (CVF-33, 2026-09-22): `rust/src/bin/sts.rs` encrypts with
   `encrypt_bytes_v8`.

**Scope question.** The product's cryptographic core is the NAPQES AEAD
(the v8 block format) in the Rust crate, which is the surface ABDK audited.
`kem`, `kem_exchange`, `ot_frame` and `protocols` are integration code for
our OT gateway. They have not been audited, and we do not describe them as
audited.

---

## 5. Answer to report Section 9 (provenance of `tests/sts_report_v6.json`)

- **Tool.** `tests/sts_report_v6.json` was produced by our from-scratch
  Rust implementation of NIST SP 800-22, `rust/src/bin/sts.rs`, in the
  version committed with it in `00dcaa9` (2026-05-26). It was not produced
  by `tests/sts_pipeline.py`. The schema ABDK observed is the one `sts.rs`
  writes: `name`, `passed`, `skipped`, `p_value`, `note`, a summary with
  `skipped`, and one row per random-excursion state.
- **Version.** The run was over a v6 ciphertext bitstream of 10⁷ bits, as
  the file says.
- **The eight tests.** The eight tests that `sts_pipeline.py` skips were
  run. They are skipped only in the Python pipeline, which drives the
  `nistrng` library and works around defects in it. `sts.rs` implements
  all fifteen SP 800-22 tests itself.
- **Current evidence.** That v6 file is historical. The evidence for the
  current scheme is `sts_report.json` (v8, 5·10⁷ bits, 40/40 pass,
  2026-09-25), documented in `docs/STS_ATTESTATION.md`. Section 9 of the
  paper (revision 4.2) cites `sts.rs` and that report.

---

## 6. Verification at `a2fbd13` (client-run)

- **Rust:**
  - `cargo test` passes with default features, with all features
    (`fips_gate,fault_injection,legacy-v7,experimental-stream`), and in
    `--release`;
  - the MSRV 1.88 check passes;
  - the fuzz crate builds.
- **Cross-language:** Rust, Python and C reproduce the v6, v8 and v8-stream
  KAT corpora byte for byte.
- **Python:** `pytest tests` gives 377 passed and 1 skipped. One
  intermittent failure in the deprecated v6 basic stream predates these
  changes.
- **Fuzzing:** each of 4 targets ran for 600 s under ASan with no crashes
  (`docs/FUZZ_ATTESTATION.md`).
- **Constant-time (dudect):**
  - comparator |t| = 0.785 over 7.6M samples;
  - positive control |t| = 4,610;
  - CI gate |t| < 4.5 (`docs/DUDECT_ATTESTATION.md`).
- **Specification:** revision 4.2 (`docs/napseq-eprint-v4.tex`) builds
  cleanly. ABDK has **not** reviewed the new material in revision 4.2
  (report §6, "Specification").

---

## 7. How to verify a fix yourself

```bash
git clone https://github.com/Synergeon-epineon/NAPQES && cd NAPQES
git log --oneline acbf9d0..a2fbd13          # the 34 post-audit commits
git log -E --grep "CVF-V5-1[,)]" --stat     # the commit(s) for one finding
git diff acbf9d0 a2fbd13 -- rust/src/lib.rs # the full change to the core
```
