# Certification Readiness Assessment — NAPQES v6

**Verdict: READY WITH MINOR GAPS**

The repository can support a third-party engagement today. No structural cryptographic break was found. ~10 days of focused work eliminates all gaps that would otherwise consume billable reviewer time.

---

## Traffic-Light Summary

| Dimension | Status | Summary |
|---|:---:|---|
| Code quality & completeness | 🟡 | All 3 implementations wire-compatible; C lacks deterministic-encrypt KAT stub |
| Specification completeness | 🟢 | SPEC.md covers all domain bytes, wire format, streaming AE; I-D not yet filed |
| Test infrastructure | 🟡 | KAT corpus solid; STS results not committed; no cross-language CI round-trip |
| Security documentation | 🟡 | SECURITY_TARGET.md and PRIMITIVES_ATTESTATION.md still marked DRAFT |
| Compliance evidence pack | 🔴 | SBOM absent; FIPS 140-3 not submitted; VDP not yet live — **CRA Art. 14 deadline is 11 Sep 2026 (14 weeks)** |
| Structural cryptanalytic surface | 🟢 | No break found; all 2026-05-26 findings remediated |

---

## P0 — Do Before Countersigning the RFP (~4 days)

| # | Action | Effort |
|---|---|---|
| PRE-1 | Run sts_pipeline.py and commit the report | 0.5 day |
| PRE-2 | Remove DRAFT from `SECURITY_TARGET.md`; get informal external cryptographer sign-off | 1–2 days |
| PRE-3 | Add `napqes_encrypt_bytes_with_nonce()` to C port; wire deterministic KAT in test_kats.c | 1 day |
| PRE-4 | Commit fuzz attestation (corpus size + wall-clock runtime) | 0.5 day |

## P1 — Do Before Review Kickoff (~6 days)

| # | Action | Effort |
|---|---|---|
| P1-1 | Add streaming AE KAT vectors to `v6_vectors.json` | 1 day |
| P1-2 | Add cross-language CI test (Python-encrypt → C/Rust-decrypt, and vice versa) | 1–2 days |
| P1-3 | Switch Rust tag compare to `subtle::ConstantTimeEq`; run `dudect` smoke-test | 1 day |
| P1-4 | Fix nist_tests.py note string (`[100, 300]` → `[1 024, ~1 100]`) | 0.25 day |

## Expected Review Findings (anticipate, prepare roadmaps)

| Finding | Severity | Mitigation path |
|---|---|---|
| Python/C not constant-time | High | Documented non-claim; Rust TVLA (Phase 2 workstream 2.2) is the answer |
| IND-CCA proof is prose-only | Medium | Extend ePrint with game-hopping reduction (Bellare & Namprempre 2000) |
| No streaming AE KAT vectors | Medium | Close in P1-1 above |
| Key-ordering undocumented as security parameter | Low | Add a one-sentence API warning |

## Hard Deadline (Independent of Review)

**CRA Art. 14 active-exploit reporting obligation: 11 September 2026.** The VDP + advisory channel must be live before that date. This is a parallel-track item regardless of where the third-party engagement sits in the schedule.