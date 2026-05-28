# Roadmap
## Stage 1: Pre-Review — ~2 weeks (P0)
These items directly consume reviewer time and bill-rate if not done first.

###	Action	Effort	Reason
S1-1	Run tests/sts_pipeline.py on 10^7-bit sample; commit report JSON and pass/fail verdict	0.5 d	Reviewers will ask for it on day 1
S1-2	Count primes in [1M, 15M] via sieve; update key-space claim in SPEC.md, SECURITY_TARGET.md, and comparator.py with exact figure	0.5 d	Quantitative claim must be defensible
S1-3	Remove "DRAFT" from SECURITY_TARGET.md; obtain informal external cryptographer sign-off on §6.5 scope	1–2 d	Reviewers will not start under a DRAFT security target
S1-4	Verify napqes_encrypt_bytes_with_nonce() in C port is implemented (header exists at C/napqes.h:52); wire it into C/test_kats.c against at least two v6_vectors.json vectors	1 d	C KAT cross-check gap identified in readiness doc
S1-5	Commit fuzz attestation: corpus size, wall-clock time, any crashes found and resolved	0.5 d	Reviewers want evidence fuzz was run, not just exists

## Stage 2: Pre-Kickoff — ~3 weeks (P1)
Required before the engagement clock starts.

###	Action	Effort	Reason
S2-1	Write the full IND-CPA game-hopping proof as a LaTeX section in the ePrint preprint: PRF-replacement hop (show HMAC calls are distinguishable only via PRF advantage), OTP argument (domain-0x07 keystream information-theoretically hides masked blob under PRF)	3–5 d	Biggest open cryptographic gap; blocks the IND-CCA sketch
S2-2	Write the IND-CCA game-hop as a lemma: INT-CTXT (tag forgery ⟹ PRF distinguisher) + IND-CPA → IND-CCA via B&N 2000 Theorem 3	2–3 d	Reviewer's first question on AEAD correctness
S2-3	Add cross-language CI roundtrip: Python-encrypt → Rust-decrypt, Rust-encrypt → Python-decrypt, Python-encrypt → C-decrypt; at least 5 vectors from v6_vectors.json	2 d	Confirms wire-format conformance; reviewers will test this
S2-4	Add streaming AE KAT vectors explicitly to v6_vectors.json if not already there; confirm test_kats.py _STREAM_AE_POSITIVE loads them	1 d	Stream AE is a material feature with its own security claim
S2-5	Fix nist_tests.py line 33 note string: change [100, 300] to [1 024, ~1 100]	0.25 d	Cosmetic but visible to reviewers
S2-6	Explicitly document the key-ordering security parameter in every language API (Python module docstring, C header, Rust crate docs) with a one-line warning	0.5 d	Expected finding listed in readiness doc

## Stage 3: During Third-Party Review
###	Action	Notes
S3-1	Resolve any findings categorized "must fix" before the report is finalized	Coordinate timeline with reviewing firm
S3-2	Publish dudect TVLA methodology and t-statistic history in DUDECT_ATTESTATION.md	Supports any side-channel claims in the report
S3-3	Begin SBOM generation (CycloneDX JSON) for all three language implementations	CRA Art. 14 requirement; needed before VDP goes live

## Stage 4: For IACR ePrint Submission
###	Action	Effort
S4-1	Finalize ePrint preprint: abstract, construction, IND-CPA proof, IND-CCA sketch (from S2-1/S2-2), performance data, caveats	1–2 weeks
S4-2	Include exact prime-count entropy figure (from S1-2) and dudect result (t = +1.134, n = 12.7M) in the preprint	In S4-1
S4-3	Submit to IACR ePrint; share preprint DOI with reviewing firm for the report appendix	

## Stage 5: For Public Repository & Compliance
###	Action	Deadline
S5-1	Live VDP (responsible disclosure policy, advisory channel, contact email)	Sep 11, 2026 (CRA Art. 14)
S5-2	Public repository with issue tracker; migrate CAVEATS.md entries to GitHub issues	Same window
S5-3	File IETF I-D (draft-napqes-aead-00.md already exists — submit to datatracker)	After third-party report is public
S5-4	INT-1 binary HMAC integrity check in Rust: implement build.rs HMAC over .text + .rodata, embed digest via include_bytes!	Phase 4 workstream 4.1
S5-5	Rust streaming AE implementation; C streaming API (both scope-gaps relative to Python reference)	v1.0 feature parity target


## Priority Stack for the Next 30 Days
S1-3 — informal external sign-off on security target scope (unblocks everything)
S2-1 + S2-2 — write the IND-CPA/IND-CCA proofs (longest single item; start immediately)
S1-1 — STS results committed (fast, no code)
S1-4 — C port KAT stub (1 day, closes the only C implementation gap)
S2-3 — cross-language CI (insurance that no silent wire-format divergence creeps in)
Everything else in Stage 1–2 is either ≤0.5 day or can run in parallel with the proof writing.

The algorithm itself has no known structural break. The main pre-publication risk is not the cryptography — it is the absence of a written proof and the absence of an external signature on the security claims.