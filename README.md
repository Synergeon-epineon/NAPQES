# NAPQES

**NAPQES** (Noise-Augmented Post Quantum Encryption System) is an HMAC-SHA256-based AEAD construction for short-to-medium messages. It uses structured noise tokens and deterministic, key-derived padding to make ciphertexts look heterogeneous without requiring a block cipher or elliptic-curve primitive.

> **Status:** Phase 0 — Foundations & Claim Discipline in progress.
> Wire format v6 is frozen; see [`SPEC.md`](SPEC.md).

---

## Quick start

```bash
python -m venv .venv
# Windows
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python main.py        # starts FastAPI demo on :8000

# Linux / macOS
.venv/bin/pip install -r requirements.txt
.venv/bin/python main.py
```

## Python API

```python
from napqes import encrypt, decrypt

key = [1031, 1033, 1039, 1049, 1051]   # ordered list of prime integers (>= 1024)
ciphertext = encrypt("hello world", key)
plaintext  = decrypt(ciphertext, key)
```

See [`SPEC.md`](SPEC.md) for the complete wire-format specification including
key serialisation, domain-separated HMAC derivation functions, and KAT vectors.

## Repository layout

| Path | Description |
|---|---|
| `napqes.py` | Python reference implementation (v6 wire format) |
| `SPEC.md` | Normative wire-format freeze document |
| `C/` | C port (`napqes.c`, `napqes.h`); build with `make` |
| `rust/` | Rust port (`cargo build --release`) |
| `tests/` | pytest suite + KAT vectors (`tests/kat/v6_vectors.json`) |
| `tools/claim_lint.py` | Claim-traceability linter for `docs/business/` |
| `docs/CAVEATS.md` | Known design trade-offs and planned mitigations |
| `docs/SECURITY_TARGET.md` | Adversary model and explicit non-claims |
| `docs/PRIMITIVES_ATTESTATION.md` | FIPS primitive mapping (draft) |
| `docs/business/` | Business & roadmap documents |
| `main.py` | FastAPI web demo (encryption / decryption UI) |
| `comparator.py` | CLI tool for cross-implementation comparison |

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability disclosure policy and
a list of known limitations. **Do not open public GitHub issues for security
vulnerabilities** — e-mail `security@epineon.com` instead.

Known limitations are tracked in [`docs/CAVEATS.md`](docs/CAVEATS.md).

## Tests

```bash
# Run full test suite (87 tests)
.venv\Scripts\pytest tests/ -v

# Verify KAT vectors match current implementation
.venv\Scripts\python tests/gen_kats.py --check

# Claim-traceability linter (must exit 0)
.venv\Scripts\python tools/claim_lint.py docs/business/
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
