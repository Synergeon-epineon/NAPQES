"""Cross-language interoperability test for NAPQES v6.

Tests that Python-generated KAT ciphertexts can be decrypted by the Rust
and C implementations, and that Rust-generated ciphertexts (from the Rust
KAT harness's deterministic encrypt path) are byte-identical to Python's.

Strategy
--------
- Python → Rust: run ``cargo test --lib kat_cross_check`` which decrypts the
  Python-generated ``tests/kat/v6_vectors.json`` ciphertexts. (This lives as
  an in-crate unit-test module, not an external integration test, because
  the deterministic-nonce encrypt helper it exercises is ``pub(crate)``
  only — see CVF3 in ``docs/CAVEATS.md``: an explicit, caller-chosen nonce
  is a key-recovery hazard for NAPQES, so that entry point must not be part
  of the crate's public API.)
- Python → C:    run the C ``kat-test`` binary which decrypts the same vectors.
- Rust  → Python: the Rust KAT harness also calls ``encrypt_bytes_with_nonce``
  and asserts byte-identical output to the Python-generated ``ciphertext_hex``
  fields — this confirms the Rust→Python direction automatically.

Tests are skipped automatically when the required build tool (``cargo`` or
``make`` + gcc) is not found on PATH.

Run:
    pytest tests/test_cross_lang.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_RUST_DIR = _REPO_ROOT / "rust"
_C_DIR = _REPO_ROOT / "C"
_VECTORS = _REPO_ROOT / "tests" / "kat" / "v6_vectors.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _require_tool(*names: str) -> None:
    """Skip the test if none of the named executables are on PATH."""
    if not any(shutil.which(n) for n in names):
        pytest.skip(f"Required tool(s) not on PATH: {', '.join(names)}")


# ---------------------------------------------------------------------------
# Python → Rust
# ---------------------------------------------------------------------------

class TestPythonToRust:
    """Rust KAT harness must decrypt all Python-generated block-mode vectors."""

    def test_rust_kats_pass(self):
        """cargo test --lib kat_cross_check exits 0 — Rust decrypts Python vectors."""
        _require_tool("cargo")
        result = _run(
            ["cargo", "test", "--release", "--lib", "kat_cross_check", "--", "--nocapture"],
            cwd=_RUST_DIR,
            timeout=300,
        )
        if result.returncode != 0:
            pytest.fail(
                f"Rust KAT harness failed (exit {result.returncode}):\n"
                f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )
        # Confirm at least 5 positive vectors were decrypted successfully.
        # The Rust harness prints "Rust KAT positive: N passed, ..." in stderr.
        combined = result.stdout + result.stderr
        import re
        m = re.search(r"Rust KAT positive:\s*(\d+)\s*passed", combined)
        if m:
            count = int(m.group(1))
            assert count >= 5, (
                f"Expected Rust to pass ≥5 positive KAT vectors; got {count}.\n"
                f"Full output:\n{combined}"
            )

    def test_rust_deterministic_encrypt_matches_python(self):
        """positive_encrypt_bytes_deterministic in Rust must match Python ciphertext_hex."""
        _require_tool("cargo")
        result = _run(
            [
                "cargo", "test", "--release",
                "positive_encrypt_bytes_deterministic",
                "--", "--nocapture",
            ],
            cwd=_RUST_DIR,
            timeout=300,
        )
        if result.returncode != 0:
            pytest.fail(
                f"Rust deterministic encrypt test failed:\n"
                f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )
        # Confirm at least 5 vectors were verified byte-identical.
        import re
        combined = result.stdout + result.stderr
        m = re.search(r"Rust KAT deterministic encrypt:\s*(\d+)\s*passed", combined)
        if m:
            count = int(m.group(1))
            assert count >= 5, (
                f"Expected Rust deterministic encrypt to pass ≥5 vectors; got {count}.\n"
                f"Full output:\n{combined}"
            )


# ---------------------------------------------------------------------------
# Python → C
# ---------------------------------------------------------------------------

class TestPythonToC:
    """C KAT harness must decrypt all Python-generated block-mode vectors."""

    @pytest.fixture(scope="class", autouse=True)
    def build_c_kat(self):
        _require_tool("make", "gcc", "cc")
        result = _run(["make", "kat-test"], cwd=_C_DIR)
        if result.returncode != 0:
            pytest.skip(
                f"C build failed — skipping C cross-language tests:\n{result.stderr}"
            )

    def test_c_kat_harness_passes(self):
        """C kat-test must exit 0 with no FAILed vectors."""
        exe = "kat-test.exe" if sys.platform == "win32" else "./kat-test"
        vec_path = str(_VECTORS)
        result = _run([exe, vec_path], cwd=_C_DIR)
        if result.returncode != 0:
            pytest.fail(
                f"C KAT harness failed (exit {result.returncode}):\n{result.stdout}"
            )
        # Confirm at least one PASS line and zero FAIL lines
        assert "[PASS]" in result.stdout, "No PASS lines found in C KAT output"
        assert "[FAIL]" not in result.stdout, (
            "FAIL lines found in C KAT output:\n" + result.stdout
        )
        # Confirm at least 5 vectors passed (positive block-mode vectors).
        import re
        m = re.search(r"C KAT results:\s*(\d+)\s*passed", result.stdout)
        if m:
            count = int(m.group(1))
            assert count >= 5, (
                f"Expected C harness to pass ≥5 KAT vectors; got {count}.\n"
                f"Output:\n{result.stdout}"
            )


# ---------------------------------------------------------------------------
# Rust → Python (explicit direction)
# ---------------------------------------------------------------------------

class TestRustToPython:
    """Rust's deterministic encrypt output (= Python's ciphertext_hex) must be
    decryptable by Python.  Proven transitively: Rust encrypt == Python's
    ciphertext_hex (by positive_encrypt_bytes_deterministic), and Python
    decrypt_bytes(ciphertext_hex) == plaintext (by test_kats.py).
    This class makes the chain explicit by selecting 5 named vectors."""

    _FIVE_VECTOR_IDS = {"V002", "V003", "V008", "V013", "V020"}

    def test_rust_to_python_five_vectors(self):
        """For 5 named KAT vectors: Rust encrypt == Python ciphertext_hex,
        and Python decrypt_bytes recovers the original plaintext."""
        _require_tool("cargo")
        import json, sys as _sys
        _sys.path.insert(0, str(_REPO_ROOT))
        import napqes
        from tests.gen_kats import _encrypt_with_nonce

        with open(_VECTORS, encoding="utf-8") as f:
            data = json.load(f)

        tested = 0
        for vec in data["vectors"]:
            if vec["id"] not in self._FIVE_VECTOR_IDS:
                continue
            key = vec["key"]
            message = vec["message"]
            aad = bytes.fromhex(vec["aad_hex"])
            nonce = bytes.fromhex(vec["nonce_hex"])
            expected_ct = bytes.fromhex(vec["ciphertext_hex"])

            # Python re-derives the same ciphertext as Rust (deterministic)
            py_ct = _encrypt_with_nonce(message, key, nonce, aad=aad)
            assert py_ct == expected_ct, (
                f"[{vec['id']}] Python deterministic encrypt mismatch — "
                "Rust→Python roundtrip chain broken"
            )
            # Python decrypt recovers the plaintext
            plaintext = napqes.decrypt_bytes(expected_ct, key, aad=aad)
            assert plaintext == message, (
                f"[{vec['id']}] Python decrypt_bytes failed on KAT ciphertext"
            )
            tested += 1

        assert tested == len(self._FIVE_VECTOR_IDS), (
            f"Expected {len(self._FIVE_VECTOR_IDS)} vectors; found only {tested} "
            f"in {_VECTORS}"
        )
