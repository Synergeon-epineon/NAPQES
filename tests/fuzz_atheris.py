"""Atheris fuzz harness for NAPSEQ v6 decoder paths.

Phase 1, workstream 1.6.

Targets three entry points:
  1. ``decrypt_bytes``         — full v6 decode pipeline (auth check → varint
                                  → unpad → plaintext)
  2. ``_b128_decode_tokens``   — LEB128 varint parser in isolation
  3. ``decrypt_bytes`` legacy  — optional ``allow_legacy_unauthenticated`` path

Coverage-guided mode (Linux / macOS, requires libFuzzer via atheris)::

    pip install atheris
    python tests/fuzz_atheris.py -atheris_runs=100000

Simple random-input mode (all platforms; no coverage guidance)::

    python tests/fuzz_atheris.py

The simple mode runs 10 000 random inputs drawn from a seeded PRNG and is
suitable as a quick CI smoke-test.  It will detect crashes, hangs, and any
exception type other than the documented ``ValueError`` / ``IndexError``.

Security contract verified by this harness
-------------------------------------------
``decrypt_bytes`` MUST:
  * Return a ``str`` on success (rare with random data — auth almost always fails).
  * Raise ``ValueError`` on any authentication or format error.
  * Never raise any other exception type regardless of input content.

``_b128_decode_tokens`` MUST:
  * Return a ``list[int]`` on well-formed input.
  * Raise ``IndexError`` on truncated input (acceptable; function is private
    and always called after auth verification inside ``decrypt_bytes``).
  * Never raise any other exception type.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import napqes  # noqa: E402

# ---------------------------------------------------------------------------
# Key fixtures — three representative sizes, selected by fuzzer byte[0]
# ---------------------------------------------------------------------------

_FUZZ_KEYS: list[list[int]] = [
    [1_000_003, 1_000_033],                                           # 2-element
    [7_999_993],                                                      # 1-element
    [1_000_003, 1_000_033, 1_000_037, 1_000_039,
     1_000_081, 1_000_099, 1_000_117, 1_000_121,
     1_000_133, 1_000_151],                                           # 10-element
]

_FUZZ_AADS: list[bytes] = [
    b"",
    b"aad-context",
    b"\x00\xff\x80\x01",
]


# ---------------------------------------------------------------------------
# Single fuzz iteration
# ---------------------------------------------------------------------------

def _fuzz_one(data: bytes) -> None:
    """Apply one corpus entry to all fuzz targets."""
    if len(data) < 2:
        return

    key = _FUZZ_KEYS[data[0] % len(_FUZZ_KEYS)]
    aad = _FUZZ_AADS[data[1] % len(_FUZZ_AADS)]
    payload = data[2:]

    # ── Target 1: decrypt_bytes ──────────────────────────────────────────
    try:
        result = napqes.decrypt_bytes(payload, key, aad=aad)
        # On the rare path where auth passes: result must be a str
        if not isinstance(result, str):
            raise AssertionError(
                f"decrypt_bytes returned {type(result).__name__}, expected str"
            )
    except ValueError:
        pass  # documented: auth failure, too-short, format error
    except Exception as exc:
        raise AssertionError(
            f"decrypt_bytes raised unexpected {type(exc).__name__}: {exc}"
        ) from exc

    # ── Target 2: _b128_decode_tokens (private, called after auth) ───────
    try:
        tokens = napqes._b128_decode_tokens(payload)
        if not isinstance(tokens, list):
            raise AssertionError(
                f"_b128_decode_tokens returned {type(tokens).__name__}, expected list"
            )
    except IndexError:
        pass  # documented: truncated varint (continuation bit on last byte)
    except Exception as exc:
        raise AssertionError(
            f"_b128_decode_tokens raised unexpected {type(exc).__name__}: {exc}"
        ) from exc

    # ── Target 3: decrypt_bytes with legacy opt-in ───────────────────────
    try:
        napqes.decrypt_bytes(
            payload, key, aad=aad, allow_legacy_unauthenticated=True
        )
    except (ValueError, UnicodeDecodeError, OverflowError):
        pass  # all acceptable failure modes on the legacy path
    except Exception as exc:
        raise AssertionError(
            f"decrypt_bytes (legacy) raised unexpected {type(exc).__name__}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        import atheris  # type: ignore[import-untyped]

        atheris.Setup(sys.argv, _fuzz_one)
        atheris.Fuzz()

    except ImportError:
        # Atheris not available (e.g. Windows): fall back to simple random mode.
        import random

        print(
            "atheris not available — running simple random-input mode (10 000 iterations).",
            flush=True,
        )
        rng = random.Random(0xDEAD_BEEF)
        iterations = 10_000

        for i in range(iterations):
            length = rng.randint(0, 512)
            corpus = bytes(rng.randint(0, 255) for _ in range(length))
            _fuzz_one(corpus)
            if (i + 1) % 1_000 == 0:
                print(f"  {i + 1:>6}/{iterations} iterations OK", flush=True)

        print(
            f"Simple random-input mode complete: {iterations} iterations, "
            "no unexpected exceptions.",
            flush=True,
        )


if __name__ == "__main__":
    main()
