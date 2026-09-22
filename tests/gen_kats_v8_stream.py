"""Generate deterministic Known-Answer Test vectors for NAPQES v8 streaming AE.

Unlike v8 block mode (whose synthetic-IV construction makes encryption a pure
function of `(primes, sk, aad, message)`), v8 streaming uses a random 16-byte
nonce that MUST be fresh per stream (see CAV-005 in `docs/CAVEATS.md`).  To
produce byte-reproducible KAT vectors that the Rust and C ports can validate
against, this generator uses the private, test-only helper
`napqes._encrypt_stream_ae_v8_with_nonce`, which takes an injected nonce.

The Rust and C ports each expose a matching test-only entry point:

  * Rust:  `pub(crate) fn encrypt_stream_ae_v8_with_nonce(...)`
  * C:     `napqes_stream_v8_encrypt_init_with_nonce(...)`
           (gated on `NAPQES_ENABLE_TEST_NONCE_API`)

If the byte streams diverge, the three ports disagree on the wire format.

Run:
    python tests/gen_kats_v8_stream.py                  # write v8_stream_vectors.json
    python tests/gen_kats_v8_stream.py --check          # regenerate and compare (CI)

Output schema per vector:
  id                  unique string identifier
  kind                "positive" (only kind for now)
  description         human-readable note
  primes              list[int] - prime key elements
  sk_hex              hex of the 32-byte independent HMAC subkey `sk`
  nonce_hex           hex of the 16-byte injected stream nonce
  aad_hex             hex of AAD bytes ("" means empty)
  frame_codepoints    F: real codepoints per chunk
  message             plaintext string
  ciphertext_hex      expected byte stream produced by
                      `_encrypt_stream_ae_v8_with_nonce`
"""

import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import sys

# Make napqes importable from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import napqes  # noqa: E402

_SEED_KEY = b"napseq-kat-seed-v8-stream"
_OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kat")
_OUT_FILE = os.path.join(_OUT_DIR, "v8_stream_vectors.json")

# Keys used across vectors. Matches the shape of the block v8 KAT keys so
# a stream/block divergence cannot be blamed on differing key material.
KEY_4 = [1_000_003, 1_000_033, 1_000_037, 1_000_039]
KEY_10 = [1_000_003, 1_000_033, 1_000_037, 1_000_039,
          1_000_081, 1_000_099, 1_000_117, 1_000_121,
          1_000_133, 1_000_151]
KEY_13 = KEY_10 + [1_000_159, 1_000_171, 1_000_183]


def _sk(index: int) -> bytes:
    """Derive a deterministic 32-byte v8 subkey for vector *index*."""
    return hmac_mod.new(
        _SEED_KEY,
        b"sk:" + index.to_bytes(4, "big"),
        hashlib.sha256,
    ).digest()


def _nonce(index: int) -> bytes:
    """Derive a deterministic 16-byte stream nonce for vector *index*.

    KAT-only. Production callers MUST NEVER inject nonces this way -- see
    CAV-005.
    """
    return hmac_mod.new(
        _SEED_KEY,
        b"nonce:" + index.to_bytes(4, "big"),
        hashlib.sha256,
    ).digest()[:16]


def _build_positive(
    vec_id: str,
    description: str,
    primes: list[int],
    idx: int,
    message: str,
    aad: bytes = b"",
    frame_codepoints: int = napqes.STREAM_AE_V8_DEFAULT_FRAME,
) -> dict:
    sk = _sk(idx)
    nonce = _nonce(idx)
    stream = b"".join(napqes._encrypt_stream_ae_v8_with_nonce(
        iter(message), primes, sk, nonce, aad,
        frame_codepoints=frame_codepoints,
    ))
    # Roundtrip via the public decrypt API confirms the vector is valid.
    back = "".join(napqes.decrypt_stream_ae_v8([stream], primes, sk, aad))
    assert back == message, f"Roundtrip failed for {vec_id}: got {back!r}"
    return {
        "id": vec_id,
        "kind": "positive",
        "description": description,
        "primes": primes,
        "sk_hex": sk.hex(),
        "nonce_hex": nonce.hex(),
        "aad_hex": aad.hex(),
        "frame_codepoints": frame_codepoints,
        "message": message,
        "ciphertext_hex": stream.hex(),
    }


def generate() -> list[dict]:
    vectors: list[dict] = []
    idx = 0

    # -- Positive: boundary / coverage --

    # S001: empty plaintext -> header + 0 chunks + sentinel = 21 + 44 = 65 B.
    vectors.append(_build_positive(
        "S001", "Empty plaintext (only header + sentinel)",
        KEY_4, idx := idx + 1, "", frame_codepoints=8,
    ))

    # S002: single character.
    vectors.append(_build_positive(
        "S002", "Single character; one chunk with 1 real + 7 filler codepoints",
        KEY_4, idx := idx + 1, "A", frame_codepoints=8,
    ))

    # S003: exactly one full frame, no filler.
    vectors.append(_build_positive(
        "S003", "Exactly F codepoints; one full chunk, no filler",
        KEY_4, idx := idx + 1, "A" * 8, frame_codepoints=8,
    ))

    # S004: F+1 codepoints -> two chunks, last one filler-padded.
    vectors.append(_build_positive(
        "S004", "F+1 codepoints; two chunks, last one filler-padded",
        KEY_4, idx := idx + 1, "A" * 9, frame_codepoints=8,
    ))

    # S005: short message with F=8.
    vectors.append(_build_positive(
        "S005", "Nine-char message 'hello v8!' with F=8 (KAT canary)",
        KEY_13, idx := idx + 1, "hello v8!", frame_codepoints=8,
    ))

    # S006: with non-empty AAD.
    vectors.append(_build_positive(
        "S006", "Short message with non-empty AAD; F=8",
        KEY_4, idx := idx + 1, "secret payload",
        aad=b"sender=alice", frame_codepoints=8,
    ))

    # S007: long AAD (64 bytes) -- exercises 8-byte AAD length prefix.
    vectors.append(_build_positive(
        "S007", "Long AAD (64 bytes) pins the 8-byte AAD length prefix",
        KEY_4, idx := idx + 1, "aad width check",
        aad=b"L" * 64, frame_codepoints=8,
    ))

    # S008: 10-element key.
    vectors.append(_build_positive(
        "S008", "10-element key; multi-chunk plaintext",
        KEY_10, idx := idx + 1, "abcdefghijklmnop", frame_codepoints=4,
    ))

    # S009: F=1 pathological case (one real codepoint per chunk).
    vectors.append(_build_positive(
        "S009", "F=1 -- one real codepoint per chunk (pathological small F)",
        KEY_4, idx := idx + 1, "xyz", frame_codepoints=1,
    ))

    # S010: default frame (128) with a message just over one frame.
    vectors.append(_build_positive(
        "S010", "Default F=128 with a 130-char message (2 chunks, filler in 2nd)",
        KEY_13, idx := idx + 1, "z" * 130,
        frame_codepoints=napqes.STREAM_AE_V8_DEFAULT_FRAME,
    ))

    return vectors


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NAPQES v8 streaming AE KAT vector generator")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Regenerate and compare to existing file (exit 1 on mismatch)",
    )
    parser.add_argument(
        "--out",
        default=_OUT_FILE,
        help=f"Output path (default: {_OUT_FILE})",
    )
    args = parser.parse_args()

    vectors = generate()
    blob = json.dumps(
        {"spec_version": "v8-stream", "vectors": vectors}, indent=2) + "\n"

    if args.check:
        if not os.path.exists(args.out):
            print(f"FAIL: {args.out} does not exist; run without --check to generate.")
            sys.exit(1)
        with open(args.out, encoding="utf-8") as f:
            existing = f.read()
        if existing == blob:
            print(f"OK: {args.out} matches regenerated output ({len(vectors)} vectors).")
        else:
            print("FAIL: regenerated vectors differ from checked-in file.")
            print("  Run 'python tests/gen_kats_v8_stream.py' to update.")
            sys.exit(1)
    else:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob)
        print(f"Wrote {len(vectors)} vectors to {args.out}")


if __name__ == "__main__":
    main()
