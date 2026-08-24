"""Generate deterministic Known-Answer Test vectors for NAPQES v8 block mode.

v8 is *misuse-resistant*: the nonce is a synthetic IV derived from
``(sk_fmt, aad, message)`` under domain ``0x0A``, and every derivation is
keyed by the domain-``0x0B`` format subkey
``sk_fmt = HMAC(sk, 0x0B || FORMAT_BLOCK_V8)`` rather than by ``sk`` itself.
Encryption is therefore a pure function of ``(primes, sk, aad, message)`` —
no nonce needs to be injected, so these vectors exercise the *public*
``napqes.encrypt_bytes_v8`` API directly rather than a KAT-only
fixed-nonce reimplementation (unlike the v7 generator, ``gen_kats.py``).

These vectors exist specifically to pin cross-language v8 parity: the v7
corpus (``tests/kat/v6_vectors.json``) does not cover v8 at all, which is
how the Rust port's missing format subkey went undetected until the
third-round audit follow-up (see ``docs/CAVEATS.md``, V3-CVF1 Residual 4).

Run:
    python tests/gen_kats_v8.py                  # write tests/kat/v8_vectors.json
    python tests/gen_kats_v8.py --check          # regenerate and compare (CI mode)

Output schema per vector:
  id                  unique string identifier
  kind                "positive" or "negative"
  description         human-readable note
  key                 list[int] – prime key elements
  sk_hex              hex of the 32-byte independent HMAC subkey ``sk``
  message             plaintext string (positive only)
  aad_hex             hex of AAD bytes ("" means empty)
  ciphertext_hex      expected encrypt_bytes_v8() output (positive only)
  tampered_hex        ciphertext that must fail to decrypt (negative only)
  expected_exception  substring of the expected ValueError message (negative)
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

_SEED_KEY = b"napseq-kat-seed-v8"
_OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kat")
_OUT_FILE = os.path.join(_OUT_DIR, "v8_vectors.json")

# Keys used across vectors (all elements are prime); identical to the v7
# corpus so that a v7/v8 divergence cannot be blamed on differing key material.
KEY_4 = [1_000_003, 1_000_033, 1_000_037, 1_000_039]
KEY_1 = [7_999_993]
KEY_10 = [1_000_003, 1_000_033, 1_000_037, 1_000_039,
          1_000_081, 1_000_099, 1_000_117, 1_000_121,
          1_000_133, 1_000_151]


def _sk(index: int) -> bytes:
    """Derive a deterministic 32-byte v8 subkey for vector *index*."""
    return hmac_mod.new(
        _SEED_KEY,
        b"sk:" + index.to_bytes(4, "big"),
        hashlib.sha256,
    ).digest()


def _build_positive(
    vec_id: str,
    description: str,
    key: list[int],
    sk_index: int,
    message: str,
    aad: bytes = b"",
) -> dict:
    sk = _sk(sk_index)
    ct = napqes.encrypt_bytes_v8(message, key, sk, aad=aad)
    back = napqes.decrypt_bytes_v8(ct, key, sk, aad=aad)
    assert back == message, f"Roundtrip failed for {vec_id}: got {back!r}"
    return {
        "id": vec_id,
        "kind": "positive",
        "description": description,
        "key": key,
        "sk_hex": sk.hex(),
        "message": message,
        "aad_hex": aad.hex(),
        "ciphertext_hex": ct.hex(),
    }


def _build_negative(
    vec_id: str,
    description: str,
    key: list[int],
    sk: bytes,
    tampered: bytes,
    aad: bytes = b"",
    expected_exception: str = "Authentication failed",
) -> dict:
    return {
        "id": vec_id,
        "kind": "negative",
        "description": description,
        "key": key,
        "sk_hex": sk.hex(),
        "aad_hex": aad.hex(),
        "tampered_hex": tampered.hex(),
        "expected_exception": expected_exception,
    }


def _retag(original_ct: bytes, sk: bytes, aad: bytes, new_masked_blob: bytes) -> bytes:
    """Rebuild a ciphertext around *new_masked_blob* with a **valid** tag.

    Reuses the nonce from *original_ct* and recomputes the domain-0x03 tag
    over the new payload, so the result passes tag verification and the
    decryptor is forced all the way into the structural checks that
    V3-CVF8 added.  Used only to build negative vectors.
    """
    nonce = original_ct[:napqes._NONCE_SIZE]
    sk_fmt = napqes._derive_format_subkey(sk, napqes.FORMAT_BLOCK_V8)
    payload = nonce + new_masked_blob
    tag = napqes._compute_auth_tag(sk_fmt, aad, payload, napqes._AAD_LEN_WIDTH_V8)
    return payload + tag


def _oversized_length_prefix_ct(key: list[int], sk: bytes) -> bytes:
    """Encrypt with a deliberately inflated 2-codepoint length prefix.

    Produces a validly tagged ciphertext whose decrypted padded buffer
    claims more codepoints than it holds, exercising the ``2 + n <= R``
    guard in every port (V3-CVF8).
    """
    real_pad = napqes._pad_message

    def _bogus_pad(msg, kb, nonce, pad_profile=napqes.PAD_BUCKET):
        padded = real_pad(msg, kb, nonce, pad_profile)
        inflated = len(padded)  # > len(padded) - 2, so 2 + n > len(padded)
        padded[0] = inflated >> 8
        padded[1] = inflated & 0xFF
        return padded

    napqes._pad_message = _bogus_pad
    try:
        return napqes.encrypt_bytes_v8("prefix-overflow", key, sk, aad=b"")
    finally:
        napqes._pad_message = real_pad


def generate() -> list[dict]:
    vectors: list[dict] = []
    idx = 0

    # ── Positive: boundary / coverage ────────────────────────────────────

    # W001: empty message — v8 pads it through the normal path, so the
    # output is a full 2928-byte authenticated ciphertext, NOT empty bytes.
    vectors.append(_build_positive(
        "W001", "Empty message produces a full authenticated ciphertext",
        KEY_4, idx := idx + 1, "",
    ))

    vectors.append(_build_positive(
        "W002", "Single character 'A'", KEY_4, idx := idx + 1, "A",
    ))

    vectors.append(_build_positive(
        "W003", "Short message (7 chars, pads to block 16)",
        KEY_4, idx := idx + 1, "Hello!!",
    ))

    vectors.append(_build_positive(
        "W004", "Exactly 15 chars (pads to block 16)",
        KEY_4, idx := idx + 1, "A" * 15,
    ))

    vectors.append(_build_positive(
        "W005", "Exactly 16 chars (pads to block 32)",
        KEY_4, idx := idx + 1, "A" * 16,
    ))

    vectors.append(_build_positive(
        "W006", "Exactly 32 chars (pads to block 64)",
        KEY_4, idx := idx + 1, "C" * 32,
    ))

    vectors.append(_build_positive(
        "W007", "Same message as W003 with 1-element key",
        KEY_1, idx := idx + 1, "Hello!!",
    ))

    vectors.append(_build_positive(
        "W008", "Same message as W003 with 10-element key",
        KEY_10, idx := idx + 1, "Hello!!",
    ))

    vectors.append(_build_positive(
        "W009", "Non-empty AAD 'sender=alice'",
        KEY_4, idx := idx + 1, "secret payload", aad=b"sender=alice",
    ))

    vectors.append(_build_positive(
        "W010", "AAD with binary content (bytes 0x00-0x0f)",
        KEY_4, idx := idx + 1, "payload", aad=bytes(range(0, 16)),
    ))

    # W011: exercises the 8-byte AAD length prefix (V3-CVF1) against a
    # long AAD whose length would still fit a 4-byte prefix — a decryptor
    # using the wrong width fails here even though the length is small.
    vectors.append(_build_positive(
        "W011", "Long AAD (64 bytes) — pins the 8-byte AAD length prefix",
        KEY_4, idx := idx + 1, "aad width check", aad=b"L" * 64,
    ))

    vectors.append(_build_positive(
        "W012", "Message with punctuation and mixed case",
        KEY_10, idx := idx + 1, "Hello, CVF1!", aad=b"aad-test",
    ))

    # ── Negative: authentication must fail ───────────────────────────────

    sk_n1 = _sk(idx := idx + 1)
    ct_n1 = napqes.encrypt_bytes_v8("tamper-me", KEY_4, sk_n1, aad=b"")
    vectors.append(_build_negative(
        "W-N01", "Final tag byte flipped (XOR 0xff) -> auth failure",
        KEY_4, sk_n1, ct_n1[:-1] + bytes([ct_n1[-1] ^ 0xFF]),
    ))

    sk_n2 = _sk(idx := idx + 1)
    ct_n2 = napqes.encrypt_bytes_v8("aad-bound", KEY_4, sk_n2, aad=b"right-aad")
    vectors.append(_build_negative(
        "W-N02", "Correct ciphertext verified under the wrong AAD -> auth failure",
        KEY_4, sk_n2, ct_n2, aad=b"wrong-aad",
    ))

    sk_n3 = _sk(idx := idx + 1)
    ct_n3 = napqes.encrypt_bytes_v8("masked-blob", KEY_4, sk_n3, aad=b"")
    vectors.append(_build_negative(
        "W-N03", "First masked-blob byte flipped (XOR 0x01) -> auth failure",
        KEY_4, sk_n3,
        ct_n3[:16] + bytes([ct_n3[16] ^ 0x01]) + ct_n3[17:],
    ))

    sk_n4 = _sk(idx := idx + 1)
    vectors.append(_build_negative(
        "W-N04", "Ciphertext shorter than nonce+tag -> parse failure",
        KEY_4, sk_n4, bytes(47),
        expected_exception="too short",
    ))

    sk_n5 = _sk(idx := idx + 1)
    ct_n5 = napqes.encrypt_bytes_v8("wrong-key test", KEY_4, sk_n5, aad=b"")
    vectors.append(_build_negative(
        "W-N05", "Correct ciphertext decrypted under the wrong sk -> auth failure",
        KEY_4, _sk(idx := idx + 1), ct_n5,
    ))

    # ── Negative: structurally malformed but *validly tagged* (V3-CVF8) ───
    # These are the cases a decryptor only reaches after the tag verifies,
    # so they cannot be produced by an attacker without sk. They exist to
    # pin that every port rejects them rather than mis-parsing, panicking,
    # or allocating against an attacker-chosen token count.

    sk_n6 = _sk(idx := idx + 1)
    ct_n6 = napqes.encrypt_bytes_v8("token-count", KEY_4, sk_n6, aad=b"")
    vectors.append(_build_negative(
        "W-N06",
        "Blob truncated by one token: token count no longer a multiple of "
        "(MAX_NOISE_RUN + 1); re-tagged so the failure is structural",
        KEY_4, sk_n6,
        _retag(ct_n6, sk_n6, b"", ct_n6[16:-32][:-napqes._TOKEN_WIDTH]),
        expected_exception="not a multiple of the padding ceiling",
    ))

    sk_n7 = _sk(idx := idx + 1)
    ct_n7 = napqes.encrypt_bytes_v8("bucket-check", KEY_4, sk_n7, aad=b"")
    # 20 real tokens is a legal multiple of the ceiling unit but is not
    # B + 2 for any reachable block size B in {16, 32, ..., 65536}.
    _illegal_blob_len = 20 * (napqes.MAX_NOISE_RUN + 1) * napqes._TOKEN_WIDTH
    vectors.append(_build_negative(
        "W-N07",
        "Real-token count 20 is a legal multiple of the ceiling unit but is "
        "not B + 2 for any reachable padded block size; re-tagged",
        KEY_4, sk_n7,
        _retag(ct_n7, sk_n7, b"", bytes(_illegal_blob_len)),
        expected_exception="reachable padded block size",
    ))

    sk_n8 = _sk(idx := idx + 1)
    vectors.append(_build_negative(
        "W-N08",
        "Padded length prefix claims more codepoints than the padded buffer "
        "holds; re-tagged so the failure is structural",
        KEY_4, sk_n8,
        _oversized_length_prefix_ct(KEY_4, sk_n8),
        expected_exception="exceeds available data",
    ))

    return vectors


def main() -> None:
    parser = argparse.ArgumentParser(description="NAPQES v8 KAT vector generator")
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
    blob = json.dumps({"spec_version": "v8", "vectors": vectors}, indent=2) + "\n"

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
            print("  Run 'python tests/gen_kats_v8.py' to update.")
            sys.exit(1)
    else:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob)
        print(f"Wrote {len(vectors)} vectors to {args.out}")


if __name__ == "__main__":
    main()
