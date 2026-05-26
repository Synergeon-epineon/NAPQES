"""Generate deterministic Known-Answer Test vectors for NAPSEQ v6.

Run:
    python tests/gen_kats.py                  # write tests/kat/v6_vectors.json
    python tests/gen_kats.py --check          # regenerate and compare (CI mode)

Vectors are fully deterministic: nonces are derived from a fixed seed so the
file is reproducible on any platform.  The generator uses NAPSEQ's own
internal primitives directly so that the output is authoritative — any
implementation must produce byte-identical ciphertext_hex for positive
vectors and the documented exception for negative vectors.

Output schema per vector:
  id                  unique string identifier
  kind                "positive" or "negative"
  description         human-readable note
  key                 list[int] – prime key elements
  nonce_hex           hex of the 16-byte nonce used for encryption
  message             plaintext string (positive only, absent for negatives)
  aad_hex             hex of AAD bytes ("" means empty)
  ciphertext_hex      expected encrypt_bytes() output (positive only)
  tampered_hex        modified ciphertext for negative auth-failure vectors
  expected_exception  substring of expected ValueError message (negatives)
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

_SEED_KEY = b"napseq-kat-seed-v1"
_OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kat")
_OUT_FILE = os.path.join(_OUT_DIR, "v6_vectors.json")


# ---------------------------------------------------------------------------
# Deterministic nonce derivation
# ---------------------------------------------------------------------------

def _nonce(index: int) -> bytes:
    """Derive a deterministic 16-byte nonce for vector *index*."""
    h = hmac_mod.new(
        _SEED_KEY,
        b"nonce:" + index.to_bytes(4, "big"),
        hashlib.sha256,
    ).digest()
    return h[:16]


# ---------------------------------------------------------------------------
# Encrypt-with-fixed-nonce (bypasses secrets.token_bytes)
# ---------------------------------------------------------------------------

def _encrypt_with_nonce(
    message: str,
    key: list[int],
    nonce: bytes,
    aad: bytes = b"",
) -> bytes:
    """Replicate encrypt_bytes with a caller-supplied nonce (KAT use only)."""
    kb = napqes._key_bytes(key)
    noise_p = napqes._derive_noise_p(kb, nonce)
    padded = napqes._pad_message([ord(c) for c in message], kb, nonce)
    K = len(key)

    cypher: list[int] = []
    real_idx = 0
    ct_pos = 0

    for c in padded:
        while True:
            if napqes._is_noise_pos(kb, nonce, ct_pos, noise_p):
                k = key[real_idx % K]
                noise_c = napqes._derive_noise_char(kb, nonce, ct_pos)
                noise_add = napqes._derive_noise_token_addend(kb, nonce, ct_pos, k)
                cypher.append(noise_c * k + noise_add)
                ct_pos += 1
            else:
                k = key[real_idx % K]
                addend = napqes._derive_addend(kb, nonce, real_idx, k)
                cypher.append(c * k + addend)
                ct_pos += 1
                real_idx += 1
                break

    varint_blob = napqes._b128_encode_tokens(cypher)
    ks = napqes._varint_keystream(kb, nonce, len(varint_blob))
    masked_blob = bytes(a ^ b for a, b in zip(varint_blob, ks))
    payload = nonce + masked_blob
    tag = napqes._compute_auth_tag(kb, aad, payload)
    return payload + tag


# ---------------------------------------------------------------------------
# Deterministic streaming-AE encrypt (bypasses secrets.token_bytes)
# ---------------------------------------------------------------------------

def _encrypt_stream_ae_with_nonce(
    message: str,
    key: list[int],
    nonce: bytes,
    aad: bytes = b"",
    chunk_size: int = napqes.STREAM_AE_CHUNK_SIZE,
) -> bytes:
    """Replicate encrypt_stream_ae with a caller-supplied nonce (KAT use only)."""
    kb = napqes._key_bytes(key)
    noise_p = napqes._derive_noise_p(kb, nonce)
    K = len(key)
    aad_len4 = len(aad).to_bytes(4, "big")

    result = bytearray(nonce)

    ct_pos = 0
    real_idx = 0
    ks_gen = napqes._varint_keystream_blocks(kb, nonce)
    ks_buf: bytearray = bytearray()
    pending_masked: bytearray = bytearray()
    chunk_idx = 0

    def _flush_chunk(data: bytes) -> bytes:
        tag = hmac_mod.new(
            kb,
            b"\x08" + aad_len4 + aad + nonce + chunk_idx.to_bytes(4, "big") + data,
            hashlib.sha256,
        ).digest()
        return len(data).to_bytes(4, "big") + data + tag

    for char in message:
        c = ord(char)
        buf = bytearray()
        while True:
            if napqes._is_noise_pos(kb, nonce, ct_pos, noise_p):
                k = key[real_idx % K]
                noise_c = napqes._derive_noise_char(kb, nonce, ct_pos)
                noise_add = napqes._derive_noise_token_addend(kb, nonce, ct_pos, k)
                buf.extend(napqes._b128_encode_token(noise_c * k + noise_add))
                ct_pos += 1
            else:
                k = key[real_idx % K]
                addend = napqes._derive_addend(kb, nonce, real_idx, k)
                buf.extend(napqes._b128_encode_token(c * k + addend))
                ct_pos += 1
                real_idx += 1
                break
        raw = bytes(buf)
        while len(ks_buf) < len(raw):
            ks_buf.extend(next(ks_gen))
        masked = bytes(a ^ b for a, b in zip(raw, ks_buf[: len(raw)]))
        del ks_buf[: len(raw)]
        pending_masked.extend(masked)
        while len(pending_masked) >= chunk_size:
            frame_data = bytes(pending_masked[:chunk_size])
            del pending_masked[:chunk_size]
            result.extend(_flush_chunk(frame_data))
            chunk_idx += 1

    if pending_masked:
        result.extend(_flush_chunk(bytes(pending_masked)))
        chunk_idx += 1

    final_tag = hmac_mod.new(
        kb,
        b"\x09" + aad_len4 + aad + nonce + chunk_idx.to_bytes(4, "big"),
        hashlib.sha256,
    ).digest()
    result.extend((0).to_bytes(4, "big") + final_tag)
    return bytes(result)


def _build_streaming_ae_positive(
    vec_id: str,
    description: str,
    key: list[int],
    nonce_index: int,
    message: str,
    aad: bytes = b"",
    chunk_size: int = napqes.STREAM_AE_CHUNK_SIZE,
) -> dict:
    nonce = _nonce(nonce_index)
    full_ct = _encrypt_stream_ae_with_nonce(message, key, nonce, aad, chunk_size)
    recovered = napqes.decrypt_stream_ae(iter([full_ct]), key, aad)
    recovered_str = "".join(recovered)
    assert recovered_str == message, (
        f"Streaming AE roundtrip failed for {vec_id}: got {recovered_str!r}"
    )
    return {
        "id": vec_id,
        "kind": "positive",
        "api": "stream_ae",
        "description": description,
        "key": key,
        "nonce_hex": nonce.hex(),
        "message": message,
        "aad_hex": aad.hex(),
        "chunk_size": chunk_size,
        "full_ciphertext_hex": full_ct.hex(),
    }


def _build_streaming_ae_negative(
    vec_id: str,
    description: str,
    key: list[int],
    tampered_hex: str,
    aad: bytes = b"",
    expected_exception: str = "Authentication failed",
) -> dict:
    return {
        "id": vec_id,
        "kind": "negative",
        "api": "stream_ae",
        "description": description,
        "key": key,
        "aad_hex": aad.hex(),
        "tampered_hex": tampered_hex,
        "expected_exception": expected_exception,
    }


# ---------------------------------------------------------------------------
# Vector definitions
# ---------------------------------------------------------------------------

# Keys used across vectors (all elements are prime)
KEY_4  = [1_000_003, 1_000_033, 1_000_037, 1_000_039]  # 4-element key
KEY_1  = [7_999_993]                                     # 1-element key
KEY_10 = [1_000_003, 1_000_033, 1_000_037, 1_000_039,
          1_000_081, 1_000_099, 1_000_117, 1_000_121,
          1_000_133, 1_000_151]                          # 10-element key


def _build_positive(
    vec_id: str,
    description: str,
    key: list[int],
    nonce_index: int,
    message: str,
    aad: bytes = b"",
) -> dict:
    nonce = _nonce(nonce_index)
    ct = _encrypt_with_nonce(message, key, nonce, aad)
    plaintext_back = napqes.decrypt_bytes(ct, key, aad=aad)
    assert plaintext_back == message, (
        f"Roundtrip failed for {vec_id}: got {plaintext_back!r}"
    )
    return {
        "id": vec_id,
        "kind": "positive",
        "description": description,
        "key": key,
        "nonce_hex": nonce.hex(),
        "message": message,
        "aad_hex": aad.hex(),
        "ciphertext_hex": ct.hex(),
    }


def _build_negative(
    vec_id: str,
    description: str,
    key: list[int],
    tampered_hex: str,
    aad: bytes = b"",
    expected_exception: str = "Authentication failed",
    allow_legacy: bool = False,
) -> dict:
    return {
        "id": vec_id,
        "kind": "negative",
        "description": description,
        "key": key,
        "nonce_hex": "",
        "aad_hex": aad.hex(),
        "tampered_hex": tampered_hex,
        "expected_exception": expected_exception,
        "allow_legacy_unauthenticated": allow_legacy,
    }


def generate() -> list[dict]:
    vectors: list[dict] = []
    idx = 0  # nonce index counter

    # ── Positive: boundary / coverage ─────────────────────────────────────

    # V001: empty message — must produce a full authenticated ciphertext
    vectors.append(_build_positive(
        "V001", "Empty message produces authenticated ciphertext (not empty bytes)",
        KEY_4, idx := idx + 1, "",
    ))

    # V002: single printable character
    vectors.append(_build_positive(
        "V002", "Single character 'A'", KEY_4, idx := idx + 1, "A",
    ))

    # V003: short message (< 16 chars → pads to block_size=16)
    vectors.append(_build_positive(
        "V003", "Short message (7 chars, pads to block 16)", KEY_4, idx := idx + 1,
        "Hello!!", aad=b"",
    ))

    # V004: message exactly 15 chars (pads to block_size=16)
    vectors.append(_build_positive(
        "V004", "Exactly 15 chars (pads to block 16)", KEY_4, idx := idx + 1,
        "A" * 15,
    ))

    # V005: message exactly 16 chars (pads to block_size=32)
    vectors.append(_build_positive(
        "V005", "Exactly 16 chars (pads to block 32)", KEY_4, idx := idx + 1,
        "A" * 16,
    ))

    # V006: message exactly 31 chars (pads to block 32)
    vectors.append(_build_positive(
        "V006", "Exactly 31 chars (pads to block 32)", KEY_4, idx := idx + 1,
        "B" * 31,
    ))

    # V007: message exactly 32 chars (pads to block 64)
    vectors.append(_build_positive(
        "V007", "Exactly 32 chars (pads to block 64)", KEY_4, idx := idx + 1,
        "C" * 32,
    ))

    # V008: typical plaintext — full ASCII printable range sample
    vectors.append(_build_positive(
        "V008", "Typical mixed printable ASCII", KEY_4, idx := idx + 1,
        "The quick brown fox jumps over the lazy dog.",
    ))

    # V009: message with all printable ASCII characters
    printable_ascii = "".join(chr(c) for c in range(32, 127))  # 95 chars
    vectors.append(_build_positive(
        "V009", "All printable ASCII characters (95 chars)", KEY_4, idx := idx + 1,
        printable_ascii,
    ))

    # V010: longer message (256 chars, crosses multiple block boundaries)
    vectors.append(_build_positive(
        "V010", "256-char message (pads to block 512)", KEY_4, idx := idx + 1,
        "NAPSEQ " * 36 + "END",  # 252+3 = 255 chars → pads to 256
    ))

    # V011: same message, different key (output must differ)
    vectors.append(_build_positive(
        "V011", "Same message as V003 with 1-element key", KEY_1, idx := idx + 1,
        "Hello!!",
    ))

    # V012: 10-element key
    vectors.append(_build_positive(
        "V012", "Same message with 10-element key", KEY_10, idx := idx + 1,
        "Hello!!",
    ))

    # V013: AAD non-empty
    vectors.append(_build_positive(
        "V013", "Non-empty AAD 'sender=alice'", KEY_4, idx := idx + 1,
        "secret payload", aad=b"sender=alice",
    ))

    # V014: AAD with binary content
    vectors.append(_build_positive(
        "V014", "AAD with binary content", KEY_4, idx := idx + 1,
        "payload", aad=bytes(range(0, 16)),
    ))

    # V015: same message + key, different nonce → different ciphertext
    vectors.append(_build_positive(
        "V015", "Same inputs as V003 but different nonce (V015 ≠ V003)", KEY_4, idx := idx + 1,
        "Hello!!",
    ))

    # V016: message with spaces and punctuation
    vectors.append(_build_positive(
        "V016", "Message with spaces and punctuation", KEY_4, idx := idx + 1,
        "NAPSEQ v6: 100% authenticated encryption — no plaintext leaks!",
    ))

    # V017: 128-char message (pads to block 256)
    vectors.append(_build_positive(
        "V017", "128-char message (pads to block 256)", KEY_4, idx := idx + 1,
        "x" * 128,
    ))

    # V018: 1000-char message
    vectors.append(_build_positive(
        "V018", "1000-char message", KEY_4, idx := idx + 1,
        "y" * 1000,
    ))

    # V019: single-char message with AAD
    vectors.append(_build_positive(
        "V019", "Single char with non-empty AAD", KEY_4, idx := idx + 1,
        "Z", aad=b"context=test",
    ))

    # V020: message that exercises all key positions (K=4, len>4)
    vectors.append(_build_positive(
        "V020", "Message longer than key (exercises key rotation)", KEY_4, idx := idx + 1,
        "ABCDEFGHIJ",  # 10 chars, rotates through 4-element key
    ))

    # ── Negative: tag tampered ─────────────────────────────────────────────

    # Build a valid ciphertext, then tamper its last byte
    nonce_neg = _nonce(idx := idx + 1)
    ct_neg = _encrypt_with_nonce("tamper test", KEY_4, nonce_neg)
    tampered = ct_neg[:-1] + bytes([ct_neg[-1] ^ 0xFF])  # flip last tag byte

    vectors.append(_build_negative(
        "N001", "Auth tag tampered (last byte XOR 0xFF)",
        KEY_4, tampered.hex(),
        expected_exception="Authentication failed",
    ))

    # N002: tag truncated — ciphertext shorter than nonce+tag
    vectors.append(_build_negative(
        "N002", "Ciphertext shorter than minimum (nonce+tag = 48 bytes)",
        KEY_4, (b"\x00" * 20).hex(),
        expected_exception="not a valid authenticated v6 payload",
    ))

    # N003: correct ciphertext but wrong key → tag mismatch
    nonce_n3 = _nonce(idx := idx + 1)
    ct_n3 = _encrypt_with_nonce("wrong key test", KEY_4, nonce_n3)
    vectors.append(_build_negative(
        "N003", "Correct ciphertext decrypted with wrong key",
        KEY_1, ct_n3.hex(),
        expected_exception="Authentication failed",
    ))

    # N004: correct ciphertext but wrong AAD → tag mismatch
    nonce_n4 = _nonce(idx := idx + 1)
    ct_n4 = _encrypt_with_nonce("aad test", KEY_4, nonce_n4, aad=b"correct-aad")
    vectors.append(_build_negative(
        "N004", "Correct ciphertext decrypted with wrong AAD",
        KEY_4, ct_n4.hex(),
        aad=b"wrong-aad",
        expected_exception="Authentication failed",
    ))

    # N005: legacy v5-style blob (no tag) without allow_legacy_unauthenticated
    # Build a v5-style blob: just nonce || varint_blob (no tag)
    nonce_n5 = _nonce(idx := idx + 1)
    kb_n5 = napqes._key_bytes(KEY_4)
    noise_p_n5 = napqes._derive_noise_p(kb_n5, nonce_n5)
    padded_n5 = napqes._pad_message([ord(c) for c in "legacy"], kb_n5, nonce_n5)
    cypher_n5: list[int] = []
    real_idx_n5 = 0
    ct_pos_n5 = 0
    K4 = len(KEY_4)
    for c in padded_n5:
        while True:
            if napqes._is_noise_pos(kb_n5, nonce_n5, ct_pos_n5, noise_p_n5):
                k = KEY_4[real_idx_n5 % K4]
                nc = napqes._derive_noise_char(kb_n5, nonce_n5, ct_pos_n5)
                na = napqes._derive_noise_token_addend(kb_n5, nonce_n5, ct_pos_n5, k)
                cypher_n5.append(nc * k + na)
                ct_pos_n5 += 1
            else:
                k = KEY_4[real_idx_n5 % K4]
                a = napqes._derive_addend(kb_n5, nonce_n5, real_idx_n5, k)
                cypher_n5.append(c * k + a)
                ct_pos_n5 += 1
                real_idx_n5 += 1
                break
    v5_blob = nonce_n5 + napqes._b128_encode_tokens(cypher_n5)  # no tag
    vectors.append(_build_negative(
        "N005",
        "v5 unauthenticated blob rejected without allow_legacy_unauthenticated",
        KEY_4, v5_blob.hex(),
        expected_exception="Authentication failed",
    ))

    # N006: first byte of nonce zeroed (tag will mismatch)
    nonce_n6 = _nonce(idx := idx + 1)
    ct_n6 = _encrypt_with_nonce("nonce tamper", KEY_4, nonce_n6)
    tampered_n6 = bytes([ct_n6[0] ^ 0x01]) + ct_n6[1:]
    vectors.append(_build_negative(
        "N006", "First byte of nonce flipped (tag will not match)",
        KEY_4, tampered_n6.hex(),
        expected_exception="Authentication failed",
    ))

    # ── Determinism and nonce-reuse documentation vectors ─────────────────

    # V021: same (key, nonce, message, aad) as V003 → identical ciphertext.
    # Verifies that the construction is fully deterministic given (key, nonce,
    # plaintext); required property for cross-implementation KAT parity.
    v003 = next(v for v in vectors if v["id"] == "V003")
    v021_nonce = bytes.fromhex(v003["nonce_hex"])
    v021_ct = _encrypt_with_nonce("Hello!!", KEY_4, v021_nonce)
    assert v021_ct.hex() == v003["ciphertext_hex"], (
        "Determinism failure: V021 ciphertext != V003 ciphertext"
    )
    vectors.append({
        "id": "V021",
        "kind": "positive",
        "description": (
            "Determinism: same (key, nonce, message, aad) as V003 must produce "
            "bit-identical ciphertext (cross-implementation KAT parity)"
        ),
        "key": KEY_4,
        "nonce_hex": v021_nonce.hex(),
        "message": "Hello!!",
        "aad_hex": "",
        "ciphertext_hex": v021_ct.hex(),
    })

    # V022: same (key, nonce) as V003/V021 but different message → different
    # ciphertext.  Documents that nonce-reuse with a different plaintext yields
    # a different output (semantic-security documentation vector).
    v022_nonce = v021_nonce  # same nonce as V003/V021
    v022_ct = _encrypt_with_nonce("World!!", KEY_4, v022_nonce)
    assert v022_ct.hex() != v021_ct.hex(), (
        "Security failure: same nonce with different message produced identical ciphertext"
    )
    vectors.append({
        "id": "V022",
        "kind": "positive",
        "description": (
            "Nonce-reuse, different message: same (key, nonce) with different plaintext "
            "produces a different ciphertext (semantic-security documentation)"
        ),
        "key": KEY_4,
        "nonce_hex": v022_nonce.hex(),
        "message": "World!!",
        "aad_hex": "",
        "ciphertext_hex": v022_ct.hex(),
    })

    # ── Negative: single-bit AAD tamper ───────────────────────────────────

    # N007: ciphertext correct for aad_n7_enc; decryption uses aad with last
    # byte XOR'd by 0x01 (one-bit change in the AAD) → tag must not verify.
    # Demonstrates that AAD binding is sensitive to single-bit changes.
    nonce_n7 = _nonce(idx := idx + 1)
    aad_n7_enc = b"aad-reference"
    ct_n7 = _encrypt_with_nonce("aad binding test", KEY_4, nonce_n7, aad=aad_n7_enc)
    aad_n7_bad = aad_n7_enc[:-1] + bytes([aad_n7_enc[-1] ^ 0x01])
    vectors.append(_build_negative(
        "N007",
        "AAD tampered by 1 bit (last byte XOR 0x01): auth tag must not verify",
        KEY_4, ct_n7.hex(),
        aad=aad_n7_bad,
        expected_exception="Authentication failed",
    ))

    # N009: empty ciphertext must be rejected (not silently return "")
    vectors.append(_build_negative(
        "N009", "Empty ciphertext rejected: no nonce, no tag, no authentication",
        KEY_4, "",
        expected_exception="not a valid authenticated v6 payload",
    ))

    # N008: v3-format colon-delimited string encoded as raw bytes.  When fed
    # to decrypt_bytes (which expects v6 binary), the bytes are >= 48 so the
    # too-short guard is not triggered; instead the last 32 bytes are treated
    # as an auth tag that will not verify → "Authentication failed".
    # Demonstrates that old colon-delimited blobs are not silently decoded.
    nonce_n8 = _nonce(idx := idx + 1)
    token_hex_placeholder = " ".join(f"{i:06x}" for i in range(10))
    v3_str_n8 = f"{nonce_n8.hex()}:3f800000:{token_hex_placeholder}"
    v3_bytes_n8 = v3_str_n8.encode("ascii")
    assert len(v3_bytes_n8) >= 48, (
        f"N008 blob too short ({len(v3_bytes_n8)} bytes); auth-mismatch path requires >= 48"
    )
    vectors.append(_build_negative(
        "N008",
        "v3-format string as raw bytes: rejected by decrypt_bytes (auth tag mismatch)",
        KEY_4, v3_bytes_n8.hex(),
        expected_exception="Authentication failed",
    ))

    # ── Streaming AE (encrypt_stream_ae / decrypt_stream_ae) ──────────────

    # SA001: empty message
    vectors.append(_build_streaming_ae_positive(
        "SA001", "Streaming AE: empty message produces nonce + sentinel only",
        KEY_4, idx := idx + 1, "",
    ))

    # SA002: short message (single chunk)
    vectors.append(_build_streaming_ae_positive(
        "SA002", "Streaming AE: short message (single chunk)",
        KEY_4, idx := idx + 1, "Hello, streaming world!",
    ))

    # SA003: multi-chunk message (small chunk_size to force >1 frame)
    vectors.append(_build_streaming_ae_positive(
        "SA003", "Streaming AE: multi-chunk message (chunk_size=32)",
        KEY_4, idx := idx + 1, "A" * 200,
        chunk_size=32,
    ))

    # SA004: non-empty AAD
    vectors.append(_build_streaming_ae_positive(
        "SA004", "Streaming AE: non-empty AAD",
        KEY_4, idx := idx + 1, "payload with AAD",
        aad=b"sender=alice",
    ))

    # SA005: tampered chunk tag → auth failure
    nonce_sa5 = _nonce(idx := idx + 1)
    ct_sa5 = _encrypt_stream_ae_with_nonce("tamper-me", KEY_4, nonce_sa5)
    # Flip the last byte of the first chunk tag (bytes 16+4+blob_len .. +32)
    # Simplest: flip last byte of the whole stream (hits final_tag)
    tampered_sa5 = ct_sa5[:-1] + bytes([ct_sa5[-1] ^ 0xFF])
    vectors.append(_build_streaming_ae_negative(
        "SA005",
        "Streaming AE: final tag flipped (last byte XOR 0xFF) → auth failure",
        KEY_4, tampered_sa5.hex(),
        expected_exception="Authentication failed",
    ))

    # SA006: wrong key for decrypt
    nonce_sa6 = _nonce(idx := idx + 1)
    ct_sa6 = _encrypt_stream_ae_with_nonce("wrong-key test", KEY_4, nonce_sa6)
    vectors.append(_build_streaming_ae_negative(
        "SA006",
        "Streaming AE: correct ciphertext decrypted with wrong key → auth failure",
        KEY_1, ct_sa6.hex(),
        expected_exception="Authentication failed",
    ))

    return vectors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="NAPSEQ v6 KAT vector generator")
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
    blob = json.dumps({"spec_version": "v6", "vectors": vectors}, indent=2) + "\n"

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
            print("  Run 'python tests/gen_kats.py' to update.")
            sys.exit(1)
    else:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob)
        print(f"Wrote {len(vectors)} vectors to {args.out}")


if __name__ == "__main__":
    main()
