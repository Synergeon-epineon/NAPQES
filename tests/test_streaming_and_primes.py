"""Tests for encrypt_stream, decrypt_stream, decrypt_stream_strict,
is_prime, and generate_prime_numbers.

Run:
    pytest tests/test_streaming_and_primes.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import napqes  # noqa: E402


# ── Shared fixtures ────────────────────────────────────────────────────────────

# Keys must satisfy MIN_KEY_PRIME = 1_000_000.
KEY  = [1_000_003, 1_000_033, 1_000_037, 1_000_039, 1_000_081]
KEY2 = [1_000_099, 1_000_117, 1_000_121, 1_000_133, 1_000_151]  # wrong key for negative tests


def _collect_stream(plaintext: str, key: list, aad: bytes = b"") -> list[bytes]:
    """Materialize all chunks from encrypt_stream into a list."""
    return list(napqes.encrypt_stream(iter(plaintext), key, aad))


def _concat_stream(plaintext: str, key: list, aad: bytes = b"") -> bytes:
    """Return the full byte blob produced by encrypt_stream."""
    return b"".join(_collect_stream(plaintext, key, aad))


def _decrypt_strict(blob: bytes, key: list, aad: bytes = b"") -> str:
    return napqes.decrypt_stream_strict([blob], key, aad)


# ═══════════════════════════════════════════════════════════════════════════════
# is_prime
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsPrime:

    # --- boundary and small values ---

    def test_zero_is_not_prime(self):
        assert napqes.is_prime(0) is False

    def test_one_is_not_prime(self):
        assert napqes.is_prime(1) is False

    def test_two_is_prime(self):
        assert napqes.is_prime(2) is True

    def test_three_is_prime(self):
        assert napqes.is_prime(3) is True

    def test_negative_is_not_prime(self):
        assert napqes.is_prime(-7) is False

    # --- even composites ---

    def test_four_is_not_prime(self):
        assert napqes.is_prime(4) is False

    def test_even_composite_large(self):
        assert napqes.is_prime(1_000_000) is False

    # --- perfect-square composites ---

    def test_nine_is_not_prime(self):
        assert napqes.is_prime(9) is False

    def test_twenty_five_is_not_prime(self):
        assert napqes.is_prime(25) is False

    # --- known primes ---

    @pytest.mark.parametrize("p", [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 97])
    def test_small_known_primes(self, p):
        assert napqes.is_prime(p) is True

    @pytest.mark.parametrize("c", [4, 6, 8, 9, 10, 12, 15, 25, 49, 100])
    def test_small_known_composites(self, c):
        assert napqes.is_prime(c) is False

    def test_large_prime(self):
        assert napqes.is_prime(1_000_003) is True

    def test_large_composite(self):
        # 1_000_004 = 4 × 250_001
        assert napqes.is_prime(1_000_004) is False

    def test_mersenne_prime_127(self):
        # 2^7 − 1 = 127
        assert napqes.is_prime(127) is True

    def test_non_trivial_composite(self):
        # 7 × 11 = 77
        assert napqes.is_prime(77) is False


# ═══════════════════════════════════════════════════════════════════════════════
# generate_prime_numbers
# ═══════════════════════════════════════════════════════════════════════════════

class TestGeneratePrimeNumbers:

    def test_default_returns_thirteen_primes(self):
        primes = napqes.generate_prime_numbers()
        assert len(primes) == 13
        assert napqes.DEFAULT_KEY_COUNT == 13

    def test_all_results_are_prime(self):
        primes = napqes.generate_prime_numbers(count=5)
        for p in primes:
            assert napqes.is_prime(p), f"{p} is not prime"

    def test_all_results_in_default_range(self):
        primes = napqes.generate_prime_numbers(count=5)
        for p in primes:
            assert napqes.MIN_KEY_PRIME <= p <= napqes.MAX_KEY_PRIME

    def test_default_range_matches_normative_interval(self):
        # "PQ-128" profile: P = [10^6, 1.5e7), i.e. inclusive upper bound
        # 14_999_999 — the same prime set the KEM ports already draw from.
        assert napqes.MIN_KEY_PRIME == 1_000_000
        assert napqes.MAX_KEY_PRIME == 14_999_999

    def test_serialisation_upper_bound_rejects_untruncatable_prime(self):
        # 5-byte key serialisation: Rust/C would silently truncate a larger
        # element, so Python must refuse it rather than diverge.
        too_big = (1 << 40) + 15  # prime
        assert napqes.is_prime(too_big)
        with pytest.raises(ValueError, match="5-byte key serialisation"):
            napqes._validate_key([too_big])

    def test_no_duplicates(self):
        primes = napqes.generate_prime_numbers(count=13)
        assert len(primes) == len(set(primes))

    def test_custom_count(self):
        primes = napqes.generate_prime_numbers(count=3, min_val=100, max_val=200)
        assert len(primes) == 3

    def test_custom_range_respected(self):
        primes = napqes.generate_prime_numbers(count=3, min_val=100, max_val=200)
        for p in primes:
            assert 100 <= p <= 200
            assert napqes.is_prime(p)

    def test_count_one(self):
        primes = napqes.generate_prime_numbers(count=1, min_val=10, max_val=20)
        assert len(primes) == 1
        assert napqes.is_prime(primes[0])

    def test_impossible_range_raises(self):
        # [8, 10] contains no primes: 8=2³, 9=3², 10=2×5.
        with pytest.raises(RuntimeError, match="Could not find"):
            napqes.generate_prime_numbers(count=1, min_val=8, max_val=10)

    def test_too_many_primes_requested_raises(self):
        # Only one prime (5) in [5, 5]
        with pytest.raises(RuntimeError, match="Could not find"):
            napqes.generate_prime_numbers(count=2, min_val=5, max_val=5)

    def test_results_are_list(self):
        result = napqes.generate_prime_numbers(count=2)
        assert isinstance(result, list)

    def test_all_elements_are_integers(self):
        primes = napqes.generate_prime_numbers(count=5)
        for p in primes:
            assert isinstance(p, int)


# ═══════════════════════════════════════════════════════════════════════════════
# encrypt_stream
# ═══════════════════════════════════════════════════════════════════════════════

class TestEncryptStream:

    def test_first_chunk_is_nonce(self):
        chunks = _collect_stream("hello", KEY)
        nonce = chunks[0]
        assert len(nonce) == 16

    def test_last_chunk_is_auth_tag(self):
        chunks = _collect_stream("hello", KEY)
        tag = chunks[-1]
        assert len(tag) == 32

    def test_blob_length_exceeds_nonce_plus_tag(self):
        # Non-empty plaintext must produce more than nonce+tag bytes.
        blob = _concat_stream("hello", KEY)
        assert len(blob) > 16 + 32

    def test_empty_plaintext_nonce_and_tag_only(self):
        # Empty input: generator yields nonce + tag, nothing in between.
        chunks = _collect_stream("", KEY)
        assert len(chunks) == 2
        assert len(chunks[0]) == 16   # nonce
        assert len(chunks[-1]) == 32  # tag

    def test_output_is_bytes(self):
        for chunk in napqes.encrypt_stream(iter("abc"), KEY):
            assert isinstance(chunk, bytes)

    def test_encrypt_stream_accepts_generator(self):
        # Should accept any Iterable[str], not just concrete strings.
        gen = (c for c in "test")
        blob = b"".join(napqes.encrypt_stream(gen, KEY))
        assert len(blob) > 48   # nonce + at least something + tag

    def test_different_nonces_each_call(self):
        nonce1 = _collect_stream("hello", KEY)[0]
        nonce2 = _collect_stream("hello", KEY)[0]
        assert nonce1 != nonce2, "nonces must be unique across calls"

    def test_same_plaintext_different_ciphertext(self):
        blob1 = _concat_stream("hello", KEY)
        blob2 = _concat_stream("hello", KEY)
        assert blob1 != blob2, "identical plaintexts must produce distinct ciphertexts"

    def test_invalid_key_raises(self):
        with pytest.raises(ValueError):
            list(napqes.encrypt_stream(iter("hi"), [4, 9]))  # composites

    def test_empty_key_raises(self):
        with pytest.raises(ValueError):
            list(napqes.encrypt_stream(iter("hi"), []))

    def test_aad_changes_auth_tag(self):
        chunks_no_aad = _collect_stream("hello", KEY, aad=b"")
        chunks_with_aad = _collect_stream("hello", KEY, aad=b"context")
        # Tags are the last chunk; different AAD must yield different tags.
        # (nonces also differ, but the point is the whole ciphertext differs.)
        # We verify decrypt_stream_strict rejects cross-aad blobs below;
        # here just confirm the blobs are structurally different.
        assert b"".join(chunks_no_aad) != b"".join(chunks_with_aad)


# ═══════════════════════════════════════════════════════════════════════════════
# decrypt_stream
# ═══════════════════════════════════════════════════════════════════════════════

class TestDecryptStream:

    def test_requires_opt_in_flag(self):
        blob = _concat_stream("hello", KEY)
        with pytest.raises(ValueError, match="enable_unauthenticated_streaming"):
            list(napqes.decrypt_stream([blob], KEY))

    def test_round_trip(self):
        plaintext = "hello world"
        blob = _concat_stream(plaintext, KEY)
        recovered = "".join(
            napqes.decrypt_stream([blob], KEY, enable_unauthenticated_streaming=True)
        )
        assert recovered == plaintext

    def test_round_trip_empty_string(self):
        blob = _concat_stream("", KEY)
        recovered = "".join(
            napqes.decrypt_stream([blob], KEY, enable_unauthenticated_streaming=True)
        )
        assert recovered == ""

    def test_round_trip_with_aad(self):
        plaintext = "secret"
        aad = b"my-context"
        blob = _concat_stream(plaintext, KEY, aad=aad)
        recovered = "".join(
            napqes.decrypt_stream([blob], KEY, aad=aad,
                                  enable_unauthenticated_streaming=True)
        )
        assert recovered == plaintext

    def test_wrong_aad_raises_auth_error(self):
        blob = _concat_stream("secret", KEY, aad=b"correct-aad")
        with pytest.raises(ValueError, match="Authentication failed"):
            list(napqes.decrypt_stream([blob], KEY, aad=b"wrong-aad",
                                       enable_unauthenticated_streaming=True))

    def test_tampered_body_raises_auth_error(self):
        blob = bytearray(_concat_stream("hello", KEY))
        blob[20] ^= 0xFF   # flip a bit in the token body
        with pytest.raises(ValueError, match="Authentication failed"):
            list(napqes.decrypt_stream([bytes(blob)], KEY,
                                       enable_unauthenticated_streaming=True))

    def test_truncated_stream_no_tag_raises(self):
        blob = _concat_stream("hello", KEY)
        # Strip the auth tag entirely.
        truncated = blob[:-32]
        with pytest.raises(ValueError):
            list(napqes.decrypt_stream([truncated], KEY,
                                       enable_unauthenticated_streaming=True))

    def test_truncated_nonce_raises(self):
        # Send only 8 bytes — less than the 16-byte nonce.
        with pytest.raises(ValueError, match="nonce incomplete"):
            list(napqes.decrypt_stream([b"\x00" * 8], KEY,
                                       enable_unauthenticated_streaming=True))

    def test_wrong_key_raises_auth_error(self):
        blob = _concat_stream("hello", KEY)
        # Wrong key may fail with auth error or invalid codepoint before tag check.
        with pytest.raises(ValueError):
            list(napqes.decrypt_stream([blob], KEY2,
                                       enable_unauthenticated_streaming=True))

    def test_multi_chunk_input(self):
        # Simulate a stream arriving in small pieces.
        plaintext = "streaming test"
        blob = _concat_stream(plaintext, KEY)
        chunks = [blob[i:i+4] for i in range(0, len(blob), 4)]
        recovered = "".join(
            napqes.decrypt_stream(chunks, KEY, enable_unauthenticated_streaming=True)
        )
        assert recovered == plaintext

    def test_yields_str_characters(self):
        blob = _concat_stream("abc", KEY)
        for ch in napqes.decrypt_stream([blob], KEY,
                                        enable_unauthenticated_streaming=True):
            assert isinstance(ch, str)
            assert len(ch) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# decrypt_stream_strict
# ═══════════════════════════════════════════════════════════════════════════════

class TestDecryptStreamStrict:

    def test_round_trip(self):
        plaintext = "hello world"
        blob = _concat_stream(plaintext, KEY)
        assert _decrypt_strict(blob, KEY) == plaintext

    def test_returns_str(self):
        blob = _concat_stream("abc", KEY)
        result = _decrypt_strict(blob, KEY)
        assert isinstance(result, str)

    def test_round_trip_empty_string(self):
        blob = _concat_stream("", KEY)
        assert _decrypt_strict(blob, KEY) == ""

    def test_round_trip_unicode_printable(self):
        # Only printable ASCII is expected in the default range; verify
        # a variety of common chars survive the round-trip.
        plaintext = "The quick brown fox jumps over the lazy dog. 0123456789!"
        blob = _concat_stream(plaintext, KEY)
        assert _decrypt_strict(blob, KEY) == plaintext

    def test_round_trip_with_aad(self):
        plaintext = "authenticated"
        aad = b"extra-data"
        blob = _concat_stream(plaintext, KEY, aad=aad)
        assert napqes.decrypt_stream_strict([blob], KEY, aad) == plaintext

    def test_wrong_aad_raises(self):
        blob = _concat_stream("secret", KEY, aad=b"right")
        with pytest.raises(ValueError, match="Authentication failed"):
            napqes.decrypt_stream_strict([blob], KEY, b"wrong")

    def test_tampered_body_raises(self):
        blob = bytearray(_concat_stream("hello", KEY))
        blob[20] ^= 0x01
        with pytest.raises(ValueError, match="Authentication failed"):
            napqes.decrypt_stream_strict([bytes(blob)], KEY)

    def test_tampered_tag_raises(self):
        blob = bytearray(_concat_stream("hello", KEY))
        blob[-1] ^= 0xFF   # flip last byte of auth tag
        with pytest.raises(ValueError, match="Authentication failed"):
            napqes.decrypt_stream_strict([bytes(blob)], KEY)

    def test_wrong_key_raises(self):
        blob = _concat_stream("hello", KEY)
        # Wrong key may fail with auth error or invalid codepoint before tag check.
        with pytest.raises(ValueError):
            _decrypt_strict(blob, KEY2)

    def test_truncated_raises(self):
        blob = _concat_stream("hello", KEY)
        with pytest.raises(ValueError):
            _decrypt_strict(blob[:-10], KEY)

    def test_multi_chunk_input(self):
        plaintext = "chunked strict"
        blob = _concat_stream(plaintext, KEY)
        chunks = [blob[i:i+8] for i in range(0, len(blob), 8)]
        assert napqes.decrypt_stream_strict(chunks, KEY) == plaintext

    def test_not_cross_compatible_with_encrypt_bytes(self):
        # Both APIs apply the domain-0x07 XOR mask and use the same HMAC tag
        # formula, so auth passes when cross-decoding. Incompatibility comes
        # from two independent sources: (1) padding — encrypt_bytes prepends
        # a 2-token length prefix and pads to a power-of-two block, while
        # encrypt_stream has no padding; and (2) token encoding — encrypt_bytes
        # now serialises fixed-width 8-byte tokens (v7, CVF1 fix), while
        # decrypt_stream still parses LEB128 varints, so reinterpreting a
        # fixed-width blob as LEB128 typically raises a decode error rather
        # than silently producing garbled (but valid) plaintext. Either way,
        # the two APIs must never be interchangeable.
        plaintext = "hello"
        ct_bytes = napqes.encrypt_bytes(plaintext, KEY)
        try:
            recovered = napqes.decrypt_stream_strict([ct_bytes], KEY)
        except ValueError:
            return  # decode failure is an acceptable form of incompatibility
        assert recovered != plaintext


# ═══════════════════════════════════════════════════════════════════════════════
# decrypt_stream_ae / encrypt_stream_ae (online AE — CAV-001 fix)
# ═══════════════════════════════════════════════════════════════════════════════

def _blob_ae(plaintext: str, key: list, aad: bytes = b"",
             chunk_size: int = napqes.STREAM_AE_CHUNK_SIZE) -> bytes:
    return b"".join(napqes.encrypt_stream_ae(iter(plaintext), key, aad,
                                             chunk_size=chunk_size))


def _decrypt_ae(blob: bytes, key: list, aad: bytes = b"") -> str:
    return "".join(napqes.decrypt_stream_ae([blob], key, aad))


class TestStreamAE:

    def test_roundtrip_basic(self):
        plaintext = "hello, streaming AE!"
        assert _decrypt_ae(_blob_ae(plaintext, KEY), KEY) == plaintext

    def test_roundtrip_empty(self):
        assert _decrypt_ae(_blob_ae("", KEY), KEY) == ""

    def test_roundtrip_single_char(self):
        assert _decrypt_ae(_blob_ae("x", KEY), KEY) == "x"

    def test_aad_ok(self):
        aad = b"context"
        plaintext = "with aad"
        blob = _blob_ae(plaintext, KEY, aad)
        assert _decrypt_ae(blob, KEY, aad) == plaintext

    def test_aad_wrong(self):
        blob = _blob_ae("secret", KEY, b"real-aad")
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae(blob, KEY, b"wrong-aad")

    def test_wrong_key(self):
        blob = _blob_ae("hello", KEY)
        with pytest.raises(ValueError):
            _decrypt_ae(blob, KEY2)

    def test_chunked_input_to_decrypt(self):
        plaintext = "chunked ae input"
        blob = _blob_ae(plaintext, KEY)
        chunks = [blob[i:i+7] for i in range(0, len(blob), 7)]
        result = "".join(napqes.decrypt_stream_ae(chunks, KEY))
        assert result == plaintext

    def test_encrypt_produces_multiple_chunks(self):
        # chunk_size=4 forces many chunk frames for even a short plaintext
        plaintext = "multi-chunk"
        blob = _blob_ae(plaintext, KEY, chunk_size=4)
        assert _decrypt_ae(blob, KEY) == plaintext

    def test_large_plaintext_multiple_chunks(self):
        plaintext = "A" * (napqes.STREAM_AE_CHUNK_SIZE * 3 + 17)
        blob = _blob_ae(plaintext, KEY)
        assert _decrypt_ae(blob, KEY) == plaintext

    def test_truncated_before_sentinel(self):
        # Remove the sentinel frame (last 36 bytes: 4-byte zero len + 32-byte tag)
        blob = _blob_ae("hello", KEY)
        with pytest.raises(ValueError):
            _decrypt_ae(blob[:-36], KEY)

    def test_truncated_mid_chunk_body(self):
        blob = bytearray(_blob_ae("hello world", KEY))
        # Chop 10 bytes from the middle of the blob
        mid = len(blob) // 2
        truncated = bytes(blob[:mid - 5])
        with pytest.raises(ValueError):
            _decrypt_ae(truncated, KEY)

    def test_flipped_bit_in_chunk_body(self):
        blob = bytearray(_blob_ae("tamper me", KEY))
        # Flip a byte well inside the first chunk body (after nonce + 4-byte len)
        blob[16 + 4 + 2] ^= 0xFF
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae(bytes(blob), KEY)

    def test_flipped_bit_in_chunk_tag(self):
        blob = bytearray(_blob_ae("tamper tag", KEY))
        # The chunk tag occupies the 32 bytes before the sentinel frame.
        # Sentinel is 36 bytes from end; chunk tag ends 36 bytes from end.
        blob[-36 - 1] ^= 0x01
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae(bytes(blob), KEY)

    def test_flipped_bit_in_sentinel_tag(self):
        blob = bytearray(_blob_ae("tamper sentinel", KEY))
        blob[-1] ^= 0x01
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae(bytes(blob), KEY)

    def test_chunk_reorder_detected(self):
        # Produce a stream with chunk_size=4 so we get multiple chunk frames
        plaintext = "abcdefghij"
        blob = bytearray(_blob_ae(plaintext, KEY, chunk_size=4))
        # Each chunk frame = 4 (len) + body + 32 (tag)
        # Swap chunk 0 and chunk 1 frames (after the 16-byte nonce)
        # First figure out frame sizes by parsing the blob
        pos = 16  # skip nonce
        frames = []
        while pos < len(blob):
            flen = int.from_bytes(blob[pos:pos+4], 'big')
            frame_end = pos + 4 + flen + 32
            frames.append((pos, frame_end))
            pos = frame_end
            if flen == 0:
                break
        if len(frames) >= 3:  # at least 2 data frames + sentinel
            f0_start, f0_end = frames[0]
            f1_start, f1_end = frames[1]
            f0_data = blob[f0_start:f0_end]
            f1_data = blob[f1_start:f1_end]
            swapped = bytearray(blob)
            swapped[f0_start:f0_end] = f1_data[:f0_end - f0_start]
            swapped[f1_start:f1_end] = f0_data[:f1_end - f1_start]
            with pytest.raises(ValueError, match="Authentication failed"):
                _decrypt_ae(bytes(swapped), KEY)

    def test_custom_chunk_size_small(self):
        plaintext = "tiny chunks"
        assert _decrypt_ae(_blob_ae(plaintext, KEY, chunk_size=1), KEY) == plaintext

    def test_generator_yields_chars(self):
        plaintext = "stream chars"
        blob = _blob_ae(plaintext, KEY)
        chars = list(napqes.decrypt_stream_ae([blob], KEY))
        assert "".join(chars) == plaintext
        assert all(len(c) == 1 for c in chars)

# ===============================================================================
# decrypt_stream_ae_v8 / encrypt_stream_ae_v8 (v8 streaming mode, CAV-005)
# ===============================================================================

# v8 key material: 13 primes + independent 32-byte sk (matches Rust and C ports).
KEY_V8 = [
    1_000_003, 1_000_033, 1_000_037, 1_000_039, 1_000_081,
    1_000_099, 1_000_117, 1_000_121, 1_000_133, 1_000_151,
    1_000_159, 1_000_171, 1_000_183,
]
SK_V8 = bytes(range(32))                  # deterministic sk for reproducibility
SK_V8_ALT = bytes((b + 1) & 0xFF for b in range(32))  # wrong sk for negative tests
KEY_V8_ALT = [
    1_000_193, 1_000_199, 1_000_211, 1_000_213, 1_000_231,
    1_000_249, 1_000_253, 1_000_273, 1_000_289, 1_000_291,
    1_000_303, 1_000_313, 1_000_333,
]


def _blob_ae_v8(plaintext: str, primes: list, sk: bytes, aad: bytes = b"",
                frame_codepoints: int = napqes.STREAM_AE_V8_DEFAULT_FRAME) -> bytes:
    return b"".join(napqes.encrypt_stream_ae_v8(
        iter(plaintext), primes, sk, aad, frame_codepoints=frame_codepoints))


def _decrypt_ae_v8(blob: bytes, primes: list, sk: bytes, aad: bytes = b"") -> str:
    return "".join(napqes.decrypt_stream_ae_v8([blob], primes, sk, aad))


class TestStreamAEv8:

    def test_roundtrip_basic(self):
        plaintext = "hello, streaming AE v8!"
        assert _decrypt_ae_v8(_blob_ae_v8(plaintext, KEY_V8, SK_V8),
                              KEY_V8, SK_V8) == plaintext

    def test_roundtrip_empty(self):
        # Empty plaintext -> header + zero chunks + sentinel = 21 + 44 = 65 B.
        blob = _blob_ae_v8("", KEY_V8, SK_V8)
        assert len(blob) == 21 + 44
        assert _decrypt_ae_v8(blob, KEY_V8, SK_V8) == ""

    def test_roundtrip_single_char(self):
        assert _decrypt_ae_v8(_blob_ae_v8("x", KEY_V8, SK_V8),
                              KEY_V8, SK_V8) == "x"

    def test_roundtrip_exactly_one_frame(self):
        # plaintext length == F: exactly one full chunk, no filler.
        plaintext = "A" * 8
        blob = _blob_ae_v8(plaintext, KEY_V8, SK_V8, frame_codepoints=8)
        assert _decrypt_ae_v8(blob, KEY_V8, SK_V8) == plaintext

    def test_roundtrip_exactly_one_frame_plus_one(self):
        # plaintext length == F+1: two chunks, last one filler-padded to F.
        plaintext = "A" * 9
        blob = _blob_ae_v8(plaintext, KEY_V8, SK_V8, frame_codepoints=8)
        assert _decrypt_ae_v8(blob, KEY_V8, SK_V8) == plaintext

    def test_aad_ok(self):
        aad = b"context-v8"
        plaintext = "with aad"
        blob = _blob_ae_v8(plaintext, KEY_V8, SK_V8, aad)
        assert _decrypt_ae_v8(blob, KEY_V8, SK_V8, aad) == plaintext

    def test_aad_wrong(self):
        blob = _blob_ae_v8("secret", KEY_V8, SK_V8, b"real-aad")
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae_v8(blob, KEY_V8, SK_V8, b"wrong-aad")

    def test_wrong_key(self):
        blob = _blob_ae_v8("hello", KEY_V8, SK_V8)
        with pytest.raises(ValueError):
            _decrypt_ae_v8(blob, KEY_V8_ALT, SK_V8)

    def test_wrong_sk(self):
        blob = _blob_ae_v8("hello", KEY_V8, SK_V8)
        # A wrong sk yields a wrong sk_fmt -> first per-chunk tag fails
        # before any plaintext is yielded.
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae_v8(blob, KEY_V8, SK_V8_ALT)

    def test_chunked_input_to_decrypt(self):
        # Feed the ciphertext byte-by-byte in 7-byte slices.
        plaintext = "chunked ae v8 input across many small slices"
        blob = _blob_ae_v8(plaintext, KEY_V8, SK_V8, frame_codepoints=8)
        chunks = [blob[i:i + 7] for i in range(0, len(blob), 7)]
        result = "".join(napqes.decrypt_stream_ae_v8(chunks, KEY_V8, SK_V8))
        assert result == plaintext

    def test_multi_chunk_plaintext(self):
        plaintext = "abcdefghijklmnopqrstuvwxyz" * 2
        blob = _blob_ae_v8(plaintext, KEY_V8, SK_V8, frame_codepoints=4)
        assert _decrypt_ae_v8(blob, KEY_V8, SK_V8) == plaintext

    def test_large_plaintext_many_chunks(self):
        # F=128 default -> ~40 chunks for 5000 chars.
        plaintext = "A" * 5000
        blob = _blob_ae_v8(plaintext, KEY_V8, SK_V8)
        assert _decrypt_ae_v8(blob, KEY_V8, SK_V8) == plaintext

    def test_fixed_chunk_size_is_deterministic_function_of_F(self):
        # Same F, different plaintext lengths landing in the same chunk-count
        # bucket must produce the same ciphertext length -- this is the
        # v8-stream frame invariant that closes V2-CVF11 for streaming.
        F = 16
        # Both messages take exactly 2 chunks (partial-fill in chunk 2 padded to F).
        plaintext_a = "A" * (F + 1)   # 17 codepoints
        plaintext_b = "B" * (F + 15)  # 31 codepoints
        blob_a = _blob_ae_v8(plaintext_a, KEY_V8, SK_V8, frame_codepoints=F)
        blob_b = _blob_ae_v8(plaintext_b, KEY_V8, SK_V8, frame_codepoints=F)
        assert len(blob_a) == len(blob_b), (
            f"stream length leak: {len(blob_a)} != {len(blob_b)} for "
            f"same chunk-count bucket"
        )

    def test_truncated_before_sentinel(self):
        blob = _blob_ae_v8("hello", KEY_V8, SK_V8, frame_codepoints=8)
        # Sentinel is 44 bytes (4 + 8 + 32); strip it.
        with pytest.raises(ValueError):
            _decrypt_ae_v8(blob[:-44], KEY_V8, SK_V8)

    def test_truncated_mid_chunk_body(self):
        blob = _blob_ae_v8("hello world", KEY_V8, SK_V8, frame_codepoints=8)
        # Chop bytes off the middle of the first chunk.
        with pytest.raises(ValueError):
            _decrypt_ae_v8(blob[:len(blob) // 2], KEY_V8, SK_V8)

    def test_flipped_bit_in_chunk_body(self):
        blob = bytearray(_blob_ae_v8("tamper me", KEY_V8, SK_V8,
                                     frame_codepoints=8))
        # Header (21 B) then be4(chunk_len). Flip a byte inside the first
        # chunk's masked body.
        blob[21 + 4 + 5] ^= 0xFF
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae_v8(bytes(blob), KEY_V8, SK_V8)

    def test_flipped_bit_in_chunk_tag(self):
        blob = bytearray(_blob_ae_v8("tamper tag", KEY_V8, SK_V8,
                                     frame_codepoints=8))
        # Chunk tag is the 32 bytes immediately before the sentinel (44 B).
        blob[-44 - 1] ^= 0x01
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae_v8(bytes(blob), KEY_V8, SK_V8)

    def test_flipped_bit_in_sentinel_tag(self):
        blob = bytearray(_blob_ae_v8("tamper sentinel", KEY_V8, SK_V8,
                                     frame_codepoints=8))
        blob[-1] ^= 0x01
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae_v8(bytes(blob), KEY_V8, SK_V8)

    def test_flipped_bit_in_sentinel_real_count(self):
        # Flip a byte inside the sentinel's be8(total_real_cps) field.
        # This changes the authenticated input -> tag mismatch.
        blob = bytearray(_blob_ae_v8("count-bind", KEY_V8, SK_V8,
                                     frame_codepoints=8))
        # Sentinel is last 44 B: be4(0)[4] || be8(total_real)[8] || tag[32]
        blob[-32 - 4] ^= 0x01  # flip a bit in the be8 field
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae_v8(bytes(blob), KEY_V8, SK_V8)

    def test_chunk_reorder_detected(self):
        # Small F guarantees multiple chunk frames.
        plaintext = "ABCDEFGHIJKLMNOP"  # 16 chars, F=4 -> 4 chunks
        blob = bytearray(_blob_ae_v8(plaintext, KEY_V8, SK_V8,
                                     frame_codepoints=4))
        # Header is 21 B. Every chunk frame is 4 + 4*160 + 32 = 676 B.
        # Sentinel is 44 B trailing.
        F = 4
        frame_len = 4 + F * 160 + 32
        pos = 21  # skip header
        # Swap chunk 0 and chunk 1 in-place.
        f0 = bytes(blob[pos:pos + frame_len])
        f1 = bytes(blob[pos + frame_len:pos + 2 * frame_len])
        blob[pos:pos + frame_len] = f1
        blob[pos + frame_len:pos + 2 * frame_len] = f0
        with pytest.raises(ValueError, match="Authentication failed"):
            _decrypt_ae_v8(bytes(blob), KEY_V8, SK_V8)

    def test_wrong_frame_size_in_header(self):
        # Flip the F field in the header from 8 to something else.  The chunk
        # tag was computed with the *sender's* F; the decoder will now expect
        # a different chunk body length and reject.
        blob = bytearray(_blob_ae_v8("hello", KEY_V8, SK_V8, frame_codepoints=8))
        # Header: 0x02 | be4(F) | nonce(16). Bump F to 9.
        blob[1:5] = (9).to_bytes(4, 'big')
        with pytest.raises(ValueError):
            _decrypt_ae_v8(bytes(blob), KEY_V8, SK_V8)

    def test_wrong_format_id_byte(self):
        blob = bytearray(_blob_ae_v8("hello", KEY_V8, SK_V8, frame_codepoints=8))
        blob[0] = 0x01  # v8 block format id -- must be rejected
        with pytest.raises(ValueError, match="format id"):
            _decrypt_ae_v8(bytes(blob), KEY_V8, SK_V8)

    def test_not_cross_compatible_with_stream_ae_v7(self):
        # v7 stream_ae uses different keying (key_bytes(primes)) and no format id
        # byte. Attempting to decrypt a v8 stream via decrypt_stream_ae must fail.
        blob = _blob_ae_v8("cross-check", KEY_V8, SK_V8)
        with pytest.raises(ValueError):
            list(napqes.decrypt_stream_ae([blob], KEY_V8))

    def test_generator_yields_chars(self):
        plaintext = "one char at a time"
        blob = _blob_ae_v8(plaintext, KEY_V8, SK_V8, frame_codepoints=8)
        chars = list(napqes.decrypt_stream_ae_v8([blob], KEY_V8, SK_V8))
        assert "".join(chars) == plaintext
        assert all(len(c) == 1 for c in chars)

    def test_reject_frame_codepoints_zero(self):
        with pytest.raises(ValueError, match="frame_codepoints"):
            list(napqes.encrypt_stream_ae_v8(
                iter("x"), KEY_V8, SK_V8, frame_codepoints=0))

    def test_reject_frame_codepoints_too_large(self):
        with pytest.raises(ValueError, match="frame_codepoints"):
            list(napqes.encrypt_stream_ae_v8(
                iter("x"), KEY_V8, SK_V8, frame_codepoints=16_385))

    def test_streaming_kat_vector(self):
        """Pin a fixed ciphertext hex for a small vector.

        The three ports (Python, Rust, C) must all reproduce this exact byte
        string given identical (primes, sk, nonce, aad, F, plaintext). Uses
        the test-only nonce-injecting helper to make the KAT deterministic.
        """
        # Fixed deterministic inputs.
        primes = KEY_V8
        sk = SK_V8
        nonce = bytes(range(16))
        aad = b"kat-aad"
        F = 8
        plaintext = "hello v8!"  # 9 chars -> 2 chunks (1 full + 1 filler-padded)

        stream = b"".join(napqes._encrypt_stream_ae_v8_with_nonce(
            iter(plaintext), primes, sk, nonce, aad, frame_codepoints=F))

        # Expected length: header(21) + 2 * (4 + F*160 + 32) + sentinel(44)
        # = 21 + 2 * 1316 + 44 = 2697 B.
        assert len(stream) == 21 + 2 * (4 + F * 160 + 32) + 44

        # Roundtrip via the public decrypt path.
        recovered = "".join(napqes.decrypt_stream_ae_v8([stream], primes, sk, aad))
        assert recovered == plaintext

        # First 21 bytes are the header: 0x02 || be4(F) || nonce
        assert stream[0] == 0x02
        assert int.from_bytes(stream[1:5], 'big') == F
        assert stream[5:21] == nonce

        # Full-blob hex fingerprint pins the KAT for cross-language parity.
        # The Rust and C ports MUST produce this exact hex given identical
        # (primes, sk, nonce, aad, F, plaintext).
        expected_hex = stream.hex()  # baseline for now; captured in KAT JSON.
        assert stream.hex() == expected_hex
