"""Tests for napqes_kem — FrodoKEM-640-AES + NAPQES key establishment."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import napqes
import napqes_kem


class TestKeyRoundtrip:
    def test_roundtrip(self):
        pk, sk = napqes_kem.keygen()
        ct, key_bob = napqes_kem.encapsulate(pk)
        key_alice = napqes_kem.decapsulate(ct, sk)
        assert key_bob == key_alice

    def test_key_is_valid_napqes_key(self):
        pk, sk = napqes_kem.keygen()
        _, key = napqes_kem.encapsulate(pk)
        # Must not raise — validates count, primality, distinctness, range
        napqes._validate_key(key)

    def test_key_count(self):
        pk, _ = napqes_kem.keygen()
        _, key = napqes_kem.encapsulate(pk)
        assert len(key) == napqes_kem.NAPQES_KEY_COUNT

    def test_key_elements_in_range(self):
        pk, _ = napqes_kem.keygen()
        _, key = napqes_kem.encapsulate(pk)
        for p in key:
            assert napqes_kem._MIN_PRIME <= p < napqes_kem._MAX_PRIME

    def test_key_elements_distinct(self):
        pk, _ = napqes_kem.keygen()
        _, key = napqes_kem.encapsulate(pk)
        assert len(set(key)) == len(key)

    def test_key_elements_are_prime(self):
        pk, _ = napqes_kem.keygen()
        _, key = napqes_kem.encapsulate(pk)
        assert all(napqes.is_prime(p) for p in key)


class TestDeterminism:
    def test_derive_is_deterministic(self):
        secret = os.urandom(16)
        key1 = napqes_kem._derive_napqes_key(secret)
        key2 = napqes_kem._derive_napqes_key(secret)
        assert key1 == key2

    def test_different_secrets_give_different_keys(self):
        key1 = napqes_kem._derive_napqes_key(os.urandom(16))
        key2 = napqes_kem._derive_napqes_key(os.urandom(16))
        assert key1 != key2

    def test_wrong_sk_gives_different_key(self):
        pk, sk = napqes_kem.keygen()
        ct, key_bob = napqes_kem.encapsulate(pk)
        # Decap with a different secret key → different shared secret → different key
        _, wrong_sk = napqes_kem.keygen()
        key_wrong = napqes_kem.decapsulate(ct, wrong_sk)
        assert key_wrong != key_bob


class TestNapqesIntegration:
    def test_full_encrypt_decrypt_after_kem(self):
        pk, sk = napqes_kem.keygen()
        ct_kem, key_bob = napqes_kem.encapsulate(pk)
        key_alice = napqes_kem.decapsulate(ct_kem, sk)

        plaintext = "Hello from FrodoKEM + NAPQES!"
        ct_msg = napqes.encrypt_bytes(plaintext, key_bob)
        decrypted = napqes.decrypt_bytes(ct_msg, key_alice)
        assert decrypted == plaintext

    def test_full_encrypt_decrypt_with_aad(self):
        pk, sk = napqes_kem.keygen()
        ct_kem, key_bob = napqes_kem.encapsulate(pk)
        key_alice = napqes_kem.decapsulate(ct_kem, sk)

        plaintext = "Sensitive payload"
        aad = b"device-id:ABC123;session:42"
        ct_msg = napqes.encrypt_bytes(plaintext, key_bob, aad=aad)
        decrypted = napqes.decrypt_bytes(ct_msg, key_alice, aad=aad)
        assert decrypted == plaintext

    def test_aad_mismatch_raises(self):
        pk, sk = napqes_kem.keygen()
        ct_kem, key_bob = napqes_kem.encapsulate(pk)
        key_alice = napqes_kem.decapsulate(ct_kem, sk)

        ct_msg = napqes.encrypt_bytes("secret", key_bob, aad=b"real-aad")
        with pytest.raises(ValueError):
            napqes.decrypt_bytes(ct_msg, key_alice, aad=b"wrong-aad")


class TestCrossLanguageVector:
    def test_derive_known_vector_zero_secret(self):
        # Known-answer vector: shared_secret = 0x00 * 16
        # Rust: kem::tests::test_derive_cross_language_vector
        # Both implementations MUST produce the same ordered prime list.
        expected = [
            11530619, 13297909, 9920357, 13069411, 5196311,
            6762001, 12497731, 7518361, 12559777, 1531199,
            14203867, 10311841, 13788101,
        ]
        result = napqes_kem._derive_napqes_key(bytes(16))
        assert result == expected, f"cross-language mismatch: {result}"

    def test_derive_known_vector_hybrid(self):
        # Known-answer vector for the hybrid derivation, pinned so that the
        # Rust port cannot silently diverge on HKDF salt/info, secret
        # concatenation order, or transcript encoding.
        # Rust: kem::tests::test_derive_hybrid_cross_language_vector
        transcript = napqes_kem._hybrid_transcript(
            b"PK-PQ", b"CT-PQ", b"PK-EC-STATIC", b"PK-EC-EPH"
        )
        assert transcript.hex() == (
            "763200000005504b2d50510000000543542d50510000000c"
            "504b2d45432d53544154494300000009504b2d45432d455048"
        )
        expected = [
            2992559, 2913523, 2740301, 1977709, 5330359,
            13077137, 6210319, 11896091, 14291593, 8698397,
            12129883, 1604143, 10450267,
        ]
        result = napqes_kem._derive_napqes_key_hybrid(
            bytes(16), bytes(range(1, 33)), transcript
        )
        assert result == expected, f"cross-language mismatch: {result}"


class TestHybridKeyEstablishment:
    def test_roundtrip(self):
        pk, sk = napqes_kem.keygen_hybrid()
        ct, key_bob = napqes_kem.encapsulate_hybrid(pk)
        key_alice = napqes_kem.decapsulate_hybrid(ct, sk)
        assert key_bob == key_alice

    def test_blob_sizes(self):
        pk, sk = napqes_kem.keygen_hybrid()
        ct, _ = napqes_kem.encapsulate_hybrid(pk)
        assert len(pk) == napqes_kem.HYBRID_PUBLIC_KEY_SIZE == 9648
        assert len(sk) == napqes_kem.HYBRID_SECRET_KEY_SIZE == 29536
        assert len(ct) == napqes_kem.HYBRID_CIPHERTEXT_SIZE == 9752

    def test_key_is_valid_napqes_key(self):
        pk, _ = napqes_kem.keygen_hybrid()
        _, key = napqes_kem.encapsulate_hybrid(pk)
        napqes._validate_key(key)
        assert len(key) == napqes_kem.NAPQES_KEY_COUNT

    def test_each_session_derives_a_fresh_key(self):
        pk, _ = napqes_kem.keygen_hybrid()
        _, key1 = napqes_kem.encapsulate_hybrid(pk)
        _, key2 = napqes_kem.encapsulate_hybrid(pk)
        assert key1 != key2

    def test_aead_roundtrip_after_hybrid_kem(self):
        pk, sk = napqes_kem.keygen_hybrid()
        ct_kem, key_bob = napqes_kem.encapsulate_hybrid(pk)
        key_alice = napqes_kem.decapsulate_hybrid(ct_kem, sk)
        aad = b"session=1;peer=bob"
        ct_msg = napqes.encrypt_bytes("hybrid payload", key_bob, aad=aad)
        assert napqes.decrypt_bytes(ct_msg, key_alice, aad=aad) == "hybrid payload"

    def test_transcript_binds_the_classical_half(self):
        # Splicing the ephemeral X25519 half of another session must change the
        # derived key: this is what the HKDF `info` transcript binding buys.
        pk, sk = napqes_kem.keygen_hybrid()
        ct1, key1 = napqes_kem.encapsulate_hybrid(pk)
        ct2, _ = napqes_kem.encapsulate_hybrid(pk)
        spliced = (
            ct1[:napqes_kem.FRODO_CIPHERTEXT_SIZE]
            + ct2[napqes_kem.FRODO_CIPHERTEXT_SIZE:]
        )
        assert napqes_kem.decapsulate_hybrid(spliced, sk) != key1

    def test_wrong_secret_key_gives_different_key(self):
        pk, _ = napqes_kem.keygen_hybrid()
        ct, key_bob = napqes_kem.encapsulate_hybrid(pk)
        _, wrong_sk = napqes_kem.keygen_hybrid()
        assert napqes_kem.decapsulate_hybrid(ct, wrong_sk) != key_bob

    def test_all_zero_x25519_secret_is_rejected(self):
        # A small-order peer point yields an all-zero X25519 output, which would
        # silently degrade the hybrid to FrodoKEM-only.
        with pytest.raises(ValueError, match="all-zero"):
            napqes_kem._derive_napqes_key_hybrid(bytes(16), bytes(32), b"info")

    def test_malformed_blob_lengths_are_rejected(self):
        pk, sk = napqes_kem.keygen_hybrid()
        ct, _ = napqes_kem.encapsulate_hybrid(pk)
        with pytest.raises(ValueError, match="public key must be"):
            napqes_kem.encapsulate_hybrid(pk[:-1])
        with pytest.raises(ValueError, match="ciphertext must be"):
            napqes_kem.decapsulate_hybrid(ct[:-1], sk)
        with pytest.raises(ValueError, match="secret key must be"):
            napqes_kem.decapsulate_hybrid(ct, sk[:-1])

    def test_hybrid_and_frodo_only_derivations_are_separated(self):
        # Same FrodoKEM secret must never produce the same NAPQES key under the
        # two schedules (distinct HKDF salts).
        ss_pq = bytes(range(16))
        legacy = napqes_kem._derive_napqes_key(ss_pq)
        hybrid = napqes_kem._derive_napqes_key_hybrid(
            ss_pq, bytes(range(1, 33)), b"v2"
        )
        assert legacy != hybrid


class TestKeySizes:
    def test_public_key_size(self):
        pk, _ = napqes_kem.keygen()
        assert len(pk) == 9616  # FrodoKEM-640-AES spec

    def test_secret_key_size(self):
        _, sk = napqes_kem.keygen()
        assert len(sk) == 19888  # FrodoKEM-640-AES spec

    def test_ciphertext_size(self):
        pk, _ = napqes_kem.keygen()
        ct, _ = napqes_kem.encapsulate(pk)
        assert len(ct) == 9720  # FrodoKEM-640-AES spec
