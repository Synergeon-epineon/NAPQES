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
