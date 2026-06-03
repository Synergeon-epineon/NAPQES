"""
napqes_kem.py — FrodoKEM-640-AES key encapsulation for NAPQES v6

Two-phase key establishment:
  1. KEM phase: FrodoKEM-640-AES (unstructured LWE, no ring/ideal structure)
     establishes a 16-byte shared secret between Alice and Bob.
  2. Derivation phase: HKDF-SHA256 + counter-mode HMAC-SHA256 converts that
     shared secret into a valid NAPQES prime-list key (13 distinct primes from
     [1 000 000, 15 000 000]), matching the ~128.5-bit post-Grover security level
     of NAPQES v6 at K=13.

All derivation steps use only HMAC-SHA256 and HKDF-SHA256, consistent with
NAPQES's design philosophy of a single FIPS-approved primitive.

Usage (Alice = key-holder, Bob = sender):

    import napqes_kem, napqes

    # Alice generates a keypair once and publishes public_key
    public_key, secret_key = napqes_kem.keygen()

    # Bob encapsulates to Alice's public key, gets a NAPQES key
    kem_ciphertext, napqes_key_bob = napqes_kem.encapsulate(public_key)

    # Alice decapsulates using her secret key, recovers the same NAPQES key
    napqes_key_alice = napqes_kem.decapsulate(kem_ciphertext, secret_key)

    # Both sides now hold identical NAPQES keys → encrypt / decrypt as usual
    ct = napqes.encrypt_bytes("hello", napqes_key_bob)
    pt = napqes.decrypt_bytes(ct, napqes_key_alice)
    assert pt == "hello"

Security notes:
  - FrodoKEM-640-AES is an IND-CCA2 KEM with NIST security level 1 (~128-bit
    classical, ~128-bit post-quantum against Grover on the symmetric layer).
  - The shared secret passes through HKDF (domain separation, extraction) before
    any use, preventing any weakness in the KEM's raw shared-secret distribution
    from reaching the NAPQES key.
  - Key ordering in the derived prime list is a security parameter — the ordered
    output of _derive_napqes_key must not be sorted or shuffled by callers.
"""

import hmac
import hashlib

import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

import napqes

KEM_VARIANT = "FrodoKEM-640-AES"
NAPQES_KEY_COUNT = 13

_MIN_PRIME = 1_000_000
_MAX_PRIME = 15_000_000

_HKDF_SALT = b"NAPQES-v6-FrodoKEM-640-prime-key"
_HKDF_INFO = b"v1"

_PRIME_RANGE = _MAX_PRIME - _MIN_PRIME


def keygen() -> tuple[bytes, bytes]:
    """Generate a FrodoKEM-640-AES keypair.

    Returns:
        (public_key, secret_key) as raw bytes.
        Publish public_key; keep secret_key confidential.
    """
    kem = oqs.KeyEncapsulation(KEM_VARIANT)
    try:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    finally:
        kem.free()
    return public_key, secret_key


def encapsulate(public_key: bytes) -> tuple[bytes, list[int]]:
    """Encapsulate a fresh shared secret to *public_key*.

    Args:
        public_key: FrodoKEM-640-AES public key (9 616 bytes) from keygen().

    Returns:
        (kem_ciphertext, napqes_key)
        Send kem_ciphertext to the key-holder (Alice); use napqes_key locally.
    """
    kem = oqs.KeyEncapsulation(KEM_VARIANT)
    try:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    finally:
        kem.free()
    return ciphertext, _derive_napqes_key(shared_secret)


def decapsulate(ciphertext: bytes, secret_key: bytes) -> list[int]:
    """Decapsulate *ciphertext* using *secret_key*, recovering the NAPQES key.

    Args:
        ciphertext: FrodoKEM-640-AES ciphertext (9 720 bytes) from encapsulate().
        secret_key: FrodoKEM-640-AES secret key (19 888 bytes) from keygen().

    Returns:
        The NAPQES prime-list key that the encapsulator holds.
    """
    kem = oqs.KeyEncapsulation(KEM_VARIANT, secret_key)
    try:
        shared_secret = kem.decap_secret(ciphertext)
    finally:
        kem.free()
    return _derive_napqes_key(shared_secret)


def _derive_napqes_key(shared_secret: bytes,
                       count: int = NAPQES_KEY_COUNT) -> list[int]:
    """Deterministically derive a NAPQES prime-list key from a KEM shared secret.

    Step 1 — Extract: HKDF-SHA256 maps the 16-byte FrodoKEM shared secret to a
      uniform 32-byte seed using a domain-separation salt.

    Step 2 — Expand: counter-mode HMAC-SHA256(seed, counter) generates a stream
      of 32-byte digests.  Each digest's first 8 bytes are mapped into the prime
      range [1 000 000, 15 000 000) via modular reduction, then checked for
      primality and uniqueness.  This mirrors how NAPQES derives noise positions,
      addends, and keystream — all operations reduce to HMAC-SHA256.

    The resulting list is ordered (key ordering is a security parameter).

    Args:
        shared_secret: Raw bytes from the KEM (16 bytes for FrodoKEM-640-AES).
        count: Number of distinct primes to derive (default: 13).

    Returns:
        Ordered list of *count* distinct prime integers from [1M, 15M].
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    )
    seed = hkdf.derive(shared_secret)

    primes: list[int] = []
    seen: set[int] = set()
    counter = 0
    while len(primes) < count:
        digest = hmac.new(seed, counter.to_bytes(4, "big"), hashlib.sha256).digest()
        candidate = int.from_bytes(digest[:8], "big") % _PRIME_RANGE + _MIN_PRIME
        counter += 1
        if candidate not in seen and napqes.is_prime(candidate):
            primes.append(candidate)
            seen.add(candidate)
    return primes
