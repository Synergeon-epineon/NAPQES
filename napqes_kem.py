"""
napqes_kem.py — hybrid FrodoKEM-640-AES + X25519 key establishment for NAPQES

Two-phase key establishment:
  1. KEM phase: FrodoKEM-640-AES (unstructured LWE, no ring/ideal structure)
     establishes a 16-byte post-quantum shared secret, and X25519 establishes a
     32-byte classical shared secret, between Alice and Bob.
  2. Derivation phase: HKDF-SHA256 + counter-mode HMAC-SHA256 converts the
     concatenated secrets into a valid NAPQES prime-list key (13 distinct
     primes from [1 000 000, 15 000 000)), matching the ~128.5-bit post-Grover
     security level of the NAPQES "PQ-128" profile at K=13.

All derivation steps use only HMAC-SHA256 and HKDF-SHA256, consistent with
NAPQES's design philosophy of a single FIPS-approved symmetric primitive.

Two APIs are provided:

  * ``keygen_hybrid`` / ``encapsulate_hybrid`` / ``decapsulate_hybrid`` —
    **recommended**. Hybridises the post-quantum KEM with X25519, as required
    by ANSSI's post-quantum migration doctrine: the derived key stays secure as
    long as *either* component holds.
  * ``keygen`` / ``encapsulate`` / ``decapsulate`` — legacy FrodoKEM-only
    exchange, retained for compatibility with deployments provisioned before
    hybridisation. New deployments should use the hybrid API.

Usage (Alice = key-holder, Bob = sender):

    import napqes_kem, napqes

    # Alice generates a keypair once and publishes public_key
    public_key, secret_key = napqes_kem.keygen_hybrid()

    # Bob encapsulates to Alice's public key, gets a NAPQES key
    kem_ciphertext, napqes_key_bob = napqes_kem.encapsulate_hybrid(public_key)

    # Alice decapsulates using her secret key, recovers the same NAPQES key
    napqes_key_alice = napqes_kem.decapsulate_hybrid(kem_ciphertext, secret_key)

    # Both sides now hold identical NAPQES keys → encrypt / decrypt as usual
    ct = napqes.encrypt_bytes("hello", napqes_key_bob)
    pt = napqes.decrypt_bytes(ct, napqes_key_alice)
    assert pt == "hello"

Security notes:
  - FrodoKEM-640-AES is an IND-CCA2 KEM with NIST security level 1 (~128-bit
    classical, ~128-bit post-quantum against Grover on the symmetric layer).
  - Both shared secrets pass through HKDF-Extract (domain separation,
    extraction) before any use. Because HKDF-Extract is a PRF keyed by the
    salt, an adversary must break *every* concatenated component to recover
    the seed — this is what makes the construction a true hybrid.
  - The HKDF ``info`` binds the full transcript (both public keys and both
    ciphertext halves), so a derived key commits to the session it came from.
  - An all-zero X25519 output is rejected: it would mean the peer sent a
    small-order point and the classical half contributed nothing.
  - Key ordering in the derived prime list is a security parameter — the
    ordered output of the derivation must not be sorted or shuffled by callers.
"""

import hmac
import hashlib

import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

import napqes

KEM_VARIANT = "FrodoKEM-640-AES"
NAPQES_KEY_COUNT = 13

_MIN_PRIME = 1_000_000
_MAX_PRIME = 15_000_000

_HKDF_SALT = b"NAPQES-v6-FrodoKEM-640-prime-key"
_HKDF_INFO = b"v1"

_PRIME_RANGE = _MAX_PRIME - _MIN_PRIME

#: Wire sizes of the FrodoKEM-640-AES artefacts, used to split the concatenated
#: hybrid blobs. Cross-checked by ``tests/test_kem.py::TestKeySizes``.
FRODO_PUBLIC_KEY_SIZE = 9_616
FRODO_SECRET_KEY_SIZE = 19_888
FRODO_CIPHERTEXT_SIZE = 9_720

#: X25519 public keys, private scalars and shared secrets are all 32 bytes.
X25519_KEY_SIZE = 32

#: Hybrid blob sizes. The recipient's FrodoKEM public key is carried inside the
#: hybrid secret key so that the decapsulator can rebuild the same transcript
#: as the encapsulator (liboqs does not expose pk recovery from sk).
HYBRID_PUBLIC_KEY_SIZE = FRODO_PUBLIC_KEY_SIZE + X25519_KEY_SIZE
HYBRID_SECRET_KEY_SIZE = (
    FRODO_SECRET_KEY_SIZE + X25519_KEY_SIZE + FRODO_PUBLIC_KEY_SIZE
)
HYBRID_CIPHERTEXT_SIZE = FRODO_CIPHERTEXT_SIZE + X25519_KEY_SIZE

#: Domain separation for the hybrid derivation. Distinct from ``_HKDF_SALT`` so
#: that a hybrid and a Frodo-only exchange can never derive the same key even
#: if an attacker could force the same FrodoKEM shared secret in both.
_HYBRID_HKDF_SALT = b"NAPQES-hybrid-FrodoKEM640AES-X25519-prime-key"
_HYBRID_HKDF_INFO_PREFIX = b"v2"


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
    return _expand_seed_to_primes(seed, count)


def _expand_seed_to_primes(seed: bytes, count: int) -> list[int]:
    """Counter-mode HMAC-SHA256 expansion of *seed* into *count* distinct primes.

    Shared by the Frodo-only and the hybrid derivations so that the two differ
    exactly in their HKDF-Extract inputs (secret material and transcript) and
    nowhere else.

    The reduction ``digest[:8] mod _PRIME_RANGE`` is not unbiased range
    sampling, but the bias is bounded by ``_PRIME_RANGE / 2^64 < 2^-40`` per
    draw and is therefore negligible; rejection is applied for primality and
    uniqueness only.
    """
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


# ─── Hybrid key establishment: FrodoKEM-640-AES + X25519 ─────────────────────
#
# ANSSI's post-quantum doctrine requires that a post-quantum mechanism be
# *hybridised* with a well-understood classical one until the post-quantum
# assumptions have matured: the derived key must stay secure as long as
# *either* component holds.  This is achieved by concatenating both shared
# secrets into a single HKDF-Extract input — HKDF-Extract is a PRF keyed by the
# salt, so recovering the seed requires breaking every concatenated component.
#
# The X25519 half is ephemeral-static: the recipient publishes a long-term
# X25519 public key alongside its FrodoKEM public key, and the sender draws a
# fresh ephemeral scalar per encapsulation, mirroring the FrodoKEM semantics.


def _hybrid_transcript(pk_pq: bytes, ct_pq: bytes,
                       pk_ec_static: bytes, pk_ec_ephemeral: bytes) -> bytes:
    """Length-prefixed binding of every public value of the exchange.

    Fed to HKDF as ``info`` so that the derived key commits to the recipient's
    identity and to both ciphertext halves; an attacker who swaps one half for
    a replayed one from another session changes the transcript and therefore
    the derived key.  Length prefixes make the concatenation injective.
    """
    parts = (pk_pq, ct_pq, pk_ec_static, pk_ec_ephemeral)
    return _HYBRID_HKDF_INFO_PREFIX + b"".join(
        len(p).to_bytes(4, "big") + p for p in parts
    )


def _derive_napqes_key_hybrid(ss_pq: bytes, ss_ec: bytes, transcript: bytes,
                              count: int = NAPQES_KEY_COUNT) -> list[int]:
    """Derive the NAPQES prime key from both shared secrets and the transcript."""
    if len(ss_ec) != X25519_KEY_SIZE:
        raise ValueError(
            f"X25519 shared secret must be {X25519_KEY_SIZE} bytes, "
            f"got {len(ss_ec)}."
        )
    # An all-zero X25519 output means the peer sent a small-order point, which
    # would make the classical half contribute nothing. RFC 7748 §6.1 leaves
    # the check optional; for a hybrid it is mandatory, otherwise the exchange
    # silently degrades to FrodoKEM-only.
    if not any(ss_ec):
        raise ValueError(
            "X25519 shared secret is all-zero: the peer supplied a "
            "small-order point, so the classical half of the hybrid would "
            "contribute no entropy."
        )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HYBRID_HKDF_SALT,
        info=transcript,
    )
    seed = hkdf.derive(ss_pq + ss_ec)
    return _expand_seed_to_primes(seed, count)


def keygen_hybrid() -> tuple[bytes, bytes]:
    """Generate a hybrid FrodoKEM-640-AES + X25519 keypair.

    Returns:
        ``(public_key, secret_key)`` where
        ``public_key  = pk_frodo(9 616) || pk_x25519(32)`` and
        ``secret_key  = sk_frodo(19 888) || sk_x25519(32) || pk_frodo(9 616)``.
        Publish public_key; keep secret_key confidential.
    """
    kem = oqs.KeyEncapsulation(KEM_VARIANT)
    try:
        pk_pq = kem.generate_keypair()
        sk_pq = kem.export_secret_key()
    finally:
        kem.free()

    sk_ec_obj = x25519.X25519PrivateKey.generate()
    sk_ec = sk_ec_obj.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    pk_ec = sk_ec_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return pk_pq + pk_ec, sk_pq + sk_ec + pk_pq


def encapsulate_hybrid(public_key: bytes) -> tuple[bytes, list[int]]:
    """Encapsulate a fresh hybrid shared secret to *public_key*.

    Args:
        public_key: Hybrid public key from :func:`keygen_hybrid`.

    Returns:
        ``(ciphertext, napqes_key)`` where
        ``ciphertext = ct_frodo(9 720) || pk_x25519_ephemeral(32)``.
    """
    if len(public_key) != HYBRID_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"Hybrid public key must be {HYBRID_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(public_key)}."
        )
    pk_pq = public_key[:FRODO_PUBLIC_KEY_SIZE]
    pk_ec_static = public_key[FRODO_PUBLIC_KEY_SIZE:]

    kem = oqs.KeyEncapsulation(KEM_VARIANT)
    try:
        ct_pq, ss_pq = kem.encap_secret(pk_pq)
    finally:
        kem.free()

    eph = x25519.X25519PrivateKey.generate()
    pk_ec_ephemeral = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ss_ec = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk_ec_static))

    transcript = _hybrid_transcript(pk_pq, ct_pq, pk_ec_static, pk_ec_ephemeral)
    napqes_key = _derive_napqes_key_hybrid(ss_pq, ss_ec, transcript)
    return ct_pq + pk_ec_ephemeral, napqes_key


def decapsulate_hybrid(ciphertext: bytes, secret_key: bytes) -> list[int]:
    """Decapsulate a hybrid *ciphertext*, recovering the same NAPQES key.

    Args:
        ciphertext: Hybrid ciphertext from :func:`encapsulate_hybrid`.
        secret_key: Hybrid secret key from :func:`keygen_hybrid`.

    Returns:
        The NAPQES prime-list key that the encapsulator holds.
    """
    if len(ciphertext) != HYBRID_CIPHERTEXT_SIZE:
        raise ValueError(
            f"Hybrid ciphertext must be {HYBRID_CIPHERTEXT_SIZE} bytes, "
            f"got {len(ciphertext)}."
        )
    if len(secret_key) != HYBRID_SECRET_KEY_SIZE:
        raise ValueError(
            f"Hybrid secret key must be {HYBRID_SECRET_KEY_SIZE} bytes, "
            f"got {len(secret_key)}."
        )
    ct_pq = ciphertext[:FRODO_CIPHERTEXT_SIZE]
    pk_ec_ephemeral = ciphertext[FRODO_CIPHERTEXT_SIZE:]

    sk_pq = secret_key[:FRODO_SECRET_KEY_SIZE]
    sk_ec = secret_key[
        FRODO_SECRET_KEY_SIZE:FRODO_SECRET_KEY_SIZE + X25519_KEY_SIZE
    ]
    pk_pq = secret_key[FRODO_SECRET_KEY_SIZE + X25519_KEY_SIZE:]

    kem = oqs.KeyEncapsulation(KEM_VARIANT, sk_pq)
    try:
        ss_pq = kem.decap_secret(ct_pq)
    finally:
        kem.free()

    sk_ec_obj = x25519.X25519PrivateKey.from_private_bytes(sk_ec)
    pk_ec_static = sk_ec_obj.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    ss_ec = sk_ec_obj.exchange(
        x25519.X25519PublicKey.from_public_bytes(pk_ec_ephemeral)
    )

    transcript = _hybrid_transcript(pk_pq, ct_pq, pk_ec_static, pk_ec_ephemeral)
    return _derive_napqes_key_hybrid(ss_pq, ss_ec, transcript)
