"""NAPSEQ reference implementation (Python).

Wire format v6 (frozen — see ``SPEC.md`` at repo root). The wire format and
the Python SDK version are versioned independently: this module's public API
may change in backward-incompatible ways while keeping the v6 byte layout
stable.

Known leakage and caveats (see ``docs/CAVEATS.md`` for full triage):

* **Length-bucket leakage.** ``encrypt_bytes`` / ``encrypt_str`` pad plaintext
  to the next power-of-two block size (min 16). The ciphertext therefore
  reveals which power-of-two bucket the plaintext length falls into. Callers
  needing full length-hiding must layer a fixed-frame transport on top.
* **16-bit length cap.** Block-mode plaintext is capped at
  ``MAX_PLAINTEXT_CODEPOINTS`` (65535) by the 2-codepoint length prefix in
  ``_pad_message``. Raising the cap requires a v7 wire format (deferred).
* **Streaming RUP.** ``decrypt_stream`` releases plaintext before the auth
  tag is verified. It is gated behind
  ``enable_unauthenticated_streaming=True``; prefer ``decrypt_stream_strict``
  which buffers all plaintext and verifies the tag before returning.
* **Legacy v2/v3/v5 formats** are read-only and require explicit opt-in via
  ``allow_legacy_unauthenticated=True``.
"""

import math
import os
import secrets
import hmac
import hashlib
import base64
from collections.abc import Generator, Iterable


_NONCE_SIZE = 16
_TAG_SIZE = 32

#: Maximum plaintext length (in codepoints) accepted by the block-mode
#: ``encrypt_bytes`` / ``encrypt_str`` API. Imposed by the 2-codepoint
#: big-endian length prefix written by ``_pad_message``. Raising this cap
#: requires a wire-format change (v7, deferred per ROADMAP.md §3.7).
MAX_PLAINTEXT_CODEPOINTS = 0xFFFF


def _secure_float() -> float:
    """Cryptographically secure float in [0, 1) via os.urandom."""
    return int.from_bytes(os.urandom(8), 'big') / (2 ** 64)


def _secure_randint(low: int, high: int) -> int:
    """Cryptographically secure integer in [low, high) via secrets."""
    span = high - low
    if span <= 0:
        raise ValueError(f"Invalid range [{low}, {high})")
    return secrets.randbelow(span) + low


def is_prime(n: int) -> bool:
    """Check if a number is prime."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True


def generate_prime_numbers(count: int = 10,
                           min_val: int = 1_000_000,
                           max_val: int = 15_000_000) -> list[int]:
    """Generate *count* distinct primes drawn uniformly from [min_val, max_val].

    Default range [1 000 000, 15 000 000] contains ≈ 829 000 primes.
    A 10-element key (ordered, no repetition) from this range gives a key
    space of ≈ 2^196.6 (≈ 2^98.3 post-Grover), meeting the 2^98 PQ target.
    """
    primes: list[int] = []
    max_attempts = (max_val - min_val) * 4
    attempts = 0
    while len(primes) < count and attempts < max_attempts:
        num = secrets.randbelow(max_val - min_val + 1) + min_val
        if is_prime(num) and num not in primes:
            primes.append(num)
        attempts += 1
    if len(primes) < count:
        raise RuntimeError(
            f"Could not find {count} distinct primes in [{min_val}, {max_val}] "
            f"after {max_attempts} attempts — widen the range."
        )
    return primes


# ─── HMAC session helpers ────────────────────────────────────────────────────

def _validate_nonce(nonce: bytes) -> None:
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__!r}.")
    if len(nonce) != _NONCE_SIZE:
        raise ValueError(
            f"Nonce must be exactly {_NONCE_SIZE} bytes, got {len(nonce)}."
        )


def _validate_cypher(cypher: list[int]) -> None:
    if not isinstance(cypher, list):
        raise TypeError(f"Cypher must be a list, got {type(cypher).__name__!r}.")
    for i, token in enumerate(cypher):
        if not isinstance(token, int) or isinstance(token, bool):
            raise TypeError(
                f"Cypher token at index {i} ({token!r}) is not an integer."
            )
        if token < 0:
            raise ValueError(
                f"Cypher token at index {i} ({token!r}) is negative; "
                "all tokens must be non-negative integers."
            )


def _validate_key(key: list[int]) -> None:
    """Validate that *key* is a non-empty list of distinct primes > 1.

    Raises ValueError if the key is empty, contains a composite or unit
    element, or contains duplicate elements.  Call this at the entry point
    of every public API that accepts a key so that callers get a clear error
    rather than a ZeroDivisionError or a silent security degradation.
    """
    if not key:
        raise ValueError("Key must be a non-empty list of integers.")
    seen: set[int] = set()
    for i, k in enumerate(key):
        if not is_prime(k):
            raise ValueError(
                f"Key element at index {i} ({k!r}) is not prime. "
                "All key elements must be prime integers greater than 1."
            )
        if k in seen:
            raise ValueError(
                f"Key element {k!r} at index {i} is a duplicate. "
                "All key elements must be distinct."
            )
        seen.add(k)


def _key_bytes(key: list[int]) -> bytes:
    """Serialise key list to fixed-width bytes for HMAC keying."""
    return b''.join(k.to_bytes(5, 'big') for k in key)


def _is_noise_pos(kb: bytes, nonce: bytes, ct_pos: int, noise_p: float) -> bool:
    """Return True iff ciphertext position *ct_pos* should hold a noise token.

    This decision is made deterministically via HMAC-SHA256 keyed with the
    serialised encryption key, so an attacker without the key cannot distinguish
    noise positions from real-token positions — eliminating the divisibility
    oracle that made the original design vulnerable.
    """
    digest = hmac.new(kb,
                      nonce + b'\x00' + ct_pos.to_bytes(5, 'big'),
                      hashlib.sha256).digest()
    val = int.from_bytes(digest[:8], 'big') / 2**64   # uniform in [0, 1)
    return val < noise_p


def _derive_addend(kb: bytes, nonce: bytes, real_idx: int,
                   key_element: int) -> int:
    """Return a per-real-token addend in [1, key_element − 1].

    Because *key_element* is prime every value in (0, key_element) is coprime
    to it.  The addend is derived from HMAC(key, nonce, real_idx), so without
    the key it is computationally unpredictable.  Adding it to ``char × key[i]``
    makes real tokens non-divisible by any key element and statistically unique
    even for repeated characters — defeating frequency analysis and all
    divisibility-based key-recovery attacks.
    """
    digest = hmac.new(kb,
                      nonce + b'\x01' + real_idx.to_bytes(5, 'big'),
                      hashlib.sha256).digest()
    return (int.from_bytes(digest[:4], 'big') % (key_element - 1)) + 1


def _derive_noise_char(kb: bytes, nonce: bytes, ct_pos: int) -> int:
    """Return a noise 'character' codepoint in [32, 127] derived from HMAC.

    Domain separator ``b'\\x04'`` isolates this from all real-token derivations.
    Noise tokens are generated as ``noise_c * k + noise_addend`` — the same
    formula used for real tokens — so they are never exact multiples of k and
    therefore can never equal ``known_cp * k`` for any integer ``known_cp``.
    This defeats the known-plaintext divisibility attack that targeted old noise
    tokens whose range ``[k*32, k*129)`` could contain the value ``known_cp*k``.
    """
    digest = hmac.new(kb,
                      nonce + b'\x04' + ct_pos.to_bytes(5, 'big'),
                      hashlib.sha256).digest()
    return (int.from_bytes(digest[:4], 'big') % 96) + 32   # [32, 127]


def _derive_noise_token_addend(kb: bytes, nonce: bytes, ct_pos: int,
                               key_element: int) -> int:
    """Return a per-noise-token addend in [1, key_element − 1].

    Domain separator ``b'\\x05'`` isolates this from real-token addend
    derivation (domain ``b'\\x01'``).  With ``noise_addend ∈ [1, k-1]``,
    the noise token ``noise_c * k + noise_addend`` is never divisible by k,
    making it indistinguishable from a real token under GCD analysis.
    """
    digest = hmac.new(kb,
                      nonce + b'\x05' + ct_pos.to_bytes(5, 'big'),
                      hashlib.sha256).digest()
    return (int.from_bytes(digest[:4], 'big') % (key_element - 1)) + 1


def _derive_noise_p(kb: bytes, nonce: bytes) -> float:
    """Derive noise probability deterministically in [0.75, 0.99] from key and nonce.

    HMAC-SHA256 is keyed with the serialised encryption key and bound to the
    per-message nonce via domain separator ``b'\x02'``.  Because the nonce is
    fresh per message and the key is secret, the derived value is
    cryptographically unpredictable to any passive observer — it is never
    written to or stored in the ciphertext.
    """
    digest = hmac.new(kb, nonce + b'\x02', hashlib.sha256).digest()
    t = int.from_bytes(digest[:8], 'big') / 2**64   # uniform in [0, 1)
    return 0.75 + t * (0.99 - 0.75)


def _varint_keystream(kb: bytes, nonce: bytes, length: int) -> bytes:
    """Generate *length* keystream bytes for masking the varint blob.

    Uses CTR-mode HMAC-SHA256: each 32-byte block is
    ``HMAC(key_bytes, nonce || b'\\x07' || uint32_be(block_index))``.
    Domain separator ``b'\\x07'`` is reserved exclusively for this purpose
    and does not overlap with any other derivation domain.

    Rationale: raw LEB128-encoded token values (c × k + addend,
    c ∈ [32, 127], k ≈ 10⁶) always occupy exactly 4 bytes.  In 4-byte
    LEB128 encoding bytes 0-2 carry MSB=1 (continuation) and byte 3
    carries MSB=0 (terminal), producing a 3:1 MSB bias that fails every
    NIST SP 800-22 frequency test.  XORing the varint blob with this
    keystream eliminates the structural bias without altering the wire
    layout (nonce ‖ masked_blob ‖ auth_tag).
    """
    out = bytearray()
    block = 0
    while len(out) < length:
        digest = hmac.new(
            kb,
            nonce + b'\x07' + block.to_bytes(4, 'big'),
            hashlib.sha256,
        ).digest()
        out.extend(digest)
        block += 1
    return bytes(out[:length])


def _compute_auth_tag(kb: bytes, aad: bytes, payload: bytes) -> bytes:
    """Compute HMAC-SHA256 authentication tag for payload and optional AAD.

    Domain separator ``b'\x03'`` is used to isolate authentication from
    schedule/addend/noise derivation domains.
    """
    aad_len = len(aad).to_bytes(4, 'big')
    msg = b'\x03' + aad_len + aad + payload
    return hmac.new(kb, msg, hashlib.sha256).digest()


def _decode_v5_unauth(ciphertext: bytes, key: list[int]) -> str:
    """Legacy unauthenticated decode for v5 payloads (nonce || varint_blob)."""
    if len(ciphertext) < _NONCE_SIZE:
        raise ValueError(
            f"Ciphertext too short: {len(ciphertext)} bytes; "
            f"header requires at least {_NONCE_SIZE} bytes (nonce)."
        )
    nonce = ciphertext[:_NONCE_SIZE]
    token_blob = ciphertext[_NONCE_SIZE:]
    try:
        tokens = _b128_decode_tokens(token_blob)
    except IndexError as exc:
        raise ValueError(
            "Legacy v5 payload contains a truncated varint (continuation bit "
            "set on final byte); ciphertext is malformed."
        ) from exc
    return "".join(chr(c) for c in decrypt(nonce, tokens, key))


# ─── Plaintext padding ───────────────────────────────────────────────────────

def _pad_message(msg: list[int], kb: bytes, nonce: bytes) -> list[int]:
    """Pad *msg* to the next power-of-two block size.

    Layout: [len_hi, len_lo] + original_msg + hmac_padding
    where block_size = max(16, smallest power of 2 strictly > len(msg)).
    Total output length: 2 + block_size.

    The 2-codepoint length prefix stores the original message length as a
    big-endian 16-bit integer (max 65535 codepoints).  Padding codepoints
    are HMAC-derived from (key, nonce, pad_index) using domain separator
    ``b'\x06'``, placing each in printable ASCII [32, 126].  HMAC-derived
    padding makes the scheme fully deterministic given (key, nonce, plaintext),
    which enables cross-implementation Known-Answer Tests (KATs).
    """
    n = len(msg)
    if n > MAX_PLAINTEXT_CODEPOINTS:
        raise ValueError(
            f"Message too long for 2-byte length prefix "
            f"(got {n} codepoints, max {MAX_PLAINTEXT_CODEPOINTS}). "
            f"See napqes.MAX_PLAINTEXT_CODEPOINTS and docs/CAVEATS.md."
        )
    block_size = max(16, 1 << n.bit_length())   # smallest power of 2 strictly > n
    pad_len    = block_size - n
    padding: list[int] = []
    for i in range(pad_len):
        d = hmac.new(kb, nonce + b'\x06' + i.to_bytes(4, 'big'), hashlib.sha256).digest()
        padding.append((int.from_bytes(d[:4], 'big') % 95) + 32)  # [32, 126]
    return [n >> 8, n & 0xFF] + msg + padding


def _unpad_message(padded: list[int]) -> list[int]:
    """Recover the original message from a padded codepoint list.

    Reads the 2-codepoint big-endian length prefix written by ``_pad_message``
    and slices the original content from the padded buffer.
    """
    if len(padded) < 2:
        raise ValueError("Padded message too short to contain length prefix.")
    n = (padded[0] << 8) | padded[1]
    if 2 + n > len(padded):
        raise ValueError(
            f"Length prefix ({n}) exceeds available data ({len(padded) - 2} bytes)."
        )
    return padded[2 : 2 + n]


# ─── Core encrypt / decrypt ──────────────────────────────────────────────────

def encrypt(message: list[int], key: list[int]) -> tuple[bytes, list[int]]:
    """Encrypt *message* (list of integer codepoints).

    Returns ``(nonce, tokens)``; ``encrypt_str`` / ``encrypt_bytes`` embed
    them in a single self-contained ciphertext.  The noise probability is
    derived deterministically from the key and nonce via HMAC-SHA256 and is
    never transmitted — a passive observer cannot recover it without the key.

    Security enhancements:
      • Noise probability is HMAC-derived from key+nonce per call, hidden
        from ciphertext observers and unpredictable without the secret key.
      • Plaintext is transparently padded to a power-of-two block size,
        reducing length leakage to revealing only the power-of-two bucket.
      • Noise positions and real-token addends are HMAC-derived, so the
        key cannot be recovered via divisibility, frequency, or ratio attacks.
    """
    _validate_key(key)
    nonce    = secrets.token_bytes(16)
    kb       = _key_bytes(key)
    noise_probability = _derive_noise_p(kb, nonce)
    padded   = _pad_message(message, kb, nonce)
    K        = len(key)

    cypher:   list[int] = []
    real_idx: int = 0
    ct_pos:   int = 0

    for c in padded:
        while True:
            if _is_noise_pos(kb, nonce, ct_pos, noise_probability):
                # Noise tokens use noise_c * k + noise_addend — same formula
                # as real tokens.  noise_c ∈ [32,127] and noise_addend ∈ [1,k−1]
                # are HMAC-derived (domains 0x04, 0x05), so the token is
                # never an exact multiple of k and can never equal
                # known_cp * k for any integer known_cp, defeating the
                # known-plaintext divisibility attack on noise tokens.
                k          = key[real_idx % K]
                noise_c    = _derive_noise_char(kb, nonce, ct_pos)
                noise_add  = _derive_noise_token_addend(kb, nonce, ct_pos, k)
                cypher.append(noise_c * k + noise_add)
                ct_pos += 1
            else:
                k      = key[real_idx % K]
                addend = _derive_addend(kb, nonce, real_idx, k)
                cypher.append(c * k + addend)
                ct_pos  += 1
                real_idx += 1
                break

    return nonce, cypher


def _decrypt_with_noise_p(nonce: bytes, cypher: list[int], key: list[int],
                          noise_probability: float) -> list[int]:
    """Internal decrypt with an explicit noise_probability.

    Used by the legacy v2/v3 backward-compat path in ``decrypt_str``, which
    reads the stored noise_p from the old colon-delimited ciphertext format.
    New code should always use the public ``decrypt`` API.
    """
    _validate_key(key)
    kb       = _key_bytes(key)
    K        = len(key)
    padded:  list[int] = []
    real_idx: int = 0

    for ct_pos, token in enumerate(cypher):
        if not _is_noise_pos(kb, nonce, ct_pos, noise_probability):
            k      = key[real_idx % K]
            addend = _derive_addend(kb, nonce, real_idx, k)
            padded.append((token - addend) // k)
            real_idx += 1

    return _unpad_message(padded)


def decrypt(nonce: bytes, cypher: list[int], key: list[int]) -> list[int]:
    """Decrypt tokens produced by ``encrypt``.

    *noise_probability* is derived from *key* and *nonce* via HMAC-SHA256,
    exactly as during encryption — it is never transmitted or required as a
    parameter.  A wrong key or nonce yields incorrect output without raising
    an error; callers should verify plaintext validity independently.
    Padding added by ``encrypt`` is stripped automatically.
    """
    _validate_nonce(nonce)
    _validate_cypher(cypher)
    _validate_key(key)
    kb = _key_bytes(key)
    noise_probability = _derive_noise_p(kb, nonce)
    return _decrypt_with_noise_p(nonce, cypher, key, noise_probability)


# ─── Base-128 (varint) token encoding ────────────────────────────────────────
# Encodes each integer token as a Protocol-Buffers-style unsigned varint:
# 7 bits are stored per byte; the MSB is 1 if more bytes follow, 0 for the
# final byte of each value.  All encoded bytes are concatenated.

def _b128_encode_tokens(tokens: list[int]) -> bytes:
    """Encode a list of non-negative integers as concatenated base-128 varints."""
    out = bytearray()
    for n in tokens:
        while n > 0x7F:
            out.append((n & 0x7F) | 0x80)
            n >>= 7
        out.append(n & 0x7F)
    return bytes(out)


def _b128_encode_token(n: int) -> bytes:
    """Encode a single non-negative integer as a base-128 varint."""
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def _b128_decode_tokens(data: bytes) -> list[int]:
    """Decode a concatenated base-128 varint blob back to a list of integers."""
    tokens: list[int] = []
    i = 0
    while i < len(data):
        value = 0
        shift = 0
        while True:
            b = data[i]; i += 1
            value |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        tokens.append(value)
    return tokens


# ─── Binary transport ───────────────────────────────────────────────────────────────
# Ciphertext binary format v6 (authenticated):
#   nonce (16 bytes) || varint_blob (variable) || auth_tag (32 bytes)
# where auth_tag = HMAC-SHA256(key_bytes, b'\x03' || len(aad) || aad || payload)
# and payload = nonce || masked_blob
#       masked_blob = varint_blob XOR _varint_keystream(key_bytes, nonce, len(varint_blob))
#
# The scheme now provides confidentiality + integrity/authenticity for v6 data.
# Legacy unauthenticated v5 blobs can still be decoded with explicit opt-in.
#
# The string wrappers base64-encode (RFC 4648) the full binary blob for
# safe embedding in text protocols (JSON, HTTP headers, etc.).
# Compared to v3 (hex-encoded varints), v6 reduces ciphertext size by ~53%
# on binary channels and ~18% on text channels (base64 vs hex).

def encrypt_bytes(message: str, key: list[int], aad: bytes = b"") -> bytes:
    """Encrypt *message* and return a compact binary ciphertext (v6 format).

    Wire layout:  nonce (16 B) || masked_blob || auth_tag (32 B).
    masked_blob = varint_blob XOR _varint_keystream(key_bytes, nonce, len(varint_blob)).
    noise_probability is derived from key+nonce via HMAC and never stored.
    The auth tag is HMAC-SHA256 over the payload (nonce || masked_blob) plus
    optional AAD, providing ciphertext integrity and authenticity.
    No encoding overhead; suitable for binary sockets, files, or any
    binary-safe channel.
    """
    nonce, tokens = encrypt([ord(c) for c in message], key)
    kb = _key_bytes(key)
    varint_blob = _b128_encode_tokens(tokens)
    ks = _varint_keystream(kb, nonce, len(varint_blob))
    masked_blob = bytes(a ^ b for a, b in zip(varint_blob, ks))
    payload = nonce + masked_blob
    tag = _compute_auth_tag(kb, aad, payload)
    return payload + tag


def decrypt_bytes(ciphertext: bytes, key: list[int], aad: bytes = b"",
                  allow_legacy_unauthenticated: bool = False) -> str:
    """Decrypt a binary ciphertext produced by ``encrypt_bytes``.

    Accepts v6 format: nonce (16 B) || masked_blob || auth_tag (32 B).
    masked_blob is XOR-unmasked with _varint_keystream before LEB128 decoding.
    noise_probability is re-derived from key+nonce via HMAC — not read from
    the ciphertext.

    If ``allow_legacy_unauthenticated`` is True, this function will also
    decode old v5 payloads (nonce || varint_blob) without integrity checks.
    """
    _validate_key(key)
    if len(ciphertext) >= (_NONCE_SIZE + _TAG_SIZE):
        kb = _key_bytes(key)
        payload = ciphertext[:-_TAG_SIZE]
        recv_tag = ciphertext[-_TAG_SIZE:]
        calc_tag = _compute_auth_tag(kb, aad, payload)
        if hmac.compare_digest(recv_tag, calc_tag):
            nonce = payload[:_NONCE_SIZE]
            masked_blob = payload[_NONCE_SIZE:]
            ks = _varint_keystream(kb, nonce, len(masked_blob))
            token_blob = bytes(a ^ b for a, b in zip(masked_blob, ks))
            tokens = _b128_decode_tokens(token_blob)
            return "".join(chr(c) for c in decrypt(nonce, tokens, key))
        if not allow_legacy_unauthenticated:
            raise ValueError("Authentication failed: invalid HMAC tag.")
    if allow_legacy_unauthenticated:
        return _decode_v5_unauth(ciphertext, key)
    raise ValueError(
        "Ciphertext is not a valid authenticated v6 payload. "
        "To decode legacy v5 unauthenticated payloads, set "
        "allow_legacy_unauthenticated=True."
    )


# ─── String-level wrappers (base64 of v6 binary) ──────────────────────────────────
# Ciphertext string format v6:
#   base64( nonce || varint_blob || auth_tag )
# Entirely printable ASCII; 0-3 trailing '=' pad chars possible.
# noise_p is HMAC-derived from key+nonce — never stored in the ciphertext.
# Backward-compatible: legacy v5/v3/v2 strings remain decodable with opt-in.

def encrypt_str(message: str, key: list[int], aad: bytes = b"") -> str:
    """Encrypt *message* and return a base64-encoded v6 ciphertext string.

    The string is safe for any ASCII-compatible text channel.  Use
    ``encrypt_bytes`` directly when the transport channel is binary-safe.
    """
    return base64.b64encode(encrypt_bytes(message, key, aad=aad)).decode('ascii')


def decrypt_str(cypher: str, key: list[int], aad: bytes = b"",
                allow_legacy_unauthenticated: bool = False) -> str:
    """Decrypt a ciphertext string produced by ``encrypt_str``.

    Accepts:
      v6  — base64-encoded authenticated binary blob (no colon).
      v5  — base64-encoded unauthenticated binary blob (legacy, opt-in).
      v3  — ``<nonce_hex>:<noise_p_hex>:<b128_tokens_hex>`` (colon-separated).
      v2  — ``<nonce_hex>:<noise_p_hex>:<space-separated decimals>`` (legacy).
    """
    if ":" not in cypher:
        return decrypt_bytes(base64.b64decode(cypher), key, aad=aad,
                             allow_legacy_unauthenticated=allow_legacy_unauthenticated)
    # Legacy v2/v3 path — requires explicit opt-in, same policy as v5.
    if not allow_legacy_unauthenticated:
        raise ValueError(
            "Ciphertext appears to be a legacy v2/v3 colon-delimited format. "
            "These formats carry no integrity protection. To decode them, set "
            "allow_legacy_unauthenticated=True."
        )
    try:
        nonce_hex, noise_p_hex, token_field = cypher.split(":", 2)
    except ValueError:
        raise ValueError(
            "Malformed ciphertext — expected base64 (v6/v5) or "
            "'<nonce_hex>:<noise_p_hex>:<tokens>' (v2/v3)."
        )
    nonce   = bytes.fromhex(nonce_hex)
    noise_p = int(noise_p_hex, 16) / 255.0
    if ' ' in token_field:
        tokens = [int(t) for t in token_field.split()]          # v2
    else:
        tokens = _b128_decode_tokens(bytes.fromhex(token_field))  # v3
    # Use the noise_p stored in the legacy ciphertext (HMAC derivation was
    # introduced in v5; v2/v3 ciphertexts carry their own stored noise_p).
    return "".join(chr(c) for c in _decrypt_with_noise_p(nonce, tokens, key, noise_p))


# ─── Streaming encrypt / decrypt ─────────────────────────────────────────────
# Wire format: nonce (16 B) || varint-encoded tokens || HMAC-SHA256 tag (32 B).
# Identical to the v6 binary layout but without block padding — plaintext
# length is not hidden.  Use the block API when length obfuscation is required.
# encrypt_stream / decrypt_stream are their own round-trip pair and are not
# cross-compatible with encrypt_bytes / decrypt_bytes (padding differs).

def encrypt_stream(
    plaintext: Iterable[str],
    key: list[int],
    aad: bytes = b"",
) -> Generator[bytes, None, None]:
    """Yield nonce, per-character token bytes, then HMAC-SHA256 auth tag.

    Wire layout: nonce (16 B) || varint token bytes || auth tag (32 B).
    No block padding is applied — use encrypt_bytes when length obfuscation
    is required.  Decryption must use decrypt_stream.
    """
    _validate_key(key)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    kb = _key_bytes(key)
    noise_p = _derive_noise_p(kb, nonce)
    K = len(key)

    h = hmac.new(kb, digestmod=hashlib.sha256)
    h.update(b'\x03' + len(aad).to_bytes(4, 'big') + aad + nonce)

    yield nonce

    ct_pos = 0
    real_idx = 0

    for char in plaintext:
        c = ord(char)
        buf = bytearray()
        while True:
            if _is_noise_pos(kb, nonce, ct_pos, noise_p):
                k = key[real_idx % K]
                noise_c = _derive_noise_char(kb, nonce, ct_pos)
                noise_add = _derive_noise_token_addend(kb, nonce, ct_pos, k)
                buf.extend(_b128_encode_token(noise_c * k + noise_add))
                ct_pos += 1
            else:
                k = key[real_idx % K]
                addend = _derive_addend(kb, nonce, real_idx, k)
                buf.extend(_b128_encode_token(c * k + addend))
                ct_pos += 1
                real_idx += 1
                break
        chunk = bytes(buf)
        h.update(chunk)
        yield chunk

    yield h.digest()


def decrypt_stream(
    byte_chunks: Iterable[bytes],
    key: list[int],
    aad: bytes = b"",
    *,
    enable_unauthenticated_streaming: bool = False,
) -> Generator[str, None, None]:
    """Decrypt a byte stream produced by encrypt_stream; yield plaintext chars.

    The last 32 bytes are buffered to isolate the HMAC auth tag.  **Plaintext
    characters are yielded before the tag is verified** (release of
    unverified plaintext, RUP). This API is therefore unsafe by default;
    callers must opt in via ``enable_unauthenticated_streaming=True`` to
    acknowledge the RUP semantics.

    For most use cases prefer :func:`decrypt_stream_strict`, which buffers
    all decrypted plaintext and verifies the tag before returning.

    Raises ValueError on truncated input or authentication failure (the auth
    failure is raised after all plaintext has already been yielded).
    """
    if not enable_unauthenticated_streaming:
        raise ValueError(
            "decrypt_stream releases plaintext before the auth tag is "
            "verified (RUP). Pass enable_unauthenticated_streaming=True to "
            "acknowledge this, or use decrypt_stream_strict to buffer + "
            "verify before any plaintext is returned."
        )
    _validate_key(key)
    kb = _key_bytes(key)
    chunk_iter = iter(byte_chunks)

    # Phase 1: read nonce from the head of the stream
    nonce_buf = bytearray()
    for chunk in chunk_iter:
        nonce_buf.extend(chunk)
        if len(nonce_buf) >= _NONCE_SIZE:
            leftover = bytes(nonce_buf[_NONCE_SIZE:])
            nonce = bytes(nonce_buf[:_NONCE_SIZE])
            break
    else:
        raise ValueError(
            f"Stream truncated: nonce incomplete "
            f"({len(nonce_buf)}/{_NONCE_SIZE} bytes)."
        )

    noise_p = _derive_noise_p(kb, nonce)
    K = len(key)
    h = hmac.new(kb, digestmod=hashlib.sha256)
    h.update(b'\x03' + len(aad).to_bytes(4, 'big') + aad + nonce)

    tail = bytearray(leftover)
    varint_buf: bytearray = bytearray()
    ct_pos = 0
    real_idx = 0

    def _drain(data: bytes) -> Generator[str, None, None]:
        nonlocal ct_pos, real_idx
        h.update(data)
        for b in data:
            varint_buf.append(b)
            if not (b & 0x80):
                value = 0
                shift = 0
                for vb in varint_buf:
                    value |= (vb & 0x7F) << shift
                    shift += 7
                varint_buf.clear()
                if not _is_noise_pos(kb, nonce, ct_pos, noise_p):
                    k = key[real_idx % K]
                    addend = _derive_addend(kb, nonce, real_idx, k)
                    yield chr((value - addend) // k)
                    real_idx += 1
                ct_pos += 1

    # Phase 2: slide through chunks, keeping last _TAG_SIZE bytes in tail
    for chunk in chunk_iter:
        tail.extend(chunk)
        safe_len = len(tail) - _TAG_SIZE
        if safe_len > 0:
            yield from _drain(bytes(tail[:safe_len]))
            del tail[:safe_len]

    # Phase 3: split tail into body remainder and auth tag
    if len(tail) < _TAG_SIZE:
        raise ValueError(
            f"Stream truncated: need {_TAG_SIZE}-byte auth tag, "
            f"only {len(tail)} bytes remain."
        )

    body_remainder = bytes(tail[:-_TAG_SIZE])
    recv_tag = bytes(tail[-_TAG_SIZE:])

    if body_remainder:
        yield from _drain(body_remainder)

    # Phase 4: verify auth tag
    if not hmac.compare_digest(h.digest(), recv_tag):
        raise ValueError("Authentication failed: invalid HMAC tag.")


def decrypt_stream_strict(
    byte_chunks: Iterable[bytes],
    key: list[int],
    aad: bytes = b"",
) -> str:
    """Authenticated streaming decrypt: buffer all plaintext, verify, return.

    Consumes the full ``byte_chunks`` iterable, verifies the HMAC-SHA256
    auth tag, and only then returns the joined plaintext string. No partial
    plaintext escapes this function on authentication failure.

    Use this in preference to :func:`decrypt_stream` whenever the consumer
    cannot tolerate seeing unverified plaintext (i.e. nearly always).
    """
    chars: list[str] = []
    gen = decrypt_stream(
        byte_chunks, key, aad,
        enable_unauthenticated_streaming=True,
    )
    for ch in gen:
        chars.append(ch)
    return "".join(chars)