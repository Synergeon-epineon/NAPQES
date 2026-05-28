---
title: "NAPQES Authenticated Encryption with Associated Data"
abbrev: "NAPQES-AEAD"
category: info

docname: draft-napqes-aead-00
submissiontype: IETF
number:
date: 2026-05-12
consensus: false
v: 3

area: Security
workgroup: Crypto Forum Research Group (CFRG)

keyword:
  - authenticated encryption
  - AEAD
  - HMAC
  - post-quantum
  - noise tokens

author:
  - fullname: "[AUTHOR NAME]"
    organization: "[ORGANIZATION]"
    email: "[EMAIL]"

normative:
  RFC2104:   # HMAC
  RFC4868:   # HMAC-SHA256 in IPsec
  FIPS180-4:
    title: "Secure Hash Standard (SHS)"
    author:
      org: NIST
    date: 2015-08
    target: https://csrc.nist.gov/publications/detail/fips/180/4/final
  FIPS198-1:
    title: "The Keyed-Hash Message Authentication Code (HMAC)"
    author:
      org: NIST
    date: 2008-07
    target: https://csrc.nist.gov/publications/detail/fips/198/1/final

informative:
  RFC5116:   # AEAD interface
  RFC7539:   # ChaCha20-Poly1305
  AES-GCM:
    title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
    author:
      org: NIST
    date: 2007-11
    target: https://csrc.nist.gov/publications/detail/sp/800-38/d/final
  GROVER96:
    title: "A fast quantum mechanical algorithm for database search"
    author:
      name: L. K. Grover
    date: 1996
    seriesinfo: "STOC '96, pp. 212–219"
  SP800-22:
    title: "A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications"
    author:
      org: NIST
    date: 2010-04
    target: https://csrc.nist.gov/publications/detail/sp/800/22/rev-1a/final

--- abstract

This document describes NAPQES, an Authenticated Encryption with Associated
Data (AEAD) construction built exclusively from HMAC-SHA256 (FIPS 198-1) and
SHA-256 (FIPS 180-4).  NAPQES combines a prime-indexed token cipher with
HMAC-derived noise injection and a standard HMAC-SHA256 authentication tag.
It does not rely on algebraic structures such as finite-field arithmetic,
group operations, or AES S-box permutations, and is therefore not subject to
Shor's algorithm or hidden-subgroup quantum attacks.  The security of
NAPQES reduces to the pseudorandomness of HMAC-SHA256.

This document specifies the wire format (version 6, frozen), the key
derivation schedule, the token construction, the padding scheme, and the
authentication tag computation.  Known-Answer Test (KAT) vectors are
provided in Appendix A.

--- middle

# Introduction

Classical AEAD constructions such as AES-GCM {{AES-GCM}} and
ChaCha20-Poly1305 {{RFC7539}} rely on algebraic structures — finite-field
multiplication (GCM) or add-rotate-XOR over 32-bit words (ChaCha20) — whose
security against quantum adversaries running Shor's algorithm or
hidden-subgroup variants has not been fully characterised.

NAPQES takes a different approach: the entire construction is defined in
terms of a single primitive, HMAC-SHA256, which is approved under FIPS 198-1
and FIPS 180-4 and whose security reduces to the collision resistance and
pseudorandomness of SHA-256.  Grover's algorithm applies to SHA-256 with a
quadratic speedup, yielding an effective post-quantum security level of
approximately 128 bits for a 256-bit hash.

## Goals

The design goals of NAPQES are:

1. **Single-primitive security.** All cryptographic operations — token
   derivation, noise injection, padding, and authentication — use
   HMAC-SHA256 with domain-separated calls.  No other primitive is required.

2. **FIPS-approved component set.** HMAC-SHA256 and SHA-256 are both approved
   under current NIST standards, facilitating compliance arguments under
   FIPS 140-3 and CMMC.

3. **IND-CCA3 goal.** The scheme targets IND-CCA3 (indistinguishability under
   chosen-ciphertext attack with decryption oracle) under the pseudorandomness
   assumption on HMAC-SHA256.  A formal security reduction is deferred to the
   companion analysis document.

4. **Conventional AEAD interface.** The external API follows the conventions
   of {{RFC5116}}: `Encrypt(K, N, P, A) -> C` and `Decrypt(K, N, C, A) -> P
   or FAIL`.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

The following notation is used throughout:

- `||`      Byte concatenation
- `HMAC(K, M)`  HMAC-SHA256 keyed with K over message M ({{RFC2104}})
- `be5(x)`  The 5 least-significant bytes of x, encoded big-endian
- `varint(x)`  Unsigned LEB128 (Protocol Buffers) encoding of integer x
- `noise_p`   Noise probability, a real in [0.75, 0.99]

# Key Representation

A NAPQES key is an ordered tuple of K distinct prime integers, each in the
range [1 000 000, 15 000 000].  The reference implementation generates keys
using a cryptographically secure random source (FIPS140-3-compliant DRBG).

The key is serialised to a byte string `key_bytes` for use as the HMAC key:

~~~
key_bytes = be5(key[0]) || be5(key[1]) || ... || be5(key[K-1])
~~~

A 10-element key in the range [1 000 000, 15 000 000] provides a key space
of approximately 2^197.67 (approximately 2^98.84 post-Grover), meeting the
2^98 post-quantum security target after Grover's quadratic speedup.

# Domain-Separated HMAC Derivation

All internal values are derived via HMAC-SHA256 with a 1-byte domain
separator prepended to the HMAC message to ensure derivation functions are
computationally independent.

| Domain byte | Function               | Output range              |
|-------------|------------------------|---------------------------|
| `0x00`      | Noise position oracle  | Boolean (threshold on uniform [0,1)) |
| `0x01`      | Real-token addend      | Integer in [1, key[i] − 1]          |
| `0x02`      | Noise probability      | Float in [0.75, 0.99]               |
| `0x03`      | Authentication tag     | 32 bytes (full HMAC output)         |
| `0x04`      | Noise character        | Integer in [32, 127]                |
| `0x05`      | Noise-token addend     | Integer in [1, key[i] − 1]          |
| `0x06`      | Padding codepoint      | Integer in [32, 126]                |

## Noise Probability (domain 0x02)

~~~
d     = HMAC(key_bytes, nonce || 0x02)
t     = bytes_to_uint64_big(d[0:8]) / 2^64    ; uniform in [0, 1)
noise_p = 0.75 + t * (0.99 - 0.75)
~~~

## Noise Position Oracle (domain 0x00)

For ciphertext position `ct_pos`:

~~~
d   = HMAC(key_bytes, nonce || 0x00 || be5(ct_pos))
val = bytes_to_uint64_big(d[0:8]) / 2^64
is_noise(ct_pos) = (val < noise_p)
~~~

## Real-Token Addend (domain 0x01)

For real token at index `real_idx`, using key element `k = key[real_idx mod K]`:

~~~
d      = HMAC(key_bytes, nonce || 0x01 || be5(real_idx))
addend = (bytes_to_uint32_big(d[0:4]) mod (k − 1)) + 1   ; in [1, k−1]
~~~

## Noise Character and Noise-Token Addend (domains 0x04, 0x05)

For noise slot at position `ct_pos`, using key element `k = key[real_idx mod K]`:

~~~
d_c        = HMAC(key_bytes, nonce || 0x04 || be5(ct_pos))
noise_c    = (bytes_to_uint32_big(d_c[0:4]) mod 96) + 32  ; in [32, 127]

d_a        = HMAC(key_bytes, nonce || 0x05 || be5(ct_pos))
noise_add  = (bytes_to_uint32_big(d_a[0:4]) mod (k−1)) + 1
~~~

## Padding Codepoints (domain 0x06)

For padding slot at index `i`:

~~~
d      = HMAC(key_bytes, nonce || 0x06 || be4(i))
pad[i] = (bytes_to_uint32_big(d[0:4]) mod 95) + 32   ; in [32, 126]
~~~

# Plaintext Padding

The padding scheme makes the construction fully deterministic given
(key, nonce, plaintext), which is required for cross-implementation KAT
parity.

~~~
n          = len(plaintext)                    ; in [0, 65535]
block_size = max(16, smallest power of 2 strictly > n)
padded     = [n >> 8, n & 0xFF] || plaintext || pad[0..block_size-n-1]
~~~

The 2-codepoint big-endian length prefix allows recovery of the original
message length.  Padding codepoints are HMAC-derived (domain 0x06) and fall
in the printable-ASCII range [32, 126].

**Known caveat (CAV-003):** the ciphertext length reveals which power-of-two
bucket the plaintext length falls into.  Callers requiring full length-hiding
MUST apply a fixed-frame transport on top.

# Token Construction

Each codepoint `c` in the padded plaintext is encrypted as follows.  Let
`K = len(key)`, `real_idx` the 0-based index of real tokens emitted so far,
`ct_pos` the 0-based index into the ciphertext token array.

~~~
loop for each c in padded:
    while is_noise(ct_pos):
        k         = key[real_idx mod K]
        noise_c   = derive_noise_char(ct_pos)
        noise_add = derive_noise_token_addend(ct_pos, k)
        emit  noise_c * k + noise_add
        ct_pos += 1
    k      = key[real_idx mod K]
    addend = derive_real_addend(real_idx, k)
    emit  c * k + addend
    ct_pos  += 1
    real_idx += 1
~~~

Each real token satisfies:

    token ≡ addend (mod k),   addend ∈ [1, k−1]

so no real token is divisible by any key element, defeating
divisibility-based key-recovery attacks.  Noise tokens follow the same
formula with independently derived noise character and addend, making them
computationally indistinguishable from real tokens without the key.

## Token Encoding

Each token is encoded as an unsigned LEB128 (base-128) varint, following the
Protocol Buffers wire format: 7 bits of value per byte, MSB = 1 if more
bytes follow, MSB = 0 on the final byte of each token.  The encoded tokens
are concatenated to form `varint_blob`.

# Wire Format — Version 6

The binary wire format for block-mode encryption is:

~~~
ciphertext = nonce(16) || varint_blob(variable) || auth_tag(32)
~~~

- `nonce` (16 bytes): uniformly random, generated by a FIPS 140-3 compliant
  DRBG per encryption call.
- `varint_blob` (variable): LEB128-encoded token sequence as described in
  Section 5.1.
- `auth_tag` (32 bytes): HMAC-SHA256 over the payload with optional AAD
  (Section 6).

Minimum valid ciphertext length: **48 bytes**.

String-encoded ciphertext: RFC 4648 standard base64 with `=` padding applied
to the full binary blob.

**Empty plaintext:** `Encrypt(K, N, "", A) = ""` (zero-length output).

## Authentication Tag Computation (domain 0x03)

~~~
aad_len  = len(aad)                    ; 32-bit big-endian
payload  = nonce || varint_blob
tag_msg  = 0x03 || be4(aad_len) || aad || payload
auth_tag = HMAC(key_bytes, tag_msg)    ; 32 bytes
~~~

## Verification

On decryption, the implementation MUST:

1. Verify `len(ciphertext) >= 48`; otherwise return FAIL.
2. Extract `nonce = ciphertext[0:16]`, `tag = ciphertext[-32:]`,
   `varint_blob = ciphertext[16:-32]`.
3. Recompute `auth_tag` as above and compare with `hmac.compare_digest` (or
   equivalent constant-time comparison).  If tags do not match, return FAIL.
4. Decode `varint_blob` to tokens, run the decrypt loop, unpad, return
   plaintext.

Implementations MUST NOT release any plaintext before the tag is verified
(no Release of Unverified Plaintext, RUP).

## Streaming Mode

A streaming variant exists in which padding is not applied and the auth tag
is appended after the token stream.  The stream and block modes are **not
cross-compatible**.  Decryption in streaming mode with verification of the
auth tag before yielding plaintext is provided by `decrypt_stream_strict`;
the RUP variant requires explicit caller opt-in.

**Known caveat (CAV-001):** the streaming RUP API (`decrypt_stream` with
`enable_unauthenticated_streaming=True`) yields plaintext before tag
verification.  Callers SHOULD use `decrypt_stream_strict` instead.

# Security Considerations

## Security Reduction

The confidentiality and integrity of NAPQES reduce to the pseudorandomness
of HMAC-SHA256.  Specifically:

- **Confidentiality (IND-CPA):** Under the PRF assumption on HMAC-SHA256,
  the noise-position oracle `is_noise(ct_pos)` is computationally
  indistinguishable from a uniformly random bit-string to any adversary
  without the key.  The addend derivation further randomises each token
  independently, so the token sequence is computationally pseudorandom.

- **Integrity (EUF-CMA):** The 32-byte HMAC-SHA256 authentication tag
  provides existential unforgeability under chosen-message attack, with
  security level 256 bits against classical adversaries and approximately
  128 bits after Grover's algorithm.

- **AAD binding:** The AAD is included in the tag computation with a
  4-byte length prefix, providing strong commitment: any 1-bit change to
  the AAD produces a uniformly unpredictable change to the expected tag.

## Post-Quantum Analysis

NAPQES does not use finite-field arithmetic, discrete logarithms, lattice
problems, or any structure exploitable by Shor's algorithm or known quantum
hidden-subgroup algorithms.  The sole quantum speedup applicable is Grover's
algorithm applied to SHA-256 preimage search, reducing the effective security
level from 256 bits to approximately 128 bits — still above all recommended
thresholds.

Key enumeration requires testing up to 2^197.67 key candidates (10-element key,
[1M, 15M] range).  Grover's algorithm reduces this to approximately 2^98.84,
which remains computationally infeasible with foreseeable quantum hardware.

## Nonce Requirements

A fresh nonce MUST be generated for each encryption call using a FIPS 140-3
compliant DRBG.  Nonce reuse with the same key and different plaintexts
produces different ciphertexts (the noise probability and all token addends
are nonce-dependent), but may expose information about which token positions
differ.  Nonce reuse is therefore NOT RECOMMENDED.

The nonce is not required to be secret; it is transmitted in the clear as the
first 16 bytes of the ciphertext.

## Length Leakage

Ciphertext length reveals the power-of-two padding bucket of the plaintext
(CAV-003).  For example, plaintexts of 1–15 codepoints always produce the
same padded length of 18 codepoints (2 length prefix + 16 padded).  Callers
requiring full length-hiding MUST apply a fixed-frame transport.

## Key Size and Format

The prime-tuple key format is unusual compared to conventional AEAD keys.
The minimum recommended key is a 10-element prime tuple from [1M, 15M],
providing approximately 2^197.67 classical key entropy and approximately 2^98.84
post-quantum key entropy.  Single-element keys provide approximately 2^23
entropy and are NOT RECOMMENDED for production use.

## Ciphertext Expansion

The noise injection mechanism produces a ciphertext of (1 + noise_p) /
(1 − noise_p) times the padded plaintext length in tokens, plus the
16-byte nonce and 32-byte tag.  For noise_p ≈ 0.87 (midpoint of [0.75,
0.99]), this is approximately 13.5× token expansion, plus LEB128 encoding
overhead.

# IANA Considerations

This document has no IANA actions.

--- back

# Known-Answer Test Vectors {#kat}

The following vectors are a subset of the full KAT corpus maintained in
`tests/kat/v6_vectors.json` in the reference implementation repository.
Conforming implementations MUST produce byte-identical `ciphertext_hex`
for all positive vectors.

## Vector V001 — Empty Message

~~~
Key:      [1000003, 1000033, 1000037, 1000039]
AAD:      (empty)
Nonce:    (none — empty message produces empty ciphertext)
Message:  (empty)
Cipher:   (empty)
~~~

## Vector V002 — Single Character

~~~
Key:      [1000003, 1000033, 1000037, 1000039]
AAD:      (empty)
Message:  "A"
Nonce:    [see v6_vectors.json, id=V002]
Cipher:   [see v6_vectors.json, id=V002]
~~~

## Vector N001 — Auth Tag Tampered

~~~
Key:      [1000003, 1000033, 1000037, 1000039]
Input:    valid V002 ciphertext with last byte XOR 0xFF
Expected: FAIL with "Authentication failed"
~~~

Full vectors with hexadecimal ciphertext fields are provided in
`tests/kat/v6_vectors.json`.  The KAT generator (`tests/gen_kats.py`)
can be used to regenerate and verify the corpus on any conforming
implementation.
