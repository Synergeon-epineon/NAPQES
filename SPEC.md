# NAPSEQ Wire Format Specification — Version 6 (Frozen)

**Version:** v6 (frozen 2026-05-12)
**Status:** Normative reference for all NAPSEQ implementations.
**Python reference:** [`napqes.py`](napqes.py) — all normative paragraphs below cite line ranges in that file.
**Companion documents:** [`docs/CAVEATS.md`](docs/CAVEATS.md), [`docs/SECURITY_TARGET.md`](docs/SECURITY_TARGET.md)

> **Wire-format freeze guarantee.** The v6 byte layout is frozen. Changes to
> confidentiality properties, performance, or side-channel behaviour may
> occur in the Python SDK, C port, or Rust core without altering the wire
> format. Any change to the byte layout requires a new version designator
> (v7+) and a documented deprecation window.

---

## 1. Notation

| Symbol | Meaning |
|---|---|
| `\|\|` | Byte concatenation |
| `B[a:b]` | Bytes from index `a` (inclusive) to `b` (exclusive) |
| `uint16_be(x)` | Big-endian 2-byte unsigned integer encoding of `x` |
| `uint32_be(x)` | Big-endian 4-byte unsigned integer encoding of `x` |
| `varint(x)` | Protocol-Buffers-style base-128 unsigned varint encoding of `x` |
| `HMAC(k, m)` | HMAC-SHA256 keyed with `k` over message `m` |
| `\|\|_v` | Concatenation of varint-encoded token list |
| `noise_p` | Noise insertion probability ∈ [0.75, 0.99], HMAC-derived |

Byte values are written as hex (`0x03`) or Python `b'\x03'`.

---

## 2. Key serialisation

*(napqes.py `_key_bytes`, approx. L94–96)*

A NAPSEQ key is an ordered list of K distinct prime integers, each in
`[1 000 000, 15 000 000]` by default. The list is serialised to a fixed-width
byte string:

```
key_bytes = key[0].to_bytes(5, 'big') || key[1].to_bytes(5, 'big') || … || key[K-1].to_bytes(5, 'big')
```

Each element occupies exactly 5 bytes (the range fits in 24 bits but is
stored as 5 bytes for alignment). `key_bytes` is used as the HMAC key
throughout the session.

> **Key ordering is a security parameter.** `[k_0, k_1, …]` and `[k_1, k_0, …]`
> are distinct keys that produce non-interoperable ciphertexts. Callers must
> preserve element order when storing or transmitting key material.

---

## 3. HMAC derivation functions

All keyed derivations use `HMAC-SHA256(key_bytes, domain_byte || context)`.
Domain bytes are non-overlapping single bytes; the 5-byte context size is
chosen to allow 40-bit position counters without truncation.

### 3.1 Noise probability  *(napqes.py `_derive_noise_p`, approx. L147–157)*

```
noise_p_raw = HMAC(key_bytes, b'\x02' || nonce)   # 32-byte digest
t           = uint64_be(noise_p_raw[0:8]) / 2^64  # uniform in [0, 1)
noise_p     = 0.75 + t × (0.99 − 0.75)            # ∈ [0.75, 0.99]
```

`noise_p` is **never stored in the ciphertext**. The receiver re-derives it
from `key_bytes` and `nonce`.

### 3.2 Noise position oracle  *(napqes.py `_is_noise_pos`, approx. L97–106)*

For each ciphertext slot `ct_pos` (0-indexed):

```
h    = HMAC(key_bytes, nonce || b'\x00' || uint40_be(ct_pos))
val  = uint64_be(h[0:8]) / 2^64
is_noise = (val < noise_p)
```

### 3.3 Real-token addend  *(napqes.py `_derive_addend`, approx. L108–118)*

For each real-plaintext token at sequential index `real_idx`:

```
h      = HMAC(key_bytes, nonce || b'\x01' || uint40_be(real_idx))
addend = uint32_be(h[0:4]) mod (key_element − 1) + 1   # ∈ [1, key_element − 1]
```

### 3.4 Noise character codepoint  *(napqes.py `_derive_noise_char`, approx. L122–131)*

```
h         = HMAC(key_bytes, nonce || b'\x04' || uint40_be(ct_pos))
noise_c   = uint32_be(h[0:4]) mod 96 + 32              # ∈ [32, 127]
```

### 3.5 Noise-token addend  *(napqes.py `_derive_noise_token_addend`, approx. L134–144)*

```
h           = HMAC(key_bytes, nonce || b'\x05' || uint40_be(ct_pos))
noise_addend = uint32_be(h[0:4]) mod (key_element − 1) + 1  # ∈ [1, key_element − 1]
```

### 3.6 Authentication tag  *(napqes.py `_compute_auth_tag`, approx. L158–163)*

```
auth_tag = HMAC(key_bytes,
    b'\x03' || uint32_be(len(aad)) || aad || payload)
```

where `payload = nonce || masked_blob` (see §5).

### 3.7 Varint keystream  *(napqes.py `_varint_keystream`)*

Raw LEB128-encoded token values (`c × k + addend`, `c ∈ [32, 127]`, `k ≈ 10⁶`)
always occupy exactly 4 bytes.  In 4-byte LEB128 encoding bytes 0–2 carry
MSB=1 (continuation) and byte 3 carries MSB=0 (terminal), producing a 3:1
MSB bias that fails NIST SP 800-22 frequency tests.  To eliminate this
structural bias the varint blob is XOR-masked with a keystream before being
placed in the ciphertext:

```
For block_index = 0, 1, 2, …:
    block[block_index] = HMAC(key_bytes, nonce || b'\x07' || uint32_be(block_index))
keystream = block[0] || block[1] || …        # truncated to len(varint_blob)
masked_blob = varint_blob XOR keystream[:len(varint_blob)]
```

Domain byte `0x07` is reserved exclusively for this derivation.  The receiver
re-derives the identical keystream from `key_bytes` and `nonce` (both
already available at decryption time), XORs the received `masked_blob`, and
then LEB128-decodes the recovered varint blob.

Domain-byte summary:

| Domain byte | Purpose |
|---|---|
| `0x00` | Noise position oracle |
| `0x01` | Real-token addend |
| `0x02` | Noise probability |
| `0x03` | Authentication tag |
| `0x04` | Noise character codepoint |
| `0x05` | Noise-token addend |
| `0x06` | Padding codepoint derivation |
| `0x07` | Varint blob keystream masking |
| `0x08` | Per-chunk authentication tag (streaming AE) |
| `0x09` | Final sentinel tag (streaming AE, binds total chunk count) |

---

## 4. Token encoding

*(napqes.py `_b128_encode_tokens`, `_b128_decode_tokens`, approx. L279–332)*

Tokens are unsigned integers encoded as Protocol-Buffers-style unsigned
varints (LEB128 / base-128):

- Each 7 bits of the value occupy one byte.
- Bytes are emitted least-significant group first.
- The MSB of each byte is `1` if more bytes follow, `0` for the final byte.
- Single-byte tokens (value ≤ 127) are stored as one byte with MSB `0`.

Token list → varint blob:

```
varint_blob = varint(token[0]) || varint(token[1]) || … || varint(token[N-1])
```

Decoding is unambiguous because each varint is self-delimiting.

---

## 5. Block ciphertext wire format (v6)

*(napqes.py `encrypt_bytes`, `decrypt_bytes`, approx. L335–386)*

```
ciphertext_binary = nonce (16 bytes) || masked_blob (variable) || auth_tag (32 bytes)
```

where `masked_blob = varint_blob XOR keystream` (see §3.7).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       nonce (16 bytes)                        |
|                           (cont.)                             |
|                           (cont.)                             |
|                           (cont.)                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          masked_blob (variable length, XOR-masked)  …         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      auth_tag (32 bytes)                      |
|                           (cont.)                             |
|                           (cont.)                             |
|                           (cont.)                             |
|                           (cont.)                             |
|                           (cont.)                             |
|                           (cont.)                             |
|                           (cont.)                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**String encoding.** `encrypt_str` / `decrypt_str` Base64-encode
(RFC 4648 standard alphabet, with `=` padding) the full binary ciphertext.
The resulting string contains only printable ASCII characters.

**Minimum valid ciphertext length:** 16 (nonce) + 0 (empty varint_blob) + 32 (tag) = **48 bytes** binary; **64 characters** base64.

---

## 6. Plaintext padding scheme

*(napqes.py `_pad_message`, `_unpad_message`, approx. L174–203)*

Block-mode encryption applies a power-of-two padding scheme before token
encoding:

```
n          = len(plaintext_codepoints)   # ∈ [1, MAX_PLAINTEXT_CODEPOINTS]
block_size = max(16, smallest power of 2 strictly > n)
For i in range(block_size − n):
    d      = HMAC(key_bytes, nonce || 0x06 || uint32_be(i))
    pad[i] = uint32_be(d[0:4]) mod 95 + 32              # ∈ [32, 126]
padded     = [n >> 8, n & 0xFF] + plaintext_codepoints + pad
```

Padding codepoints are HMAC-derived from `(key_bytes, nonce, pad_index)` using
domain separator `0x06`. This makes the full scheme **deterministic** given
(key, nonce, plaintext): given the same inputs, all implementations must produce
byte-identical ciphertext. HMAC-derived padding is indistinguishable from real
tokens to an observer without the key (same range, same token formula).

**Length cap.** `n` must satisfy `n ≤ MAX_PLAINTEXT_CODEPOINTS = 0xFFFF`
(65535). Exceeding this raises `ValueError`. See CAV-002.

**Length leakage.** The ciphertext length reveals which power-of-two bucket
the plaintext length occupies (`{16, 32, 64, 128, …, 65536}`). This leaks
up to `⌈log₂(n)⌉` bits of length information. See CAV-003.

---

## 7. Token construction

*(napqes.py `encrypt`, approx. L206–277)*

Given `padded` (list of integer codepoints), `key` (list of K primes),
`key_bytes`, `nonce`:

```
For each codepoint c in padded (real_idx tracks real-token count, ct_pos all slots):
    LOOP:
        if is_noise(ct_pos):
            k          = key[real_idx % K]
            noise_c    = derive_noise_char(ct_pos)       # ∈ [32, 127]
            noise_add  = derive_noise_addend(ct_pos, k)  # ∈ [1, k−1]
            token      = noise_c × k + noise_add
            emit token; ct_pos += 1
            (do NOT advance real_idx)
        else:
            k      = key[real_idx % K]
            addend = derive_addend(real_idx, k)          # ∈ [1, k−1]
            token  = c × k + addend
            emit token; ct_pos += 1; real_idx += 1
            BREAK
```

The loop ensures every real codepoint is emitted exactly once. Noise tokens
may appear in any adjacent slots before the real token for that position.

**Decryption.** *(napqes.py `_decrypt_with_noise_p`, approx. L379–406)*

```
For each (ct_pos, token):
    if NOT is_noise(ct_pos):
        k      = key[real_idx % K]
        addend = derive_addend(real_idx, k)
        codepoint = (token − addend) // k
        append codepoint; real_idx += 1
```

Noise tokens are skipped. The unpadded codepoint list is recovered via
`_unpad_message`.

---

## 8. Streaming wire format

*(napqes.py `encrypt_stream`, `decrypt_stream`, approx. L471–651)*

The streaming format uses the **same byte layout** as the block format,
including the domain-0x07 XOR keystream mask over the varint blob:

```
stream = nonce (16 bytes) || masked_blob (variable) || auth_tag (32 bytes)
masked_blob = varint_blob XOR _varint_keystream(key_bytes, nonce, len(varint_blob))
```

Differences from block mode:
- **No padding.** Plaintext length is not hidden; `_pad_message` is not
  applied. The plaintext length is therefore directly deducible from the
  ciphertext token count.
- **No length cap.** The 16-bit cap of block mode does not apply.
- **Streaming RUP.** `decrypt_stream` yields plaintext characters before
  the auth tag at the end of the stream is verified. See CAV-001 and §10.

The stream and block APIs are **not cross-compatible**: a block ciphertext
cannot be decoded with `decrypt_stream` and vice versa, because the padded
token count differs (block mode prepends a 2-token length prefix and pads
to the next power-of-two block size).

---

## 8.1 Streaming AE wire format (v6s-ae) — CAV-001 fix

*(napqes.py `encrypt_stream_ae`, `decrypt_stream_ae`)*

The v6s-ae format adds per-chunk HMAC-SHA256 tags to eliminate RUP (CAV-001).
`decrypt_stream_ae` verifies each chunk's tag before yielding its plaintext;
a final sentinel tag authenticates the total chunk count.

```
stream_ae = nonce (16 bytes)
            || [uint32_be(chunk_len) || masked_chunk || chunk_tag(32 bytes)] × N
            || uint32_be(0) || final_tag(32 bytes)
```

**chunk_tag** for chunk index `i`:

```
chunk_tag = HMAC(key_bytes,
    b'\x08' || uint32_be(len(aad)) || aad || nonce || uint32_be(i) || masked_chunk)
```

**final_tag** (sentinel, `chunk_len = 0`):

```
final_tag = HMAC(key_bytes,
    b'\x09' || uint32_be(len(aad)) || aad || nonce || uint32_be(N))
```

where `N` is the total number of non-sentinel chunks.

The domain-0x07 XOR keystream is applied cumulatively across all chunks
in the same way as the basic streaming format — the masked bytes are
identical for equal inputs.

**Security properties:**
- Per-chunk tags prevent any unverified plaintext from reaching the caller.
- Chunk index `i` in each tag prevents chunk-reordering attacks.
- `N` in `final_tag` prevents silent truncation at a chunk boundary.
- AAD is bound into every tag; cross-session confusion is detected.

**Compatibility:** v6s-ae streams are **not** compatible with `encrypt_stream`
/ `decrypt_stream`. Each pair must be used together.

---

## 9. Legacy format compatibility (read-only, opt-in)

*(napqes.py `decrypt_str`, approx. L397–; `decrypt_bytes`, approx. L360–)*

| Format | Identifier | Auth | Wire layout |
|---|---|---|---|
| v6 | No colon in base64 string | HMAC-SHA256 | nonce \|\| varint_blob \|\| tag |
| v5 | No colon, no auth tag | None | nonce \|\| varint_blob |
| v3 | `nonce_hex:noise_p_hex:tokens_hex` | None | hex-encoded varints |
| v2 | `nonce_hex:noise_p_hex:space-sep-decimals` | None | decimal token list |

v5, v3, and v2 are **read-only** (there are no `encrypt_v5/v3/v2` functions).
Decoding requires `allow_legacy_unauthenticated=True`. See CAV-005.

---

## 10. Error model

| Condition | Raised by | Exception |
|---|---|---|
| Tag mismatch (v6 block) | `decrypt_bytes`, `decrypt_str` | `ValueError("Authentication failed: invalid HMAC tag.")` |
| Ciphertext too short for v6 + auth declined | `decrypt_bytes` | `ValueError("Ciphertext is not a valid authenticated v6 payload…")` |
| Message too long (block mode) | `_pad_message` via `encrypt_bytes` | `ValueError("Message too long for 2-byte length prefix…")` |
| Streaming without RUP opt-in | `decrypt_stream` | `ValueError("decrypt_stream releases plaintext before the auth tag…")` |
| Truncated stream (no nonce) | `decrypt_stream` | `ValueError("Stream truncated: nonce incomplete…")` |
| Truncated stream (short tag) | `decrypt_stream` | `ValueError("Stream truncated: need 32-byte auth tag…")` |
| Tag mismatch (streaming) | `decrypt_stream` | `ValueError("Authentication failed: invalid HMAC tag.")` |
| Malformed legacy ciphertext | `decrypt_str` | `ValueError("Malformed ciphertext…")` |

---

## 11. Known caveats

See [`docs/CAVEATS.md`](docs/CAVEATS.md) for full triage. Summary:

| ID | Title | Severity | Target |
|---|---|---|---|
| CAV-001 | Streaming RUP | Medium | Fixed — use `encrypt_stream_ae` / `decrypt_stream_ae` (§8.1) |
| CAV-002 | 16-bit length cap | Low | Phase 5 (v7 wire format) |
| CAV-003 | Padding length-bucket leak | Low | Phase 5 (v7 fixed-frame option) |
| CAV-004 | Ciphertext expansion bound | Info | No fix planned |
---

## 12. Test vectors (KAT)

Known-answer test vectors are in [`tests/kat/v6_vectors.json`](tests/kat/v6_vectors.json).
The vector file is generated by [`tests/gen_kats.py`](tests/gen_kats.py) using a
fixed seed, and CI re-derives it on every run to verify determinism.

Each vector specifies:
- `id`: unique test identifier
- `kind`: `"positive"` (expect successful round-trip) or `"negative"` (expect exception)
- `key`: list of prime integers
- `nonce_hex`: hex-encoded 16-byte nonce (for deterministic replay)
- `message`: plaintext string (positive vectors only)
- `aad_hex`: hex-encoded AAD (may be empty string = `""`)
- `ciphertext_hex`: expected `encrypt_bytes` output (positive vectors)
- `expected_exception`: exception substring (negative vectors)
- `description`: human-readable note

Implementations conforming to this spec must produce byte-identical
`ciphertext_hex` when given the same `key`, `nonce_hex`, and `message`,
and must raise a matching exception for negative vectors.
