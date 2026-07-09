# NAPSEQ Wire Format Specification — Version 7 (Frozen)

**Version:** v7 (frozen 2026-07-06 — supersedes v6, see CVF1 fix below)
**Status:** Normative reference for all NAPSEQ implementations.
**Python reference:** [`napqes.py`](napqes.py) — all normative paragraphs below cite line ranges in that file.
**Companion documents:** [`docs/CAVEATS.md`](docs/CAVEATS.md), [`docs/SECURITY_TARGET.md`](docs/SECURITY_TARGET.md)

> **v7 supersedes v6 (audit finding CVF1).** The only byte-layout change is
> §4/§5: block-mode tokens are now serialised as fixed-width 8-byte
> big-endian fields instead of variable-length LEB128 varints. Under v6, a
> token's LEB128 byte-length grew with its magnitude — which is a function
> of the plaintext codepoint value — so the serialised blob length (and
> hence ciphertext length) leaked plaintext content even between messages of
> equal padded length. This broke the IND-CPA hiding argument (see
> `docs/napseq-eprint-preprint.tex` Theorem 1). v7's fixed-width encoding
> makes blob length a function only of the token *count* (itself a function
> of the padded codepoint count and the HMAC-derived, content-independent
> noise schedule), never of codepoint values, restoring that argument. v6
> ciphertexts remain readable via explicit opt-in (`legacy_v6_varint=True`);
> they were never insecure against tampering (HMAC authentication was
> unaffected), only against the length side channel described here.
>
> **Wire-format freeze guarantee.** The v7 byte layout is frozen. Changes to
> confidentiality properties, performance, or side-channel behaviour may
> occur in the Python SDK, C port, or Rust core without altering the wire
> format. Any change to the byte layout requires a new version designator
> (v8+) and a documented deprecation window.
>
> **CVF2 fix (domain-separation layout unification, 2026-07-06).** Section 3
> below was revised to unify every HMAC domain derivation onto a single
> `domain_byte || nonce || ctx` layout (previously seven domains used
> `nonce || domain_byte || ctx` while three — `0x03`, `0x08`, `0x09` — used
> an AAD-binding `domain_byte || …` layout that placed the nonce after the
> AAD). This is **not** a wire-layout change (§5's `nonce ‖ masked_blob ‖
> tag` outer shape, and §8.1's frame shape, are unchanged) and so does not
> require a v8 designator under the freeze guarantee above — only the
> *internal* HMAC inputs used to derive noise positions, addends, the
> keystream, and authentication tags changed shape. Ciphertexts produced by
> pre-CVF2 code are **not** decryptable by post-CVF2 code (and vice versa)
> for the same key/nonce/message, since every derived value changes; there
> is no legacy opt-in for this fix (unlike CVF1's `legacy_v6_varint`) because
> the old layout was never a deployed, versioned wire format — it was an
> internal inconsistency between the spec, the proof, and the code. See
> `docs/audit_mitigation_responses.md` (CVF-2) and
> `docs/napseq-eprint-preprint.tex` Remark `rem:domsep`.>
> **CVF7 fix (format applicability and normative status, 2026-07-07).**
> Three wire encodings exist — block mode (§5), the basic streaming format
> (§8), and the online-AE streaming format (§8.1) — and none carries a
> version/format discriminator byte. Block mode and streaming mode are both
> normative and coexist by design (they serve disjoint use cases: bounded,
> length-hidden messages vs. unbounded/memory-constrained streams). Within
> streaming mode, only the online-AE format (§8.1) is normative as of this
> fix: the basic streaming format (§8) is **deprecated and forbidden** for
> producing new ciphertext, retained solely to decrypt streams produced
> before this fix. Format selection is an out-of-band API contract — the
> caller chooses which function to call — not something a decryptor infers
> from ciphertext bytes; implementations MUST NOT auto-detect or negotiate
> down between formats. See `docs/napseq-eprint-preprint.tex`
> §sec:format-applicability and `docs/audit_mitigation_responses.md` (CVF-7).
---

## 1. Notation

| Symbol | Meaning |
|---|---|
| `\|\|` | Byte concatenation |
| `B[a:b]` | Bytes from index `a` (inclusive) to `b` (exclusive) |
| `uint16_be(x)` | Big-endian 2-byte unsigned integer encoding of `x` |
| `uint32_be(x)` | Big-endian 4-byte unsigned integer encoding of `x` |
| `uint64_be(x)` | Big-endian 8-byte unsigned integer encoding of `x` (v7 fixed-width token field) |
| `varint(x)` | **Retired in v7** (see CVF1). Protocol-Buffers-style base-128 unsigned varint encoding of `x`, used only by the legacy v6 decode path (`legacy_v6_varint=True`) and the streaming API (§8), which is not affected by this fix. |
| `HMAC(k, m)` | HMAC-SHA256 keyed with `k` over message `m` |
| `\|\|_v` | Concatenation of fixed-width (v7) or varint-encoded (v6/streaming) token list |
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

> **Minimum `K` (CVF8 fix, 2026-07-07).** The IND-CPA bound
> (`docs/napseq-eprint-preprint.tex`, Theorem 1) includes a key-guessing
> term `q_F·2^(−H∞(k))` where `H∞(k) = log2(|𝒫|!/(|𝒫|−K)!)` is the key's
> min-entropy — **not** its raw `40K`-bit serialised length. For the
> default prime range this is ≈19.16 bits per key element, so `K` **MUST**
> be at least `7` (≈134 bits) to keep this term negligible against the
> paper's ≈128-bit post-Grover target, and `K=10` (the library default,
> ≈196 bits) or higher **SHOULD** be used. `K` below `7` is a materially
> weaker configuration, not merely a smaller margin — see
> `docs/CAVEATS.md` CVF8 for detail. No reference implementation currently
> enforces this floor at the API level; callers who override the default
> `count` passed to `generate_prime_numbers` are responsible for keeping
> `K≥7`.

---

## 3. HMAC derivation functions

> **CVF2 fix (domain-separation layout unification, 2026-07-06).** Prior to
> this fix, domains `0x00`–`0x02` and `0x04`–`0x07` used a *nonce-first*
> input layout (`nonce || domain_byte || ctx`), while domain `0x03`
> (authentication tag) used a *domain-first*, AAD-binding layout
> (`domain_byte || len(aad) || aad || nonce || masked_blob`). Table 1 of
> `docs/napseq-eprint-preprint.tex` stated only the nonce-first formula, so
> reading the wire-format tag definition through that formula silently
> dropped the AAD from the modelled input — an inconsistency between the
> spec, the security proof, and the reference code (audit finding **CVF2**).
> All ten domains now share a single **domain-first** layout,
> `HMAC(key_bytes, domain_byte || nonce || ctx)`, with every variable-width
> field length-prefixed (`uint32_be(len(x)) || x`). This makes domain
> separation unconditional rather than probabilistic: domains differ at
> byte 0, and — because the nonce always occupies bytes 1‥16 — inputs
> within a domain are injective functions of their fixed-width counters or
> length-prefixed AAD. See `docs/napseq-eprint-preprint.tex` Remark
> `rem:domsep` for the updated proof.

All keyed derivations use `HMAC-SHA256(key_bytes, domain_byte || nonce || context)`.
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
h    = HMAC(key_bytes, b'\x00' || nonce || uint40_be(ct_pos))
val  = uint64_be(h[0:8]) / 2^64
is_noise = (val < noise_p)
```

### 3.3 Real-token addend  *(napqes.py `_derive_addend`, approx. L108–118)*

For each real-plaintext token at sequential index `real_idx`:

```
h      = HMAC(key_bytes, b'\x01' || nonce || uint40_be(real_idx))
addend = uint32_be(h[0:4]) mod (key_element − 1) + 1   # ∈ [1, key_element − 1]
```

### 3.4 Noise character codepoint  *(napqes.py `_derive_noise_char`, approx. L122–131)*

```
h         = HMAC(key_bytes, b'\x04' || nonce || uint40_be(ct_pos))
noise_c   = uint32_be(h[0:4]) mod 96 + 32              # ∈ [32, 127]
```

### 3.5 Noise-token addend  *(napqes.py `_derive_noise_token_addend`, approx. L134–144)*

```
h           = HMAC(key_bytes, b'\x05' || nonce || uint40_be(ct_pos))
noise_addend = uint32_be(h[0:4]) mod (key_element − 1) + 1  # ∈ [1, key_element − 1]
```

### 3.6 Authentication tag  *(napqes.py `_compute_auth_tag`, approx. L158–163)*

```
auth_tag = HMAC(key_bytes,
    b'\x03' || nonce || uint32_be(len(aad)) || aad || masked_blob)
```

where `payload = nonce || masked_blob` (see §5); the nonce is split off the
front of `payload` so it occupies the same fixed byte 1‥16 offset used by
every other domain (CVF2 fix — previously the nonce was placed *after* the
AAD, `b'\x03' || len(aad) || aad || nonce || masked_blob`).

### 3.7 Token blob keystream  *(napqes.py `_varint_keystream`)*

**Historical rationale (v6).** Raw LEB128-encoded token values
(`c × k + addend`, `c ∈ [32, 127]`, `k ≈ 10⁶`) always occupied exactly 4
bytes. In 4-byte LEB128 encoding bytes 0–2 carry MSB=1 (continuation) and
byte 3 carries MSB=0 (terminal), producing a 3:1 MSB bias that fails NIST
SP 800-22 frequency tests.

**v7 rationale.** The fixed-width big-endian encoding (§4) has no
continuation-bit structure, but its high-order bytes are frequently zero
(token magnitudes are well under 2⁶⁴), which is its own statistical bias.
In both cases the fix is the same: XOR-mask the token blob with a keystream
before placing it in the ciphertext:

```
For block_index = 0, 1, 2, …:
    block[block_index] = HMAC(key_bytes, b'\x07' || nonce || uint32_be(block_index))
keystream = block[0] || block[1] || …        # truncated to len(token_blob)
masked_blob = token_blob XOR keystream[:len(token_blob)]
```

Domain byte `0x07` is reserved exclusively for this derivation.  The receiver
re-derives the identical keystream from `key_bytes` and `nonce` (both
already available at decryption time), XORs the received `masked_blob`, and
then decodes the recovered token blob (fixed-width for v7, LEB128 for
legacy v6 — see §4).

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
| `0x07` | Token blob keystream masking |
| `0x08` | Per-chunk authentication tag (streaming AE) |
| `0x09` | Final sentinel tag (streaming AE, binds total chunk count) |

Streaming-AE domains (CVF2 fix — see `docs/napseq-eprint-preprint.tex`
§sec:streaming-ae): `chunk_tag = HMAC(key_bytes, b'\x08' || nonce ||
uint32_be(len(aad)) || aad || uint32_be(chunk_index) || masked_chunk)` and
`final_tag = HMAC(key_bytes, b'\x09' || nonce || uint32_be(len(aad)) || aad
|| uint32_be(total_chunks))`. Previously the nonce was placed *after* the
AAD in both; it now occupies the same fixed byte 1‥16 offset as every other
domain.

---

## 4. Token encoding

*(napqes.py `_fixed_encode_tokens`, `_fixed_decode_tokens`, approx. L522–585)*

> **CVF1 fix.** v6 encoded tokens as Protocol-Buffers-style unsigned LEB128
> varints, whose byte-length grows with the token's magnitude. Because
> `token = codepoint × key_element + addend`, this magnitude — and hence
> the serialised blob's byte-length — depended on the plaintext codepoint
> *value*, not just the padded codepoint *count*. Two plaintexts with equal
> padded length but different codepoint values (e.g. `U+0001` repeated vs.
> `U+FFFF` repeated) therefore produced ciphertexts of different
> byte-length with overwhelming probability, giving an IND-CPA distinguishing
> advantage ≈ 1 and invalidating the equal-byte-length step of the hiding
> lemma in `docs/napseq-eprint-preprint.tex` Theorem 1. v7 closes this by
> giving every token the same, constant width.

Every token is an unsigned integer serialised as a fixed-width, big-endian
field of `TOKEN_WIDTH = 8` bytes (`uint64_be`), regardless of its magnitude:

```
token_blob = uint64_be(token[0]) || uint64_be(token[1]) || … || uint64_be(token[N-1])
```

`len(token_blob) == N * 8`, where `N` (the total token count, real + noise)
is a function of the padded codepoint count and the HMAC-derived noise
schedule (domain `0x00`) — both independent of codepoint values. Decoding
splits `token_blob` into consecutive 8-byte big-endian chunks; a blob whose
length is not a multiple of 8 is malformed (or is a legacy v6 LEB128 blob —
see below).

`TOKEN_WIDTH = 8` is sized to comfortably hold the largest realistic token
(`codepoint ≤ 0x10FFFF` times a 5-byte-serialised key element, plus an
addend), which is bounded well under 2⁶⁴ − 1.

**Legacy v6 decoding.** `decrypt_bytes` / `decrypt_str` accept
`legacy_v6_varint=True` to decode ciphertexts produced before the CVF1 fix,
whose token blob is instead a concatenation of Protocol-Buffers-style
unsigned LEB128 varints (7 bits/byte, MSB=1 if more bytes follow). Such
ciphertexts remain fully authenticated; the flag only selects the token
*deserialisation* format.

**Streaming API unaffected.** `encrypt_stream` / `encrypt_stream_ae` (§8,
§8.1) still use the LEB128 encoding — streaming mode already discloses the
exact plaintext length (no padding is applied there), so the content-length
correlation does not break an IND-CPA claim the way it did for block mode.
Tracked as a CVF1 follow-up in `docs/CAVEATS.md`.

---

## 5. Block ciphertext wire format (v7)

*(napqes.py `encrypt_bytes`, `decrypt_bytes`, approx. L610–700)*

```
ciphertext_binary = nonce (16 bytes) || masked_blob (token_count * 8 bytes) || auth_tag (32 bytes)
```

where `masked_blob = token_blob XOR keystream` (see §3.7), and `token_blob`
is the fixed-width encoding of §4.

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

**Minimum valid ciphertext length:** 16 (nonce) + 0 (empty token_blob) + 32 (tag) = **48 bytes** binary; **64 characters** base64.

---

## 6. Plaintext padding scheme

*(napqes.py `_pad_message`, `_unpad_message`, approx. L174–203)*

Block-mode encryption applies a power-of-two padding scheme before token
encoding:

```
n          = len(plaintext_codepoints)   # ∈ [1, MAX_PLAINTEXT_CODEPOINTS]
block_size = max(16, smallest power of 2 strictly > n)
For i in range(block_size − n):
    d      = HMAC(key_bytes, 0x06 || nonce || uint32_be(i))
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

## 8. Streaming wire format (basic — deprecated, forbidden for new ciphertext)

*(napqes.py `encrypt_stream`, `decrypt_stream`, approx. L471–651)*

> **Deprecated (CVF7 fix).** As of the CVF7 fix, this basic streaming
> format is superseded by the online-AE streaming format (§8.1), which is
> the sole normative streaming format. `encrypt_stream` / `decrypt_stream`
> MUST NOT be used to produce new ciphertext; they are retained only so
> that streams produced before this fix remain decryptable (behind the
> existing `enable_unauthenticated_streaming=True` opt-in on the decrypt
> side — see §10). No protocol may fall back to this format if §8.1
> decoding fails; doing so would recreate the RUP hazard (CAV-001) this fix
> closes.

The streaming format uses the **same outer byte layout** as the block format
(nonce ‖ masked_blob ‖ tag) and the same domain-0x07 XOR keystream mask, but
— unlike block mode as of the CVF1 fix — its token blob is still LEB128
varint-encoded (§4 "Streaming API unaffected"):

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
- **Still LEB128 tokens.** Because streaming mode already discloses the
  exact plaintext length, the CVF1 content-length correlation does not
  break an IND-CPA claim here the way it did for block mode; fixing it is
  tracked as a CVF1 follow-up in `docs/CAVEATS.md`.

The stream and block APIs are **not cross-compatible**: a block ciphertext
cannot be decoded with `decrypt_stream` and vice versa, both because the
padded token count differs (block mode prepends a 2-token length prefix and
pads to the next power-of-two block size) and because their token
encodings now differ (fixed-width v7 vs. LEB128).

---

## 8.1 Streaming AE wire format (v6s-ae) — CAV-001 fix, sole normative streaming format

*(napqes.py `encrypt_stream_ae`, `decrypt_stream_ae`)*

> **Normative status (CVF7 fix).** This is the sole normative streaming
> format as of the CVF7 fix; it MUST be used for all new streaming
> deployments. The basic streaming format (§8) is deprecated and forbidden
> for new ciphertext.

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
    b'\x08' || nonce || uint32_be(len(aad)) || aad || uint32_be(i) || masked_chunk)
```

**final_tag** (sentinel, `chunk_len = 0`):

```
final_tag = HMAC(key_bytes,
    b'\x09' || nonce || uint32_be(len(aad)) || aad || uint32_be(N))
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
| CAV-001 | Streaming RUP | Medium | Fixed — basic format (§8) deprecated/forbidden as of CVF7; use `encrypt_stream_ae` / `decrypt_stream_ae` (§8.1) |
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
