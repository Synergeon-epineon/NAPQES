# napqes (C)

C11 port of the v6 authenticated EpiCypher in `../napqes.py`.

## Files

- `napqes.h` / `napqes.c` — public API + core encrypt/decrypt
- `sha256.h` / `sha256.c` — portable SHA-256 + HMAC-SHA256
- `base64.h` / `base64.c` — RFC 4648 base64 encode/decode
- `main.c` — demo / smoke test
- `Makefile` — POSIX & MinGW build

## Build

```sh
make                 # POSIX or MinGW (links -lbcrypt on Windows)
./napqes_demo        # or napqes_demo.exe
```

MSVC (Developer Command Prompt):

```
cl /std:c11 /O2 sha256.c base64.c napqes.c main.c bcrypt.lib
```

## API

```c
#include "napqes.h"

uint64_t key[10];
napqes_generate_primes(key, NAPQES_DEFAULT_KEY_COUNT,
                       NAPQES_MIN_KEY_PRIME, NAPQES_MAX_KEY_PRIME);

char *ct = napqes_encrypt_str("hello", key, 10, NULL, 0);
char *pt = napqes_decrypt_str(ct, key, 10, NULL, 0);
/* pt == "hello" */
free(ct); free(pt);
```

All returned pointers are heap-allocated; the caller owns them and must
`free()` them. A NULL return indicates auth failure, parse error, or OOM.

## Wire format

Byte-compatible with the Python reference:

```
nonce(16) || varint_blob || hmac_sha256_tag(32)
```

String wrappers base64-encode the binary blob.

## Scope

Implements: prime generation, `napqes_encrypt_str`/`napqes_decrypt_str`,
`napqes_encrypt_bytes`/`napqes_decrypt_bytes`, v8 block mode
(`napqes_encrypt_bytes_v8`/`napqes_decrypt_bytes_v8`), v8 streaming mode
(`napqes_encrypt_stream_ae_v8_bytes` / `napqes_decrypt_stream_ae_v8_bytes`),
all HMAC derivations. The current implementation handles ASCII messages
(codepoints 0–127); extending to full UTF-8 would only require widening
the surface I/O paths.

Out of scope: legacy v2/v3/v5 ciphertexts, v7 basic/AE streaming (the
legacy Python-only formats before v8).

## Streaming (v8) — usage

```c
uint64_t primes[NAPQES_DEFAULT_KEY_COUNT];
uint8_t  sk[NAPQES_SK_SIZE];
napqes_generate_v8_key(primes, NAPQES_DEFAULT_KEY_COUNT,
                       NAPQES_MIN_KEY_PRIME, NAPQES_MAX_KEY_PRIME, sk);

size_t ct_len = 0;
uint8_t *ct = napqes_encrypt_stream_ae_v8_bytes(
    "hello, streaming!", primes, NAPQES_DEFAULT_KEY_COUNT, sk,
    NULL, 0,                                  /* aad, aad_len */
    NAPQES_STREAM_AE_V8_DEFAULT_FRAME,        /* frame codepoints */
    &ct_len);

char *pt = napqes_decrypt_stream_ae_v8_bytes(
    ct, ct_len, primes, NAPQES_DEFAULT_KEY_COUNT, sk, NULL, 0);
/* pt is a malloc'd NUL-terminated ASCII string; caller free()s. */
free(pt); free(ct);
```

**Security caveat.** v8 streaming is NOT misuse-resistant — the 16-byte
per-stream nonce is CSPRNG-drawn (BCryptGenRandom / /dev/urandom), not
SIV-derived. Nonce reuse under the same `sk` is a CVF3-class hazard.
See `docs/CAVEATS.md` CAV-005. For messages that fit in memory, prefer
the SIV-protected block API (`napqes_encrypt_bytes_v8` /
`napqes_decrypt_bytes_v8`).

## Security notes

- Uses BCryptGenRandom on Windows, /dev/urandom on POSIX.
- HMAC tag verified with constant-time comparison before decryption.
- The codepoint-to-char conversion masks with `0x7F`; binary or non-ASCII
  data should not be passed through the string API as-is.
