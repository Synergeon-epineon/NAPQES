/* napqes.c — C port of napqes.py (v7 authenticated EpiCypher, CVF1 fix).
 *
 * Implements: prime generation, encrypt/decrypt with HMAC-SHA256
 * derivations, fixed-width (8-byte) token encoding, base64 wrappers.
 *
 * Wire format (binary): nonce(16) || masked_blob(token_count*8) || hmac_sha256_tag(32)
 * String form: base64(binary).
 *
 * Byte-compatible with the Python reference implementation.
 */

#include "napqes.h"
#include "sha256.h"
#include "base64.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <bcrypt.h>
  #ifdef _MSC_VER
    #pragma comment(lib, "bcrypt.lib")
  #endif
  static int secure_rand_bytes(uint8_t *buf, size_t n) {
      NTSTATUS s = BCryptGenRandom(NULL, buf, (ULONG)n,
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
      return s == 0 ? 0 : -1;
  }
#else
  #include <stdio.h>
  static int secure_rand_bytes(uint8_t *buf, size_t n) {
      FILE *f = fopen("/dev/urandom", "rb");
      if (!f) return -1;
      size_t got = fread(buf, 1, n, f);
      fclose(f);
      return got == n ? 0 : -1;
  }
#endif

static uint64_t secure_rand_u64(void) {
    uint8_t b[8];
    if (secure_rand_bytes(b, 8) != 0) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[i];
    return v;
}

/* ── Primes ───────────────────────────────────────────────────────────────── */

int napqes_is_prime(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if ((n & 1) == 0) return 0;
    for (uint64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return 0;
    }
    return 1;
}

/* Minimum recommended number of prime key elements (Remark "min-K",
 * docs/napseq-eprint-preprint.tex §CVF8-fix). With |P| ~ 586,000-892,000
 * primes, H_inf(key) ~= 19.16*K bits; K < 7 gives H_inf(key) < 128 bits,
 * making offline exhaustive key search feasible. Enforced as a *warning*
 * only (not a hard failure) so existing small-K KAT/test vectors keep
 * working. */
#define NAPQES_MIN_KEY_COUNT 7

static void warn_if_weak_key_count(size_t count) {
    if (count < NAPQES_MIN_KEY_COUNT) {
        fprintf(stderr,
            "napqes: WARNING: key element count K=%zu is below the "
            "recommended minimum of %d. H_inf(key) < 128 bits at this size, "
            "making offline exhaustive key search feasible (see "
            "docs/napseq-eprint-preprint.tex, Remark 'min-K'). This key is "
            "usable but is NOT conformant with NAPQES's IND-CPA security "
            "claim; use K>=7 (default K=10) for production deployments.\n",
            count, NAPQES_MIN_KEY_COUNT);
    }
}

int napqes_generate_primes(uint64_t *out, size_t count,
                           uint64_t min_val, uint64_t max_val) {
    warn_if_weak_key_count(count);
    if (max_val <= min_val) return -1;
    uint64_t span = max_val - min_val + 1;
    uint64_t max_attempts = span * 4;
    size_t filled = 0;
    for (uint64_t attempts = 0; attempts < max_attempts && filled < count; ++attempts) {
        uint64_t num = min_val + (secure_rand_u64() % span);
        if (!napqes_is_prime(num)) continue;
        int dup = 0;
        for (size_t i = 0; i < filled; ++i) {
            if (out[i] == num) { dup = 1; break; }
        }
        if (!dup) out[filled++] = num;
    }
    return filled == count ? 0 : -1;
}

/* ── HMAC helpers ─────────────────────────────────────────────────────────── */

static void be5_write(uint8_t buf[5], uint64_t n) {
    buf[0] = (uint8_t)((n >> 32) & 0xFF);
    buf[1] = (uint8_t)((n >> 24) & 0xFF);
    buf[2] = (uint8_t)((n >> 16) & 0xFF);
    buf[3] = (uint8_t)((n >> 8)  & 0xFF);
    buf[4] = (uint8_t)(n & 0xFF);
}

static uint8_t *key_bytes_alloc(const uint64_t *key, size_t klen, size_t *out_len) {
    uint8_t *kb = (uint8_t *)malloc(klen * 5);
    if (!kb) return NULL;
    for (size_t i = 0; i < klen; ++i) {
        be5_write(kb + i * 5, key[i]);
    }
    *out_len = klen * 5;
    return kb;
}

static uint64_t u64_from_be8(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[i];
    return v;
}

static uint32_t u32_from_be4(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] << 8)  | (uint32_t)b[3];
}

#define TWO_POW_64 18446744073709551616.0

/* CVF2 fix: all HMAC calls feed the unified domain-first layout
 * sep || nonce || (be5(idx) | empty), so every domain differs at byte 0
 * and the nonce always occupies the fixed byte 1..16 offset. */
static void hmac_with_sep(const uint8_t *kb, size_t klen,
                          const uint8_t *nonce, uint8_t sep,
                          const uint8_t *tail, size_t tail_len,
                          uint8_t out[SHA256_DIGEST_SIZE]) {
    /* Stitch via update calls to avoid malloc on hot path. */
    sha256_ctx c;
    /* HMAC manually using ipad/opad to allow streaming input. */
    uint8_t k0[SHA256_BLOCK_SIZE];
    if (klen > SHA256_BLOCK_SIZE) {
        sha256(kb, klen, k0);
        memset(k0 + SHA256_DIGEST_SIZE, 0, SHA256_BLOCK_SIZE - SHA256_DIGEST_SIZE);
    } else {
        memcpy(k0, kb, klen);
        memset(k0 + klen, 0, SHA256_BLOCK_SIZE - klen);
    }
    uint8_t ipad[SHA256_BLOCK_SIZE], opad[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    uint8_t inner[SHA256_DIGEST_SIZE];
    sha256_init(&c);
    sha256_update(&c, ipad, SHA256_BLOCK_SIZE);
    sha256_update(&c, &sep, 1);
    sha256_update(&c, nonce, NAPQES_NONCE_SIZE);
    if (tail_len) sha256_update(&c, tail, tail_len);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, SHA256_BLOCK_SIZE);
    sha256_update(&c, inner, SHA256_DIGEST_SIZE);
    sha256_final(&c, out);
}

static int is_noise_pos(const uint8_t *kb, size_t klen,
                        const uint8_t *nonce, uint64_t ct_pos, double noise_p) {
    uint8_t idx[5]; be5_write(idx, ct_pos);
    uint8_t d[32];
    hmac_with_sep(kb, klen, nonce, 0x00, idx, 5, d);
    double v = (double)u64_from_be8(d) / TWO_POW_64;
    return v < noise_p;
}

static uint64_t derive_addend(const uint8_t *kb, size_t klen,
                              const uint8_t *nonce, uint64_t real_idx,
                              uint64_t k_elem) {
    uint8_t idx[5]; be5_write(idx, real_idx);
    uint8_t d[32];
    hmac_with_sep(kb, klen, nonce, 0x01, idx, 5, d);
    return ((uint64_t)u32_from_be4(d) % (k_elem - 1)) + 1;
}

static uint64_t derive_noise_char(const uint8_t *kb, size_t klen,
                                  const uint8_t *nonce, uint64_t ct_pos) {
    uint8_t idx[5]; be5_write(idx, ct_pos);
    uint8_t d[32];
    hmac_with_sep(kb, klen, nonce, 0x04, idx, 5, d);
    return ((uint64_t)u32_from_be4(d) % 96) + 32;
}

static uint64_t derive_noise_token_addend(const uint8_t *kb, size_t klen,
                                          const uint8_t *nonce, uint64_t ct_pos,
                                          uint64_t k_elem) {
    uint8_t idx[5]; be5_write(idx, ct_pos);
    uint8_t d[32];
    hmac_with_sep(kb, klen, nonce, 0x05, idx, 5, d);
    return ((uint64_t)u32_from_be4(d) % (k_elem - 1)) + 1;
}

static uint32_t derive_pad_char(const uint8_t *kb, size_t klen,
                                const uint8_t *nonce, uint32_t pad_idx) {
    uint8_t idx[4] = {
        (uint8_t)((pad_idx >> 24) & 0xFF),
        (uint8_t)((pad_idx >> 16) & 0xFF),
        (uint8_t)((pad_idx >> 8)  & 0xFF),
        (uint8_t)(pad_idx         & 0xFF),
    };
    uint8_t d[SHA256_DIGEST_SIZE];
    hmac_with_sep(kb, klen, nonce, 0x06, idx, 4, d);
    return (u32_from_be4(d) % 95) + 32;
}

static double derive_noise_p(const uint8_t *kb, size_t klen, const uint8_t *nonce) {
    uint8_t d[32];
    hmac_with_sep(kb, klen, nonce, 0x02, NULL, 0, d);
    double t = (double)u64_from_be8(d) / TWO_POW_64;
    return 0.75 + t * (0.99 - 0.75);
}

static void compute_auth_tag(const uint8_t *kb, size_t klen,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *payload, size_t payload_len,
                             uint8_t out[32]) {
    /* CVF2 fix: HMAC over the unified domain-first layout
     * 0x03 || nonce || be32(aad_len) || aad || masked_blob, where
     * payload = nonce || masked_blob (payload_len >= NAPQES_NONCE_SIZE). */
    const uint8_t *nonce = payload;
    const uint8_t *masked_blob = payload + NAPQES_NONCE_SIZE;
    size_t masked_blob_len = payload_len - NAPQES_NONCE_SIZE;
    uint8_t k0[SHA256_BLOCK_SIZE];
    if (klen > SHA256_BLOCK_SIZE) {
        sha256(kb, klen, k0);
        memset(k0 + SHA256_DIGEST_SIZE, 0, SHA256_BLOCK_SIZE - SHA256_DIGEST_SIZE);
    } else {
        memcpy(k0, kb, klen);
        memset(k0 + klen, 0, SHA256_BLOCK_SIZE - klen);
    }
    uint8_t ipad[SHA256_BLOCK_SIZE], opad[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    uint8_t sep = 0x03;
    uint8_t aad_len_be[4] = {
        (uint8_t)((aad_len >> 24) & 0xFF),
        (uint8_t)((aad_len >> 16) & 0xFF),
        (uint8_t)((aad_len >> 8)  & 0xFF),
        (uint8_t)(aad_len & 0xFF),
    };
    sha256_ctx c;
    uint8_t inner[32];
    sha256_init(&c);
    sha256_update(&c, ipad, SHA256_BLOCK_SIZE);
    sha256_update(&c, &sep, 1);
    sha256_update(&c, nonce, NAPQES_NONCE_SIZE);
    sha256_update(&c, aad_len_be, 4);
    if (aad_len) sha256_update(&c, aad, aad_len);
    sha256_update(&c, masked_blob, masked_blob_len);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, SHA256_BLOCK_SIZE);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

static int constant_time_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= a[i] ^ b[i];
    return d == 0;
}

/* ── V8: misuse-resistant synthetic-nonce construction ───────────────────────
 * See napqes.h for the full rationale. `sk_fmt` (the domain-0x0B format
 * subkey, always exactly SHA256_DIGEST_SIZE=32 bytes) is used everywhere a
 * v7 call site would use `kb`/`kb_len` — every existing domain-derivation
 * helper above (is_noise_pos, derive_addend, derive_noise_char,
 * derive_noise_token_addend, derive_noise_p, pad_message,
 * varint_keystream_alloc, compute_auth_tag) already takes a generic
 * (kb, klen) HMAC key parameter, so no new derivation helpers are needed
 * for domains 0x00-0x07 — only the domain-0x0A (synthetic nonce) and
 * domain-0x0B (format subkey) derivations below are new. */

/* Domain 0x0B: sk_fmt = HMAC(sk, 0x0B || format_id). Binds every subsequent
 * v8 derivation to the specific wire format in use, so a ciphertext/tag
 * produced for one format (e.g. block mode) can never verify under another
 * format's decoder (e.g. streaming-AE), even with the same (primes, sk). */
static void derive_format_subkey(const uint8_t sk[NAPQES_SK_SIZE], uint8_t format_id,
                                 uint8_t out[SHA256_DIGEST_SIZE]) {
    uint8_t k0[SHA256_BLOCK_SIZE];
    memcpy(k0, sk, NAPQES_SK_SIZE);
    memset(k0 + NAPQES_SK_SIZE, 0, SHA256_BLOCK_SIZE - NAPQES_SK_SIZE);
    uint8_t ipad[SHA256_BLOCK_SIZE], opad[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    uint8_t msg[2] = { 0x0b, format_id };
    uint8_t inner[SHA256_DIGEST_SIZE];
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, ipad, SHA256_BLOCK_SIZE);
    sha256_update(&c, msg, 2);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, SHA256_BLOCK_SIZE);
    sha256_update(&c, inner, SHA256_DIGEST_SIZE);
    sha256_final(&c, out);
}

/* Domain 0x0A: N = HMAC(sk_fmt, 0x0A || be4(len(aad)) || aad || message)[0:16].
 * SIV-style synthetic nonce: deterministic in (sk_fmt, aad, message), so
 * re-encrypting an identical (aad, message) reproduces the identical nonce
 * (and hence identical ciphertext) — the disclosed MRAE trade-off — while
 * distinct messages get distinct nonces with overwhelming probability,
 * closing the v7 nonce-reuse key-recovery hazard by construction. */
static void synthetic_nonce(const uint8_t sk_fmt[SHA256_DIGEST_SIZE],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *message, size_t message_len,
                            uint8_t out_nonce[NAPQES_NONCE_SIZE]) {
    uint8_t k0[SHA256_BLOCK_SIZE];
    memcpy(k0, sk_fmt, SHA256_DIGEST_SIZE);
    memset(k0 + SHA256_DIGEST_SIZE, 0, SHA256_BLOCK_SIZE - SHA256_DIGEST_SIZE);
    uint8_t ipad[SHA256_BLOCK_SIZE], opad[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    uint8_t sep = 0x0a;
    uint8_t aad_len_be[4] = {
        (uint8_t)((aad_len >> 24) & 0xFF), (uint8_t)((aad_len >> 16) & 0xFF),
        (uint8_t)((aad_len >> 8)  & 0xFF), (uint8_t)(aad_len & 0xFF),
    };
    uint8_t inner[SHA256_DIGEST_SIZE];
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, ipad, SHA256_BLOCK_SIZE);
    sha256_update(&c, &sep, 1);
    sha256_update(&c, aad_len_be, 4);
    if (aad_len) sha256_update(&c, aad, aad_len);
    if (message_len) sha256_update(&c, message, message_len);
    sha256_final(&c, inner);
    uint8_t full[SHA256_DIGEST_SIZE];
    sha256_init(&c);
    sha256_update(&c, opad, SHA256_BLOCK_SIZE);
    sha256_update(&c, inner, SHA256_DIGEST_SIZE);
    sha256_final(&c, full);
    memcpy(out_nonce, full, NAPQES_NONCE_SIZE);
}

/* ── Padding ──────────────────────────────────────────────────────────────── */

static size_t next_block_size(size_t n) {
    if (n == 0) return 16;
    size_t bl = 0;
    size_t v = n;
    while (v) { ++bl; v >>= 1; }
    size_t p = (size_t)1 << bl;
    return p < 16 ? 16 : p;
}

/* Pads `msg` (len n) into newly-malloc'd codepoint array of length 2+block.
 * Caller frees. Returns NULL on failure. *out_len receives total length.
 * Padding codepoints are HMAC-derived (domain 0x06) to match the Python
 * reference and enable cross-implementation KATs. */
static uint32_t *pad_message(const uint32_t *msg, size_t n,
                             const uint8_t *kb, size_t klen,
                             const uint8_t *nonce,
                             size_t *out_len) {
    if (n > 0xFFFF) return NULL;
    size_t block = next_block_size(n);
    size_t total = 2 + block;
    uint32_t *out = (uint32_t *)malloc(total * sizeof(uint32_t));
    if (!out) return NULL;
    out[0] = (uint32_t)((n >> 8) & 0xFF);
    out[1] = (uint32_t)(n & 0xFF);
    if (n) memcpy(out + 2, msg, n * sizeof(uint32_t));
    size_t pad_len = block - n;
    for (size_t i = 0; i < pad_len; ++i) {
        out[2 + n + i] = derive_pad_char(kb, klen, nonce, (uint32_t)i);
    }
    *out_len = total;
    return out;
}

/* ── Fixed-width token encoding (v7 — CVF1 fix) ──────────────────────────────
 * The retired LEB128 varint encoding gave each token a byte-length that grew
 * with its magnitude (token = codepoint * key_element + addend), leaking
 * plaintext content through ciphertext length even between messages of
 * equal padded length (audit finding CVF1). encrypt_core_det/decrypt_core
 * use this fixed-width, big-endian encoding instead: every token occupies
 * exactly TOKEN_WIDTH bytes, so blob length is a function only of the
 * token *count* (itself a function of padded length and the HMAC-derived,
 * content-independent noise schedule), never of codepoint values. See
 * docs/CAVEATS.md and SPEC.md. */

#define TOKEN_WIDTH 8

static void fixed_encode(uint64_t n, uint8_t out[TOKEN_WIDTH]) {
    for (int i = TOKEN_WIDTH - 1; i >= 0; --i) {
        out[i] = (uint8_t)(n & 0xFF);
        n >>= 8;
    }
}

static uint64_t fixed_decode(const uint8_t in[TOKEN_WIDTH]) {
    uint64_t v = 0;
    for (int i = 0; i < TOKEN_WIDTH; ++i) {
        v = (v << 8) | in[i];
    }
    return v;
}


/* HMAC-CTR keystream for XOR-masking the varint blob (domain byte 0x07).
 * block[i] = HMAC(key_bytes, 0x07 || nonce || uint32_be(i))  (CVF2 fix)
 * Returns block[0]||block[1]||… in a malloc'd buffer; caller uses first
 * `length` bytes then frees.  Returns NULL on allocation failure. */
static uint8_t *varint_keystream_alloc(const uint8_t *kb, size_t klen,
                                       const uint8_t *nonce, size_t length) {
    if (length == 0) return (uint8_t *)malloc(1);
    size_t n_blocks = (length + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    uint8_t *ks = (uint8_t *)malloc(n_blocks * SHA256_DIGEST_SIZE);
    if (!ks) return NULL;
    for (uint32_t b = 0; (size_t)b < n_blocks; ++b) {
        uint8_t blk_be[4] = {
            (uint8_t)((b >> 24) & 0xFF),
            (uint8_t)((b >> 16) & 0xFF),
            (uint8_t)((b >> 8)  & 0xFF),
            (uint8_t)(b         & 0xFF),
        };
        hmac_with_sep(kb, klen, nonce, 0x07, blk_be, 4,
                      ks + (size_t)b * SHA256_DIGEST_SIZE);
    }
    return ks;
}

/* ── Core encrypt / decrypt ───────────────────────────────────────────────── */

/* Deterministic core: encrypts a codepoint array using a caller-supplied nonce.
 * Outputs a fixed-width token blob (malloc'd) of *blob_len bytes, where
 * *blob_len is always a multiple of TOKEN_WIDTH (v7 wire format, CVF1 fix).
 * Returns 0 or -1. */
static int encrypt_core_det(const uint32_t *msg, size_t n,
                            const uint64_t *key, size_t klen,
                            const uint8_t nonce[NAPQES_NONCE_SIZE],
                            uint8_t **blob_out, size_t *blob_len) {
    if (klen == 0) return -1;

    size_t kb_len = 0;
    uint8_t *kb = key_bytes_alloc(key, klen, &kb_len);
    if (!kb) return -1;
    double noise_p = derive_noise_p(kb, kb_len, nonce);

    size_t padded_len = 0;
    uint32_t *padded = pad_message(msg, n, kb, kb_len, nonce, &padded_len);
    if (!padded) { free(kb); return -1; }

    /* Growable byte buffer for the fixed-width token blob. */
    size_t cap = padded_len * TOKEN_WIDTH * 2 + 64;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { free(kb); free(padded); return -1; }
    size_t len = 0;

    uint64_t real_idx = 0;
    uint64_t ct_pos = 0;

    for (size_t i = 0; i < padded_len; ++i) {
        for (;;) {
            /* Ensure room for one fixed-width token. */
            if (len + TOKEN_WIDTH > cap) {
                size_t ncap = cap * 2;
                uint8_t *nbuf = (uint8_t *)realloc(buf, ncap);
                if (!nbuf) { free(buf); free(kb); free(padded); return -1; }
                buf = nbuf; cap = ncap;
            }
            uint64_t k = key[real_idx % klen];
            if (is_noise_pos(kb, kb_len, nonce, ct_pos, noise_p)) {
                uint64_t nc  = derive_noise_char(kb, kb_len, nonce, ct_pos);
                uint64_t nad = derive_noise_token_addend(kb, kb_len, nonce, ct_pos, k);
                fixed_encode(nc * k + nad, buf + len);
                len += TOKEN_WIDTH;
                ct_pos++;
            } else {
                uint64_t addend = derive_addend(kb, kb_len, nonce, real_idx, k);
                uint64_t token  = (uint64_t)padded[i] * k + addend;
                fixed_encode(token, buf + len);
                len += TOKEN_WIDTH;
                ct_pos++;
                real_idx++;
                break;
            }
        }
    }

    free(kb);
    free(padded);
    *blob_out = buf;
    *blob_len = len;
    return 0;
}

/* Generates a random nonce then delegates to encrypt_core_det. */
static int encrypt_core(const uint32_t *msg, size_t n,
                        const uint64_t *key, size_t klen,
                        uint8_t nonce[NAPQES_NONCE_SIZE],
                        uint8_t **blob_out, size_t *blob_len) {
    if (secure_rand_bytes(nonce, NAPQES_NONCE_SIZE) != 0) return -1;
    return encrypt_core_det(msg, n, key, klen, nonce, blob_out, blob_len);
}

/* Decrypts a fixed-width (v7, CVF1 fix) token blob; returns malloc'd
 * codepoint array of *out_len real codepoints (already unpadded). Returns
 * NULL on failure, including if blob_len is not a multiple of TOKEN_WIDTH. */
static uint32_t *decrypt_core(const uint8_t *blob, size_t blob_len,
                              const uint8_t nonce[NAPQES_NONCE_SIZE],
                              const uint64_t *key, size_t klen,
                              size_t *out_len) {
    if (klen == 0) return NULL;
    if (blob_len % TOKEN_WIDTH != 0) return NULL;
    size_t kb_len = 0;
    uint8_t *kb = key_bytes_alloc(key, klen, &kb_len);
    if (!kb) return NULL;
    double noise_p = derive_noise_p(kb, kb_len, nonce);

    size_t n_tokens = blob_len / TOKEN_WIDTH;
    uint64_t *tokens = (uint64_t *)malloc((n_tokens + 1) * sizeof(uint64_t));
    if (!tokens) { free(kb); return NULL; }
    for (size_t i = 0; i < n_tokens; ++i) {
        tokens[i] = fixed_decode(blob + i * TOKEN_WIDTH);
    }

    uint32_t *padded = (uint32_t *)malloc((n_tokens + 2) * sizeof(uint32_t));
    if (!padded) { free(tokens); free(kb); return NULL; }
    size_t padded_n = 0;
    uint64_t real_idx = 0;
    for (size_t ct_pos = 0; ct_pos < n_tokens; ++ct_pos) {
        if (!is_noise_pos(kb, kb_len, nonce, (uint64_t)ct_pos, noise_p)) {
            uint64_t k = key[real_idx % klen];
            uint64_t addend = derive_addend(kb, kb_len, nonce, real_idx, k);
            uint64_t cp = (tokens[ct_pos] - addend) / k;
            padded[padded_n++] = (uint32_t)cp;
            real_idx++;
        }
    }

    free(tokens);
    free(kb);

    if (padded_n < 2) { free(padded); return NULL; }
    size_t orig_n = ((size_t)padded[0] << 8) | (size_t)padded[1];
    if (2 + orig_n > padded_n) { free(padded); return NULL; }

    uint32_t *out = (uint32_t *)malloc((orig_n + 1) * sizeof(uint32_t));
    if (!out) { free(padded); return NULL; }
    if (orig_n) memcpy(out, padded + 2, orig_n * sizeof(uint32_t));
    free(padded);
    *out_len = orig_n;
    return out;
}

/* ── V8 core encrypt / decrypt (misuse-resistant) ────────────────────────────
 * Identical token-emission loop to encrypt_core_det/decrypt_core, except
 * every domain derivation is keyed by `sk_fmt` (32-byte v8 format subkey)
 * instead of key_bytes(primes), and a hard cap of NAPQES_MAX_NOISE_RUN
 * consecutive noise tokens bounds worst-case ciphertext expansion (see
 * napqes.h). `primes` is still used directly, un-keyed, for the arithmetic
 * token map c*k+a — exactly as in v7. */

static int encrypt_core_det_v8(const uint32_t *msg, size_t n,
                               const uint64_t *primes, size_t klen,
                               const uint8_t sk_fmt[SHA256_DIGEST_SIZE],
                               const uint8_t nonce[NAPQES_NONCE_SIZE],
                               uint8_t **blob_out, size_t *blob_len) {
    if (klen == 0) return -1;

    double noise_p = derive_noise_p(sk_fmt, SHA256_DIGEST_SIZE, nonce);

    size_t padded_len = 0;
    uint32_t *padded = pad_message(msg, n, sk_fmt, SHA256_DIGEST_SIZE, nonce, &padded_len);
    if (!padded) return -1;

    size_t cap = padded_len * TOKEN_WIDTH * 2 + 64;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { free(padded); return -1; }
    size_t len = 0;

    uint64_t real_idx = 0;
    uint64_t ct_pos = 0;

    for (size_t i = 0; i < padded_len; ++i) {
        unsigned noise_run = 0;
        for (;;) {
            if (len + TOKEN_WIDTH > cap) {
                size_t ncap = cap * 2;
                uint8_t *nbuf = (uint8_t *)realloc(buf, ncap);
                if (!nbuf) { free(buf); free(padded); return -1; }
                buf = nbuf; cap = ncap;
            }
            uint64_t k = primes[real_idx % klen];
            if (noise_run < NAPQES_MAX_NOISE_RUN
                && is_noise_pos(sk_fmt, SHA256_DIGEST_SIZE, nonce, ct_pos, noise_p)) {
                uint64_t nc  = derive_noise_char(sk_fmt, SHA256_DIGEST_SIZE, nonce, ct_pos);
                uint64_t nad = derive_noise_token_addend(sk_fmt, SHA256_DIGEST_SIZE, nonce, ct_pos, k);
                fixed_encode(nc * k + nad, buf + len);
                len += TOKEN_WIDTH;
                ct_pos++;
                noise_run++;
            } else {
                uint64_t addend = derive_addend(sk_fmt, SHA256_DIGEST_SIZE, nonce, real_idx, k);
                uint64_t token  = (uint64_t)padded[i] * k + addend;
                fixed_encode(token, buf + len);
                len += TOKEN_WIDTH;
                ct_pos++;
                real_idx++;
                break;
            }
        }
    }

    free(padded);
    *blob_out = buf;
    *blob_len = len;
    return 0;
}

/* Decrypts a v8 fixed-width token blob using sk_fmt in place of key_bytes,
 * applying the identical NAPQES_MAX_NOISE_RUN-capped schedule derivation so
 * encryption and decryption stay in lock-step. Returns NULL (never reads
 * out of bounds) on a truncated token stream. */
static uint32_t *decrypt_core_v8(const uint8_t *blob, size_t blob_len,
                                 const uint8_t nonce[NAPQES_NONCE_SIZE],
                                 const uint64_t *primes, size_t klen,
                                 const uint8_t sk_fmt[SHA256_DIGEST_SIZE],
                                 size_t *out_len) {
    if (klen == 0) return NULL;
    if (blob_len % TOKEN_WIDTH != 0) return NULL;
    double noise_p = derive_noise_p(sk_fmt, SHA256_DIGEST_SIZE, nonce);

    size_t n_tokens = blob_len / TOKEN_WIDTH;
    uint64_t *tokens = (uint64_t *)malloc((n_tokens + 1) * sizeof(uint64_t));
    if (!tokens) return NULL;
    for (size_t i = 0; i < n_tokens; ++i) {
        tokens[i] = fixed_decode(blob + i * TOKEN_WIDTH);
    }

    uint32_t *padded = (uint32_t *)malloc((n_tokens + 2) * sizeof(uint32_t));
    if (!padded) { free(tokens); return NULL; }
    size_t padded_n = 0;
    uint64_t real_idx = 0;
    size_t ct_pos = 0;

    while (ct_pos < n_tokens) {
        unsigned noise_run = 0;
        while (noise_run < NAPQES_MAX_NOISE_RUN
               && is_noise_pos(sk_fmt, SHA256_DIGEST_SIZE, nonce, (uint64_t)ct_pos, noise_p)) {
            ct_pos++;
            noise_run++;
        }
        if (ct_pos >= n_tokens) { free(tokens); free(padded); return NULL; }
        uint64_t k = primes[real_idx % klen];
        uint64_t addend = derive_addend(sk_fmt, SHA256_DIGEST_SIZE, nonce, real_idx, k);
        uint64_t cp = (tokens[ct_pos] - addend) / k;
        padded[padded_n++] = (uint32_t)cp;
        ct_pos++;
        real_idx++;
    }

    free(tokens);

    if (padded_n < 2) { free(padded); return NULL; }
    size_t orig_n = ((size_t)padded[0] << 8) | (size_t)padded[1];
    if (2 + orig_n > padded_n) { free(padded); return NULL; }

    uint32_t *out = (uint32_t *)malloc((orig_n + 1) * sizeof(uint32_t));
    if (!out) { free(padded); return NULL; }
    if (orig_n) memcpy(out, padded + 2, orig_n * sizeof(uint32_t));
    free(padded);
    *out_len = orig_n;
    return out;
}

/* ── Public binary API ────────────────────────────────────────────────────── */

uint8_t *napqes_encrypt_bytes(const char *message,
                              const uint64_t *key, size_t klen,
                              const uint8_t *aad, size_t aad_len,
                              size_t *out_len) {
    if (!message || !out_len || !key) return NULL;
    size_t n = strlen(message);
    if (n == 0) { *out_len = 0; uint8_t *e = (uint8_t *)malloc(1); if (e) e[0] = 0; return e; }
    if (n > 0xFFFF) return NULL;

    uint32_t *cp = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (!cp) return NULL;
    for (size_t i = 0; i < n; ++i) cp[i] = (uint8_t)message[i];

    uint8_t nonce[NAPQES_NONCE_SIZE];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (encrypt_core(cp, n, key, klen, nonce, &blob, &blob_len) != 0) {
        free(cp); return NULL;
    }
    free(cp);

    size_t kb_len = 0;
    uint8_t *kb = key_bytes_alloc(key, klen, &kb_len);
    if (!kb) { free(blob); return NULL; }

    /* XOR-mask the varint blob with HMAC-CTR keystream (domain 0x07) so that
     * the wire payload is masked_blob, matching Python/Rust. */
    uint8_t *ks = varint_keystream_alloc(kb, kb_len, nonce, blob_len);
    if (!ks) { free(kb); free(blob); return NULL; }
    for (size_t i = 0; i < blob_len; ++i) blob[i] ^= ks[i];
    free(ks);

    size_t payload_len = NAPQES_NONCE_SIZE + blob_len;
    size_t total = payload_len + NAPQES_TAG_SIZE;
    uint8_t *out = (uint8_t *)malloc(total);
    if (!out) { free(kb); free(blob); return NULL; }
    memcpy(out, nonce, NAPQES_NONCE_SIZE);
    memcpy(out + NAPQES_NONCE_SIZE, blob, blob_len);
    free(blob);

    uint8_t tag[NAPQES_TAG_SIZE];
    compute_auth_tag(kb, kb_len, aad, aad_len, out, payload_len, tag);
    free(kb);
    memcpy(out + payload_len, tag, NAPQES_TAG_SIZE);
    *out_len = total;
    return out;
}

#ifdef NAPQES_ENABLE_TEST_NONCE_API
/* Deterministic-nonce encrypt — TEST BUILDS ONLY (CVF3 fix, 2026-07-06).
 * Not declared in napqes.h / not compiled unless NAPQES_ENABLE_TEST_NONCE_API
 * is defined, so this symbol is absent from the default napqes_demo build
 * and cannot be linked against by production code. See docs/CAVEATS.md
 * (CVF3): an explicit, caller-chosen nonce is a key-recovery hazard for
 * NAPQES, not merely a confidentiality-losing one. */
uint8_t *napqes_encrypt_bytes_with_nonce(const char *message,
                                          const uint64_t *key, size_t klen,
                                          const uint8_t *aad, size_t aad_len,
                                          const uint8_t *nonce,
                                          size_t *out_len) {
    if (!message || !out_len || !key || !nonce) return NULL;
    size_t n = strlen(message);
    if (n == 0) { *out_len = 0; uint8_t *e = (uint8_t *)malloc(1); if (e) e[0] = 0; return e; }
    if (n > 0xFFFF) return NULL;

    uint32_t *cp = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (!cp) return NULL;
    for (size_t i = 0; i < n; ++i) cp[i] = (uint8_t)message[i];

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (encrypt_core_det(cp, n, key, klen, nonce, &blob, &blob_len) != 0) {
        free(cp); return NULL;
    }
    free(cp);

    size_t kb_len = 0;
    uint8_t *kb = key_bytes_alloc(key, klen, &kb_len);
    if (!kb) { free(blob); return NULL; }

    uint8_t *ks = varint_keystream_alloc(kb, kb_len, nonce, blob_len);
    if (!ks) { free(kb); free(blob); return NULL; }
    for (size_t i = 0; i < blob_len; ++i) blob[i] ^= ks[i];
    free(ks);

    size_t payload_len = NAPQES_NONCE_SIZE + blob_len;
    size_t total = payload_len + NAPQES_TAG_SIZE;
    uint8_t *out = (uint8_t *)malloc(total);
    if (!out) { free(kb); free(blob); return NULL; }
    memcpy(out, nonce, NAPQES_NONCE_SIZE);
    memcpy(out + NAPQES_NONCE_SIZE, blob, blob_len);
    free(blob);

    uint8_t tag[NAPQES_TAG_SIZE];
    compute_auth_tag(kb, kb_len, aad, aad_len, out, payload_len, tag);
    free(kb);
    memcpy(out + payload_len, tag, NAPQES_TAG_SIZE);
    *out_len = total;
    return out;
}
#endif /* NAPQES_ENABLE_TEST_NONCE_API */

char *napqes_decrypt_bytes(const uint8_t *ciphertext, size_t ct_len,
                           const uint64_t *key, size_t klen,
                           const uint8_t *aad, size_t aad_len) {
    if (!ciphertext || !key) return NULL;
    if (ct_len == 0) { char *e = (char *)malloc(1); if (e) e[0] = 0; return e; }
    if (ct_len < NAPQES_NONCE_SIZE + NAPQES_TAG_SIZE) return NULL;

    size_t payload_len = ct_len - NAPQES_TAG_SIZE;
    const uint8_t *recv_tag = ciphertext + payload_len;

    size_t kb_len = 0;
    uint8_t *kb = key_bytes_alloc(key, klen, &kb_len);
    if (!kb) return NULL;
    uint8_t calc_tag[NAPQES_TAG_SIZE];
    compute_auth_tag(kb, kb_len, aad, aad_len, ciphertext, payload_len, calc_tag);
    if (!constant_time_eq(recv_tag, calc_tag, NAPQES_TAG_SIZE)) {
        free(kb); return NULL;
    }
    const uint8_t *nonce  = ciphertext;
    const uint8_t *masked = ciphertext + NAPQES_NONCE_SIZE;
    size_t blob_len       = payload_len - NAPQES_NONCE_SIZE;

    /* XOR-unmask the masked_blob back to raw varint blob (domain 0x07). */
    uint8_t *blob = (uint8_t *)malloc(blob_len + 1); /* +1 avoids malloc(0) */
    if (!blob) { free(kb); return NULL; }
    uint8_t *ks = varint_keystream_alloc(kb, kb_len, nonce, blob_len);
    free(kb);
    if (!ks) { free(blob); return NULL; }
    for (size_t i = 0; i < blob_len; ++i) blob[i] = masked[i] ^ ks[i];
    free(ks);

    size_t out_len = 0;
    uint32_t *cp = decrypt_core(blob, blob_len, nonce, key, klen, &out_len);
    free(blob);
    if (!cp) return NULL;
    char *s = (char *)malloc(out_len + 1);
    if (!s) { free(cp); return NULL; }
    for (size_t i = 0; i < out_len; ++i) s[i] = (char)(cp[i] & 0xFF);
    s[out_len] = '\0';
    free(cp);
    return s;
}

/* ── V8 public API (misuse-resistant) ────────────────────────────────────── */

int napqes_generate_v8_key(uint64_t *primes_out, size_t count,
                           uint64_t min_val, uint64_t max_val,
                           uint8_t sk_out[NAPQES_SK_SIZE]) {
    if (napqes_generate_primes(primes_out, count, min_val, max_val) != 0) return -1;
    if (secure_rand_bytes(sk_out, NAPQES_SK_SIZE) != 0) return -1;
    return 0;
}

uint8_t *napqes_encrypt_bytes_v8(const char *message,
                                 const uint64_t *primes, size_t klen,
                                 const uint8_t sk[NAPQES_SK_SIZE],
                                 const uint8_t *aad, size_t aad_len,
                                 size_t *out_len) {
    if (!message || !out_len || !primes || !sk) return NULL;
    size_t n = strlen(message);
    if (n == 0) { *out_len = 0; uint8_t *e = (uint8_t *)malloc(1); if (e) e[0] = 0; return e; }
    if (n > 0xFFFF) return NULL;

    uint32_t *cp = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (!cp) return NULL;
    for (size_t i = 0; i < n; ++i) cp[i] = (uint8_t)message[i];

    uint8_t sk_fmt[SHA256_DIGEST_SIZE];
    derive_format_subkey(sk, NAPQES_FORMAT_BLOCK_V8, sk_fmt);

    uint8_t nonce[NAPQES_NONCE_SIZE];
    synthetic_nonce(sk_fmt, aad, aad_len, (const uint8_t *)message, n, nonce);

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (encrypt_core_det_v8(cp, n, primes, klen, sk_fmt, nonce, &blob, &blob_len) != 0) {
        free(cp); return NULL;
    }
    free(cp);

    /* XOR-mask the token blob with HMAC-CTR keystream (domain 0x07),
     * keyed by sk_fmt instead of key_bytes(primes). */
    uint8_t *ks = varint_keystream_alloc(sk_fmt, SHA256_DIGEST_SIZE, nonce, blob_len);
    if (!ks) { free(blob); return NULL; }
    for (size_t i = 0; i < blob_len; ++i) blob[i] ^= ks[i];
    free(ks);

    size_t payload_len = NAPQES_NONCE_SIZE + blob_len;
    size_t total = payload_len + NAPQES_TAG_SIZE;
    uint8_t *out = (uint8_t *)malloc(total);
    if (!out) { free(blob); return NULL; }
    memcpy(out, nonce, NAPQES_NONCE_SIZE);
    memcpy(out + NAPQES_NONCE_SIZE, blob, blob_len);
    free(blob);

    uint8_t tag[NAPQES_TAG_SIZE];
    compute_auth_tag(sk_fmt, SHA256_DIGEST_SIZE, aad, aad_len, out, payload_len, tag);
    memcpy(out + payload_len, tag, NAPQES_TAG_SIZE);
    *out_len = total;
    return out;
}

char *napqes_decrypt_bytes_v8(const uint8_t *ciphertext, size_t ct_len,
                              const uint64_t *primes, size_t klen,
                              const uint8_t sk[NAPQES_SK_SIZE],
                              const uint8_t *aad, size_t aad_len) {
    if (!ciphertext || !primes || !sk) return NULL;
    if (ct_len == 0) { char *e = (char *)malloc(1); if (e) e[0] = 0; return e; }
    if (ct_len < NAPQES_NONCE_SIZE + NAPQES_TAG_SIZE) return NULL;

    size_t payload_len = ct_len - NAPQES_TAG_SIZE;
    const uint8_t *recv_tag = ciphertext + payload_len;

    uint8_t sk_fmt[SHA256_DIGEST_SIZE];
    derive_format_subkey(sk, NAPQES_FORMAT_BLOCK_V8, sk_fmt);

    uint8_t calc_tag[NAPQES_TAG_SIZE];
    compute_auth_tag(sk_fmt, SHA256_DIGEST_SIZE, aad, aad_len, ciphertext, payload_len, calc_tag);
    if (!constant_time_eq(recv_tag, calc_tag, NAPQES_TAG_SIZE)) return NULL;

    const uint8_t *nonce  = ciphertext;
    const uint8_t *masked = ciphertext + NAPQES_NONCE_SIZE;
    size_t blob_len       = payload_len - NAPQES_NONCE_SIZE;

    uint8_t *blob = (uint8_t *)malloc(blob_len + 1); /* +1 avoids malloc(0) */
    if (!blob) return NULL;
    uint8_t *ks = varint_keystream_alloc(sk_fmt, SHA256_DIGEST_SIZE, nonce, blob_len);
    if (!ks) { free(blob); return NULL; }
    for (size_t i = 0; i < blob_len; ++i) blob[i] = masked[i] ^ ks[i];
    free(ks);

    size_t out_len = 0;
    uint32_t *cp = decrypt_core_v8(blob, blob_len, nonce, primes, klen, sk_fmt, &out_len);
    free(blob);
    if (!cp) return NULL;
    char *s = (char *)malloc(out_len + 1);
    if (!s) { free(cp); return NULL; }
    for (size_t i = 0; i < out_len; ++i) s[i] = (char)(cp[i] & 0xFF);
    s[out_len] = '\0';
    free(cp);
    return s;
}

char *napqes_encrypt_str_v8(const char *message,
                            const uint64_t *primes, size_t klen,
                            const uint8_t sk[NAPQES_SK_SIZE],
                            const uint8_t *aad, size_t aad_len) {
    if (!message) return NULL;
    if (message[0] == '\0') { char *e = (char *)malloc(1); if (e) e[0] = 0; return e; }
    size_t bin_len = 0;
    uint8_t *bin = napqes_encrypt_bytes_v8(message, primes, klen, sk, aad, aad_len, &bin_len);
    if (!bin) return NULL;
    size_t enc_len = base64_encoded_len(bin_len);
    char *out = (char *)malloc(enc_len + 1);
    if (!out) { free(bin); return NULL; }
    base64_encode(bin, bin_len, out);
    free(bin);
    return out;
}

char *napqes_decrypt_str_v8(const char *cypher,
                            const uint64_t *primes, size_t klen,
                            const uint8_t sk[NAPQES_SK_SIZE],
                            const uint8_t *aad, size_t aad_len) {
    if (!cypher) return NULL;
    if (cypher[0] == '\0') { char *e = (char *)malloc(1); if (e) e[0] = 0; return e; }
    size_t clen = strlen(cypher);
    size_t max = base64_decoded_max_len(clen);
    uint8_t *bin = (uint8_t *)malloc(max + 1);
    if (!bin) return NULL;
    long n = base64_decode(cypher, clen, bin);
    if (n < 0) { free(bin); return NULL; }
    char *s = napqes_decrypt_bytes_v8(bin, (size_t)n, primes, klen, sk, aad, aad_len);
    free(bin);
    return s;
}

/* ── Public string API (base64 wrapper) ───────────────────────────────────── */

char *napqes_encrypt_str(const char *message,
                         const uint64_t *key, size_t klen,
                         const uint8_t *aad, size_t aad_len) {
    if (!message) return NULL;
    if (message[0] == '\0') { char *e = (char *)malloc(1); if (e) e[0] = 0; return e; }
    size_t bin_len = 0;
    uint8_t *bin = napqes_encrypt_bytes(message, key, klen, aad, aad_len, &bin_len);
    if (!bin) return NULL;
    size_t enc_len = base64_encoded_len(bin_len);
    char *out = (char *)malloc(enc_len + 1);
    if (!out) { free(bin); return NULL; }
    base64_encode(bin, bin_len, out);
    free(bin);
    return out;
}

char *napqes_decrypt_str(const char *cypher,
                         const uint64_t *key, size_t klen,
                         const uint8_t *aad, size_t aad_len) {
    if (!cypher) return NULL;
    if (cypher[0] == '\0') { char *e = (char *)malloc(1); if (e) e[0] = 0; return e; }
    size_t clen = strlen(cypher);
    size_t max = base64_decoded_max_len(clen);
    uint8_t *bin = (uint8_t *)malloc(max + 1);
    if (!bin) return NULL;
    long n = base64_decode(cypher, clen, bin);
    if (n < 0) { free(bin); return NULL; }
    char *s = napqes_decrypt_bytes(bin, (size_t)n, key, klen, aad, aad_len);
    free(bin);
    return s;
}
