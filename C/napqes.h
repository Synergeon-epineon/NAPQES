#ifndef NAPQES_H
#define NAPQES_H

#include <stddef.h>
#include <stdint.h>

#define NAPQES_NONCE_SIZE 16
#define NAPQES_TAG_SIZE   32

/* ── Primes ───────────────────────────────────────────────────────────────── */

int  napqes_is_prime(uint64_t n);

/* Fill `out` with `count` distinct primes drawn uniformly from [min_val,max_val].
 * Returns 0 on success, -1 on failure (could not find enough primes / RNG). */
int  napqes_generate_primes(uint64_t *out, size_t count,
                            uint64_t min_val, uint64_t max_val);

/* ── String API (v6 authenticated) ────────────────────────────────────────── */

/* Encrypt an ASCII NUL-terminated `message` with `key` (`klen` primes) and
 * optional `aad` of `aad_len` bytes.
 * Returns a malloc'd NUL-terminated base64 string the caller must free().
 * Returns NULL on allocation failure / oversized message. */
char *napqes_encrypt_str(const char *message,
                         const uint64_t *key, size_t klen,
                         const uint8_t *aad, size_t aad_len);

/* Decrypt a base64 ciphertext produced by napqes_encrypt_str.
 * Returns a malloc'd NUL-terminated ASCII string the caller must free(),
 * or NULL on authentication failure / parse error / allocation failure. */
char *napqes_decrypt_str(const char *cypher,
                         const uint64_t *key, size_t klen,
                         const uint8_t *aad, size_t aad_len);

/* ── Binary API (v6 authenticated) ────────────────────────────────────────── */

/* Encrypt an ASCII NUL-terminated `message` into a malloc'd binary blob.
 * `*out_len` is set to the blob length. Returns malloc'd buffer or NULL. */
uint8_t *napqes_encrypt_bytes(const char *message,
                              const uint64_t *key, size_t klen,
                              const uint8_t *aad, size_t aad_len,
                              size_t *out_len);

/* Decrypt a v6 binary blob to a malloc'd NUL-terminated ASCII string.
 * Returns NULL on auth failure / parse error. */
char *napqes_decrypt_bytes(const uint8_t *ciphertext, size_t ct_len,
                           const uint64_t *key, size_t klen,
                           const uint8_t *aad, size_t aad_len);

/* Deterministic-nonce encrypt for KAT testing.  nonce must be NAPQES_NONCE_SIZE bytes.
 * Output is byte-identical to the Python/Rust reference given the same nonce. */
uint8_t *napqes_encrypt_bytes_with_nonce(const char *message,
                                          const uint64_t *key, size_t klen,
                                          const uint8_t *aad, size_t aad_len,
                                          const uint8_t *nonce,
                                          size_t *out_len);

#endif
