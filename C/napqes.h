#ifndef NAPQES_H
#define NAPQES_H

#include <stddef.h>
#include <stdint.h>

#define NAPQES_NONCE_SIZE 16
#define NAPQES_TAG_SIZE   32

/*
 * KEY ORDERING IS A SECURITY PARAMETER.
 * key = {k0, k1, ...} and key = {k1, k0, ...} are *distinct* keys that
 * produce non-interoperable ciphertexts.  Callers must preserve element
 * order when storing or transmitting key material.
 */

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

#ifdef NAPQES_ENABLE_TEST_NONCE_API
/* Deterministic-nonce encrypt for KAT testing.  nonce must be NAPQES_NONCE_SIZE bytes.
 * Output is byte-identical to the Python/Rust reference given the same nonce.
 *
 * NOT PART OF THE PRODUCTION API (CVF3 fix, 2026-07-06). Every internal
 * NAPQES value (noise positions, addends, keystream) is a deterministic
 * function of (key, nonce) alone, so an explicit, caller-chosen nonce is a
 * key-recovery hazard, not merely a confidentiality-losing one — see
 * docs/CAVEATS.md (CVF3). This symbol is compiled in only when
 * NAPQES_ENABLE_TEST_NONCE_API is defined (the C KAT harness build); it is
 * absent from the default library / napqes_demo build, so it cannot be
 * linked against by production code. Use napqes_encrypt_bytes(), which
 * always generates a fresh CSPRNG nonce internally. */
uint8_t *napqes_encrypt_bytes_with_nonce(const char *message,
                                          const uint64_t *key, size_t klen,
                                          const uint8_t *aad, size_t aad_len,
                                          const uint8_t *nonce,
                                          size_t *out_len);
#endif /* NAPQES_ENABLE_TEST_NONCE_API */

/* ── V8: misuse-resistant synthetic-nonce construction (CVF3/CVF8/CVF13 fix) ──
 *
 * v7's nonce is a fresh CSPRNG draw per call. Every internal value (noise
 * schedule, addends, keystream, tag) is a deterministic function of
 * (key_bytes(key), nonce) alone, so a *reused* nonce reproduces an identical
 * keystream/schedule; combined with the exact affine token map c*k+a, this
 * permits exact key recovery from two known plaintexts under one reused
 * nonce (docs/CAVEATS.md, CVF3). A CSPRNG nonce only makes *accidental*
 * reuse improbable — it does nothing against DRBG failure, process
 * restart/replay, or VM/container snapshot-and-restore.
 *
 * v8 closes this by construction (SIV-style synthetic nonce, RFC 5297 /
 * AES-GCM-SIV): the nonce is *derived*, not drawn, as a keyed HMAC of the
 * (aad, message) being encrypted, under an **independently**-sampled
 * 256-bit subkey `sk` that is never a function of the prime-tuple key. See
 * docs/napseq-eprint-preprint.tex §"V8 Key Schedule and Synthetic Nonce".
 *
 * This implementation additionally derives a per-wire-format subkey
 * (domain 0x0B, `sk_fmt = HMAC(sk, 0x0B || format_id)`) and uses `sk_fmt` in
 * place of `sk` for every subsequent domain derivation (0x00-0x0A), so a
 * ciphertext/tag produced for one wire format can never verify under
 * another format's effective key, even with the same (primes, sk).
 *
 * v8 is additive: the v7 API above is unchanged and remains available. v7
 * and v8 ciphertexts are NOT interoperable (different keying and nonce
 * derivation) — callers must agree out-of-band on which schedule a given
 * key/ciphertext pair uses (see docs/napseq-eprint-preprint.tex
 * §"Format Applicability"). */

#define NAPQES_SK_SIZE 32

/* Hard cap on consecutive noise tokens emitted before a real token, applied
 * only by the v8 token-emission loop (never by v7). Without a cap, the
 * noise-probability range [0.75, 0.99] implies a worst-case expansion of
 * up to ~100 tokens per real codepoint. Capping at 19 bounds the worst
 * case to exactly 20 tokens per real codepoint, matching the documented
 * "<=20x" ciphertext-expansion bound exactly. */
#define NAPQES_MAX_NOISE_RUN 19

/* Domain 0x0B format-subkey identifiers. */
#define NAPQES_FORMAT_BLOCK_V8      0x01
#define NAPQES_FORMAT_STREAM_AE_V8  0x02

/* Generate v8 key material: `count` distinct primes in `primes_out` (used
 * only by the public, un-keyed arithmetic token map c*k+a) plus an
 * **independently**-sampled 256-bit HMAC subkey in `sk_out`. No function
 * relates `sk_out` to `primes_out`; both are secret key material that MUST
 * be generated, stored, and transmitted together. Returns 0 on success,
 * -1 on failure (insufficient primes in range / RNG failure). */
int napqes_generate_v8_key(uint64_t *primes_out, size_t count,
                           uint64_t min_val, uint64_t max_val,
                           uint8_t sk_out[NAPQES_SK_SIZE]);

/* Misuse-resistant v8 block-mode encryption (synthetic nonce, independent
 * subkey). `primes`/`klen` are the arithmetic key (as in
 * napqes_encrypt_bytes); `sk` is the independent 256-bit v8 subkey from
 * napqes_generate_v8_key(). The nonce is *derived*, not drawn from a
 * CSPRNG: encrypting the same (sk, aad, message) twice yields
 * byte-identical ciphertext (the disclosed MRAE trade-off, cf.
 * AES-GCM-SIV); distinct messages get distinct nonces with overwhelming
 * probability. Returns malloc'd buffer (caller frees) or NULL on
 * failure/oversized message. v8 ciphertexts are NOT interoperable with v7
 * ciphertexts. */
uint8_t *napqes_encrypt_bytes_v8(const char *message,
                                 const uint64_t *primes, size_t klen,
                                 const uint8_t sk[NAPQES_SK_SIZE],
                                 const uint8_t *aad, size_t aad_len,
                                 size_t *out_len);

/* Decrypt a v8 ciphertext produced by napqes_encrypt_bytes_v8(). Returns
 * malloc'd NUL-terminated string (caller frees) or NULL on authentication
 * failure / parse error / allocation failure. */
char *napqes_decrypt_bytes_v8(const uint8_t *ciphertext, size_t ct_len,
                              const uint64_t *primes, size_t klen,
                              const uint8_t sk[NAPQES_SK_SIZE],
                              const uint8_t *aad, size_t aad_len);

/* Base64-wrapped v8 string API (mirrors napqes_encrypt_str/decrypt_str). */
char *napqes_encrypt_str_v8(const char *message,
                            const uint64_t *primes, size_t klen,
                            const uint8_t sk[NAPQES_SK_SIZE],
                            const uint8_t *aad, size_t aad_len);
char *napqes_decrypt_str_v8(const char *cypher,
                            const uint64_t *primes, size_t klen,
                            const uint8_t sk[NAPQES_SK_SIZE],
                            const uint8_t *aad, size_t aad_len);

#endif
