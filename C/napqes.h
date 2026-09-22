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

/* ── Padding profiles (audit finding V3-CVF2) ─────────────────────────────
 * A padding profile is the map from plaintext codepoint count to padded
 * block size B (docs/napseq-eprint-v3.tex, Section "Padding Profiles").
 * This map is the *only* source of NAPQES's length-hiding property
 * (Theorem "lh-ind-cpa"); the token expansion factor contributes none,
 * since |C| = 48 + 160*(B+2) is a public injective function of B
 * (Proposition "expansion-neutral").
 *
 * Every profile takes values in the same 13-element set {2^4, ..., 2^16},
 * so the set of legal token counts is profile-independent: the profile is
 * a sender-side deployment parameter, is never transmitted, and
 * napqes_decrypt_bytes_v8() needs no matching argument. */

#define NAPQES_PAD_MIN_EXP 4
#define NAPQES_PAD_MAX_EXP 16

typedef enum {
    /* Default: smallest power of two strictly above n, floored at 16.
     * 13 reachable sizes, leaking at most log2(13) ~= 3.70 bits. */
    NAPQES_PAD_BUCKET = 0,
    /* NAPQES_PAD_BUCKET thinned by a stride g dividing 12 (param = g),
     * leaving 12/g + 1 reachable sizes. */
    NAPQES_PAD_COARSE = 1,
    /* Every message padded to the single size F (param = F), leaking
     * exactly zero bits. Requires n < F. */
    NAPQES_PAD_FRAME  = 2
} napqes_pad_kind_t;

typedef struct {
    napqes_pad_kind_t kind;
    uint32_t          param;  /* stride g / frame size F; unused for BUCKET */
} napqes_pad_profile_t;

/* Normative prime interval P = [NAPQES_MIN_KEY_PRIME, NAPQES_MAX_KEY_PRIME]
 * of the "PQ-128" profile. The upper bound is inclusive and chosen so that P
 * is exactly the half-open interval [10^6, 1.5e7) already used by the KEM
 * ports, so the AEAD and the KEM draw from the same prime set. P contains
 * exactly 892206 primes (verified by sieve), giving |P|!/(|P|-13)! =
 * 2^256.9711 ordered 13-tuples (2^128.4855 post-Grover). These bounds
 * constrain key *generation* only; validation and decryption accept any prime
 * >= NAPQES_MIN_KEY_PRIME, so keys generated under the earlier
 * [10^6, 9.9e6] interval remain usable. Matches
 * napqes.py::MIN_KEY_PRIME/MAX_KEY_PRIME and rust/src/lib.rs. */
#define NAPQES_MIN_KEY_PRIME 1000000ULL
#define NAPQES_MAX_KEY_PRIME 14999999ULL

/* Number of prime key elements generated by default ("PQ-128" profile).
 * K=13 is the smallest count reaching the 128-bit post-quantum target over P;
 * K=13 over the earlier [10^6, 9.9e6] interval would have given only 124.4
 * bits, which is why the interval was widened too. */
#define NAPQES_DEFAULT_KEY_COUNT 13u

/* Largest key element representable in the 5-byte key serialisation. A larger
 * value would be silently truncated to its low 5 bytes, producing a different
 * key than the Python port (which rejects it) would use. */
#define NAPQES_MAX_SERIALISABLE_KEY_PRIME 0xFFFFFFFFFFULL

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
 * ciphertexts. Uses the default NAPQES_PAD_BUCKET profile. */
uint8_t *napqes_encrypt_bytes_v8(const char *message,
                                 const uint64_t *primes, size_t klen,
                                 const uint8_t sk[NAPQES_SK_SIZE],
                                 const uint8_t *aad, size_t aad_len,
                                 size_t *out_len);

/* napqes_encrypt_bytes_v8() with an explicit padding profile. Pass NULL for
 * `pad_profile` to get NAPQES_PAD_BUCKET. Returns NULL on an invalid profile
 * (stride not dividing 12, frame not a power of two in [16, 65536]) or a
 * message that does not fit the requested frame. */
uint8_t *napqes_encrypt_bytes_v8_profiled(const char *message,
                                          const uint64_t *primes, size_t klen,
                                          const uint8_t sk[NAPQES_SK_SIZE],
                                          const uint8_t *aad, size_t aad_len,
                                          const napqes_pad_profile_t *pad_profile,
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
char *napqes_encrypt_str_v8_profiled(const char *message,
                                     const uint64_t *primes, size_t klen,
                                     const uint8_t sk[NAPQES_SK_SIZE],
                                     const uint8_t *aad, size_t aad_len,
                                     const napqes_pad_profile_t *pad_profile);
char *napqes_decrypt_str_v8(const char *cypher,
                            const uint64_t *primes, size_t klen,
                            const uint8_t sk[NAPQES_SK_SIZE],
                            const uint8_t *aad, size_t aad_len);


/* -- V8 streaming AE (FORMAT_STREAM_AE_V8, docs/CAVEATS.md CAV-005) ----------
 *
 * Wire format:
 *   HEADER (21 B):     0x02 || be4(F) || nonce(16)
 *   CHUNK * C:         be4(F*160) || masked(F*160) || tag(32)
 *   SENTINEL (44 B):   be4(0) || be8(total_real_codepoints) || tag(32)
 *
 * Every chunk i is a self-contained v8 primitive call keyed by
 * (sk_fmt, sub_nonce_i) where sub_nonce_i = HMAC(sk_fmt, 0x0E || nonce ||
 * be4(i))[:16]. Fixed-width 8-byte tokens plus per-chunk padding to F*20
 * tokens close the LEB128 length leak (V2-CVF11) that v7 stream_ae retains.
 *
 * Security caveat (CAV-005): the stream nonce is CSPRNG-drawn per stream
 * (NOT a v8-block SIV -- SIV requires hashing the full message, which is
 * incompatible with streaming). Nonce reuse under the same sk is
 * catastrophic (CVF3-class hazard on aligned codepoint positions). */

#define NAPQES_STREAM_AE_V8_DEFAULT_FRAME 128u
#define NAPQES_STREAM_AE_V8_MAX_FRAME     16384u

/* Encrypt an ASCII NUL-terminated `message` into a malloc'd v8 streaming
 * byte stream (header + chunk frames + sentinel). Returns NULL on invalid
 * inputs (bad primes, F out of [1, NAPQES_STREAM_AE_V8_MAX_FRAME], too-long
 * message). Caller frees. Uses a CSPRNG-drawn 16-byte nonce internally. */
uint8_t *napqes_encrypt_stream_ae_v8_bytes(const char *message,
                                           const uint64_t *primes, size_t klen,
                                           const uint8_t sk[NAPQES_SK_SIZE],
                                           const uint8_t *aad, size_t aad_len,
                                           uint32_t frame_codepoints,
                                           size_t *out_len);

/* Decrypt a v8 streaming byte stream produced by
 * `napqes_encrypt_stream_ae_v8_bytes`. Returns a malloc'd NUL-terminated
 * ASCII string (caller frees) or NULL on any authentication failure /
 * parse error / allocation failure. Each per-chunk tag is verified before
 * that chunk's plaintext contributes to the output; the sentinel binds
 * both the chunk count (anti-truncation) and the true real-codepoint
 * count (used to strip filler codepoints from the final chunk). */
char *napqes_decrypt_stream_ae_v8_bytes(const uint8_t *stream, size_t stream_len,
                                        const uint64_t *primes, size_t klen,
                                        const uint8_t sk[NAPQES_SK_SIZE],
                                        const uint8_t *aad, size_t aad_len);

#ifdef NAPQES_ENABLE_TEST_NONCE_API
/* Deterministic-nonce v8 stream encrypt -- TEST BUILDS ONLY.
 *
 * Same as `napqes_encrypt_stream_ae_v8_bytes` but with an injected 16-byte
 * `nonce`. Used by the KAT harness to cross-check byte-for-byte against the
 * Python reference. Production callers MUST NEVER pass a caller-chosen
 * nonce for v8 streaming: CAV-005 explains that nonce reuse under the same
 * `sk` allows a CVF3-class key recovery on aligned codepoint positions.
 * Symbol is absent unless `NAPQES_ENABLE_TEST_NONCE_API` is defined. */
uint8_t *napqes_encrypt_stream_ae_v8_bytes_with_nonce(
    const char *message,
    const uint64_t *primes, size_t klen,
    const uint8_t sk[NAPQES_SK_SIZE],
    const uint8_t *aad, size_t aad_len,
    uint32_t frame_codepoints,
    const uint8_t nonce[NAPQES_NONCE_SIZE],
    size_t *out_len);
#endif /* NAPQES_ENABLE_TEST_NONCE_API */

#endif
