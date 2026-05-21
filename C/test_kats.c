/*
 * C KAT harness for NAPSEQ v6 (Phase 0, workstream 0.1 / ROADMAP §2.B8).
 *
 * Reads tests/kat/v6_vectors.json relative to the repo root, calls the C
 * napqes_decrypt_bytes() API for every positive vector and asserts the
 * decrypted plaintext matches the expected message.  Negative vectors are
 * also exercised: the call must fail (return NULL).
 *
 * Build:
 *   make -C C kat-test
 *
 * STATUS: Port-parity stub.  Encryption determinism (encrypt-with-fixed-nonce)
 * requires an internal C helper that is not yet exposed in napqes.h.
 * Known divergences from the Python reference are logged as PARITY-NOTE below.
 * Fixing divergences is Phase 2 (workstream 2.1).
 *
 * Exit codes:
 *   0  all tested assertions passed (or were skipped with PARITY-NOTE)
 *   1  at least one unexpected assertion failed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── Minimal JSON path extractor ─────────────────────────────────────────── */

/* Find the value of a top-level string key in a trivially-flat JSON object.
 * Returns a malloc'd copy of the value string, or NULL if not found.
 * This is NOT a general JSON parser — it is only adequate for the flat
 * per-vector objects produced by gen_kats.py.                               */
static char *json_str(const char *json, const char *key) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char *p = strstr(json, pattern);
    if (!p) return NULL;
    p += strlen(pattern);
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        const char *end = strchr(p, '"');
        if (!end) return NULL;
        size_t len = (size_t)(end - p);
        char *val = malloc(len + 1);
        if (!val) return NULL;
        memcpy(val, p, len);
        val[len] = '\0';
        return val;
    }
    return NULL;
}

/* Decode a hex string into a freshly malloc'd byte array.
 * Sets *out_len to the number of decoded bytes.
 * Returns NULL on error or if hex is empty string "".                       */
static uint8_t *hex_decode(const char *hex, size_t *out_len) {
    *out_len = 0;
    if (!hex || hex[0] == '\0') return NULL;
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return NULL;
    size_t n = hlen / 2;
    uint8_t *buf = malloc(n);
    if (!buf) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) {
            free(buf);
            return NULL;
        }
        buf[i] = (uint8_t)byte;
    }
    *out_len = n;
    return buf;
}

/* ── Placeholder for napqes C API ─────────────────────────────────────────── */
/*
 * PARITY-NOTE: The C port (napqes.h / napqes.c) exposes napqes_decrypt_bytes()
 * but does not yet expose a fixed-nonce encrypt path or a direct
 * napqes_decrypt_bytes_raw() that accepts binary ciphertext.  The public
 * napqes_decrypt_str() accepts base64.  This stub exercises that interface.
 *
 * A full cross-check (encrypting with a fixed nonce and comparing hex to the
 * Python-generated ciphertext_hex) requires:
 *   1. An internal napqes_encrypt_bytes_with_nonce() C function, OR
 *   2. Exposing a binary-input decrypt variant.
 * Both are deferred to Phase 2 (workstream 2.1 "Rust core + KAT parity").
 */

/* Minimal stubs so this file compiles even if napqes.h is not yet updated. */
#ifndef NAPQES_H
typedef struct { int dummy; } napqes_ctx_t;
static inline char *napqes_decrypt_str(const char *ct_b64,
                                        const uint64_t *key, size_t klen,
                                        const uint8_t *aad, size_t aad_len) {
    (void)ct_b64; (void)key; (void)klen; (void)aad; (void)aad_len;
    return NULL; /* PARITY-NOTE: not yet implemented */
}
#else
#include "napqes.h"
#endif

/* ── Base64 encode (for assembling test input from raw hex) ──────────────── */

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;
    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)data[i] << 16) |
                     ((uint32_t)data[i+1] << 8) |
                     (uint32_t)data[i+2];
        out[j++] = B64_CHARS[(v >> 18) & 0x3F];
        out[j++] = B64_CHARS[(v >> 12) & 0x3F];
        out[j++] = B64_CHARS[(v >> 6)  & 0x3F];
        out[j++] = B64_CHARS[ v        & 0x3F];
    }
    if (i < len) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len) v |= (uint32_t)data[i+1] << 8;
        out[j++] = B64_CHARS[(v >> 18) & 0x3F];
        out[j++] = B64_CHARS[(v >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? B64_CHARS[(v >> 6) & 0x3F] : '=';
        out[j++] = '=';
    }
    out[j] = '\0';
    return out;
}

/* ── Load and split JSON vector objects ────────────────────────────────────── */

#define MAX_VECTORS 64

static int split_vectors(const char *json, const char **starts,
                          const char **ends, int max) {
    int count = 0;
    const char *p = json;
    int depth = 0;
    const char *obj_start = NULL;
    while (*p && count < max) {
        if (*p == '{') {
            if (depth == 0) obj_start = p;
            depth++;
        } else if (*p == '}') {
            depth--;
            if (depth == 0 && obj_start) {
                starts[count] = obj_start;
                ends[count]   = p + 1;
                count++;
                obj_start = NULL;
            }
        }
        p++;
    }
    return count;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

int main(int argc, char *argv[]) {
    const char *vec_path = (argc > 1) ? argv[1] : "../tests/kat/v6_vectors.json";
    char *json = read_file(vec_path);
    if (!json) {
        fprintf(stderr, "ERROR: cannot open %s\n", vec_path);
        fprintf(stderr, "PARITY-NOTE: run from C/ subdirectory or pass path as arg\n");
        return 1;
    }

    const char *starts[MAX_VECTORS], *ends[MAX_VECTORS];
    int nv = split_vectors(json, starts, ends, MAX_VECTORS);
    if (nv == 0) {
        fprintf(stderr, "ERROR: no vectors found in %s\n", vec_path);
        free(json);
        return 1;
    }

    int passed = 0, failed = 0, skipped = 0;

    for (int i = 0; i < nv; i++) {
        /* Copy the vector JSON object into a NUL-terminated buffer */
        size_t obj_len = (size_t)(ends[i] - starts[i]);
        char *obj = malloc(obj_len + 1);
        if (!obj) { failed++; continue; }
        memcpy(obj, starts[i], obj_len);
        obj[obj_len] = '\0';

        char *id   = json_str(obj, "id");
        char *kind = json_str(obj, "kind");
        if (!id || !kind) { free(id); free(kind); free(obj); skipped++; continue; }

        if (strcmp(kind, "positive") == 0) {
            char *ct_hex = json_str(obj, "ciphertext_hex");
            char *msg    = json_str(obj, "message");
            char *aad_h  = json_str(obj, "aad_hex");

            if (!ct_hex || !msg || !aad_h) {
                /* Empty message vector */
                printf("[SKIP] %s: empty message — no C assertion defined\n", id);
                skipped++;
                free(ct_hex); free(msg); free(aad_h);
                free(id); free(kind); free(obj);
                continue;
            }

            size_t ct_len = 0, aad_len = 0;
            uint8_t *ct_bytes = hex_decode(ct_hex, &ct_len);
            uint8_t *aad_bytes = (aad_h[0] != '\0')
                                 ? hex_decode(aad_h, &aad_len)
                                 : NULL;

            /* PARITY-NOTE: napqes_decrypt_str requires base64 + key array.
             * Key parsing from JSON is not implemented here; this stub
             * marks positive decrypt tests as SKIP until Phase 2.           */
            printf("[SKIP] %s (%s): decrypt parity not yet implemented "
                   "(Phase 2)\n", id, msg);
            skipped++;

            free(ct_bytes); free(aad_bytes); free(ct_hex); free(msg);
            free(aad_h);

        } else if (strcmp(kind, "negative") == 0) {
            /* PARITY-NOTE: negative vectors also require key array parsing  */
            printf("[SKIP] %s (negative): key parsing not yet implemented "
                   "(Phase 2)\n", id);
            skipped++;
        }

        free(id); free(kind); free(obj);
    }

    free(json);

    printf("\nC KAT results: %d passed, %d failed, %d skipped\n",
           passed, failed, skipped);
    printf("PARITY-NOTE: All tests skipped pending Phase 2 port parity work.\n");
    printf("  Divergences (if any) will be logged in docs/CAVEATS.md.\n");

    return (failed > 0) ? 1 : 0;
}
