#ifndef NAPQES_SHA256_H
#define NAPQES_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[SHA256_BLOCK_SIZE];
    size_t   buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_SIZE]);

/* One-shot. */
void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

/* HMAC-SHA256. */
void hmac_sha256(const uint8_t *key, size_t klen,
                 const uint8_t *msg, size_t mlen,
                 uint8_t out[SHA256_DIGEST_SIZE]);

#endif
