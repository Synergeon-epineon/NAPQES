/* Minimal portable SHA-256 + HMAC-SHA256 implementation.
 * Derived from FIPS 180-4 pseudocode; public-domain style.
 */
#include "sha256.h"
#include <string.h>

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n)) | ((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y)) ^ (~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
#define BSIG0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define BSIG1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SSIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x)>>3))
#define SSIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x)>>10))

static void sha256_compress(sha256_ctx *ctx, const uint8_t *blk) {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = ((uint32_t)blk[i*4]<<24) | ((uint32_t)blk[i*4+1]<<16)
             | ((uint32_t)blk[i*4+2]<<8) | ((uint32_t)blk[i*4+3]);
    }
    for (int i = 16; i < 64; ++i) {
        W[i] = SSIG1(W[i-2]) + W[i-7] + SSIG0(W[i-15]) + W[i-16];
    }
    uint32_t a=ctx->state[0], b=ctx->state[1], c=ctx->state[2], d=ctx->state[3];
    uint32_t e=ctx->state[4], f=ctx->state[5], g=ctx->state[6], h=ctx->state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + BSIG1(e) + CH(e,f,g) + K256[i] + W[i];
        uint32_t t2 = BSIG0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void sha256_init(sha256_ctx *ctx) {
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bitlen += (uint64_t)len * 8;
    if (ctx->buflen) {
        size_t need = SHA256_BLOCK_SIZE - ctx->buflen;
        if (len < need) {
            memcpy(ctx->buffer + ctx->buflen, data, len);
            ctx->buflen += len;
            return;
        }
        memcpy(ctx->buffer + ctx->buflen, data, need);
        sha256_compress(ctx, ctx->buffer);
        data += need; len -= need; ctx->buflen = 0;
    }
    while (len >= SHA256_BLOCK_SIZE) {
        sha256_compress(ctx, data);
        data += SHA256_BLOCK_SIZE;
        len  -= SHA256_BLOCK_SIZE;
    }
    if (len) {
        memcpy(ctx->buffer, data, len);
        ctx->buflen = len;
    }
}

void sha256_final(sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_SIZE]) {
    uint64_t bits = ctx->bitlen;
    ctx->buffer[ctx->buflen++] = 0x80;
    if (ctx->buflen > 56) {
        while (ctx->buflen < SHA256_BLOCK_SIZE) ctx->buffer[ctx->buflen++] = 0;
        sha256_compress(ctx, ctx->buffer);
        ctx->buflen = 0;
    }
    while (ctx->buflen < 56) ctx->buffer[ctx->buflen++] = 0;
    for (int i = 7; i >= 0; --i) ctx->buffer[ctx->buflen++] = (uint8_t)(bits >> (i*8));
    sha256_compress(ctx, ctx->buffer);
    for (int i = 0; i < 8; ++i) {
        out[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        out[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out);
}

void hmac_sha256(const uint8_t *key, size_t klen,
                 const uint8_t *msg, size_t mlen,
                 uint8_t out[SHA256_DIGEST_SIZE]) {
    uint8_t k0[SHA256_BLOCK_SIZE];
    uint8_t ipad[SHA256_BLOCK_SIZE], opad[SHA256_BLOCK_SIZE];
    if (klen > SHA256_BLOCK_SIZE) {
        sha256(key, klen, k0);
        memset(k0 + SHA256_DIGEST_SIZE, 0, SHA256_BLOCK_SIZE - SHA256_DIGEST_SIZE);
    } else {
        memcpy(k0, key, klen);
        memset(k0 + klen, 0, SHA256_BLOCK_SIZE - klen);
    }
    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    sha256_ctx c;
    uint8_t inner[SHA256_DIGEST_SIZE];
    sha256_init(&c);
    sha256_update(&c, ipad, SHA256_BLOCK_SIZE);
    sha256_update(&c, msg, mlen);
    sha256_final(&c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, SHA256_BLOCK_SIZE);
    sha256_update(&c, inner, SHA256_DIGEST_SIZE);
    sha256_final(&c, out);
}
