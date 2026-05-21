#include "base64.h"
#include <string.h>

static const char ALPHA[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encoded_len(size_t in_len) { return ((in_len + 2) / 3) * 4; }
size_t base64_decoded_max_len(size_t in_len) { return (in_len / 4) * 3; }

size_t base64_encode(const uint8_t *in, size_t in_len, char *out) {
    size_t i = 0, j = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[j++] = ALPHA[(v >> 18) & 0x3F];
        out[j++] = ALPHA[(v >> 12) & 0x3F];
        out[j++] = ALPHA[(v >> 6)  & 0x3F];
        out[j++] = ALPHA[v & 0x3F];
        i += 3;
    }
    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[j++] = ALPHA[(v >> 18) & 0x3F];
        out[j++] = ALPHA[(v >> 12) & 0x3F];
        out[j++] = '=';
        out[j++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8);
        out[j++] = ALPHA[(v >> 18) & 0x3F];
        out[j++] = ALPHA[(v >> 12) & 0x3F];
        out[j++] = ALPHA[(v >> 6)  & 0x3F];
        out[j++] = '=';
    }
    out[j] = '\0';
    return j;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

long base64_decode(const char *in, size_t in_len, uint8_t *out) {
    if (in_len % 4 != 0) return -1;
    size_t j = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        int v0 = b64_val(in[i]);
        int v1 = b64_val(in[i+1]);
        if (v0 < 0 || v1 < 0) return -1;
        int pad2 = (in[i+2] == '=');
        int pad3 = (in[i+3] == '=');
        int v2 = pad2 ? 0 : b64_val(in[i+2]);
        int v3 = pad3 ? 0 : b64_val(in[i+3]);
        if (v2 < 0 || v3 < 0) return -1;
        uint32_t triple = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12)
                        | ((uint32_t)v2 << 6)  | (uint32_t)v3;
        out[j++] = (uint8_t)((triple >> 16) & 0xFF);
        if (!pad2) out[j++] = (uint8_t)((triple >> 8) & 0xFF);
        if (!pad3) out[j++] = (uint8_t)(triple & 0xFF);
        if (pad2 && !pad3) return -1;
    }
    return (long)j;
}
