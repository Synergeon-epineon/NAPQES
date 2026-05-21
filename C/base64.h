#ifndef NAPQES_BASE64_H
#define NAPQES_BASE64_H

#include <stddef.h>
#include <stdint.h>

/* Returns the exact base64-encoded length (no NUL) for `in_len` input bytes. */
size_t base64_encoded_len(size_t in_len);

/* Returns the maximum decoded length for `in_len` base64 chars. */
size_t base64_decoded_max_len(size_t in_len);

/* Encodes `in_len` bytes into `out` (writes a trailing NUL).
 * `out` must have room for base64_encoded_len(in_len) + 1 bytes.
 * Returns the number of base64 chars written (excluding NUL).
 */
size_t base64_encode(const uint8_t *in, size_t in_len, char *out);

/* Decodes `in_len` base64 chars (must be exact multiple of 4 incl. padding).
 * Writes raw bytes to `out`; returns decoded byte length, or -1 on error.
 */
long base64_decode(const char *in, size_t in_len, uint8_t *out);

#endif
