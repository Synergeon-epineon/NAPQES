/* Demo / smoke test for the C port of napqes. */
#include "napqes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *b, size_t n) {
    printf("%s (%zu bytes): ", label, n);
    for (size_t i = 0; i < n && i < 32; ++i) printf("%02x", b[i]);
    if (n > 32) printf("...");
    printf("\n");
}

int main(void) {
    uint64_t key[10];
    if (napqes_generate_primes(key, 10, 1000000, 9999999) != 0) {
        fprintf(stderr, "prime generation failed\n");
        return 1;
    }
    printf("key:");
    for (int i = 0; i < 10; ++i) printf(" %llu", (unsigned long long)key[i]);
    printf("\n\n");

    const char *msg = "Hello from the C port of napqes!";
    const uint8_t aad[] = "ctx=demo";
    size_t aad_len = sizeof(aad) - 1;

    /* String API */
    char *ct_str = napqes_encrypt_str(msg, key, 10, aad, aad_len);
    if (!ct_str) { fprintf(stderr, "encrypt_str failed\n"); return 1; }
    printf("plaintext : %s\n", msg);
    printf("cipher_b64: %s\n", ct_str);

    char *pt = napqes_decrypt_str(ct_str, key, 10, aad, aad_len);
    if (!pt) { fprintf(stderr, "decrypt_str failed\n"); free(ct_str); return 1; }
    printf("decrypted : %s\n", pt);
    int ok_str = strcmp(pt, msg) == 0;
    printf("string round-trip: %s\n\n", ok_str ? "OK" : "MISMATCH");
    free(ct_str); free(pt);

    /* Binary API */
    size_t bin_len = 0;
    uint8_t *bin = napqes_encrypt_bytes(msg, key, 10, NULL, 0, &bin_len);
    if (!bin) { fprintf(stderr, "encrypt_bytes failed\n"); return 1; }
    print_hex("cipher_bin", bin, bin_len);
    char *pt2 = napqes_decrypt_bytes(bin, bin_len, key, 10, NULL, 0);
    int ok_bin = pt2 && strcmp(pt2, msg) == 0;
    printf("binary round-trip: %s\n", ok_bin ? "OK" : "MISMATCH");

    /* Negative: tamper the tag. */
    bin[bin_len - 1] ^= 0x01;
    char *pt3 = napqes_decrypt_bytes(bin, bin_len, key, 10, NULL, 0);
    printf("tampered ciphertext rejected: %s\n", pt3 == NULL ? "OK" : "FAIL");
    free(pt3);
    free(pt2);
    free(bin);

    return (ok_str && ok_bin) ? 0 : 1;
}
