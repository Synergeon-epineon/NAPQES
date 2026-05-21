/*
 * napqes_bootloader.c — NAPQES partition-decrypt helper
 *
 * Cleartext section: this code ships in the public bootloader partition.
 * It wraps the NAPQES static library with the drone-specific AAD construction
 * (device_serial || fw_version || partition_name) and loads decrypted
 * plaintext into SRAM.
 *
 * The key never leaves the CPU during this process; decrypted bytes are
 * written directly to SRAM and the encrypted blob in flash is never modified.
 *
 * Target: ESP32-S3, IDF 5.x — uses esp_flash_read() for flash access.
 * Section: .text.bootloader  (cleartext)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "napqes_bootloader.h"
#include "napqes.h"   /* NAPQES static library (also cleartext) */

/* ── AAD construction ────────────────────────────────────────────────────── */
/*
 * AAD = device_serial (16 B) || fw_version (4 B, BE) || partition_name (N B)
 *
 * Binding the AAD to device_serial means an encrypted blob is device-specific:
 * transplanting it to another unit fails the HMAC tag check.
 * Binding to fw_version prevents a downgrade attack using an older blob.
 */
static size_t build_aad(
    const uint8_t *device_serial, size_t serial_len,
    uint32_t       fw_version,
    const char    *partition_name,
    uint8_t       *aad_out, size_t aad_max)
{
    size_t name_len = strlen(partition_name);
    size_t total    = serial_len + 4 + name_len;
    if (total > aad_max) return 0;

    memcpy(aad_out, device_serial, serial_len);
    aad_out[serial_len + 0] = (fw_version >> 24) & 0xFF;
    aad_out[serial_len + 1] = (fw_version >> 16) & 0xFF;
    aad_out[serial_len + 2] = (fw_version >>  8) & 0xFF;
    aad_out[serial_len + 3] = (fw_version      ) & 0xFF;
    memcpy(aad_out + serial_len + 4, partition_name, name_len);
    return total;
}

/* ── Main decrypt entry point ────────────────────────────────────────────── */
int napqes_decrypt_partition(
    uint32_t        flash_addr,
    uint32_t        flash_size,
    const uint64_t *key,       size_t key_count,
    const uint8_t  *device_serial, size_t serial_len,
    uint32_t        fw_version,
    const char     *partition_name,
    void           *sram_dest)
{
    uint8_t  aad[64];
    size_t   aad_len;
    uint8_t *blob    = NULL;
    char    *plain   = NULL;
    int      rc      = -1;

    /* Build AAD */
    aad_len = build_aad(device_serial, serial_len, fw_version,
                        partition_name, aad, sizeof(aad));
    if (aad_len == 0) {
        fprintf(stderr, "[NAPQES] AAD construction failed\n");
        return -1;
    }

    /* Read encrypted blob from flash into a temporary heap buffer.
     * In production: esp_flash_read(NULL, blob, flash_addr, flash_size). */
    blob = (uint8_t *)malloc(flash_size);
    if (!blob) {
        fprintf(stderr, "[NAPQES] OOM allocating %u-byte blob buffer\n",
                flash_size);
        return -1;
    }
    /* Stub: in simulation the caller provides the blob differently */
    (void)flash_addr;

    /* Decrypt + authenticate */
    plain = napqes_decrypt_bytes(blob, flash_size,
                                 key, key_count,
                                 aad, aad_len);
    if (!plain) {
        fprintf(stderr, "[NAPQES] Authentication FAILED for partition '%s'. "
                "Blob is tampered or key mismatch.\n", partition_name);
        goto done;
    }

    /* Copy verified plaintext to SRAM */
    memcpy(sram_dest, plain, strlen(plain));
    rc = 0;

done:
    free(blob);
    free(plain);
    return rc;
}
