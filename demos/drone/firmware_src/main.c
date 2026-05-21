/*
 * main.c — ESP32 Flight Controller Bootloader
 *
 * Runs from cleartext flash (public, non-proprietary).
 * Reads the NAPQES prime-list key from OTP eFuse, then decrypts
 * each proprietary partition into SRAM before handing off to the
 * flight stack.
 *
 * Target: ESP32-S3 / Xtensa LX7, IDF 5.x
 * Section: .text.bootloader  (cleartext)
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "napqes_bootloader.h"

/* ── OTP eFuse layout ───────────────────────────────────────────────────── */
/* The prime-list key occupies 50 bytes of the USER_DATA eFuse block.
 * 10 primes × 5 bytes each, big-endian.  Written once at manufacturing;
 * RDP Level 2 locks JTAG after injection so the key cannot be read back. */
#define EFUSE_NAPQES_KEY_OFFSET  0x00
#define EFUSE_NAPQES_KEY_LEN     50
#define NAPQES_KEY_COUNT         10

/* ── Partition table (flash layout) ────────────────────────────────────── */
typedef struct {
    const char *name;
    uint32_t    flash_addr;   /* start address in flash */
    uint32_t    flash_size;   /* encrypted blob size    */
    void       *sram_dest;    /* target SRAM address    */
    int         encrypted;    /* 1 = NAPQES-protected   */
} partition_entry_t;

extern uint8_t _obstacle_avoid_start[];  /* linker symbols */
extern uint8_t _sensor_fusion_start[];
extern uint8_t _sram_obstacle_avoid[];
extern uint8_t _sram_sensor_fusion[];

static const partition_entry_t PARTITION_TABLE[] = {
    { "obstacle_avoid", 0x00200000, 0, _sram_obstacle_avoid, 1 },
    { "sensor_fusion",  0x00280000, 0, _sram_sensor_fusion,  1 },
};
#define NUM_PARTITIONS (sizeof(PARTITION_TABLE) / sizeof(PARTITION_TABLE[0]))

/* ── Device identity (burned into eFuse at manufacturing) ───────────────── */
static const uint8_t DEVICE_SERIAL[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
};
static const uint32_t FIRMWARE_VERSION = 0x00010002;  /* v1.2 */

/* ── Stub: read prime-list key from OTP eFuse ───────────────────────────── */
static void efuse_read_napqes_key(uint64_t *key_out) {
    /* In production: call esp_efuse_read_field_blob() targeting USER_DATA.
     * This stub loads a compile-time placeholder for simulation only. */
    const uint8_t raw[EFUSE_NAPQES_KEY_LEN] = { 0 };  /* replaced at build */
    for (int i = 0; i < NAPQES_KEY_COUNT; i++) {
        key_out[i] = 0;
        for (int b = 0; b < 5; b++)
            key_out[i] = (key_out[i] << 8) | raw[i * 5 + b];
    }
}

/* ── Boot entry point ───────────────────────────────────────────────────── */
void app_main(void) {
    uint64_t napqes_key[NAPQES_KEY_COUNT];

    printf("[BOOT] ESP32 Flight Controller v%u.%u\n",
           FIRMWARE_VERSION >> 16, FIRMWARE_VERSION & 0xFFFF);

    /* Step 1: recover key from OTP eFuse */
    efuse_read_napqes_key(napqes_key);
    printf("[BOOT] NAPQES key loaded from OTP eFuse\n");

    /* Step 2: decrypt each proprietary partition */
    for (size_t i = 0; i < NUM_PARTITIONS; i++) {
        const partition_entry_t *p = &PARTITION_TABLE[i];
        printf("[BOOT] Decrypting partition '%s'...\n", p->name);

        int rc = napqes_decrypt_partition(
            p->flash_addr, p->flash_size,
            napqes_key, NAPQES_KEY_COUNT,
            DEVICE_SERIAL, sizeof(DEVICE_SERIAL),
            FIRMWARE_VERSION, p->name,
            p->sram_dest
        );

        if (rc != 0) {
            printf("[BOOT] FATAL: auth tag mismatch on partition '%s'. "
                   "Halting.\n", p->name);
            /* Halt — do not execute unauthenticated code */
            for (;;) __asm__ volatile("nop");
        }
        printf("[BOOT] Partition '%s' verified and loaded into SRAM\n",
               p->name);
    }

    /* Step 3: hand off to flight stack (runs entirely from SRAM) */
    printf("[BOOT] All partitions authenticated. Launching flight stack.\n");
    /* flight_stack_main(); */
}
