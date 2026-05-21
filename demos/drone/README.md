# Demo: Drone Firmware Protection (NAPQES Use Case 2)

Demonstrates how NAPQES v6 AEAD protects proprietary drone flight-controller
firmware against reverse engineering via raw flash dumps.

## Story

An inspection drone contains two highly proprietary modules:

| Module | Secret |
|---|---|
| `obstacle_avoidance.c` | BFS path planner, dynamic safety-margin scaling, proprietary HV cable-sag model (3 years R&D) |
| `sensor_fusion.c` | Extended Kalman Filter with hand-tuned noise matrices (Q, R) from 800+ flight hours |

These are encrypted at rest in flash using NAPQES v6. Even with a full flash
dump an attacker sees only pseudorandom noise — no code, no constants, no
variable names.

## How it works

```
[firmware_src/*.c]
       │
       │  protect.py reads source files as section payloads
       ▼
[firmware_plain.bin]     ← all sections cleartext (reference)
       │
       │  napqes.encrypt_bytes(plaintext, key,
       │      aad = device_serial ‖ fw_version ‖ section_name)
       ▼
[firmware_protected.bin] ← proprietary sections = NAPQES blobs
       │
       │  esptool.py write_flash (optional, if board connected)
       ▼
[ESP32 board flash]
```

At runtime the bootloader (`napqes_bootloader.c`) decrypts each protected
section into SRAM using the key stored in OTP eFuse. If the HMAC-SHA256 tag
fails (tampered or wrong device), the bootloader halts — no partial code runs.

## Quick start

```bash
# Step 1: build + encrypt
cd demos/drone/protect
python protect.py

# Step 2: inspect the plain firmware (C source code is readable)
cd ../inspect
python inspect_firmware.py ../protect/output/firmware_plain.bin

# Step 3: inspect the protected firmware (proprietary sections are noise)
python inspect_firmware.py ../protect/output/firmware_protected.bin

# Step 4: side-by-side entropy comparison
python inspect_firmware.py ../protect/output/firmware_plain.bin \
                           ../protect/output/firmware_protected.bin

# Optional: flash to a connected ESP32
cd ../protect
python protect.py --flash --port COM3          # Windows
python protect.py --flash --port /dev/ttyUSB0  # Linux/macOS
```

## Directory layout

```
demos/drone/
├── firmware_src/
│   ├── main.c                  cleartext bootloader init (shows NAPQES decrypt calls)
│   ├── napqes_bootloader.c     cleartext NAPQES wrapper (AAD construction, HMAC halt)
│   ├── obstacle_avoidance.c    PROPRIETARY — encrypted in protected image
│   └── sensor_fusion.c         PROPRIETARY — encrypted in protected image
├── protect/
│   ├── firmware_image.py       binary image format library (shared with inspect)
│   ├── protect.py              build + encrypt CLI
│   └── output/
│       ├── key.json            demo prime-list key (generated on first run)
│       ├── firmware_plain.bin  unprotected reference image
│       └── firmware_protected.bin  NAPQES-protected image
└── inspect/
    └── inspect_firmware.py     firmware inspector + entropy analyser
```

## Expected output

### `firmware_plain.bin` — obstacle_avoid section
```
  obstacle_avoid  [CLEARTEXT]
    Size    : 4,321 bytes
    Entropy : ████░░░░░░░░░░  4.87 bits/byte

    ✓  CLEARTEXT — decoded content (first 300 chars):
    │ /*
    │  * obstacle_avoidance.c — Proprietary Obstacle-Avoidance Algorithm
    │  * *** TRADE SECRET — DO NOT DISTRIBUTE ***
    │  ...
```

### `firmware_protected.bin` — obstacle_avoid section
```
  obstacle_avoid  [ENCRYPTED]
    Size    : 9,248 bytes
    Entropy : ████████████████████████████████  7.94 bits/byte

    ⛔  ENCRYPTED — section content is unreadable without the NAPQES key.
       No readable strings, no code patterns, no algebraic structure.
```

## Security properties demonstrated

| Property | How the demo shows it |
|---|---|
| Confidentiality | Inspector can't decode encrypted sections — hex dump is noise |
| HMAC authentication | Any bit flip in the blob would cause `decrypt_bytes` to raise `ValueError` |
| Device binding | AAD includes `device_serial` — transplanting the blob to another unit fails the tag |
| Version binding | AAD includes `fw_version` — downgrade attacks fail the tag |
| No algebraic structure | Entropy ≈ 8 bits/byte, no repeating patterns visible in hex dump |
