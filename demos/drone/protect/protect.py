#!/usr/bin/env python3
"""
protect.py — Drone firmware build + NAPQES encryption pipeline.

Usage
-----
    python protect.py [--key output/key.json] [--flash] [--port /dev/ttyUSB0]

What it does
------------
1.  Loads (or generates) a NAPQES prime-list key from key.json.
2.  Reads the C source files from ../firmware_src/ as section payloads.
3.  Writes output/firmware_plain.bin  — all sections cleartext.
4.  Encrypts the proprietary sections (obstacle_avoid, sensor_fusion) with
    NAPQES v6 authenticated encryption using AAD = device_serial || fw_version
    || section_name.
5.  Writes output/firmware_protected.bin — proprietary sections encrypted.
6.  Optionally flashes firmware_protected.bin via esptool if --flash is passed
    and esptool is available on PATH.
"""

import sys
import os
import json
import argparse
import subprocess
from pathlib import Path

# ── Path plumbing ─────────────────────────────────────────────────────────────
SCRIPT_DIR  = Path(__file__).parent
REPO_ROOT   = SCRIPT_DIR.parent.parent.parent   # demo_napseq/
FW_SRC      = SCRIPT_DIR.parent / "firmware_src"
OUTPUT_DIR  = SCRIPT_DIR / "output"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SCRIPT_DIR))

import napqes                             # from demo_napseq/napqes.py
from firmware_image import (              # local library
    Section, build_image, make_aad, aad_tag
)

# ── Device identity (fixed for demo; in production: OTP eFuse) ───────────────
DEVICE_SERIAL    = bytes.fromhex("DEADBEEF0123456789ABCDFEDCBA98")  # 15 B
DEVICE_SERIAL    = DEVICE_SERIAL.ljust(16, b"\x00")[:16]
FIRMWARE_VERSION = 0x00010002  # v1.2

# ── Section definitions ───────────────────────────────────────────────────────
#  (source_file, section_name, is_proprietary)
SECTION_DEFS = [
    ("main.c",                 "main",          False),
    ("napqes_bootloader.c",    "napqes_boot",   False),
    ("obstacle_avoidance.c",   "obstacle_avoid",True),
    ("sensor_fusion.c",        "sensor_fusion", True),
]


# ── Key management ────────────────────────────────────────────────────────────

def load_or_generate_key(key_path: Path) -> list[int]:
    if key_path.exists():
        data = json.loads(key_path.read_text())
        key  = data["key"]
        print(f"[KEY]  Loaded existing key from {key_path}")
    else:
        key = napqes.generate_prime_numbers(10)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(json.dumps({"key": key}, indent=2))
        print(f"[KEY]  Generated new key -> {key_path}")
    return key


# ── Build helpers ─────────────────────────────────────────────────────────────

def read_section_payload(src_file: str) -> bytes:
    path = FW_SRC / src_file
    if not path.exists():
        raise FileNotFoundError(f"Source file not found: {path}")
    return path.read_bytes()


def build_sections(key: list[int], encrypt_proprietary: bool) -> list[Section]:
    sections: list[Section] = []
    for src_file, sec_name, is_prop in SECTION_DEFS:
        payload = read_section_payload(src_file)
        aad     = make_aad(DEVICE_SERIAL, FIRMWARE_VERSION, sec_name)
        tag     = aad_tag(aad)

        if is_prop and encrypt_proprietary:
            # encrypt_bytes expects a str; decode the C source as latin-1
            # (safe for all byte values, lossless round-trip)
            plain_str  = payload.decode("latin-1")
            ciphertext = napqes.encrypt_bytes(plain_str, key, aad=aad)
            sections.append(Section(
                name=sec_name, payload=ciphertext,
                encrypted=True, aad_tag=tag,
            ))
            print(f"[ENC]  {sec_name:<18} {len(payload):>6} B "
                  f"-> {len(ciphertext):>6} B (NAPQES-encrypted)")
        else:
            sections.append(Section(
                name=sec_name, payload=payload,
                encrypted=False, aad_tag=tag,
            ))
            label = "proprietary-plain" if is_prop else "cleartext"
            print(f"[COPY] {sec_name:<18} {len(payload):>6} B ({label})")

    return sections


def write_image(path: Path, sections: list[Section]) -> None:
    image = build_image(DEVICE_SERIAL, FIRMWARE_VERSION, sections)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(image)
    print(f"[OUT]  {path}  ({len(image):,} bytes)")


# ── Optional esptool flash ────────────────────────────────────────────────────

def try_flash(bin_path: Path, port: str) -> None:
    print("\n[FLASH] Checking for esptool...")
    try:
        result = subprocess.run(
            ["esptool.py", "version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            raise FileNotFoundError
        print(f"[FLASH] esptool detected: {result.stdout.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("[FLASH] esptool not found — skipping flash step.")
        print(f"        To flash manually: esptool.py --port {port} "
              f"write_flash 0x00000 {bin_path}")
        return

    print(f"[FLASH] Flashing {bin_path} to {port}...")
    cmd = [
        "esptool.py", "--port", port, "--baud", "921600",
        "write_flash", "--flash_mode", "dio", "--flash_freq", "80m",
        "0x00000", str(bin_path),
    ]
    subprocess.run(cmd, check=True)
    print("[FLASH] Done.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build and encrypt ESP32 drone firmware with NAPQES."
    )
    parser.add_argument("--key",   default=str(OUTPUT_DIR / "key.json"),
                        help="Path to key JSON file (generated if missing)")
    parser.add_argument("--flash", action="store_true",
                        help="Flash firmware_protected.bin via esptool after build")
    parser.add_argument("--port",  default="/dev/ttyUSB0",
                        help="Serial port for esptool (default: /dev/ttyUSB0)")
    args = parser.parse_args()

    key_path = Path(args.key)

    print("=" * 60)
    print(" EPINeon Drone Firmware Protection — NAPQES v6 AEAD")
    print("=" * 60)
    print(f" Device serial : {DEVICE_SERIAL.hex().upper()}")
    print(f" FW version    : {FIRMWARE_VERSION >> 16}.{FIRMWARE_VERSION & 0xFFFF}")
    print()

    key = load_or_generate_key(key_path)

    # ── Build plaintext reference image ──────────────────────────────────────
    print("\n[STEP 1] Building plaintext reference image...")
    plain_sections    = build_sections(key, encrypt_proprietary=False)
    plain_path        = OUTPUT_DIR / "firmware_plain.bin"
    write_image(plain_path, plain_sections)

    # ── Build NAPQES-protected image ──────────────────────────────────────────
    print("\n[STEP 2] Building NAPQES-protected image...")
    protected_sections = build_sections(key, encrypt_proprietary=True)
    protected_path     = OUTPUT_DIR / "firmware_protected.bin"
    write_image(protected_path, protected_sections)

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print(" Build complete.")
    print(f"  Plaintext   : {plain_path}")
    print(f"  Protected   : {protected_path}")
    print()
    print(" Next step: inspect the firmware images:")
    inspect_script = SCRIPT_DIR.parent / "inspect" / "inspect.py"
    print(f"   python {inspect_script} {plain_path}")
    print(f"   python {inspect_script} {protected_path}")
    print("=" * 60)

    if args.flash:
        try_flash(protected_path, args.port)


if __name__ == "__main__":
    main()
