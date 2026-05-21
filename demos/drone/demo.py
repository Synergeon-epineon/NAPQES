#!/usr/bin/env python3
"""
demo.py -- EPINeon Drone Firmware Protection: A-to-Z terminal demo.

Run from any directory:
    python demos/drone/demo.py

Walks through 7 steps:
  1. Show the proprietary C source (the trade secret)
  2. Generate / load the NAPQES prime-list key
  3. Build the plaintext firmware image
  4. Inspect the plaintext image -- proprietary sections are readable
  5. Encrypt proprietary sections with NAPQES v6 AEAD
  6. Inspect the protected image -- proprietary sections are noise
  7. Entropy proof + security property summary
"""

import sys
import os
import io
import json

# Force UTF-8 output on Windows so em-dashes in C source files display correctly.
if os.name == "nt":
    os.system("chcp 65001 > nul 2>&1")
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace", line_buffering=True)
import math
import time
import threading
import struct
from pathlib import Path
from collections import Counter

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
DEMO_DIR  = Path(__file__).parent.resolve()
REPO_ROOT = DEMO_DIR.parent.parent
PROTECT   = DEMO_DIR / "protect"
FW_SRC    = DEMO_DIR / "firmware_src"
OUTPUT    = PROTECT / "output"

sys.path.insert(0, str(REPO_ROOT))   # napqes.py
sys.path.insert(0, str(PROTECT))     # firmware_image.py

import napqes
from firmware_image import (
    Section, build_image, parse_image, make_aad, aad_tag,
)

# ---------------------------------------------------------------------------
# Device identity (mirrors protect.py)
# ---------------------------------------------------------------------------
DEVICE_SERIAL    = bytes.fromhex("DEADBEEF0123456789ABCDFEDCBA98").ljust(16, b"\x00")[:16]
FIRMWARE_VERSION = 0x00010002  # v1.2

SECTION_DEFS = [
    ("main.c",               "main",          False),
    ("napqes_bootloader.c",  "napqes_boot",   False),
    ("obstacle_avoidance.c", "obstacle_avoid",True),
    ("sensor_fusion.c",      "sensor_fusion", True),
]

KEY_PATH       = OUTPUT / "key.json"
PLAIN_PATH     = OUTPUT / "firmware_plain.bin"
PROTECTED_PATH = OUTPUT / "firmware_protected.bin"

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------
_ANSI = sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _ANSI else text

def RED(t):    return _c("31;1", t)
def GREEN(t):  return _c("32;1", t)
def YELLOW(t): return _c("33;1", t)
def CYAN(t):   return _c("36;1", t)
def BOLD(t):   return _c("1", t)
def DIM(t):    return _c("2", t)

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def hr(char="-", width=62):
    print(char * width)

def pause(msg="  Press Enter to continue..."):
    try:
        input(f"\n{DIM(msg)}")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

def banner(title, step=None, total=7):
    clear()
    hr("=")
    if step:
        prefix = f"  [Step {step}/{total}] "
        print(BOLD(prefix) + CYAN(title))
    else:
        print(BOLD(f"  {title}"))
    hr("=")
    print()


# ---------------------------------------------------------------------------
# Spinner for slow operations
# ---------------------------------------------------------------------------
def _spin_worker(msg, stop):
    frames = ["-", "\\", "|", "/"]
    i = 0
    while not stop.is_set():
        print(f"\r  {msg} {frames[i % 4]}", end="", flush=True)
        time.sleep(0.12)
        i += 1
    print(f"\r  {msg} done.       ", flush=True)

def with_spinner(msg, fn, *args, **kwargs):
    stop = threading.Event()
    t = threading.Thread(target=_spin_worker, args=(msg, stop), daemon=True)
    t.start()
    try:
        return fn(*args, **kwargs)
    finally:
        stop.set()
        t.join()


# ---------------------------------------------------------------------------
# Build helpers (inlined from protect.py)
# ---------------------------------------------------------------------------
def load_or_generate_key():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        data = json.loads(KEY_PATH.read_text())
        return data["key"], False   # (key, was_generated)
    key = napqes.generate_prime_numbers(10)
    KEY_PATH.write_text(json.dumps({"key": key}, indent=2))
    return key, True


def build_sections(key, encrypt_proprietary):
    sections = []
    for src_file, sec_name, is_prop in SECTION_DEFS:
        payload = (FW_SRC / src_file).read_bytes()
        aad     = make_aad(DEVICE_SERIAL, FIRMWARE_VERSION, sec_name)
        tag     = aad_tag(aad)
        if is_prop and encrypt_proprietary:
            plain_str  = payload.decode("latin-1")
            ciphertext = napqes.encrypt_bytes(plain_str, key, aad=aad)
            sections.append(Section(name=sec_name, payload=ciphertext,
                                    encrypted=True, aad_tag=tag))
        else:
            sections.append(Section(name=sec_name, payload=payload,
                                    encrypted=False, aad_tag=tag))
    return sections


def write_image(path, sections):
    image = build_image(DEVICE_SERIAL, FIRMWARE_VERSION, sections)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(image)
    return len(image)


# ---------------------------------------------------------------------------
# Inspect helpers (inlined from inspect_firmware.py)
# ---------------------------------------------------------------------------
def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total  = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def hex_dump(data, max_bytes=64, indent="    "):
    chunk = data[:max_bytes]
    lines = []
    for i in range(0, len(chunk), 16):
        row  = chunk[i : i + 16]
        hex_ = " ".join(f"{b:02x}" for b in row)
        asc  = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{indent}{i:04x}  {hex_:<47}  |{asc}|")
    if len(data) > max_bytes:
        lines.append(f"{indent}... ({len(data) - max_bytes:,} more bytes not shown)")
    return "\n".join(lines)


def entropy_bar(e, width=24):
    filled = round(e / 8.0 * width)
    bar = "#" * filled + "." * (width - filled)
    label = f"{e:.2f} b/byte"
    if e > 7.5:
        return RED(f"[{bar}]") + f" {label}"
    elif e > 6.0:
        return YELLOW(f"[{bar}]") + f" {label}"
    else:
        return GREEN(f"[{bar}]") + f" {label}"


# ---------------------------------------------------------------------------
# STEP 0: Welcome
# ---------------------------------------------------------------------------
def step_welcome():
    clear()
    print()
    hr("=")
    print(BOLD("  EPINeon NAPQES  --  Drone Firmware Protection"))
    print(BOLD("  Use Case 2: Anti-Reverse-Engineering at Rest"))
    hr("=")
    print()
    print("  A European drone manufacturer produces inspection drones")
    print("  used over high-voltage transmission lines.")
    print()
    print("  The flight controller contains:")
    print(GREEN("    * Obstacle-avoidance algorithm") + " (BFS + HV cable-sag model, 3 yrs R&D)")
    print(GREEN("    * Sensor-fusion engine") + "      (Kalman filter, 800+ flight hours tuning)")
    print()
    print("  Competitors have extracted firmware from scrapped units")
    print("  via JTAG probing and cold-boot attacks on external flash.")
    print()
    print("  This demo shows how NAPQES v6 AEAD encrypts those sections")
    print("  so that a raw flash dump yields nothing useful.")
    print()
    hr("-")
    print()
    print("  What we will demonstrate:")
    print(f"    {BOLD('Step 1')} -- Show the proprietary source code (the trade secret)")
    print(f"    {BOLD('Step 2')} -- Generate the NAPQES prime-list key")
    print(f"    {BOLD('Step 3')} -- Build the plaintext firmware image")
    print(f"    {BOLD('Step 4')} -- Inspect plaintext: proprietary sections readable")
    print(f"    {BOLD('Step 5')} -- Encrypt with NAPQES v6 AEAD")
    print(f"    {BOLD('Step 6')} -- Inspect protected: proprietary sections = noise")
    print(f"    {BOLD('Step 7')} -- Entropy proof + security property summary")
    print()
    pause("  Press Enter to start...")


# ---------------------------------------------------------------------------
# STEP 1: Show the trade secret
# ---------------------------------------------------------------------------
def step_trade_secret():
    banner("THE TRADE SECRET", step=1)

    src = FW_SRC / "obstacle_avoidance.c"
    lines = src.read_text(encoding="utf-8", errors="replace").splitlines()

    print(f"  File: {src.name}  ({src.stat().st_size:,} bytes)")
    print()
    print(BOLD("  -- BEGIN obstacle_avoidance.c --"))
    hr()
    for i, line in enumerate(lines[:48], 1):
        # Highlight key trade-secret lines
        if any(kw in line for kw in
               ["TRADE SECRET", "cable_sag_coeff", "sensor_range_cm",
                "safety_margin_base", "cable_sag_coeff_a", "cable_sag_coeff_b"]):
            print(YELLOW(f"  {i:3}  {line}"))
        else:
            print(f"  {i:3}  {DIM(line)}")
    hr()
    print(BOLD("  -- (truncated) --"))
    print()
    print(RED("  [PROBLEM]") + " Without flash protection, this C source -- including")
    print("  proprietary coefficients and algorithms -- is recoverable by")
    print("  anyone with a $30 flash reader or JTAG probe.")
    pause()


# ---------------------------------------------------------------------------
# STEP 2: NAPQES key
# ---------------------------------------------------------------------------
def step_key():
    banner("GENERATE NAPQES PRIME-LIST KEY", step=2)

    print("  The NAPQES key is a list of 10 large primes (50 bytes total).")
    print("  Key space: ~2^196 ordered tuples -> well above 128-bit security.")
    print()

    key, generated = load_or_generate_key()

    if generated:
        print(GREEN("  [NEW]") + " Generated fresh key and saved to:")
    else:
        print(GREEN("  [LOADED]") + " Using existing key from:")
    print(f"    {KEY_PATH}")
    print()
    hr()
    print(BOLD(f"  {'#':>3}  {'Prime value':>12}  {'Hex':>10}"))
    hr()
    for i, p in enumerate(key, 1):
        print(f"  {i:>3}  {p:>12,}  {p:>#10x}")
    hr()
    print()
    print("  In production:")
    print("    1. Key is injected into OTP eFuse at the manufacturing station")
    print("    2. JTAG / SWD is locked (RDP Level 2) after injection")
    print("    3. The key can never be read back from the device")
    print()
    print(DIM("  (key.json used here for demo only -- never ship key.json with firmware)"))
    pause()
    return key


# ---------------------------------------------------------------------------
# STEP 3: Build plaintext image
# ---------------------------------------------------------------------------
def step_build_plain(key):
    banner("BUILD PLAINTEXT FIRMWARE IMAGE", step=3)

    print("  Packing 4 C source files as firmware sections...")
    print()

    sections = build_sections(key, encrypt_proprietary=False)
    size     = write_image(PLAIN_PATH, sections)

    hr()
    print(BOLD(f"  {'Section':<16} {'Size':>8}  {'Encrypted':>9}  Entropy"))
    hr()
    for sec in sections:
        e = shannon_entropy(sec.payload)
        enc_str = RED("YES") if sec.encrypted else GREEN("no")
        print(f"  {sec.name:<16} {len(sec.payload):>8,}  {enc_str:>9}  {entropy_bar(e)}")
    hr()
    print()
    print(f"  Written: {PLAIN_PATH.name}  ({size:,} bytes)")
    print()
    print(DIM("  All sections are cleartext -- this is the reference (unprotected) image."))
    pause()
    return sections


# ---------------------------------------------------------------------------
# STEP 4: Inspect plaintext -- proprietary sections readable
# ---------------------------------------------------------------------------
def step_inspect_plain():
    banner("INSPECT PLAINTEXT -- PROPRIETARY SECTIONS READABLE", step=4)

    _, _, sections = parse_image(PLAIN_PATH.read_bytes())

    # Find obstacle_avoid
    sec = next(s for s in sections if s.name == "obstacle_avo")
    e   = shannon_entropy(sec.payload)

    print(f"  Inspecting section: {BOLD(sec.name)}")
    print(f"  Size   : {len(sec.payload):,} bytes")
    print(f"  Entropy: {entropy_bar(e)}")
    print()
    print(BOLD("  Hex dump (first 64 bytes):"))
    print(hex_dump(sec.payload, max_bytes=64))
    print()
    print(BOLD("  Decoded content (first 25 lines):"))
    hr()
    text  = sec.payload.decode("utf-8", errors="replace")
    for i, line in enumerate(text.splitlines()[:25], 1):
        if any(kw in line for kw in
               ["TRADE SECRET", "cable_sag_coeff", "sensor_range", "safety_margin"]):
            print(YELLOW(f"  {i:3}  {line}"))
        else:
            print(f"  {i:3}  {line}")
    hr()
    print()
    print(RED("  [!!]") + " The trade-secret algorithm is fully visible in the hex dump.")
    print("       Any attacker with the flash binary can read this source code.")
    pause()


# ---------------------------------------------------------------------------
# STEP 5: Encrypt with NAPQES
# ---------------------------------------------------------------------------
def step_encrypt(key):
    banner("ENCRYPT PROPRIETARY SECTIONS WITH NAPQES v6 AEAD", step=5)

    print("  NAPQES wire format:  nonce(16) || masked_varint_blob || HMAC-SHA256(32)")
    print()
    print("  AAD (Associated Authenticated Data) for each section:")
    print(f"    device_serial   = {DEVICE_SERIAL.hex().upper()}")
    print(f"    firmware_version= {FIRMWARE_VERSION >> 16}.{FIRMWARE_VERSION & 0xFFFF}")
    print()
    print("  AAD construction per section:")
    for _, sec_name, is_prop in SECTION_DEFS:
        if is_prop:
            aad = make_aad(DEVICE_SERIAL, FIRMWARE_VERSION, sec_name)
            print(f"    {sec_name:<18}  aad = serial || version || \"{sec_name}\"")
            print(f"    {'':<18}       ({len(aad)} bytes total)")
    print()
    print(DIM("  Device-binding: any encrypted blob transplanted to a different unit"))
    print(DIM("  will fail the HMAC tag check -- the serial is baked into the AAD."))
    print()
    hr()
    print()

    # Encrypt with spinner
    sections = with_spinner(
        "Encrypting proprietary sections (NAPQES noise token generation)...",
        build_sections, key, True
    )

    # Report expansion
    print()
    hr()
    print(BOLD(f"  {'Section':<16} {'Plaintext':>10}  {'Ciphertext':>12}  Expansion"))
    hr()
    plain_sections = build_sections(key, encrypt_proprietary=False)
    plain_map = {s.name: s for s in plain_sections}
    for sec in sections:
        if sec.encrypted:
            plain_size = len(plain_map[sec.name].payload)
            ratio = len(sec.payload) / plain_size
            print(f"  {sec.name:<16} {plain_size:>10,}  {len(sec.payload):>12,}  {ratio:.0f}x "
                  f"{DIM('(noise token expansion)')}")
        else:
            print(f"  {sec.name:<16} {len(sec.payload):>10,}  {'(unchanged)':>12}")
    hr()
    print()

    size = write_image(PROTECTED_PATH, sections)
    print(GREEN("  [OK]") + f" Written: {PROTECTED_PATH.name}  ({size:,} bytes)")
    print()
    print(DIM("  Note: NAPQES noise token expansion is intentional -- it makes"))
    print(DIM("  frequency analysis and length inference impossible."))
    pause()
    return sections


# ---------------------------------------------------------------------------
# STEP 6: Inspect protected -- proprietary sections are noise
# ---------------------------------------------------------------------------
def step_inspect_protected():
    banner("INSPECT PROTECTED -- PROPRIETARY SECTIONS ARE NOISE", step=6)

    _, _, sections = parse_image(PROTECTED_PATH.read_bytes())

    for sec in sections:
        if not sec.encrypted:
            continue
        e = shannon_entropy(sec.payload)
        print(f"  Section: {BOLD(sec.name)}")
        print(f"  Size   : {len(sec.payload):,} bytes (encrypted blob)")
        print(f"  Entropy: {entropy_bar(e)}")
        print()
        print(BOLD("  Hex dump (first 64 bytes):"))
        print(hex_dump(sec.payload, max_bytes=64))
        print()
        print(RED("  [!!] ENCRYPTED") + " -- no readable content, no code patterns,")
        print("       no algebraic structure that an attacker can exploit.")
        print()
        hr()
        print()

    print(GREEN("  [OK]") + " The HMAC-SHA256 tag at the end of each blob ensures:")
    print("       ANY modification to the encrypted blob will be detected")
    print("       by the bootloader before a single byte of code executes.")
    pause()


# ---------------------------------------------------------------------------
# STEP 7: Entropy proof + security summary
# ---------------------------------------------------------------------------
def step_proof():
    banner("ENTROPY PROOF + SECURITY PROPERTY SUMMARY", step=7)

    _, _, plain_secs   = parse_image(PLAIN_PATH.read_bytes())
    _, _, prot_secs    = parse_image(PROTECTED_PATH.read_bytes())

    plain_map = {s.name: s for s in plain_secs}
    prot_map  = {s.name: s for s in prot_secs}
    all_names = list(plain_map)

    # Table
    col = 16
    hr()
    print(BOLD(
        f"  {'Section':{col}}  "
        f"{'A enc':>5}  {'A entropy':>10}  "
        f"{'B enc':>5}  {'B entropy':>10}  "
        f"{'Delta':>6}"
    ))
    print(f"  {'A = firmware_plain.bin    B = firmware_protected.bin'}")
    hr()
    for name in all_names:
        a = plain_map.get(name)
        b = prot_map.get(name)
        ea = shannon_entropy(a.payload) if a else 0.0
        eb = shannon_entropy(b.payload) if b else 0.0
        ae = "YES" if (a and a.encrypted) else "no"
        be = "YES" if (b and b.encrypted) else "no"
        delta = eb - ea
        delta_s = f"{delta:+.2f}"
        enc_a = RED(f"{ae:>5}") if ae == "YES" else GREEN(f"{ae:>5}")
        enc_b = RED(f"{be:>5}") if be == "YES" else GREEN(f"{be:>5}")
        delta_c = RED(delta_s) if delta > 1 else DIM(delta_s)
        print(
            f"  {name:{col}}  "
            f"{enc_a}  {ea:>10.2f}  "
            f"{enc_b}  {eb:>10.2f}  "
            f"{delta_c:>6}"
        )
    hr()
    print()
    print(BOLD("  Interpretation:"))
    print(f"    {GREEN('4-6 bits/byte')} -> ASCII text, readable code")
    print(f"    {RED('~8 bits/byte')} -> NAPQES ciphertext, statistically uniform noise")
    print()
    hr()
    print()
    print(BOLD("  Security properties demonstrated:"))
    print()
    print(f"  {GREEN('[1]')} {BOLD('Confidentiality')}")
    print("      Entropy is ~8.00 b/byte -- indistinguishable from random.")
    print("      No S-box, no GF polynomial, no repeating structure to exploit.")
    print()
    print(f"  {GREEN('[2]')} {BOLD('HMAC-SHA256 authentication')}")
    print("      The bootloader verifies the HMAC tag before any plaintext byte")
    print("      is executed. Tampered blob -> tag mismatch -> halt.")
    print()
    print(f"  {GREEN('[3]')} {BOLD('Device binding (AAD = device_serial || version || section)')}")
    print(f"      Encrypted blob for serial {DEVICE_SERIAL[:6].hex().upper()}... fails the tag")
    print("      check on any other device -- preventing transplant attacks.")
    print()
    print(f"  {GREEN('[4]')} {BOLD('Downgrade protection')}")
    print(f"      AAD includes fw_version={FIRMWARE_VERSION >> 16}.{FIRMWARE_VERSION & 0xFFFF}.")
    print("      An older encrypted blob will fail the tag check on a newer device.")
    print()
    print(f"  {GREEN('[5]')} {BOLD('Nonce-reuse tolerance')}")
    print("      Even if a nonce is reused (power cycle / reset), the HMAC-SHA256")
    print("      authentication key is NOT algebraically recoverable (no GHASH")
    print("      polynomial structure). Impact is bounded to semantic-security")
    print("      loss for the two affected messages only.")
    print()
    hr()
    print()
    print(BOLD("  Output files:"))
    print(f"    Plaintext   : {PLAIN_PATH}")
    print(f"    Protected   : {PROTECTED_PATH}")
    print()
    print(BOLD("  To flash the protected firmware to an ESP32:"))
    print(f"    {DIM('esptool.py --port <PORT> --baud 921600 write_flash 0x0 ' + str(PROTECTED_PATH))}")
    print()
    hr("=")
    print()
    print(BOLD("  Demo complete."))
    print()
    pause("  Press Enter to exit.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    step_welcome()
    step_trade_secret()
    key = step_key()
    step_build_plain(key)
    step_inspect_plain()
    prot_sections = step_encrypt(key)
    step_inspect_protected()
    step_proof()

    clear()
    print()
    print(BOLD("  EPINeon Drone Firmware Protection -- Demo finished."))
    print()


if __name__ == "__main__":
    main()
