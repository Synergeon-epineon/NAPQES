#!/usr/bin/env python3
"""
inspect.py -- Drone firmware image inspector.

Usage
-----
    python inspect.py <firmware.bin> [<firmware2.bin> ...]

For each firmware image, the inspector:
  * Parses the NPDRONE header and section table.
  * For each section displays:
      - Name, size, encrypted flag
      - First 64 bytes as a hex dump (16 bytes / row)
      - Shannon entropy (bits/byte)
      - For cleartext: the first 300 chars of decoded text
      - For encrypted: a clear "ENCRYPTED - unreadable" marker
  * When two images are given, prints a side-by-side entropy comparison table.
"""

import sys
import math
from pathlib import Path
from collections import Counter

# -- Path plumbing ------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "protect"))   # firmware_image.py

from firmware_image import parse_image

# -- ANSI colour codes --------------------------------------------------------
_ANSI = sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _ANSI else text

def RED(t):    return _c("31;1", t)
def GREEN(t):  return _c("32;1", t)
def YELLOW(t): return _c("33;1", t)
def BOLD(t):   return _c("1", t)
def DIM(t):    return _c("2", t)


# -- Entropy ------------------------------------------------------------------

def shannon_entropy(data):
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = Counter(data)
    total  = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# -- Hex dump -----------------------------------------------------------------

def hex_dump(data, max_bytes=64, indent="    "):
    chunk = data[:max_bytes]
    lines = []
    for i in range(0, len(chunk), 16):
        row  = chunk[i : i + 16]
        hex_ = " ".join(f"{b:02x}" for b in row)
        asc  = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{indent}{i:04x}  {hex_:<47}  |{asc}|")
    if len(data) > max_bytes:
        lines.append(f"{indent}... ({len(data) - max_bytes} more bytes)")
    return "\n".join(lines)


# -- Entropy bar --------------------------------------------------------------

def entropy_bar(e, width=30):
    filled = round(e / 8.0 * width)
    bar    = "#" * filled + "." * (width - filled)
    label  = f"{e:.2f} bits/byte"
    if e > 7.5:
        return RED(bar) + f" {label}"
    elif e > 6.0:
        return YELLOW(bar) + f" {label}"
    else:
        return GREEN(bar) + f" {label}"


# -- Section inspector --------------------------------------------------------

def inspect_section(sec, verbose=True):
    entropy = shannon_entropy(sec.payload)
    result  = {"name": sec.name, "size": len(sec.payload),
                "encrypted": sec.encrypted, "entropy": entropy}

    if not verbose:
        return result

    enc_marker = RED(" [ENCRYPTED]") if sec.encrypted else GREEN(" [CLEARTEXT]")
    print(f"\n  {BOLD(sec.name)}{enc_marker}")
    print(f"    Size    : {len(sec.payload):,} bytes")
    print(f"    Entropy : {entropy_bar(entropy)}")
    print()
    print(f"    Hex dump (first 64 bytes):")
    print(hex_dump(sec.payload, max_bytes=64))

    if sec.encrypted:
        print()
        print(f"    {RED('[!!] ENCRYPTED -- section content is unreadable without the NAPQES key.')}")
        print(f"    {DIM('     No readable strings, no code patterns, no algebraic structure.')}")
    else:
        print()
        print(f"    {GREEN('[OK] CLEARTEXT -- decoded content (first 300 chars):')}")
        try:
            text = sec.payload.decode("utf-8", errors="replace")
        except Exception:
            text = "(binary)"
        preview = text[:300].replace("\r", "")
        pipe = DIM("|")
        for line in preview.split("\n")[:12]:
            print(f"    {pipe} {line}")
        if len(text) > 300 or text.count("\n") > 12:
            print(f"    {pipe} ...")

    return result


# -- Image inspector ----------------------------------------------------------

def inspect_image(path, verbose=True):
    data = path.read_bytes()
    try:
        device_serial, fw_version, sections = parse_image(data)
    except ValueError as e:
        print(RED(f"  ERROR: {e}"))
        return []

    if verbose:
        print(BOLD(f"\n{'='*60}"))
        print(BOLD(f"  Image: {path.name}  ({len(data):,} bytes)"))
        print(f"  Device serial   : {device_serial.hex().upper()}")
        print(f"  Firmware version: {fw_version >> 16}.{fw_version & 0xFFFF}")
        print(f"  Sections        : {len(sections)}")
        print(BOLD(f"{'='*60}"))

    results = []
    for sec in sections:
        results.append(inspect_section(sec, verbose=verbose))

    return results


# -- Comparison table ---------------------------------------------------------

def print_comparison(path_a, path_b):
    print(BOLD(f"\n{'='*60}"))
    print(BOLD(f"  Side-by-side entropy comparison"))
    print(BOLD(f"{'='*60}"))
    print(f"  A: {path_a.name}")
    print(f"  B: {path_b.name}\n")

    res_a = {r["name"]: r for r in inspect_image(path_a, verbose=False)}
    res_b = {r["name"]: r for r in inspect_image(path_b, verbose=False)}

    all_names = list(dict.fromkeys(list(res_a) + list(res_b)))
    col = 18

    header = (
        f"  {'Section':{col}}"
        f" {'A enc':>6} {'A entropy':>12}"
        f" {'B enc':>6} {'B entropy':>12}"
        f" {'Delta':>8}"
    )
    print(BOLD(header))
    print("  " + "-" * (len(header) - 2))

    for name in all_names:
        a = res_a.get(name)
        b = res_b.get(name)
        ea = a["entropy"] if a else 0.0
        eb = b["entropy"] if b else 0.0
        ae = ("YES" if a and a["encrypted"] else "no") if a else "--"
        be = ("YES" if b and b["encrypted"] else "no") if b else "--"
        delta = eb - ea
        delta_str = f"{delta:+.2f}"

        enc_a = RED(f"{ae:>6}") if ae == "YES" else GREEN(f"{ae:>6}")
        enc_b = RED(f"{be:>6}") if be == "YES" else GREEN(f"{be:>6}")
        delta_col = RED(delta_str) if delta > 1 else DIM(delta_str)

        print(
            f"  {name:{col}}"
            f" {enc_a} {ea:>12.2f}"
            f" {enc_b} {eb:>12.2f}"
            f" {delta_col:>8}"
        )

    print()
    print(BOLD("  Interpretation:"))
    print("    Entropy ~4-6 bits/byte  -> ASCII text / source code (readable)")
    print("    Entropy ~7.8-8.0 bits/byte -> NAPQES ciphertext (uniform noise)")
    print()


# -- Entry point --------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python inspect.py <firmware.bin> [<firmware2.bin>]")
        sys.exit(1)

    paths = [Path(p) for p in sys.argv[1:]]

    for p in paths:
        if not p.exists():
            print(RED(f"File not found: {p}"))
            sys.exit(1)

    if len(paths) == 1:
        inspect_image(paths[0], verbose=True)
    elif len(paths) == 2:
        inspect_image(paths[0], verbose=True)
        inspect_image(paths[1], verbose=True)
        print_comparison(paths[0], paths[1])
    else:
        for p in paths:
            inspect_image(p, verbose=True)


if __name__ == "__main__":
    main()
