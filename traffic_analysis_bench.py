#!/usr/bin/env python3
"""Length-leakage benchmark: what a passive length observer learns.

Measures the quantity bounded by Corollary ``length-leak`` of
``docs/napseq-eprint-v3.tex`` -- the mutual information between the plaintext
codepoint count and the ciphertext byte length -- for NAPQES under each padding
profile, and for AES-GCM and ChaCha20-Poly1305.

Three adversaries are evaluated against each scheme, all of them passive and
given only ``|C|``:

  * ``I(n; |C|)``   -- information-theoretic leakage in bits per message.
  * exact-length    -- probability of recovering ``n`` exactly (MAP guess).
  * two-class       -- the naval-C2 distinguisher: short command (12-20
                       codepoints) versus full mission parameters (300-500),
                       equiprobable.

The reference schemes are included because their length function is public and
deterministic, which is precisely what makes them lose: ``|C| = |M| + 16``
determines ``n``, so every metric saturates.

Usage::

    python traffic_analysis_bench.py            # table
    python traffic_analysis_bench.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import json
import math
import os
from collections import Counter, defaultdict
from typing import Callable, Iterable

import napqes

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - exercised only on a bare install
    _HAVE_CRYPTOGRAPHY = False


# ─── Length functions ────────────────────────────────────────────────────────
# Each maps a plaintext codepoint count to the resulting ciphertext byte length.
# NAPQES's is measured by actually encrypting; the AEAD baselines are measured
# too when `cryptography` is installed, and fall back to their exact published
# formula otherwise.

LengthFn = Callable[[int], int]


def napqes_length_fn(pad_profile: napqes.PadProfile) -> LengthFn:
    """Ciphertext length under NAPQES v8 with *pad_profile*, by encryption."""
    primes = napqes.generate_prime_numbers(10)
    sk = napqes.generate_v8_key()
    if isinstance(sk, tuple):          # tolerate either return shape
        sk = sk[-1]

    def length_of(n: int) -> int:
        return len(napqes.encrypt_bytes_v8("a" * n, primes, sk, b"", pad_profile))

    return length_of


def aead_length_fn(name: str) -> LengthFn:
    """Ciphertext length under a standard AEAD, by encryption where possible."""
    if not _HAVE_CRYPTOGRAPHY:
        return lambda n: n + 16        # |C| = |M| + 16, both schemes
    cipher = AESGCM(AESGCM.generate_key(256)) if name == "AES-GCM" \
        else ChaCha20Poly1305(ChaCha20Poly1305.generate_key())
    nonce_len = 12

    def length_of(n: int) -> int:
        return len(cipher.encrypt(os.urandom(nonce_len), b"a" * n, b""))

    return length_of


# ─── Metrics ─────────────────────────────────────────────────────────────────

def _entropy(counts: Iterable[int], total: int) -> float:
    h = -sum((c / total) * math.log2(c / total) for c in counts if c)
    return h + 0.0        # normalise -0.0 for display


def mutual_information(lengths: dict[int, int], weights: Counter[int]) -> float:
    """I(n; |C|) in bits, for the empirical distribution *weights* over n.

    ``|C|`` is a deterministic function of ``n``, so I(n;|C|) = H(|C|).
    """
    total = sum(weights.values())
    by_ct: Counter[int] = Counter()
    for n, w in weights.items():
        by_ct[lengths[n]] += w
    return _entropy(by_ct.values(), total)


def exact_length_accuracy(lengths: dict[int, int], weights: Counter[int]) -> float:
    """P[adversary recovers n exactly from |C|] under the MAP rule."""
    total = sum(weights.values())
    groups: dict[int, list[int]] = defaultdict(list)
    for n, w in weights.items():
        groups[lengths[n]].append(w)
    return sum(max(g) for g in groups.values()) / total


def two_class_accuracy(lengths: dict[int, int],
                       class_a: list[int], class_b: list[int]) -> float:
    """P[adversary identifies which of two equiprobable classes was sent]."""
    mass: dict[int, list[float]] = defaultdict(lambda: [0.0, 0.0])
    for idx, klass in enumerate((class_a, class_b)):
        share = 0.5 / len(klass)
        for n in klass:
            mass[lengths[n]][idx] += share
    return sum(max(pair) for pair in mass.values())


# ─── Harness ─────────────────────────────────────────────────────────────────

#: Short-command versus full-mission-parameters, the traffic-analysis scenario
#: used in the NAPQES briefing material.
NAVAL_SHORT = range(12, 21)
NAVAL_LONG = range(300, 501)


def run(max_n: int, sample: int) -> dict:
    """Measure every scheme over plaintext lengths 0..max_n.

    Lengths are probed on a grid rather than exhaustively: |C| is a step
    function of n for every scheme here, so a grid recovers the same length
    distribution at a fraction of the encryption cost.
    """
    grid = set(range(0, max_n + 1, sample))
    naval_short = list(NAVAL_SHORT)
    naval_long = list(NAVAL_LONG)[::4]
    probe = sorted(grid | set(naval_short) | set(naval_long))

    schemes: list[tuple[str, LengthFn]] = [
        ("NAPQES bucket (default)", napqes_length_fn("bucket")),
        ("NAPQES coarse(3)", napqes_length_fn(("coarse", 3))),
        ("NAPQES frame(1024)", napqes_length_fn(("frame", 1024))),
        ("AES-GCM", aead_length_fn("AES-GCM")),
        ("ChaCha20-Poly1305", aead_length_fn("ChaCha20-Poly1305")),
    ]

    baseline_bits = math.log2(len(grid))
    results = []
    for name, fn in schemes:
        try:
            lengths = {n: fn(n) for n in probe}
        except ValueError as exc:      # e.g. frame(F) with a message >= F
            results.append({"scheme": name, "error": str(exc)})
            continue
        uniform = Counter({n: 1 for n in grid})
        results.append({
            "scheme": name,
            "distinct_lengths": len({lengths[n] for n in grid}),
            "mutual_information_bits": mutual_information(lengths, uniform),
            "exact_length_accuracy": exact_length_accuracy(lengths, uniform),
            "two_class_accuracy": two_class_accuracy(
                lengths, naval_short, naval_long),
            "min_ciphertext_bytes": min(lengths.values()),
        })
    return {
        "plaintext_domain": f"0..{max_n} codepoints, every {sample}",
        "uniform_length_entropy_bits": baseline_bits,
        "results": results,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-n", type=int, default=512,
                    help="largest plaintext codepoint count to probe")
    ap.add_argument("--sample", type=int, default=8,
                    help="probe every Nth length (|C| is a step function of n)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    report = run(args.max_n, args.sample)
    if args.json:
        print(json.dumps(report, indent=2))
        return

    print(f"Plaintext domain: {report['plaintext_domain']}")
    print(f"H(n) for a uniform length prior: "
          f"{report['uniform_length_entropy_bits']:.2f} bits")
    if not _HAVE_CRYPTOGRAPHY:
        print("NOTE: `cryptography` not installed; baselines use |C| = |M| + 16.")
    print()
    header = f"{'Scheme':<26}{'|C| vals':>9}{'I(n;|C|)':>10}{'exact n':>9}{'2-class':>9}{'min |C|':>10}"
    print(header)
    print("-" * len(header))
    for row in report["results"]:
        if "error" in row:
            print(f"{row['scheme']:<26}  n/a  ({row['error']})")
            continue
        print(f"{row['scheme']:<26}"
              f"{row['distinct_lengths']:>9}"
              f"{row['mutual_information_bits']:>9.2f}b"
              f"{row['exact_length_accuracy'] * 100:>8.1f}%"
              f"{row['two_class_accuracy'] * 100:>8.1f}%"
              f"{row['min_ciphertext_bytes']:>10}")
    print()
    print("I(n;|C|) is the leakage bounded by Corollary `length-leak`; "
          "2-class is the\nnaval-C2 distinguisher, where 50% is a coin flip "
          "and 100% is total disclosure.")


if __name__ == "__main__":
    main()
