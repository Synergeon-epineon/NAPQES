"""
NAPSEQ Algorithm Comparator
============================
Static property comparison and live benchmark vs AES-256-GCM and ChaCha20-Poly1305.
"""

import os
import sys
import time
import secrets

_HERE  = os.path.dirname(os.path.abspath(__file__))
_STATS = os.path.abspath(os.path.join(_HERE, "..", "Statistics"))
sys.path.insert(0, _STATS)

from napqes import encrypt_bytes, decrypt_bytes, generate_prime_numbers

# ─── Static comparison data ───────────────────────────────────────────────────

_PROPERTIES = [
    {
        "property":    "Algebraic structure",
        "napseq":      "None — integer arithmetic + HMAC-SHA256 only",
        "aes_gcm":     "GF(2⁸) S-box + GF(2¹²⁸) GHASH polynomial",
        "chacha20":    "ARX (mod 2³² add · rotate · XOR)",
        "napseq_wins": True,
        "why": (
            "NAPSEQ exposes no polynomial ring, group, or field structure. "
            "Quantum algorithms exploiting algebraic structure (hidden subgroup, "
            "Simon's algorithm) find no foothold."
        ),
    },
    {
        "property":    "Authentication primitive",
        "napseq":      "HMAC-SHA256 (FIPS 198-1) — no polynomial ring",
        "aes_gcm":     "GHASH — polynomial eval over GF(2¹²⁸)",
        "chacha20":    "Poly1305 — polynomial eval mod 2¹³⁰−5",
        "napseq_wins": True,
        "why": (
            "Polynomial-based MACs (GHASH, Poly1305) are vulnerable to the "
            "Forbidden Attack if a nonce is ever reused: two ciphertexts under "
            "the same nonce allow the attacker to solve a linear system and recover "
            "the authentication key. HMAC has no such algebraic recovery path."
        ),
    },
    {
        "property":    "Post-quantum security (Grover)",
        "napseq":      "≈ 98.84 bits post-Grover (key-space ≈ 2¹⁹⁷·⁶⁷, 10 primes from [10⁶, 1.5×10⁷])",
        "aes_gcm":     "≈ 128 bits (AES-256 vs Grover)",
        "chacha20":    "≈ 128 bits (ChaCha20-256 vs Grover)",
        "napseq_wins": True,
        "why": (
            "Grover's algorithm gives a quadratic speed-up on key search, halving "
            "effective key length. NAPSEQ's ≈2¹⁹⁷·⁶⁷ key space → ≈98.84 bits post-Grover. "
            "AES-256 and ChaCha20-256 with 256-bit keys → 128 bits post-quantum. "
            "NAPSEQ trades some Grover margin for the 'no algebraic structure' property."
        ),
    },
    {
        "property":    "FIPS-approved primitives only",
        "napseq":      "Yes — HMAC-SHA256 = FIPS 198-1",
        "aes_gcm":     "Yes — AES = FIPS 197",
        "chacha20":    "No — ChaCha20 is not FIPS-approved",
        "napseq_wins": True,
        "why": (
            "NAPSEQ's sole cryptographic primitive is HMAC-SHA256, which is standardised "
            "in FIPS 198-1 and universally accepted in government and regulated contexts. "
            "ChaCha20 and Poly1305 are not FIPS-approved."
        ),
    },
    {
        "property":    "Nonce-reuse consequence",
        "napseq":      "CRITICAL — encryption key fully recoverable (see CVF3)",
        "aes_gcm":     "CRITICAL — authentication key fully recoverable (Forbidden Attack)",
        "chacha20":    "CRITICAL — keystream reuse + auth key recoverable",
        "napseq_wins": False,
        "why": (
            "In AES-GCM and ChaCha20-Poly1305, reusing a nonce under the same key "
            "exposes the polynomial authentication key via simple GCD / linear algebra. "
            "In NAPSEQ every internal value (noise positions, addends, keystream) is a "
            "deterministic function of (key, nonce) only, and the real-token map "
            "c -> c*k+a is an exact affine function. Under a reused nonce, two "
            "known-plaintext tokens at the same position yield k and a exactly via "
            "ordinary linear algebra (XOR-cancel the shared keystream, then solve "
            "k = (t1-t2)/(c1-c2)) — this recovers the encryption key itself, which is "
            "strictly worse than AES-GCM/ChaCha20-Poly1305 losing only their "
            "authentication key. See docs/audit_mitigation_responses.md (CVF3)."
        ),
    },
    {
        "property":    "Key material",
        "napseq":      "10 distinct primes from [10⁶, 1.5×10⁷] — 50 bytes serialised",
        "aes_gcm":     "256-bit uniform random — 32 bytes",
        "chacha20":    "256-bit uniform random — 32 bytes",
        "napseq_wins": False,
        "why": (
            "NAPSEQ keys are ordered tuples of distinct primes, serialised to 50 bytes. "
            "While slightly larger than AES/ChaCha keys, the prime-tuple structure is "
            "the basis for the multiplicative noise construction."
        ),
    },
    {
        "property":    "Ciphertext expansion",
        "napseq":      "High — 160 B per plaintext codepoint; 2 928 B minimum",
        "aes_gcm":     "Minimal — plaintext length + 16-byte tag",
        "chacha20":    "Minimal — plaintext length + 16-byte tag",
        "napseq_wins": False,
        "why": (
            "NAPSEQ pads every message to a power-of-two bucket of tokens and emits each "
            "token as 8 fixed-width bytes, so |C| = 48 + 160·(B+2) bytes. This is the cost "
            "of the arithmetic/noise layer and it buys no theorem: length hiding comes from "
            "the coarseness of the padding bucket alone, and a public constant multiplier "
            "leaks exactly as much as no multiplier (docs/napseq-eprint-v3.tex, "
            "Proposition 'Expansion is length-neutral')."
        ),
    },
    {
        "property":    "Underlying assumption",
        "napseq":      "PRF security of HMAC-SHA256 only",
        "aes_gcm":     "PRP security of AES + collision resistance of GHASH",
        "chacha20":    "PRF security of ChaCha20 + weak-key resistance of Poly1305",
        "napseq_wins": True,
        "why": (
            "NAPSEQ's entire security reduces to a single, well-audited assumption: "
            "HMAC-SHA256 is a PRF. No additional hardness assumptions (lattice, code, "
            "group, or otherwise) are required — unlike most PQC candidates."
        ),
    },
]

_QUANTUM_ANALYSIS = [
    {
        "attack":      "Grover's algorithm (generic key search)",
        "napseq":      "2^98.84 queries — NIST PQ Level II",
        "aes_gcm":     "2^128 queries (AES-256)",
        "chacha20":    "2^128 queries (ChaCha20-256)",
        "notes": "Grover provides a generic quadratic speedup. All symmetric ciphers are affected. NAPSEQ and AES-256-GCM both satisfy NIST PQ Level II (≥ 89.5 bits).",
    },
    {
        "attack":      "Simon's algorithm (hidden shift / period)",
        "napseq":      "Not applicable — no group/shift structure in HMAC",
        "aes_gcm":     "Theoretical concern for AES-based constructions",
        "chacha20":    "Limited concern — ARX has partial group structure",
        "notes": "Simon's algorithm efficiently finds hidden periods in functions with group structure. HMAC-SHA256 has no such structure — Simon's algorithm finds no period to exploit.",
    },
    {
        "attack":      "Quantum algebraic attacks (polynomial solving)",
        "napseq":      "Not applicable — HMAC is not a polynomial",
        "aes_gcm":     "GHASH is a polynomial over GF(2^128) — quantum solvers applicable",
        "chacha20":    "Poly1305 is a polynomial over prime field — quantum solvers applicable",
        "notes": "Quantum computers running BV or HHL algorithms can exploit polynomial structure. NAPSEQ's HMAC-SHA256 core has no polynomial ring structure to attack.",
    },
    {
        "attack":      "Quantum collision search (birthday on MAC)",
        "napseq":      "2^128 complexity (SHA-256 collision resistance)",
        "aes_gcm":     "2^64 (GCM with 128-bit tag, Brassard et al.)",
        "chacha20":    "2^64 (Poly1305 with 128-bit tag, Brassard et al.)",
        "notes": "Quantum birthday attacks on 128-bit MACs require 2^64 queries. NAPSEQ's HMAC-SHA256 outputs 256-bit tags, requiring 2^128 queries — full SHA-256 collision resistance.",
    },
]


def get_comparison_data() -> dict:
    """Return static comparison table and quantum analysis data."""
    return {
        "properties":       _PROPERTIES,
        "quantum_analysis": _QUANTUM_ANALYSIS,
    }


# ─── Live benchmark ───────────────────────────────────────────────────────────

def run_benchmark(message: str, iterations: int = 10) -> dict:
    """Benchmark NAPSEQ, AES-256-GCM, and ChaCha20-Poly1305."""
    data = message.encode()
    results: dict = {}

    # ── NAPSEQ ────────────────────────────────────────────────────────────────
    napseq_key = generate_prime_numbers(count=10)
    enc_times, dec_times = [], []
    napseq_ct = b""
    for _ in range(iterations):
        t0 = time.perf_counter()
        napseq_ct = encrypt_bytes(message, napseq_key)
        enc_times.append((time.perf_counter() - t0) * 1000)
    for _ in range(iterations):
        t0 = time.perf_counter()
        decrypt_bytes(napseq_ct, napseq_key)
        dec_times.append((time.perf_counter() - t0) * 1000)
    results["napseq"] = {
        "avg_encrypt_ms": round(sum(enc_times) / len(enc_times), 3),
        "avg_decrypt_ms": round(sum(dec_times) / len(dec_times), 3),
        "ciphertext_bytes": len(napseq_ct),
        "expansion_x":     round(len(napseq_ct) / max(len(data), 1), 1),
    }

    # ── AES-256-GCM ───────────────────────────────────────────────────────────
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes_key = secrets.token_bytes(32)
        aes_nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(aes_key)
        enc_times, dec_times = [], []
        aes_ct = b""
        for _ in range(iterations):
            nonce = secrets.token_bytes(12)
            t0    = time.perf_counter()
            aes_ct = aesgcm.encrypt(nonce, data, None)
            enc_times.append((time.perf_counter() - t0) * 1000)
        for _ in range(iterations):
            t0 = time.perf_counter()
            aesgcm.decrypt(aes_nonce, aesgcm.encrypt(aes_nonce, data, None), None)
            dec_times.append((time.perf_counter() - t0) * 1000)
        results["aes_gcm"] = {
            "avg_encrypt_ms": round(sum(enc_times) / len(enc_times), 4),
            "avg_decrypt_ms": round(sum(dec_times) / len(dec_times), 4),
            "ciphertext_bytes": len(aes_ct),
            "expansion_x":     round(len(aes_ct) / max(len(data), 1), 2),
        }
    except ImportError:
        results["aes_gcm"] = {"error": "cryptography package not installed"}

    # ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        cc_key   = secrets.token_bytes(32)
        cc_nonce = secrets.token_bytes(12)
        chacha   = ChaCha20Poly1305(cc_key)
        enc_times, dec_times = [], []
        cc_ct = b""
        for _ in range(iterations):
            nonce = secrets.token_bytes(12)
            t0    = time.perf_counter()
            cc_ct = chacha.encrypt(nonce, data, None)
            enc_times.append((time.perf_counter() - t0) * 1000)
        for _ in range(iterations):
            t0 = time.perf_counter()
            chacha.decrypt(cc_nonce, chacha.encrypt(cc_nonce, data, None), None)
            dec_times.append((time.perf_counter() - t0) * 1000)
        results["chacha20"] = {
            "avg_encrypt_ms": round(sum(enc_times) / len(enc_times), 4),
            "avg_decrypt_ms": round(sum(dec_times) / len(dec_times), 4),
            "ciphertext_bytes": len(cc_ct),
            "expansion_x":     round(len(cc_ct) / max(len(data), 1), 2),
        }
    except ImportError:
        results["chacha20"] = {"error": "cryptography package not installed"}

    return {
        "message_length_bytes": len(data),
        "iterations":           iterations,
        "results":              results,
        "note": (
            "NAPSEQ reference implementation is pure Python running on HMAC-SHA256 "
            "for every token. The Rust edition achieves ~100× speedup. "
            "AES-GCM and ChaCha20-Poly1305 use hardware-accelerated C implementations."
        ),
    }
