# NAPQES Cryptographic Module — Boundary Specification

**Module name:** NAPQES Cryptographic Module  
**Version:** 0.1 (Rust core, `napqes` crate v0.1.0)  
**Date:** 2026-05-28  
**Status:** DRAFT — pending CMVP lab review

---

## 1. Module Type

The NAPQES Cryptographic Module is a **multi-chip standalone software module**
(ISO/IEC 19790:2012 §4.4.2). The module is a dynamically linked library
compiled from `rust/src/lib.rs`.

| Platform | Library file |
|---|---|
| Linux | `libnapqes.so` |
| Windows | `napqes.dll` |
| macOS | `libnapqes.dylib` |
| Embedded (future) | `libnapqes.a` (static archive) |

---

## 2. Module Boundary

The cryptographic boundary is the compiled library object file. All
cryptographic operations occur within this boundary. The boundary encloses:

```
┌──────────────────────────────────────────────────────────────────┐
│                 NAPQES Cryptographic Module                       │
│   (libnapqes.so / napqes.dll / libnapqes.dylib)                  │
│                                                                  │
│  ┌──────────────────────────────────────────┐                    │
│  │  Public API (exported symbols)            │                    │
│  │  ─────────────────────────────────────── │                    │
│  │  encrypt_bytes / encrypt_str             │                    │
│  │  decrypt_bytes / decrypt_str             │                    │
│  │  encrypt_bytes_with_nonce (test only)    │                    │
│  │  generate_prime_numbers                  │                    │
│  │  is_prime                                │                    │
│  │  zeroize_key                             │                    │
│  │  run_power_on_self_tests                 │                    │
│  └──────────────────────────────────────────┘                    │
│                                                                  │
│  ┌──────────────────────────────────────────┐                    │
│  │  Internal cryptographic core             │                    │
│  │  ─────────────────────────────────────── │                    │
│  │  hmac_digest (HMAC-SHA256 via hmac crate)│                    │
│  │  key_bytes / be5 / u64_from_be8          │                    │
│  │  Domain-separated derivations:           │                    │
│  │    is_noise_pos (0x00)                   │                    │
│  │    derive_addend (0x01)                  │                    │
│  │    derive_noise_p (0x02)                 │                    │
│  │    compute_auth_tag (0x03)               │                    │
│  │    derive_noise_char (0x04)              │                    │
│  │    derive_noise_token_addend (0x05)      │                    │
│  │    pad_message / derive pad (0x06)       │                    │
│  │    varint_keystream (0x07)               │                    │
│  │  ct_eq_bytes (constant-time comparison)  │                    │
│  │  b128_encode_tokens / b128_decode_tokens │                    │
│  │  pad_message / unpad_message             │                    │
│  │  encrypt / decrypt (token layer)         │                    │
│  └──────────────────────────────────────────┘                    │
│                                                                  │
│  ┌──────────────────────────────────────────┐                    │
│  │  Self-test engine (rust/src/self_test.rs)│                    │
│  │  ─────────────────────────────────────── │                    │
│  │  run_power_on_self_tests                 │                    │
│  │  KAT encrypt / KAT decrypt / KAT auth   │                    │
│  │  Software integrity HMAC check          │                    │
│  │  CRNG continuity check                  │                    │
│  └──────────────────────────────────────────┘                    │
└──────────────────────────────────────────────────────────────────┘
                    │                        │
        ┌──────────▼──────────┐   ┌──────────▼────────────┐
        │  OS DRBG (outside   │   │  Caller application   │
        │  module boundary)   │   │  (outside boundary)   │
        │                     │   │                       │
        │  Linux: getrandom() │   │  Supplies: key, AAD,  │
        │  Win:   BCryptGen…  │   │  plaintext / cipher   │
        │  macOS: getentropy()│   │  Receives: ciphertext │
        └─────────────────────┘   │  / plaintext or error │
                                  └───────────────────────┘
```

---

## 3. Interfaces

### 3.1 Data Input Interface

Data enters the module boundary through the function parameters of the
public API functions:

| Parameter | Function(s) | Type |
|---|---|---|
| `message` (plaintext) | `encrypt_bytes`, `encrypt_str`, `encrypt_bytes_with_nonce` | `&str` |
| `key` (prime tuple) | All encrypt / decrypt functions, `zeroize_key` | `&[u64]` / `&mut [u64]` |
| `aad` (associated data) | All encrypt / decrypt functions | `&[u8]` |
| `nonce` (deterministic) | `encrypt_bytes_with_nonce` (test only) | `[u8; 16]` |
| `ciphertext` | `decrypt_bytes`, `decrypt_str` | `&[u8]` / `&str` |

### 3.2 Data Output Interface

| Output | Function(s) | Type |
|---|---|---|
| `ciphertext` (binary) | `encrypt_bytes`, `encrypt_bytes_with_nonce` | `Vec<u8>` |
| `ciphertext` (base64) | `encrypt_str` | `String` |
| `plaintext` | `decrypt_bytes`, `decrypt_str` | `Result<String, String>` |
| Generated key | `generate_prime_numbers` | `Vec<u64>` |
| Self-test result | `run_power_on_self_tests` | `Result<(), SelfTestError>` |

### 3.3 Control Input Interface

- Function call dispatch (the OS/caller's function call mechanism).
- Feature flags / crate feature gates (compile-time).

### 3.4 Status Output Interface

- Function return values (`Ok` / `Err`).
- `SelfTestError` variants indicating which self-test failed.

---

## 4. Excluded from Boundary

The following are explicitly **outside** the module boundary:

| Component | Reason |
|---|---|
| OS DRBG (`getrandom` / `BCryptGenRandom` / `getentropy`) | OS-provided service; consumed but not implemented by the module |
| `rand` crate internals | Wrapper over OS DRBG; consumed at the nonce-generation boundary |
| `hmac` and `sha2` Rust crates | Underlying cryptographic primitive libraries; CAVP validation is obtained from the provider, not re-implemented |
| Base64 encoder/decoder (`base64` crate) | Non-cryptographic encoding utility |
| Caller application code | Outside boundary; caller is responsible for key management |
| `main.rs` and `bin/sts.rs` | Driver executables; not part of the library module |
| Python reference (`napqes.py`) | Reference implementation; not the validated module |
| C port (`C/napqes.c`) | Reference port; not the validated module |

---

## 5. Operating Environment Requirements

The module operates correctly and securely when:

1. The OS DRBG is correctly seeded and operational (no DRBG failure or
   depletion). The CRNG conditional test detects catastrophic DRBG failures
   at the module level.
2. The process memory is protected from unauthorised read/write access by the
   OS memory isolation mechanisms.
3. The compiled library is loaded from a trusted filesystem path (integrity
   is verified by the module's software integrity self-test).
4. No debugger or code-injection tool is attached to the process.

---

## 6. Firmware / Software Loading

The module is loaded by the host OS dynamic linker. Module integrity is
verified at load time by `run_power_on_self_tests` (step 4 of the POST
sequence: software integrity HMAC). The reference HMAC digest is embedded
in the module at compile time by `build.rs`.

---

## 7. Algorithms and Key Sizes

| Algorithm | Standard | Key size | Purpose |
|---|---|---|---|
| HMAC-SHA256 | FIPS 198-1 / FIPS 180-4 | K×5 bytes (K ≥ 7, ≥ 35 bytes) | All keyed derivations + authentication tag |
| SHA-256 | FIPS 180-4 | N/A (used inside HMAC) | Inner hash function |

No other cryptographic algorithms are implemented inside the boundary.
