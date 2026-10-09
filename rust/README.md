# napqes (Rust)

Rust implementation of NAPQES, the paper-specified AEAD scheme
(EPINeon NAPQES v4 — see `docs/napseq-eprint-v3.tex`; the filename lags the
version tag one revision).

## Build / run

```sh
cargo build --release
cargo test
```

## API — v8 (normative, recommended)

The v8 wire format is deterministic in `(primes, sk, aad, message)`, uses a
domain-`0x0B` format subkey and a synthetic nonce (RFC 5297 SIV style), and
applies a `MAX_NOISE_RUN` cap plus a per-bucket token ceiling so ciphertext
length depends only on the padding bucket.

```rust
use napqes::{decrypt_bytes_v8_key, encrypt_bytes_v8_key, NapqesKey};

// Required under `--features fips_gate` (see "Power-on self-tests" below);
// harmless otherwise.
napqes::self_test::run_power_on_self_tests().expect("POST failed");

// Validated once at construction, wiped on drop.
let key = NapqesKey::generate().unwrap();
let ct = encrypt_bytes_v8_key("hello", &key, b"aad").unwrap();
let pt = decrypt_bytes_v8_key(&ct, &key, b"aad").unwrap();
assert_eq!(pt, "hello");
```

The bare-slice entry points take the two key components directly and
re-validate the prime tuple on every call:

```rust
use napqes::{
    generate_v8_key, encrypt_bytes_v8, decrypt_bytes_v8,
    zeroize_key, zeroize_sk,
    DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME,
};

napqes::self_test::run_power_on_self_tests().expect("POST failed");

let (mut primes, mut sk) =
    generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME).unwrap();

let ct = encrypt_bytes_v8("hello", &primes, &sk, b"aad").unwrap();
let pt = decrypt_bytes_v8(&ct, &primes, &sk, b"aad").unwrap();
assert_eq!(pt, "hello");

zeroize_key(&mut primes);
zeroize_sk(&mut sk);
```

### Wire format

```text
v8 block:    nonce(16) || masked_blob(fixed-width tokens) || tag(32)
v8 streaming:                                        (see below)
```

The ciphertext carries no format identifier — format selection is an
out-of-band API contract. A v7 ciphertext handed to `decrypt_bytes_v8`
fails the tag check like any wrong-key ciphertext, and vice versa.

## Streaming AE (v8)

```rust
use napqes::{
    generate_v8_key, encrypt_stream_ae_v8, decrypt_stream_ae_v8,
    StreamV8Encryptor,
    DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME,
};

napqes::self_test::run_power_on_self_tests().expect("POST failed");

let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME).unwrap();

// All-at-once
let ct = encrypt_stream_ae_v8("hello, streaming!", &primes, &sk, b"", 128).unwrap();
let pt = decrypt_stream_ae_v8(&ct, &primes, &sk, b"").unwrap();

// Chunk-at-a-time
let (mut enc, header) = StreamV8Encryptor::new(&primes, &sk, b"", 128).unwrap();
let mut buf: Vec<u8> = header;
for c in "chunk-by-chunk".chars() {
    if let Some(frame) = enc.push(c).unwrap() { buf.extend_from_slice(&frame); }
}
buf.extend_from_slice(&enc.finish().unwrap());
```

**Streaming caveat.** v8 streaming is NOT misuse-resistant — the 16-byte
per-stream nonce is CSPRNG-drawn, not SIV-derived. Nonce reuse under the
same `sk` is a CVF-3-class hazard. See `docs/CAVEATS.md` CAV-005. For
messages that fit in memory, prefer the SIV-protected block API
(`encrypt_bytes_v8` / `decrypt_bytes_v8`).

## Power-on self-tests (FIPS 140-3)

`napqes::self_test::run_power_on_self_tests()` runs the SP 800-140B §4.9.1
KATs (v7 and v8) and latches the outcome process-wide. Building with
`--features fips_gate` makes every public v8 encrypt/decrypt entry point
(block, streaming, `NapqesKey` variants) refuse to run
(`module not operational`) until that call has returned `Ok(())`; a failed
POST keeps the module in the error state. Without the feature the outcome
is still latched but not enforced. The gate covers v8 encryption and
decryption only — key generation, the v7 legacy decryptors, `kem`,
`kem_exchange`, `ot_frame`, `protocols` and `vale` are outside it.

## Public surface

**Recommended (v8):**
`NapqesKey` with `encrypt_bytes_v8_key`, `decrypt_bytes_v8_key`,
`encrypt_bytes_v8_with_profile_key` (validates once, wipes on drop);
`encrypt_bytes_v8`, `encrypt_bytes_v8_with_profile`, `decrypt_bytes_v8`,
`encrypt_stream_ae_v8`, `decrypt_stream_ae_v8`, `StreamV8Encryptor`,
`generate_v8_key`, `zeroize_key`, `zeroize_sk`.

**Constants:** `NONCE_SIZE`, `TAG_SIZE`, `SK_SIZE`, `MIN_KEY_PRIME`,
`MAX_KEY_PRIME`, `DEFAULT_KEY_COUNT`, `MAX_NOISE_RUN`, `FORMAT_BLOCK_V8`,
`FORMAT_STREAM_AE_V8`, `PAD_MIN_EXP`, `PAD_MAX_EXP`,
`STREAM_AE_V8_DEFAULT_FRAME`, `STREAM_AE_V8_MAX_FRAME`.

**Padding profile:** `PadProfile` (Bucket / Coarse / Frame).

**Modules:** `self_test` (FIPS 140-3 SP 800-140B §4.9.1 power-on tests),
`kem`, `kem_exchange`, `ot_frame`, `protocols`, `vale`.

**Deprecated (v7 legacy — kept only for archived ciphertexts):**
`encrypt`, `encrypt_bytes`, `encrypt_bytes_with_nonce`, `encrypt_str`,
`encrypt_raw` — audit finding CVF-17 (length not a function of the padding
bucket alone; the length-hiding property Corollary 4.14 proves for v8 does
not hold). The corresponding decryptors (`decrypt`, `decrypt_bytes`,
`decrypt_str`, `decrypt_raw`) remain to decrypt existing v7 ciphertexts and
are not deprecated.

## Key handling

Every entry point taking `&[u64]` runs `validate_key` at its head
(CVF-15/CVF-16). Rejected: empty tuples, composite elements, elements
outside `[MIN_KEY_PRIME, MAX_KEY_PRIME]`, duplicates. Key ordering is a
security parameter — `[k0, k1]` and `[k1, k0]` are distinct keys.

## Specification and caveats

* Paper: EPINeon NAPQES v4 (`docs/napseq-eprint-v3.tex`; will be renamed
  to `napseq-eprint-v4.tex` in the next revision).
* Known caveats: `docs/CAVEATS.md`.
* Wire format details: `SPEC.md`.
