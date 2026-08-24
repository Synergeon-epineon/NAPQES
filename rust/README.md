# napqes (Rust)

Rust port of the v6 authenticated EpiCypher in `../napqes.py`.

## Build / run

```sh
cargo run --release
cargo test
```

## API

```rust
use napqes::{encrypt_str, decrypt_str, generate_prime_numbers};

let key = generate_prime_numbers(10, MIN_KEY_PRIME, MAX_KEY_PRIME);
let ct  = encrypt_str("hello", &key, b"");
let pt  = decrypt_str(&ct, &key, b"").unwrap();
```

Wire format (interoperable with Python):

```
nonce(16) || varint_blob || hmac_sha256_tag(32)
```

String form is the base64 encoding of the above.

## Scope

Implements: prime generation, `encrypt` / `decrypt`, `encrypt_bytes` /
`decrypt_bytes`, `encrypt_str` / `decrypt_str`, all HMAC derivations
(positions, addends, noise chars, noise probability, auth tag) — all
byte-compatible with the Python reference.

Out of scope: streaming API, legacy v2/v3/v5 ciphertexts.
