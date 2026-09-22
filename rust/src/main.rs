// CVF-17: demo binary still exercises the v7 legacy encrypt_str/decrypt_str
// pair. The deprecated encryptor is intentional here — the demo is meant to
// exercise the surface consumers are being nudged away from — but the module
// suppresses the deprecation warning to keep the build clean.
#![allow(deprecated)]

use napqes::{
    decrypt_str, encrypt_str, generate_prime_numbers, DEFAULT_KEY_COUNT, MAX_KEY_PRIME,
    MIN_KEY_PRIME,
};

fn main() {
    let key = generate_prime_numbers(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
    println!("key: {:?}", key);

    let msg = "Hello from the Rust port of napqes!";
    let ct = encrypt_str(msg, &key, b"").expect("encrypt failed");
    println!("\nplaintext : {}", msg);
    println!("ciphertext: {}", ct);

    let pt = decrypt_str(&ct, &key, b"").expect("decrypt failed");
    println!("decrypted : {}", pt);
    assert_eq!(pt, msg);
    println!("\nround-trip OK");
}
