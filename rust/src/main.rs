use napqes::{
    decrypt_str, encrypt_str, generate_prime_numbers, MAX_KEY_PRIME, MIN_KEY_PRIME,
};

fn main() {
    let key = generate_prime_numbers(10, MIN_KEY_PRIME, MAX_KEY_PRIME);
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
