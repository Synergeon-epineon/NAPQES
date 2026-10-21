// CVF-V5-4: the demo uses the normative v8 format; the v7 encryptors are
// compiled only with the `legacy-v7` feature.
use base64::{engine::general_purpose::STANDARD, Engine};
use napqes::{decrypt_bytes_v8_key, encrypt_bytes_v8_key, NapqesKey};

fn main() {
    napqes::self_test::run_power_on_self_tests().expect("power-on self-tests failed");
    let key = NapqesKey::generate().expect("key generation failed");
    println!("key: {:?}", key);

    let msg = "Hello from the Rust port of napqes!";
    let ct = encrypt_bytes_v8_key(msg, &key, b"").expect("encrypt failed");
    println!("\nplaintext : {}", msg);
    println!("ciphertext: {} bytes, base64 {}...", ct.len(), &STANDARD.encode(&ct)[..48]);

    let pt = decrypt_bytes_v8_key(&ct, &key, b"").expect("decrypt failed");
    println!("decrypted : {}", pt);
    assert_eq!(pt, msg);
    println!("\nround-trip OK");
}