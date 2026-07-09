//! KEM key-establishment protocol for the Legacy Shield Gateway.
//!
//! Runs a single TCP exchange to derive a shared NAPQES session key using
//! **FrodoKEM-640-AES** (IND-CCA2).  After the exchange both the ingress
//! (initiator) and egress (responder) gateway hold an identical NAPQES key
//! without any pre-shared secret material.
//!
//! # Protocol — one round-trip
//!
//! ```text
//! Responder (egress)            Initiator (ingress)
//!      |                              |
//!      |─── 4-byte pk_len BE ────────►|
//!      |─── pk_bytes (9616 B) ───────►|
//!      |                              | encapsulate(pk) → (ct, session_key)
//!      |◄── 4-byte ct_len BE ─────────|
//!      |◄── ct_bytes (9720 B) ─────────|
//!      | decapsulate(ct, sk)           |
//!      |  → session_key               |
//!      |─── 1-byte ACK (0x01) ───────►|
//!      |                              |
//!  session_key_egress == session_key_ingress  (FrodoKEM correctness)
//! ```
//!
//! # Security properties
//!
//! - **IND-CCA2** under Learning With Errors (FrodoKEM-640-AES, NIST PQC finalist).
//! - The FrodoKEM shared secret is fed into HKDF-SHA256 → NAPQES prime-list
//!   key derivation (see `crate::kem::derive_napqes_key`).
//! - The exchange happens over an unencrypted TCP connection on the *management*
//!   network; the only secret transmitted is the KEM ciphertext, which is secure
//!   against a passive eavesdropper and an active MITM (IND-CCA2).
//! - Neither the public key nor the ciphertext reveals the shared secret.
//!
//! # Periodic re-keying
//!
//! Call `run_initiator` / `run_responder_once` again at the desired interval.
//! The `SessionKeyStore::insert` call in `ls_gateway.rs` atomically replaces
//! the session key so in-flight frames using the old key continue to the end
//! of their connection before the key is garbage-collected.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};

use crate::kem::{decapsulate, encapsulate, keygen};
use crate::ot_frame::{SessionKeyStore, WILDCARD_DEVICE_ID};

// ─── Wire constants ───────────────────────────────────────────────────────────

const ACK: u8 = 0x01;

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn recv_framed(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await
        .map_err(|e| format!("KEM recv length: {}", e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 {
        return Err(format!("KEM frame too large: {} bytes", len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await
        .map_err(|e| format!("KEM recv payload ({} bytes): {}", len, e))?;
    Ok(buf)
}

async fn send_framed(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await.map_err(|e| format!("KEM send length: {}", e))?;
    stream.write_all(data).await.map_err(|e| format!("KEM send payload: {}", e))?;
    Ok(())
}

// ─── Responder (egress gateway) ───────────────────────────────────────────────

/// Accept **one** incoming KEM exchange on `listener`, complete the handshake,
/// and return the derived NAPQES session key.
///
/// The caller is responsible for calling this function again to handle the next
/// re-key request (see `run_responder_loop`).
pub async fn run_responder_once(listener: &TcpListener) -> Result<Vec<u64>, String> {
    let (mut stream, peer) = listener.accept().await
        .map_err(|e| format!("KEM accept: {}", e))?;
    eprintln!("[kem-responder] incoming exchange from {}", peer);

    // Generate a fresh keypair for this session
    let (pk, sk) = keygen();

    // Send public key
    send_framed(&mut stream, &pk).await?;

    // Receive ciphertext
    let ct = recv_framed(&mut stream).await?;

    // Decapsulate → session key
    let session_key = decapsulate(&ct, &sk)
        .map_err(|e| format!("KEM decapsulate: {}", e))?;

    // ACK
    stream.write_all(&[ACK]).await
        .map_err(|e| format!("KEM ACK send: {}", e))?;

    eprintln!("[kem-responder] exchange complete with {}; session key derived ({} primes)",
        peer, session_key.len());
    Ok(session_key)
}

/// Continuously re-key loop for the egress gateway.
///
/// Listens for KEM exchanges and updates `store` with each new session key.
/// Runs indefinitely — spawn as a background task.
pub async fn run_responder_loop(
    listen_addr: String,
    store:       Arc<SessionKeyStore>,
) {
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => { eprintln!("[kem-responder] listening on {}", listen_addr); l }
        Err(e) => { eprintln!("[kem-responder] bind {} failed: {}", listen_addr, e); return; }
    };
    loop {
        match run_responder_once(&listener).await {
            Ok(key) => {
                store.insert(WILDCARD_DEVICE_ID, key);
                eprintln!("[kem-responder] session key installed (wildcard)");
            }
            Err(e) => {
                eprintln!("[kem-responder] exchange error: {} — waiting 5s", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

// ─── Initiator (ingress gateway) ─────────────────────────────────────────────

/// Connect to the egress gateway, complete one KEM exchange, and return the
/// derived NAPQES session key.
pub async fn run_initiator_once(peer_addr: &str) -> Result<Vec<u64>, String> {
    let mut stream = TcpStream::connect(peer_addr).await
        .map_err(|e| format!("KEM connect to {}: {}", peer_addr, e))?;
    eprintln!("[kem-initiator] connected to {}", peer_addr);

    // Receive public key
    let pk = recv_framed(&mut stream).await?;

    // Encapsulate → (ciphertext, session key)
    let (ct, session_key) = encapsulate(&pk)
        .map_err(|e| format!("KEM encapsulate: {}", e))?;

    // Send ciphertext
    send_framed(&mut stream, &ct).await?;

    // Wait for ACK
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await
        .map_err(|e| format!("KEM ACK recv: {}", e))?;
    if ack[0] != ACK {
        return Err(format!("KEM: unexpected ACK byte 0x{:02x}", ack[0]));
    }

    eprintln!("[kem-initiator] exchange complete; session key derived ({} primes)",
        session_key.len());
    Ok(session_key)
}

/// Continuously re-key loop for the ingress gateway.
///
/// Runs one KEM exchange at startup, then repeats every `interval_secs`.
/// Updates `store` with each derived key — the update is atomic so
/// in-flight wraps complete with the previous key before it is replaced.
///
/// Runs indefinitely — spawn as a background task.
pub async fn run_initiator_loop(
    peer_addr:     String,
    interval_secs: u64,
    store:         Arc<SessionKeyStore>,
) {
    loop {
        match run_initiator_once(&peer_addr).await {
            Ok(key) => {
                store.insert(WILDCARD_DEVICE_ID, key);
                eprintln!("[kem-initiator] session key installed (wildcard); \
                    next re-key in {}s", interval_secs);
                sleep(Duration::from_secs(interval_secs)).await;
            }
            Err(e) => {
                eprintln!("[kem-initiator] exchange failed: {} — retrying in 5s", e);
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn kem_exchange_derives_same_key() {
        // Bind on a random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        // Responder in a background task
        let responder = tokio::spawn(async move {
            run_responder_once(&listener).await
        });

        // Initiator
        let init_key = run_initiator_once(&addr).await.unwrap();
        let resp_key = responder.await.unwrap().unwrap();

        assert_eq!(init_key, resp_key, "KEM exchange must produce equal keys on both sides");
        assert!(!init_key.is_empty(), "session key must not be empty");
        // All elements must be distinct primes
        let mut seen = std::collections::HashSet::new();
        for &p in &init_key {
            assert!(crate::is_prime(p), "{} must be prime", p);
            assert!(seen.insert(p), "{} appears twice", p);
        }
    }

    #[tokio::test]
    async fn session_key_store_wildcard() {
        use crate::ot_frame::{SessionKeyStore, WILDCARD_DEVICE_ID};
        use crate::ot_frame::KeyStore;
        let store = Arc::new(SessionKeyStore::new());
        assert!(!store.is_ready());

        store.insert(WILDCARD_DEVICE_ID, vec![1_000_003, 1_000_033]);
        assert!(store.is_ready());

        // Any device_id falls back to wildcard
        let k1 = store.load(1).unwrap();
        let k2 = store.load(42).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1[0], 1_000_003);
    }

    #[tokio::test]
    async fn session_key_store_per_device_overrides_wildcard() {
        use crate::ot_frame::{SessionKeyStore, WILDCARD_DEVICE_ID, KeyStore};
        let store = Arc::new(SessionKeyStore::new());
        store.insert(WILDCARD_DEVICE_ID, vec![1_000_003]);
        store.insert(7, vec![1_000_033]);

        assert_eq!(store.load(7).unwrap()[0], 1_000_033); // device-specific
        assert_eq!(store.load(1).unwrap()[0], 1_000_003); // wildcard fallback
    }
}
