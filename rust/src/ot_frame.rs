//! OT framing layer — NAPQES v6 AEAD wrapper for industrial protocol PDUs.
//!
//! Every PDU is wrapped as:
//!
//! ```text
//! NAPQES_ciphertext(pdu, aad = protocol_id(1) || device_id(8 BE) || seq(8 BE))
//! ```
//!
//! The AAD binds each frame to its originating device and sequence number,
//! so cross-device replay and sequence-rollback attacks are detected and
//! rejected by the HMAC tag.
//!
//! # Wire format of the outer OT envelope
//!
//! ```text
//! [2 bytes] envelope magic  : 0x4E51 ("NQ")
//! [1 byte]  protocol_id     : ProtocolId as u8
//! [8 bytes] device_id       : u64 big-endian
//! [8 bytes] seq             : u64 big-endian
//! [4 bytes] napqes_len      : u32 big-endian, length of following NAPQES blob
//! [N bytes] napqes_blob     : output of encrypt_raw()
//! ```
//!
//! The envelope fields are NOT encrypted (they are visible to the network
//! operator for routing and SIEM event correlation), but they are bound into
//! the NAPQES AAD, so any modification of device_id, seq, or protocol_id is
//! detected by the authentication tag.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};

use crate::{decrypt_raw, encrypt_raw};

// ─── Protocol identifiers ─────────────────────────────────────────────────────

/// Industrial protocol carried inside the OT envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProtocolId {
    ModbusTcp = 0x01,
    Dnp3      = 0x02,
}

impl ProtocolId {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(ProtocolId::ModbusTcp),
            0x02 => Some(ProtocolId::Dnp3),
            _    => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolId::ModbusTcp => "MODBUS",
            ProtocolId::Dnp3      => "DNP3",
        }
    }
}

// ─── AAD ─────────────────────────────────────────────────────────────────────

/// Authenticated Additional Data bound into every NAPQES frame.
///
/// 17 bytes: `protocol_id(1) || device_id(8 BE) || seq(8 BE)`.
#[derive(Debug, Clone, Copy)]
pub struct OtAad {
    pub protocol:  ProtocolId,
    pub device_id: u64,
    pub seq:       u64,
}

impl OtAad {
    pub fn to_bytes(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[0] = self.protocol as u8;
        out[1..9].copy_from_slice(&self.device_id.to_be_bytes());
        out[9..17].copy_from_slice(&self.seq.to_be_bytes());
        out
    }
}

// ─── Envelope magic ───────────────────────────────────────────────────────────

pub const ENVELOPE_MAGIC: [u8; 2] = [0x4E, 0x51]; // "NQ"
pub const ENVELOPE_HEADER_SIZE: usize = 2 + 1 + 8 + 8 + 4; // magic+proto+device+seq+len = 23

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum FrameError {
    /// HMAC tag verification failed — frame is corrupt or tampered.
    AuthenticationFailed {
        device_id: u64,
        protocol:  ProtocolId,
        seq:       u64,
    },
    /// The received sequence number is not strictly greater than last seen.
    ReplayDetected {
        device_id: u64,
        protocol:  ProtocolId,
        seq:       u64,
        last_seen: u64,
    },
    /// The envelope header is malformed (truncated, wrong magic, etc.).
    MalformedEnvelope(String),
    /// Underlying encryption or decryption error.
    CryptoError(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::AuthenticationFailed { device_id, protocol, seq } =>
                write!(f, "AUTH_FAIL device_id=0x{:x} proto={} seq={}", device_id, protocol.as_str(), seq),
            FrameError::ReplayDetected { device_id, protocol, seq, last_seen } =>
                write!(f, "REPLAY device_id=0x{:x} proto={} seq={} last_seen={}", device_id, protocol.as_str(), seq, last_seen),
            FrameError::MalformedEnvelope(s) => write!(f, "MALFORMED_ENVELOPE {}", s),
            FrameError::CryptoError(s) => write!(f, "CRYPTO_ERROR {}", s),
        }
    }
}

// ─── Sequence counter + anti-replay ──────────────────────────────────────────

type DeviceKey = (ProtocolId, u64); // (protocol, device_id)

/// Per-device monotonic sequence counter.
///
/// On wrap: increments and returns the next value to use when sealing.
/// On receive: rejects any seq ≤ last_seen to prevent replay.
pub struct SequenceCounter {
    send_state: Mutex<HashMap<DeviceKey, u64>>,
    recv_state: Mutex<HashMap<DeviceKey, u64>>,
}

impl SequenceCounter {
    pub fn new() -> Self {
        Self {
            send_state: Mutex::new(HashMap::new()),
            recv_state: Mutex::new(HashMap::new()),
        }
    }

    /// Return the next outgoing sequence number for (protocol, device_id).
    pub fn next_seq(&self, protocol: ProtocolId, device_id: u64) -> u64 {
        let key = (protocol, device_id);
        let mut state = self.send_state.lock().unwrap();
        let seq = state.entry(key).or_insert(0);
        *seq += 1;
        *seq
    }

    /// Validate an incoming sequence number.  Returns `Ok(())` if the seq is
    /// strictly greater than the last seen value; updates the last-seen record.
    pub fn validate_recv(
        &self,
        protocol:  ProtocolId,
        device_id: u64,
        seq:       u64,
    ) -> Result<(), FrameError> {
        let key = (protocol, device_id);
        let mut state = self.recv_state.lock().unwrap();
        let last = state.entry(key).or_insert(0);
        if seq <= *last {
            return Err(FrameError::ReplayDetected {
                device_id,
                protocol,
                seq,
                last_seen: *last,
            });
        }
        *last = seq;
        Ok(())
    }
}

impl Default for SequenceCounter {
    fn default() -> Self { Self::new() }
}

// ─── Key store ───────────────────────────────────────────────────────────────

/// Map a device_id to its NAPQES key (list of primes).
pub trait KeyStore: Send + Sync {
    fn load(&self, device_id: u64) -> Result<Vec<u64>, String>;
}

/// Loads keys from a JSON file.
///
/// Expected format:
/// ```json
/// {
///   "1": [1000003, 1000033, 1000037, ...],
///   "2": [1000099, 1000117, 1000121, ...]
/// }
/// ```
/// Keys are indexed by the decimal string representation of device_id.
pub struct FileKeyStore {
    data: HashMap<u64, Vec<u64>>,
}

impl FileKeyStore {
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("key store read '{}': {}", path, e))?;
        let raw: HashMap<String, Vec<u64>> = serde_json::from_str(&content)
            .map_err(|e| format!("key store JSON parse '{}': {}", path, e))?;
        let mut data = HashMap::new();
        for (k, v) in raw {
            let id: u64 = k.parse()
                .map_err(|_| format!("key store: device id '{}' is not a u64", k))?;
            data.insert(id, v);
        }
        Ok(Self { data })
    }
}

impl KeyStore for FileKeyStore {
    fn load(&self, device_id: u64) -> Result<Vec<u64>, String> {
        self.data.get(&device_id)
            .cloned()
            .ok_or_else(|| format!("no key for device_id {}", device_id))
    }
}

// ─── Session key store (KEM-derived) ─────────────────────────────────────────

/// A thread-safe key store populated by the KEM key-establishment protocol.
///
/// Keys can be addressed per-device (`device_id`) or as a wildcard (`u64::MAX`)
/// that applies to all devices not explicitly registered.  The wildcard is the
/// typical case after a gateway-pair KEM exchange: one shared session key
/// covers all devices on the conduit.
///
/// # Key rotation
///
/// Call `insert` with the new key after a successful re-keying round.  The
/// update is immediately visible to all threads holding an `Arc<SessionKeyStore>`.
#[derive(Default)]
pub struct SessionKeyStore {
    inner: RwLock<HashMap<u64, Vec<u64>>>,
}

/// Sentinel device_id meaning "apply to all devices" (wildcard).
pub const WILDCARD_DEVICE_ID: u64 = u64::MAX;

impl SessionKeyStore {
    pub fn new() -> Self {
        Self { inner: RwLock::new(HashMap::new()) }
    }

    /// Install (or replace) the key for `device_id`.
    ///
    /// Use `WILDCARD_DEVICE_ID` to apply the key to every device not
    /// individually registered.
    pub fn insert(&self, device_id: u64, key: Vec<u64>) {
        self.inner.write().unwrap().insert(device_id, key);
    }

    /// Return `true` if at least one key (including wildcard) is loaded.
    pub fn is_ready(&self) -> bool {
        !self.inner.read().unwrap().is_empty()
    }
}

impl KeyStore for SessionKeyStore {
    fn load(&self, device_id: u64) -> Result<Vec<u64>, String> {
        let map = self.inner.read().unwrap();
        if let Some(k) = map.get(&device_id) {
            return Ok(k.clone());
        }
        map.get(&WILDCARD_DEVICE_ID)
            .cloned()
            .ok_or_else(|| format!(
                "no session key for device_id {} (KEM exchange not yet completed?)", device_id
            ))
    }
}

impl KeyStore for Arc<SessionKeyStore> {
    fn load(&self, device_id: u64) -> Result<Vec<u64>, String> {
        self.as_ref().load(device_id)
    }
}

// ─── Wrap / unwrap ────────────────────────────────────────────────────────────

/// Seal a raw PDU into an OT envelope.
///
/// Returns the full envelope bytes (header + NAPQES blob) ready to write to
/// the secure-side TCP connection.
pub fn wrap_pdu(pdu: &[u8], aad: OtAad, key: &[u64]) -> Result<Vec<u8>, FrameError> {
    let aad_bytes = aad.to_bytes();
    let napqes_blob = encrypt_raw(pdu, key, &aad_bytes)
        .map_err(|e| FrameError::CryptoError(e))?;

    let mut envelope = Vec::with_capacity(ENVELOPE_HEADER_SIZE + napqes_blob.len());
    envelope.extend_from_slice(&ENVELOPE_MAGIC);
    envelope.push(aad.protocol as u8);
    envelope.extend_from_slice(&aad.device_id.to_be_bytes());
    envelope.extend_from_slice(&aad.seq.to_be_bytes());
    envelope.extend_from_slice(&(napqes_blob.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&napqes_blob);
    Ok(envelope)
}

/// Parse the envelope header from a byte buffer.
///
/// Returns `(protocol, device_id, seq, napqes_blob_slice_start_offset)`.
pub fn parse_envelope_header(buf: &[u8]) -> Result<(ProtocolId, u64, u64, usize, usize), FrameError> {
    if buf.len() < ENVELOPE_HEADER_SIZE {
        return Err(FrameError::MalformedEnvelope(format!(
            "buffer too short: {} < {}", buf.len(), ENVELOPE_HEADER_SIZE
        )));
    }
    if buf[0..2] != ENVELOPE_MAGIC {
        return Err(FrameError::MalformedEnvelope(format!(
            "bad magic: {:02x}{:02x}", buf[0], buf[1]
        )));
    }
    let protocol = ProtocolId::from_u8(buf[2])
        .ok_or_else(|| FrameError::MalformedEnvelope(format!("unknown protocol_id 0x{:02x}", buf[2])))?;
    let device_id = u64::from_be_bytes(buf[3..11].try_into().unwrap());
    let seq       = u64::from_be_bytes(buf[11..19].try_into().unwrap());
    let blob_len  = u32::from_be_bytes(buf[19..23].try_into().unwrap()) as usize;

    if buf.len() < ENVELOPE_HEADER_SIZE + blob_len {
        return Err(FrameError::MalformedEnvelope(format!(
            "truncated blob: have {} want {}", buf.len() - ENVELOPE_HEADER_SIZE, blob_len
        )));
    }
    Ok((protocol, device_id, seq, ENVELOPE_HEADER_SIZE, blob_len))
}

/// Unseal an OT envelope.
///
/// Verifies the HMAC tag, rejects replays, and returns the decrypted PDU bytes.
pub fn unwrap_pdu(
    buf:      &[u8],
    key:      &[u64],
    counters: &SequenceCounter,
) -> Result<Vec<u8>, FrameError> {
    let (protocol, device_id, seq, blob_start, blob_len) = parse_envelope_header(buf)?;

    counters.validate_recv(protocol, device_id, seq)?;

    let napqes_blob = &buf[blob_start..blob_start + blob_len];
    let aad = OtAad { protocol, device_id, seq };
    let aad_bytes = aad.to_bytes();

    decrypt_raw(napqes_blob, key, &aad_bytes).map_err(|_| {
        FrameError::AuthenticationFailed { device_id, protocol, seq }
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u64> {
        vec![
            1_000_003, 1_000_033, 1_000_037, 1_000_039, 1_000_081,
            1_000_099, 1_000_117, 1_000_121, 1_000_133, 1_000_151,
        ]
    }

    fn make_aad(protocol: ProtocolId, device_id: u64, seq: u64) -> OtAad {
        OtAad { protocol, device_id, seq }
    }

    #[test]
    fn wrap_unwrap_modbus_roundtrip() {
        let key      = test_key();
        let counters = SequenceCounter::new();
        let pdu      = b"\x01\x03\x00\x00\x00\x0a"; // Modbus read-holding-registers
        let aad      = make_aad(ProtocolId::ModbusTcp, 1, 1);

        let envelope = wrap_pdu(pdu, aad, &key).unwrap();
        let recovered = unwrap_pdu(&envelope, &key, &counters).unwrap();
        assert_eq!(recovered, pdu.as_ref());
    }

    #[test]
    fn wrap_unwrap_dnp3_roundtrip() {
        let key      = test_key();
        let counters = SequenceCounter::new();
        // Minimal DNP3 data link layer header bytes (application payload stub)
        let pdu      = b"\x05\x64\x05\xc4\x01\x00\x03\x00\xf9\x53";
        let aad      = make_aad(ProtocolId::Dnp3, 3, 1);

        let envelope = wrap_pdu(pdu, aad, &key).unwrap();
        let recovered = unwrap_pdu(&envelope, &key, &counters).unwrap();
        assert_eq!(recovered, pdu.as_ref());
    }

    #[test]
    fn replay_rejected() {
        let key      = test_key();
        let counters = SequenceCounter::new();
        let pdu      = b"\x01\x03\x00\x00\x00\x0a";
        let aad1     = make_aad(ProtocolId::ModbusTcp, 1, 1);
        let aad2     = make_aad(ProtocolId::ModbusTcp, 1, 2);

        let env1 = wrap_pdu(pdu, aad1, &key).unwrap();
        let env2 = wrap_pdu(pdu, aad2, &key).unwrap();

        unwrap_pdu(&env2, &key, &counters).unwrap(); // seq=2 accepted first
        // seq=1 must be rejected as replay
        let result = unwrap_pdu(&env1, &key, &counters);
        assert!(matches!(result, Err(FrameError::ReplayDetected { .. })));
    }

    #[test]
    fn tampered_napqes_blob_rejected() {
        let key      = test_key();
        let counters = SequenceCounter::new();
        let pdu      = b"\x01\x03\x00\x00\x00\x0a";
        let aad      = make_aad(ProtocolId::ModbusTcp, 1, 1);

        let mut envelope = wrap_pdu(pdu, aad, &key).unwrap();
        // Flip a bit in the NAPQES blob (after the 23-byte header)
        envelope[ENVELOPE_HEADER_SIZE] ^= 0x01;

        let result = unwrap_pdu(&envelope, &key, &counters);
        assert!(matches!(result, Err(FrameError::AuthenticationFailed { .. })));
    }

    #[test]
    fn wrong_key_rejected() {
        let key1     = test_key();
        let key2     = vec![
            1_000_159, 1_000_171, 1_000_183, 1_000_187, 1_000_193,
            1_000_199, 1_000_211, 1_000_223, 1_000_231, 1_000_249,
        ];
        let counters = SequenceCounter::new();
        let pdu      = b"\x01\x03\x00\x00\x00\x0a";
        let aad      = make_aad(ProtocolId::ModbusTcp, 1, 1);

        let envelope = wrap_pdu(pdu, aad, &key1).unwrap();
        let result   = unwrap_pdu(&envelope, &key2, &counters);
        assert!(matches!(result, Err(FrameError::AuthenticationFailed { .. })));
    }

    #[test]
    fn aad_device_id_mismatch_rejected() {
        let key      = test_key();
        let counters = SequenceCounter::new();
        let pdu      = b"\x01\x03\x00\x00\x00\x0a";
        // Seal for device 1
        let aad_send = make_aad(ProtocolId::ModbusTcp, 1, 1);
        let mut envelope = wrap_pdu(pdu, aad_send, &key).unwrap();
        // Patch device_id field in envelope header to 2
        let did_bytes = 2u64.to_be_bytes();
        envelope[3..11].copy_from_slice(&did_bytes);
        // The NAPQES tag was computed over the original AAD (device_id=1),
        // so it must fail even though seq=1 hasn't been seen for device 2.
        let result = unwrap_pdu(&envelope, &key, &counters);
        assert!(matches!(result, Err(FrameError::AuthenticationFailed { .. })));
    }

    #[test]
    fn file_key_store_roundtrip() {
        // Write a temp JSON key file and load it
        let dir  = std::env::temp_dir();
        let path = dir.join("test_keys.json");
        let json = r#"{"1":[1000003,1000033,1000037,1000039,1000081,1000099,1000117,1000121,1000133,1000151]}"#;
        std::fs::write(&path, json).unwrap();
        let ks  = FileKeyStore::load_from_file(path.to_str().unwrap()).unwrap();
        let key = ks.load(1).unwrap();
        assert_eq!(key[0], 1_000_003);
    }
}
