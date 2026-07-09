//! Modbus TCP PDU extractor.
//!
//! Modbus TCP framing (IEC 61158 / Modbus Application Protocol Specification v1.1b3):
//!
//! ```text
//! MBAP Header (7 bytes):
//!   [0..2]  transaction_id  : u16 big-endian  — echoed in response
//!   [2..4]  protocol_id     : u16 big-endian  — must be 0x0000
//!   [4..6]  length          : u16 big-endian  — bytes following this field
//!   [6]     unit_id         : u8              — device address (used as device_id)
//! PDU (length - 1 bytes):
//!   [7..]   function_code + data
//! ```
//!
//! The gateway seals `pdu = unit_id_byte || function_code || data` so that
//! the unit_id is integrity-protected even though it is also in the AAD.

pub const MBAP_HEADER_SIZE: usize = 7;
pub const MODBUS_PROTOCOL_ID: u16 = 0x0000;

#[derive(Debug, Clone)]
pub struct MbapHeader {
    pub transaction_id: u16,
    pub length: u16,
    pub unit_id: u8,
}

#[derive(Debug)]
pub enum ModbusError {
    TooShort { have: usize, need: usize },
    BadProtocolId(u16),
    LengthMismatch { declared: usize, available: usize },
}

impl std::fmt::Display for ModbusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModbusError::TooShort { have, need } =>
                write!(f, "Modbus frame too short: have {} need {}", have, need),
            ModbusError::BadProtocolId(pid) =>
                write!(f, "Modbus protocol_id must be 0x0000, got 0x{:04x}", pid),
            ModbusError::LengthMismatch { declared, available } =>
                write!(f, "Modbus length mismatch: declared {} available {}", declared, available),
        }
    }
}

/// Extract the MBAP header and PDU from a raw Modbus TCP frame.
///
/// Returns `(header, pdu_bytes)` where `pdu_bytes` starts with the `unit_id`
/// byte followed by the function-code and data.
pub fn extract_pdu(buf: &[u8]) -> Result<(MbapHeader, Vec<u8>), ModbusError> {
    if buf.len() < MBAP_HEADER_SIZE {
        return Err(ModbusError::TooShort { have: buf.len(), need: MBAP_HEADER_SIZE });
    }
    let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
    let protocol_id    = u16::from_be_bytes([buf[2], buf[3]]);
    let length         = u16::from_be_bytes([buf[4], buf[5]]);
    let unit_id        = buf[6];

    if protocol_id != MODBUS_PROTOCOL_ID {
        return Err(ModbusError::BadProtocolId(protocol_id));
    }

    // `length` counts unit_id + PDU bytes (everything after byte index 5)
    let declared_remaining = length as usize;
    let available_remaining = buf.len() - 6; // from unit_id onward
    if available_remaining < declared_remaining {
        return Err(ModbusError::LengthMismatch {
            declared: declared_remaining,
            available: available_remaining,
        });
    }

    let header = MbapHeader { transaction_id, length, unit_id };
    // Seal unit_id + function_code + data as one opaque PDU
    let pdu = buf[6..6 + declared_remaining].to_vec();
    Ok((header, pdu))
}

/// Reassemble a Modbus TCP frame from a recovered (decrypted) PDU and the
/// original MBAP header.
///
/// The `pdu` slice must start with the `unit_id` byte (as produced by
/// `extract_pdu`).
pub fn reconstruct(header: &MbapHeader, pdu: &[u8]) -> Vec<u8> {
    let length = pdu.len() as u16;
    let mut out = Vec::with_capacity(6 + pdu.len());
    out.extend_from_slice(&header.transaction_id.to_be_bytes());
    out.extend_from_slice(&MODBUS_PROTOCOL_ID.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(pdu);
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Modbus TCP read-holding-registers request (FC=0x03, addr=0x0000, count=10)
    const SAMPLE: &[u8] = &[
        0x00, 0x01, // transaction_id = 1
        0x00, 0x00, // protocol_id    = 0
        0x00, 0x06, // length         = 6
        0x01,       // unit_id        = 1
        0x03,       // function_code  = read holding registers
        0x00, 0x00, // start address  = 0
        0x00, 0x0a, // quantity       = 10
    ];

    #[test]
    fn extract_and_reconstruct_roundtrip() {
        let (hdr, pdu) = extract_pdu(SAMPLE).unwrap();
        assert_eq!(hdr.unit_id, 1);
        assert_eq!(hdr.transaction_id, 1);
        // PDU starts with unit_id then FC
        assert_eq!(pdu[0], 0x01);
        assert_eq!(pdu[1], 0x03);

        let reassembled = reconstruct(&hdr, &pdu);
        assert_eq!(reassembled, SAMPLE);
    }

    #[test]
    fn bad_protocol_id_rejected() {
        let mut bad = SAMPLE.to_vec();
        bad[2] = 0x00;
        bad[3] = 0x01; // protocol_id = 1, not Modbus
        assert!(matches!(extract_pdu(&bad), Err(ModbusError::BadProtocolId(1))));
    }

    #[test]
    fn truncated_frame_rejected() {
        assert!(matches!(
            extract_pdu(&SAMPLE[..4]),
            Err(ModbusError::TooShort { .. })
        ));
    }
}
