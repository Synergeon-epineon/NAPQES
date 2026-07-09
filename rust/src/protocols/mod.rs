//! Protocol extractor modules.
//!
//! Each module exposes `extract_pdu` (parse raw socket bytes → header + PDU)
//! and `reconstruct` (re-frame the authenticated PDU for delivery to the
//! SCADA side).

pub mod modbus;
pub mod dnp3;
