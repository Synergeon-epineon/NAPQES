//! Legacy Shield Gateway — `ls_gateway`
//!
//! A bump-in-the-wire TCP proxy that wraps legacy OT protocol PDUs (Modbus TCP,
//! DNP3) in NAPQES v6 AEAD frames on the ingress side and unwraps them on the
//! egress side, exporting authentication-failure events to a SIEM via UDP syslog
//! in CEF format.
//!
//! # Key management modes
//!
//! ## KEM mode (recommended — no pre-shared secret needed)
//!
//! On startup the two gateways run a **FrodoKEM-640-AES** (IND-CCA2) exchange
//! over a dedicated management TCP port.  Neither side needs a pre-shared secret;
//! the session key is derived from the KEM shared secret via HKDF-SHA256.
//!
//! - Egress gateway (`mode = "egress"`) acts as KEM **responder**:
//!   generates a fresh keypair, sends the public key, receives the ciphertext,
//!   decapsulates.
//! - Ingress gateway (`mode = "ingress"`) acts as KEM **initiator**:
//!   receives the public key, encapsulates, sends the ciphertext.
//!
//! Periodic re-keying is configured via `kem_rekey_interval_secs`.
//!
//! ## Pre-shared key mode (fallback / offline environments)
//!
//! If `kem` is not configured, keys are loaded from the JSON file at
//! `key_store_path` (see `FileKeyStore`).
//!
//! # Config file schema (`gateway_config.json`)
//!
//! ```json
//! {
//!   "mode": "ingress",
//!   "protocols": ["modbus", "dnp3"],
//!   "forward_addr": "gateway-egress:5502",
//!   "siem_addr": "siem-stub:514",
//!   "modbus_listen": "0.0.0.0:502",
//!   "dnp3_listen":   "0.0.0.0:20000",
//!   "modbus_secure_listen": "0.0.0.0:5502",
//!   "dnp3_secure_listen":   "0.0.0.0:25000",
//!
//!   "kem_peer_addr":          "gateway-egress:5600",
//!   "kem_listen_addr":        "0.0.0.0:5600",
//!   "kem_rekey_interval_secs": 300,
//!
//!   "key_store_path": ""
//! }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, Duration};

use napqes::kem_exchange;
use napqes::ot_frame::{
    wrap_pdu, unwrap_pdu, OtAad, ProtocolId, SequenceCounter,
    FileKeyStore, KeyStore, SessionKeyStore, WILDCARD_DEVICE_ID,
};
use napqes::protocols::{modbus, dnp3};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "ls_gateway", about = "Legacy Shield NAPQES OT Gateway")]
struct Cli {
    /// Path to the JSON configuration file.
    #[arg(short, long, default_value = "gateway_config.json")]
    config: String,
}

// ─── Config ──────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct Config {
    /// "ingress" or "egress"
    mode: String,
    /// List of protocols to handle: ["modbus", "dnp3"]
    #[serde(default = "default_protocols")]
    protocols: Vec<String>,
    /// Address to forward frames/PDUs to.
    forward_addr: String,
    /// UDP address of the SIEM (CEF syslog receiver).  Empty string disables.
    #[serde(default)]
    siem_addr: String,

    // ── OT listener ports ────────────────────────────────────────────────────
    #[serde(default = "default_modbus_listen")]
    modbus_listen: String,
    #[serde(default = "default_dnp3_listen")]
    dnp3_listen: String,
    #[serde(default = "default_modbus_secure")]
    modbus_secure_listen: String,
    #[serde(default = "default_dnp3_secure")]
    dnp3_secure_listen: String,

    // ── KEM key establishment ─────────────────────────────────────────────────
    /// Egress gateway KEM listen address (responder).
    /// Required for `mode = "egress"` with KEM enabled.
    #[serde(default)]
    kem_listen_addr: String,
    /// Ingress gateway KEM peer address (initiator → connects here).
    /// Required for `mode = "ingress"` with KEM enabled.
    #[serde(default)]
    kem_peer_addr: String,
    /// Seconds between automatic KEM re-key exchanges.
    /// 0 or absent = re-key only at startup.
    #[serde(default)]
    kem_rekey_interval_secs: u64,

    // ── Pre-shared key fallback ──────────────────────────────────────────────
    /// Path to the JSON key store file.
    /// Used only when KEM is not configured (empty `kem_peer_addr` / `kem_listen_addr`).
    #[serde(default)]
    key_store_path: String,
}

fn default_protocols()     -> Vec<String> { vec!["modbus".into(), "dnp3".into()] }
fn default_modbus_listen() -> String      { "0.0.0.0:502".into() }
fn default_dnp3_listen()   -> String      { "0.0.0.0:20000".into() }
fn default_modbus_secure() -> String      { "0.0.0.0:5502".into() }
fn default_dnp3_secure()   -> String      { "0.0.0.0:25000".into() }

// ─── Shared state ────────────────────────────────────────────────────────────

struct GatewayState {
    config:    Config,
    key_store: Arc<dyn KeyStore>,
    counters:  SequenceCounter,
    siem:      Option<Arc<UdpSocket>>,
}

// ─── SIEM CEF logging ─────────────────────────────────────────────────────────

fn cef_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn emit_cef_event(
    siem:      &UdpSocket,
    siem_addr: &str,
    event_id:  &str,
    severity:  u8,
    extension: &str,
) {
    let msg = format!(
        "CEF:0|EPINeon|LegacyShieldGateway|1.0|{}|{}|{}|rt={} {}\n",
        event_id,
        event_id.replace('_', " "),
        severity,
        cef_timestamp(),
        extension
    );
    let addr_opt: Option<SocketAddr> = if let Ok(a) = siem_addr.parse::<SocketAddr>() {
        Some(a)
    } else {
        tokio::net::lookup_host(siem_addr).await.ok()
            .and_then(|mut it| it.next())
    };
    if let Some(addr) = addr_opt {
        let _ = siem.send_to(msg.as_bytes(), addr).await;
    }
}

// ─── Ingress: wrap PDU ───────────────────────────────────────────────────────

async fn handle_ingress_modbus(
    mut stream: TcpStream,
    peer:       SocketAddr,
    state:      Arc<GatewayState>,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => { eprintln!("[ingress][modbus] read error from {}: {}", peer, e); break; }
        };

        let frame = &buf[..n];
        match modbus::extract_pdu(frame) {
            Err(e) => {
                eprintln!("[ingress][modbus] parse error from {}: {}", peer, e);
                emit_siem(&state, "PARSE_ERR", 5, &format!("proto=MODBUS src={}", peer)).await;
            }
            Ok((hdr, pdu)) => {
                let device_id = hdr.unit_id as u64;
                let seq = state.counters.next_seq(ProtocolId::ModbusTcp, device_id);
                let aad = OtAad { protocol: ProtocolId::ModbusTcp, device_id, seq };

                let key = match state.key_store.load(device_id) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("[ingress][modbus] no key for device {}: {}", device_id, e);
                        emit_siem(&state, "KEY_MISSING", 7,
                            &format!("proto=MODBUS deviceId=0x{:x} src={}", device_id, peer)).await;
                        continue;
                    }
                };

                match wrap_pdu(&pdu, aad, &key) {
                    Err(e) => eprintln!("[ingress][modbus] wrap error: {}", e),
                    Ok(envelope) => {
                        if let Err(e) = forward_envelope(&state.config.forward_addr, &envelope).await {
                            eprintln!("[ingress][modbus] forward error: {}", e);
                        }
                    }
                }
            }
        }
    }
}

async fn handle_ingress_dnp3(
    mut stream: TcpStream,
    peer:       SocketAddr,
    state:      Arc<GatewayState>,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => { eprintln!("[ingress][dnp3] read error from {}: {}", peer, e); break; }
        };

        let frame = &buf[..n];
        match dnp3::extract_payload(frame) {
            Err(e) => {
                eprintln!("[ingress][dnp3] parse error from {}: {}", peer, e);
                emit_siem(&state, "PARSE_ERR", 5, &format!("proto=DNP3 src={}", peer)).await;
            }
            Ok((hdr, payload)) => {
                let device_id = hdr.source as u64;
                let seq = state.counters.next_seq(ProtocolId::Dnp3, device_id);
                let aad = OtAad { protocol: ProtocolId::Dnp3, device_id, seq };

                let key = match state.key_store.load(device_id) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("[ingress][dnp3] no key for device {}: {}", device_id, e);
                        emit_siem(&state, "KEY_MISSING", 7,
                            &format!("proto=DNP3 deviceId=0x{:x} src={}", device_id, peer)).await;
                        continue;
                    }
                };

                match wrap_pdu(&payload, aad, &key) {
                    Err(e) => eprintln!("[ingress][dnp3] wrap error: {}", e),
                    Ok(envelope) => {
                        if let Err(e) = forward_envelope(&state.config.forward_addr, &envelope).await {
                            eprintln!("[ingress][dnp3] forward error: {}", e);
                        }
                    }
                }
            }
        }
    }
}

// ─── Egress: unwrap PDU ──────────────────────────────────────────────────────

async fn handle_egress(
    mut stream: TcpStream,
    peer:       SocketAddr,
    state:      Arc<GatewayState>,
    protocol:   ProtocolId,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("[egress][{}] read error from {}: {}", protocol.as_str(), peer, e);
                break;
            }
        };

        let envelope = &buf[..n];

        let device_id = match peek_device_id(envelope) {
            Some(id) => id,
            None => {
                eprintln!("[egress][{}] malformed envelope from {}", protocol.as_str(), peer);
                emit_siem(&state, "PARSE_ERR", 5,
                    &format!("proto={} src={}", protocol.as_str(), peer)).await;
                continue;
            }
        };

        let key = match state.key_store.load(device_id) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[egress][{}] no key for device {}: {}", protocol.as_str(), device_id, e);
                emit_siem(&state, "KEY_MISSING", 7,
                    &format!("proto={} deviceId=0x{:x} src={}", protocol.as_str(), device_id, peer)).await;
                continue;
            }
        };

        let seq_from_env = peek_seq(envelope).unwrap_or(0);
        match unwrap_pdu(envelope, &key, &state.counters) {
            Err(e) => {
                eprintln!("[egress][{}] unwrap error: {}", protocol.as_str(), e);
                emit_siem(&state, "AUTH_FAIL", 7, &format!(
                    "proto={} deviceId=0x{:x} seq={} src={}",
                    protocol.as_str(), device_id, seq_from_env, peer
                )).await;
                // Drop — never forward unauthenticated data
            }
            Ok(pdu) => {
                let frame = match protocol {
                    ProtocolId::ModbusTcp => reassemble_modbus(&pdu),
                    ProtocolId::Dnp3      => pdu.clone(),
                };
                if let Err(e) = forward_envelope(&state.config.forward_addr, &frame).await {
                    eprintln!("[egress][{}] forward error: {}", protocol.as_str(), e);
                }
            }
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn peek_device_id(buf: &[u8]) -> Option<u64> {
    use napqes::ot_frame::ENVELOPE_HEADER_SIZE;
    if buf.len() < ENVELOPE_HEADER_SIZE { return None; }
    if buf[0..2] != napqes::ot_frame::ENVELOPE_MAGIC { return None; }
    Some(u64::from_be_bytes(buf[3..11].try_into().ok()?))
}

fn peek_seq(buf: &[u8]) -> Option<u64> {
    use napqes::ot_frame::ENVELOPE_HEADER_SIZE;
    if buf.len() < ENVELOPE_HEADER_SIZE { return None; }
    Some(u64::from_be_bytes(buf[11..19].try_into().ok()?))
}

fn reassemble_modbus(pdu: &[u8]) -> Vec<u8> {
    let hdr = modbus::MbapHeader {
        transaction_id: 0,
        length: pdu.len() as u16,
        unit_id: if pdu.is_empty() { 0 } else { pdu[0] },
    };
    modbus::reconstruct(&hdr, pdu)
}

async fn forward_envelope(addr: &str, data: &[u8]) -> std::io::Result<()> {
    let mut conn = TcpStream::connect(addr).await?;
    let len_prefix = (data.len() as u32).to_be_bytes();
    conn.write_all(&len_prefix).await?;
    conn.write_all(data).await?;
    Ok(())
}

async fn emit_siem(state: &GatewayState, event_id: &str, severity: u8, ext: &str) {
    if let (Some(siem), addr) = (&state.siem, &state.config.siem_addr) {
        emit_cef_event(siem, addr, event_id, severity, ext).await;
    }
}

// ─── Listener spawners ────────────────────────────────────────────────────────

async fn run_ingress_listener(
    listen_addr: String,
    protocol:    ProtocolId,
    state:       Arc<GatewayState>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    println!("[ingress][{}] listening on {}", protocol.as_str(), listen_addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let s = Arc::clone(&state);
        match protocol {
            ProtocolId::ModbusTcp =>
                tokio::spawn(async move { handle_ingress_modbus(stream, peer, s).await }),
            ProtocolId::Dnp3 =>
                tokio::spawn(async move { handle_ingress_dnp3(stream, peer, s).await }),
        };
    }
}

async fn run_egress_listener(
    listen_addr: String,
    protocol:    ProtocolId,
    state:       Arc<GatewayState>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    println!("[egress][{}] listening on {}", protocol.as_str(), listen_addr);
    loop {
        let (stream, peer) = listener.accept().await?;
        let s = Arc::clone(&state);
        tokio::spawn(async move { handle_egress(stream, peer, s, protocol).await });
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config_text = std::fs::read_to_string(&cli.config)
        .map_err(|e| format!("cannot read config '{}': {}", cli.config, e))?;
    let config: Config = serde_json::from_str(&config_text)
        .map_err(|e| format!("config JSON parse error: {}", e))?;

    println!("[ls_gateway] starting in {} mode", config.mode);

    let use_kem = match config.mode.as_str() {
        "ingress" => !config.kem_peer_addr.is_empty(),
        "egress"  => !config.kem_listen_addr.is_empty(),
        _         => false,
    };

    // Build typed SessionKeyStore (KEM) or FileKeyStore (pre-shared).
    // For KEM: keep a typed Arc for the KEM loop + a dyn Arc for GatewayState.
    // Both arcs point to the same allocation; insert() via the typed arc is
    // immediately visible through the dyn arc.
    let (key_store_dyn, session_store_opt): (Arc<dyn KeyStore>, Option<Arc<SessionKeyStore>>) =
        if use_kem {
            let ss = Arc::new(SessionKeyStore::new());
            println!("[ls_gateway] key mode: FrodoKEM-640-AES (no pre-shared secret)");
            (Arc::clone(&ss) as Arc<dyn KeyStore>, Some(ss))
        } else {
            if config.key_store_path.is_empty() {
                return Err("neither KEM nor key_store_path is configured".into());
            }
            let fs = FileKeyStore::load_from_file(&config.key_store_path)
                .map_err(|e| format!("key store: {}", e))?;
            println!("[ls_gateway] key mode: pre-shared ({})", config.key_store_path);
            (Arc::new(fs) as Arc<dyn KeyStore>, None)
        };

    let siem = if !config.siem_addr.is_empty() {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        println!("[ls_gateway] SIEM CEF events → {}", config.siem_addr);
        Some(Arc::new(sock))
    } else {
        None
    };

    let state = Arc::new(GatewayState {
        config,
        key_store: key_store_dyn,
        counters: SequenceCounter::new(),
        siem,
    });

    let mut tasks = tokio::task::JoinSet::new();

    // ── KEM background task ───────────────────────────────────────────────────
    if let Some(session_store) = session_store_opt {
        match state.config.mode.as_str() {
            "ingress" => {
                let peer     = state.config.kem_peer_addr.clone();
                let interval = if state.config.kem_rekey_interval_secs > 0 {
                    state.config.kem_rekey_interval_secs
                } else {
                    u64::MAX / 2 // one-shot — no automatic re-key
                };
                let store_clone = Arc::clone(&session_store);
                tasks.spawn(async move {
                    kem_exchange::run_initiator_loop(peer, interval, store_clone).await;
                    Ok(())
                });
                // Wait for initial key before accepting OT frames
                wait_for_key(&session_store).await;
            }
            "egress" => {
                let listen      = state.config.kem_listen_addr.clone();
                let store_clone = Arc::clone(&session_store);
                tasks.spawn(async move {
                    kem_exchange::run_responder_loop(listen, store_clone).await;
                    Ok(())
                });
                wait_for_key(&session_store).await;
            }
            _ => {}
        }
    }

    // ── OT protocol listeners ─────────────────────────────────────────────────
    start_ot_listeners(&state, &mut tasks);
    run_task_loop(tasks).await;
    Ok(())
}

/// Poll until at least one key is installed in the session store (max 120s).
async fn wait_for_key(store: &Arc<SessionKeyStore>) {
    for _ in 0..240 {
        if store.is_ready() { return; }
        sleep(Duration::from_millis(500)).await;
    }
    eprintln!("[ls_gateway] WARNING: KEM exchange timed out (120s); \
        OT listeners starting — frames will be dropped until exchange completes");
}

fn start_ot_listeners(
    state: &Arc<GatewayState>,
    tasks: &mut tokio::task::JoinSet<Result<(), String>>,
) {
    match state.config.mode.as_str() {
        "ingress" => {
            for proto_str in &state.config.protocols {
                let s = Arc::clone(state);
                match proto_str.as_str() {
                    "modbus" => {
                        let addr = s.config.modbus_listen.clone();
                        tasks.spawn(async move {
                            run_ingress_listener(addr, ProtocolId::ModbusTcp, s).await
                                .map_err(|e| e.to_string())
                        });
                    }
                    "dnp3" => {
                        let addr = s.config.dnp3_listen.clone();
                        tasks.spawn(async move {
                            run_ingress_listener(addr, ProtocolId::Dnp3, s).await
                                .map_err(|e| e.to_string())
                        });
                    }
                    other => eprintln!("[ls_gateway] unknown protocol '{}', skipping", other),
                }
            }
        }
        "egress" => {
            for proto_str in &state.config.protocols {
                let s = Arc::clone(state);
                match proto_str.as_str() {
                    "modbus" => {
                        let addr = s.config.modbus_secure_listen.clone();
                        tasks.spawn(async move {
                            run_egress_listener(addr, ProtocolId::ModbusTcp, s).await
                                .map_err(|e| e.to_string())
                        });
                    }
                    "dnp3" => {
                        let addr = s.config.dnp3_secure_listen.clone();
                        tasks.spawn(async move {
                            run_egress_listener(addr, ProtocolId::Dnp3, s).await
                                .map_err(|e| e.to_string())
                        });
                    }
                    other => eprintln!("[ls_gateway] unknown protocol '{}', skipping", other),
                }
            }
        }
        other => eprintln!("[ls_gateway] unknown mode '{}' in start_ot_listeners", other),
    }
}

async fn run_task_loop(mut tasks: tokio::task::JoinSet<Result<(), String>>) {
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Err(e)) => eprintln!("[ls_gateway] listener error: {}", e),
            Err(e)     => eprintln!("[ls_gateway] task panic: {}", e),
            Ok(Ok(())) => {}
        }
    }
}
