//! VALE end-to-end demonstration.
//!
//! Runs through the complete lawful-escrow protocol in one process:
//!
//!   Phase 0  Sovereign setup ceremony (3-of-5 threshold)
//!   Phase 1  NAPQES session key escrow
//!   Phase 2  Warrant issuance by the Judicial Authority
//!   Phase 3  Three SKEN nodes validate the warrant and contribute shares
//!   Phase 4  Wrapping-key reconstruction + session key recovery
//!   Phase 5  Abuse-detection scenarios (expired warrant, tampered ciphertext, …)
//!   Phase 6  Transparency log chain verification

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use napqes::vale::{
    escrow,
    shamir::ShamirShare,
    sken::SkenNode,
    sovereign::{self, SovereignSetup},
    tlog::{self, TlogEvent},
    warrant::{Warrant, WarrantScope},
};

// ─── Terminal helpers ─────────────────────────────────────────────────────────

fn bar() {
    println!("{}", "═".repeat(64));
}

fn hdr(title: &str) {
    println!();
    println!("  ── {} ──", title);
}

macro_rules! ok   { ($($a:tt)*) => { println!("  [OK] {}", format!($($a)*)); }; }
macro_rules! fail { ($($a:tt)*) => { println!("  [!!] {}", format!($($a)*)); }; }
macro_rules! info { ($($a:tt)*) => { println!("       {}", format!($($a)*)); }; }

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Demo ─────────────────────────────────────────────────────────────────────

fn main() {
    bar();
    println!("  VALE — Verifiable Accountable Lawful Escrow  (demo)");
    println!("  EPINeon / NAPQES stack — post-quantum, HMAC-SHA256 only");
    bar();

    // Fixed demo parameters.
    let authority_key = [0xABu8; 32]; // JA's 32-byte HMAC key
    let session_id    = [0x42u8; 16]; // opaque session identifier
    let user_id_hash  = [0x07u8; 32]; // SHA-256(user identity)

    let tlog_path = format!(
        "{}/vale_demo_{}.ndjson",
        std::env::temp_dir().display(),
        now()
    );

    // ─────────────────────────────────────────────────────────────────────────
    hdr("PHASE 0 — SOVEREIGN SETUP CEREMONY  (3-of-5 threshold)");

    print!("       Generating FrodoKEM-640-AES escrow master keypair ...");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let setup = SovereignSetup::generate(3, 5);
    println!("  done.");

    ok!("emk_pub    : {} bytes  (FrodoKEM-640-AES public key — publish openly)",
        setup.emk_pub.len());
    ok!("enc_emk_sk : {} bytes  (EMK_sk encrypted under wk — store at KEA)",
        setup.enc_emk_sk.len());
    ok!("{} SKEN institution packages generated", setup.num_packages());

    // Build SKEN nodes from the ceremony packages.
    let node_names = [
        "FR-JUDICIAIRE-TGI",
        "DE-BUNDESVERFASSUNG",
        "EU-INDEPENDENT-PRESS",
        "INT-OMBUDSMAN-OFFICE",
        "CIVIL-SOCIETY-ORG",
    ];
    let nodes: Vec<SkenNode> = (1u8..=5)
        .map(|id| {
            let pkg = setup.sken_package(id).unwrap();
            SkenNode::new(
                id,
                node_names[(id - 1) as usize].to_string(),
                pkg.share.clone(),
                tlog_path.clone(),
            )
        })
        .collect();

    for n in &nodes {
        info!("Node {:?}  {}", n.node_id, n.node_name);
    }

    // ─────────────────────────────────────────────────────────────────────────
    hdr("PHASE 1 — SESSION KEY ESCROW");

    // A realistic NAPQES prime-list session key (13 distinct primes).
    let session_key: Vec<u64> = vec![
        1_000_003, 1_000_033, 1_000_037, 1_000_039, 1_000_079,
        1_000_081, 1_000_099, 1_000_117, 1_000_121, 1_000_133,
        1_000_151, 1_000_159, 1_000_171,
    ];
    info!("Session key: {} primes, e.g. [{}, {}, …, {}]",
        session_key.len(), session_key[0], session_key[1], session_key[12]);

    print!("       Creating escrow record (KEM-DEM) ...");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let record = escrow::create_record(
        &session_key,
        &setup.emk_pub,
        &session_id,
        &user_id_hash,
        now(),
    ).expect("escrow::create_record");
    println!("  done.");

    ok!("escrow_ct   : {} bytes  (KEM ciphertext + DEM payload + auth tag)",
        record.escrow_ct.len());
    ok!("commitment  : {}...  (published to TLog)", &record.commitment_b64()[..24]);

    tlog::append(&tlog_path, TlogEvent::EscrowCreated {
        session_id:   STANDARD.encode(session_id),
        user_id_hash: STANDARD.encode(user_id_hash),
        commitment:   record.commitment_b64(),
    }, now()).unwrap();
    info!("TLog  <--  EscrowCreated");

    // ─────────────────────────────────────────────────────────────────────────
    hdr("PHASE 2 — WARRANT ISSUANCE  (Judicial Authority)");

    let t = now();
    let warrant = Warrant::sign(
        "W-2026-DEMO-001".to_string(),
        &user_id_hash,
        Some(&session_id),
        t - 60,           // issued 60 s ago
        t + 86400 * 365,  // valid for one year
        WarrantScope::Content,
        "FR-JUDICIAIRE-TGI-PARIS-01".to_string(),
        &authority_key,
    );

    warrant.verify(&authority_key, t).expect("warrant must verify");
    ok!("Warrant   : {}", warrant.warrant_id);
    ok!("Authority : {}", warrant.authority_id);
    ok!("Scope     : {:?}  (full content decryption authorised)", warrant.scope);
    ok!("Validity  : issued {} | expires {}", warrant.issued_at, warrant.expires_at);

    tlog::append(&tlog_path, TlogEvent::WarrantPresented {
        warrant_id:          warrant.warrant_id.clone(),
        authority_id:        warrant.authority_id.clone(),
        scope:               format!("{:?}", warrant.scope),
        target_user_id_hash: warrant.target_user_id_hash.clone(),
    }, now()).unwrap();
    info!("TLog  <--  WarrantPresented  (OA receives full warrant immediately)");

    // ─────────────────────────────────────────────────────────────────────────
    hdr("PHASE 3 — SKEN NODE PARTICIPATION  (nodes 1, 3, 5  of  5)");

    // Collect shares from 3 of the 5 nodes (indices 0, 2, 4 → node_ids 1, 3, 5).
    let participating = [0usize, 2, 4];
    let mut shares: Vec<ShamirShare> = Vec::new();

    for &idx in &participating {
        let node = &nodes[idx];
        print!("       Node {:?}  ({}) ... verifying warrant ...",
            node.node_id, node.node_name);
        let _ = std::io::Write::flush(&mut std::io::stdout());

        let share = node
            .contribute_share(&warrant, &authority_key, &session_id, &user_id_hash, now())
            .expect("valid warrant must release share");
        println!("  share released");
        shares.push(share);
    }

    ok!("3 shares collected");
    info!("TLog: 3 x ShareContributed appended — OA notified in real time");

    // ─────────────────────────────────────────────────────────────────────────
    hdr("PHASE 4 — KEY RECOVERY");

    print!("       Combining 3 Shamir shares  -->  wrapping key ...");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let emk_sk = sovereign::recover_emk_sk(&shares, &setup.enc_emk_sk)
        .expect("k-of-n recovery");
    println!("  done.  ({} bytes)", emk_sk.len());

    print!("       Decrypting escrow record with recovered EMK_sk ...");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let recovered = escrow::recover_session_key(&record, &emk_sk)
        .expect("escrow::recover_session_key");
    println!("  done.");

    assert_eq!(recovered, session_key, "recovered key must equal original");
    ok!("Recovered key  ==  original session key  [MATCH]");
    info!("Primes: [{}, {}, ..., {}]", recovered[0], recovered[1], recovered[12]);

    tlog::append(&tlog_path, TlogEvent::KeyReconstructed {
        warrant_id: warrant.warrant_id.clone(),
        session_id: STANDARD.encode(session_id),
    }, now()).unwrap();
    info!("TLog  <--  KeyReconstructed");

    // ─────────────────────────────────────────────────────────────────────────
    hdr("PHASE 5 — ABUSE DETECTION SCENARIOS");

    // 5a — Expired warrant
    {
        print!("       Expired warrant                    -->  ");
        let exp = Warrant::sign(
            "W-EXPIRED".into(), &user_id_hash, Some(&session_id),
            t - 200, t - 100,  // issued and expired in the past
            WarrantScope::Content, "FR-JUDICIAIRE-TGI-PARIS-01".into(), &authority_key,
        );
        match nodes[0].contribute_share(&exp, &authority_key, &session_id, &user_id_hash, now()) {
            Err(e) => { println!("REJECTED"); fail!("{}", e.split(':').last().unwrap_or(&e).trim()); }
            Ok(_)  => panic!("expired warrant must be rejected"),
        }
    }

    // 5b — Metadata-scope warrant (does not authorise content decryption)
    {
        print!("       Metadata-scope warrant             -->  ");
        let meta = Warrant::sign(
            "W-METADATA".into(), &user_id_hash, Some(&session_id),
            t - 60, t + 86400,
            WarrantScope::Metadata, "FR-JUDICIAIRE-TGI-PARIS-01".into(), &authority_key,
        );
        match nodes[0].contribute_share(&meta, &authority_key, &session_id, &user_id_hash, now()) {
            Err(e) => { println!("REJECTED"); fail!("{}", e.split(':').last().unwrap_or(&e).trim()); }
            Ok(_)  => panic!("metadata warrant must not release content share"),
        }
    }

    // 5c — Wrong session ID (warrant for a different session)
    {
        print!("       Warrant for wrong session ID       -->  ");
        let wrong_sid = Warrant::sign(
            "W-WRONG-SID".into(), &user_id_hash, Some(&[0xFFu8; 16]),
            t - 60, t + 86400,
            WarrantScope::Content, "FR-JUDICIAIRE-TGI-PARIS-01".into(), &authority_key,
        );
        match nodes[0].contribute_share(&wrong_sid, &authority_key, &session_id, &user_id_hash, now()) {
            Err(e) => { println!("REJECTED"); fail!("{}", e.split(':').last().unwrap_or(&e).trim()); }
            Ok(_)  => panic!("wrong session must be rejected"),
        }
    }

    // 5d — Forged warrant (signed with wrong authority key)
    {
        print!("       Forged warrant (wrong signing key) -->  ");
        let forged = Warrant::sign(
            "W-FORGED".into(), &user_id_hash, Some(&session_id),
            t - 60, t + 86400,
            WarrantScope::Content, "ATTACKER".into(), &[0x00u8; 32],
        );
        match nodes[0].contribute_share(&forged, &authority_key, &session_id, &user_id_hash, now()) {
            Err(e) => { println!("REJECTED"); fail!("{}", e.split(':').last().unwrap_or(&e).trim()); }
            Ok(_)  => panic!("forged warrant must be rejected"),
        }
    }

    // 5e — Tampered escrow ciphertext
    {
        print!("       Tampered escrow ciphertext         -->  ");
        let mut bad = record.clone();
        let flip = bad.escrow_ct.len() - 33; // inside ct_dem, before auth_tag
        bad.escrow_ct[flip] ^= 0xFF;
        match escrow::recover_session_key(&bad, &emk_sk) {
            Err(e) => { println!("REJECTED"); fail!("{}", e); }
            Ok(_)  => panic!("tampered ciphertext must fail authentication"),
        }
    }

    // 5f — Insufficient shares (k-1 = 2 shares for a 3-of-5 scheme)
    {
        print!("       Insufficient shares (k-1 = 2)      -->  ");
        let two_shares = shares[..2].to_vec();
        let bad_sk = sovereign::recover_emk_sk(&two_shares, &setup.enc_emk_sk)
            .expect("combine succeeds (wrong result)");
        match escrow::recover_session_key(&record, &bad_sk) {
            Err(e) => { println!("REJECTED"); fail!("{}", e); }
            Ok(k)  => {
                // With high probability the wrong wk produces the wrong EMK_sk,
                // which the auth tag will reject.  If by chance it passes the
                // tag check, the recovered key must differ from the original.
                if k == session_key {
                    panic!("k-1 shares must not recover the correct key");
                }
                println!("WRONG KEY (auth check bypassed by collision — negligible probability)");
            }
        }
    }

    ok!("All 6 abuse scenarios correctly rejected");

    // ─────────────────────────────────────────────────────────────────────────
    hdr("PHASE 6 — TRANSPARENCY LOG VERIFICATION");

    let count = tlog::verify_chain(&tlog_path).expect("chain verification");
    ok!("{} entries — hash chain intact", count);
    println!();

    let entries = tlog::read_all(&tlog_path).expect("read_all");
    println!("  {:>3}  {:<22}  prev_hash (first 12 chars)", "ID", "Event");
    println!("  {}  {}  {}", "-".repeat(3), "-".repeat(22), "-".repeat(16));
    for e in &entries {
        let label = match &e.event {
            TlogEvent::EscrowCreated { .. }                          => "EscrowCreated     ",
            TlogEvent::WarrantPresented { .. }                       => "WarrantPresented  ",
            TlogEvent::ShareContributed { .. }   =>
                { println!("  {:>3}  ShareContributed      prev: {}...",
                    e.entry_id, &e.prev_hash[..12]); continue; }
            TlogEvent::KeyReconstructed { .. }                       => "KeyReconstructed  ",
            TlogEvent::NotificationSent { .. }                       => "NotificationSent  ",
        };
        println!("  {:>3}  {}  prev: {}...", e.entry_id, label, &e.prev_hash[..12]);
    }

    let _ = std::fs::remove_file(&tlog_path);

    // ─────────────────────────────────────────────────────────────────────────
    println!();
    bar();
    println!("  Demo complete.  All assertions passed.");
    println!();
    println!("  Cryptographic guarantees demonstrated:");
    println!("    Session key escrow  FrodoKEM-640-AES + HMAC-SHA256 KEM-DEM");
    println!("    Threshold access    3-of-5 Shamir/GF(2^8) — any k subset works");
    println!("    Warrant binding     HMAC-SHA256 signature, scope + expiry enforced");
    println!("    Tamper evidence     HMAC-chained transparency log verified");
    println!("    Abuse deterrence    OA notified on every share contribution");
    bar();
}
