//! `napqes_integrity` — produce the INT-2 software-integrity reference value
//! (CVF-V5-5).
//!
//! Run after linking, on every executable that contains the module:
//!
//! ```text
//! napqes_integrity target/release/ls_gateway.exe
//! ```
//!
//! writes `target/release/ls_gateway.exe.hmac` containing
//! `HMAC-SHA256(INTEGRITY_KEY, <executable bytes>)` in hex. Install the
//! `.hmac` file next to the executable; `run_power_on_self_tests` (INT-2)
//! recomputes the HMAC at start-up and fails on any mismatch. Builds with the
//! `fips_integrity` feature also fail when the file is missing.

use napqes::self_test::{integrity_sidecar_path, integrity_tag};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: napqes_integrity <executable>...");
        return ExitCode::from(2);
    }
    for p in &paths {
        let path = Path::new(p);
        let image = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{}: {}", p, e);
                return ExitCode::FAILURE;
            }
        };
        let hex: String = integrity_tag(&image).iter().map(|b| format!("{:02x}", b)).collect();
        let sidecar = integrity_sidecar_path(path);
        if let Err(e) = std::fs::write(&sidecar, format!("{}\n", hex)) {
            eprintln!("{}: {}", sidecar.display(), e);
            return ExitCode::FAILURE;
        }
        println!("{}  {}", hex, sidecar.display());
    }
    ExitCode::SUCCESS
}
