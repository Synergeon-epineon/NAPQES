//! Throughput harness for demos/legacy_shield/file_crypto_bench_webdemo.
//!
//! Usage: file_bench <enc|dec> --size BYTES --chunk BYTES --frame F
//! Protocol: prints `READY` after setup, `PROGRESS <bytes>` every ~0.5 s,
//! `DONE {json}` after the timed phase, then waits for a stdin line so the
//! parent can read final CPU counters.
//! Ciphertext is counted, not written, to isolate compute from disk I/O.

use napqes::{
    decrypt_stream_ae_v8, encrypt_stream_ae_v8, generate_v8_key, DEFAULT_KEY_COUNT,
    MAX_KEY_PRIME, MAX_NOISE_RUN, MIN_KEY_PRIME,
};
use rand::RngCore;
use std::io::{BufRead, Write};
use std::time::Instant;

fn arg(args: &[String], name: &str, default: u64) -> u64 {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn random_text(n: usize, rng: &mut impl RngCore) -> String {
    let mut raw = vec![0u8; n];
    rng.fill_bytes(&mut raw);
    // One file byte -> one codepoint, matching the Python reference framing.
    raw.into_iter().map(|b| b as char).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let op = args.get(1).cloned().unwrap_or_default();
    if op != "enc" && op != "dec" {
        eprintln!("usage: file_bench <enc|dec> --size BYTES --chunk BYTES --frame F");
        std::process::exit(2);
    }
    let size = arg(&args, "--size", 1 << 20);
    let chunk = arg(&args, "--chunk", 1 << 16).max(1).min(size.max(1));
    let frame = arg(&args, "--frame", 1024) as u32;

    let (primes, sk) = generate_v8_key(DEFAULT_KEY_COUNT, MIN_KEY_PRIME, MAX_KEY_PRIME);
    let mut rng = rand::thread_rng();
    let enc = |p: &str| encrypt_stream_ae_v8(p, &primes, &sk, b"", frame).expect("encrypt");

    let n_full = size / chunk;
    let tail_len = (size % chunk) as usize;
    let plain = random_text(chunk as usize, &mut rng);
    let tail = random_text(tail_len, &mut rng);
    let (ct, tail_ct) = if op == "dec" {
        (enc(&plain), enc(&tail))
    } else {
        (Vec::new(), Vec::new())
    };

    println!("READY");
    std::io::stdout().flush().ok();

    let started = Instant::now();
    let mut ct_bytes: u64 = 0;
    let mut run = |p: &str, c: &[u8]| {
        if op == "enc" {
            ct_bytes += enc(p).len() as u64;
        } else {
            let pt = decrypt_stream_ae_v8(c, &primes, &sk, b"").expect("decrypt");
            assert_eq!(pt.chars().count(), p.chars().count());
            ct_bytes += c.len() as u64;
        }
    };
    let mut last_report = Instant::now();
    for i in 0..n_full {
        run(&plain, &ct);
        if last_report.elapsed().as_secs_f64() >= 0.5 {
            println!("PROGRESS {}", (i + 1) * chunk);
            std::io::stdout().flush().ok();
            last_report = Instant::now();
        }
    }
    if tail_len > 0 {
        run(&tail, &tail_ct);
    }
    let wall = started.elapsed().as_secs_f64();

    println!(
        "DONE {{\"plaintext_bytes\":{},\"ciphertext_bytes\":{},\"wall_s\":{},\"max_noise_run\":{}}}",
        size, ct_bytes, wall, MAX_NOISE_RUN
    );
    std::io::stdout().flush().ok();
    let _ = std::io::stdin().lock().lines().next();
}
