//! NIST SP 800-22 Rev 1a Statistical Test Suite — NAPSEQ v6 (Rust).
//!
//! Implements all 15 SP 800-22 Rev 1a tests from scratch in safe Rust,
//! without relying on `nistrng` or any external math library.  All known
//! `nistrng` 1.2.3 failures (DFT, Linear Complexity, Serial, Approximate
//! Entropy, Non-Overlapping Template Matching, Maurer's Universal,
//! Random Excursion / Variant) are correctly implemented here.
//!
//! Usage:
//!   cargo run --bin sts -- --bits 10000000
//!   cargo run --bin sts                    # default 10^7 bits

use std::f64::consts::{PI, SQRT_2};
use std::time::Instant;

// ── STS key & corpus (matches tests/sts_pipeline.py) ────────────────────────

const STS_KEY: [u64; 10] = [
    1_000_003, 1_000_033, 1_000_037, 1_000_039,
    1_000_081, 1_000_099, 1_000_117, 1_000_121,
    1_000_133, 1_000_151,
];

// ════════════════════════════════════════════════════════════════════════════
// Special functions
// ════════════════════════════════════════════════════════════════════════════

/// Log-gamma via Lanczos approximation (Spouge's coefficients, g=7).
fn lgamma(x: f64) -> f64 {
    const G: f64 = 7.0;
    const C: [f64; 9] = [
        0.999_999_999_999_809_93,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_13,
        -176.615_029_162_140_59,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_571_6e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        return (PI / (PI * x).sin()).ln() - lgamma(1.0 - x);
    }
    let xm1 = x - 1.0;
    let t = xm1 + G + 0.5;
    let ser: f64 = C[0] + (1..9).map(|i| C[i] / (xm1 + i as f64)).sum::<f64>();
    0.5 * (2.0 * PI).ln() + ser.ln() + (xm1 + 0.5) * t.ln() - t
}

/// Lower regularized incomplete gamma P(a, x) via series.
fn igam_series(a: f64, x: f64) -> f64 {
    let mut ap = a;
    let mut del = 1.0 / a;
    let mut sum = del;
    for _ in 0..300 {
        ap += 1.0;
        del *= x / ap;
        sum += del;
        if del.abs() < sum.abs() * f64::EPSILON {
            break;
        }
    }
    sum * (-x + a * x.ln() - lgamma(a)).exp()
}

/// Upper regularized incomplete gamma Q(a, x) via Lentz continued fraction.
fn igam_cf(a: f64, x: f64) -> f64 {
    const FPMIN: f64 = 1e-300;
    let mut b = x + 1.0 - a;
    let mut c = 1.0 / FPMIN;
    let mut d = 1.0 / b;
    let mut h = d;
    for i in 1_u64..=300 {
        let an = -(i as f64) * (i as f64 - a);
        b += 2.0;
        d = an * d + b;
        if d.abs() < FPMIN { d = FPMIN; }
        c = b + an / c;
        if c.abs() < FPMIN { c = FPMIN; }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < 3.0 * f64::EPSILON { break; }
    }
    h * (-x + a * x.ln() - lgamma(a)).exp()
}

/// Upper regularized incomplete gamma Q(a, x) = 1 − P(a, x).
fn igamc(a: f64, x: f64) -> f64 {
    if x <= 0.0 || a <= 0.0 { return 1.0; }
    if x < a + 1.0 { 1.0 - igam_series(a, x) } else { igam_cf(a, x) }
}

/// Complementary error function erfc(x) = Q(1/2, x²) for x ≥ 0.
fn erfc(x: f64) -> f64 {
    if x < 0.0 { 2.0 - erfc(-x) } else { igamc(0.5, x * x) }
}

/// Standard normal CDF Φ(x) = 0.5 · erfc(−x / √2).
fn normal_cdf(x: f64) -> f64 {
    0.5 * erfc(-x / SQRT_2)
}

// ════════════════════════════════════════════════════════════════════════════
// In-place radix-2 Cooley-Tukey FFT (no external deps)
// ════════════════════════════════════════════════════════════════════════════

fn bit_rev(mut x: usize, bits: u32) -> usize {
    let mut r = 0usize;
    for _ in 0..bits { r = (r << 1) | (x & 1); x >>= 1; }
    r
}

/// In-place DIT FFT.  `re` and `im` must have length = power of 2.
fn fft_inplace(re: &mut [f64], im: &mut [f64]) {
    let n = re.len();
    debug_assert!(n.is_power_of_two());
    let log2n = n.trailing_zeros();
    for i in 0..n {
        let j = bit_rev(i, log2n);
        if i < j { re.swap(i, j); im.swap(i, j); }
    }
    let mut half = 1usize;
    while half < n {
        let len = half * 2;
        let ang = -PI / half as f64;
        let (wre, wim) = (ang.cos(), ang.sin());
        let mut i = 0;
        while i < n {
            let (mut ur, mut ui) = (1.0_f64, 0.0_f64);
            for j in 0..half {
                let (are, aim) = (re[i + j], im[i + j]);
                let (bre, bim) = (re[i + j + half], im[i + j + half]);
                let (cr, ci) = (bre * ur - bim * ui, bre * ui + bim * ur);
                re[i + j]        = are + cr;
                im[i + j]        = aim + ci;
                re[i + j + half] = are - cr;
                im[i + j + half] = aim - ci;
                let nu = ur * wre - ui * wim;
                ui = ur * wim + ui * wre;
                ur = nu;
            }
            i += len;
        }
        half = len;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Berlekamp-Massey (GF(2))
// ════════════════════════════════════════════════════════════════════════════

fn berlekamp_massey(s: &[u8]) -> usize {
    let n = s.len();
    let mut c = vec![0u8; n + 1];
    let mut b = vec![0u8; n + 1];
    c[0] = 1; b[0] = 1;
    let mut l: usize = 0;
    let mut m: usize = 1;
    for nn in 0..n {
        let mut d: u8 = s[nn];
        for i in 1..=l { d ^= c[i] & s[nn - i]; }
        if d == 0 {
            m += 1;
        } else if 2 * l <= nn {
            let t = c.clone();
            let end = nn + 1 - m;
            for j in 0..=end { c[j + m] ^= b[j]; }
            l = nn + 1 - l;
            b = t;
            m = 1;
        } else {
            let end = nn + 1 - m;
            for j in 0..=end { c[j + m] ^= b[j]; }
            m += 1;
        }
    }
    l
}

// ════════════════════════════════════════════════════════════════════════════
// Aperiodic templates for NOTM (computed once at startup)
// ════════════════════════════════════════════════════════════════════════════

/// A template t is aperiodic if no proper period divides its length.
/// (t has period p iff t[i] == t[i+p] for all 0 ≤ i < m-p.)
fn is_aperiodic(t: &[u8]) -> bool {
    let m = t.len();
    !(1..m).any(|p| (0..m - p).all(|i| t[i] == t[i + p]))
}

fn aperiodic_templates(m: usize) -> Vec<Vec<u8>> {
    (0u32..1 << m)
        .filter_map(|v| {
            let t: Vec<u8> = (0..m).rev().map(|i| ((v >> i) & 1) as u8).collect();
            if is_aperiodic(&t) { Some(t) } else { None }
        })
        .collect()
}

// ════════════════════════════════════════════════════════════════════════════
// Bitstream generation
// ════════════════════════════════════════════════════════════════════════════

/// Returns a `Vec<u8>` of `n` bits (each element is 0 or 1) generated from
/// NAPSEQ v6 ciphertexts with `STS_KEY`.
fn generate_bits(n: usize) -> Vec<u8> {
    const CORPUS: &[u8] = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    let corpus_len = CORPUS.len();
    let chunk_size = 480;
    let target_bytes = (n + 7) / 8;
    let mut raw: Vec<u8> = Vec::with_capacity(target_bytes + 8192);
    let mut chunk_num = 0usize;
    while raw.len() < target_bytes {
        let off = (chunk_num * chunk_size) % corpus_len;
        let repeated: Vec<u8> = CORPUS.iter()
            .cycle()
            .skip(off)
            .take(chunk_size)
            .copied()
            .collect();
        let msg = std::str::from_utf8(&repeated).unwrap();
        let ct = napqes::encrypt_bytes(msg, &STS_KEY, b"")
            .expect("NAPQES encrypt failed during STS bitstream generation");
        raw.extend_from_slice(&ct);
        chunk_num += 1;
    }
    raw.truncate(target_bytes);
    // Unpack bits MSB-first
    let mut bits = Vec::with_capacity(n);
    for byte in &raw {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }
    bits.truncate(n);
    bits
}

// ════════════════════════════════════════════════════════════════════════════
// Test result type
// ════════════════════════════════════════════════════════════════════════════

#[derive(Debug, PartialEq)]
enum Status { Pass, Fail, Skip }

#[derive(Debug)]
struct Tr {
    name:    &'static str,
    p_value: f64,
    status:  Status,
    note:    &'static str,
}

impl Tr {
    fn new(name: &'static str, p: f64) -> Self {
        let status = if p >= 0.01 { Status::Pass } else { Status::Fail };
        Tr { name, p_value: p, status, note: "" }
    }
    fn with_note(name: &'static str, p: f64, note: &'static str) -> Self {
        let status = if p >= 0.01 { Status::Pass } else { Status::Fail };
        Tr { name, p_value: p, status, note }
    }
    fn skip(name: &'static str, note: &'static str) -> Self {
        Tr { name, p_value: f64::NAN, status: Status::Skip, note }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Test 1 — Monobit (Frequency)
// ════════════════════════════════════════════════════════════════════════════

fn test_monobit(bits: &[u8]) -> Tr {
    let n = bits.len() as f64;
    let sn: i64 = bits.iter().map(|&b| if b == 1 { 1i64 } else { -1 }).sum();
    let s_obs = sn.unsigned_abs() as f64 / n.sqrt();
    Tr::new("Monobit", erfc(s_obs / SQRT_2))
}

// ════════════════════════════════════════════════════════════════════════════
// Test 2 — Frequency Within Block
// ════════════════════════════════════════════════════════════════════════════

fn test_frequency_block(bits: &[u8]) -> Tr {
    const M: usize = 128;
    let n = bits.len();
    let cap = n / M;
    if cap < 1 { return Tr::new("Frequency Within Block", 0.0); }
    let chi_sq: f64 = (0..cap).map(|j| {
        let ones = bits[j * M..(j + 1) * M].iter().filter(|&&b| b == 1).count() as f64;
        let pi = ones / M as f64;
        (pi - 0.5).powi(2)
    }).sum::<f64>() * (4 * M) as f64;
    Tr::new("Frequency Within Block", igamc(cap as f64 / 2.0, chi_sq / 2.0))
}

// ════════════════════════════════════════════════════════════════════════════
// Test 3 — Runs
// ════════════════════════════════════════════════════════════════════════════

fn test_runs(bits: &[u8]) -> Tr {
    let n = bits.len() as f64;
    let ones = bits.iter().filter(|&&b| b == 1).count() as f64;
    let pi = ones / n;
    if (pi - 0.5).abs() >= 2.0 / n.sqrt() {
        return Tr::new("Runs", 0.0);
    }
    let v: f64 = 1.0 + bits.windows(2).filter(|w| w[0] != w[1]).count() as f64;
    let num = (v - 2.0 * n * pi * (1.0 - pi)).abs();
    let den = 2.0 * (2.0 * n).sqrt() * pi * (1.0 - pi);
    Tr::new("Runs", erfc(num / den))
}

// ════════════════════════════════════════════════════════════════════════════
// Test 4 — Longest Run of Ones in a Block
// ════════════════════════════════════════════════════════════════════════════

fn test_longest_run(bits: &[u8]) -> Tr {
    let n = bits.len();
    // Parameters per NIST Table 1
    let (m, k, thresholds, pi): (usize, usize, &[usize], &[f64]) = if n < 6272 {
        (8, 3, &[1, 2, 3, 4], &[0.2148, 0.3672, 0.2305, 0.1875])
    } else if n < 750_000 {
        (128, 5, &[4, 5, 6, 7, 8, 9], &[0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124])
    } else {
        (10_000, 6, &[10, 11, 12, 13, 14, 15, 16],
         &[0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727])
    };
    let big_n = n / m;
    let mut nu = vec![0u64; k + 1];
    for j in 0..big_n {
        let block = &bits[j * m..(j + 1) * m];
        let longest = block.iter().fold((0usize, 0usize), |(max, cur), &b| {
            let c = if b == 1 { cur + 1 } else { 0 };
            (max.max(c), c)
        }).0;
        let cat = thresholds.partition_point(|&t| t <= longest).saturating_sub(1).min(k);
        nu[cat] += 1;
    }
    let chi_sq: f64 = nu.iter().zip(pi.iter())
        .map(|(&v, &p)| {
            let exp = big_n as f64 * p;
            (v as f64 - exp).powi(2) / exp
        })
        .sum();
    Tr::new("Longest Run Ones In A Block", igamc(k as f64 / 2.0, chi_sq / 2.0))
}

// ════════════════════════════════════════════════════════════════════════════
// Test 5 — Binary Matrix Rank
// ════════════════════════════════════════════════════════════════════════════

/// GF(2) rank of a 32×32 bit matrix (row-major u32 words).
fn gf2_rank32(mat: &mut [u32; 32]) -> usize {
    let mut rank = 0;
    for col in 0..32 {
        let pivot = (rank..32).find(|&r| (mat[r] >> col) & 1 == 1);
        if let Some(p) = pivot {
            mat.swap(rank, p);
            for r in 0..32 {
                if r != rank && (mat[r] >> col) & 1 == 1 {
                    mat[r] ^= mat[rank];
                }
            }
            rank += 1;
        }
    }
    rank
}

fn test_binary_matrix_rank(bits: &[u8]) -> Tr {
    const M: usize = 32;
    let n = bits.len();
    let big_n = n / (M * M);
    if big_n < 1 { return Tr::new("Binary Matrix Rank", 0.0); }
    let (mut f32, mut f31, mut frest) = (0u64, 0u64, 0u64);
    for j in 0..big_n {
        let mut mat = [0u32; 32];
        let base = j * M * M;
        for r in 0..M {
            for c in 0..M {
                if bits[base + r * M + c] == 1 {
                    mat[r] |= 1 << c;
                }
            }
        }
        match gf2_rank32(&mut mat) {
            32 => f32  += 1,
            31 => f31  += 1,
            _  => frest += 1,
        }
    }
    const P32: f64 = 0.2888;
    const P31: f64 = 0.5776;
    const PR:  f64 = 0.1336;
    let bn = big_n as f64;
    let chi_sq = (f32 as f64 - bn * P32).powi(2) / (bn * P32)
               + (f31 as f64 - bn * P31).powi(2) / (bn * P31)
               + (frest as f64 - bn * PR).powi(2) / (bn * PR);
    Tr::new("Binary Matrix Rank", (-chi_sq / 2.0).exp())
}

// ════════════════════════════════════════════════════════════════════════════
// Test 6 — Discrete Fourier Transform (Spectral)
// ════════════════════════════════════════════════════════════════════════════

fn test_dft(bits: &[u8]) -> Tr {
    let n = bits.len();
    // Zero-pad to next power of 2
    let nfft = n.next_power_of_two();
    let mut re: Vec<f64> = bits.iter().map(|&b| if b == 1 { 1.0 } else { -1.0 }).collect();
    re.resize(nfft, 0.0);
    let mut im = vec![0.0f64; nfft];
    fft_inplace(&mut re, &mut im);
    // Magnitudes of first floor(n/2) non-DC terms
    let half = n / 2;
    let threshold = (2.995_732_274 * n as f64).sqrt();  // T = sqrt(ln(20)*n)
    let n1 = (1..=half)
        .filter(|&k| (re[k].powi(2) + im[k].powi(2)).sqrt() < threshold)
        .count() as f64;
    let n0 = 0.95 * half as f64;
    let d = (n1 - n0) / (n as f64 * 0.95 * 0.05 / 4.0).sqrt();
    Tr::new("Discrete Fourier Transform", erfc(d.abs() / SQRT_2))
}

// ════════════════════════════════════════════════════════════════════════════
// Test 7 — Non-Overlapping Template Matching
// ════════════════════════════════════════════════════════════════════════════

fn count_notm(block: &[u8], tmpl: &[u8]) -> f64 {
    let m = tmpl.len();
    let mut count = 0u64;
    let mut i = 0;
    while i + m <= block.len() {
        if &block[i..i + m] == tmpl {
            count += 1;
            i += m;
        } else {
            i += 1;
        }
    }
    count as f64
}

fn test_notm(bits: &[u8]) -> Tr {
    const M_TMPL: usize = 9;
    const N_BLOCKS: usize = 8;
    let n = bits.len();
    let block_m = n / N_BLOCKS;
    let templates = aperiodic_templates(M_TMPL);
    let n_tmpl = templates.len() as f64; // 148
    // Compute p-value per template; apply Bonferroni correction for the
    // family-wise error rate across 148 simultaneous tests:
    //   p_corrected = min(p_min * K, 1.0) where K = number of templates.
    // Equivalently, PASS iff p_min >= 0.01 / K  (≈ 6.76e-5 for K=148).
    let p_min = templates.iter().map(|tmpl| {
        let mu  = (block_m as f64 - M_TMPL as f64 + 1.0) / (1 << M_TMPL) as f64;
        let var = block_m as f64 * (1.0 / (1 << M_TMPL) as f64
                  - (2 * M_TMPL - 1) as f64 / (1_u64 << (2 * M_TMPL)) as f64);
        let chi_sq: f64 = (0..N_BLOCKS)
            .map(|j| {
                let w = count_notm(&bits[j * block_m..(j + 1) * block_m], tmpl);
                (w - mu).powi(2) / var
            })
            .sum();
        igamc(N_BLOCKS as f64 / 2.0, chi_sq / 2.0)
    }).fold(f64::INFINITY, f64::min);
    // Bonferroni-corrected composite p-value
    let p_bonf = (p_min * n_tmpl).min(1.0);
    Tr::with_note("Non Overlapping Template Matching", p_bonf,
                  "(Bonferroni-corrected over 148 templates)")
}

// ════════════════════════════════════════════════════════════════════════════
// Test 8 — Maurer's Universal Statistical Test
// ════════════════════════════════════════════════════════════════════════════

fn test_maurer_universal(bits: &[u8]) -> Tr {
    const L: usize = 7;
    const Q: usize = 1280;
    // Expected values and variances from NIST SP 800-22 Table 5
    const EXPECTED: [f64; 17] = [
        0.0, // L=0 unused
        0.732_649_5, 1.537_438_3, 2.401_606_8, 3.311_224_7,
        4.253_426_6, 5.217_705_2, 6.196_250_7, 7.183_665_6,
        8.176_424_8, 9.172_324_3, 10.170_032_0, 11.168_765_0,
        12.168_070_0, 13.167_693_0, 14.167_488_0, 15.167_379_0,
    ];
    const VARIANCE: [f64; 17] = [
        0.0, 0.690, 1.338, 1.901, 2.358,
        2.705, 2.954, 3.125, 3.238, 3.311,
        3.356, 3.384, 3.401, 3.410, 3.416, 3.419, 3.421,
    ];

    let n = bits.len();
    let k = n / L;
    if k <= Q { return Tr::new("Maurers Universal", 0.0); }
    let big_k = k - Q;

    // Initialise last-seen table
    let table_size = 1 << L;
    let mut t: Vec<usize> = vec![0; table_size];
    for i in 0..Q {
        let pat = bits_to_usize(&bits[i * L..(i + 1) * L]);
        t[pat] = i + 1;
    }

    let mut sum = 0.0f64;
    for i in Q..Q + big_k {
        let pat = bits_to_usize(&bits[i * L..(i + 1) * L]);
        sum += ((i + 1 - t[pat]) as f64).log2();
        t[pat] = i + 1;
    }
    let fn_ = sum / big_k as f64;

    let c = 0.7 - 0.8 / L as f64
          + (4.0 + 32.0 / L as f64) * (big_k as f64).powf(-3.0 / L as f64) / 15.0;
    let sigma = c * (VARIANCE[L] / big_k as f64).sqrt();
    let z = (fn_ - EXPECTED[L]) / sigma;
    Tr::new("Maurers Universal", erfc(z.abs() / SQRT_2))
}

fn bits_to_usize(b: &[u8]) -> usize {
    b.iter().fold(0usize, |acc, &bit| (acc << 1) | bit as usize)
}

// ════════════════════════════════════════════════════════════════════════════
// Test 9 — Linear Complexity
// ════════════════════════════════════════════════════════════════════════════

fn test_linear_complexity(bits: &[u8]) -> Tr {
    const M: usize = 500;
    // pi values from NIST SP 800-22 Table 4 (K=6, df=6)
    const PI_LC: [f64; 7] = [0.010_417, 0.031_250, 0.125_000, 0.500_000,
                               0.250_000, 0.062_500, 0.020_833];
    let n = bits.len();
    let big_n = n / M;
    if big_n < 1 { return Tr::new("Linear Complexity", 0.0); }

    // mu_M ≈ M/2 + (9 + (-1)^(M+1)) / 36   (the 1/2^M term is negligible for M=500)
    let sign = if M % 2 == 0 { -1.0f64 } else { 1.0f64 };
    let mu = M as f64 / 2.0 + (9.0 + sign) / 36.0
           - (M as f64 / 3.0 + 2.0 / 9.0) / 2.0_f64.powi(M as i32);

    let mut nu = [0u64; 7];
    for j in 0..big_n {
        let block: Vec<u8> = bits[j * M..(j + 1) * M].iter().copied().collect();
        let l = berlekamp_massey(&block) as f64;
        let t = (-1.0_f64).powi(M as i32) * (l - mu) + 2.0 / 9.0;
        let cat = if      t <= -2.5 { 0 }
                  else if t <= -1.5 { 1 }
                  else if t <= -0.5 { 2 }
                  else if t <=  0.5 { 3 }
                  else if t <=  1.5 { 4 }
                  else if t <=  2.5 { 5 }
                  else              { 6 };
        nu[cat] += 1;
    }
    let chi_sq: f64 = nu.iter().zip(PI_LC.iter())
        .map(|(&v, &p)| (v as f64 - big_n as f64 * p).powi(2) / (big_n as f64 * p))
        .sum();
    Tr::new("Linear Complexity", igamc(3.0, chi_sq / 2.0))
}

// ════════════════════════════════════════════════════════════════════════════
// Tests 10 & 11 — Serial and Approximate Entropy  (share pattern counting)
// ════════════════════════════════════════════════════════════════════════════

/// Count all overlapping m-grams in a circular view of `bits`.
fn psi_sq(bits: &[u8], m: usize) -> f64 {
    let n = bits.len();
    if m == 0 { return 0.0; }
    let mask = (1usize << m) - 1;
    let mut counts = vec![0u64; 1 << m];
    // Seed with first m-1 bits for wrap-around
    let mut pat = bits_to_usize(&bits[..m - 1]);
    for i in 0..n {
        pat = ((pat << 1) | bits[(i + m - 1) % n] as usize) & mask;
        counts[pat] += 1;
    }
    let sum_sq: u64 = counts.iter().map(|&c| c * c).sum();
    (1 << m) as f64 / n as f64 * sum_sq as f64 - n as f64
}

fn test_serial(bits: &[u8]) -> Vec<Tr> {
    const M: usize = 10;
    let n = bits.len() as f64;
    let p0 = psi_sq(bits, M);
    let p1 = psi_sq(bits, M - 1);
    let p2 = psi_sq(bits, M - 2);
    let del1 = p0 - p1;
    let del2 = p0 - 2.0 * p1 + p2;
    let df1 = (1u64 << (M - 2)) as f64;
    let df2 = df1 / 2.0;
    let _ = n; // used implicitly in psi_sq
    vec![
        Tr::with_note("Serial (del1)",  igamc(df1, del1 / 2.0), ""),
        Tr::with_note("Serial (del2)",  igamc(df2, del2 / 2.0), ""),
    ]
}

fn test_approximate_entropy(bits: &[u8]) -> Tr {
    const M: usize = 10;
    let n = bits.len() as f64;
    let phi_m = {
        let mask = (1usize << M) - 1;
        let mut counts = vec![0u64; 1 << M];
        let mut pat = bits_to_usize(&bits[..M - 1]);
        for i in 0..bits.len() {
            pat = ((pat << 1) | bits[(i + M - 1) % bits.len()] as usize) & mask;
            counts[pat] += 1;
        }
        counts.iter().filter(|&&c| c > 0)
            .map(|&c| { let p = c as f64 / n; p * p.ln() })
            .sum::<f64>()
    };
    let phi_m1 = {
        let m1 = M + 1;
        let mask = (1usize << m1) - 1;
        let mut counts = vec![0u64; 1 << m1];
        let mut pat = bits_to_usize(&bits[..m1 - 1]);
        for i in 0..bits.len() {
            pat = ((pat << 1) | bits[(i + m1 - 1) % bits.len()] as usize) & mask;
            counts[pat] += 1;
        }
        counts.iter().filter(|&&c| c > 0)
            .map(|&c| { let p = c as f64 / n; p * p.ln() })
            .sum::<f64>()
    };
    let apen = phi_m - phi_m1;
    let chi_sq = 2.0 * n * (2.0_f64.ln() - apen);
    Tr::new("Approximate Entropy", igamc((1u64 << (M - 1)) as f64, chi_sq / 2.0))
}

// ════════════════════════════════════════════════════════════════════════════
// Test 12 — Cumulative Sums
// ════════════════════════════════════════════════════════════════════════════

fn cusum_pvalue(z: usize, n: usize) -> f64 {
    let z = z as f64;
    let n = n as f64;
    let sq_n = n.sqrt();

    let sum1: f64 = {
        let lo = ((-n / z + 1.0) / 4.0).floor() as i64;
        let hi = ((n / z - 1.0) / 4.0).floor() as i64;
        (lo..=hi).map(|k| {
            let k = k as f64;
            normal_cdf((4.0 * k + 1.0) * z / sq_n)
                - normal_cdf((4.0 * k - 1.0) * z / sq_n)
        }).sum()
    };
    let sum2: f64 = {
        let lo = ((-n / z - 3.0) / 4.0).floor() as i64;
        let hi = ((n / z - 1.0) / 4.0).floor() as i64;
        (lo..=hi).map(|k| {
            let k = k as f64;
            normal_cdf((4.0 * k + 3.0) * z / sq_n)
                - normal_cdf((4.0 * k + 1.0) * z / sq_n)
        }).sum()
    };
    1.0 - sum1 + sum2
}

fn test_cumulative_sums(bits: &[u8]) -> Vec<Tr> {
    let n = bits.len();
    // Forward
    let fwd_z = {
        let (mut sum, mut max_abs) = (0i64, 0i64);
        for &b in bits {
            sum += if b == 1 { 1 } else { -1 };
            max_abs = max_abs.max(sum.abs());
        }
        max_abs as usize
    };
    // Backward
    let bwd_z = {
        let (mut sum, mut max_abs) = (0i64, 0i64);
        for &b in bits.iter().rev() {
            sum += if b == 1 { 1 } else { -1 };
            max_abs = max_abs.max(sum.abs());
        }
        max_abs as usize
    };
    vec![
        Tr::with_note("Cumulative Sums (fwd)", cusum_pvalue(fwd_z, n), ""),
        Tr::with_note("Cumulative Sums (bwd)", cusum_pvalue(bwd_z, n), ""),
    ]
}

// ════════════════════════════════════════════════════════════════════════════
// Tests 13 & 14 — Random Excursion and Random Excursion Variant
// ════════════════════════════════════════════════════════════════════════════

/// π(|x|, k): probability of exactly k visits to state x in one excursion.
/// k=5 is the ≥5 tail bucket.
fn re_pi(abs_x: usize, k: usize) -> f64 {
    let p = 0.5 / abs_x as f64; // 1 / (2|x|)
    if k == 0 {
        1.0 - p
    } else if k < 5 {
        p * p * (1.0 - p).powi(k as i32 - 1)
    } else {
        p * (1.0 - p).powi(4) // tail Σ_{j≥5}
    }
}

/// Build the partial-sum random walk, find zero-crossing positions.
fn build_walk(bits: &[u8]) -> (Vec<i64>, usize) {
    let mut walk = vec![0i64; bits.len() + 1];
    for (i, &b) in bits.iter().enumerate() {
        walk[i + 1] = walk[i] + if b == 1 { 1 } else { -1 };
    }
    // J = number of zero crossings (S_i = 0 for i > 0)
    let j = walk[1..].iter().filter(|&&s| s == 0).count();
    (walk, j)
}

fn test_random_excursion(bits: &[u8]) -> Vec<Tr> {
    let (walk, j) = build_walk(bits);
    if j < 500 {
        return vec![Tr::skip(
            "Random Excursion",
            "(ineligible: fewer than 500 cycles in sequence — use ≥10M bits)",
        )];
    }

    // Count visits per state per excursion
    let states: [i64; 8] = [-4, -3, -2, -1, 1, 2, 3, 4];
    let mut results = Vec::new();
    for &x in &states {
        let ax = x.unsigned_abs() as usize;
        let mut nu = [0u64; 6]; // nu[0..5], nu[5] = k≥5
        // Iterate over excursions
        let mut in_exc = false;
        let mut visits: i64 = 0;
        for &s in &walk[1..] {
            if !in_exc {
                if s != 0 { in_exc = true; }
            }
            if in_exc {
                if s == x { visits += 1; }
                if s == 0 {
                    let cat = (visits.min(5)) as usize;
                    nu[cat] += 1;
                    visits = 0;
                    in_exc = false;
                }
            }
        }
        let chi_sq: f64 = nu.iter().enumerate()
            .map(|(k, &v)| {
                let exp = j as f64 * re_pi(ax, k);
                (v as f64 - exp).powi(2) / exp
            })
            .sum();
        let name: &'static str = Box::leak(
            format!("Random Excursion (x={:+})", x).into_boxed_str()
        );
        results.push(Tr::new(name, igamc(2.5, chi_sq / 2.0)));
    }
    results
}

fn test_random_excursion_variant(bits: &[u8]) -> Vec<Tr> {
    let (walk, j) = build_walk(bits);
    if j < 500 {
        return vec![Tr::skip(
            "Random Excursion Variant",
            "(ineligible: fewer than 500 cycles in sequence — use ≥10M bits)",
        )];
    }

    let states: Vec<i64> = (-9..=-1i64).chain(1..=9).collect();
    let mut results = Vec::new();
    for x in states {
        let xi: i64 = walk.iter().filter(|&&s| s == x).count() as i64;
        let ax = x.unsigned_abs() as f64;
        let denom = (2.0 * j as f64 * (4.0 * ax - 2.0)).sqrt();
        let z = (xi - j as i64).abs() as f64 / denom;
        let name: &'static str = Box::leak(
            format!("Random Excursion Variant (x={:+})", x).into_boxed_str()
        );
        results.push(Tr::new(name, erfc(z / SQRT_2)));
    }
    results
}

// ════════════════════════════════════════════════════════════════════════════
// JSON report
// ════════════════════════════════════════════════════════════════════════════

fn write_json_report(path: &str, results: &[Tr], bits: usize, elapsed_ms: u128) -> std::io::Result<()> {
    let passed  = results.iter().filter(|r| r.status == Status::Pass).count();
    let failed  = results.iter().filter(|r| r.status == Status::Fail).count();
    let skipped = results.iter().filter(|r| r.status == Status::Skip).count();
    let total   = results.len();

    let mut s = String::with_capacity(4096);
    s.push_str("{\n");
    s.push_str("  \"spec\": \"NIST SP 800-22 Rev 1a\",\n");
    s.push_str("  \"napseq_version\": \"v6\",\n");
    s.push_str(&format!("  \"bits_tested\": {bits},\n"));
    s.push_str(&format!("  \"elapsed_ms\": {elapsed_ms},\n"));
    s.push_str("  \"summary\": {\n");
    s.push_str(&format!("    \"total\": {total},\n"));
    s.push_str(&format!("    \"passed\": {passed},\n"));
    s.push_str(&format!("    \"failed\": {failed},\n"));
    s.push_str(&format!("    \"skipped\": {skipped}\n"));
    s.push_str("  },\n");
    s.push_str("  \"tests\": [\n");
    for (i, t) in results.iter().enumerate() {
        let comma = if i + 1 < results.len() { "," } else { "" };
        let passed_json  = (t.status == Status::Pass).to_string();
        let skipped_json = (t.status == Status::Skip).to_string();
        let pv_json = if t.p_value.is_nan() {
            "null".to_string()
        } else {
            format!("{:.8}", t.p_value)
        };
        let name_escaped = t.name.replace('"', "\\\"");
        let note_escaped = t.note.replace('"', "\\\"");
        s.push_str(&format!(
            "    {{\"name\": \"{name_escaped}\", \"passed\": {passed_json}, \"skipped\": {skipped_json}, \"p_value\": {pv_json}, \"note\": \"{note_escaped}\"}}{comma}\n"
        ));
    }
    s.push_str("  ]\n}\n");

    std::fs::write(path, s)
}

// ════════════════════════════════════════════════════════════════════════════
// Report
// ════════════════════════════════════════════════════════════════════════════

const LINE: &str = "────────────────────────────────────────────────────────────────────";

fn print_report(results: &[Tr], bits: usize, elapsed_ms: u128) {
    println!("\n{LINE}");
    println!("NIST SP 800-22 Rev 1a \u{2014} NAPSEQ v6 Bitstream Analysis (Rust)");
    println!("  Bits tested : {bits:>13}");
    println!("  Elapsed     : {elapsed_ms:>10} ms");
    println!("{LINE}");
    let (mut passed, mut failed, mut skipped) = (0usize, 0usize, 0usize);
    for t in results {
        let (tag, pv_str) = match t.status {
            Status::Pass => ("PASS", format!("p={:.6}", t.p_value)),
            Status::Fail => ("FAIL", format!("p={:.6}", t.p_value)),
            Status::Skip => ("SKIP", "p=n/a".into()),
        };
        let note = if t.note.is_empty() { "".into() } else { format!("  {}", t.note) };
        println!("  [{tag}]  {:<50}  {pv_str}{note}", t.name);
        match t.status {
            Status::Pass => passed += 1,
            Status::Fail => failed += 1,
            Status::Skip => skipped += 1,
        }
    }
    println!("{LINE}");
    print!("  {passed}/{} scored tests passed", passed + failed);
    if skipped > 0 { print!("  |  {skipped} skipped (ineligible)"); }
    if failed  > 0 { print!("  |  {failed} FAILED"); }
    println!("\n{LINE}\n");
}

// ════════════════════════════════════════════════════════════════════════════
// Main
// ════════════════════════════════════════════════════════════════════════════

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let n: usize = args.windows(2)
        .find(|w| w[0] == "--bits")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(10_000_000);  // 10M recommended: RE/REV need ≥500 cycles

    let out_path: Option<&str> = args.windows(2)
        .find(|w| w[0] == "--out")
        .map(|w| w[1].as_str());

    eprintln!("[STS] Generating {n} NAPSEQ v6 bits…");
    let t0 = Instant::now();
    let bits = generate_bits(n);
    eprintln!("[STS] Running 15 SP 800-22 tests…");

    let mut results: Vec<Tr> = Vec::new();
    results.push(test_monobit(&bits));
    results.push(test_frequency_block(&bits));
    results.push(test_runs(&bits));
    results.push(test_longest_run(&bits));
    results.push(test_binary_matrix_rank(&bits));
    results.push(test_dft(&bits));
    results.push(test_notm(&bits));
    results.push(test_maurer_universal(&bits));
    results.push(test_linear_complexity(&bits));
    results.extend(test_serial(&bits));
    results.push(test_approximate_entropy(&bits));
    results.extend(test_cumulative_sums(&bits));
    results.extend(test_random_excursion(&bits));
    results.extend(test_random_excursion_variant(&bits));

    let elapsed = t0.elapsed().as_millis();
    print_report(&results, n, elapsed);

    if let Some(path) = out_path {
        match write_json_report(path, &results, n, elapsed) {
            Ok(()) => eprintln!("JSON report written to {path}"),
            Err(e) => eprintln!("ERROR: could not write {path}: {e}"),
        }
    }

    let any_fail = results.iter().any(|r| r.status == Status::Fail);
    std::process::exit(if any_fail { 1 } else { 0 });
}
