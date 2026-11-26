//! Local adversarial harness for VORB3-SP1. Not a demo and not shipped.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use vorb3::keys::{ExpandedSecretKey, PublicKey, SecretKey};
use vorb3::sign::{sign_into, verify_bytes};

const SEED: &[u8; 36] = include_bytes!("../../../kat/seed_sp288_35.bin");
const EXPECTED_PK: &[u8; 72] = include_bytes!("../../../kat/pk_sp288_35.bin");
const EXPECTED_SIG: &[u8; 13_672] = include_bytes!("../../../kat/sign_sp288_35.bin");
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";

fn public_key() -> PublicKey {
    match PublicKey::from_bytes(*EXPECTED_PK) {
        Ok(public) => public,
        Err(_) => {
            eprintln!("invalid KAT public key");
            std::process::exit(2);
        }
    }
}

fn bitflip() {
    let public = public_key();
    assert!(
        verify_bytes(MESSAGE, &public, EXPECTED_SIG).is_ok(),
        "KAT rejected"
    );
    let failed = AtomicBool::new(false);
    let checked = AtomicUsize::new(0);
    let threads = 16usize;
    let bytes = EXPECTED_SIG.len();
    std::thread::scope(|scope| {
        for worker in 0..threads {
            let failed = &failed;
            let checked = &checked;
            scope.spawn(move || {
                let start = worker * bytes / threads;
                let end = (worker + 1) * bytes / threads;
                for byte_index in start..end {
                    for bit in 0..8u8 {
                        let mut mutated = *EXPECTED_SIG;
                        if let Some(byte) = mutated.get_mut(byte_index) {
                            *byte ^= 1u8 << bit;
                        }
                        if verify_bytes(MESSAGE, &public, &mutated).is_ok() {
                            failed.store(true, Ordering::Relaxed);
                            eprintln!("ACCEPTED mutation at byte {byte_index} bit {bit}");
                        }
                        checked.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let count = checked.load(Ordering::Relaxed);
    if failed.load(Ordering::Relaxed) {
        eprintln!("BITFLIP FAILED after {count} mutations");
        std::process::exit(1);
    }
    println!("BITFLIP PASS: {count} single-bit mutations rejected");
}

fn key_from_seed(seed: [u8; 36]) -> ExpandedSecretKey {
    let compact = SecretKey::from_seed(seed);
    ExpandedSecretKey::from_seed(&compact)
}

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let n = a.len() as f64;
    let m = b.len() as f64;
    let mean_a = a.iter().sum::<f64>() / n;
    let mean_b = b.iter().sum::<f64>() / m;
    let var_a = a.iter().map(|x| (x - mean_a) * (x - mean_a)).sum::<f64>() / (n - 1.0);
    let var_b = b.iter().map(|x| (x - mean_b) * (x - mean_b)).sum::<f64>() / (m - 1.0);
    (mean_a - mean_b) / (var_a / n + var_b / m).sqrt()
}

fn dudect(samples: usize) {
    let fixed = key_from_seed(*SEED);
    let mut other_seed = *SEED;
    if let Some(byte) = other_seed.get_mut(0) {
        *byte ^= 0x5A;
    }
    let other = key_from_seed(other_seed);
    let mut fixed_times = Vec::with_capacity(samples / 2);
    let mut other_times = Vec::with_capacity(samples / 2);
    for index in 0..samples {
        let mut signature = [0u8; 13_672];
        let key = if index & 1 == 0 { &fixed } else { &other };
        let start = Instant::now();
        let result = sign_into(MESSAGE, key, &[0u8; 32], &mut signature);
        let elapsed = start.elapsed().as_nanos() as f64;
        assert!(result.is_ok());
        if index & 1 == 0 {
            fixed_times.push(elapsed);
        } else {
            other_times.push(elapsed);
        }
    }
    let t = welch_t(&fixed_times, &other_times);
    println!("DUDECT smoke: n={samples}, Welch t={t:.3}");
}

fn bench() {
    let key = key_from_seed(*SEED);
    let public = public_key();
    let mut signature = [0u8; 13_672];
    let start = Instant::now();
    for _ in 0..10 {
        assert!(sign_into(MESSAGE, &key, &[0u8; 32], &mut signature).is_ok());
    }
    let sign_time = start.elapsed() / 10;
    let start = Instant::now();
    for _ in 0..10 {
        assert!(verify_bytes(MESSAGE, &public, &signature).is_ok());
    }
    let verify_time = start.elapsed() / 10;
    println!("BENCH sign={sign_time:?} verify={verify_time:?}");
}

fn stress(iterations: usize) {
    let public = public_key();
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut accepted = 0usize;
    for _ in 0..iterations {
        let mut mutated = *EXPECTED_SIG;
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let index = usize::try_from(state % 13_672).unwrap_or(0);
        state = state.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        if let Some(byte) = mutated.get_mut(index) {
            *byte ^= u8::try_from(state & 0xFF).unwrap_or(1) | 1;
        }
        if verify_bytes(MESSAGE, &public, &mutated).is_ok() {
            accepted += 1;
        }
    }
    if accepted != 0 {
        eprintln!("STRESS FAILED: {accepted} mutations accepted");
        std::process::exit(1);
    }
    println!("STRESS PASS: {iterations} random mutations rejected");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("bitflip") => bitflip(),
        Some("dudect") => {
            let n = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2_000);
            dudect(n);
        }
        Some("stress") => {
            let n = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10_000);
            stress(n);
        }
        Some("bench") | None => bench(),
        Some(other) => {
            eprintln!("unknown command: {other}");
            std::process::exit(2);
        }
    }
}
