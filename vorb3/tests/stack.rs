//! Stack-bound smoke tests for the sign and verify paths separately.
//!
//! The release internal-working-set target is 32 KiB; debug builds use 64 KiB
//! because unoptimized frames are larger. The 13,672-byte signature output
//! buffer is caller-owned; the sign test places it on the heap so the
//! measurement covers library temporaries, not the output buffer.

use vorb3::keys::{ExpandedSecretKey, SecretKey};
use vorb3::sign::{sign_into, verify_bytes};

const SEED: &[u8; 36] = include_bytes!("../../kat/seed_sp288_35.bin");
const EXPECTED_SIG: &[u8; 13_672] = include_bytes!("../../kat/sign_sp288_35.bin");
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";

fn configured_stack() -> usize {
    if let Ok(kb) = std::env::var("VORB3_STACK_KB")
        && let Ok(kb) = kb.parse::<usize>()
    {
        return kb.saturating_mul(1024);
    }
    if cfg!(debug_assertions) {
        64 * 1024
    } else {
        32 * 1024
    }
}

fn run_on_stack_bytes<F>(bytes: usize, work: F)
where
    F: FnOnce() + Send + 'static,
{
    let spawn_result = std::thread::Builder::new().stack_size(bytes).spawn(work);
    assert!(spawn_result.is_ok(), "stack thread could not be created");
    let Ok(handle) = spawn_result else {
        return;
    };
    assert!(handle.join().is_ok(), "stack worker panicked");
}

fn run_on_stack<F>(work: F)
where
    F: FnOnce() + Send + 'static,
{
    run_on_stack_bytes(configured_stack(), work);
}

#[test]
fn sign_in_32k_stack_heap_output() {
    run_on_stack(|| {
        let seed: [u8; 36] = *SEED;
        let compact = SecretKey::from_seed(seed);
        let expanded = ExpandedSecretKey::from_seed(&compact);
        let mut storage = std::vec![0u8; 13_672];
        let slice: &mut [u8] = &mut storage;
        let Ok(signature) = <&mut [u8; 13_672]>::try_from(slice) else {
            return;
        };
        let result = sign_into(MESSAGE, &expanded, &[0u8; 32], signature);
        assert!(result.is_ok(), "sign_into failed");
    });
}

#[test]
fn sign_in_64k_stack_with_stack_output() {
    run_on_stack_bytes(configured_stack().max(64 * 1024), || {
        let seed: [u8; 36] = *SEED;
        let compact = SecretKey::from_seed(seed);
        let expanded = ExpandedSecretKey::from_seed(&compact);
        let mut signature = [0u8; 13_672];
        let result = sign_into(MESSAGE, &expanded, &[0u8; 32], &mut signature);
        assert!(result.is_ok(), "sign_into failed");
    });
}

#[test]
fn verify_in_32k_stack() {
    run_on_stack(|| {
        let seed: [u8; 36] = *SEED;
        let compact = SecretKey::from_seed(seed);
        let expanded = ExpandedSecretKey::from_seed(&compact);
        let public_result = expanded.public_key();
        assert!(public_result.is_ok(), "public key failed");
        let Ok(public) = public_result else {
            return;
        };
        assert!(verify_bytes(MESSAGE, &public, EXPECTED_SIG).is_ok());
        assert!(verify_bytes(b"wrong message", &public, EXPECTED_SIG).is_err());
    });
}
