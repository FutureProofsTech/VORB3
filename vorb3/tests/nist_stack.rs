#![allow(missing_docs)]
#![cfg(any(feature = "nist1", feature = "nist3"))]
//! 32 KiB stack tests for the NIST-tier packs.

use vorb3::SIGNATURE_LEN;
use vorb3::keys::{ExpandedSecretKey, SecretKey};
use vorb3::sign::{sign_into, verify_bytes};

#[cfg(feature = "nist1")]
const SEED: &[u8] = include_bytes!("../../kat/seed_sp160_32.bin");
#[cfg(feature = "nist1")]
const EXPECTED_SIG: &[u8] = include_bytes!("../../kat/sign_sp160_32.bin");
#[cfg(feature = "nist1")]
const MESSAGE: &[u8] = b"VORB3 phase-0 SP160_32";

#[cfg(feature = "nist3")]
const SEED: &[u8] = include_bytes!("../../kat/seed_sp224_32.bin");
#[cfg(feature = "nist3")]
const EXPECTED_SIG: &[u8] = include_bytes!("../../kat/sign_sp224_32.bin");
#[cfg(feature = "nist3")]
const MESSAGE: &[u8] = b"VORB3 phase-0 SP224_32";

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

fn seed() -> [u8; vorb3::FIELD_BYTES] {
    SEED.try_into().unwrap_or([0u8; vorb3::FIELD_BYTES])
}

#[test]
#[ignore = "run separately with VORB3_STACK_KB"]
fn sign_in_32k_stack_heap_output() {
    run_on_stack_bytes(configured_stack(), || {
        let compact = SecretKey::from_seed(seed());
        let expanded = ExpandedSecretKey::from_seed(&compact);
        let mut storage = std::vec![0u8; SIGNATURE_LEN];
        let slice: &mut [u8] = &mut storage;
        let Ok(signature) = <&mut [u8; SIGNATURE_LEN]>::try_from(slice) else {
            return;
        };
        assert!(sign_into(MESSAGE, &expanded, &[0u8; 32], signature).is_ok());
    });
}

#[test]
#[ignore = "run separately with VORB3_STACK_KB"]
fn sign_in_64k_stack_with_stack_output() {
    run_on_stack_bytes(configured_stack().max(64 * 1024), || {
        let compact = SecretKey::from_seed(seed());
        let expanded = ExpandedSecretKey::from_seed(&compact);
        let mut signature = [0u8; SIGNATURE_LEN];
        assert!(sign_into(MESSAGE, &expanded, &[0u8; 32], &mut signature).is_ok());
    });
}

#[test]
#[ignore = "run separately with VORB3_STACK_KB"]
fn verify_in_32k_stack() {
    run_on_stack_bytes(configured_stack(), || {
        let compact = SecretKey::from_seed(seed());
        let expanded = ExpandedSecretKey::from_seed(&compact);
        let Ok(public) = expanded.public_key() else {
            return;
        };
        let expected: [u8; SIGNATURE_LEN] = EXPECTED_SIG.try_into().unwrap_or([0u8; SIGNATURE_LEN]);
        assert!(verify_bytes(MESSAGE, &public, &expected).is_ok());
        assert!(verify_bytes(b"wrong message", &public, &expected).is_err());
    });
}
