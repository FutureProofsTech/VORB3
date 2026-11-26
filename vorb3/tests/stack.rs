//! Stack-bound smoke tests for the sign and verify paths separately.

use vorb3::keys::{ExpandedSecretKey, SecretKey};
use vorb3::sign::{sign_into, verify_bytes};

const SEED: &[u8; 36] = include_bytes!("../../kat/seed_sp288_35.bin");
const EXPECTED_SIG: &[u8; 13_672] = include_bytes!("../../kat/sign_sp288_35.bin");
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";

fn run_on_64k<F>(work: F)
where
    F: FnOnce() + Send + 'static,
{
    let spawn_result = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(work);
    assert!(
        spawn_result.is_ok(),
        "64 KiB stack thread could not be created"
    );
    let Ok(handle) = spawn_result else {
        return;
    };
    assert!(handle.join().is_ok(), "64 KiB worker panicked");
}

#[test]
fn sign_in_64k_stack() {
    run_on_64k(|| {
        let seed: [u8; 36] = *SEED;
        let compact = SecretKey::from_seed(seed);
        let expanded = ExpandedSecretKey::from_seed(&compact);
        let mut signature = [0u8; 13_672];
        let result = sign_into(MESSAGE, &expanded, &[0u8; 32], &mut signature);
        assert!(result.is_ok(), "sign_into failed");
    });
}

#[test]
fn verify_in_64k_stack() {
    run_on_64k(|| {
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
