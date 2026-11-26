#![no_main]

use libfuzzer_sys::fuzz_target;
use vorb3::keys::{ExpandedSecretKey, SecretKey};
use vorb3::sign::{sign_into, verify_bytes};
use vorb3::SIGNATURE_LEN;

const SEED_LEN: usize = 36;
const ENTROPY_LEN: usize = 32;
const PREFIX: usize = SEED_LEN + ENTROPY_LEN;

fuzz_target!(|data: &[u8]| {
    let mut seed = [0u8; SEED_LEN];
    let mut entropy = [0u8; ENTROPY_LEN];
    for (index, slot) in seed.iter_mut().enumerate() {
        *slot = data.get(index).copied().unwrap_or(0);
    }
    for (index, slot) in entropy.iter_mut().enumerate() {
        *slot = data.get(SEED_LEN + index).copied().unwrap_or(0);
    }
    let message = data.get(PREFIX..).unwrap_or(&[]);
    let compact = SecretKey::from_seed(seed);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let Ok(public) = expanded.public_key() else {
        return;
    };
    let mut signature = [0u8; SIGNATURE_LEN];
    if sign_into(message, &expanded, &entropy, &mut signature).is_ok() {
        assert!(verify_bytes(message, &public, &signature).is_ok());
        assert!(verify_bytes(b"wrong-message", &public, &signature).is_err());
    }
});
