//! Phase-7 negative tests: mutations, truncation, wrong key/message.

use vorb3::keys::{ExpandedSecretKey, PublicKey, SecretKey};
use vorb3::sign::verify;
use vorb3::signature::Signature;

const SEED: &[u8; 36] = include_bytes!("../../kat/seed_sp288_35.bin");
const EXPECTED_PK: &[u8; 72] = include_bytes!("../../kat/pk_sp288_35.bin");
const EXPECTED_SIG: &[u8; 13_672] = include_bytes!("../../kat/sign_sp288_35.bin");
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";

fn kat_public_key() -> Option<PublicKey> {
    let seed: [u8; 36] = *SEED;
    let compact = SecretKey::from_seed(seed);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let result = expanded.public_key();
    assert!(result.is_ok(), "KAT public key derivation failed");
    result.ok()
}

fn kat_signature() -> Option<Signature> {
    let result = Signature::from_bytes(EXPECTED_SIG);
    assert!(result.is_ok(), "KAT signature parse failed");
    result.ok()
}

#[test]
fn mutation_and_length_rejection() {
    let Some(public) = kat_public_key() else {
        return;
    };
    let Some(signature) = kat_signature() else {
        return;
    };
    assert!(verify(MESSAGE, &public, &signature).is_ok());
    assert!(verify(b"wrong message", &public, &signature).is_err());

    let positions = [
        0usize, 1, 63, 64, 127, 128, 1_243, 1_244, 1_279, 1_280, 1_315, 1_316, 1_351, 1_352,
        11_431, 11_432, 13_671,
    ];
    for position in positions {
        let mut mutated = *EXPECTED_SIG;
        if let Some(byte) = mutated.get_mut(position) {
            *byte ^= 0x01;
        }
        let Ok(candidate) = Signature::from_bytes(&mutated) else {
            continue;
        };
        assert!(verify(MESSAGE, &public, &candidate).is_err());
    }

    let short_len = EXPECTED_SIG.len().wrapping_sub(1);
    let short = EXPECTED_SIG.get(..short_len).unwrap_or(&[]);
    assert!(Signature::from_bytes(short).is_err());

    let mut long = [0u8; 13_673];
    if let Some(destination) = long.get_mut(..13_672) {
        destination.copy_from_slice(EXPECTED_SIG);
    }
    assert!(Signature::from_bytes(&long).is_err());

    let zero = [0u8; 13_672];
    let zero_result = Signature::from_bytes(&zero);
    assert!(zero_result.is_ok(), "zero signature parse failed");
    let Ok(zero_signature) = zero_result else {
        return;
    };
    assert!(verify(MESSAGE, &public, &zero_signature).is_err());
}

#[test]
fn wrong_public_key_rejected() {
    let mut bytes = *EXPECTED_PK;
    if let Some(byte) = bytes.get_mut(0) {
        *byte ^= 0x01;
    }
    let Ok(public) = PublicKey::from_bytes(bytes) else {
        return;
    };
    let Some(signature) = kat_signature() else {
        return;
    };
    assert!(verify(MESSAGE, &public, &signature).is_err());
}
