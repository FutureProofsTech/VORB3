//! Phase-7 negative tests: mutations, truncation, wrong key/message.

use vorb3::keys::{ExpandedSecretKey, PublicKey, SecretKey};
use vorb3::sign::{sign_into, verify};
use vorb3::signature::Signature;

const SEED: &[u8; 36] = include_bytes!("../../kat/seed_sp288_35.bin");
const EXPECTED_PK: &[u8; 72] = include_bytes!("../../kat/pk_sp288_35.bin");
const EXPECTED_SIG: &[u8; 13_672] = include_bytes!("../../kat/sign_sp288_35.bin");
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";
// KAT secret derived from SEED by the independent model; used only to scan the
// signature output for accidental disclosure.
const EXPECTED_SK: [u8; 36] = [
    0x4e, 0x35, 0xc5, 0x04, 0xb9, 0x1d, 0x32, 0x35, 0xa0, 0x61, 0xe4, 0x89, 0xd6, 0x6a, 0x47, 0x46,
    0x02, 0xa1, 0x29, 0x14, 0x96, 0x88, 0x4a, 0x24, 0x41, 0xf6, 0xcc, 0xa3, 0x56, 0x3b, 0xaf, 0xfb,
    0x01, 0x8f, 0x2e, 0x09,
];

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
fn signature_buffer_canary_and_secret_scan() {
    let seed: [u8; 36] = *SEED;
    let compact = SecretKey::from_seed(seed);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let guard = 256usize;
    let mut storage = std::vec![0xA5u8; 13_672 + 2 * guard];
    let (prefix, rest) = storage.split_at_mut(guard);
    let (middle, suffix) = rest.split_at_mut(13_672);
    let Ok(signature) = <&mut [u8; 13_672]>::try_from(middle) else {
        return;
    };
    let result = sign_into(MESSAGE, &expanded, &[0u8; 32], signature);
    assert!(result.is_ok(), "sign_into failed");
    assert!(
        prefix.iter().all(|byte| *byte == 0xA5),
        "prefix canary changed"
    );
    assert!(
        suffix.iter().all(|byte| *byte == 0xA5),
        "suffix canary changed"
    );
    for (left, right) in signature.iter().zip(EXPECTED_SIG.iter()) {
        assert_eq!(left, right);
    }
    for window in SEED.windows(16) {
        assert!(
            !signature.windows(16).any(|candidate| candidate == window),
            "secret seed fragment leaked into signature"
        );
    }
    for window in EXPECTED_SK.windows(16) {
        assert!(
            !signature.windows(16).any(|candidate| candidate == window),
            "expanded secret-key fragment leaked into signature"
        );
    }
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
