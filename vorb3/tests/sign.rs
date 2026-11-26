//! End-to-end SP-288/35 signature KAT against the independent Python model.
use vorb3::keys::{ExpandedSecretKey, SecretKey};
use vorb3::sign::{sign, verify};
use vorb3::signature::Signature;

const SEED: &[u8; 36] = include_bytes!("../../kat/seed_sp288_35.bin");
const EXPECTED_PK: &[u8; 72] = include_bytes!("../../kat/pk_sp288_35.bin");
const EXPECTED_SIG: &[u8; 13_672] = include_bytes!("../../kat/sign_sp288_35.bin");
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";

#[test]
fn sign_and_verify_kat() {
    let seed: [u8; 36] = *SEED;
    let compact = SecretKey::from_seed(seed);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let public_result = expanded.public_key();
    assert!(public_result.is_ok(), "public key derivation failed");
    let Ok(public) = public_result else {
        return;
    };
    assert_eq!(public.as_bytes(), EXPECTED_PK);

    let signature_result = sign(MESSAGE, &expanded, &[0u8; 32]);
    assert!(signature_result.is_ok(), "sign failed");
    let Ok(signature) = signature_result else {
        return;
    };
    for (left, right) in signature.as_bytes().iter().zip(EXPECTED_SIG.iter()) {
        assert_eq!(left, right);
    }

    assert!(verify(MESSAGE, &public, &signature).is_ok());
    assert!(verify(b"different message", &public, &signature).is_err());
    let expected_result = Signature::from_bytes(EXPECTED_SIG);
    assert!(expected_result.is_ok(), "KAT signature parse failed");
    let Ok(expected) = expected_result else {
        return;
    };
    assert!(verify(MESSAGE, &public, &expected).is_ok());
}
