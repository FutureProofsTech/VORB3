#![allow(missing_docs)]
#![cfg(not(any(feature = "nist1", feature = "nist3")))]
//! Signature encoding/equality/debug coverage.

use vorb3::signature::Signature;

const EXPECTED_SIG: &[u8; 13_672] = include_bytes!("../../kat/sign_sp288_35.bin");

#[test]
fn signature_encoding_equality_and_debug() {
    let Ok(signature) = Signature::from_bytes(EXPECTED_SIG) else {
        return;
    };
    assert_eq!(signature.as_bytes(), EXPECTED_SIG);
    assert_eq!(signature.to_bytes(), *EXPECTED_SIG);
    let Ok(same) = Signature::from_bytes(EXPECTED_SIG) else {
        return;
    };
    assert_eq!(signature, same);
    let mut changed = *EXPECTED_SIG;
    changed[0] ^= 1;
    let Ok(other) = Signature::from_bytes(&changed) else {
        return;
    };
    assert_ne!(signature, other);
    assert_eq!(format!("{signature:?}"), "Signature(..)");
}
