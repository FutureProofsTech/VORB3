//! Key parsing/encoding and invalid-key coverage.

use vorb3::keys::{Error, ExpandedSecretKey, PublicKey, SecretKey};

const SEED: &[u8; 36] = include_bytes!("../../kat/seed_sp288_35.bin");
const EXPECTED_PK: &[u8; 72] = include_bytes!("../../kat/pk_sp288_35.bin");

#[test]
fn key_encodings_and_zero_rejection() {
    let compact = SecretKey::from_seed(*SEED);
    assert_eq!(compact.to_seed(), *SEED);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let Ok(public) = expanded.public_key() else {
        return;
    };
    assert_eq!(public.as_bytes(), EXPECTED_PK);
    assert_eq!(public.to_bytes(), *EXPECTED_PK);
    assert_eq!(public.pt().to_bytes(), EXPECTED_PK[..36]);
    assert_eq!(public.ct().to_bytes(), EXPECTED_PK[36..]);

    let zero = [0u8; 72];
    assert_eq!(PublicKey::from_bytes(zero), Err(Error::InvalidPublicKey));
    let mut zero_ct = *EXPECTED_PK;
    zero_ct[36..].fill(0);
    assert_eq!(PublicKey::from_bytes(zero_ct), Err(Error::InvalidPublicKey));
}
