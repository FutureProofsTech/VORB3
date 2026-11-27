#![allow(missing_docs)]
#![cfg(any(feature = "nist1", feature = "nist3"))]
//! Profile KAT and differential tests for the NIST-tier packs.

use vorb3::field::F288;
use vorb3::keys::{ExpandedSecretKey, PublicKey, SecretKey};
use vorb3::sign::{sign, sign_into, verify, verify_bytes};
use vorb3::signature::Signature;
use vorb3::{FIELD_BYTES, PUBLIC_KEY_LEN, SIGNATURE_LEN};

#[cfg(feature = "nist1")]
const SEED: &[u8] = include_bytes!("../../kat/seed_sp160_32.bin");
#[cfg(feature = "nist1")]
const PUBLIC: &[u8] = include_bytes!("../../kat/pk_sp160_32.bin");
#[cfg(feature = "nist1")]
const SIGNATURE: &[u8] = include_bytes!("../../kat/sign_sp160_32.bin");
#[cfg(feature = "nist1")]
const SIGN_DIFF: &[u8] = include_bytes!("../../kat/sign_diff_sp160_32.bin");
#[cfg(feature = "nist1")]
const FIELD_DIFF: &[u8] = include_bytes!("../../kat/field_sp160_32_diff.bin");
#[cfg(feature = "nist1")]
const MESSAGE: &[u8] = b"VORB3 phase-0 SP160_32";

#[cfg(feature = "nist3")]
const SEED: &[u8] = include_bytes!("../../kat/seed_sp224_32.bin");
#[cfg(feature = "nist3")]
const PUBLIC: &[u8] = include_bytes!("../../kat/pk_sp224_32.bin");
#[cfg(feature = "nist3")]
const SIGNATURE: &[u8] = include_bytes!("../../kat/sign_sp224_32.bin");
#[cfg(feature = "nist3")]
const SIGN_DIFF: &[u8] = include_bytes!("../../kat/sign_diff_sp224_32.bin");
#[cfg(feature = "nist3")]
const FIELD_DIFF: &[u8] = include_bytes!("../../kat/field_sp224_32_diff.bin");
#[cfg(feature = "nist3")]
const MESSAGE: &[u8] = b"VORB3 phase-0 SP224_32";

const RECORD_LEN: usize = 4 * FIELD_BYTES;

fn profile_seed() -> Option<[u8; FIELD_BYTES]> {
    SEED.try_into().ok()
}

fn profile_public() -> Option<[u8; PUBLIC_KEY_LEN]> {
    PUBLIC.try_into().ok()
}

fn profile_signature() -> Option<[u8; SIGNATURE_LEN]> {
    SIGNATURE.try_into().ok()
}

#[test]
fn profile_constants_and_kat() {
    assert_eq!(PUBLIC.len(), PUBLIC_KEY_LEN);
    assert_eq!(SIGNATURE.len(), SIGNATURE_LEN);
    assert_eq!(
        SIGNATURE_LEN,
        128 + 34 * FIELD_BYTES + 32 * (8 * FIELD_BYTES + 64)
    );
    let seed = profile_seed().unwrap_or([0u8; FIELD_BYTES]);
    let public_bytes = profile_public().unwrap_or([0u8; PUBLIC_KEY_LEN]);
    let expected = profile_signature().unwrap_or([0u8; SIGNATURE_LEN]);
    let compact = SecretKey::from_seed(seed);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let Ok(public) = expanded.public_key() else {
        return;
    };
    assert_eq!(public.as_bytes(), &public_bytes);
    let mut signature = [0u8; SIGNATURE_LEN];
    assert!(sign_into(MESSAGE, &expanded, &[0u8; 32], &mut signature).is_ok());
    let first_diff = signature
        .iter()
        .zip(expected.iter())
        .position(|(left, right)| left != right);
    assert!(
        first_diff.is_none(),
        "first signature diff at {first_diff:?}"
    );
    let Ok(parsed) = Signature::from_bytes(&expected) else {
        return;
    };
    assert!(verify_bytes(MESSAGE, &public, &expected).is_ok());
    assert!(verify(MESSAGE, &public, &parsed).is_ok());
    assert!(verify(b"wrong message", &public, &parsed).is_err());
    assert!(verify_bytes(b"wrong message", &public, &expected).is_err());
    assert_eq!(parsed.to_bytes(), expected);
}

#[test]
fn profile_model_differential() {
    let mut offset = 0usize;
    let take = |offset: &mut usize, len: usize| -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        let slice = SIGN_DIFF.get(*offset..end)?;
        *offset = end;
        Some(slice)
    };
    assert_eq!(take(&mut offset, 10), Some(b"VORB3DIFF1".as_slice()));
    let count_bytes = take(&mut offset, 2).unwrap_or(&[]);
    let count = usize::from(u16::from_le_bytes([
        count_bytes.first().copied().unwrap_or(0),
        count_bytes.get(1).copied().unwrap_or(0),
    ]));
    assert_eq!(count, 28);
    for case in 0..count {
        let seed = take(&mut offset, FIELD_BYTES).unwrap_or(&[]);
        let Ok(seed): Result<[u8; FIELD_BYTES], _> = seed.try_into() else {
            return;
        };
        let public_bytes = take(&mut offset, PUBLIC_KEY_LEN).unwrap_or(&[]);
        let Ok(public_bytes): Result<[u8; PUBLIC_KEY_LEN], _> = public_bytes.try_into() else {
            return;
        };
        let entropy = take(&mut offset, 32).unwrap_or(&[]);
        let Ok(entropy): Result<[u8; 32], _> = entropy.try_into() else {
            return;
        };
        let len_bytes = take(&mut offset, 4).unwrap_or(&[]);
        let mut len_le = [0u8; 4];
        len_le.copy_from_slice(len_bytes.get(..4).unwrap_or(&[0u8; 4]));
        let message_len = usize::try_from(u32::from_le_bytes(len_le)).unwrap_or(0);
        let message = take(&mut offset, message_len).unwrap_or(&[]);
        let expected = take(&mut offset, SIGNATURE_LEN).unwrap_or(&[]);
        let Ok(expected): Result<[u8; SIGNATURE_LEN], _> = expected.try_into() else {
            return;
        };
        let compact = SecretKey::from_seed(seed);
        let expanded = ExpandedSecretKey::from_seed(&compact);
        let Ok(public) = PublicKey::from_bytes(public_bytes) else {
            continue;
        };
        let Ok(signature) = sign(message, &expanded, &entropy) else {
            continue;
        };
        assert_eq!(signature.to_bytes(), expected, "case {case}");
        assert!(
            verify_bytes(message, &public, &expected).is_ok(),
            "case {case}"
        );
    }
    assert_eq!(offset, SIGN_DIFF.len());
}

#[test]
fn profile_field_differential_and_laws() {
    let (records, remainder) = FIELD_DIFF.as_chunks::<RECORD_LEN>();
    assert_eq!(remainder, []);
    let mut checked = 0usize;
    for record in records {
        let (words, rest) = record.as_chunks::<FIELD_BYTES>();
        assert_eq!(rest, []);
        let [a, b, product, inverse] = words else {
            continue;
        };
        let a = F288::from_bytes(*a);
        let b = F288::from_bytes(*b);
        assert_eq!(a * b, F288::from_bytes(*product));
        assert_eq!(a.inverse(), F288::from_bytes(*inverse));
        checked += 1;
    }
    assert_eq!(checked, 4096);

    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..2048 {
        let mut bytes = [0u8; FIELD_BYTES];
        for chunk in bytes.as_chunks_mut::<4>().0.iter_mut() {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..4]);
        }
        let value = F288::from_bytes(bytes);
        if !value.is_zero() {
            assert_eq!(value * value.inverse(), F288::ONE);
        }
        assert_eq!(value + value, F288::ZERO);
    }
}
