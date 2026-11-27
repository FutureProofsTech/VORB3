#![allow(missing_docs)]
#![cfg(any(feature = "nist1", feature = "nist3"))]
//! Structured envelope attacks for the NIST-tier packs.

use vorb3::keys::{ExpandedSecretKey, PublicKey, SecretKey};
use vorb3::sign::{sign_into, verify_bytes};
use vorb3::signature::Signature;
use vorb3::{
    COMMITMENT_LEN, COPATH_LEN, FIELD_BYTES, H2_LEN, HIDDEN_COMS_LEN, PUBLIC_KEY_LEN, SALT_LEN,
    SIGNATURE_LEN, TREE_COUNT, TREE_DEPTH, WIRE_D_LEN,
};

#[cfg(feature = "nist1")]
const SEED: &[u8] = include_bytes!("../../kat/seed_sp160_32.bin");
#[cfg(feature = "nist1")]
const EXPECTED_PK: &[u8] = include_bytes!("../../kat/pk_sp160_32.bin");
#[cfg(feature = "nist1")]
const EXPECTED_SIG: &[u8] = include_bytes!("../../kat/sign_sp160_32.bin");
#[cfg(feature = "nist1")]
const MESSAGE: &[u8] = b"VORB3 phase-0 SP160_32";

#[cfg(feature = "nist3")]
const SEED: &[u8] = include_bytes!("../../kat/seed_sp224_32.bin");
#[cfg(feature = "nist3")]
const EXPECTED_PK: &[u8] = include_bytes!("../../kat/pk_sp224_32.bin");
#[cfg(feature = "nist3")]
const EXPECTED_SIG: &[u8] = include_bytes!("../../kat/sign_sp224_32.bin");
#[cfg(feature = "nist3")]
const MESSAGE: &[u8] = b"VORB3 phase-0 SP224_32";

const SALT_OFF: usize = 0;
const H2_OFF: usize = SALT_LEN;
const WIRE_D_OFF: usize = SALT_LEN + H2_LEN;
const U_OFF: usize = WIRE_D_OFF + WIRE_D_LEN;
const V_OFF: usize = U_OFF + FIELD_BYTES;
const OUT_TAG_OFF: usize = V_OFF + FIELD_BYTES;
const COPATH_OFF: usize = OUT_TAG_OFF + FIELD_BYTES;
const HIDDEN_OFF: usize = COPATH_OFF + COPATH_LEN;
const COPATH_TREE_LEN: usize = TREE_DEPTH * FIELD_BYTES;

fn seed() -> [u8; FIELD_BYTES] {
    SEED.try_into().unwrap_or([0u8; FIELD_BYTES])
}

fn expected_pk() -> [u8; PUBLIC_KEY_LEN] {
    EXPECTED_PK.try_into().unwrap_or([0u8; PUBLIC_KEY_LEN])
}

fn expected_sig() -> [u8; SIGNATURE_LEN] {
    EXPECTED_SIG.try_into().unwrap_or([0u8; SIGNATURE_LEN])
}

fn public_key() -> Option<PublicKey> {
    let compact = SecretKey::from_seed(seed());
    let expanded = ExpandedSecretKey::from_seed(&compact);
    expanded.public_key().ok()
}

fn flipped(offset: usize, mask: u8) -> Option<[u8; SIGNATURE_LEN]> {
    let mut bytes = expected_sig();
    let slot = bytes.get_mut(offset)?;
    *slot ^= mask;
    Some(bytes)
}

#[test]
fn nist_replay_and_cross_context_rejection() {
    let Some(public) = public_key() else {
        return;
    };
    let expected = expected_sig();
    assert!(verify_bytes(MESSAGE, &public, &expected).is_ok());
    assert!(verify_bytes(b"other message", &public, &expected).is_err());

    let mut other_seed = seed();
    if let Some(byte) = other_seed.get_mut(0) {
        *byte ^= 0x5A;
    }
    let compact = SecretKey::from_seed(other_seed);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let Ok(other_public) = expanded.public_key() else {
        return;
    };
    assert!(verify_bytes(MESSAGE, &other_public, &expected).is_err());

    let mut second = [0u8; SIGNATURE_LEN];
    assert!(sign_into(MESSAGE, &expanded, &[1u8; 32], &mut second).is_ok());
    assert!(verify_bytes(MESSAGE, &other_public, &second).is_ok());
    assert!(verify_bytes(MESSAGE, &public, &second).is_err());
}

#[test]
fn nist_envelope_region_damage_rejected() {
    let Some(public) = public_key() else {
        return;
    };
    let regions = [
        (SALT_OFF, SALT_LEN),
        (H2_OFF, H2_LEN),
        (WIRE_D_OFF, WIRE_D_LEN),
        (U_OFF, FIELD_BYTES),
        (V_OFF, FIELD_BYTES),
        (OUT_TAG_OFF, FIELD_BYTES),
        (COPATH_OFF, COPATH_LEN),
        (HIDDEN_OFF, HIDDEN_COMS_LEN),
    ];
    for (offset, length) in regions {
        for (name, byte) in [("zero", 0x00u8), ("ones", 0xFFu8)] {
            let mut bytes = expected_sig();
            if let Some(region) = bytes.get_mut(offset..offset.saturating_add(length)) {
                region.fill(byte);
            }
            assert!(
                verify_bytes(MESSAGE, &public, &bytes).is_err(),
                "{name} damage at {offset} accepted"
            );
        }
    }
}

#[test]
fn nist_component_swaps_and_duplication_rejected() {
    let Some(public) = public_key() else {
        return;
    };
    let mut swapped = expected_sig();
    let (left, right) = swapped.split_at_mut(V_OFF);
    if let (Some(u), Some(v)) = (left.get_mut(U_OFF..V_OFF), right.get_mut(..FIELD_BYTES)) {
        let Ok(u_copy): Result<[u8; FIELD_BYTES], _> = u.try_into() else {
            return;
        };
        let Ok(v_copy): Result<[u8; FIELD_BYTES], _> = v.try_into() else {
            return;
        };
        u.copy_from_slice(&v_copy);
        v.copy_from_slice(&u_copy);
    }
    assert!(verify_bytes(MESSAGE, &public, &swapped).is_err());

    let mut duplicated = expected_sig();
    let first_copath = COPATH_OFF;
    let second_copath = COPATH_OFF + COPATH_TREE_LEN;
    if let Some(source) = duplicated
        .get(first_copath..first_copath + COPATH_TREE_LEN)
        .map(<[u8; COPATH_TREE_LEN]>::try_from)
        && let Ok(source) = source
        && let Some(dst) = duplicated.get_mut(second_copath..second_copath + COPATH_TREE_LEN)
    {
        dst.copy_from_slice(&source);
    }
    if let Some(src) = duplicated
        .get(HIDDEN_OFF..HIDDEN_OFF + COMMITMENT_LEN)
        .map(<[u8; COMMITMENT_LEN]>::try_from)
        && let Ok(src) = src
        && let Some(dst) =
            duplicated.get_mut(HIDDEN_OFF + COMMITMENT_LEN..HIDDEN_OFF + 2 * COMMITMENT_LEN)
    {
        dst.copy_from_slice(&src);
    }
    assert!(verify_bytes(MESSAGE, &public, &duplicated).is_err());
}

#[test]
fn nist_sampled_field_and_key_bitflips_rejected() {
    let Some(public) = public_key() else {
        return;
    };
    let positions = [
        SALT_OFF,
        H2_OFF + 1,
        WIRE_D_OFF + 3,
        U_OFF + 5,
        V_OFF + 7,
        OUT_TAG_OFF + 9,
        COPATH_OFF + 11,
        HIDDEN_OFF + 13,
        SIGNATURE_LEN - 1,
    ];
    for position in positions {
        for bit in 0..8u8 {
            if let Some(bytes) = flipped(position, 1u8 << bit) {
                assert!(verify_bytes(MESSAGE, &public, &bytes).is_err());
            }
        }
    }
    for bit in 0..8u8 {
        let mut pk = expected_pk();
        if let Some(byte) = pk.get_mut(PUBLIC_KEY_LEN - 1) {
            *byte ^= 1u8 << bit;
        }
        if let Ok(candidate) = PublicKey::from_bytes(pk) {
            assert!(verify_bytes(MESSAGE, &candidate, &expected_sig()).is_err());
        }
    }
}

#[test]
fn nist_parse_edges_and_tree_count() {
    let Some(public) = public_key() else {
        return;
    };
    let expected = expected_sig();
    assert!(Signature::from_bytes(&expected[..SIGNATURE_LEN - 1]).is_err());
    let mut long = [0u8; SIGNATURE_LEN + 1];
    if let Some(dst) = long.get_mut(..SIGNATURE_LEN) {
        dst.copy_from_slice(&expected);
    }
    assert!(Signature::from_bytes(&long).is_err());
    let zero = [0u8; SIGNATURE_LEN];
    assert!(verify_bytes(MESSAGE, &public, &zero).is_err());
    assert_eq!(TREE_COUNT, 32);
    assert!(Signature::from_bytes(&[]).is_err());
}

#[test]
fn nist_large_message_zero_seed_and_entropy_separation() {
    let compact = SecretKey::from_seed([0u8; FIELD_BYTES]);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let Ok(public) = expanded.public_key() else {
        return;
    };
    let message = std::vec![0xA5u8; 1024 * 1024];
    let mut first = [0u8; SIGNATURE_LEN];
    let mut second = [0u8; SIGNATURE_LEN];
    assert!(sign_into(&message, &expanded, &[0u8; 32], &mut first).is_ok());
    assert!(sign_into(&message, &expanded, &[0u8; 32], &mut second).is_ok());
    assert_eq!(first, second);
    assert!(verify_bytes(&message, &public, &first).is_ok());
    assert!(verify_bytes(b"other", &public, &first).is_err());

    let mut third = [0u8; SIGNATURE_LEN];
    assert!(sign_into(&message, &expanded, &[1u8; 32], &mut third).is_ok());
    assert_ne!(first, third);
    assert!(verify_bytes(&message, &public, &third).is_ok());
}
