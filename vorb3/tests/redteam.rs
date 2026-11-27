//! Structured red-team attacks on the signature envelope.

use vorb3::keys::{ExpandedSecretKey, PublicKey, SecretKey};
use vorb3::sign::{sign_into, verify_bytes};
use vorb3::signature::Signature;
use vorb3::{SIGNATURE_LEN, TREE_COUNT};

const SEED: &[u8; 36] = include_bytes!("../../kat/seed_sp288_35.bin");
const EXPECTED_PK: &[u8; 72] = include_bytes!("../../kat/pk_sp288_35.bin");
const EXPECTED_SIG: &[u8; SIGNATURE_LEN] = include_bytes!("../../kat/sign_sp288_35.bin");
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";

const SALT_OFF: usize = 0;
const H2_OFF: usize = 64;
const WIRE_D_OFF: usize = 128;
const U_OFF: usize = 1_244;
const V_OFF: usize = 1_280;
const OUT_TAG_OFF: usize = 1_316;
const COPATH_OFF: usize = 1_352;
const HIDDEN_OFF: usize = 11_432;

fn public_key() -> Option<PublicKey> {
    let compact = SecretKey::from_seed(*SEED);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    expanded.public_key().ok()
}

fn flipped(offset: usize, mask: u8) -> Option<[u8; SIGNATURE_LEN]> {
    let mut bytes = *EXPECTED_SIG;
    let slot = bytes.get_mut(offset)?;
    *slot ^= mask;
    Some(bytes)
}

#[test]
fn replay_and_cross_context_rejection() {
    let Some(public) = public_key() else {
        return;
    };
    assert!(verify_bytes(MESSAGE, &public, EXPECTED_SIG).is_ok());
    assert!(verify_bytes(b"other message", &public, EXPECTED_SIG).is_err());

    let mut other_seed = *SEED;
    if let Some(byte) = other_seed.get_mut(0) {
        *byte ^= 0x5A;
    }
    let compact = SecretKey::from_seed(other_seed);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let Ok(other_public) = expanded.public_key() else {
        return;
    };
    assert!(verify_bytes(MESSAGE, &other_public, EXPECTED_SIG).is_err());

    let mut second = [0u8; SIGNATURE_LEN];
    assert!(sign_into(MESSAGE, &expanded, &[1u8; 32], &mut second).is_ok());
    assert!(verify_bytes(MESSAGE, &other_public, &second).is_ok());
    assert!(verify_bytes(MESSAGE, &public, &second).is_err());
}

#[test]
fn envelope_region_damage_rejected() {
    let Some(public) = public_key() else {
        return;
    };
    let regions = [
        (SALT_OFF, 64),
        (H2_OFF, 64),
        (WIRE_D_OFF, 1_116),
        (U_OFF, 36),
        (V_OFF, 36),
        (OUT_TAG_OFF, 36),
        (COPATH_OFF, 10_080),
        (HIDDEN_OFF, 2_240),
    ];
    for (offset, length) in regions {
        for (name, byte) in [("zero", 0x00u8), ("ones", 0xFFu8)] {
            let mut bytes = *EXPECTED_SIG;
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
fn component_swaps_and_duplication_rejected() {
    let Some(public) = public_key() else {
        return;
    };
    // U <-> V
    let mut swapped = *EXPECTED_SIG;
    let (left, right) = swapped.split_at_mut(V_OFF);
    if let (Some(u), Some(v)) = (left.get_mut(U_OFF..V_OFF), right.get_mut(..36)) {
        let u_copy: [u8; 36] = match u.try_into() {
            Ok(array) => array,
            Err(_) => return,
        };
        let v_copy: [u8; 36] = match v.try_into() {
            Ok(array) => array,
            Err(_) => return,
        };
        u.copy_from_slice(&v_copy);
        v.copy_from_slice(&u_copy);
    }
    assert!(verify_bytes(MESSAGE, &public, &swapped).is_err());

    // Duplicate the first tree's copath/hidden commitment into the second.
    let mut duplicated = *EXPECTED_SIG;
    let first_copath = COPATH_OFF;
    let second_copath = COPATH_OFF + 288;
    if let Some(source) = duplicated
        .get(first_copath..first_copath + 288)
        .map(<[u8; 288]>::try_from)
        && let Ok(source) = source
        && let Some(dst) = duplicated.get_mut(second_copath..second_copath + 288)
    {
        dst.copy_from_slice(&source);
    }
    if let Some(src) = duplicated
        .get(HIDDEN_OFF..HIDDEN_OFF + 64)
        .map(<[u8; 64]>::try_from)
        && let Ok(src) = src
        && let Some(dst) = duplicated.get_mut(HIDDEN_OFF + 64..HIDDEN_OFF + 128)
    {
        dst.copy_from_slice(&src);
    }
    assert!(verify_bytes(MESSAGE, &public, &duplicated).is_err());
}

#[test]
fn sampled_field_and_key_bitflips_rejected() {
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
        let mut pk = *EXPECTED_PK;
        if let Some(byte) = pk.get_mut(71) {
            *byte ^= 1u8 << bit;
        }
        if let Ok(candidate) = PublicKey::from_bytes(pk) {
            assert!(verify_bytes(MESSAGE, &candidate, EXPECTED_SIG).is_err());
        }
    }
}

#[test]
fn parse_edges_and_tree_count() {
    let Some(public) = public_key() else {
        return;
    };
    assert!(Signature::from_bytes(&EXPECTED_SIG[..SIGNATURE_LEN - 1]).is_err());
    let mut long = [0u8; SIGNATURE_LEN + 1];
    if let Some(dst) = long.get_mut(..SIGNATURE_LEN) {
        dst.copy_from_slice(EXPECTED_SIG);
    }
    assert!(Signature::from_bytes(&long).is_err());
    let zero = [0u8; SIGNATURE_LEN];
    assert!(verify_bytes(MESSAGE, &public, &zero).is_err());
    assert_eq!(TREE_COUNT, 35);
    let empty = [0u8; 0];
    assert!(Signature::from_bytes(&empty).is_err());
}

#[test]
fn large_message_zero_seed_and_entropy_separation() {
    let compact = SecretKey::from_seed([0u8; 36]);
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
