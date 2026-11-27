//! Kani harnesses for Phase-2 bounded properties.
//!
//! These are compiled only under `cfg(kani)`. They prove bounded functional
//! properties; they are not a cryptographic security proof.

use crate::SIGNATURE_LEN;
use crate::ct::{CtChoice, ct_eq_u64, ct_is_zero_u64};
use crate::field::F288;
use crate::keys::{ExpandedSecretKey, PublicKey, SecretKey};
use crate::sign::{sign_into, verify_bytes};
use crate::signature::Signature;

#[kani::proof]
fn field_encoding_roundtrip() {
    let bytes: [u8; 36] = kani::any();
    let value = F288::from_bytes(bytes);
    assert_eq!(value.to_bytes(), bytes);
}

#[kani::proof]
fn field_additive_identities() {
    let bytes: [u8; 36] = kani::any();
    let value = F288::from_bytes(bytes);
    assert_eq!(value + F288::ZERO, value);
    assert_eq!(value + value, F288::ZERO);
    assert_eq!(F288::ZERO + value, value);
}

#[kani::proof]
fn constant_time_equality_matches_bool() {
    let left: u64 = kani::any();
    let right: u64 = kani::any();
    assert_eq!(ct_eq_u64(left, right).to_bool(), left == right);
}

#[kani::proof]
fn constant_time_select_matches_branch() {
    let flag: bool = kani::any();
    let choice = CtChoice::from_bool(flag);
    let if_false: u64 = kani::any();
    let if_true: u64 = kani::any();
    let expected = if flag { if_true } else { if_false };
    assert_eq!(choice.select_u64(if_false, if_true), expected);
}

#[kani::proof]
fn constant_time_zero_u64_matches_bool() {
    let value: u64 = kani::any();
    assert_eq!(ct_is_zero_u64(value).to_bool(), value == 0);
}

#[kani::proof]
#[kani::unwind(40)]
fn field_zero_test_matches_all_bytes() {
    let bytes: [u8; 36] = kani::any();
    let value = F288::from_bytes(bytes);
    let mut any = 0u8;
    let mut index = 0usize;
    while index < bytes.len() {
        any |= bytes[index];
        index += 1;
    }
    assert_eq!(value.ct_is_zero().to_bool(), any == 0);
}

#[kani::proof]
fn field_select_matches_branch() {
    let flag: bool = kani::any();
    let if_false: [u8; 36] = kani::any();
    let if_true: [u8; 36] = kani::any();
    let selected = F288::ct_select(
        CtChoice::from_bool(flag),
        F288::from_bytes(if_false),
        F288::from_bytes(if_true),
    );
    let expected = if flag { if_true } else { if_false };
    assert_eq!(selected.to_bytes(), expected);
}

#[kani::proof]
fn bit_select_matches_branch() {
    let bit: u8 = kani::any();
    kani::assume(bit <= 1);
    let if_false: u64 = kani::any();
    let if_true: u64 = kani::any();
    let selected = CtChoice::from_bit(bit).select_u64(if_false, if_true);
    let expected = if bit == 1 { if_true } else { if_false };
    assert_eq!(selected, expected);
}

#[kani::proof]
fn field_multiplicative_identities() {
    let bytes: [u8; 36] = kani::any();
    let value = F288::from_bytes(bytes);
    assert_eq!(value * F288::ONE, value);
    assert_eq!(value * F288::ZERO, F288::ZERO);
}

#[kani::proof]
fn public_key_parse_roundtrip() {
    let bytes: [u8; 72] = kani::any();
    if let Ok(public) = PublicKey::from_bytes(bytes) {
        assert_eq!(public.to_bytes(), bytes);
    }
}

#[kani::proof]
fn public_key_rejects_zero_component() {
    let pt: [u8; 36] = kani::any();
    let ct: [u8; 36] = kani::any();
    let mut bytes = [0u8; 72];
    bytes[..36].copy_from_slice(&pt);
    bytes[36..].copy_from_slice(&ct);
    let expected = F288::from_bytes(pt).is_zero() || F288::from_bytes(ct).is_zero();
    assert_eq!(PublicKey::from_bytes(bytes).is_err(), expected);
}

#[kani::proof]
fn select_mask_or_xor_equivalent() {
    let mask: u8 = kani::any();
    kani::assume(mask == 0 || mask == 0xFF);
    let if_false: u64 = kani::any();
    let if_true: u64 = kani::any();
    let byte = u64::from(mask);
    let mask = byte
        | (byte << 8)
        | (byte << 16)
        | (byte << 24)
        | (byte << 32)
        | (byte << 40)
        | (byte << 48)
        | (byte << 56);
    assert_eq!(
        (if_false & !mask) | (if_true & mask),
        (if_false & !mask) ^ (if_true & mask)
    );
}

#[kani::proof]
fn signature_parse_accepts_exact_length() {
    let bytes: [u8; SIGNATURE_LEN] = kani::any();
    assert!(Signature::from_bytes(&bytes).is_ok());
}

#[kani::proof]
fn signature_parse_rejects_neighbor_lengths() {
    let short = [0u8; SIGNATURE_LEN];
    let long = [0u8; SIGNATURE_LEN + 1];
    assert!(Signature::from_bytes(&short[..SIGNATURE_LEN - 1]).is_err());
    assert!(Signature::from_bytes(&long).is_err());
}

#[kani::proof]
fn signature_parse_rejects_all_other_lengths() {
    let length: usize = kani::any();
    kani::assume(length != SIGNATURE_LEN);
    let data = [0u8; SIGNATURE_LEN + 1];
    if let Some(input) = data.get(..length) {
        assert!(Signature::from_bytes(input).is_err());
    }
}
