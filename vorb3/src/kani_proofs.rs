//! Kani harnesses for Phase-2 bounded properties.
//!
//! These are compiled only under `cfg(kani)`. They prove bounded functional
//! properties; they are not a cryptographic security proof.

use crate::SIGNATURE_LEN;
use crate::ct::{CtChoice, ct_eq_u64};
use crate::field::F288;
use crate::keys::{ExpandedSecretKey, SecretKey};
use crate::sign::{sign_into, verify_bytes};

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
