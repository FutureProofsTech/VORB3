#![allow(missing_docs)]
#![cfg(not(any(feature = "nist1", feature = "nist3")))]
//! Frozen-profile constants smoke test.

use vorb3::{
    CHALLENGE_BITS, COMMITMENT_LEN, COPATH_LEN, FIELD_BITS, FIELD_BYTES, GATES, H2_LEN,
    HIDDEN_COMS_LEN, MASK_TREE, ROUNDS, SALT_LEN, SECRET_WIRES, SIGNATURE_LEN, SPEC_VERSION,
    TREE_COUNT, TREE_DEPTH, WIRE_D_LEN,
};

#[test]
fn frozen_profile_constants_match_specification() {
    assert_eq!(SPEC_VERSION, "VORB3-SP1-FROZEN-288/35-2026-11-26");
    assert_eq!(FIELD_BITS, 288);
    assert_eq!(FIELD_BYTES, 36);
    assert_eq!(TREE_COUNT, 35);
    assert_eq!(TREE_DEPTH, 8);
    assert_eq!(ROUNDS, 15);
    assert_eq!(SECRET_WIRES, 31);
    assert_eq!(MASK_TREE, 31);
    assert_eq!(SALT_LEN, 64);
    assert_eq!(H2_LEN, 64);
    assert_eq!(COMMITMENT_LEN, 64);
    assert_eq!(WIRE_D_LEN, 1_116);
    assert_eq!(COPATH_LEN, 10_080);
    assert_eq!(HIDDEN_COMS_LEN, 2_240);
    assert_eq!(GATES, 60);
    assert_eq!(CHALLENGE_BITS, 280);
    assert_eq!(SIGNATURE_LEN, 13_672);
}
