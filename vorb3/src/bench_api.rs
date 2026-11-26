//! Benchmark-only access to internal protocol phases.
//!
//! This module is gated behind the non-default `bench-api` feature. It is not
//! part of the production API and adds no runtime dependencies. It exists so
//! `tools/bench` can time GGM, transcript, and sign-phase boundaries that are
//! private to the shipping crate.

use crate::field::F288;
use crate::ggm;
use crate::keys::{ExpandedSecretKey, PublicKey};
use crate::rain::{RainConstants, RainWitness};
use crate::sign;
use crate::transcript::Transcript;
use crate::{
    COMMITMENT_LEN, FIELD_BYTES, H2_LEN, SALT_LEN, SECRET_WIRES, SIGNATURE_LEN, TREE_COUNT,
    TREE_DEPTH,
};

/// Returns the expanded secret field elements `(sk, pt)`.
#[must_use]
#[inline]
pub const fn secret_parts(secret: &ExpandedSecretKey) -> (F288, F288) {
    (secret.sk, secret.pt)
}

/// Computes one streaming GGM tree root.
#[must_use]
#[inline]
pub fn ggm_tree_root(
    root_seed: [u8; FIELD_BYTES],
    tree_index: u16,
    salt: [u8; SALT_LEN],
    pk_hash: [u8; COMMITMENT_LEN],
) -> [u8; COMMITMENT_LEN] {
    ggm::tree_root(root_seed, tree_index, &salt, &pk_hash)
}

/// Extracts one hidden leaf and its copath.
#[must_use]
#[inline]
pub fn ggm_hidden_opening(
    root_seed: [u8; FIELD_BYTES],
    tree_index: u16,
    alpha: u8,
    salt: [u8; SALT_LEN],
    pk_hash: [u8; COMMITMENT_LEN],
) -> (F288, [u8; COMMITMENT_LEN], [[u8; FIELD_BYTES]; TREE_DEPTH]) {
    ggm::hidden_opening(root_seed, tree_index, alpha, &salt, &pk_hash)
}

/// Reconstructs one Merkle root from a hidden commitment and copath.
#[must_use]
#[inline]
pub fn ggm_reconstruct_root(
    hidden_commitment: [u8; COMMITMENT_LEN],
    copath: [[u8; FIELD_BYTES]; TREE_DEPTH],
    tree_index: u16,
    alpha: u8,
    salt: [u8; SALT_LEN],
    pk_hash: [u8; COMMITMENT_LEN],
) -> [u8; COMMITMENT_LEN] {
    ggm::reconstruct_root(
        hidden_commitment,
        &copath,
        tree_index,
        alpha,
        &salt,
        &pk_hash,
    )
}

/// Runs the four transcript absorptions and three squeezes used by signing.
#[must_use]
#[inline]
pub fn transcript_challenges(
    public_key: &[u8; 72],
    salt: &[u8; SALT_LEN],
    message: &[u8],
    roots: &[u8; TREE_COUNT * COMMITMENT_LEN],
) -> (F288, F288, [u8; H2_LEN]) {
    let mut transcript = Transcript::new();
    transcript.absorb("PK", public_key);
    transcript.absorb("SALT", salt);
    transcript.absorb("MSG", message);
    transcript.absorb("ROOTS", roots);
    let mut delta_bytes = [0u8; FIELD_BYTES];
    let mut chi_bytes = [0u8; FIELD_BYTES];
    let mut h2 = [0u8; H2_LEN];
    transcript.squeeze("DELTA", &mut delta_bytes);
    transcript.squeeze("CHI", &mut chi_bytes);
    transcript.squeeze("H2", &mut h2);
    (
        nonzero(F288::from_bytes(delta_bytes)),
        nonzero(F288::from_bytes(chi_bytes)),
        h2,
    )
}

/// Times the hedged master-seed derivation.
#[must_use]
#[inline]
pub fn sign_master_seed(
    secret: &ExpandedSecretKey,
    public_key: &PublicKey,
    message: &[u8],
    entropy: &[u8; 32],
) -> [u8; FIELD_BYTES] {
    sign::bench::master_seed_bench(secret, public_key, message, entropy)
}

/// Times the salt derivation from the master seed.
#[must_use]
#[inline]
pub fn sign_salt(master: [u8; FIELD_BYTES]) -> [u8; SALT_LEN] {
    sign::bench::salt_bench(&master)
}

/// Times the public-key WH512 hash.
#[must_use]
#[inline]
pub fn sign_public_key_hash(public_key: &PublicKey) -> [u8; COMMITMENT_LEN] {
    sign::bench::pk_hash_bench(public_key)
}

/// Times the full 35-tree root pass.
#[must_use]
#[inline]
pub fn sign_roots(
    master: [u8; FIELD_BYTES],
    salt: [u8; SALT_LEN],
    pk_hash: [u8; COMMITMENT_LEN],
) -> [u8; TREE_COUNT * COMMITMENT_LEN] {
    sign::bench::roots_bench(&master, &salt, &pk_hash)
}

/// Times hidden-opening extraction for all 35 trees.
#[must_use]
#[inline]
pub fn sign_openings(
    master: [u8; FIELD_BYTES],
    salt: [u8; SALT_LEN],
    pk_hash: [u8; COMMITMENT_LEN],
    h2: [u8; H2_LEN],
    signature: &mut [u8; SIGNATURE_LEN],
) -> ([F288; TREE_COUNT], [F288; TREE_COUNT]) {
    sign::bench::openings_bench(&master, &salt, &pk_hash, &h2, signature)
}

/// Times wire construction and MAC tagging.
#[must_use]
#[inline]
pub fn sign_wires(
    sk: F288,
    witness: &RainWitness,
    u_values: &[F288; TREE_COUNT],
    q_values: &[F288; TREE_COUNT],
    delta: F288,
    signature: &mut [u8; SIGNATURE_LEN],
) -> ([F288; SECRET_WIRES], [F288; SECRET_WIRES]) {
    sign::bench::wires_bench(sk, witness, u_values, q_values, delta, signature)
}

/// Times the 60-gate `QuickSilver` prover.
#[must_use]
#[inline]
pub fn sign_prove(
    witness: &RainWitness,
    wire_w: &[F288; SECRET_WIRES],
    tags: &[F288; SECRET_WIRES],
    chi: F288,
    constants: &RainConstants,
) -> (F288, F288, F288) {
    sign::bench::prove_bench(witness, wire_w, tags, chi, constants)
}

/// Times verifier wire-opening extraction.
#[must_use]
#[inline]
pub fn sign_opened_wires(bytes: &[u8; SIGNATURE_LEN], delta: F288) -> [F288; SECRET_WIRES] {
    sign::bench::opened_wires_bench(bytes, delta)
}

/// Times the 60-gate `QuickSilver` verifier check.
#[must_use]
#[inline]
pub fn sign_check_proof(
    public_key: &PublicKey,
    bytes: &[u8; SIGNATURE_LEN],
    delta: F288,
    chi: F288,
    q_open: &[F288; SECRET_WIRES],
    constants: &RainConstants,
) -> bool {
    sign::bench::check_proof_bench(public_key, bytes, delta, chi, q_open, constants)
}

/// Times the 35-tree verifier root reconstruction.
#[must_use]
#[inline]
pub fn sign_reconstruct_roots(
    bytes: &[u8; SIGNATURE_LEN],
    salt: [u8; SALT_LEN],
    pk_hash: [u8; COMMITMENT_LEN],
    h2: [u8; H2_LEN],
) -> [u8; TREE_COUNT * COMMITMENT_LEN] {
    sign::bench::reconstruct_roots_bench(bytes, &salt, &pk_hash, &h2)
}

#[inline]
fn nonzero(value: F288) -> F288 {
    let zero = value.ct_is_zero();
    F288::ct_select(zero, value, F288::ONE)
}
