//! VORB3-SP1 post-quantum signature library.
//!
//! **Default frozen profile:** SP-288/35 — GF(2^288), 35 GGM trees, depth 8,
//! 15 rounds, 13,672-byte signature, 128-bit quantum target with a conservative
//! ~140-bit floor.
//!
//! **Alternative packs:** the mutually exclusive `nist1` and `nist3` features
//! select SP-160/32 (NIST Level 1+) and SP-224/32 (NIST Level 3+) respectively.
//! They keep the 15-round protocol and use the 32-tree minimum.
//!
//! # Status
//!
//! Phase 1 is the repository/toolchain/lint skeleton; Phase 2 implements the
//! constant-time/GF(2^288) foundation; Phase 3 implements BLAKE3/WH512; Phase 4
//! implements Rain-SP1; Phase 5 implements GGM/Merkle/transcript; Phase 6
//! implements `QuickSilver`, sign/verify, and the fixed signature type; Phase 7
//! adds streaming GGM/Merkle, masked hidden selection, zeroization, and
//! fixed-work verification; the attack checkpoint adds the 109,376-bit sweep,
//! 1-hour fuzz, 32 KiB stack target, and Kani/Miri evidence. This is not a
//! release certificate and no external audit is claimed. Profile constants are
//! the source of truth.
//!
//! # Doctrine
//!
//! - `no_std` and no allocator.
//! - `forbid(unsafe_code)`.
//! - Zero third-party runtime dependencies.
//! - No demo binary.
//! - The specification is `docs/VORB3-SPEC-1.md`; the independent reference
//!   model is `model/vorb3_model.py`.
//!
//! # Profile constants
//!
//! The frozen values below are the single source of truth for the Rust
//! implementation. Any profile change increments [`SPEC_VERSION`] and
//! invalidates the locked KATs.

#![no_std]
#![forbid(unsafe_code)]
// LEVEL 1: deny all default lax patterns
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::cargo)]
// LEVEL 2: core ecosystem isolation
#![deny(clippy::alloc_instead_of_core)]
#![deny(clippy::std_instead_of_core)]
#![deny(clippy::std_instead_of_alloc)]
// LEVEL 3: zero runtime panic matrices
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unreachable)]
// LEVEL 4: bit-level security and casting
#![deny(clippy::as_conversions)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::float_arithmetic)]
// LEVEL 5: compiler restructuring and memory tracking
#![deny(clippy::missing_inline_in_public_items)]
#![deny(clippy::exhaustive_structs)]
// Additional VORB3 arithmetic-safety gate
#![deny(clippy::arithmetic_side_effects)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(all(feature = "nist1", feature = "nist3"))]
compile_error!("nist1 and nist3 are alternative profile packs; enable only one");

#[cfg(feature = "bench-api")]
pub mod bench_api;
pub mod blake3;
mod ct;
#[cfg(not(any(feature = "nist1", feature = "nist3")))]
pub mod field;
#[cfg(any(feature = "nist1", feature = "nist3"))]
#[path = "field_nist.rs"]
pub mod field;
mod ggm;
#[cfg(kani)]
mod kani_proofs;
pub mod keys;
pub mod rain;
pub mod sign;
pub mod signature;
mod transcript;
mod zeroize;

/// Frozen specification identifier.
#[cfg(not(any(feature = "nist1", feature = "nist3")))]
pub const SPEC_VERSION: &str = "VORB3-SP1-FROZEN-288/35-2026-11-26";
/// Frozen specification identifier for the NIST Level 1+ pack.
#[cfg(feature = "nist1")]
pub const SPEC_VERSION: &str = "VORB3-SP1-NIST1P-160/32-2026-11-27";
/// Frozen specification identifier for the NIST Level 3+ pack.
#[cfg(feature = "nist3")]
pub const SPEC_VERSION: &str = "VORB3-SP1-NIST3P-224/32-2026-11-27";

/// Field size in bits.
#[cfg(not(any(feature = "nist1", feature = "nist3")))]
pub const FIELD_BITS: usize = 288;
/// Field size in bits.
#[cfg(feature = "nist1")]
pub const FIELD_BITS: usize = 160;
/// Field size in bits.
#[cfg(feature = "nist3")]
pub const FIELD_BITS: usize = 224;

/// Field element / GGM seed size in bytes.
#[cfg(not(any(feature = "nist1", feature = "nist3")))]
pub const FIELD_BYTES: usize = 36;
/// Field element / GGM seed size in bytes.
#[cfg(feature = "nist1")]
pub const FIELD_BYTES: usize = 20;
/// Field element / GGM seed size in bytes.
#[cfg(feature = "nist3")]
pub const FIELD_BYTES: usize = 28;

/// Number of GGM trees.
#[cfg(not(any(feature = "nist1", feature = "nist3")))]
pub const TREE_COUNT: usize = 35;
/// Number of GGM trees (protocol minimum for 15 rounds).
#[cfg(any(feature = "nist1", feature = "nist3"))]
pub const TREE_COUNT: usize = 32;

/// GGM tree depth.
pub const TREE_DEPTH: usize = 8;

/// Rain-SP1 round count (security-margin baseline).
pub const ROUNDS: usize = 15;

/// Number of secret wire openings (`sk`, 15 `y`, 15 `b`).
pub const SECRET_WIRES: usize = 31;

/// Hidden mask tree index.
pub const MASK_TREE: usize = 31;

/// Salt length in bytes (WH512 output).
pub const SALT_LEN: usize = 64;

/// Challenge digest `h2` length in bytes (WH512 output).
pub const H2_LEN: usize = 64;

/// WH512 commitment / Merkle node / root length in bytes.
pub const COMMITMENT_LEN: usize = 64;

/// Public key length in bytes (`pt || ct`).
pub const PUBLIC_KEY_LEN: usize = 2 * FIELD_BYTES;

/// `wire_d` field length in bytes (`31 × FIELD_BYTES`).
pub const WIRE_D_LEN: usize = SECRET_WIRES * FIELD_BYTES;

/// Copath field length in bytes (`TREE_COUNT × 8 × FIELD_BYTES`).
pub const COPATH_LEN: usize = TREE_COUNT * TREE_DEPTH * FIELD_BYTES;

/// Hidden leaf commitments field length in bytes.
pub const HIDDEN_COMS_LEN: usize = TREE_COUNT * COMMITMENT_LEN;

/// Frozen signature length in bytes.
#[cfg(not(any(feature = "nist1", feature = "nist3")))]
pub const SIGNATURE_LEN: usize = 13_672;
/// Frozen signature length in bytes.
#[cfg(feature = "nist1")]
pub const SIGNATURE_LEN: usize = 7_976;
/// Frozen signature length in bytes.
#[cfg(feature = "nist3")]
pub const SIGNATURE_LEN: usize = 10_296;

/// Number of `QuickSilver` multiplication gates (4 per round).
pub const GATES: usize = 60;

/// Number of challenge bits (`TREE_COUNT × 8`).
pub const CHALLENGE_BITS: usize = TREE_COUNT * 8;
