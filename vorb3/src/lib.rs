//! VORB3-SP1 post-quantum signature library.
//!
//! **Frozen profile:** SP-288/35 — GF(2^288), 35 GGM trees, depth 8, 15 rounds,
//! 13,672-byte signature, 128-bit quantum target with a conservative ~140-bit
//! floor.
//!
//! # Status
//!
//! Phase 1 is the repository/toolchain/lint skeleton; Phase 2 has started with
//! the constant-time foundation and GF(2^288) arithmetic. The remaining
//! cryptographic modules (BLAKE3/WH512, Rain-SP1, GGM/Merkle, transcript,
//! `QuickSilver`, sign/verify) follow in later phases. Profile constants are the
//! single source of truth for the implementation.
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
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod ct;
pub mod field;
#[cfg(kani)]
mod kani_proofs;
mod zeroize;

/// Frozen specification identifier.
pub const SPEC_VERSION: &str = "VORB3-SP1-FROZEN-288/35-2026-11-26";

/// Field size in bits.
pub const FIELD_BITS: usize = 288;

/// Field element / GGM seed size in bytes.
pub const FIELD_BYTES: usize = 36;

/// Number of GGM trees.
pub const TREE_COUNT: usize = 35;

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

/// `wire_d` field length in bytes (31 × 36).
pub const WIRE_D_LEN: usize = 1_116;

/// Copath field length in bytes (35 trees × 8 siblings × 36 bytes).
pub const COPATH_LEN: usize = 10_080;

/// Hidden leaf commitments field length in bytes (35 × 64).
pub const HIDDEN_COMS_LEN: usize = 2_240;

/// Frozen signature length in bytes.
pub const SIGNATURE_LEN: usize = 13_672;

/// Number of `QuickSilver` multiplication gates (4 per round).
pub const GATES: usize = 60;

/// Number of challenge bits (35 trees × 8 bits).
pub const CHALLENGE_BITS: usize = 280;
