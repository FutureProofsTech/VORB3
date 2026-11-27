#![cfg(not(any(feature = "nist1", feature = "nist3")))]
//! C ABI wrapper used by the Valgrind ctgrind harness.
//!
//! The wrapper itself contains `unsafe` FFI glue; the `vorb3` library remains
//! safe Rust with `forbid(unsafe_code)`. Secrets are marked undefined by the C
//! harness, so Memcheck flags any secret-dependent branch or memory address in
//! the signing path.

use core::slice;
use vorb3::SIGNATURE_LEN;
use vorb3::keys::{ExpandedSecretKey, SecretKey};
use vorb3::sign::sign_into;

/// Derives a public key from a 36-byte seed.
///
/// # Safety
///
/// `seed` must point to 36 readable bytes and `public_key` to 72 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vorb3_ct_keygen(seed: *const u8, public_key: *mut u8) -> i32 {
    // SAFETY: the caller provides the documented buffer sizes.
    let seed = unsafe { slice::from_raw_parts(seed, 36) };
    // SAFETY: the caller provides the documented buffer sizes.
    let output = unsafe { slice::from_raw_parts_mut(public_key, 72) };
    let Ok(seed): Result<[u8; 36], _> = seed.try_into() else {
        return 1;
    };
    let compact = SecretKey::from_seed(seed);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    let Ok(public) = expanded.public_key() else {
        return 2;
    };
    output.copy_from_slice(&public.to_bytes());
    0
}

/// Signs a message from a 36-byte seed and 32-byte entropy value.
///
/// # Safety
///
/// `seed` must point to 36 readable bytes, `entropy` to 32 readable bytes,
/// `message` to `message_len` readable bytes, and `signature` to
/// [`SIGNATURE_LEN`] writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vorb3_ct_sign(
    seed: *const u8,
    entropy: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *mut u8,
) -> i32 {
    // SAFETY: the caller provides the documented buffer sizes.
    let seed = unsafe { slice::from_raw_parts(seed, 36) };
    // SAFETY: the caller provides the documented buffer sizes.
    let entropy = unsafe { slice::from_raw_parts(entropy, 32) };
    // SAFETY: the caller provides the documented buffer sizes.
    let message = unsafe { slice::from_raw_parts(message, message_len) };
    // SAFETY: the caller provides the documented buffer sizes.
    let output = unsafe { slice::from_raw_parts_mut(signature, SIGNATURE_LEN) };
    let Ok(seed): Result<[u8; 36], _> = seed.try_into() else {
        return 1;
    };
    let Ok(entropy): Result<[u8; 32], _> = entropy.try_into() else {
        return 2;
    };
    let Ok(output): Result<&mut [u8; SIGNATURE_LEN], _> = output.try_into() else {
        return 3;
    };
    let compact = SecretKey::from_seed(seed);
    let expanded = ExpandedSecretKey::from_seed(&compact);
    match sign_into(message, &expanded, &entropy, output) {
        Ok(()) => 0,
        Err(_) => 4,
    }
}
