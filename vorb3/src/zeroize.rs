//! Safe zeroization helpers.
//!
//! Safe Rust cannot guarantee that every compiler temporary is wiped, but
//! `fill(0)` plus `black_box` prevents the compiler from eliminating an owned
//! buffer wipe. Secret-bearing types call these functions on every exit path.

use core::hint::black_box;

/// Wipes a byte slice in place.
///
/// The `black_box` barrier prevents dead-store elimination of the wipe. This is
/// best-effort zeroization, not a proof about registers or compiler temporaries.
#[allow(dead_code)] // used by secret types introduced in later phases.
#[inline]
pub fn wipe_bytes(bytes: &mut [u8]) {
    bytes.fill(0);
    black_box(bytes);
}

/// Wipes a five-limb GF(2^288) value in place.
#[inline]
pub fn wipe_u64s(limbs: &mut [u64; 5]) {
    limbs.fill(0);
    black_box(limbs);
}

#[cfg(test)]
mod tests {
    use super::{wipe_bytes, wipe_u64s};

    #[test]
    fn wipes_byte_buffer() {
        let mut bytes = [0xA5u8; 8];
        wipe_bytes(&mut bytes);
        assert_eq!(bytes, [0u8; 8]);
    }

    #[test]
    fn wipes_limbs() {
        let mut limbs = [u64::MAX; 5];
        wipe_u64s(&mut limbs);
        assert_eq!(limbs, [0u64; 5]);
    }
}
