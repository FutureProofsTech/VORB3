//! Constant-time choice and comparison primitives.
//!
//! Some operations are intentionally present before their first call site; the
//! cryptographic modules use them in later phases. The `dead_code` allow is
//! therefore temporary and is removed as each operation gets a production use.
#![allow(dead_code)]
//!
//! `CtChoice` carries a `0x00` or `0xFF` byte mask. It is intentionally tiny and
//! internal; the public field API exposes declassified `bool` only for values
//! whose secrecy does not matter (tests, public validation).

use core::hint::black_box;

/// A constant-time boolean represented by `0x00` (false) or `0xFF` (true).
#[derive(Clone, Copy)]
pub struct CtChoice(u8);

impl CtChoice {
    /// Constructs a choice from a public `bool`.
    #[must_use]
    #[inline]
    pub const fn from_bool(value: bool) -> Self {
        if value { Self(0xFF) } else { Self(0x00) }
    }

    /// Constructs a choice from a 0/1 bit using an arithmetic mask.
    #[must_use]
    #[inline]
    pub const fn from_bit(bit: u8) -> Self {
        Self(0u8.wrapping_sub(bit & 1))
    }

    /// Returns the raw `0x00`/`0xFF` mask.
    #[must_use]
    #[inline]
    pub const fn mask(self) -> u8 {
        self.0
    }

    /// Constant-time logical NOT.
    #[must_use]
    #[inline]
    pub const fn not(self) -> Self {
        Self(self.0 ^ 0xFF)
    }

    /// Constant-time logical AND.
    #[must_use]
    #[inline]
    pub const fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Constant-time logical OR.
    #[must_use]
    #[inline]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Constant-time logical XOR.
    #[must_use]
    #[inline]
    pub const fn xor(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }

    /// Selects `if_false` when false, `if_true` when true, without branching on
    /// the choice.
    #[must_use]
    #[inline]
    pub const fn select_u8(self, if_false: u8, if_true: u8) -> u8 {
        let mask = black_box(self.0);
        (if_false & !mask) | (if_true & mask)
    }

    /// Selects a `u64` without branching on the choice.
    #[must_use]
    #[inline]
    #[allow(clippy::missing_const_for_fn)] // u64::from is not const-stable here.
    pub fn select_u64(self, if_false: u64, if_true: u64) -> u64 {
        let byte = u64::from(black_box(self.0));
        let mask = byte
            | (byte << 8)
            | (byte << 16)
            | (byte << 24)
            | (byte << 32)
            | (byte << 40)
            | (byte << 48)
            | (byte << 56);
        (if_false & !mask) | (if_true & mask)
    }

    /// Declassifies the choice to a `bool`. Only use this for public decisions.
    #[must_use]
    #[inline]
    pub const fn to_bool(self) -> bool {
        self.0 != 0
    }
}

/// Constant-time equality of two `u64` values.
#[must_use]
#[inline]
pub fn ct_eq_u64(left: u64, right: u64) -> CtChoice {
    let diff = left ^ right;
    let nonzero = (diff | diff.wrapping_neg()) >> 63;
    CtChoice::from_bit(u8::try_from((nonzero ^ 1) & 1).unwrap_or(0))
}

/// Constant-time test that a `u64` is zero.
#[must_use]
#[inline]
pub fn ct_is_zero_u64(value: u64) -> CtChoice {
    ct_eq_u64(value, 0)
}

#[cfg(test)]
mod tests {
    use super::{CtChoice, ct_eq_u64, ct_is_zero_u64};

    #[test]
    fn masks_and_logic() {
        let yes = CtChoice::from_bool(true);
        let no = CtChoice::from_bool(false);
        assert_eq!(yes.mask(), 0xFF);
        assert_eq!(no.mask(), 0x00);
        assert_eq!(yes.not().mask(), 0x00);
        assert_eq!(yes.and(no).mask(), 0x00);
        assert_eq!(yes.or(no).mask(), 0xFF);
        assert_eq!(yes.xor(yes).mask(), 0x00);
        assert_eq!(CtChoice::from_bit(1).mask(), 0xFF);
        assert_eq!(CtChoice::from_bit(0).mask(), 0x00);
    }

    #[test]
    fn selects() {
        let yes = CtChoice::from_bool(true);
        let no = CtChoice::from_bool(false);
        assert_eq!(yes.select_u8(0x12, 0x34), 0x34);
        assert_eq!(no.select_u8(0x12, 0x34), 0x12);
        assert_eq!(yes.select_u64(1, 2), 2);
        assert_eq!(no.select_u64(1, 2), 1);
    }

    #[test]
    fn equality() {
        assert!(ct_eq_u64(0, 0).to_bool());
        assert!(ct_eq_u64(u64::MAX, u64::MAX).to_bool());
        assert!(!ct_eq_u64(0, 1).to_bool());
        assert!(!ct_eq_u64(1, 0).to_bool());
        assert!(ct_is_zero_u64(0).to_bool());
        assert!(!ct_is_zero_u64(1).to_bool());
    }
}
