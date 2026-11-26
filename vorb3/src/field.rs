//! Arithmetic in GF(2^288) for the frozen VORB3-SP1 profile.
//!
//! The field is represented in polynomial basis modulo
//!
//! ```text
//! p(x) = x^288 + x^11 + x^10 + x + 1
//! ```
//!
//! with a 36-byte little-endian canonical encoding. The implementation is
//! intentionally simple and constant-time: fixed iteration counts, masked
//! carry-less multiplication, and a masked bitwise reduction. Optimisation is a
//! later phase; correctness and timing discipline come first.

use core::fmt;
use core::ops::{Add, Mul, Sub};

use crate::ct::{CtChoice, ct_is_zero_u64};

/// Number of 64-bit limbs in a field element.
const LIMB_COUNT: usize = 5;

/// An element of GF(2^288).
///
/// Field values are secret-bearing. `Debug` is redacted; equality is
/// constant-time internally but exposes a declassified `bool` through
/// [`PartialEq`], which is only appropriate for public decisions.
#[derive(Clone, Copy)]
pub struct F288 {
    limbs: [u64; LIMB_COUNT],
}

impl F288 {
    /// The additive identity.
    pub const ZERO: Self = Self {
        limbs: [0; LIMB_COUNT],
    };

    /// The multiplicative identity.
    pub const ONE: Self = Self {
        limbs: [1, 0, 0, 0, 0],
    };

    /// Constructs a field element from a `u64`.
    #[must_use]
    #[inline]
    pub const fn from_u64(value: u64) -> Self {
        Self {
            limbs: [value, 0, 0, 0, 0],
        }
    }

    /// Decodes the canonical 36-byte little-endian representation.
    #[must_use]
    #[inline]
    pub fn from_bytes(bytes: [u8; 36]) -> Self {
        let mut limbs = [0u64; LIMB_COUNT];
        let (head, tail) = bytes.split_at(32);
        for (index, chunk) in head.as_chunks::<8>().0.iter().enumerate() {
            if let Some(slot) = limbs.get_mut(index) {
                *slot = u64::from_le_bytes(*chunk);
            }
        }
        let mut top_word = [0u8; 4];
        top_word.copy_from_slice(tail);
        if let Some(slot) = limbs.get_mut(4) {
            *slot = u64::from(u32::from_le_bytes(top_word));
        }
        Self { limbs }
    }

    /// Encodes the canonical 36-byte little-endian representation.
    #[must_use]
    #[inline]
    pub fn to_bytes(self) -> [u8; 36] {
        let [limb0, limb1, limb2, limb3, limb4] = self.limbs;
        let mut out = [0u8; 36];
        let (head, tail) = out.split_at_mut(32);
        let words = [limb0, limb1, limb2, limb3];
        for (chunk, word) in head.as_chunks_mut::<8>().0.iter_mut().zip(words.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        let top = u32::try_from(limb4 & 0xFFFF_FFFF).unwrap_or(0);
        let top_bytes = top.to_le_bytes();
        for (dst, src) in tail.iter_mut().zip(top_bytes.iter()) {
            *dst = *src;
        }
        out
    }

    /// Returns true iff the element is zero.
    ///
    /// This declassifies one bit. For secret values, use the internal
    /// constant-time choice instead.
    #[must_use]
    #[inline]
    pub fn is_zero(self) -> bool {
        self.ct_is_zero().to_bool()
    }

    /// Constant-time equality.
    #[must_use]
    #[inline]
    pub(crate) fn ct_eq(self, other: Self) -> CtChoice {
        let [a0, a1, a2, a3, a4] = self.limbs;
        let [b0, b1, b2, b3, b4] = other.limbs;
        ct_is_zero_u64(a0 ^ b0)
            .and(ct_is_zero_u64(a1 ^ b1))
            .and(ct_is_zero_u64(a2 ^ b2))
            .and(ct_is_zero_u64(a3 ^ b3))
            .and(ct_is_zero_u64(a4 ^ b4))
    }

    /// Constant-time field selection: returns `if_true` when `choice` is true,
    /// otherwise `if_false`.
    #[must_use]
    #[inline]
    pub(crate) fn ct_select(choice: CtChoice, if_false: Self, if_true: Self) -> Self {
        let [a0, a1, a2, a3, a4] = if_false.limbs;
        let [b0, b1, b2, b3, b4] = if_true.limbs;
        Self {
            limbs: [
                choice.select_u64(a0, b0),
                choice.select_u64(a1, b1),
                choice.select_u64(a2, b2),
                choice.select_u64(a3, b3),
                choice.select_u64(a4, b4),
            ],
        }
    }

    /// Wipes this field element in place.
    ///
    /// This is best-effort zeroization of the owned limbs; it uses the safe
    /// `fill(0)` plus `black_box` barrier.
    #[inline]
    pub fn wipe(&mut self) {
        crate::zeroize::wipe_u64s(&mut self.limbs);
    }

    /// Constant-time zero test.
    #[must_use]
    #[inline]
    pub(crate) fn ct_is_zero(self) -> CtChoice {
        let [limb0, limb1, limb2, limb3, limb4] = self.limbs;
        ct_is_zero_u64(limb0 | limb1 | limb2 | limb3 | limb4)
    }

    /// Squaring in GF(2^288).
    ///
    /// Bit interleaving expands each limb to even polynomial positions, so the
    /// 5×5 carry-less product collapses to five independent spreads.
    #[must_use]
    #[inline]
    pub fn square(self) -> Self {
        Self {
            limbs: square_reduce(self.limbs),
        }
    }

    /// Field inversion, with `0^-1 = 0`.
    ///
    /// Itoh–Tsujii addition chain for `2^288 - 2`: 16 chain multiplications and
    /// fixed squarings, with no secret-dependent branches.
    #[must_use]
    #[inline]
    pub fn inverse(self) -> Self {
        let mut table = [(0u16, Self::ZERO); CHAIN.len() + 1];
        if let Some(slot) = table.get_mut(0) {
            *slot = (1, self);
        }
        for (index, &(target, left, right)) in CHAIN.iter().enumerate() {
            let left_value = chain_lookup(&table, left);
            let right_value = chain_lookup(&table, right);
            let mut value = left_value;
            let mut squarings = 0u16;
            while squarings < right {
                value = value.square();
                squarings = squarings.wrapping_add(1);
            }
            value = value.mul_value(right_value);
            if let Some(slot) = table.get_mut(index.wrapping_add(1)) {
                *slot = (target, value);
            }
        }
        chain_lookup(&table, 287).square()
    }
}

impl F288 {
    /// Field addition (XOR), without the operator trait.
    #[must_use]
    #[inline]
    pub(crate) const fn add_value(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.limbs;
        let [b0, b1, b2, b3, b4] = rhs.limbs;
        Self {
            limbs: [a0 ^ b0, a1 ^ b1, a2 ^ b2, a3 ^ b3, a4 ^ b4],
        }
    }

    /// Field multiplication, without the operator trait.
    #[must_use]
    #[inline]
    pub(crate) fn mul_value(self, rhs: Self) -> Self {
        Self {
            limbs: mul_reduce(self.limbs, rhs.limbs),
        }
    }
}

/// Itoh–Tsujii addition chain for exponents `2^n - 1`, ending at 287.
const CHAIN: [(u16, u16, u16); 16] = [
    (2, 1, 1),
    (3, 2, 1),
    (6, 3, 3),
    (7, 6, 1),
    (14, 7, 7),
    (15, 14, 1),
    (30, 15, 15),
    (31, 30, 1),
    (62, 31, 31),
    (63, 62, 1),
    (126, 63, 63),
    (127, 126, 1),
    (254, 127, 127),
    (255, 254, 1),
    (286, 255, 31),
    (287, 286, 1),
];

/// Look up a previously computed chain value by exponent.
#[inline]
fn chain_lookup(table: &[(u16, F288); CHAIN.len() + 1], exponent: u16) -> F288 {
    for &(candidate, value) in table {
        if candidate == exponent {
            return value;
        }
    }
    F288::ZERO
}

impl Add for F288 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_value(rhs)
    }
}

impl Sub for F288 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        // Characteristic two: subtraction is addition.
        self.add_value(rhs)
    }
}

impl Mul for F288 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        self.mul_value(rhs)
    }
}

impl PartialEq for F288 {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(*other).to_bool()
    }
}

impl Eq for F288 {}

impl fmt::Debug for F288 {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("F288(..)")
    }
}

/// Carry-less multiplication of two 64-bit words, fixed 64 iterations.
#[inline]
fn clmul_u64(left: u64, mut right: u64) -> u128 {
    // Horner form: shift the accumulator by one and add the masked left word.
    // Reversing `right` consumes bits MSB-first, so the final result has the
    // original bit order. This avoids a variable 128-bit shift per bit.
    right = right.reverse_bits();
    let mut result = 0u128;
    let mut index = 0u32;
    while index < 64 {
        let mask = 0u64.wrapping_sub(right & 1);
        result = (result << 1) ^ u128::from(left & mask);
        right >>= 1;
        index = index.wrapping_add(1);
    }
    result
}

/// Spread the 64 bits of `value` to the even positions of a 128-bit word.
#[inline]
fn spread64(value: u64) -> u128 {
    let mut spread = u128::from(value);
    spread = (spread | (spread << 32)) & 0x0000_0000_FFFF_FFFF_0000_0000_FFFF_FFFFu128;
    spread = (spread | (spread << 16)) & 0x0000_FFFF_0000_FFFF_0000_FFFF_0000_FFFFu128;
    spread = (spread | (spread << 8)) & 0x00FF_00FF_00FF_00FF_00FF_00FF_00FF_00FFu128;
    spread = (spread | (spread << 4)) & 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0Fu128;
    spread = (spread | (spread << 2)) & 0x3333_3333_3333_3333_3333_3333_3333_3333u128;
    spread = (spread | (spread << 1)) & 0x5555_5555_5555_5555_5555_5555_5555_5555u128;
    spread
}

/// XOR a 64-bit word into the 640-bit accumulator at a public bit offset.
#[inline]
fn xor_u64_at(limbs: &mut [u64; 10], bit: u32, value: u64) {
    let limb_index = usize::try_from(bit >> 6).unwrap_or(10);
    let shift = bit & 63;
    let shifted = u128::from(value) << shift;
    let low = u64::try_from(shifted & 0xFFFF_FFFF_FFFF_FFFF).unwrap_or(0);
    let high = u64::try_from(shifted >> 64).unwrap_or(0);
    if let Some(slot) = limbs.get_mut(limb_index) {
        *slot ^= low;
    }
    if let Some(slot) = limbs.get_mut(limb_index.wrapping_add(1)) {
        *slot ^= high;
    }
}

/// Reduce a 576-bit product with five fixed word reductions.
///
/// For a high word at bit base `w*64` (w >= 5), each bit at `base+j` reduces to
/// `j-288`, `j-287`, `j-278`, `j-277`. Word 4 contributes only its high 32
/// bits; its generated terms are handled last so feedback is included.
#[inline]
fn reduce_product(product: &mut [u64; 10]) -> [u64; 5] {
    for word_index in (4usize..=8).rev() {
        let word = product.get(word_index).copied().unwrap_or(0);
        if word_index == 4 {
            let high = word >> 32;
            xor_u64_at(product, 0, high);
            xor_u64_at(product, 1, high);
            xor_u64_at(product, 10, high);
            xor_u64_at(product, 11, high);
        } else {
            let base = u32::try_from(word_index.wrapping_mul(64).wrapping_sub(288)).unwrap_or(0);
            xor_u64_at(product, base, word);
            xor_u64_at(product, base.wrapping_add(1), word);
            xor_u64_at(product, base.wrapping_add(10), word);
            xor_u64_at(product, base.wrapping_add(11), word);
        }
    }
    if let Some(top) = product.get_mut(4) {
        *top &= 0xFFFF_FFFF;
    }
    let [r0, r1, r2, r3, r4, _, _, _, _, _] = *product;
    [r0, r1, r2, r3, r4]
}

/// Square a field element and reduce.
#[inline]
fn square_reduce(value: [u64; 5]) -> [u64; 5] {
    let mut product = [0u64; 10];
    for (index, limb) in value.iter().enumerate() {
        let spread = spread64(*limb);
        let low = u64::try_from(spread & 0xFFFF_FFFF_FFFF_FFFF).unwrap_or(0);
        let high = u64::try_from(spread >> 64).unwrap_or(0);
        if let Some(slot) = product.get_mut(index.wrapping_mul(2)) {
            *slot = low;
        }
        if let Some(slot) = product.get_mut(index.wrapping_mul(2).wrapping_add(1)) {
            *slot = high;
        }
    }
    reduce_product(&mut product)
}

/// Multiply two 5-limb elements and reduce modulo the field polynomial.
#[inline]
fn mul_reduce(left: [u64; LIMB_COUNT], right: [u64; LIMB_COUNT]) -> [u64; LIMB_COUNT] {
    let mut product = [0u64; 10];
    for (left_index, &left_limb) in left.iter().enumerate() {
        for (right_index, &right_limb) in right.iter().enumerate() {
            let product_128 = clmul_u64(left_limb, right_limb);
            let low = u64::try_from(product_128 & 0xFFFF_FFFF_FFFF_FFFF).unwrap_or(0);
            let high = u64::try_from(product_128 >> 64).unwrap_or(0);
            let index = left_index.wrapping_add(right_index);
            if let Some(slot) = product.get_mut(index) {
                *slot ^= low;
            }
            if let Some(slot) = product.get_mut(index.wrapping_add(1)) {
                *slot ^= high;
            }
        }
    }
    reduce_product(&mut product)
}

#[cfg(test)]
mod tests {
    use super::{CHAIN, F288, chain_lookup};

    #[test]
    fn defensive_lookups_return_zero() {
        let table = [(0u16, F288::ONE); CHAIN.len() + 1];
        assert!(chain_lookup(&table, 999).is_zero());
    }
}
