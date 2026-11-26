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

/// Degree of the field polynomial.
const FIELD_DEGREE: u32 = 288;

/// Exponent bits of the product before reduction: 2 * 288 - 2 = 574.
const HIGH_PRODUCT_BIT: u32 = 574;

/// Public exponents of the irreducible polynomial, including the leading term.
const POLY_OFFSETS: [u32; 5] = [0, 1, 10, 11, 288];

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
        let Ok(top_word) = <[u8; 4]>::try_from(tail) else {
            return Self { limbs };
        };
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
    #[must_use]
    #[inline]
    pub fn square(self) -> Self {
        self.mul_value(self)
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
    const fn add_value(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.limbs;
        let [b0, b1, b2, b3, b4] = rhs.limbs;
        Self {
            limbs: [a0 ^ b0, a1 ^ b1, a2 ^ b2, a3 ^ b3, a4 ^ b4],
        }
    }

    /// Field multiplication, without the operator trait.
    #[must_use]
    #[inline]
    fn mul_value(self, rhs: Self) -> Self {
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
fn clmul_u64(left: u64, right: u64) -> u128 {
    let mut result = 0u128;
    let mut index = 0u32;
    while index < 64 {
        let bit = (right >> index) & 1;
        let mask = 0u64.wrapping_sub(bit);
        result ^= u128::from(left & mask) << index;
        index = index.wrapping_add(1);
    }
    result
}

/// XOR `value` into a product limb; public index, no secret branch.
#[inline]
fn xor_limb(limbs: &mut [u64; 10], index: usize, value: u64) {
    if let Some(slot) = limbs.get_mut(index) {
        *slot ^= value;
    }
}

/// Extract a bit from a 640-bit product; public index.
#[inline]
fn product_bit(limbs: &[u64; 10], bit: u32) -> u64 {
    let limb_index = usize::try_from(bit >> 6).unwrap_or(10);
    let offset = bit & 63;
    match limbs.get(limb_index) {
        Some(&limb) => (limb >> offset) & 1,
        None => 0,
    }
}

/// XOR an all-zero/all-one mask at a public bit position.
#[inline]
fn xor_bit_mask(limbs: &mut [u64; 10], bit: u32, mask: u64) {
    let limb_index = usize::try_from(bit >> 6).unwrap_or(10);
    let offset = bit & 63;
    if let Some(slot) = limbs.get_mut(limb_index) {
        *slot ^= mask.wrapping_shl(offset);
    }
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
            xor_limb(&mut product, index, low);
            xor_limb(&mut product, index.wrapping_add(1), high);
        }
    }

    // Masked bitwise reduction, high bit to field degree.
    let mut bit = HIGH_PRODUCT_BIT;
    while bit >= FIELD_DEGREE {
        let current = product_bit(&product, bit);
        let mask = current;
        let shift = bit.wrapping_sub(FIELD_DEGREE);
        for &offset in &POLY_OFFSETS {
            xor_bit_mask(&mut product, shift.wrapping_add(offset), mask);
        }
        bit = bit.wrapping_sub(1);
    }

    if let Some(top) = product.get_mut(4) {
        *top &= 0xFFFF_FFFF;
    }
    let [r0, r1, r2, r3, r4, _, _, _, _, _] = product;
    [r0, r1, r2, r3, r4]
}
