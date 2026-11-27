//! Small binary-field arithmetic for compact NIST-tier profiles.
//!
//! Elements are 32-bit limbs, little-endian. Multiplication is carry-less;
//! reduction uses the profile polynomial `x^BITS + x^A + x^B + x^C + 1`.
//! Every value-dependent operation is mask-based.

use core::hint::black_box;
use core::ops::{Add, Mul, Sub};

use crate::ct::{CtChoice, ct_is_zero_u64};

macro_rules! impl_small_field {
    ($name:ident, $limbs:expr, $product_limbs:expr, $bytes:expr, $bits:expr, $a:expr, $b:expr, $c:expr, $one:expr) => {
        /// A field element in the profile's binary field.
        #[derive(Clone, Copy, Default)]
        pub struct $name {
            limbs: [u32; $limbs],
        }

        impl $name {
            /// Zero.
            pub const ZERO: Self = Self {
                limbs: [0u32; $limbs],
            };
            /// One.
            pub const ONE: Self = Self { limbs: $one };

            /// Decodes the canonical little-endian representation.
            #[must_use]
            #[inline]
            pub fn from_bytes(bytes: [u8; $bytes]) -> Self {
                let mut limbs = [0u32; $limbs];
                for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(4)) {
                    if let Ok(word) = <[u8; 4]>::try_from(chunk) {
                        *limb = u32::from_le_bytes(word);
                    }
                }
                Self { limbs }
            }

            /// Encodes the canonical little-endian representation.
            #[must_use]
            #[inline]
            pub fn to_bytes(self) -> [u8; $bytes] {
                let mut out = [0u8; $bytes];
                for (chunk, limb) in out.chunks_exact_mut(4).zip(self.limbs) {
                    chunk.copy_from_slice(&limb.to_le_bytes());
                }
                out
            }

            /// Constructs a small field element.
            #[must_use]
            #[inline]
            pub const fn from_u64(value: u64) -> Self {
                let [b0, b1, b2, b3, b4, b5, b6, b7] = value.to_le_bytes();
                let low = u32::from_le_bytes([b0, b1, b2, b3]);
                let high = u32::from_le_bytes([b4, b5, b6, b7]);
                let mut limbs = [0u32; $limbs];
                if $limbs > 0 {
                    limbs[0] = low;
                }
                if $limbs > 1 {
                    limbs[1] = high;
                }
                Self { limbs }
            }

            /// Field addition.
            #[must_use]
            #[inline]
            pub fn add_value(self, other: Self) -> Self {
                let mut limbs = [0u32; $limbs];
                for ((out, left), right) in limbs.iter_mut().zip(self.limbs).zip(other.limbs) {
                    *out = left ^ right;
                }
                Self { limbs }
            }

            /// Field multiplication.
            #[must_use]
            #[inline]
            pub fn mul_value(self, other: Self) -> Self {
                let mut product = [0u32; $product_limbs];
                for (i, left) in self.limbs.iter().copied().enumerate() {
                    for (j, right) in other.limbs.iter().copied().enumerate() {
                        let word = clmul32(left, right);
                        let [w0, w1, w2, w3, w4, w5, w6, w7] = word.to_le_bytes();
                        let low = u32::from_le_bytes([w0, w1, w2, w3]);
                        let high = u32::from_le_bytes([w4, w5, w6, w7]);
                        if let Some(slot) = product.get_mut(i.wrapping_add(j)) {
                            *slot ^= low;
                        }
                        if let Some(slot) = product.get_mut(i.wrapping_add(j).wrapping_add(1)) {
                            *slot ^= high;
                        }
                    }
                }
                reduce_words::<$product_limbs>($bits, $a, $b, $c, &mut product);
                let mut limbs = [0u32; $limbs];
                for (out, word) in limbs.iter_mut().zip(product) {
                    *out = word;
                }
                Self { limbs }
            }

            /// Field squaring.
            ///
            /// Squaring inserts zero bits between the coefficient bits, so the
            /// 5/7-limb schoolbook product collapses to one spread per limb.
            #[must_use]
            #[inline]
            pub fn square(self) -> Self {
                let mut product = [0u32; $product_limbs];
                for (index, limb) in self.limbs.iter().copied().enumerate() {
                    let spread = spread32(limb);
                    let low = u32::try_from(spread & 0xFFFF_FFFF).unwrap_or(0);
                    let high = u32::try_from(spread >> 32).unwrap_or(0);
                    if let Some(slot) = product.get_mut(index.wrapping_mul(2)) {
                        *slot ^= low;
                    }
                    if let Some(slot) = product.get_mut(index.wrapping_mul(2).wrapping_add(1)) {
                        *slot ^= high;
                    }
                }
                reduce_words::<$product_limbs>($bits, $a, $b, $c, &mut product);
                let mut limbs = [0u32; $limbs];
                for (out, word) in limbs.iter_mut().zip(product) {
                    *out = word;
                }
                Self { limbs }
            }

            /// Field inversion with `0 -> 0`, using the public exponent
            /// `2^BITS - 2`.
            ///
            /// Itoh-Tsujii binary chain: `n = BITS - 1` squarings and about
            /// `log2(n)` multiplications instead of `n-1` multiplications.
            #[must_use]
            #[inline]
            pub fn inverse(self) -> Self {
                let n = $bits.wrapping_sub(1);
                let mut value = self;
                let mut width = 1usize;
                // Skip the leading chain bit: `width = 1` already represents it.
                let mut mask = n.next_power_of_two() >> 2;
                while mask != 0 {
                    let original = value;
                    let mut squared = value;
                    let mut count = 0usize;
                    while count < width {
                        squared = squared.square();
                        count = count.wrapping_add(1);
                    }
                    value = squared.mul_value(original);
                    width = width.wrapping_mul(2);
                    if (n & mask) != 0 {
                        value = value.square().mul_value(self);
                        width = width.wrapping_add(1);
                    }
                    mask >>= 1;
                }
                value.square()
            }

            /// Constant-time zero test.
            #[must_use]
            #[inline]
            pub(crate) fn ct_is_zero(self) -> CtChoice {
                let mut any = 0u32;
                for limb in self.limbs {
                    any |= limb;
                }
                ct_is_zero_u64(u64::from(any))
            }

            /// Constant-time equality.
            #[must_use]
            #[inline]
            #[allow(dead_code)]
            pub(crate) fn ct_eq(self, other: Self) -> CtChoice {
                let mut any = 0u32;
                for (left, right) in self.limbs.iter().zip(other.limbs) {
                    any |= left ^ right;
                }
                ct_is_zero_u64(u64::from(any))
            }

            /// Constant-time selection.
            #[must_use]
            #[inline]
            pub(crate) fn ct_select(choice: CtChoice, if_false: Self, if_true: Self) -> Self {
                let mask = u32::from(choice.mask());
                let mask = mask | (mask << 8) | (mask << 16) | (mask << 24);
                let mut limbs = [0u32; $limbs];
                for ((out, left), right) in limbs.iter_mut().zip(if_false.limbs).zip(if_true.limbs)
                {
                    *out = (left & !mask) | (right & mask);
                }
                Self { limbs }
            }

            /// Declassified zero test. Use only for public values.
            #[must_use]
            #[inline]
            pub fn is_zero(self) -> bool {
                self.ct_is_zero().to_bool()
            }

            /// Best-effort wipe.
            #[inline]
            pub fn wipe(&mut self) {
                self.limbs.fill(0);
                black_box(self.limbs);
            }
        }

        impl Add for $name {
            type Output = Self;
            #[inline]
            fn add(self, other: Self) -> Self {
                self.add_value(other)
            }
        }

        impl Sub for $name {
            type Output = Self;
            #[inline]
            fn sub(self, other: Self) -> Self {
                self.add_value(other)
            }
        }

        impl Mul for $name {
            type Output = Self;
            #[inline]
            fn mul(self, other: Self) -> Self {
                self.mul_value(other)
            }
        }

        impl PartialEq for $name {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.limbs == other.limbs
            }
        }
        impl Eq for $name {}

        impl core::fmt::Debug for $name {
            #[inline]
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("SmallField(..)")
            }
        }
    };
}

#[inline]
fn clmul32(left: u32, right: u32) -> u64 {
    let mut product = 0u64;
    for bit in 0..32 {
        let mask = 0u64.wrapping_sub(u64::from((right >> bit) & 1));
        product ^= (u64::from(left) << bit) & mask;
    }
    product
}

#[inline]
fn spread32(value: u32) -> u64 {
    let mut spread = u64::from(value);
    spread = (spread | (spread << 16)) & 0x0000_FFFF_0000_FFFF;
    spread = (spread | (spread << 8)) & 0x00FF_00FF_00FF_00FF;
    spread = (spread | (spread << 4)) & 0x0F0F_0F0F_0F0F_0F0F;
    spread = (spread | (spread << 2)) & 0x3333_3333_3333_3333;
    spread = (spread | (spread << 1)) & 0x5555_5555_5555_5555;
    spread
}

/// XOR `value << shift` into a fixed 32-bit word array at a public index.
#[inline]
fn xor_shifted<const N: usize>(words: &mut [u32; N], index: usize, shift: usize, value: u32) {
    let wide = u64::from(value) << shift;
    let low = u32::try_from(wide & 0xFFFF_FFFF).unwrap_or(0);
    let high = u32::try_from(wide >> 32).unwrap_or(0);
    if let Some(slot) = words.get_mut(index) {
        *slot ^= low;
    }
    if let Some(slot) = words.get_mut(index.wrapping_add(1)) {
        *slot ^= high;
    }
}

/// Reduce a 2L-limb product when `BITS` is a multiple of 32.
///
/// For `x^BITS = x^a + x^b + x^c + 1`, each high word reduces to four shifted
/// copies at `word - L`. Processing high words in descending order folds the
/// feedback back into the same pass.
#[inline]
fn reduce_words<const N: usize>(bits: usize, a: usize, b: usize, c: usize, words: &mut [u32; N]) {
    let limbs = bits / 32;
    let mut index = N;
    while index > limbs {
        index = index.wrapping_sub(1);
        let word = words.get(index).copied().unwrap_or(0);
        if let Some(slot) = words.get_mut(index) {
            *slot = 0;
        }
        let base = index.wrapping_sub(limbs);
        for shift in [0usize, a, b, c] {
            xor_shifted(words, base, shift, word);
        }
    }
}

#[cfg(feature = "nist1")]
impl_small_field!(
    F160,
    5,
    10,
    20,
    160usize,
    5usize,
    3usize,
    2usize,
    [1, 0, 0, 0, 0]
);
#[cfg(feature = "nist3")]
impl_small_field!(
    F224,
    7,
    14,
    28,
    224usize,
    9usize,
    8usize,
    3usize,
    [1, 0, 0, 0, 0, 0, 0]
);

#[cfg(test)]
mod tests {
    #[cfg(feature = "nist1")]
    use super::F160;
    #[cfg(feature = "nist3")]
    use super::F224;

    #[cfg(feature = "nist1")]
    const A160: [u8; 20] = [
        0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49, 0x50, 0x57, 0x5e, 0x65,
        0x6c, 0x73, 0x7a, 0x81, 0x88,
    ];
    #[cfg(feature = "nist1")]
    const B160: [u8; 20] = [
        0x80, 0x8b, 0x96, 0xa1, 0xac, 0xb7, 0xc2, 0xcd, 0xd8, 0xe3, 0xee, 0xf9, 0x04, 0x0f, 0x1a,
        0x25, 0x30, 0x3b, 0x46, 0x51,
    ];
    #[cfg(feature = "nist1")]
    const MUL160: [u8; 20] = [
        0xda, 0x20, 0xa0, 0xbc, 0xa1, 0xf0, 0xfe, 0xd2, 0x79, 0x2d, 0x40, 0x54, 0xb8, 0x96, 0xa1,
        0xaf, 0x6e, 0xec, 0xad, 0x3f,
    ];
    #[cfg(feature = "nist1")]
    const INV160: [u8; 20] = [
        0xef, 0x6b, 0x7a, 0x2a, 0x22, 0xa1, 0xf7, 0x15, 0x17, 0x31, 0xb4, 0xd8, 0xc9, 0x7c, 0x83,
        0x3f, 0x70, 0x78, 0x96, 0xec,
    ];
    #[cfg(feature = "nist1")]
    const SQ160: [u8; 20] = [
        0x77, 0xda, 0x46, 0xfd, 0x4a, 0xfe, 0x66, 0xf5, 0xaa, 0x67, 0x86, 0x69, 0xca, 0x4d, 0xe6,
        0x47, 0x6a, 0x45, 0x4f, 0x5b,
    ];
    #[cfg(feature = "nist1")]
    const ADD160: [u8; 20] = [
        0x83, 0x81, 0x87, 0xb9, 0xb3, 0x91, 0xef, 0xf9, 0xe3, 0xa1, 0xa7, 0xa9, 0x53, 0x51, 0x7f,
        0x49, 0x43, 0x41, 0xc7, 0xd9,
    ];

    #[cfg(feature = "nist3")]
    const A224: [u8; 28] = [
        0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49, 0x50, 0x57, 0x5e, 0x65,
        0x6c, 0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9, 0xc0,
    ];
    #[cfg(feature = "nist3")]
    const B224: [u8; 28] = [
        0x80, 0x8b, 0x96, 0xa1, 0xac, 0xb7, 0xc2, 0xcd, 0xd8, 0xe3, 0xee, 0xf9, 0x04, 0x0f, 0x1a,
        0x25, 0x30, 0x3b, 0x46, 0x51, 0x5c, 0x67, 0x72, 0x7d, 0x88, 0x93, 0x9e, 0xa9,
    ];
    #[cfg(feature = "nist3")]
    const MUL224: [u8; 28] = [
        0x85, 0x57, 0xb2, 0x99, 0xfd, 0xc6, 0x0c, 0x23, 0x7e, 0x82, 0x00, 0xa3, 0xa2, 0xa0, 0xa0,
        0x0e, 0x92, 0x17, 0x8f, 0x2e, 0x66, 0xd5, 0x1f, 0x17, 0x5f, 0x9d, 0x02, 0x38,
    ];
    #[cfg(feature = "nist3")]
    const INV224: [u8; 28] = [
        0x41, 0x5f, 0x22, 0x09, 0x54, 0x44, 0xdc, 0xf3, 0x12, 0x2a, 0x26, 0x88, 0x9a, 0xb7, 0x98,
        0x6d, 0x69, 0x4c, 0x5a, 0x05, 0x05, 0x86, 0x6c, 0x2a, 0x18, 0x46, 0xd5, 0xa4,
    ];
    #[cfg(feature = "nist3")]
    const SQ224: [u8; 28] = [
        0xfe, 0x96, 0xa9, 0x46, 0x10, 0xb3, 0x1b, 0x72, 0x63, 0x42, 0x96, 0x86, 0x6e, 0xb9, 0x66,
        0x70, 0x5d, 0xbd, 0x55, 0x44, 0xe2, 0xb9, 0xea, 0x70, 0x91, 0xbd, 0x99, 0xc1,
    ];
    #[cfg(feature = "nist3")]
    const ADD224: [u8; 28] = [
        0x83, 0x81, 0x87, 0xb9, 0xb3, 0x91, 0xef, 0xf9, 0xe3, 0xa1, 0xa7, 0xa9, 0x53, 0x51, 0x7f,
        0x49, 0x43, 0x41, 0xc7, 0xd9, 0xd3, 0xf1, 0xef, 0xd9, 0x23, 0x21, 0x27, 0x69,
    ];

    #[cfg(feature = "nist1")]
    #[test]
    fn f160_vectors() {
        let a = F160::from_bytes(A160);
        let b = F160::from_bytes(B160);
        assert_eq!((a * b).to_bytes(), MUL160);
        assert_eq!(a.inverse().to_bytes(), INV160);
        assert_eq!(a.square().to_bytes(), SQ160);
        assert_eq!((a + b).to_bytes(), ADD160);
        assert_eq!(a * a.inverse(), F160::ONE);
        assert_eq!(F160::from_bytes(a.to_bytes()), a);
    }

    #[cfg(feature = "nist3")]
    #[test]
    fn f224_vectors() {
        let a = F224::from_bytes(A224);
        let b = F224::from_bytes(B224);
        assert_eq!((a * b).to_bytes(), MUL224);
        assert_eq!(a.inverse().to_bytes(), INV224);
        assert_eq!(a.square().to_bytes(), SQ224);
        assert_eq!((a + b).to_bytes(), ADD224);
        assert_eq!(a * a.inverse(), F224::ONE);
        assert_eq!(F224::from_bytes(a.to_bytes()), a);
    }
}

/// Profile-selected field type used by the shared implementation.
#[cfg(feature = "nist1")]
pub type F288 = F160;

/// Profile-selected field type used by the shared implementation.
#[cfg(feature = "nist3")]
pub type F288 = F224;

#[cfg(test)]
mod profile_tests {
    struct Discard;
    impl core::fmt::Write for Discard {
        fn write_str(&mut self, _s: &str) -> core::fmt::Result {
            Ok(())
        }
    }

    #[cfg(feature = "nist1")]
    use super::F160;
    #[cfg(feature = "nist3")]
    use super::F224;
    use crate::ct::CtChoice;

    #[cfg(feature = "nist1")]
    #[test]
    fn f160_api_coverage() {
        let zero = F160::ZERO;
        let one = F160::ONE;
        let two = F160::from_u64(2);
        let three = F160::from_u64(3);
        assert_eq!(two + three, F160::from_u64(1));
        assert_eq!(three - two, one);
        assert_eq!(two * three, F160::from_u64(6));
        assert_eq!(two.square(), F160::from_u64(4));
        assert!(zero.is_zero());
        assert!(!one.is_zero());
        assert!(zero.ct_is_zero().to_bool());
        assert!(two.ct_eq(two).to_bool());
        assert!(!two.ct_eq(three).to_bool());
        let selected = F160::ct_select(CtChoice::from_bool(true), two, three);
        assert_eq!(selected, three);
        let selected = F160::ct_select(CtChoice::from_bool(false), two, three);
        assert_eq!(selected, two);
        assert_eq!(F160::from_bytes(one.to_bytes()), one);
        let mut wiped = three;
        wiped.wipe();
        assert!(wiped.is_zero());
        let _ = core::fmt::Write::write_fmt(&mut Discard, format_args!("{three:?}"));
    }

    #[cfg(feature = "nist3")]
    #[test]
    fn f224_api_coverage() {
        let zero = F224::ZERO;
        let one = F224::ONE;
        let two = F224::from_u64(2);
        let three = F224::from_u64(3);
        assert_eq!(two + three, F224::from_u64(1));
        assert_eq!(three - two, one);
        assert_eq!(two * three, F224::from_u64(6));
        assert_eq!(two.square(), F224::from_u64(4));
        assert!(zero.is_zero());
        assert!(!one.is_zero());
        assert!(zero.ct_is_zero().to_bool());
        assert!(two.ct_eq(two).to_bool());
        assert!(!two.ct_eq(three).to_bool());
        let selected = F224::ct_select(CtChoice::from_bool(true), two, three);
        assert_eq!(selected, three);
        let selected = F224::ct_select(CtChoice::from_bool(false), two, three);
        assert_eq!(selected, two);
        assert_eq!(F224::from_bytes(one.to_bytes()), one);
        let mut wiped = three;
        wiped.wipe();
        assert!(wiped.is_zero());
        let _ = core::fmt::Write::write_fmt(&mut Discard, format_args!("{three:?}"));
    }
}
