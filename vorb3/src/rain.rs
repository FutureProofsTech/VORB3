//! Rain-SP1: the VORB3 one-way function over GF(2^288).
//!
//! The round is
//!
//! ```text
//! x_r = s_{r-1} XOR sk XOR K_r
//! y_r = x_r^-1                  (0 -> 0)
//! s_r = c_r * y_r
//! ct  = s_{14} XOR sk
//! ```
//!
//! with public nonzero diffusion constants `c_r`. The nonlinear inversion is
//! the only non-linear operation; the per-round diffusion is GF(2^288)-linear
//! so the `QuickSilver` proof can apply it to its MAC shares.
//!
//! The witness includes the zero selector `b_r` for the proof gadget:
//!
//! ```text
//! b*b = b,  b*x = 0,  b*y = 0,  x*y = 1 XOR b
//! ```

use crate::ROUNDS;
use crate::blake3;
use crate::field::F288;

#[cfg(not(any(feature = "nist1", feature = "nist3")))]
const SEED: &[u8] = b"VORB3-RAIN288-SP-CONSTANTS-V1";

#[cfg(not(any(feature = "nist1", feature = "nist3")))]
const ROUND_CONTEXTS: [&str; ROUNDS] = [
    "VORB3-RAIN288-SP-K0-V1",
    "VORB3-RAIN288-SP-K1-V1",
    "VORB3-RAIN288-SP-K2-V1",
    "VORB3-RAIN288-SP-K3-V1",
    "VORB3-RAIN288-SP-K4-V1",
    "VORB3-RAIN288-SP-K5-V1",
    "VORB3-RAIN288-SP-K6-V1",
    "VORB3-RAIN288-SP-K7-V1",
    "VORB3-RAIN288-SP-K8-V1",
    "VORB3-RAIN288-SP-K9-V1",
    "VORB3-RAIN288-SP-K10-V1",
    "VORB3-RAIN288-SP-K11-V1",
    "VORB3-RAIN288-SP-K12-V1",
    "VORB3-RAIN288-SP-K13-V1",
    "VORB3-RAIN288-SP-K14-V1",
];

#[cfg(not(any(feature = "nist1", feature = "nist3")))]
const DIFFUSION_CONTEXTS: [&str; ROUNDS] = [
    "VORB3-RAIN288-SP-C0-V1",
    "VORB3-RAIN288-SP-C1-V1",
    "VORB3-RAIN288-SP-C2-V1",
    "VORB3-RAIN288-SP-C3-V1",
    "VORB3-RAIN288-SP-C4-V1",
    "VORB3-RAIN288-SP-C5-V1",
    "VORB3-RAIN288-SP-C6-V1",
    "VORB3-RAIN288-SP-C7-V1",
    "VORB3-RAIN288-SP-C8-V1",
    "VORB3-RAIN288-SP-C9-V1",
    "VORB3-RAIN288-SP-C10-V1",
    "VORB3-RAIN288-SP-C11-V1",
    "VORB3-RAIN288-SP-C12-V1",
    "VORB3-RAIN288-SP-C13-V1",
    "VORB3-RAIN288-SP-C14-V1",
];
#[cfg(feature = "nist1")]
const SEED: &[u8] = b"VORB3-RAIN160-SP-CONSTANTS-V1";

#[cfg(feature = "nist1")]
const ROUND_CONTEXTS: [&str; ROUNDS] = [
    "VORB3-RAIN160-SP-K0-V1",
    "VORB3-RAIN160-SP-K1-V1",
    "VORB3-RAIN160-SP-K2-V1",
    "VORB3-RAIN160-SP-K3-V1",
    "VORB3-RAIN160-SP-K4-V1",
    "VORB3-RAIN160-SP-K5-V1",
    "VORB3-RAIN160-SP-K6-V1",
    "VORB3-RAIN160-SP-K7-V1",
    "VORB3-RAIN160-SP-K8-V1",
    "VORB3-RAIN160-SP-K9-V1",
    "VORB3-RAIN160-SP-K10-V1",
    "VORB3-RAIN160-SP-K11-V1",
    "VORB3-RAIN160-SP-K12-V1",
    "VORB3-RAIN160-SP-K13-V1",
    "VORB3-RAIN160-SP-K14-V1",
];

#[cfg(feature = "nist1")]
const DIFFUSION_CONTEXTS: [&str; ROUNDS] = [
    "VORB3-RAIN160-SP-C0-V1",
    "VORB3-RAIN160-SP-C1-V1",
    "VORB3-RAIN160-SP-C2-V1",
    "VORB3-RAIN160-SP-C3-V1",
    "VORB3-RAIN160-SP-C4-V1",
    "VORB3-RAIN160-SP-C5-V1",
    "VORB3-RAIN160-SP-C6-V1",
    "VORB3-RAIN160-SP-C7-V1",
    "VORB3-RAIN160-SP-C8-V1",
    "VORB3-RAIN160-SP-C9-V1",
    "VORB3-RAIN160-SP-C10-V1",
    "VORB3-RAIN160-SP-C11-V1",
    "VORB3-RAIN160-SP-C12-V1",
    "VORB3-RAIN160-SP-C13-V1",
    "VORB3-RAIN160-SP-C14-V1",
];
#[cfg(feature = "nist3")]
const SEED: &[u8] = b"VORB3-RAIN224-SP-CONSTANTS-V1";

#[cfg(feature = "nist3")]
const ROUND_CONTEXTS: [&str; ROUNDS] = [
    "VORB3-RAIN224-SP-K0-V1",
    "VORB3-RAIN224-SP-K1-V1",
    "VORB3-RAIN224-SP-K2-V1",
    "VORB3-RAIN224-SP-K3-V1",
    "VORB3-RAIN224-SP-K4-V1",
    "VORB3-RAIN224-SP-K5-V1",
    "VORB3-RAIN224-SP-K6-V1",
    "VORB3-RAIN224-SP-K7-V1",
    "VORB3-RAIN224-SP-K8-V1",
    "VORB3-RAIN224-SP-K9-V1",
    "VORB3-RAIN224-SP-K10-V1",
    "VORB3-RAIN224-SP-K11-V1",
    "VORB3-RAIN224-SP-K12-V1",
    "VORB3-RAIN224-SP-K13-V1",
    "VORB3-RAIN224-SP-K14-V1",
];

#[cfg(feature = "nist3")]
const DIFFUSION_CONTEXTS: [&str; ROUNDS] = [
    "VORB3-RAIN224-SP-C0-V1",
    "VORB3-RAIN224-SP-C1-V1",
    "VORB3-RAIN224-SP-C2-V1",
    "VORB3-RAIN224-SP-C3-V1",
    "VORB3-RAIN224-SP-C4-V1",
    "VORB3-RAIN224-SP-C5-V1",
    "VORB3-RAIN224-SP-C6-V1",
    "VORB3-RAIN224-SP-C7-V1",
    "VORB3-RAIN224-SP-C8-V1",
    "VORB3-RAIN224-SP-C9-V1",
    "VORB3-RAIN224-SP-C10-V1",
    "VORB3-RAIN224-SP-C11-V1",
    "VORB3-RAIN224-SP-C12-V1",
    "VORB3-RAIN224-SP-C13-V1",
    "VORB3-RAIN224-SP-C14-V1",
];
/// Public Rain-SP1 round constants and diffusion constants.
pub struct RainConstants {
    pub(crate) diffusion: [F288; ROUNDS],
    pub(crate) round: [F288; ROUNDS],
}

impl RainConstants {
    /// Derives the constants from the frozen KDF labels.
    #[must_use]
    #[inline]
    pub fn derive() -> Self {
        let mut diffusion = [F288::ZERO; ROUNDS];
        let mut round = [F288::ZERO; ROUNDS];
        let mut bytes = [0u8; crate::FIELD_BYTES];
        for (index, context) in DIFFUSION_CONTEXTS.iter().enumerate() {
            blake3::derive_key(context, SEED, &mut bytes);
            if let Some(slot) = diffusion.get_mut(index) {
                *slot = nonzero(F288::from_bytes(bytes));
            }
        }
        for (index, context) in ROUND_CONTEXTS.iter().enumerate() {
            blake3::derive_key(context, SEED, &mut bytes);
            if let Some(slot) = round.get_mut(index) {
                *slot = nonzero(F288::from_bytes(bytes));
            }
        }
        Self { diffusion, round }
    }
}

/// Rain-SP1 witness for the `QuickSilver` proof.
///
/// Fields are crate-visible because the proof module consumes them; they are not
/// exposed to API users.
pub struct RainWitness {
    pub(crate) x: [F288; ROUNDS],
    pub(crate) y: [F288; ROUNDS],
    pub(crate) b: [F288; ROUNDS],
}

impl RainWitness {
    /// Wipes the witness arrays in place.
    #[inline]
    pub(crate) fn wipe(&mut self) {
        for value in &mut self.x {
            value.wipe();
        }
        for value in &mut self.y {
            value.wipe();
        }
        for value in &mut self.b {
            value.wipe();
        }
    }
}

impl Drop for RainWitness {
    #[inline]
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Encrypts `pt` under `sk`, returning the ciphertext and proof witness.
///
/// `0^-1 = 0` is implemented by field exponentiation; the selector `b` is set
/// without a secret-dependent branch.
#[must_use]
#[inline]
pub fn encrypt(sk: F288, pt: F288, constants: &RainConstants) -> (F288, RainWitness) {
    let mut x = [F288::ZERO; ROUNDS];
    let mut y = [F288::ZERO; ROUNDS];
    let mut b = [F288::ZERO; ROUNDS];
    let mut state = pt;

    for index in 0..ROUNDS {
        let round_constant = constants.round.get(index).copied().unwrap_or(F288::ZERO);
        let diffusion = constants
            .diffusion
            .get(index)
            .copied()
            .unwrap_or(F288::ZERO);
        let x_value = state.add_value(sk).add_value(round_constant);
        let zero = x_value.ct_is_zero();
        let selector = F288::from_u64(u64::from(zero.mask() & 1));
        let y_value = x_value.inverse();
        let s_value = diffusion.mul_value(y_value);

        if let Some(slot) = x.get_mut(index) {
            *slot = x_value;
        }
        if let Some(slot) = y.get_mut(index) {
            *slot = y_value;
        }
        if let Some(slot) = b.get_mut(index) {
            *slot = selector;
        }
        state = s_value;
    }

    let ciphertext = state.add_value(sk);
    (ciphertext, RainWitness { x, y, b })
}

#[inline]
fn nonzero(value: F288) -> F288 {
    let zero = value.ct_is_zero();
    F288::ct_select(zero, value, F288::ONE)
}

#[cfg(test)]
mod tests {
    use super::{RainConstants, encrypt};
    use crate::field::F288;

    #[test]
    fn witness_wipe_clears_all_fields() {
        let constants = RainConstants::derive();
        let (_, witness) = encrypt(F288::from_u64(0x1234), F288::from_u64(0x5678), &constants);
        let mut witness = witness;
        witness.wipe();
        assert!(witness.x.iter().all(|value| value.is_zero()));
        assert!(witness.y.iter().all(|value| value.is_zero()));
        assert!(witness.b.iter().all(|value| value.is_zero()));
    }

    #[test]
    fn zero_state_selector_is_set() {
        let constants = RainConstants::derive();
        let pt = F288::from_u64(0x1234);
        let round_constant = constants.round.first().copied().unwrap_or(F288::ZERO);
        let sk = pt + round_constant;
        let (_ct, witness) = encrypt(sk, pt, &constants);
        assert_eq!(witness.x.first().copied().unwrap_or(F288::ONE), F288::ZERO);
        assert_eq!(witness.b.first().copied().unwrap_or(F288::ZERO), F288::ONE);
        assert_eq!(witness.y.first().copied().unwrap_or(F288::ONE), F288::ZERO);
    }
}
