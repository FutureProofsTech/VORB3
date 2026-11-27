//! Key types and validation for VORB3-SP1.

use crate::blake3;
use crate::field::F288;
use crate::rain;
use crate::zeroize::wipe_bytes;
use crate::{FIELD_BYTES, PUBLIC_KEY_LEN};

/// Public key: `pt || ct`, 72 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_LEN],
}

impl PublicKey {
    /// Parses and validates a public key. Rejects zero `pt` or zero `ct`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the length is wrong (compile-time
    /// fixed here) or if either field element is zero.
    #[inline]
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Result<Self, Error> {
        let pt = read_field(&bytes, 0).ok_or(Error::InvalidPublicKey)?;
        let ct = read_field(&bytes, FIELD_BYTES).ok_or(Error::InvalidPublicKey)?;
        if pt.is_zero() || ct.is_zero() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self { bytes })
    }

    /// Derives the public key from an expanded secret key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSecretKey`] if the derived ciphertext is zero.
    #[inline]
    pub fn from_secret(secret: &ExpandedSecretKey) -> Result<Self, Error> {
        let constants = rain::RainConstants::derive();
        let (ct, _witness) = rain::encrypt(secret.sk, secret.pt, &constants);
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        write_field(&mut bytes, 0, secret.pt);
        write_field(&mut bytes, FIELD_BYTES, ct);
        Self::from_bytes(bytes).map_err(|_| Error::InvalidSecretKey)
    }

    /// Returns the canonical 72-byte encoding.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; PUBLIC_KEY_LEN] {
        self.bytes
    }

    /// Returns the canonical encoding by reference.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// Returns `pt`.
    #[must_use]
    #[inline]
    pub fn pt(self) -> F288 {
        read_field(&self.bytes, 0).unwrap_or(F288::ZERO)
    }

    /// Returns `ct`.
    #[must_use]
    #[inline]
    pub fn ct(self) -> F288 {
        read_field(&self.bytes, FIELD_BYTES).unwrap_or(F288::ZERO)
    }
}

/// Compact secret key: a 36-byte seed. Not `Copy`; zeroized on drop.
pub struct SecretKey {
    seed: [u8; FIELD_BYTES],
}

impl SecretKey {
    /// Wraps a seed.
    #[must_use]
    #[inline]
    pub const fn from_seed(seed: [u8; FIELD_BYTES]) -> Self {
        Self { seed }
    }

    /// Returns the seed bytes.
    #[must_use]
    #[inline]
    pub const fn to_seed(&self) -> [u8; FIELD_BYTES] {
        self.seed
    }
}

impl SecretKey {
    /// Wipes the seed in place.
    #[inline]
    pub(crate) fn wipe(&mut self) {
        wipe_bytes(&mut self.seed);
    }
}

impl Drop for SecretKey {
    #[inline]
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Expanded secret key: `sk`, `pt`, and the seed. Zeroized on drop.
pub struct ExpandedSecretKey {
    pub(crate) sk: F288,
    pub(crate) pt: F288,
    seed: [u8; FIELD_BYTES],
}

impl ExpandedSecretKey {
    /// Expands a compact seed with the frozen key-generation labels.
    #[must_use]
    #[inline]
    pub fn from_seed(seed: &SecretKey) -> Self {
        let mut sk_bytes = [0u8; FIELD_BYTES];
        let mut pt_bytes = [0u8; FIELD_BYTES];
        blake3::derive_key("VORB3-KEYGEN-SK-V1", &seed.seed, &mut sk_bytes);
        blake3::derive_key("VORB3-KEYGEN-PT-V1", &seed.seed, &mut pt_bytes);
        let sk = nonzero(F288::from_bytes(sk_bytes));
        let pt = nonzero(F288::from_bytes(pt_bytes));
        wipe_bytes(&mut sk_bytes);
        wipe_bytes(&mut pt_bytes);
        Self {
            sk,
            pt,
            seed: seed.seed,
        }
    }

    /// Derives the public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSecretKey`] if the public key is degenerate.
    #[inline]
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        PublicKey::from_secret(self)
    }
}

impl ExpandedSecretKey {
    /// Wipes the expanded key material in place.
    #[inline]
    pub(crate) fn wipe(&mut self) {
        self.sk.wipe();
        self.pt.wipe();
        wipe_bytes(&mut self.seed);
    }
}

impl Drop for ExpandedSecretKey {
    #[inline]
    fn drop(&mut self) {
        self.wipe();
    }
}

/// API error type. Verification failures are intentionally uniform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A signature is malformed or does not verify.
    InvalidSignature,
    /// A public key is malformed or degenerate.
    InvalidPublicKey,
    /// A secret key expands to a degenerate state.
    InvalidSecretKey,
}

#[inline]
fn read_field(bytes: &[u8; PUBLIC_KEY_LEN], offset: usize) -> Option<F288> {
    let end = offset.checked_add(FIELD_BYTES)?;
    let source = bytes.get(offset..end)?;
    let mut array = [0u8; FIELD_BYTES];
    array.copy_from_slice(source);
    Some(F288::from_bytes(array))
}

#[inline]
fn write_field(bytes: &mut [u8; PUBLIC_KEY_LEN], offset: usize, value: F288) {
    let end = offset.checked_add(FIELD_BYTES);
    if let Some(end) = end
        && let Some(destination) = bytes.get_mut(offset..end)
    {
        destination.copy_from_slice(&value.to_bytes());
    }
}

#[inline]
fn nonzero(value: F288) -> F288 {
    let zero = value.ct_is_zero();
    F288::ct_select(zero, value, F288::ONE)
}

#[cfg(all(test, not(any(feature = "nist1", feature = "nist3"))))]
mod tests {
    use super::{ExpandedSecretKey, F288, SecretKey, read_field, write_field};

    #[test]
    fn compact_key_wipe_clears_seed() {
        let mut key = SecretKey::from_seed([0x5Au8; 36]);
        key.wipe();
        assert!(key.seed.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn expanded_key_wipe_clears_all_fields() {
        let compact = SecretKey::from_seed([0xA5u8; 36]);
        let mut expanded = ExpandedSecretKey::from_seed(&compact);
        expanded.wipe();
        assert!(expanded.sk.is_zero());
        assert!(expanded.pt.is_zero());
        assert!(expanded.seed.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn field_io_bounds_fail_closed() {
        let bytes = [0u8; 72];
        assert!(read_field(&bytes, usize::MAX).is_none());
        assert!(read_field(&bytes, 70).is_none());
        let mut output = [0u8; 72];
        write_field(&mut output, usize::MAX, F288::ONE);
        write_field(&mut output, 70, F288::ONE);
        write_field(&mut output, 0, F288::ONE);
        assert_eq!(read_field(&output, 0), Some(F288::ONE));
    }
}

#[cfg(all(test, any(feature = "nist1", feature = "nist3")))]
mod profile_tests {
    use super::{ExpandedSecretKey, F288, PublicKey, SecretKey, read_field, write_field};
    use crate::{FIELD_BYTES, PUBLIC_KEY_LEN};

    #[cfg(feature = "nist1")]
    const SEED: &[u8] = include_bytes!("../../kat/seed_sp160_32.bin");
    #[cfg(feature = "nist1")]
    const PUBLIC: &[u8] = include_bytes!("../../kat/pk_sp160_32.bin");
    #[cfg(feature = "nist3")]
    const SEED: &[u8] = include_bytes!("../../kat/seed_sp224_32.bin");
    #[cfg(feature = "nist3")]
    const PUBLIC: &[u8] = include_bytes!("../../kat/pk_sp224_32.bin");

    #[test]
    fn profile_key_paths() {
        let kat_seed: [u8; FIELD_BYTES] = SEED.try_into().unwrap_or([0u8; FIELD_BYTES]);
        let mut compact = SecretKey::from_seed(kat_seed);
        assert_eq!(compact.to_seed(), kat_seed);
        compact.wipe();
        assert!(compact.seed.iter().all(|byte| *byte == 0));

        let compact = SecretKey::from_seed(kat_seed);
        let mut expanded = ExpandedSecretKey::from_seed(&compact);
        assert!(!expanded.sk.is_zero());
        assert!(!expanded.pt.is_zero());
        let public_result = expanded.public_key();
        assert!(public_result.is_ok(), "public key derivation failed");
        let Ok(public) = public_result else {
            return;
        };
        let pk: [u8; PUBLIC_KEY_LEN] = PUBLIC.try_into().unwrap_or([0u8; PUBLIC_KEY_LEN]);
        assert_eq!(public.as_bytes(), &pk);
        assert_eq!(public.to_bytes(), pk);
        assert_eq!(public.pt().to_bytes(), pk[..FIELD_BYTES]);
        assert_eq!(public.ct().to_bytes(), pk[FIELD_BYTES..]);
        assert_eq!(public, PublicKey::from_bytes(pk).unwrap_or(public));

        let zero = [0u8; PUBLIC_KEY_LEN];
        assert!(PublicKey::from_bytes(zero).is_err());
        let mut zero_ct = pk;
        zero_ct[FIELD_BYTES..].fill(0);
        assert!(PublicKey::from_bytes(zero_ct).is_err());

        let mut output = [0u8; PUBLIC_KEY_LEN];
        write_field(&mut output, 0, F288::ONE);
        write_field(&mut output, FIELD_BYTES, F288::ONE);
        assert_eq!(read_field(&output, 0), Some(F288::ONE));
        assert_eq!(read_field(&output, FIELD_BYTES), Some(F288::ONE));
        write_field(&mut output, usize::MAX, F288::ONE);
        write_field(&mut output, PUBLIC_KEY_LEN, F288::ONE);
        assert!(read_field(&output, usize::MAX).is_none());
        assert!(read_field(&output, PUBLIC_KEY_LEN).is_none());
        expanded.wipe();
        assert!(expanded.sk.is_zero());
        assert!(expanded.pt.is_zero());
        assert!(expanded.seed.iter().all(|byte| *byte == 0));
    }
}
