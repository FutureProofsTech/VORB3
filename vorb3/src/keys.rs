//! Key types and validation for VORB3-SP1.

use crate::blake3;
use crate::field::F288;
use crate::rain;
use crate::zeroize::wipe_bytes;

/// Public key: `pt || ct`, 72 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 72],
}

impl PublicKey {
    /// Parses and validates a public key. Rejects zero `pt` or zero `ct`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the length is wrong (compile-time
    /// fixed here) or if either field element is zero.
    #[inline]
    pub fn from_bytes(bytes: [u8; 72]) -> Result<Self, Error> {
        let pt = read_field(&bytes, 0).ok_or(Error::InvalidPublicKey)?;
        let ct = read_field(&bytes, 36).ok_or(Error::InvalidPublicKey)?;
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
        if ct.is_zero() {
            return Err(Error::InvalidSecretKey);
        }
        let mut bytes = [0u8; 72];
        write_field(&mut bytes, 0, secret.pt);
        write_field(&mut bytes, 36, ct);
        Self::from_bytes(bytes)
    }

    /// Returns the canonical 72-byte encoding.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; 72] {
        self.bytes
    }

    /// Returns the canonical encoding by reference.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 72] {
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
        read_field(&self.bytes, 36).unwrap_or(F288::ZERO)
    }
}

/// Compact secret key: a 36-byte seed. Not `Copy`; zeroized on drop.
pub struct SecretKey {
    seed: [u8; 36],
}

impl SecretKey {
    /// Wraps a seed.
    #[must_use]
    #[inline]
    pub const fn from_seed(seed: [u8; 36]) -> Self {
        Self { seed }
    }

    /// Returns the seed bytes.
    #[must_use]
    #[inline]
    pub const fn to_seed(&self) -> [u8; 36] {
        self.seed
    }
}

impl Drop for SecretKey {
    #[inline]
    fn drop(&mut self) {
        wipe_bytes(&mut self.seed);
    }
}

/// Expanded secret key: `sk`, `pt`, and the seed. Zeroized on drop.
pub struct ExpandedSecretKey {
    pub(crate) sk: F288,
    pub(crate) pt: F288,
    seed: [u8; 36],
}

impl ExpandedSecretKey {
    /// Expands a compact seed with the frozen key-generation labels.
    #[must_use]
    #[inline]
    pub fn from_seed(seed: &SecretKey) -> Self {
        let mut sk_bytes = [0u8; 36];
        let mut pt_bytes = [0u8; 36];
        blake3::derive_key("VORB3-KEYGEN-SK-V1", &seed.seed, &mut sk_bytes);
        blake3::derive_key("VORB3-KEYGEN-PT-V1", &seed.seed, &mut pt_bytes);
        let sk = nonzero(F288::from_bytes(sk_bytes));
        let pt = nonzero(F288::from_bytes(pt_bytes));
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

impl Drop for ExpandedSecretKey {
    #[inline]
    fn drop(&mut self) {
        self.sk.wipe();
        self.pt.wipe();
        wipe_bytes(&mut self.seed);
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
fn read_field(bytes: &[u8; 72], offset: usize) -> Option<F288> {
    let end = offset.checked_add(36)?;
    let source = bytes.get(offset..end)?;
    let array = <[u8; 36]>::try_from(source).ok()?;
    Some(F288::from_bytes(array))
}

#[inline]
fn write_field(bytes: &mut [u8; 72], offset: usize, value: F288) {
    let end = offset.checked_add(36);
    if let Some(end) = end
        && let Some(destination) = bytes.get_mut(offset..end)
    {
        destination.copy_from_slice(&value.to_bytes());
    }
}

#[inline]
fn nonzero(value: F288) -> F288 {
    if value.is_zero() { F288::ONE } else { value }
}
