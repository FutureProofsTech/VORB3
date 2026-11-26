//! Fixed-size VORB3-SP1 signature type.

use crate::SIGNATURE_LEN;
use crate::keys::Error;

/// A fixed 13,672-byte VORB3-SP1 signature.
pub struct Signature {
    bytes: [u8; SIGNATURE_LEN],
}

impl Signature {
    /// Parses a signature of exactly [`SIGNATURE_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if the length is not exactly
    /// [`SIGNATURE_LEN`].
    #[inline]
    pub fn from_bytes(input: &[u8]) -> Result<Self, Error> {
        let Ok(bytes) = <[u8; SIGNATURE_LEN]>::try_from(input) else {
            return Err(Error::InvalidSignature);
        };
        Ok(Self { bytes })
    }

    /// Returns the canonical signature bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.bytes
    }

    /// Copies the canonical signature bytes.
    #[must_use]
    #[inline]
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.bytes
    }
}

impl PartialEq for Signature {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Signature {}

impl core::fmt::Debug for Signature {
    #[inline]
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Signature(..)")
    }
}
