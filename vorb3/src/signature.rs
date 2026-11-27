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

#[cfg(all(test, any(feature = "nist1", feature = "nist3")))]
mod profile_tests {
    use super::Signature;
    use crate::SIGNATURE_LEN;

    struct Sink {
        wrote: bool,
    }
    impl core::fmt::Write for Sink {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            if text == "Signature(..)" {
                self.wrote = true;
            }
            Ok(())
        }
    }

    #[cfg(feature = "nist1")]
    const KAT: &[u8] = include_bytes!("../../kat/sign_sp160_32.bin");
    #[cfg(feature = "nist3")]
    const KAT: &[u8] = include_bytes!("../../kat/sign_sp224_32.bin");

    #[test]
    fn profile_signature_paths() {
        let bytes: [u8; SIGNATURE_LEN] = KAT.try_into().unwrap_or([0u8; SIGNATURE_LEN]);
        let Ok(signature) = Signature::from_bytes(&bytes) else {
            return;
        };
        assert_eq!(signature.as_bytes(), &bytes);
        let Ok(second) = Signature::from_bytes(&bytes) else {
            return;
        };
        assert_eq!(signature, second);
        let zero = [0u8; SIGNATURE_LEN];
        let Ok(zero_signature) = Signature::from_bytes(&zero) else {
            return;
        };
        assert_ne!(signature, zero_signature);
        let mut sink = Sink { wrote: false };
        assert!(core::fmt::Write::write_fmt(&mut sink, format_args!("{signature:?}")).is_ok());
        assert!(sink.wrote);
        let expected = signature.to_bytes();
        assert_eq!(expected, bytes);
        assert_eq!(second.as_bytes(), &expected);
        assert!(Signature::from_bytes(&bytes[..SIGNATURE_LEN - 1]).is_err());
        assert!(Signature::from_bytes(&zero).is_ok());
    }
}
