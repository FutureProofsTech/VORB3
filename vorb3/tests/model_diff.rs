#![allow(missing_docs)]
#![cfg(not(any(feature = "nist1", feature = "nist3")))]
//! Multi-case differential test against the independent Python model.
//!
//! The KAT file contains 28 records with different seeds, entropy, and message
//! lengths from 0 to 8192 bytes. Rust signing must reproduce every signature
//! byte-for-byte, and verification must accept it.

use vorb3::SIGNATURE_LEN;
use vorb3::keys::{ExpandedSecretKey, PublicKey, SecretKey};
use vorb3::sign::{sign_into, verify_bytes};

const DATA: &[u8] = include_bytes!("../../kat/sign_diff_sp288_35.bin");
const MAGIC: &[u8; 10] = b"VORB3DIFF1";

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(length)?;
        let slice = self.data.get(self.offset..end)?;
        self.offset = end;
        Some(slice)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        <[u8; N]>::try_from(self.take(N)?).ok()
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.array::<4>()?))
    }
}

#[test]
fn multi_case_python_differential() {
    let mut cursor = Cursor {
        data: DATA,
        offset: 0,
    };
    let magic = cursor.take(MAGIC.len()).unwrap_or(&[]);
    assert_eq!(magic, MAGIC);
    let count = cursor.u16().unwrap_or(0);
    assert_eq!(count, 28);
    for case in 0..count {
        let seed = cursor.array::<36>().unwrap_or([0u8; 36]);
        let pk_bytes = cursor.array::<72>().unwrap_or([0u8; 72]);
        let entropy = cursor.array::<32>().unwrap_or([0u8; 32]);
        let message_len = usize::try_from(cursor.u32().unwrap_or(0)).unwrap_or(0);
        let message = cursor.take(message_len).unwrap_or(&[]);
        let expected = cursor
            .array::<SIGNATURE_LEN>()
            .unwrap_or([0u8; SIGNATURE_LEN]);

        let compact = SecretKey::from_seed(seed);
        let expanded = ExpandedSecretKey::from_seed(&compact);
        let Ok(public) = PublicKey::from_bytes(pk_bytes) else {
            return;
        };
        assert_eq!(public.as_bytes(), &pk_bytes, "case {case}: public key");

        let mut signature = [0u8; SIGNATURE_LEN];
        let result = sign_into(message, &expanded, &entropy, &mut signature);
        assert!(result.is_ok(), "case {case}: sign failed");
        assert_eq!(signature, expected, "case {case}: signature bytes");
        assert!(
            verify_bytes(message, &public, &expected).is_ok(),
            "case {case}: model signature rejected"
        );
        assert!(
            verify_bytes(b"wrong message", &public, &expected).is_err(),
            "case {case}: wrong message accepted"
        );
    }
    assert_eq!(cursor.offset, DATA.len(), "trailing KAT bytes");
}
