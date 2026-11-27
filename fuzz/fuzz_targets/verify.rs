#![no_main]

use libfuzzer_sys::fuzz_target;
use vorb3::keys::PublicKey;
use vorb3::sign::verify_bytes;

#[cfg(not(any(feature = "nist1", feature = "nist3")))]
const EXPECTED_PK: &[u8] = include_bytes!("../../kat/pk_sp288_35.bin");
#[cfg(not(any(feature = "nist1", feature = "nist3")))]
const EXPECTED_SIG: &[u8] = include_bytes!("../../kat/sign_sp288_35.bin");
#[cfg(not(any(feature = "nist1", feature = "nist3")))]
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";

#[cfg(feature = "nist1")]
const EXPECTED_PK: &[u8] = include_bytes!("../../kat/pk_sp160_32.bin");
#[cfg(feature = "nist1")]
const EXPECTED_SIG: &[u8] = include_bytes!("../../kat/sign_sp160_32.bin");
#[cfg(feature = "nist1")]
const MESSAGE: &[u8] = b"VORB3 phase-0 SP160_32";

#[cfg(feature = "nist3")]
const EXPECTED_PK: &[u8] = include_bytes!("../../kat/pk_sp224_32.bin");
#[cfg(feature = "nist3")]
const EXPECTED_SIG: &[u8] = include_bytes!("../../kat/sign_sp224_32.bin");
#[cfg(feature = "nist3")]
const MESSAGE: &[u8] = b"VORB3 phase-0 SP224_32";

use vorb3::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
const LEN: usize = SIGNATURE_LEN;

fuzz_target!(|data: &[u8]| {
    let Ok(public_bytes): Result<[u8; PUBLIC_KEY_LEN], _> = EXPECTED_PK.try_into() else {
        return;
    };
    let Ok(public) = PublicKey::from_bytes(public_bytes) else {
        return;
    };
    let Ok(expected): Result<[u8; LEN], _> = EXPECTED_SIG.try_into() else {
        return;
    };
    let mut signature = [0u8; LEN];
    let take = if data.len() < LEN { data.len() } else { LEN };
    if let (Some(dst), Some(src)) = (signature.get_mut(..take), data.get(..take)) {
        dst.copy_from_slice(src);
    }
    // The exact untouched KAT is the only accepted signature in this target.
    if data.len() == LEN && data == expected {
        return;
    }
    if verify_bytes(MESSAGE, &public, &signature).is_ok() {
        panic!("mutated signature accepted");
    }
});
