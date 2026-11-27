#![no_main]

use libfuzzer_sys::fuzz_target;
use vorb3::keys::PublicKey;
use vorb3::sign::verify_bytes;
use vorb3::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

fuzz_target!(|data: &[u8]| {
    let mut pk_bytes = [0u8; PUBLIC_KEY_LEN];
    let mut signature = [0u8; SIGNATURE_LEN];
    for (index, slot) in pk_bytes.iter_mut().enumerate() {
        *slot = data.get(index).copied().unwrap_or(0);
    }
    for (index, slot) in signature.iter_mut().enumerate() {
        *slot = data.get(PUBLIC_KEY_LEN + index).copied().unwrap_or(0);
    }
    let message = data.get(PUBLIC_KEY_LEN + SIGNATURE_LEN..).unwrap_or(&[]);
    if let Ok(public) = PublicKey::from_bytes(pk_bytes) {
        let _ = verify_bytes(message, &public, &signature);
    }
});
