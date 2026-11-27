#![no_main]

use libfuzzer_sys::fuzz_target;
use vorb3::keys::PublicKey;
use vorb3::signature::Signature;
use vorb3::PUBLIC_KEY_LEN;

fuzz_target!(|data: &[u8]| {
    if let Ok(signature) = Signature::from_bytes(data) {
        let bytes = signature.to_bytes();
        let _ = Signature::from_bytes(&bytes);
    }
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    for (index, slot) in pk.iter_mut().enumerate() {
        *slot = data.get(index).copied().unwrap_or(0);
    }
    if let Ok(public) = PublicKey::from_bytes(pk) {
        let _ = public.to_bytes();
    }
});
