#![no_main]

use libfuzzer_sys::fuzz_target;
use vorb3::keys::PublicKey;
use vorb3::signature::Signature;

fuzz_target!(|data: &[u8]| {
    if let Ok(signature) = Signature::from_bytes(data) {
        let bytes = signature.to_bytes();
        let _ = Signature::from_bytes(&bytes);
    }
    let mut pk = [0u8; 72];
    for (index, slot) in pk.iter_mut().enumerate() {
        *slot = data.get(index).copied().unwrap_or(0);
    }
    if let Ok(public) = PublicKey::from_bytes(pk) {
        let _ = public.to_bytes();
    }
});
