#![no_main]

use libfuzzer_sys::fuzz_target;
use vorb3::field::F288;
use vorb3::rain::{self, RainConstants};
use vorb3::FIELD_BYTES;

fuzz_target!(|data: &[u8]| {
    let mut sk_bytes = [0u8; FIELD_BYTES];
    let mut pt_bytes = [0u8; FIELD_BYTES];
    for (index, slot) in sk_bytes.iter_mut().enumerate() {
        *slot = data.get(index).copied().unwrap_or(0);
    }
    for (index, slot) in pt_bytes.iter_mut().enumerate() {
        *slot = data.get(FIELD_BYTES + index).copied().unwrap_or(0);
    }
    let constants = RainConstants::derive();
    let sk = F288::from_bytes(sk_bytes);
    let pt = F288::from_bytes(pt_bytes);
    let (ct_a, _witness_a) = rain::encrypt(sk, pt, &constants);
    let (ct_b, _witness_b) = rain::encrypt(sk, pt, &constants);
    assert_eq!(ct_a, ct_b);
});
