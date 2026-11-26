#![no_main]

use libfuzzer_sys::fuzz_target;
use vorb3::field::F288;

fuzz_target!(|data: &[u8]| {
    let mut a_bytes = [0u8; 36];
    let mut b_bytes = [0u8; 36];
    for (index, slot) in a_bytes.iter_mut().enumerate() {
        *slot = data.get(index).copied().unwrap_or(0);
    }
    for (index, slot) in b_bytes.iter_mut().enumerate() {
        *slot = data.get(36 + index).copied().unwrap_or(0);
    }
    let a = F288::from_bytes(a_bytes);
    let b = F288::from_bytes(b_bytes);
    assert_eq!(a + b, b + a);
    assert_eq!(a * b, b * a);
    assert_eq!(a.square(), a * a);
    assert_eq!(F288::from_bytes(a.to_bytes()), a);
    if !a.is_zero() {
        assert_eq!(a * a.inverse(), F288::ONE);
    }
    assert_eq!(a - b, a + b);
});
