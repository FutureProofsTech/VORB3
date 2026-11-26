#![no_main]

use libfuzzer_sys::fuzz_target;
use vorb3::keys::PublicKey;
use vorb3::sign::verify_bytes;

const EXPECTED_PK: &[u8; 72] = include_bytes!("../../kat/pk_sp288_35.bin");
const EXPECTED_SIG: &[u8; 13_672] = include_bytes!("../../kat/sign_sp288_35.bin");
const MESSAGE: &[u8] = b"VORB3 phase-0 SP288_35";
const LEN: usize = 13_672;

fuzz_target!(|data: &[u8]| {
    let Ok(public) = PublicKey::from_bytes(*EXPECTED_PK) else {
        return;
    };
    let mut signature = [0u8; LEN];
    let take = if data.len() < LEN { data.len() } else { LEN };
    if let (Some(dst), Some(src)) = (signature.get_mut(..take), data.get(..take)) {
        dst.copy_from_slice(src);
    }
    // The exact untouched KAT is the only accepted signature in this target.
    if data.len() == LEN && data == EXPECTED_SIG {
        return;
    }
    if verify_bytes(MESSAGE, &public, &signature).is_ok() {
        panic!("mutated signature accepted");
    }
});
