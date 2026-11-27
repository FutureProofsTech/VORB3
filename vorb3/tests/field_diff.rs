//! Differential GF(2^288) test against the independent Python model.
#![allow(clippy::arithmetic_side_effects)] // field operators are total; no integer overflow.

use vorb3::field::F288;

const DATA: &[u8] = include_bytes!("../../kat/field_sp288_diff.bin");
const RECORD_LEN: usize = 144;
const WORD_LEN: usize = 36;

#[test]
fn differential_field_vectors() {
    let (records, record_remainder) = DATA.as_chunks::<RECORD_LEN>();
    assert_eq!(record_remainder, []);
    let mut checked = 0usize;
    for record in records {
        let (chunks, remainder) = record.as_chunks::<WORD_LEN>();
        assert_eq!(remainder, []);
        let [a, b, product, inverse] = chunks else {
            continue;
        };
        let a = F288::from_bytes(*a);
        let b = F288::from_bytes(*b);
        assert_eq!(a * b, F288::from_bytes(*product));
        assert_eq!(a.inverse(), F288::from_bytes(*inverse));
        checked += 1;
    }
    assert_eq!(checked, 4096);
}

#[test]
fn field_inverse_self_consistency() {
    // Deterministic splitmix64 fill; no external RNG.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..10_000 {
        let mut bytes = [0u8; WORD_LEN];
        for chunk in bytes.as_chunks_mut::<8>().0.iter_mut() {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes());
        }
        let value = F288::from_bytes(bytes);
        if !value.is_zero() {
            assert_eq!(value * value.inverse(), F288::ONE);
        }
    }
}
