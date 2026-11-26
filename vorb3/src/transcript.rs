//! Merlin-style framed and ratcheted transcript over WH512.
//!
//! Every absorption is length-framed:
//!
//! ```text
//! label_len(u64 LE) || label || data_len(u64 LE) || data
//! ```
//!
//! The state is 512 bits. Each squeeze ratchets the state and zeros the old
//! value. This module is crate-internal; its behavior is specified in
//! `docs/VORB3-SPEC-1.md`.

use crate::blake3::{Wh512Hasher, wh512};

const STATE_LEN: usize = 64;

/// A 512-bit framed transcript.
pub struct Transcript {
    state: [u8; STATE_LEN],
}

impl Transcript {
    /// Creates a fresh transcript.
    #[inline]
    pub fn new() -> Self {
        Self {
            state: wh512(b"VORB3-TRANSCRIPT-INIT-V1"),
        }
    }

    /// Absorbs a labelled, length-framed byte string.
    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        self.state = absorb_state(&self.state, label, data);
    }

    /// Squeezes up to 64 labelled bytes, then ratchets the state.
    pub fn squeeze(&mut self, label: &str, out: &mut [u8]) {
        let block = squeeze_block(&self.state, label, out.len());
        let take = if out.len() < STATE_LEN {
            out.len()
        } else {
            STATE_LEN
        };
        if let (Some(dst), Some(src)) = (out.get_mut(..take), block.get(..take)) {
            dst.copy_from_slice(src);
        }
        self.state = ratchet_state(&self.state, out.len(), &block);
    }
}

/// Absorb helper. Kept out of line so the transcript API frame does not carry
/// two BLAKE3 states at once.
#[inline(never)]
fn absorb_state(state: &[u8; STATE_LEN], label: &str, data: &[u8]) -> [u8; STATE_LEN] {
    let label_bytes = label.as_bytes();
    let mut hasher = Wh512Hasher::new();
    hasher.update(b"VORB3-TRANSCRIPT-ABSORB-V1");
    hasher.update(state);
    update_length(&mut hasher, label_bytes.len());
    hasher.update(label_bytes);
    update_length(&mut hasher, data.len());
    hasher.update(data);
    hasher.finalize()
}

/// Squeeze helper. The block and ratchet hashers are separate frames.
#[inline(never)]
fn squeeze_block(state: &[u8; STATE_LEN], label: &str, output_len: usize) -> [u8; STATE_LEN] {
    let label_bytes = label.as_bytes();
    let mut hasher = Wh512Hasher::new();
    hasher.update(b"VORB3-TRANSCRIPT-SQUEEZE-V1");
    hasher.update(state);
    update_length(&mut hasher, label_bytes.len());
    hasher.update(label_bytes);
    update_length(&mut hasher, 8);
    hasher.update(&u64::try_from(output_len).unwrap_or(u64::MAX).to_le_bytes());
    hasher.finalize()
}

/// Ratchet helper, separate from the squeeze frame.
#[inline(never)]
fn ratchet_state(
    state: &[u8; STATE_LEN],
    output_len: usize,
    block: &[u8; STATE_LEN],
) -> [u8; STATE_LEN] {
    let take = if output_len < STATE_LEN {
        output_len
    } else {
        STATE_LEN
    };
    let mut ratchet = Wh512Hasher::new();
    ratchet.update(b"VORB3-TRANSCRIPT-RATCHET-V1");
    ratchet.update(state);
    update_length(&mut ratchet, output_len);
    ratchet.update(block.get(..take).unwrap_or(&[]));
    ratchet.finalize()
}

#[inline]
fn update_length(hasher: &mut Wh512Hasher, length: usize) {
    let encoded = u64::try_from(length).unwrap_or(u64::MAX).to_le_bytes();
    hasher.update(&encoded);
}

#[cfg(test)]
mod tests {
    use super::Transcript;

    const DELTA: [u8; 36] = [
        0x57, 0x2a, 0x80, 0xcb, 0x93, 0xb4, 0x01, 0x9f, 0xa1, 0xbb, 0x59, 0x22, 0xc7, 0xae, 0x7a,
        0x14, 0x84, 0xc2, 0x66, 0x68, 0x75, 0xea, 0xbe, 0xba, 0x0c, 0xf9, 0xb1, 0x82, 0x86, 0xc3,
        0x09, 0xfb, 0x13, 0x77, 0x8c, 0x9e,
    ];
    const CHI: [u8; 36] = [
        0x2d, 0x7b, 0x7b, 0x1c, 0x98, 0xd5, 0x6f, 0x92, 0xf5, 0x4f, 0xcf, 0x1a, 0xb9, 0x1f, 0x60,
        0xeb, 0x59, 0xe1, 0xc0, 0xa9, 0x98, 0x01, 0x8b, 0x76, 0x41, 0x31, 0x87, 0xf2, 0xf8, 0x4f,
        0x33, 0x38, 0x02, 0x2f, 0x16, 0x07,
    ];
    const H2: [u8; 64] = [
        0x38, 0x48, 0x71, 0x3a, 0xbe, 0xb9, 0xcb, 0x70, 0x17, 0x72, 0xcc, 0x2b, 0xfa, 0x5f, 0x8f,
        0xe6, 0x44, 0xb6, 0xc8, 0x93, 0xe9, 0x78, 0xb2, 0x6f, 0xb9, 0x26, 0xf3, 0x9e, 0xa0, 0x60,
        0x7c, 0x59, 0x7a, 0x93, 0xf2, 0x51, 0xc0, 0x4e, 0xeb, 0xcd, 0xde, 0x78, 0xd5, 0x95, 0x24,
        0xae, 0x8f, 0x04, 0x14, 0xf9, 0x72, 0x2f, 0x7e, 0xb4, 0x85, 0xd8, 0x9c, 0xb5, 0x53, 0x57,
        0xd3, 0xd0, 0x39, 0x9e,
    ];

    #[test]
    fn transcript_kat() {
        let mut transcript = Transcript::new();
        let mut pk = [0u8; 72];
        for (index, byte) in pk.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0);
        }
        let mut salt = [0u8; 64];
        for (index, byte) in salt.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0);
        }
        let mut roots = [0u8; 64];
        for (index, byte) in roots.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0);
        }
        transcript.absorb("PK", &pk);
        transcript.absorb("SALT", &salt);
        transcript.absorb("MSG", b"abc");
        transcript.absorb("ROOTS", &roots);
        let mut delta = [0u8; 36];
        let mut chi = [0u8; 36];
        let mut h2 = [0u8; 64];
        transcript.squeeze("DELTA", &mut delta);
        transcript.squeeze("CHI", &mut chi);
        transcript.squeeze("H2", &mut h2);
        assert_eq!(delta, DELTA);
        assert_eq!(chi, CHI);
        assert_eq!(h2, H2);
    }
}
