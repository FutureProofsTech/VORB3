//! BLAKE3 and WH512 for VORB3-SP1.
//!
//! This is a from-scratch, `no_std`, no-allocation BLAKE3 implementation:
//! streaming hash, keyed hash, derive-key, XOF, and the WH512 wide-hash
//! construction used by the spec.
//!
//! BLAKE3 itself has a 256-bit chaining state. WH512 concatenates two
//! independent BLAKE3-256 derive-key outputs to get a 64-byte value for
//! commitment/transcript use; a longer XOF output from a single BLAKE3 instance
//! would not raise collision security.

const OUT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const MAX_DEPTH: usize = 54;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

macro_rules! g {
    ($v:expr, $a:literal, $b:literal, $c:literal, $d:literal, $mx:expr, $my:expr) => {{
        let v = &mut $v;
        v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($mx);
        v[$d] = (v[$d] ^ v[$a]).rotate_right(16);
        v[$c] = v[$c].wrapping_add(v[$d]);
        v[$b] = (v[$b] ^ v[$c]).rotate_right(12);
        v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($my);
        v[$d] = (v[$d] ^ v[$a]).rotate_right(8);
        v[$c] = v[$c].wrapping_add(v[$d]);
        v[$b] = (v[$b] ^ v[$c]).rotate_right(7);
    }};
}

macro_rules! round {
    ($v:expr, $m:expr) => {{
        g!($v, 0, 4, 8, 12, $m[0], $m[1]);
        g!($v, 1, 5, 9, 13, $m[2], $m[3]);
        g!($v, 2, 6, 10, 14, $m[4], $m[5]);
        g!($v, 3, 7, 11, 15, $m[6], $m[7]);
        g!($v, 0, 5, 10, 15, $m[8], $m[9]);
        g!($v, 1, 6, 11, 12, $m[10], $m[11]);
        g!($v, 2, 7, 8, 13, $m[12], $m[13]);
        g!($v, 3, 4, 9, 14, $m[14], $m[15]);
    }};
}

#[inline]
const fn permute(words: [u32; 16]) -> [u32; 16] {
    let [
        w0,
        w1,
        w2,
        w3,
        w4,
        w5,
        w6,
        w7,
        w8,
        w9,
        w10,
        w11,
        w12,
        w13,
        w14,
        w15,
    ] = words;
    [
        w2, w6, w3, w10, w7, w0, w4, w13, w1, w11, w12, w5, w9, w14, w15, w8,
    ]
}

// Hot-path exception: measured ~8% GGM/sign improvement under the release
// profile. Scoped to BLAKE3 compression and its one-shot wrapper only.
#[allow(clippy::inline_always)]
#[inline(always)]
fn compress(
    cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let [c0, c1, c2, c3, c4, c5, c6, c7] = cv;
    let counter_low = u32::try_from(counter & 0xFFFF_FFFF).unwrap_or(0);
    let counter_high = u32::try_from(counter >> 32).unwrap_or(0);
    let mut v = [
        c0,
        c1,
        c2,
        c3,
        c4,
        c5,
        c6,
        c7,
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter_low,
        counter_high,
        block_len,
        flags,
    ];
    let mut m = block_words;

    round!(v, m);
    m = permute(m);
    round!(v, m);
    m = permute(m);
    round!(v, m);
    m = permute(m);
    round!(v, m);
    m = permute(m);
    round!(v, m);
    m = permute(m);
    round!(v, m);
    m = permute(m);
    round!(v, m);

    let mut out = [0u32; 16];
    let mut index = 0usize;
    while index < 8 {
        let left = *v.get(index).unwrap_or(&0);
        let right = *v.get(index.wrapping_add(8)).unwrap_or(&0);
        let key = *cv.get(index).unwrap_or(&0);
        if let Some(slot) = out.get_mut(index) {
            *slot = left ^ right;
        }
        if let Some(slot) = out.get_mut(index.wrapping_add(8)) {
            *slot = right ^ key;
        }
        index = index.wrapping_add(1);
    }
    out
}

#[inline]
fn chaining_value(output: [u32; 16]) -> [u32; 8] {
    let mut cv = [0u32; 8];
    for (dst, src) in cv.iter_mut().zip(output.iter()) {
        *dst = *src;
    }
    cv
}

#[inline]
fn block_words(block: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (word, chunk) in words.iter_mut().zip(block.as_chunks::<4>().0.iter()) {
        *word = u32::from_le_bytes(*chunk);
    }
    words
}

#[inline]
fn key_words(key: [u8; KEY_LEN]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (word, chunk) in words.iter_mut().zip(key.as_chunks::<4>().0.iter()) {
        *word = u32::from_le_bytes(*chunk);
    }
    words
}

#[derive(Clone, Copy)]
struct Output {
    input_cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    #[inline]
    fn chaining_value(self) -> [u32; 8] {
        chaining_value(compress(
            self.input_cv,
            self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn root_bytes(self, out: &mut [u8]) {
        let mut written = 0usize;
        let mut counter = 0u64;
        while written < out.len() {
            let block = compress(
                self.input_cv,
                self.block_words,
                counter,
                self.block_len,
                self.flags | ROOT,
            );
            let mut bytes = [0u8; BLOCK_LEN];
            for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(block.iter()) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            let remaining = out.len().wrapping_sub(written);
            let take = if remaining < BLOCK_LEN {
                remaining
            } else {
                BLOCK_LEN
            };
            let end = written.wrapping_add(take);
            if let (Some(dst), Some(src)) = (out.get_mut(written..end), bytes.get(..take)) {
                dst.copy_from_slice(src);
            }
            written = end;
            counter = counter.wrapping_add(1);
        }
    }
}

#[derive(Clone)]
struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: usize,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    #[inline]
    const fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            cv: key_words,
            chunk_counter,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        usize::from(self.blocks_compressed)
            .wrapping_mul(BLOCK_LEN)
            .wrapping_add(self.block_len)
    }

    #[inline]
    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len == BLOCK_LEN {
                let flags = self.flags
                    | if self.blocks_compressed == 0 {
                        CHUNK_START
                    } else {
                        0
                    };
                self.cv = chaining_value(compress(
                    self.cv,
                    block_words(&self.block),
                    self.chunk_counter,
                    u32::try_from(BLOCK_LEN).unwrap_or(64),
                    flags,
                ));
                self.blocks_compressed = self.blocks_compressed.wrapping_add(1);
                self.block = [0u8; BLOCK_LEN];
                self.block_len = 0;
            }

            let want = BLOCK_LEN.wrapping_sub(self.block_len);
            let take = if input.len() < want {
                input.len()
            } else {
                want
            };
            let (head, tail) = input.split_at(take);
            let end = self.block_len.wrapping_add(take);
            if let Some(dst) = self.block.get_mut(self.block_len..end) {
                dst.copy_from_slice(head);
            }
            self.block_len = end;
            input = tail;
        }
    }

    #[inline]
    fn output(&self) -> Output {
        let flags = self.flags
            | CHUNK_END
            | if self.blocks_compressed == 0 {
                CHUNK_START
            } else {
                0
            };
        Output {
            input_cv: self.cv,
            block_words: block_words(&self.block),
            counter: self.chunk_counter,
            block_len: u32::try_from(self.block_len).unwrap_or(0),
            flags,
        }
    }
}

#[inline]
fn parent_output(left: [u32; 8], right: [u32; 8], key_words_value: [u32; 8], flags: u32) -> Output {
    let mut words = [0u32; 16];
    for (dst, src) in words.iter_mut().take(8).zip(left.iter()) {
        *dst = *src;
    }
    for (dst, src) in words.iter_mut().skip(8).zip(right.iter()) {
        *dst = *src;
    }
    Output {
        input_cv: key_words_value,
        block_words: words,
        counter: 0,
        block_len: u32::try_from(BLOCK_LEN).unwrap_or(64),
        flags: flags | PARENT,
    }
}

struct Hasher {
    key_words: [u32; 8],
    chunk_state: ChunkState,
    cv_stack: [[u32; 8]; MAX_DEPTH],
    stack_len: usize,
    flags: u32,
    total_chunks: u64,
}

impl Hasher {
    #[inline(never)]
    const fn new(key_words_value: [u32; 8], flags: u32) -> Self {
        Self {
            key_words: key_words_value,
            chunk_state: ChunkState::new(key_words_value, 0, flags),
            cv_stack: [[0u32; 8]; MAX_DEPTH],
            stack_len: 0,
            flags,
            total_chunks: 0,
        }
    }

    fn push_cv(&mut self, mut cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let left = if self.stack_len == 0 {
                [0u32; 8]
            } else {
                self.cv_stack
                    .get(self.stack_len.wrapping_sub(1))
                    .copied()
                    .unwrap_or([0u32; 8])
            };
            self.stack_len = self.stack_len.saturating_sub(1);
            cv = parent_output(left, cv, self.key_words, self.flags).chaining_value();
            total_chunks >>= 1;
        }
        if let Some(slot) = self.cv_stack.get_mut(self.stack_len) {
            *slot = cv;
        }
        self.stack_len = self.stack_len.saturating_add(1);
    }

    #[inline]
    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.total_chunks.wrapping_add(1);
                self.push_cv(cv, total_chunks);
                self.total_chunks = total_chunks;
                self.chunk_state = ChunkState::new(self.key_words, self.total_chunks, self.flags);
            }
            let want = CHUNK_LEN.wrapping_sub(self.chunk_state.len());
            let take = if input.len() < want {
                input.len()
            } else {
                want
            };
            let (head, tail) = input.split_at(take);
            self.chunk_state.update(head);
            input = tail;
        }
    }

    fn finalize(&self) -> Output {
        let mut output = self.chunk_state.output();
        let mut index = self.stack_len;
        while index > 0 {
            index = index.wrapping_sub(1);
            let left = self.cv_stack.get(index).copied().unwrap_or([0u32; 8]);
            output = parent_output(left, output.chaining_value(), self.key_words, self.flags);
        }
        Output {
            flags: output.flags | ROOT,
            ..output
        }
    }
}

#[allow(clippy::inline_always)]
#[inline(always)]
fn hash_internal(data: &[u8], key: [u32; 8], flags: u32) -> Output {
    if data.len() <= CHUNK_LEN {
        // One-chunk path: skip the 54-level CV tower and its zeroing.
        let mut chunk = ChunkState::new(key, 0, flags);
        chunk.update(data);
        chunk.output()
    } else {
        let mut hasher = Hasher::new(key, flags);
        hasher.update(data);
        hasher.finalize()
    }
}

/// Computes a 32-byte unkeyed BLAKE3 hash.
#[must_use]
#[inline]
pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
    let mut out = [0u8; OUT_LEN];
    hash_xof(data, &mut out);
    out
}

/// Writes an arbitrary-length unkeyed BLAKE3 XOF output.
#[inline]
pub fn hash_xof(data: &[u8], out: &mut [u8]) {
    hash_internal(data, IV, 0).root_bytes(out);
}

/// Computes a 32-byte keyed BLAKE3 hash.
#[must_use]
#[inline]
pub fn keyed_hash(key: [u8; KEY_LEN], data: &[u8]) -> [u8; OUT_LEN] {
    let mut out = [0u8; OUT_LEN];
    hash_internal(data, key_words(key), KEYED_HASH).root_bytes(&mut out);
    out
}

/// Computes the 32-byte derive-key context key for a context string.
///
/// Out of line: `derive_key` and `Wh512Hasher::new` call this while their own
/// BLAKE3 state is live, so inlining would stack two 54-level CV towers.
#[inline(never)]
fn context_key(context: &str) -> [u8; OUT_LEN] {
    let mut key = [0u8; OUT_LEN];
    hash_internal(context.as_bytes(), IV, DERIVE_KEY_CONTEXT).root_bytes(&mut key);
    key
}

/// Writes a BLAKE3 derive-key output of any length.
#[inline]
pub fn derive_key(context: &str, data: &[u8], out: &mut [u8]) {
    derive_key_inner(context, data, out);
}

#[inline(never)]
fn derive_key_inner(context: &str, data: &[u8], out: &mut [u8]) {
    let key = context_key(context);
    hash_internal(data, key_words(key), DERIVE_KEY_MATERIAL).root_bytes(out);
}

/// Derive-key material with an already-computed 32-byte context key.
#[inline]
pub(crate) fn derive_key_words(key: [u32; 8], data: &[u8], out: &mut [u8]) {
    hash_internal(data, key, DERIVE_KEY_MATERIAL).root_bytes(out);
}

/// Streaming BLAKE3 derive-key state. Used for hedged key derivation over an
/// arbitrary-length message without allocation.
pub(crate) struct DeriveKeyHasher {
    hasher: Hasher,
}

impl DeriveKeyHasher {
    #[inline(never)]
    pub(crate) fn new(context: &str) -> Self {
        let key = context_key(context);
        Self {
            hasher: Hasher::new(key_words(key), DERIVE_KEY_MATERIAL),
        }
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    #[inline]
    pub(crate) fn finalize(self, out: &mut [u8]) {
        self.hasher.finalize().root_bytes(out);
    }
}

/// Precomputed derive-key context key for `VORB3-WH512-A-V1`.
const WH512_A_KEY: [u32; 8] = [
    0x75c7_72b8,
    0xadaf_0b73,
    0x402c_c33a,
    0x35d5_aee7,
    0xd41c_5004,
    0x7f54_6611,
    0x3dd7_e492,
    0x90cd_17e6,
];

/// Precomputed derive-key context key for `VORB3-WH512-B-V1`.
const WH512_B_KEY: [u32; 8] = [
    0x9cc1_c9f9,
    0x686a_4dfc,
    0x1f56_8fb0,
    0xfd49_3af2,
    0x8cdb_6d93,
    0xdb08_7c36,
    0x2a15_b34a,
    0xa184_b12d,
];

/// Streaming WH512: two independent BLAKE3 derive-key states for the A/B
/// contexts. Used by the transcript for arbitrary-length absorptions without
/// allocation.
pub(crate) struct Wh512Hasher {
    left: Hasher,
    right: Hasher,
}

impl Wh512Hasher {
    #[inline(never)]
    pub(crate) const fn new() -> Self {
        Self {
            left: Hasher::new(WH512_A_KEY, DERIVE_KEY_MATERIAL),
            right: Hasher::new(WH512_B_KEY, DERIVE_KEY_MATERIAL),
        }
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.left.update(data);
        self.right.update(data);
    }

    #[inline]
    pub(crate) fn finalize(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        let (left, right) = out.split_at_mut(32);
        self.left.finalize().root_bytes(left);
        self.right.finalize().root_bytes(right);
        out
    }
}

/// A BLAKE3 derive-key state after a constant protocol prefix.
#[derive(Clone)]
pub(crate) struct DeriveKeyPrefix {
    chunk: ChunkState,
}

impl DeriveKeyPrefix {
    /// Absorbs a single-chunk prefix with a precomputed context key.
    #[inline]
    pub(crate) fn new(key: [u32; 8], data: &[u8]) -> Self {
        let mut chunk = ChunkState::new(key, 0, DERIVE_KEY_MATERIAL);
        chunk.update(data);
        Self { chunk }
    }

    /// Finishes the derive-key output after appending `suffix`.
    #[inline]
    pub(crate) fn finish(&self, suffix: &[u8], out: &mut [u8]) {
        let mut chunk = self.chunk.clone();
        chunk.update(suffix);
        chunk.output().root_bytes(out);
    }
}

/// Creates a derive-key prefix state for data shorter than one BLAKE3 chunk.
#[inline]
pub(crate) fn derive_key_prefix(key: [u32; 8], data: &[u8]) -> DeriveKeyPrefix {
    DeriveKeyPrefix::new(key, data)
}

/// A WH512 state after a constant protocol prefix.
///
/// GGM leaf/node records share a per-tree prefix; cloning this state and
/// appending only the variable suffix keeps the BLAKE3 output byte-identical
/// while avoiding rehashing the prefix for every node.
#[derive(Clone)]
pub(crate) struct Wh512Prefix {
    left: ChunkState,
    right: ChunkState,
}

impl Wh512Prefix {
    /// Absorbs a single-chunk prefix.
    #[inline]
    pub(crate) fn new(data: &[u8]) -> Self {
        let mut left = ChunkState::new(WH512_A_KEY, 0, DERIVE_KEY_MATERIAL);
        let mut right = ChunkState::new(WH512_B_KEY, 0, DERIVE_KEY_MATERIAL);
        left.update(data);
        right.update(data);
        Self { left, right }
    }

    /// Finishes both hashes after appending `suffix`.
    #[inline]
    pub(crate) fn finish(&self, suffix: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        let (left_out, right_out) = out.split_at_mut(32);
        let mut left = self.left.clone();
        let mut right = self.right.clone();
        left.update(suffix);
        right.update(suffix);
        left.output().root_bytes(left_out);
        right.output().root_bytes(right_out);
        out
    }
}

/// Creates a WH512 prefix state for data shorter than one BLAKE3 chunk.
#[inline]
pub(crate) fn wh512_prefix(data: &[u8]) -> Wh512Prefix {
    Wh512Prefix::new(data)
}

/// Computes the WH512 wide hash: two independent 32-byte BLAKE3 derive-key
/// outputs with the A/B domain contexts, concatenated to 64 bytes.
#[must_use]
#[inline]
pub fn wh512(data: &[u8]) -> [u8; 64] {
    wh512_inner(data)
}

#[inline(never)]
fn wh512_inner(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let (left, right) = out.split_at_mut(32);
    hash_internal(data, WH512_A_KEY, DERIVE_KEY_MATERIAL).root_bytes(left);
    hash_internal(data, WH512_B_KEY, DERIVE_KEY_MATERIAL).root_bytes(right);
    out
}

#[cfg(test)]
mod tests {
    use super::{Hasher, IV};

    #[test]
    fn push_cv_zero_stack_defensive_merge() {
        let mut hasher = Hasher::new(IV, 0);
        hasher.push_cv([7u32; 8], 2);
        assert_eq!(hasher.stack_len, 1);
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::{WH512_A_KEY, WH512_B_KEY, context_key, key_words, wh512, wh512_prefix};

    #[test]
    fn wh512_context_keys_match_derivation() {
        assert_eq!(WH512_A_KEY, key_words(context_key("VORB3-WH512-A-V1")));
        assert_eq!(WH512_B_KEY, key_words(context_key("VORB3-WH512-B-V1")));
    }

    #[test]
    fn wh512_prefix_matches_full_hash() {
        let mut data = [0u8; 400];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = u8::try_from(index.wrapping_mul(29).wrapping_add(7) & 0xFF).unwrap_or(0);
        }
        for split in [0usize, 1, 63, 64, 65, 147, 200, 399, 400] {
            let (prefix_data, suffix_data) = data.split_at(split);
            let prefix = wh512_prefix(prefix_data);
            assert_eq!(prefix.finish(suffix_data), wh512(&data));
        }
    }
}
