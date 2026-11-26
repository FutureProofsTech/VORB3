//! GGM tree and Merkle commitment for VORB3-SP1.
//!
//! The signer has a two-pass GGM/Merkle path: one streaming pass computes a
//! tree root, and a second path pass extracts the hidden leaf share,
//! commitment, and copath. No full tree is retained on the stack. All
//! secret-index selections are full-width masked scans.

use crate::blake3::{DeriveKeyPrefix, Wh512Prefix, derive_key_prefix, wh512_prefix};
use crate::ct::CtChoice;
use crate::field::F288;
use crate::zeroize::wipe_bytes;
use crate::{COMMITMENT_LEN, FIELD_BYTES, SALT_LEN, TREE_DEPTH};

const COPATH_LEN: usize = TREE_DEPTH;
const LEAF_LABEL: &[u8] = b"VORB3-GGM-LEAF-V1";
const NODE_LABEL: &[u8] = b"VORB3-GGM-NODE-V1";
const EXPAND_LABEL: &[u8] = b"VORB3-GGM-EXPAND-V1";
const EXPAND_KEY: [u32; 8] = [
    0x0423_f085,
    0x1582_3cc1,
    0x0335_33df,
    0x0248_f9ed,
    0x86d9_89eb,
    0xed2c_bf0f,
    0xda19_e3f0,
    0xde78_b884,
];
pub const TREE_ROOT_KEY: [u32; 8] = [
    0xa292_f227,
    0x53f4_035a,
    0x8d41_4be5,
    0xfbab_8096,
    0xb14c_b094,
    0x20bf_1a38,
    0x3322_13bf,
    0xbd28_92ba,
];
const EXPAND_PREFIX_LEN: usize = EXPAND_LABEL.len() + SALT_LEN + COMMITMENT_LEN + 2;
const EXPAND_SUFFIX_LEN: usize = 1 + 2 + FIELD_BYTES;
const LEAF_PREFIX_LEN: usize = LEAF_LABEL.len() + SALT_LEN + COMMITMENT_LEN + 2;
const NODE_PREFIX_LEN: usize = NODE_LABEL.len() + SALT_LEN + COMMITMENT_LEN + 2;
const LEAF_SUFFIX_LEN: usize = 2 + FIELD_BYTES;
const NODE_SUFFIX_LEN: usize = 1 + 2 + COMMITMENT_LEN + COMMITMENT_LEN;

/// Per-tree WH512 states after the constant leaf/node prefixes.
struct GgmPrefixes {
    expand: DeriveKeyPrefix,
    leaf: Wh512Prefix,
    node: Wh512Prefix,
}

impl GgmPrefixes {
    #[inline]
    fn new(tree_index: u16, salt: &[u8; SALT_LEN], pk_hash: &[u8; COMMITMENT_LEN]) -> Self {
        let mut expand = [0u8; EXPAND_PREFIX_LEN];
        let (slot, rest) = expand.split_at_mut(EXPAND_LABEL.len());
        slot.copy_from_slice(EXPAND_LABEL);
        let (slot, rest) = rest.split_at_mut(SALT_LEN);
        slot.copy_from_slice(salt);
        let (slot, rest) = rest.split_at_mut(COMMITMENT_LEN);
        slot.copy_from_slice(pk_hash);
        let (slot, _rest) = rest.split_at_mut(2);
        slot.copy_from_slice(&tree_index.to_le_bytes());

        let mut leaf = [0u8; LEAF_PREFIX_LEN];
        let (slot, rest) = leaf.split_at_mut(LEAF_LABEL.len());
        slot.copy_from_slice(LEAF_LABEL);
        let (slot, rest) = rest.split_at_mut(SALT_LEN);
        slot.copy_from_slice(salt);
        let (slot, rest) = rest.split_at_mut(COMMITMENT_LEN);
        slot.copy_from_slice(pk_hash);
        let (slot, _rest) = rest.split_at_mut(2);
        slot.copy_from_slice(&tree_index.to_le_bytes());

        let mut node = [0u8; NODE_PREFIX_LEN];
        let (slot, rest) = node.split_at_mut(NODE_LABEL.len());
        slot.copy_from_slice(NODE_LABEL);
        let (slot, rest) = rest.split_at_mut(SALT_LEN);
        slot.copy_from_slice(salt);
        let (slot, rest) = rest.split_at_mut(COMMITMENT_LEN);
        slot.copy_from_slice(pk_hash);
        let (slot, _rest) = rest.split_at_mut(2);
        slot.copy_from_slice(&tree_index.to_le_bytes());

        Self {
            expand: derive_key_prefix(EXPAND_KEY, &expand),
            leaf: wh512_prefix(&leaf),
            node: wh512_prefix(&node),
        }
    }
}

/// Computes a tree root in one streaming left-to-right pass.
#[must_use]
#[inline(never)]
pub fn tree_root(
    mut root_seed: [u8; FIELD_BYTES],
    tree_index: u16,
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
) -> [u8; COMMITMENT_LEN] {
    let prefixes = GgmPrefixes::new(tree_index, salt, pk_hash);
    let mut builder = RootBuilder {
        prefixes,
        stack: [[0u8; COMMITMENT_LEN]; TREE_DEPTH + 1],
    };
    let mut dfs = [Node::ZERO; TREE_DEPTH + 1];
    let mut top = dfs.get_mut(0).map_or(0usize, |slot| {
        *slot = Node {
            seed: root_seed,
            level: 0,
            index: 0,
        };
        1usize
    });
    wipe_bytes(&mut root_seed);

    while top > 0 {
        top = top.saturating_sub(1);
        let mut node = dfs.get(top).copied().unwrap_or(Node::ZERO);
        if let Some(slot) = dfs.get_mut(top) {
            *slot = Node::ZERO;
        }
        if usize::from(node.level) == TREE_DEPTH {
            let share = leaf_share(node.seed);
            let commitment = leaf_commitment(&builder.prefixes, node.index, share);
            builder.add_leaf(commitment, node.index);
            wipe_bytes(&mut node.seed);
            continue;
        }
        let level = node.level;
        let (left, right) = expand_child(&builder.prefixes, node.seed, level, node.index);
        wipe_bytes(&mut node.seed);
        if let Some(slot) = dfs.get_mut(top) {
            *slot = Node {
                seed: right,
                level: level.saturating_add(1),
                index: node.index.wrapping_mul(2).wrapping_add(1),
            };
            top = top.saturating_add(1);
        }
        if let Some(slot) = dfs.get_mut(top) {
            *slot = Node {
                seed: left,
                level: level.saturating_add(1),
                index: node.index.wrapping_mul(2),
            };
            top = top.saturating_add(1);
        }
    }

    builder
        .stack
        .get(TREE_DEPTH)
        .copied()
        .unwrap_or([0u8; COMMITMENT_LEN])
}

#[derive(Clone, Copy)]
struct Node {
    seed: [u8; FIELD_BYTES],
    level: u8,
    index: u16,
}

impl Node {
    const ZERO: Self = Self {
        seed: [0u8; FIELD_BYTES],
        level: 0,
        index: 0,
    };
}

struct RootBuilder {
    prefixes: GgmPrefixes,
    stack: [[u8; COMMITMENT_LEN]; TREE_DEPTH + 1],
}

impl RootBuilder {
    fn add_leaf(&mut self, commitment: [u8; COMMITMENT_LEN], leaf_index: u16) {
        let mut hash = commitment;
        let mut index = leaf_index;
        let mut merge_level = 0usize;
        while index & 1 == 1 {
            let left = self
                .stack
                .get(merge_level)
                .copied()
                .unwrap_or([0u8; COMMITMENT_LEN]);
            let parent_index = index >> 1;
            let node_level =
                u8::try_from(TREE_DEPTH.wrapping_sub(1).wrapping_sub(merge_level)).unwrap_or(0);
            hash = node_hash(&self.prefixes, node_level, parent_index, left, hash);
            index >>= 1;
            merge_level = merge_level.wrapping_add(1);
        }
        if let Some(slot) = self.stack.get_mut(merge_level) {
            *slot = hash;
        }
    }
}

/// Extracts the hidden leaf share, commitment, and copath without indexing by
/// the secret hidden leaf.
#[must_use]
#[inline(never)]
pub fn hidden_opening(
    mut root_seed: [u8; FIELD_BYTES],
    tree_index: u16,
    alpha: u8,
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
) -> (F288, [u8; COMMITMENT_LEN], [[u8; FIELD_BYTES]; COPATH_LEN]) {
    let mut parent = root_seed;
    wipe_bytes(&mut root_seed);
    let prefixes = GgmPrefixes::new(tree_index, salt, pk_hash);
    let mut copath = [[0u8; FIELD_BYTES]; COPATH_LEN];
    for level in 0..TREE_DEPTH {
        let parent_index =
            u16::try_from(usize::from(alpha) >> (TREE_DEPTH.wrapping_sub(level))).unwrap_or(0);
        let (left, right) = expand_child(
            &prefixes,
            parent,
            u8::try_from(level).unwrap_or(0),
            parent_index,
        );
        let shift = TREE_DEPTH.wrapping_sub(1).wrapping_sub(level);
        let bit = u8::try_from((usize::from(alpha) >> shift) & 1).unwrap_or(0);
        let choice = CtChoice::from_bit(bit);
        let mut sibling = select_bytes(choice, right, left);
        let mut child = select_bytes(choice, left, right);
        if let Some(slot) = copath.get_mut(TREE_DEPTH.wrapping_sub(1).wrapping_sub(level)) {
            *slot = sibling;
        }
        wipe_bytes(&mut sibling);
        wipe_bytes(&mut parent);
        parent = child;
        child = [0u8; FIELD_BYTES];
        wipe_bytes(&mut child);
    }
    let share = leaf_share(parent);
    wipe_bytes(&mut parent);
    let commitment = leaf_commitment(&prefixes, u16::from(alpha), share);
    (share, commitment, copath)
}

/// Reconstructs the Merkle root from the hidden leaf commitment and copath.
#[must_use]
#[inline(never)]
pub fn reconstruct_root(
    hidden_commitment: [u8; COMMITMENT_LEN],
    copath: &[[u8; FIELD_BYTES]; COPATH_LEN],
    tree_index: u16,
    alpha: u8,
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
) -> [u8; COMMITMENT_LEN] {
    let prefixes = GgmPrefixes::new(tree_index, salt, pk_hash);
    let mut hash = hidden_commitment;
    for level in (1..=TREE_DEPTH).rev() {
        let sibling_index = (usize::from(alpha) >> (TREE_DEPTH.wrapping_sub(level))) ^ 1;
        let sibling_seed = copath
            .get(TREE_DEPTH.wrapping_sub(level))
            .copied()
            .unwrap_or([0u8; FIELD_BYTES]);
        let sibling_hash = subtree_hash(sibling_seed, level, sibling_index, &prefixes);
        let (left, right) = if sibling_index & 1 == 1 {
            (hash, sibling_hash)
        } else {
            (sibling_hash, hash)
        };
        let parent_index = usize::from(alpha) >> (TREE_DEPTH.wrapping_sub(level).wrapping_add(1));
        hash = node_hash(
            &prefixes,
            u8::try_from(level.wrapping_sub(1)).unwrap_or(0),
            u16::try_from(parent_index).unwrap_or(0),
            left,
            right,
        );
    }
    hash
}

fn subtree_hash(
    seed: [u8; FIELD_BYTES],
    level: usize,
    index: usize,
    prefixes: &GgmPrefixes,
) -> [u8; COMMITMENT_LEN] {
    if level == TREE_DEPTH {
        return leaf_commitment(
            prefixes,
            u16::try_from(index).unwrap_or(0),
            leaf_share(seed),
        );
    }
    let (left_seed, right_seed) = expand_child(
        prefixes,
        seed,
        u8::try_from(level).unwrap_or(0),
        u16::try_from(index).unwrap_or(0),
    );
    let left = subtree_hash(
        left_seed,
        level.wrapping_add(1),
        index.wrapping_mul(2),
        prefixes,
    );
    let right = subtree_hash(
        right_seed,
        level.wrapping_add(1),
        index.wrapping_mul(2).wrapping_add(1),
        prefixes,
    );
    node_hash(
        prefixes,
        u8::try_from(level).unwrap_or(0),
        u16::try_from(index).unwrap_or(0),
        left,
        right,
    )
}

#[inline]
fn select_bytes(
    choice: CtChoice,
    if_false: [u8; FIELD_BYTES],
    if_true: [u8; FIELD_BYTES],
) -> [u8; FIELD_BYTES] {
    let mut out = [0u8; FIELD_BYTES];
    for ((dst, left), right) in out.iter_mut().zip(if_false.iter()).zip(if_true.iter()) {
        *dst = choice.select_u8(*left, *right);
    }
    out
}

#[inline]
fn leaf_share(seed: [u8; FIELD_BYTES]) -> F288 {
    let value = F288::from_bytes(seed);
    let zero = value.ct_is_zero();
    F288::ct_select(zero, value, F288::ONE)
}

fn expand_child(
    prefixes: &GgmPrefixes,
    mut parent: [u8; FIELD_BYTES],
    level: u8,
    index: u16,
) -> ([u8; FIELD_BYTES], [u8; FIELD_BYTES]) {
    let mut suffix = [0u8; EXPAND_SUFFIX_LEN];
    let (slot, rest) = suffix.split_at_mut(1);
    slot.copy_from_slice(&[level]);
    let (slot, rest) = rest.split_at_mut(2);
    slot.copy_from_slice(&index.to_le_bytes());
    let (slot, _rest) = rest.split_at_mut(FIELD_BYTES);
    slot.copy_from_slice(&parent);

    let mut output = [0u8; 2 * FIELD_BYTES];
    prefixes.expand.finish(&suffix, &mut output);
    let (left_bytes, right_bytes) = output.split_at(FIELD_BYTES);
    let mut left = [0u8; FIELD_BYTES];
    let mut right = [0u8; FIELD_BYTES];
    left.copy_from_slice(left_bytes);
    right.copy_from_slice(right_bytes);
    wipe_bytes(&mut output);
    wipe_bytes(&mut suffix);
    wipe_bytes(&mut parent);
    (left, right)
}

#[inline(never)]
fn leaf_commitment(prefixes: &GgmPrefixes, leaf_index: u16, share: F288) -> [u8; COMMITMENT_LEN] {
    let mut suffix = [0u8; LEAF_SUFFIX_LEN];
    let (slot, rest) = suffix.split_at_mut(2);
    slot.copy_from_slice(&leaf_index.to_le_bytes());
    let (slot, _rest) = rest.split_at_mut(FIELD_BYTES);
    slot.copy_from_slice(&share.to_bytes());
    prefixes.leaf.finish(&suffix)
}

#[inline(never)]
fn node_hash(
    prefixes: &GgmPrefixes,
    level: u8,
    index: u16,
    left: [u8; COMMITMENT_LEN],
    right: [u8; COMMITMENT_LEN],
) -> [u8; COMMITMENT_LEN] {
    let mut suffix = [0u8; NODE_SUFFIX_LEN];
    let (slot, rest) = suffix.split_at_mut(1);
    slot.copy_from_slice(&[level]);
    let (slot, rest) = rest.split_at_mut(2);
    slot.copy_from_slice(&index.to_le_bytes());
    let (slot, rest) = rest.split_at_mut(COMMITMENT_LEN);
    slot.copy_from_slice(&left);
    let (slot, _rest) = rest.split_at_mut(COMMITMENT_LEN);
    slot.copy_from_slice(&right);
    prefixes.node.finish(&suffix)
}

#[cfg(kani)]
mod kani_proofs {
    use super::select_bytes;
    use crate::ct::CtChoice;

    #[kani::proof]
    fn masked_selection_matches_branch() {
        let flag: bool = kani::any();
        let if_false: [u8; crate::FIELD_BYTES] = kani::any();
        let if_true: [u8; crate::FIELD_BYTES] = kani::any();
        let selected = select_bytes(CtChoice::from_bool(flag), if_false, if_true);
        let expected = if flag { if_true } else { if_false };
        assert_eq!(selected, expected);
    }
}

#[cfg(test)]
mod tests {
    use super::{hidden_opening, reconstruct_root, tree_root};
    use crate::field::F288;

    const ROOT: [u8; 64] = [
        0xe5, 0xfd, 0x2e, 0xe6, 0x37, 0x78, 0x89, 0x35, 0xf3, 0x2e, 0x63, 0xba, 0x21, 0x5d, 0xd9,
        0x9b, 0x1a, 0x0a, 0x76, 0x94, 0xdc, 0x6c, 0x70, 0xab, 0x0f, 0xf7, 0x63, 0xc5, 0xf5, 0x2e,
        0x83, 0xbd, 0x7e, 0xab, 0x94, 0xe7, 0x91, 0xd6, 0x45, 0x6f, 0x6a, 0x7a, 0x4f, 0xab, 0xd0,
        0x66, 0x0e, 0x1a, 0xe3, 0x7a, 0x19, 0xec, 0x10, 0xb6, 0x74, 0x5e, 0x21, 0x3b, 0x32, 0xc6,
        0x50, 0xd4, 0x1d, 0xf8,
    ];
    const U: [u8; 36] = [
        0xc0, 0x86, 0xd1, 0xca, 0x43, 0x57, 0x51, 0xc6, 0x0c, 0x1f, 0x94, 0xdc, 0x9f, 0xf8, 0xb9,
        0x1b, 0xd6, 0x5d, 0xed, 0xcf, 0x3e, 0x8c, 0xb5, 0x57, 0x71, 0xd0, 0x47, 0xba, 0x42, 0x4b,
        0x5b, 0x27, 0xcb, 0xd4, 0x7d, 0x44,
    ];
    const COM: [u8; 64] = [
        0xe5, 0xf7, 0x35, 0x81, 0xf3, 0xc0, 0xc9, 0xff, 0xb1, 0x7e, 0x30, 0xca, 0x52, 0x78, 0x2d,
        0xbe, 0x3b, 0xc6, 0xec, 0x6c, 0xe5, 0xc1, 0x36, 0xc7, 0x23, 0x05, 0x55, 0xa9, 0xc6, 0xd8,
        0x77, 0x36, 0xfc, 0x05, 0x15, 0xce, 0x2b, 0x8b, 0xfa, 0xa1, 0x9d, 0x75, 0xe1, 0x24, 0xc5,
        0x4f, 0x94, 0x2c, 0x81, 0x16, 0x4c, 0xee, 0x5f, 0x84, 0x9b, 0x49, 0x6d, 0x1f, 0x08, 0x50,
        0x44, 0xae, 0xd7, 0xeb,
    ];
    const CP: [[u8; 36]; 8] = [
        [
            0x6a, 0x7a, 0xf4, 0x7f, 0xce, 0x58, 0x5f, 0xb6, 0x9d, 0x20, 0x34, 0xc0, 0x69, 0xa4,
            0x31, 0x1f, 0xb7, 0x12, 0xb0, 0x46, 0x13, 0x8c, 0x34, 0x18, 0xb5, 0x15, 0x9d, 0x37,
            0x82, 0xc9, 0xa3, 0x94, 0x82, 0x78, 0xf8, 0x9f,
        ],
        [
            0x84, 0xc6, 0x86, 0x65, 0x5e, 0xe9, 0x7b, 0x90, 0x72, 0x33, 0xb1, 0xe7, 0x1f, 0x92,
            0x3d, 0x80, 0x3b, 0xed, 0xeb, 0x5f, 0x65, 0xd3, 0xd9, 0x80, 0x9a, 0x9f, 0x89, 0xad,
            0x9a, 0x0d, 0xcb, 0x7f, 0xd7, 0x9c, 0xa1, 0x98,
        ],
        [
            0xa9, 0xdd, 0xe6, 0x7e, 0x37, 0x95, 0x1b, 0xb8, 0xb4, 0x6d, 0x64, 0xa3, 0x6b, 0x15,
            0x87, 0xcb, 0xe2, 0xfb, 0x20, 0xaf, 0xad, 0x95, 0xcd, 0xb0, 0xe3, 0x90, 0xa1, 0x0e,
            0x93, 0xbe, 0xed, 0x17, 0x33, 0x8d, 0x21, 0x10,
        ],
        [
            0xea, 0x25, 0x68, 0xfe, 0x45, 0x09, 0x85, 0xa4, 0x23, 0x19, 0x42, 0xa6, 0x12, 0xc6,
            0x05, 0xbf, 0xe9, 0x79, 0x59, 0x59, 0xf5, 0xba, 0x2e, 0xb5, 0x94, 0xe5, 0x2c, 0x5f,
            0xb2, 0xdd, 0xfb, 0xa0, 0xe2, 0xad, 0x15, 0x38,
        ],
        [
            0x16, 0xa2, 0x12, 0x89, 0xc5, 0xf2, 0x3b, 0xcf, 0x02, 0x27, 0x7b, 0x1d, 0x05, 0xfd,
            0x4b, 0x45, 0x26, 0xf8, 0x1a, 0x06, 0xb5, 0x45, 0xd8, 0xd5, 0xa5, 0x6d, 0x8a, 0x73,
            0x80, 0x9f, 0xcd, 0xf6, 0xfb, 0x38, 0x30, 0x53,
        ],
        [
            0x78, 0x56, 0x32, 0x4f, 0xbf, 0xb7, 0x35, 0x16, 0x8b, 0xb5, 0xfb, 0x58, 0x68, 0x0f,
            0xe3, 0xa7, 0x15, 0x81, 0xf8, 0x57, 0x9d, 0x8f, 0x9d, 0xd0, 0xdb, 0xca, 0xec, 0xc8,
            0xc0, 0xbf, 0x1f, 0x3c, 0xe5, 0xfb, 0x84, 0xd7,
        ],
        [
            0x5c, 0x51, 0x41, 0x5a, 0x64, 0xec, 0xcc, 0x98, 0x9c, 0xd3, 0x3f, 0x28, 0x97, 0x91,
            0xeb, 0xfb, 0x28, 0xc3, 0xe8, 0x70, 0x22, 0x36, 0x04, 0xcb, 0xc7, 0x49, 0x6e, 0xee,
            0x19, 0xb4, 0x3a, 0xb4, 0xd6, 0xac, 0xbd, 0x14,
        ],
        [
            0x2b, 0x7c, 0x94, 0xfd, 0x9f, 0xad, 0xb0, 0x62, 0xad, 0x1a, 0x79, 0x9b, 0x6d, 0x16,
            0x4a, 0x21, 0xed, 0xc2, 0x3f, 0x5a, 0xa1, 0xae, 0xc5, 0xe0, 0xf6, 0x7a, 0xe8, 0xdc,
            0x22, 0xa3, 0xd1, 0x8e, 0x34, 0x48, 0x46, 0xab,
        ],
    ];

    #[test]
    fn ggm_kat_and_copath() {
        let mut root_seed = [0u8; 36];
        for (index, byte) in root_seed.iter_mut().enumerate() {
            *byte = u8::try_from(index.wrapping_mul(5).wrapping_add(1) & 0xFF).unwrap_or(0);
        }
        let mut salt = [0u8; 64];
        for (index, byte) in salt.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0);
        }
        let mut pk_hash = [0u8; 64];
        for (index, byte) in pk_hash.iter_mut().enumerate() {
            *byte = u8::try_from(index.wrapping_mul(3).wrapping_add(7) & 0xFF).unwrap_or(0);
        }
        assert_eq!(tree_root(root_seed, 7, &salt, &pk_hash), ROOT);
        let (u, com, copath) = hidden_opening(root_seed, 7, 42, &salt, &pk_hash);
        assert_eq!(u, F288::from_bytes(U));
        assert_eq!(com, COM);
        assert_eq!(copath, CP);
        assert_eq!(reconstruct_root(COM, &copath, 7, 42, &salt, &pk_hash), ROOT);
    }
}
