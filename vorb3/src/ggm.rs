//! GGM tree and Merkle commitment for VORB3-SP1.
//!
//! Each tree has 256 leaves at depth 8. A 36-byte GGM seed is expanded into two
//! 36-byte children. Leaf shares are field elements; leaf commitments and
//! internal nodes are 64-byte WH512 values. The copath stores the eight sibling
//! seeds, allowing the verifier to reconstruct the Merkle root without the
//! hidden leaf.
#![allow(dead_code)] // consumed by sign/verify in Phase 6.

use crate::blake3::{derive_key, wh512};
use crate::field::F288;
use crate::{COMMITMENT_LEN, FIELD_BYTES, SALT_LEN, TREE_DEPTH};

const LEAF_COUNT: usize = 1 << TREE_DEPTH;
const NODE_COUNT: usize = (1 << (TREE_DEPTH + 1)) - 1;
const LOWER_NODES: usize = 256;
const UPPER_NODES: usize = 255;
const LEAF_BASE: usize = (1 << TREE_DEPTH) - 1;
const COPATH_LEN: usize = TREE_DEPTH;

const LEAF_LABEL: &[u8] = b"VORB3-GGM-LEAF-V1";
const NODE_LABEL: &[u8] = b"VORB3-GGM-NODE-V1";
const EXPAND_LABEL: &[u8] = b"VORB3-GGM-EXPAND-V1";

/// A fully expanded GGM tree with its Merkle root.
pub struct GgmTree {
    lower: [[u8; FIELD_BYTES]; LOWER_NODES],
    upper: [[u8; FIELD_BYTES]; UPPER_NODES],
    root: [u8; COMMITMENT_LEN],
}

impl GgmTree {
    /// Builds one tree and its Merkle root.
    pub fn build(
        root_seed: [u8; FIELD_BYTES],
        tree_index: u16,
        salt: &[u8; SALT_LEN],
        pk_hash: &[u8; COMMITMENT_LEN],
    ) -> Self {
        let mut tree = Self {
            lower: [[0u8; FIELD_BYTES]; LOWER_NODES],
            upper: [[0u8; FIELD_BYTES]; UPPER_NODES],
            root: [0u8; COMMITMENT_LEN],
        };
        tree.set_node(0, root_seed);

        for level in 0..TREE_DEPTH {
            let count = 1usize << level;
            let base = (1usize << level).wrapping_sub(1);
            let child_base = (1usize << level.wrapping_add(1)).wrapping_sub(1);
            for index in 0..count {
                let parent = tree.node(base.wrapping_add(index));
                let (left, right) = expand_child(
                    parent,
                    tree_index,
                    u8::try_from(level).unwrap_or(0),
                    u16::try_from(index).unwrap_or(0),
                    salt,
                    pk_hash,
                );
                let left_index = child_base.wrapping_add(index.wrapping_mul(2));
                let right_index = left_index.wrapping_add(1);
                tree.set_node(left_index, left);
                tree.set_node(right_index, right);
            }
        }

        let mut hashes = [[0u8; COMMITMENT_LEN]; LEAF_COUNT];
        for index in 0..LEAF_COUNT {
            let seed = tree.node(LEAF_BASE.wrapping_add(index));
            let share = leaf_share(seed);
            let commitment = leaf_commitment(
                tree_index,
                u16::try_from(index).unwrap_or(0),
                share,
                salt,
                pk_hash,
            );
            if let Some(slot) = hashes.get_mut(index) {
                *slot = commitment;
            }
        }

        let mut count = LEAF_COUNT;
        let mut level = TREE_DEPTH;
        let mut next_hashes = [[0u8; COMMITMENT_LEN]; LEAF_COUNT];
        while level > 0 {
            count >>= 1;
            for index in 0..count {
                let left = hashes
                    .get(index.wrapping_mul(2))
                    .copied()
                    .unwrap_or([0u8; COMMITMENT_LEN]);
                let right = hashes
                    .get(index.wrapping_mul(2).wrapping_add(1))
                    .copied()
                    .unwrap_or([0u8; COMMITMENT_LEN]);
                let node = node_hash(
                    tree_index,
                    u8::try_from(level.wrapping_sub(1)).unwrap_or(0),
                    u16::try_from(index).unwrap_or(0),
                    left,
                    right,
                    salt,
                    pk_hash,
                );
                if let Some(slot) = next_hashes.get_mut(index) {
                    *slot = node;
                }
            }
            hashes = next_hashes;
            level = level.wrapping_sub(1);
        }

        tree.root = hashes.first().copied().unwrap_or([0u8; COMMITMENT_LEN]);
        tree
    }

    #[inline]
    fn node(&self, index: usize) -> [u8; FIELD_BYTES] {
        if index < LOWER_NODES {
            self.lower.get(index).copied().unwrap_or([0u8; FIELD_BYTES])
        } else {
            self.upper
                .get(index.wrapping_sub(LOWER_NODES))
                .copied()
                .unwrap_or([0u8; FIELD_BYTES])
        }
    }

    #[inline]
    fn set_node(&mut self, index: usize, value: [u8; FIELD_BYTES]) {
        if index < LOWER_NODES {
            if let Some(slot) = self.lower.get_mut(index) {
                *slot = value;
            }
        } else if let Some(slot) = self.upper.get_mut(index.wrapping_sub(LOWER_NODES)) {
            *slot = value;
        }
    }

    /// Returns the Merkle root.
    #[must_use]
    #[inline]
    pub const fn root(&self) -> [u8; COMMITMENT_LEN] {
        self.root
    }

    /// Returns the hidden leaf share for `alpha`.
    #[must_use]
    #[inline]
    pub fn hidden_leaf_share(&self, alpha: u8) -> F288 {
        let index = LEAF_BASE.wrapping_add(usize::from(alpha));
        leaf_share(self.node(index))
    }

    /// Returns the hidden leaf commitment for `alpha`.
    #[must_use]
    #[inline]
    pub fn hidden_commitment(
        &self,
        tree_index: u16,
        alpha: u8,
        salt: &[u8; SALT_LEN],
        pk_hash: &[u8; COMMITMENT_LEN],
    ) -> [u8; COMMITMENT_LEN] {
        leaf_commitment(
            tree_index,
            u16::from(alpha),
            self.hidden_leaf_share(alpha),
            salt,
            pk_hash,
        )
    }

    /// Extracts the eight sibling seeds for `alpha`, leaf level first.
    #[must_use]
    pub fn copath(&self, alpha: u8) -> [[u8; FIELD_BYTES]; COPATH_LEN] {
        let mut copath = [[0u8; FIELD_BYTES]; COPATH_LEN];
        for level in (1..=TREE_DEPTH).rev() {
            let node_index = usize::from(alpha) >> (TREE_DEPTH.wrapping_sub(level));
            let sibling = node_index ^ 1;
            let base = (1usize << level).wrapping_sub(1);
            let seed = self.node(base.wrapping_add(sibling));
            let slot = TREE_DEPTH.wrapping_sub(level);
            if let Some(dst) = copath.get_mut(slot) {
                *dst = seed;
            }
        }
        copath
    }
}

/// Reconstructs the Merkle root from the hidden leaf commitment and copath.
#[must_use]
pub fn reconstruct_root(
    hidden_commitment: [u8; COMMITMENT_LEN],
    copath: &[[u8; FIELD_BYTES]; COPATH_LEN],
    tree_index: u16,
    alpha: u8,
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
) -> [u8; COMMITMENT_LEN] {
    let mut hash = hidden_commitment;
    for level in (1..=TREE_DEPTH).rev() {
        let sibling_index = (usize::from(alpha) >> (TREE_DEPTH.wrapping_sub(level))) ^ 1;
        let sibling_seed = copath
            .get(TREE_DEPTH.wrapping_sub(level))
            .copied()
            .unwrap_or([0u8; FIELD_BYTES]);
        let sibling_hash = subtree_hash(
            sibling_seed,
            tree_index,
            level,
            sibling_index,
            salt,
            pk_hash,
        );
        let (left, right) = if sibling_index & 1 == 1 {
            (hash, sibling_hash)
        } else {
            (sibling_hash, hash)
        };
        let parent_index = usize::from(alpha) >> (TREE_DEPTH.wrapping_sub(level).wrapping_add(1));
        hash = node_hash(
            tree_index,
            u8::try_from(level.wrapping_sub(1)).unwrap_or(0),
            u16::try_from(parent_index).unwrap_or(0),
            left,
            right,
            salt,
            pk_hash,
        );
    }
    hash
}

fn subtree_hash(
    seed: [u8; FIELD_BYTES],
    tree_index: u16,
    level: usize,
    index: usize,
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
) -> [u8; COMMITMENT_LEN] {
    if level == TREE_DEPTH {
        return leaf_commitment(
            tree_index,
            u16::try_from(index).unwrap_or(0),
            leaf_share(seed),
            salt,
            pk_hash,
        );
    }
    let (left_seed, right_seed) = expand_child(
        seed,
        tree_index,
        u8::try_from(level).unwrap_or(0),
        u16::try_from(index).unwrap_or(0),
        salt,
        pk_hash,
    );
    let left = subtree_hash(
        left_seed,
        tree_index,
        level.wrapping_add(1),
        index.wrapping_mul(2),
        salt,
        pk_hash,
    );
    let right = subtree_hash(
        right_seed,
        tree_index,
        level.wrapping_add(1),
        index.wrapping_mul(2).wrapping_add(1),
        salt,
        pk_hash,
    );
    node_hash(
        tree_index,
        u8::try_from(level).unwrap_or(0),
        u16::try_from(index).unwrap_or(0),
        left,
        right,
        salt,
        pk_hash,
    )
}

#[inline]
fn leaf_share(seed: [u8; FIELD_BYTES]) -> F288 {
    let value = F288::from_bytes(seed);
    let zero = value.ct_is_zero();
    F288::ct_select(zero, value, F288::ONE)
}

fn expand_child(
    parent: [u8; FIELD_BYTES],
    tree_index: u16,
    level: u8,
    index: u16,
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
) -> ([u8; FIELD_BYTES], [u8; FIELD_BYTES]) {
    let mut data = [0u8; 192];
    let mut offset = 0usize;
    if !append(&mut data, &mut offset, EXPAND_LABEL)
        || !append(&mut data, &mut offset, salt)
        || !append(&mut data, &mut offset, pk_hash)
        || !append(&mut data, &mut offset, &tree_index.to_le_bytes())
        || !append(&mut data, &mut offset, &[level])
        || !append(&mut data, &mut offset, &index.to_le_bytes())
        || !append(&mut data, &mut offset, &parent)
    {
        return ([0u8; FIELD_BYTES], [0u8; FIELD_BYTES]);
    }
    let mut output = [0u8; 2 * FIELD_BYTES];
    derive_key(
        "VORB3-GGM-EXPAND-V1",
        data.get(..offset).unwrap_or(&[]),
        &mut output,
    );
    let (chunks, remainder) = output.as_chunks::<FIELD_BYTES>();
    if !remainder.is_empty() {
        return ([0u8; FIELD_BYTES], [0u8; FIELD_BYTES]);
    }
    let [left, right] = chunks else {
        return ([0u8; FIELD_BYTES], [0u8; FIELD_BYTES]);
    };
    (*left, *right)
}

fn leaf_commitment(
    tree_index: u16,
    leaf_index: u16,
    share: F288,
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
) -> [u8; COMMITMENT_LEN] {
    let mut data = [0u8; 192];
    let mut offset = 0usize;
    if !append(&mut data, &mut offset, LEAF_LABEL)
        || !append(&mut data, &mut offset, salt)
        || !append(&mut data, &mut offset, pk_hash)
        || !append(&mut data, &mut offset, &tree_index.to_le_bytes())
        || !append(&mut data, &mut offset, &leaf_index.to_le_bytes())
        || !append(&mut data, &mut offset, &share.to_bytes())
    {
        return [0u8; COMMITMENT_LEN];
    }
    wh512(data.get(..offset).unwrap_or(&[]))
}

fn node_hash(
    tree_index: u16,
    level: u8,
    index: u16,
    left: [u8; COMMITMENT_LEN],
    right: [u8; COMMITMENT_LEN],
    salt: &[u8; SALT_LEN],
    pk_hash: &[u8; COMMITMENT_LEN],
) -> [u8; COMMITMENT_LEN] {
    let mut data = [0u8; 288];
    let mut offset = 0usize;
    if !append(&mut data, &mut offset, NODE_LABEL)
        || !append(&mut data, &mut offset, salt)
        || !append(&mut data, &mut offset, pk_hash)
        || !append(&mut data, &mut offset, &tree_index.to_le_bytes())
        || !append(&mut data, &mut offset, &[level])
        || !append(&mut data, &mut offset, &index.to_le_bytes())
        || !append(&mut data, &mut offset, &left)
        || !append(&mut data, &mut offset, &right)
    {
        return [0u8; COMMITMENT_LEN];
    }
    wh512(data.get(..offset).unwrap_or(&[]))
}

#[inline]
fn append(buffer: &mut [u8], offset: &mut usize, data: &[u8]) -> bool {
    let Some(end) = offset.checked_add(data.len()) else {
        return false;
    };
    let Some(dst) = buffer.get_mut(*offset..end) else {
        return false;
    };
    dst.copy_from_slice(data);
    *offset = end;
    true
}

#[cfg(test)]
mod tests {
    use super::{GgmTree, reconstruct_root};
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
        let tree = GgmTree::build(root_seed, 7, &salt, &pk_hash);
        assert_eq!(tree.root(), ROOT);
        assert_eq!(tree.hidden_leaf_share(42), F288::from_bytes(U));
        assert_eq!(tree.hidden_commitment(7, 42, &salt, &pk_hash), COM);
        let copath = tree.copath(42);
        assert_eq!(copath, CP);
        assert_eq!(reconstruct_root(COM, &copath, 7, 42, &salt, &pk_hash), ROOT);
    }
}
