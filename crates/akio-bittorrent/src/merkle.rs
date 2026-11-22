//! BEP 52 merkle trees: SHA-256 over 16 KiB blocks, binary, padded to a power of two.
//!
//! A file of `n` blocks has `n.next_power_of_two()` leaves; leaves past the end of the file are
//! 32 zero bytes, and a node is `SHA-256(left || right)`. Heights count from the leaves
//! (height 0); the root of a file is at height `log2(leaves)`. A torrent's *piece layer* is the
//! height at which one node covers one piece (`log2(piece_length / 16 KiB)`).
//!
//! [`MerkleTree`] holds a file's tree from one layer up (the piece layer, as a .torrent's
//! `piece layers` carries it) and answers the hash requests of the peer wire protocol;
//! [`verify_hashes`] checks a `hashes` message against the file's root.

use akio_crypto::hash::Sha256;

/// A SHA-256 hash.
pub type Hash = [u8; 32];

/// The leaf block size.
pub const BLOCK: usize = 16 * 1024;

/// Most hashes one hash request may ask for at its base layer (libtorrent's limit: a 128 MiB
/// piece of 16 KiB blocks).
pub const MAX_REQUEST_HASHES: u32 = 8192;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data)
}

/// `SHA-256(left || right)`.
pub fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize()
}

/// The hash of an all-padding subtree of height `height` (32 zero bytes at height 0).
pub fn pad_hash(height: u32) -> Hash {
    let mut h = [0u8; 32];
    for _ in 0..height {
        h = hash_pair(&h, &h);
    }
    h
}

/// The leaf hashes of `data`: one per 16 KiB block, the last block possibly shorter.
pub fn block_hashes(data: &[u8]) -> Vec<Hash> {
    data.chunks(BLOCK).map(sha256).collect()
}

/// `log2` of a power of two.
pub(crate) fn log2(n: u64) -> u32 {
    63 - n.max(1).leading_zeros()
}

/// The root of a subtree whose layer at `height` is `nodes`, padded with [`pad_hash`]`(height)`
/// to `width` nodes (`width` a power of two of at least `nodes.len()`).
pub fn subtree_root(nodes: &[Hash], height: u32, width: usize) -> Hash {
    let width = width.max(nodes.len()).max(1).next_power_of_two();
    let mut layer: Vec<Hash> = nodes.to_vec();
    let mut pad = pad_hash(height);
    let mut w = width;
    while w > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let r = pair.get(1).unwrap_or(&pad);
            next.push(hash_pair(&pair[0], r));
        }
        if next.is_empty() {
            next.push(hash_pair(&pad, &pad));
        }
        pad = hash_pair(&pad, &pad);
        layer = next;
        w /= 2;
    }
    layer.first().copied().unwrap_or(pad)
}

/// Blocks per piece (`piece_length` a power of two of at least 16 KiB).
pub fn blocks_per_piece(piece_length: u32) -> u32 {
    (piece_length as usize / BLOCK).max(1) as u32
}

/// The height of the piece layer.
pub fn piece_height(piece_length: u32) -> u32 {
    log2(u64::from(blocks_per_piece(piece_length)))
}

/// Blocks of a file of `len` bytes.
pub fn num_blocks(len: u64) -> u64 {
    len.div_ceil(BLOCK as u64)
}

/// Height of the root of a file of `len` bytes (0 for one block).
pub fn root_height(len: u64) -> u32 {
    log2(num_blocks(len).max(1).next_power_of_two())
}

/// The piece-layer node of one piece of a file: `data` is the piece's bytes in the file (the
/// last piece may be short), padded with zero leaves to a whole piece.
pub fn piece_root(data: &[u8], piece_length: u32) -> Hash {
    subtree_root(
        &block_hashes(data),
        0,
        blocks_per_piece(piece_length) as usize,
    )
}

/// The root of a whole file held in memory.
pub fn file_root(data: &[u8]) -> Hash {
    let leaves = block_hashes(data);
    let width = leaves.len().max(1).next_power_of_two();
    subtree_root(&leaves, 0, width)
}

/// The root of a file of `len` bytes from its piece layer (one node per piece).
pub fn root_from_piece_layer(layer: &[Hash], piece_length: u32, len: u64) -> Hash {
    let h = piece_height(piece_length);
    let width = (num_blocks(len).max(1).next_power_of_two() >> h).max(1) as usize;
    subtree_root(layer, h, width)
}

/// A file's merkle tree from one layer up to the root. Nodes past the end of the file are
/// padding, computed rather than stored.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    base: u32,
    /// `levels[0]` is the base layer as given; each next level up has half as many nodes
    /// (rounded up), the last a single root.
    levels: Vec<Vec<Hash>>,
    pads: Vec<Hash>,
}

impl MerkleTree {
    /// The tree whose layer at `height` is `layer` and whose root is at `root_height`.
    pub fn from_layer(layer: &[Hash], height: u32, root_height: u32) -> MerkleTree {
        let top = root_height.max(height);
        let mut pads = Vec::with_capacity((top - height + 1) as usize);
        let mut p = pad_hash(height);
        for _ in height..=top {
            pads.push(p);
            p = hash_pair(&p, &p);
        }
        let mut levels = vec![layer.to_vec()];
        for lv in 0..(top - height) as usize {
            let cur = &levels[lv];
            let pad = pads[lv];
            let mut next = Vec::with_capacity(cur.len().div_ceil(2).max(1));
            for pair in cur.chunks(2) {
                next.push(hash_pair(&pair[0], pair.get(1).unwrap_or(&pad)));
            }
            if next.is_empty() {
                next.push(pads[lv + 1]);
            }
            levels.push(next);
        }
        MerkleTree {
            base: height,
            levels,
            pads,
        }
    }

    /// The height of the stored base layer.
    pub fn base_height(&self) -> u32 {
        self.base
    }

    /// The height of the root.
    pub fn root_height(&self) -> u32 {
        self.base + self.levels.len() as u32 - 1
    }

    /// The root.
    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .and_then(|l| l.first())
            .copied()
            .unwrap_or_else(|| pad_hash(self.base))
    }

    /// The node at `height` (at or above the base) and `index`, padding past the end; `None`
    /// below the base or above the root.
    pub fn node(&self, height: u32, index: u64) -> Option<Hash> {
        let lv = height.checked_sub(self.base)? as usize;
        let level = self.levels.get(lv)?;
        if index >= 1u64 << (self.root_height() - height) {
            return None;
        }
        Some(
            usize::try_from(index)
                .ok()
                .and_then(|i| level.get(i))
                .copied()
                .unwrap_or(self.pads[lv]),
        )
    }

    /// The uncle hashes of a hash request whose `count` base-layer nodes start at `index` of
    /// layer `base`: one sibling per layer from `log2(count)` to `proof_layers` (both counted
    /// from `base`), leaf to root, as libtorrent sends them. `None` if a sibling lies below this
    /// tree's base or above its root.
    pub fn uncles(
        &self,
        base: u32,
        index: u64,
        count: u32,
        proof_layers: u32,
    ) -> Option<Vec<Hash>> {
        let l = log2(u64::from(count));
        let mut out = Vec::new();
        let mut pos = index >> l;
        for i in l..=proof_layers {
            let h = base + i;
            if h >= self.root_height() {
                return None;
            }
            out.push(self.node(h, pos ^ 1)?);
            pos >>= 1;
        }
        Some(out)
    }

    /// Answers a hash request for this tree's own base layer: the `count` nodes at `index`
    /// followed by the uncles. `None` if the request does not fit the tree.
    pub fn hashes(&self, index: u64, count: u32, proof_layers: u32) -> Option<Vec<Hash>> {
        if !valid_range(self.root_height() - self.base, index, count) {
            return None;
        }
        let mut out = Vec::with_capacity(count as usize + 8);
        for i in index..index + u64::from(count) {
            out.push(self.node(self.base, i)?);
        }
        out.extend(self.uncles(self.base, index, count, proof_layers)?);
        Some(out)
    }
}

/// Whether `count` nodes at `index` fit a layer `levels` below the root: `count` a power of two
/// of at least 2 and at most [`MAX_REQUEST_HASHES`], `index` a multiple of it.
pub(crate) fn valid_range(levels: u32, index: u64, count: u32) -> bool {
    let size = 1u64.checked_shl(levels).unwrap_or(0);
    (2..=MAX_REQUEST_HASHES).contains(&count)
        && count.is_power_of_two()
        && index % u64::from(count) == 0
        && index + u64::from(count) <= size
}

/// The number of uncle hashes a request of `count` nodes with `proof_layers` carries.
pub fn uncle_count(count: u32, proof_layers: u32) -> usize {
    (proof_layers + 1).saturating_sub(log2(u64::from(count))) as usize
}

/// Checks `nodes` (a subtree of `count` nodes at layer `height`, starting at `index`) with its
/// `uncles` against `root` at `root_height`: the uncles must lead all the way to the root.
pub fn verify_hashes(
    nodes: &[Hash],
    height: u32,
    index: u64,
    uncles: &[Hash],
    root: &Hash,
    root_height: u32,
) -> bool {
    let count = nodes.len();
    if count == 0 || !count.is_power_of_two() || index % count as u64 != 0 {
        return false;
    }
    let l = log2(count as u64);
    if height + l + uncles.len() as u32 != root_height {
        return false;
    }
    let mut cur = subtree_root(nodes, height, count);
    let mut pos = index >> l;
    for u in uncles {
        cur = if pos & 1 == 0 {
            hash_pair(&cur, u)
        } else {
            hash_pair(u, &cur)
        };
        pos >>= 1;
    }
    cur == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn roots_agree() {
        let pl = 64 * 1024; // 4 blocks per piece
        for len in [
            1,
            BLOCK,
            BLOCK + 1,
            pl as usize,
            pl as usize + 5,
            5 * pl as usize - 3,
        ] {
            let d = data(len);
            let root = file_root(&d);
            let layer: Vec<Hash> = d.chunks(pl as usize).map(|c| piece_root(c, pl)).collect();
            if len > pl as usize {
                assert_eq!(root_from_piece_layer(&layer, pl, len as u64), root, "{len}");
            }
            let t = MerkleTree::from_layer(&block_hashes(&d), 0, root_height(len as u64));
            assert_eq!(t.root(), root, "{len}");
        }
    }

    #[test]
    fn pad_is_zero_subtree() {
        assert_eq!(pad_hash(0), [0; 32]);
        assert_eq!(subtree_root(&[], 0, 4), pad_hash(2));
        assert_eq!(subtree_root(&[[0; 32]; 4], 0, 4), pad_hash(2));
    }

    #[test]
    fn proofs_verify() {
        let pl = 32 * 1024; // 2 blocks per piece
        let d = data(37 * pl as usize + 100);
        let layer: Vec<Hash> = d.chunks(pl as usize).map(|c| piece_root(c, pl)).collect();
        let rh = root_height(d.len() as u64);
        let ph = piece_height(pl);
        let t = MerkleTree::from_layer(&layer, ph, rh);
        assert_eq!(t.root(), file_root(&d));
        // Full proofs: proof_layers up to the child of the root.
        for (index, count) in [(0u64, 2u32), (2, 2), (32, 32), (0, 64), (36, 4)] {
            let proof = rh - ph - 1;
            let h = t.hashes(index, count, proof).unwrap();
            assert_eq!(h.len(), count as usize + uncle_count(count, proof));
            let (nodes, uncles) = h.split_at(count as usize);
            assert!(
                verify_hashes(nodes, ph, index, uncles, &t.root(), rh),
                "{index} {count}"
            );
            let mut bad = nodes.to_vec();
            bad[0][0] ^= 1;
            assert!(!verify_hashes(&bad, ph, index, uncles, &t.root(), rh));
        }
        assert!(t.hashes(1, 2, 3).is_none()); // misaligned
        assert!(t.hashes(0, 3, 3).is_none()); // not a power of two
        assert!(t.hashes(64, 2, 3).is_none()); // past the layer
        // Block-layer proofs: leaves from the data, uncles from the piece tree.
        let piece = 5u64;
        let leaves =
            block_hashes(&d[piece as usize * pl as usize..(piece as usize + 1) * pl as usize]);
        let uncles = t.uncles(0, piece * 2, 2, rh - 1).unwrap();
        assert!(verify_hashes(&leaves, 0, piece * 2, &uncles, &t.root(), rh));
    }
}
