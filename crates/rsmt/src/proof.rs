//! Bitmap+siblings inclusion proof for the Sparse Merkle Tree.
//!
//! An inclusion proof demonstrates that a specific `(key, value)` exists in
//! a tree with a given root hash.
//!
//! ## Format
//!
//! - `bitmap`: `[u8; 32]` — set bits indicate node depths on the path, with
//!   depth `d` represented by the `d`-th most-significant bit.
//! - `siblings`: `Vec<[u8; 32]>` — sibling hashes ordered leaf-to-root.
//!
//! ## Verification
//!
//! Regions are not transmitted on the wire — the verifier derives the
//! expected region at each depth from the queried key itself (RSMT v6a).
//!
//! 1. `h = hash_leaf(key, value)`
//! 2. For each set bit in `bitmap` (ascending = leaf-to-root):
//!    - `region = prefix_region(key, depth)`
//!    - If `key_bit_at(key, depth) == 0`: `h = hash_node(h, sibling, depth, region)`
//!    - Else: `h = hash_node(sibling, h, depth, region)`
//! 3. Accept iff `h == root`.

use crate::hash::{hash_leaf, hash_node};
use crate::path::{key_bit_at, prefix_region, SmtKey};
use crate::tree::{SmtError, SparseMerkleTree};
use crate::types::{branch_hash, Branch};

// ─── Proof types ─────────────────────────────────────────────────────────────

/// An inclusion proof for a single leaf.
#[derive(Debug, Clone)]
pub struct InclusionProof {
    /// Bitmap: set bits indicate node depths on the proof path.
    pub bitmap: [u8; 32],
    /// Sibling hashes, ordered leaf-to-root (ascending depth order).
    pub siblings: Vec<[u8; 32]>,
}

impl InclusionProof {
    /// Number of siblings (= popcount of bitmap).
    pub fn sibling_count(&self) -> usize {
        self.siblings.len()
    }

    /// Serialize to wire format: `[bitmap_32B, sibling_0_32B, ...]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.siblings.len() * 32);
        out.extend_from_slice(&self.bitmap);
        for s in &self.siblings {
            out.extend_from_slice(s);
        }
        out
    }

    /// Deserialize from wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 32 {
            return Err("too short for bitmap");
        }
        let mut bitmap = [0u8; 32];
        bitmap.copy_from_slice(&data[..32]);

        let rest = &data[32..];
        if rest.len() % 32 != 0 {
            return Err("sibling data not aligned to 32 bytes");
        }

        let expected = bitmap.iter().map(|b| b.count_ones()).sum::<u32>() as usize;
        let actual = rest.len() / 32;
        if actual != expected {
            return Err("sibling count does not match bitmap popcount");
        }

        let siblings: Vec<[u8; 32]> = rest
            .chunks_exact(32)
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(c);
                h
            })
            .collect();

        Ok(Self { bitmap, siblings })
    }
}

// ─── Proof generation ─────────────────────────────────────────────────────────

impl SparseMerkleTree {
    /// Generate an inclusion proof for the leaf at `key`.
    ///
    /// Returns `Err(LeafNotFound)` if no leaf exists at that key.
    pub fn get_inclusion_proof(&self, key: &SmtKey) -> Result<InclusionProof, SmtError> {
        let root = self.root.as_ref().ok_or(SmtError::LeafNotFound)?;

        let mut bitmap = [0u8; 32];
        let mut siblings: Vec<[u8; 32]> = Vec::new();

        generate_proof(root, key, 0, &mut bitmap, &mut siblings)?;

        Ok(InclusionProof { bitmap, siblings })
    }
}

/// Walk tree from root to leaf, collecting sibling hashes.
fn generate_proof(
    node: &Branch,
    key: &SmtKey,
    start_bit: usize,
    bitmap: &mut [u8; 32],
    siblings: &mut Vec<[u8; 32]>,
) -> Result<(), SmtError> {
    match node {
        Branch::Leaf(l) => {
            if l.key == *key {
                Ok(())
            } else {
                Err(SmtError::LeafNotFound)
            }
        }
        Branch::Node(n) => {
            let n_path = n.path.path_len();

            // Check prefix match.
            if !n.path.matches_key(key, start_bit) {
                return Err(SmtError::LeafNotFound);
            }

            let depth = n.depth as usize;
            debug_assert_eq!(depth, start_bit + n_path);

            // Set bit in bitmap at this depth.
            bitmap[depth / 8] |= 0x80 >> (depth % 8);

            if key_bit_at(key, depth) == 1 {
                // Target is right; sibling is left.
                siblings.push(branch_hash(&n.left));
                generate_proof(&n.right, key, depth + 1, bitmap, siblings)
            } else {
                // Target is left; sibling is right.
                siblings.push(branch_hash(&n.right));
                generate_proof(&n.left, key, depth + 1, bitmap, siblings)
            }
        }
        Branch::Stub(_) => {
            panic!("generate_proof: Stub on proof path — materialize first");
        }
    }
}

// ─── Proof verification ──────────────────────────────────────────────────────

/// Verify an inclusion proof.
///
/// Returns `true` if the proof demonstrates that `(key, value)` exists in
/// a tree with root hash `root`.
///
/// Siblings are ordered root-to-leaf (shallowest first). Verification
/// iterates bitmap bits descending (deepest first) to build up from the
/// leaf hash to the root hash.
pub fn verify_inclusion(
    proof: &InclusionProof,
    root: &[u8; 32],
    key: &SmtKey,
    value: &[u8],
) -> bool {
    let mut h = hash_leaf(key, value);
    // Consume siblings from the end (deepest first).
    let mut sibling_idx = proof.siblings.len();

    // Iterate set bits in bitmap descending (deepest = leaf-to-root).
    for depth in (0..256usize).rev() {
        if proof.bitmap[depth / 8] & (0x80 >> (depth % 8)) == 0 {
            continue;
        }
        if sibling_idx == 0 {
            return false;
        }
        sibling_idx -= 1;
        let sibling = &proof.siblings[sibling_idx];
        let region = prefix_region(key, depth);

        if key_bit_at(key, depth) == 1 {
            // We went right at this depth, so sibling is left.
            h = hash_node(sibling, &h, depth as u8, &region);
        } else {
            // We went left, sibling is right.
            h = hash_node(&h, sibling, depth as u8, &region);
        }
    }

    sibling_idx == 0 && h == *root
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::SparseMerkleTree;

    fn make_key(byte: u8) -> SmtKey {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    #[test]
    fn single_leaf_proof() {
        let mut tree = SparseMerkleTree::new();
        let k = make_key(1);
        let v = vec![0xab; 32];
        tree.add_leaf(k, v.clone()).unwrap();

        let root = tree.root_hash().unwrap();
        let proof = tree.get_inclusion_proof(&k).unwrap();

        // Single leaf, no internal nodes — bitmap should be zero.
        assert_eq!(proof.sibling_count(), 0);
        assert!(verify_inclusion(&proof, &root, &k, &v));
    }

    #[test]
    fn two_leaf_proof() {
        let mut tree = SparseMerkleTree::new();
        let k1 = make_key(1);
        let k2 = make_key(2);
        let v1 = vec![1; 32];
        let v2 = vec![2; 32];
        tree.add_leaf(k1, v1.clone()).unwrap();
        tree.add_leaf(k2, v2.clone()).unwrap();
        let root = tree.root_hash().unwrap();

        let p1 = tree.get_inclusion_proof(&k1).unwrap();
        assert!(verify_inclusion(&p1, &root, &k1, &v1));

        let p2 = tree.get_inclusion_proof(&k2).unwrap();
        assert!(verify_inclusion(&p2, &root, &k2, &v2));
    }

    #[test]
    fn bitmap_uses_msb_first_depth_bits() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(0x00), vec![1; 32]).unwrap();
        tree.add_leaf(make_key(0x80), vec![2; 32]).unwrap();

        let proof = tree.get_inclusion_proof(&make_key(0x00)).unwrap();
        assert_eq!(proof.bitmap[0], 0x80, "depth zero is the bitmap MSB");
    }

    #[test]
    fn missing_leaf_returns_error() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(1), vec![1; 32]).unwrap();
        let r = tree.get_inclusion_proof(&make_key(2));
        assert!(r.is_err());
    }

    #[test]
    fn empty_tree_returns_error() {
        let tree = SparseMerkleTree::new();
        assert!(tree.get_inclusion_proof(&make_key(1)).is_err());
    }

    #[test]
    fn many_leaves_proof() {
        let mut tree = SparseMerkleTree::new();
        for i in 0u8..=64 {
            tree.add_leaf(make_key(i), vec![i; 32]).unwrap();
        }
        let root = tree.root_hash().unwrap();

        for i in 0u8..=64 {
            let k = make_key(i);
            let v = vec![i; 32];
            let proof = tree.get_inclusion_proof(&k).unwrap();
            assert!(
                verify_inclusion(&proof, &root, &k, &v),
                "inclusion proof failed for key {}",
                i
            );
        }
    }

    #[test]
    fn wrong_value_fails_verification() {
        let mut tree = SparseMerkleTree::new();
        let k = make_key(42);
        tree.add_leaf(k, vec![42; 32]).unwrap();
        let root = tree.root_hash().unwrap();
        let proof = tree.get_inclusion_proof(&k).unwrap();

        // Wrong value.
        assert!(!verify_inclusion(&proof, &root, &k, &[99; 32]));
    }

    #[test]
    fn wrong_root_fails_verification() {
        let mut tree = SparseMerkleTree::new();
        let k = make_key(1);
        let v = vec![1; 32];
        tree.add_leaf(k, v.clone()).unwrap();
        let proof = tree.get_inclusion_proof(&k).unwrap();

        let fake_root = [0xFF; 32];
        assert!(!verify_inclusion(&proof, &fake_root, &k, &v));
    }

    #[test]
    fn proof_serialization_roundtrip() {
        let mut tree = SparseMerkleTree::new();
        for i in 1u8..=8 {
            tree.add_leaf(make_key(i), vec![i; 32]).unwrap();
        }
        let root = tree.root_hash().unwrap();
        let k = make_key(5);
        let v = vec![5; 32];
        let proof = tree.get_inclusion_proof(&k).unwrap();

        let bytes = proof.to_bytes();
        let decoded = InclusionProof::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.bitmap, proof.bitmap);
        assert_eq!(decoded.siblings, proof.siblings);
        assert!(verify_inclusion(&decoded, &root, &k, &v));
    }
}
