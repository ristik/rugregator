//! Sparse Merkle Tree — insertion and root hash.

use std::sync::Arc;
use thiserror::Error;

use crate::hash::{SmtHasher, Sha256Hasher};
use crate::path::{key_bit_at, CompressedPath, SmtKey, KEY_BITS};
use crate::types::{branch_hash, make_leaf, make_node, Branch, LeafBranch, NodeBranch};

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq)]
pub enum SmtError {
    #[error("smt: duplicate leaf")]
    DuplicateLeaf,
    #[error("smt: leaf not found")]
    LeafNotFound,
}

// ─── SparseMerkleTree ────────────────────────────────────────────────────────

/// A path-compressed radix trie with 256-bit keys.
///
/// The root is `Option<Arc<Branch>>`: `None` for an empty tree.
/// Creating a snapshot via `deep_clone()` is O(1) — just an `Arc::clone`.
///
/// The tree itself is not parameterised over the hasher — hashes are stored
/// eagerly in each node.  Pass the desired [`SmtHasher`] to `add_leaf_with`
/// (or use `add_leaf` for the SHA-256 default).
pub struct SparseMerkleTree {
    pub root: Option<Arc<Branch>>,
}

impl SparseMerkleTree {
    /// Create a new empty tree.
    pub fn new() -> Self {
        Self { root: None }
    }

    /// Root hash: `None` for empty tree, `Some(hash)` otherwise.
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.root.as_ref().map(|b| branch_hash(b))
    }

    /// O(1) CoW clone — just clones the root Arc.
    pub fn deep_clone(&self) -> Self {
        Self { root: self.root.clone() }
    }

    /// Add a single leaf using the given hasher.
    /// Returns `Err(DuplicateLeaf)` if the key already exists.
    pub fn add_leaf_with<H: SmtHasher>(&mut self, key: SmtKey, value: Vec<u8>) -> Result<(), SmtError> {
        if self.find_leaf(&key).is_some() {
            return Err(SmtError::DuplicateLeaf);
        }
        self.root = Some(insert::<H>(self.root.take(), key, value, 0));
        Ok(())
    }

    /// Add a single leaf using the default SHA-256 hasher.
    /// Returns `Err(DuplicateLeaf)` if the key already exists.
    #[inline]
    pub fn add_leaf(&mut self, key: SmtKey, value: Vec<u8>) -> Result<(), SmtError> {
        self.add_leaf_with::<Sha256Hasher>(key, value)
    }

    /// Find a leaf by key.
    pub fn find_leaf(&self, key: &SmtKey) -> Option<&LeafBranch> {
        find_leaf_in(self.root.as_deref(), key, 0)
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Leaf lookup ────────────────────────────────────────────────────────────

fn find_leaf_in<'a>(node: Option<&'a Branch>, key: &SmtKey, start_bit: usize) -> Option<&'a LeafBranch> {
    let b = node?;
    match b {
        Branch::Leaf(l) => {
            if l.key == *key { Some(l) } else { None }
        }
        Branch::Node(n) => {
            let n_path = n.path.path_len();
            if !n.path.matches_key(key, start_bit) {
                return None;
            }
            let split = start_bit + n_path;
            if key_bit_at(key, split) == 1 {
                find_leaf_in(Some(&n.right), key, split + 1)
            } else {
                find_leaf_in(Some(&n.left), key, split + 1)
            }
        }
        Branch::Stub(_) => None,
    }
}

// ─── Insertion ───────────────────────────────────────────────────────────────

fn insert<H: SmtHasher>(
    node_opt: Option<Arc<Branch>>,
    key: SmtKey,
    value: Vec<u8>,
    start_bit: usize,
) -> Arc<Branch> {
    let Some(arc) = node_opt else {
        return make_leaf::<H>(key, value);
    };

    // CoW: take ownership if sole Arc owner, else clone.
    let b = match Arc::try_unwrap(arc) {
        Ok(b) => b,
        Err(a) => (*a).clone(),
    };

    match b {
        Branch::Leaf(existing) => {
            let div = first_diverging_bit(&existing.key, &key, start_bit);
            let cp = CompressedPath::from_key_range(&key, start_bit, div - start_bit);
            let old_leaf = Arc::new(Branch::Leaf(existing));
            let new_leaf = make_leaf::<H>(key, value);
            if key_bit_at(&key, div) == 1 {
                make_node::<H>(cp, old_leaf, new_leaf, div as u8)
            } else {
                make_node::<H>(cp, new_leaf, old_leaf, div as u8)
            }
        }
        Branch::Node(mut n) => {
            let n_path = n.path.path_len();
            let first_div = first_divergence_in_prefix(&n.path, &key, start_bit);

            if first_div < n_path {
                return split_node::<H>(n, key, value, start_bit, first_div);
            }

            let split = start_bit + n_path;
            n.hash = None;
            if key_bit_at(&key, split) == 1 {
                let old_right = n.right;
                n.right = insert::<H>(Some(old_right), key, value, split + 1);
            } else {
                let old_left = n.left;
                n.left = insert::<H>(Some(old_left), key, value, split + 1);
            }
            let lh = branch_hash(&n.left);
            let rh = branch_hash(&n.right);
            n.hash = Some(H::hash_node(&lh, &rh, n.depth));
            Arc::new(Branch::Node(n))
        }
        Branch::Stub(_) => {
            panic!("insert: encountered Stub — materialize from disk first");
        }
    }
}

fn split_node<H: SmtHasher>(
    mut n: NodeBranch,
    key: SmtKey,
    value: Vec<u8>,
    start_bit: usize,
    first_div: usize,
) -> Arc<Branch> {
    let new_split = start_bit + first_div;
    let old_dir = n.path.bit_at(first_div);

    let old_n_path = n.path.path_len();
    let remaining = old_n_path - first_div - 1;
    n.path = CompressedPath::from_key_range_with_path_bits(&n.path, first_div + 1, remaining);
    n.hash = None;
    let lh = branch_hash(&n.left);
    let rh = branch_hash(&n.right);
    n.hash = Some(H::hash_node(&lh, &rh, n.depth));
    let old_node = Arc::new(Branch::Node(n));

    let new_leaf = make_leaf::<H>(key, value);
    let new_cp = CompressedPath::from_key_range(&key, start_bit, first_div);

    if old_dir == 1 {
        make_node::<H>(new_cp, new_leaf, old_node, new_split as u8)
    } else {
        make_node::<H>(new_cp, old_node, new_leaf, new_split as u8)
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn first_diverging_bit(a: &SmtKey, b: &SmtKey, start_bit: usize) -> usize {
    for pos in start_bit..KEY_BITS {
        if key_bit_at(a, pos) != key_bit_at(b, pos) {
            return pos;
        }
    }
    KEY_BITS
}

fn first_divergence_in_prefix(
    path: &CompressedPath,
    key: &SmtKey,
    start_bit: usize,
) -> usize {
    let n = path.path_len();
    for i in 0..n {
        if path.bit_at(i) != key_bit_at(key, start_bit + i) {
            return i;
        }
    }
    n
}

// ─── CompressedPath extension ───────────────────────────────────────────────

impl CompressedPath {
    pub fn from_key_range_with_path_bits(src: &CompressedPath, start: usize, n_bits: usize) -> Self {
        let mut cp = Self::empty();
        cp.len = n_bits as u8;
        for i in 0..n_bits {
            let b = src.bit_at(start + i);
            if b != 0 {
                cp.set_bit(i, 1);
            }
        }
        cp
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Blake2bHasher, Blake2sHasher, Sha256Hasher};

    fn make_key(byte: u8) -> SmtKey {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    fn run_tests<H: SmtHasher>() {
        // empty tree
        let tree = SparseMerkleTree::new();
        assert!(tree.root_hash().is_none());

        // single leaf
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<H>(make_key(1), vec![0xAB; 32]).unwrap();
        assert!(tree.root_hash().is_some());

        // two leaves
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<H>(make_key(1), vec![1u8; 32]).unwrap();
        tree.add_leaf_with::<H>(make_key(2), vec![2u8; 32]).unwrap();
        assert!(tree.root_hash().is_some());

        // duplicate rejected
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<H>(make_key(42), vec![0u8; 32]).unwrap();
        assert_eq!(tree.add_leaf_with::<H>(make_key(42), vec![1u8; 32]), Err(SmtError::DuplicateLeaf));

        // find leaf
        let mut tree = SparseMerkleTree::new();
        let k = make_key(7);
        tree.add_leaf_with::<H>(k, vec![7u8; 32]).unwrap();
        let found = tree.find_leaf(&k).unwrap();
        assert_eq!(found.key, k);

        // deep clone is independent
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<H>(make_key(1), vec![1u8; 32]).unwrap();
        let mut clone = tree.deep_clone();
        clone.add_leaf_with::<H>(make_key(2), vec![2u8; 32]).unwrap();
        assert!(tree.find_leaf(&make_key(2)).is_none());

        // deterministic root
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        t1.add_leaf_with::<H>(make_key(1), vec![1u8; 32]).unwrap();
        t1.add_leaf_with::<H>(make_key(2), vec![2u8; 32]).unwrap();
        t2.add_leaf_with::<H>(make_key(1), vec![1u8; 32]).unwrap();
        t2.add_leaf_with::<H>(make_key(2), vec![2u8; 32]).unwrap();
        assert_eq!(t1.root_hash(), t2.root_hash());

        // many leaves
        let mut tree = SparseMerkleTree::new();
        for i in 0u8..=255 {
            tree.add_leaf_with::<H>(make_key(i), vec![i; 32]).unwrap();
        }
        assert!(tree.root_hash().is_some());
        for i in 0u8..=255 {
            assert!(tree.find_leaf(&make_key(i)).is_some());
        }
    }

    #[test]
    fn sha256_tree() { run_tests::<Sha256Hasher>(); }

    #[test]
    fn blake2s_tree() { run_tests::<Blake2sHasher>(); }

    #[test]
    fn blake2b_tree() { run_tests::<Blake2bHasher>(); }



    #[test]
    fn default_add_leaf_uses_sha256() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let k = make_key(1);
        let v = vec![1u8; 32];
        t1.add_leaf(k, v.clone()).unwrap();
        t2.add_leaf_with::<Sha256Hasher>(k, v).unwrap();
        assert_eq!(t1.root_hash(), t2.root_hash());
    }


}
