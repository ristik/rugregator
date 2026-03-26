//! Sparse Merkle Tree — insertion and root hash.

use std::sync::Arc;
use thiserror::Error;

use crate::hash::hash_node;
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

    /// Add a single leaf.  Returns `Err(DuplicateLeaf)` if the key exists.
    pub fn add_leaf(&mut self, key: SmtKey, value: Vec<u8>) -> Result<(), SmtError> {
        if self.find_leaf(&key).is_some() {
            return Err(SmtError::DuplicateLeaf);
        }
        self.root = Some(insert(self.root.take(), key, value, 0));
        Ok(())
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

/// Insert a new leaf into a subtree rooted at `node_opt`, with keys
/// addressed starting at `start_bit`.
fn insert(
    node_opt: Option<Arc<Branch>>,
    key: SmtKey,
    value: Vec<u8>,
    start_bit: usize,
) -> Arc<Branch> {
    let Some(arc) = node_opt else {
        return make_leaf(key, value);
    };

    // CoW: take ownership if sole Arc owner, else clone.
    let b = match Arc::try_unwrap(arc) {
        Ok(b) => b,
        Err(a) => (*a).clone(),
    };

    match b {
        Branch::Leaf(existing) => {
            // Find first diverging bit between existing key and new key.
            let div = first_diverging_bit(&existing.key, &key, start_bit);
            let cp = CompressedPath::from_key_range(&key, start_bit, div - start_bit);
            let old_leaf = Arc::new(Branch::Leaf(existing));
            let new_leaf = make_leaf(key, value);
            if key_bit_at(&key, div) == 1 {
                make_node(cp, old_leaf, new_leaf, div as u8)
            } else {
                make_node(cp, new_leaf, old_leaf, div as u8)
            }
        }
        Branch::Node(mut n) => {
            let n_path = n.path.path_len();

            // Check whether the new key diverges within this node's common prefix.
            let first_div = first_divergence_in_prefix(&n.path, &key, start_bit);

            if first_div < n_path {
                // Key diverges within the prefix — split this node.
                return split_node(n, key, value, start_bit, first_div);
            }

            // Key matches the full prefix — descend into left or right child.
            let split = start_bit + n_path;
            n.hash = None; // will be recomputed
            if key_bit_at(&key, split) == 1 {
                let old_right = n.right;
                n.right = insert(Some(old_right), key, value, split + 1);
            } else {
                let old_left = n.left;
                n.left = insert(Some(old_left), key, value, split + 1);
            }
            // Recompute hash.
            let lh = branch_hash(&n.left);
            let rh = branch_hash(&n.right);
            n.hash = Some(hash_node(&lh, &rh, n.depth));
            Arc::new(Branch::Node(n))
        }
        Branch::Stub(_) => {
            panic!("insert: encountered Stub — materialize from disk first");
        }
    }
}

/// Split a node when the new key diverges within its common prefix.
fn split_node(
    mut n: NodeBranch,
    key: SmtKey,
    value: Vec<u8>,
    start_bit: usize,
    first_div: usize,
) -> Arc<Branch> {
    let new_split = start_bit + first_div;
    let old_dir = n.path.bit_at(first_div); // which side the old node goes

    // Shorten the old node's path: drop the first `first_div + 1` bits.
    let old_n_path = n.path.path_len();
    let remaining = old_n_path - first_div - 1;
    n.path = CompressedPath::from_key_range_with_path_bits(&n.path, first_div + 1, remaining);
    n.hash = None;
    let lh = branch_hash(&n.left);
    let rh = branch_hash(&n.right);
    n.hash = Some(hash_node(&lh, &rh, n.depth));
    let old_node = Arc::new(Branch::Node(n));

    let new_leaf = make_leaf(key, value);
    let new_cp = CompressedPath::from_key_range(&key, start_bit, first_div);

    if old_dir == 1 {
        // Old node goes right, new leaf goes left.
        make_node(new_cp, new_leaf, old_node, new_split as u8)
    } else {
        // Old node goes left, new leaf goes right.
        make_node(new_cp, old_node, new_leaf, new_split as u8)
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Find the first bit position >= `start_bit` where two keys differ.
fn first_diverging_bit(a: &SmtKey, b: &SmtKey, start_bit: usize) -> usize {
    for pos in start_bit..KEY_BITS {
        if key_bit_at(a, pos) != key_bit_at(b, pos) {
            return pos;
        }
    }
    KEY_BITS // should never happen for distinct keys
}

/// Check how many bits of a `CompressedPath` match the key starting at
/// `start_bit`.  Returns the number of matching bits (0..=path.path_len()).
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
    n // full match
}

// ─── CompressedPath extension ───────────────────────────────────────────────

impl CompressedPath {
    /// Extract a range of bits from another CompressedPath (for node splitting).
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

    fn make_key(byte: u8) -> SmtKey {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    #[test]
    fn empty_tree() {
        let tree = SparseMerkleTree::new();
        assert!(tree.root_hash().is_none());
    }

    #[test]
    fn insert_single_leaf() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(1), vec![0xAB; 32]).unwrap();
        assert!(tree.root_hash().is_some());
    }

    #[test]
    fn insert_two_leaves() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(1), vec![1u8; 32]).unwrap();
        tree.add_leaf(make_key(2), vec![2u8; 32]).unwrap();
        assert!(tree.root_hash().is_some());
    }

    #[test]
    fn duplicate_leaf_rejected() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(42), vec![0u8; 32]).unwrap();
        assert_eq!(tree.add_leaf(make_key(42), vec![1u8; 32]), Err(SmtError::DuplicateLeaf));
    }

    #[test]
    fn find_leaf_works() {
        let mut tree = SparseMerkleTree::new();
        let k = make_key(7);
        tree.add_leaf(k, vec![7u8; 32]).unwrap();
        let found = tree.find_leaf(&k).unwrap();
        assert_eq!(found.key, k);
        assert_eq!(found.value, vec![7u8; 32]);
    }

    #[test]
    fn find_leaf_missing() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(1), vec![1u8; 32]).unwrap();
        assert!(tree.find_leaf(&make_key(2)).is_none());
    }

    #[test]
    fn deep_clone_is_independent() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(1), vec![1u8; 32]).unwrap();
        let mut clone = tree.deep_clone();
        clone.add_leaf(make_key(2), vec![2u8; 32]).unwrap();
        assert!(tree.find_leaf(&make_key(2)).is_none());
    }

    #[test]
    fn root_hash_deterministic() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        t1.add_leaf(make_key(1), vec![1u8; 32]).unwrap();
        t1.add_leaf(make_key(2), vec![2u8; 32]).unwrap();
        t2.add_leaf(make_key(1), vec![1u8; 32]).unwrap();
        t2.add_leaf(make_key(2), vec![2u8; 32]).unwrap();
        assert_eq!(t1.root_hash(), t2.root_hash());
    }

    #[test]
    fn insert_many_leaves() {
        let mut tree = SparseMerkleTree::new();
        for i in 0u8..=255 {
            tree.add_leaf(make_key(i), vec![i; 32]).unwrap();
        }
        assert!(tree.root_hash().is_some());
        for i in 0u8..=255 {
            assert!(tree.find_leaf(&make_key(i)).is_some());
        }
    }
}
