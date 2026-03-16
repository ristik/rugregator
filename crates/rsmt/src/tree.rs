//! Sparse Merkle Tree – insertion and root hash.
//!
//! This is a direct translation of `aggregator-go/internal/smt/smt.go`.
//! The tree is **not thread-safe**; callers must wrap it in a `RwLock`.

use num_bigint::BigUint;
use thiserror::Error;

use crate::hash::{build_imprint, hash_leaf, hash_node};
use crate::path::{bit_at, calculate_common_path, path_len, root_path, rsh, SmtPath};
use crate::types::{leaf, node, Branch, LeafBranch, NodeBranch};

/// Key length in bits for standalone (monolithic) mode.
/// StateID is 32 bytes padded to 34 bytes + 1 sentinel byte → 272 data bits.
pub const KEY_LENGTH: usize = 272;

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq)]
pub enum SmtError {
    /// Leaf at this path already exists (add-only tree; skip silently).
    #[error("smt: duplicate leaf")]
    DuplicateLeaf,
    #[error("smt: invalid key length (expected {expected}, got {got})")]
    KeyLength { expected: usize, got: usize },
    #[error("smt: key does not belong in this shard")]
    WrongShard,
    #[error("smt: cannot add leaf inside a branch (logic error)")]
    CannotAddInsideBranch,
    #[error("smt: cannot extend tree through a leaf")]
    CannotExtendThroughLeaf,
    #[error("smt: leaf not found")]
    LeafNotFound,
}

// ─── SparseMerkleTree ────────────────────────────────────────────────────────

/// A path-compressed Patricia trie compatible with the Go/TypeScript SMT.
///
/// The tree is **not** `Clone` by default because cloning is O(n) and should
/// be explicit.  Call `deep_clone()` to get a copy for snapshot purposes.
pub struct SparseMerkleTree {
    /// Bit-length of inserted keys (272 for standalone mode).
    pub key_length: usize,
    /// Root node.
    pub root: NodeBranch,
    /// `true` for the parent aggregator (allows overwriting leaves).
    pub parent_mode: bool,
}

impl SparseMerkleTree {
    /// Create a new monolithic aggregator tree (standalone mode, 272-bit keys).
    pub fn new() -> Self {
        Self::with_key_length(KEY_LENGTH)
    }

    /// Create a tree with a custom key length.
    pub fn with_key_length(key_length: usize) -> Self {
        Self {
            key_length,
            root: NodeBranch::new_root(root_path(), None, None),
            parent_mode: false,
        }
    }

    /// Deep-clone the entire tree.  Used for snapshot / rollback.
    pub fn deep_clone(&self) -> Self {
        Self {
            key_length: self.key_length,
            parent_mode: self.parent_mode,
            root: clone_node(&self.root),
        }
    }

    // ── Hash computation ──────────────────────────────────────────────────────

    /// Compute and return the root hash as a 34-byte imprint.
    pub fn root_hash_imprint(&mut self) -> [u8; 34] {
        let raw = calc_node_hash(&mut self.root);
        build_imprint(&raw)
    }

    /// Root hash as hex string.
    pub fn root_hash_hex(&mut self) -> String {
        hex::encode(self.root_hash_imprint())
    }

    // ── Leaf insertion ────────────────────────────────────────────────────────

    /// Add a single leaf.  Translates Go `AddLeaf`.
    pub fn add_leaf(&mut self, path: SmtPath, value: Vec<u8>) -> Result<(), SmtError> {
        // Validate key length: path.bits() - 1 == key_length
        let kl = path_len(&path);
        if kl != self.key_length {
            return Err(SmtError::KeyLength { expected: self.key_length, got: kl });
        }
        // Validate shard (root path must be a common prefix of the new key).
        let cp = calculate_common_path(&path, &self.root.path);
        if cp.bits() as usize != self.root.path.bits() as usize {
            return Err(SmtError::WrongShard);
        }

        // Pre-check: the tree is add-only.  If a leaf already exists at this
        // path, skip it regardless of value (matches ndsmt3.py batch_insert
        // semantics).  This also avoids tree corruption: the naive
        // take()+build_tree+? pattern would lose the child on error.
        match self.get_leaf(&path) {
            Ok(_existing) => return Err(SmtError::DuplicateLeaf),
            Err(SmtError::LeafNotFound) => {} // safe to insert
            Err(_) => {}                       // other errors: let insert proceed
        }

        // Shift path by root depth (root.path.bits()-1).
        let shift = self.root.path.bits() as usize - 1;
        let shifted = rsh(&path, shift);
        let is_right = bit_at(&shifted, 0) == 1;

        // Invalidate root hash cache (we're modifying the tree).
        self.root.hash_cache = None;

        if is_right {
            let right = self.root.right.take();
            self.root.right = Some(if let Some(existing) = right {
                build_tree(existing, shifted, value, path.clone(), self.parent_mode)?
            } else {
                leaf(shifted, value, path.clone())
            });
        } else {
            let left = self.root.left.take();
            self.root.left = Some(if let Some(existing) = left {
                build_tree(existing, shifted, value, path.clone(), self.parent_mode)?
            } else {
                leaf(shifted, value, path.clone())
            });
        }
        Ok(())
    }

    /// Add multiple leaves.  Duplicate leaves are silently skipped.
    pub fn add_leaves(&mut self, leaves: &[(SmtPath, Vec<u8>)]) -> Result<(), SmtError> {
        for (path, value) in leaves {
            match self.add_leaf(path.clone(), value.clone()) {
                Err(SmtError::DuplicateLeaf) => {} // skip silently
                r => r?,
            }
        }
        Ok(())
    }

    // ── Leaf lookup ───────────────────────────────────────────────────────────

    /// Find a leaf by its full (unshifted) path.
    pub fn get_leaf(&self, path: &SmtPath) -> Result<&LeafBranch, SmtError> {
        let shift = self.root.path.bits() as usize - 1;
        let shifted = rsh(path, shift);
        find_leaf_in_branch_ref(
            if bit_at(&shifted, 0) == 1 { &self.root.right } else { &self.root.left },
            &shifted,
        )
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ─── build_tree (Go buildTree) ────────────────────────────────────────────────

/// Recursive insertion into a subtree.  Translates Go `buildTree`.
fn build_tree(
    branch: Box<Branch>,
    remaining_path: SmtPath,
    value: Vec<u8>,
    original_path: SmtPath,
    parent_mode: bool,
) -> Result<Box<Branch>, SmtError> {
    // ── Leaf collision ────────────────────────────────────────────────────────
    if let Branch::Leaf(ref l) = *branch {
        if l.path == remaining_path {
            if l.is_child {
                // Parent-mode: overwrite child hash.
                return Ok(leaf(l.path.clone(), value, original_path));
            } else {
                // Add-only: leaf already exists at this path; skip regardless of value.
                return Err(SmtError::DuplicateLeaf);
            }
        }
    }

    let branch_path = branch.path().clone();
    let common_path = calculate_common_path(&remaining_path, &branch_path);

    // Cannot add a leaf whose path is a prefix of the branch's path.
    if common_path == remaining_path {
        return Err(SmtError::CannotAddInsideBranch);
    }

    let shift = common_path.bits() as usize - 1;
    let shifted = rsh(&remaining_path, shift);
    let is_right = bit_at(&shifted, 0) == 1;

    // ── Leaf split ────────────────────────────────────────────────────────────
    if let Branch::Leaf(ref l) = *branch {
        if common_path == l.path {
            return Err(SmtError::CannotExtendThroughLeaf);
        }
        let old_path = rsh(&l.path, shift);
        let new_path = rsh(&remaining_path, shift);
        let old_branch = leaf(old_path, l.value.clone(), l.original_path.clone());
        let new_branch = leaf(new_path, value, original_path);
        return Ok(if is_right {
            node(common_path, Some(old_branch), Some(new_branch))
        } else {
            node(common_path, Some(new_branch), Some(old_branch))
        });
    }

    // ── Node: split in the middle ─────────────────────────────────────────────
    if let Branch::Node(ref n) = *branch {
        if common_path.bits() < n.path.bits() {
            let new_leaf_path = rsh(&remaining_path, shift);
            let new_leaf_branch = leaf(new_leaf_path, value, original_path.clone());
            let old_node_path = rsh(&n.path, shift);
            let old_node = Box::new(Branch::Node(NodeBranch::new(
                old_node_path,
                n.left.clone(),
                n.right.clone(),
            )));
            return Ok(if is_right {
                node(common_path, Some(old_node), Some(new_leaf_branch))
            } else {
                node(common_path, Some(new_leaf_branch), Some(old_node))
            });
        }
    }

    // ── Recurse ───────────────────────────────────────────────────────────────
    let deeper = rsh(&remaining_path, shift);
    match *branch {
        Branch::Node(mut n) => {
            n.hash_cache = None; // invalidate cache
            if is_right {
                let right = n.right.take();
                n.right = Some(if let Some(child) = right {
                    build_tree(child, deeper, value, original_path, parent_mode)?
                } else {
                    leaf(deeper, value, original_path)
                });
            } else {
                let left = n.left.take();
                n.left = Some(if let Some(child) = left {
                    build_tree(child, deeper, value, original_path, parent_mode)?
                } else {
                    leaf(deeper, value, original_path)
                });
            }
            Ok(Box::new(Branch::Node(n)))
        }
        Branch::Leaf(_) => unreachable!("leaf handled above"),
    }
}

// ─── Hash computation (with caching) ─────────────────────────────────────────

/// Compute (and cache) the hash of a leaf.
pub fn calc_leaf_hash(l: &mut LeafBranch) -> [u8; 32] {
    if let Some(cached) = l.hash_cache {
        return cached;
    }
    let raw = if l.is_child {
        // Value IS the raw 32-byte hash (or nil → all-zeros treated as nil).
        if l.value.is_empty() {
            return [0u8; 32]; // nil child — propagate as null
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&l.value[..32]);
        arr
    } else {
        hash_leaf(&l.path, &l.value)
    };
    l.hash_cache = Some(raw);
    raw
}

/// Compute (and cache) the hash of a node.
/// Returns the raw 32-byte digest.
pub fn calc_node_hash(n: &mut NodeBranch) -> [u8; 32] {
    if let Some(cached) = n.hash_cache {
        return cached;
    }

    let left_hash = n.left.as_mut().map(|b| calc_branch_hash(b));
    let right_hash = n.right.as_mut().map(|b| calc_branch_hash(b));

    // In sharded child-tree roots (is_root && path.bits() > 1),
    // the path used in the hash is the last bit of the shard ID.
    // For monolithic mode (root path = 1, bits() = 1) we use the actual path.
    let hash_path: SmtPath = if n.is_root && n.path.bits() > 1 {
        let pos = n.path.bits() as usize - 2;
        let last_bit = bit_at(&n.path, pos);
        BigUint::from(2u8 + last_bit)
    } else {
        n.path.clone()
    };

    let raw = hash_node(
        &hash_path,
        left_hash.as_ref(),
        right_hash.as_ref(),
    );
    n.hash_cache = Some(raw);
    raw
}

/// Dispatch to leaf or node hash computation.
pub fn calc_branch_hash(b: &mut Branch) -> [u8; 32] {
    match b {
        Branch::Leaf(l) => calc_leaf_hash(l),
        Branch::Node(n) => calc_node_hash(n),
    }
}

// ─── Deep clone helpers ───────────────────────────────────────────────────────

fn clone_branch(b: &Branch) -> Box<Branch> {
    Box::new(match b {
        Branch::Leaf(l) => Branch::Leaf(l.clone()),
        Branch::Node(n) => Branch::Node(clone_node(n)),
    })
}

fn clone_node(n: &NodeBranch) -> NodeBranch {
    NodeBranch {
        path: n.path.clone(),
        left: n.left.as_deref().map(clone_branch),
        right: n.right.as_deref().map(clone_branch),
        is_root: n.is_root,
        hash_cache: n.hash_cache,
    }
}

// ─── Leaf lookup (immutable) ──────────────────────────────────────────────────

fn find_leaf_in_branch_ref<'a>(
    branch: &'a Option<Box<Branch>>,
    target: &SmtPath,
) -> Result<&'a LeafBranch, SmtError> {
    let b = branch.as_deref().ok_or(SmtError::LeafNotFound)?;
    match b {
        Branch::Leaf(l) => {
            if &l.path == target {
                Ok(l)
            } else {
                Err(SmtError::LeafNotFound)
            }
        }
        Branch::Node(n) => {
            let cp = calculate_common_path(target, &n.path);
            if cp == *target {
                return Err(SmtError::LeafNotFound);
            }
            let shift = cp.bits() as usize - 1;
            let shifted = rsh(target, shift);
            if bit_at(&shifted, 0) == 1 {
                find_leaf_in_branch_ref(&n.right, &shifted)
            } else {
                find_leaf_in_branch_ref(&n.left, &shifted)
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::*;
    use crate::path::state_id_to_smt_path;

    fn make_path(byte: u8) -> SmtPath {
        let mut id = [0u8; 32];
        id[31] = byte;
        state_id_to_smt_path(&id)
    }

    #[test]
    fn insert_single_leaf() {
        let mut tree = SparseMerkleTree::new();
        let path = make_path(1);
        tree.add_leaf(path, vec![0u8; 34]).unwrap();
        let root = tree.root_hash_imprint();
        assert_ne!(root, [0u8; 34]);
    }

    #[test]
    fn insert_two_leaves() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_path(1), vec![1u8; 34]).unwrap();
        tree.add_leaf(make_path(2), vec![2u8; 34]).unwrap();
        let root = tree.root_hash_imprint();
        assert_ne!(root, [0u8; 34]);
    }

    #[test]
    fn duplicate_leaf_skipped() {
        let mut tree = SparseMerkleTree::new();
        let path = make_path(42);
        tree.add_leaf(path.clone(), vec![0u8; 34]).unwrap();
        let r = tree.add_leaf(path, vec![0u8; 34]);
        assert_eq!(r, Err(SmtError::DuplicateLeaf));
    }

    #[test]
    fn existing_leaf_skipped_regardless_of_value() {
        // Add-only tree: inserting a different value at the same path is also a DuplicateLeaf.
        let mut tree = SparseMerkleTree::new();
        let path = make_path(7);
        tree.add_leaf(path.clone(), vec![1u8; 34]).unwrap();
        let r = tree.add_leaf(path, vec![2u8; 34]);
        assert_eq!(r, Err(SmtError::DuplicateLeaf));
        // Original value must be unchanged.
        let leaf = tree.get_leaf(&make_path(7)).unwrap();
        assert_eq!(leaf.value, vec![1u8; 34]);
    }

    #[test]
    fn wrong_key_length() {
        let mut tree = SparseMerkleTree::new();
        // Path with 273 bits instead of 273 (off by 1)
        // Use a 33-byte state_id to get a different bit-length.
        let bad_path = BigUint::from(1u8) << 100; // 101 bits
        let r = tree.add_leaf(bad_path, vec![0u8; 34]);
        assert!(matches!(r, Err(SmtError::KeyLength { .. })));
    }

    #[test]
    fn deep_clone_is_independent() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_path(1), vec![1u8; 34]).unwrap();
        let mut clone = tree.deep_clone();
        clone.add_leaf(make_path(2), vec![2u8; 34]).unwrap();
        // Original should still have only 1 leaf.
        assert!(tree.get_leaf(&make_path(2)).is_err());
    }

    #[test]
    fn root_hash_deterministic_for_same_insertions() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        t1.add_leaf(make_path(1), vec![1u8; 34]).unwrap();
        t1.add_leaf(make_path(2), vec![2u8; 34]).unwrap();
        t2.add_leaf(make_path(1), vec![1u8; 34]).unwrap();
        t2.add_leaf(make_path(2), vec![2u8; 34]).unwrap();
        assert_eq!(t1.root_hash_imprint(), t2.root_hash_imprint());
    }
}
