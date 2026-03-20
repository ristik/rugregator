//! SMT branch types: `LeafBranch`, `NodeBranch`, and the `Branch` enum.

use std::sync::Arc;
use num_bigint::BigUint;
use crate::path::SmtPath;
use crate::hash::{hash_leaf, hash_node};

// ─── Branch enum ─────────────────────────────────────────────────────────────

/// A node in the sparse Merkle tree — either a leaf or an internal node.
#[derive(Clone, Debug)]
pub enum Branch {
    Leaf(LeafBranch),
    Node(NodeBranch),
    /// Disk-backed: an on-disk subtree represented only by its hash.
    /// Must be materialized (loaded from disk) before any traversal.
    #[cfg(feature = "disk-backed")]
    Stub([u8; 32]),
}

impl Branch {
    pub fn is_leaf(&self) -> bool {
        matches!(self, Branch::Leaf(_))
    }

    pub fn path(&self) -> &SmtPath {
        match self {
            Branch::Leaf(l) => &l.path,
            Branch::Node(n) => &n.path,
            #[cfg(feature = "disk-backed")]
            Branch::Stub(_) => panic!("Branch::Stub::path() — must not navigate into a Stub; materialize first"),
        }
    }
}

// ─── LeafBranch ──────────────────────────────────────────────────────────────

/// A leaf node holding a key path and an opaque value (usually a 34-byte imprint).
#[derive(Clone, Debug)]
pub struct LeafBranch {
    /// Relative path with sentinel bit (shrinks as we descend).
    pub path: SmtPath,
    /// The leaf value (e.g. `CertDataHash` imprint, 34 bytes).
    pub value: Vec<u8>,
    /// `true` for parent-tree child-root leaves (value IS the raw 32-byte hash).
    pub is_child: bool,
    /// Cached raw SHA-256 digest (32 bytes).  None = not yet computed.
    pub hash_cache: Option<[u8; 32]>,
    /// Full original key (before path compression).  Used for consistency proofs.
    pub original_path: SmtPath,
}

impl LeafBranch {
    pub fn new(path: SmtPath, value: Vec<u8>) -> Self {
        let hash = hash_leaf(&path, &value);
        Self { original_path: path.clone(), path, value, is_child: false, hash_cache: Some(hash) }
    }

    pub fn new_keyed(path: SmtPath, value: Vec<u8>, original_path: SmtPath) -> Self {
        let hash = hash_leaf(&path, &value);
        Self { path, value, original_path, is_child: false, hash_cache: Some(hash) }
    }

    pub fn new_child(path: SmtPath, value: Option<Vec<u8>>) -> Self {
        let v = value.unwrap_or_default();
        let hash = if v.is_empty() {
            [0u8; 32]
        } else {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v[..32]);
            arr
        };
        Self {
            original_path: path.clone(),
            path,
            value: v,
            is_child: true,
            hash_cache: Some(hash),
        }
    }
}

// ─── NodeBranch ──────────────────────────────────────────────────────────────

/// An internal node with up to two children.
///
/// Children are reference-counted (`Arc`) so that CoW snapshots can share
/// unchanged subtrees without deep-copying.  Every `Arc<Branch>` child must
/// have its `hash_cache` pre-computed (the invariant is enforced by the
/// `leaf()` and `node()` smart constructors).
#[derive(Clone, Debug)]
pub struct NodeBranch {
    /// Relative common-prefix path with sentinel bit.
    pub path: SmtPath,
    pub left: Option<Arc<Branch>>,
    pub right: Option<Arc<Branch>>,
    /// `true` for the root node (affects hash path in sharded mode).
    pub is_root: bool,
    /// Cached raw SHA-256 digest.  None = not yet computed.
    pub hash_cache: Option<[u8; 32]>,
}

impl NodeBranch {
    pub fn new(path: SmtPath, left: Option<Arc<Branch>>, right: Option<Arc<Branch>>) -> Self {
        Self { path, left, right, is_root: false, hash_cache: None }
    }

    pub fn new_root(path: SmtPath, left: Option<Arc<Branch>>, right: Option<Arc<Branch>>) -> Self {
        Self { path, left, right, is_root: true, hash_cache: None }
    }
}

// ─── Helpers for building Arc-wrapped branches ───────────────────────────────

/// Create a new leaf `Arc<Branch>` with eagerly computed hash.
pub fn leaf(path: SmtPath, value: Vec<u8>, original_path: SmtPath) -> Arc<Branch> {
    Arc::new(Branch::Leaf(LeafBranch::new_keyed(path, value, original_path)))
}

/// Create a new non-root internal node `Arc<Branch>` with eagerly computed hash.
///
/// Both children must already have their `hash_cache` populated (invariant).
pub fn node(path: SmtPath, left: Option<Arc<Branch>>, right: Option<Arc<Branch>>) -> Arc<Branch> {
    let lh = left.as_ref().map(|a| branch_hash_cached(a));
    let rh = right.as_ref().map(|a| branch_hash_cached(a));
    let hash = hash_node(&path, lh.as_ref(), rh.as_ref());
    let n = NodeBranch { path, left, right, is_root: false, hash_cache: Some(hash) };
    Arc::new(Branch::Node(n))
}

pub fn root_node(
    path: SmtPath,
    left: Option<Arc<Branch>>,
    right: Option<Arc<Branch>>,
) -> NodeBranch {
    NodeBranch::new_root(path, left, right)
}

/// Read the pre-computed hash from a branch.
///
/// **Invariant**: all `Arc<Branch>` values have `hash_cache = Some(_)` (or for
/// `Stub`, the hash is the Stub value itself).  Panics if violated.
pub fn branch_hash_cached(b: &Branch) -> [u8; 32] {
    match b {
        Branch::Leaf(l) => l.hash_cache.expect("Arc<Branch::Leaf> must have pre-computed hash"),
        Branch::Node(n) => n.hash_cache.expect("Arc<Branch::Node> must have pre-computed hash"),
        #[cfg(feature = "disk-backed")]
        Branch::Stub(h) => *h,
    }
}

/// Helper: get the BigUint path of a branch.
pub fn branch_path(b: &Branch) -> &BigUint {
    b.path()
}
