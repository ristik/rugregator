//! SMT branch types: `LeafBranch`, `NodeBranch`, and the `Branch` enum.

use std::sync::Arc;
use crate::hash::{SmtHasher, Sha256Hasher};
use crate::path::{SmtKey, CompressedPath};

// ─── Branch enum ─────────────────────────────────────────────────────────────

/// A node in the sparse Merkle tree.
#[derive(Clone, Debug)]
pub enum Branch {
    Leaf(LeafBranch),
    Node(NodeBranch),
    /// Disk-backed: an on-disk subtree represented only by its hash.
    /// Must be materialized (loaded from disk) before any traversal.
    Stub([u8; 32]),
}

// ─── LeafBranch ──────────────────────────────────────────────────────────────

/// A leaf node holding a full 256-bit key and an opaque value.
#[derive(Clone, Debug)]
pub struct LeafBranch {
    /// Full 32-byte key.
    pub key: SmtKey,
    /// The leaf value (e.g. CertDataHash, 32 bytes).
    pub value: Vec<u8>,
    /// Hash, always computed at construction.
    pub hash: [u8; 32],
}

impl LeafBranch {
    /// Create a new leaf with eagerly computed SHA-256 hash (convenience constructor).
    #[inline]
    pub fn new(key: SmtKey, value: Vec<u8>) -> Self {
        let hash = Sha256Hasher::hash_leaf(&key, &value);
        Self { key, value, hash }
    }
}

// ─── NodeBranch ──────────────────────────────────────────────────────────────

/// An internal node with exactly two children.
///
/// Children are reference-counted (`Arc`) so that CoW snapshots can share
/// unchanged subtrees without deep-copying.
#[derive(Clone, Debug)]
pub struct NodeBranch {
    /// Compressed common-prefix bits (for navigation only, not hashed).
    pub path: CompressedPath,
    /// Left child (keys with bit `depth` = 0).
    pub left: Arc<Branch>,
    /// Right child (keys with bit `depth` = 1).
    pub right: Arc<Branch>,
    /// Absolute bit position where children diverge (0..255).
    /// Used in `hash_node(left, right, depth, region)`.
    pub depth: u8,
    /// Absolute key prefix `[0..depth)` shared by every descendant key,
    /// packed MSB-first into 32 bytes with bits `depth..256` cleared
    /// (RSMT v6a region commitment). Absolute like `depth`: splitting an
    /// edge above this node changes neither. Hashed — unlike `path`, which
    /// is a local, parent-relative navigation aid.
    pub region: [u8; 32],
    /// Cached hash.  None = needs recomputation.
    pub hash: Option<[u8; 32]>,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Read the pre-computed hash from a branch.
///
/// **Invariant**: all `Arc<Branch>` values must have their hash available.
/// Panics if a `Node` has `hash = None`.
#[inline]
pub fn branch_hash(b: &Branch) -> [u8; 32] {
    match b {
        Branch::Leaf(l) => l.hash,
        Branch::Node(n) => n.hash.expect("Arc<Branch::Node> must have pre-computed hash"),
        Branch::Stub(h) => *h,
    }
}

/// Create a new leaf wrapped in `Arc<Branch>` using the given hasher.
#[inline]
pub fn make_leaf<H: SmtHasher>(key: SmtKey, value: Vec<u8>) -> Arc<Branch> {
    let hash = H::hash_leaf(&key, &value);
    Arc::new(Branch::Leaf(LeafBranch { key, value, hash }))
}

/// Create a new internal node wrapped in `Arc<Branch>` with eagerly computed hash.
pub fn make_node<H: SmtHasher>(
    path: CompressedPath,
    left: Arc<Branch>,
    right: Arc<Branch>,
    depth: u8,
    region: [u8; 32],
) -> Arc<Branch> {
    let lh = branch_hash(&left);
    let rh = branch_hash(&right);
    let hash = H::hash_node(&lh, &rh, depth, &region);
    Arc::new(Branch::Node(NodeBranch {
        path,
        left,
        right,
        depth,
        region,
        hash: Some(hash),
    }))
}

/// SHA-256 convenience wrappers (preserve call sites that don't need to be generic).
pub fn make_leaf_sha256(key: SmtKey, value: Vec<u8>) -> Arc<Branch> {
    make_leaf::<Sha256Hasher>(key, value)
}
pub fn make_node_sha256(
    path: CompressedPath,
    left: Arc<Branch>,
    right: Arc<Branch>,
    depth: u8,
    region: [u8; 32],
) -> Arc<Branch> {
    make_node::<Sha256Hasher>(path, left, right, depth, region)
}
