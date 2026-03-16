//! SMT branch types: `LeafBranch`, `NodeBranch`, and the `Branch` enum.

use num_bigint::BigUint;
use super::path::SmtPath;

// ─── Branch enum ─────────────────────────────────────────────────────────────

/// A node in the sparse Merkle tree — either a leaf or an internal node.
#[derive(Clone, Debug)]
pub enum Branch {
    Leaf(LeafBranch),
    Node(NodeBranch),
}

impl Branch {
    pub fn is_leaf(&self) -> bool {
        matches!(self, Branch::Leaf(_))
    }

    pub fn path(&self) -> &SmtPath {
        match self {
            Branch::Leaf(l) => &l.path,
            Branch::Node(n) => &n.path,
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
}

impl LeafBranch {
    pub fn new(path: SmtPath, value: Vec<u8>) -> Self {
        Self { path, value, is_child: false, hash_cache: None }
    }

    pub fn new_child(path: SmtPath, value: Option<Vec<u8>>) -> Self {
        Self {
            path,
            value: value.unwrap_or_default(),
            is_child: true,
            hash_cache: None,
        }
    }
}

// ─── NodeBranch ──────────────────────────────────────────────────────────────

/// An internal node with up to two children.
#[derive(Clone, Debug)]
pub struct NodeBranch {
    /// Relative common-prefix path with sentinel bit.
    pub path: SmtPath,
    pub left: Option<Box<Branch>>,
    pub right: Option<Box<Branch>>,
    /// `true` for the root node (affects hash path in sharded mode).
    pub is_root: bool,
    /// Cached raw SHA-256 digest.  None = not yet computed.
    pub hash_cache: Option<[u8; 32]>,
}

impl NodeBranch {
    pub fn new(path: SmtPath, left: Option<Box<Branch>>, right: Option<Box<Branch>>) -> Self {
        Self { path, left, right, is_root: false, hash_cache: None }
    }

    pub fn new_root(path: SmtPath, left: Option<Box<Branch>>, right: Option<Box<Branch>>) -> Self {
        Self { path, left, right, is_root: true, hash_cache: None }
    }
}

// ─── Helpers for building boxed branches ─────────────────────────────────────

pub fn leaf(path: SmtPath, value: Vec<u8>) -> Box<Branch> {
    Box::new(Branch::Leaf(LeafBranch::new(path, value)))
}

pub fn node(path: SmtPath, left: Option<Box<Branch>>, right: Option<Box<Branch>>) -> Box<Branch> {
    Box::new(Branch::Node(NodeBranch::new(path, left, right)))
}

pub fn root_node(
    path: SmtPath,
    left: Option<Box<Branch>>,
    right: Option<Box<Branch>>,
) -> NodeBranch {
    NodeBranch::new_root(path, left, right)
}

/// Helper: get the BigUint path of a boxed branch.
pub fn branch_path(b: &Branch) -> &BigUint {
    b.path()
}
