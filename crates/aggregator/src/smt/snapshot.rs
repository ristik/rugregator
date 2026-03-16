//! Copy-on-write snapshot for the SMT.
//!
//! Phase 1: simple clone-based snapshot (O(n) per round but correct).
//! The snapshot is an independent deep copy of the tree.  On success it
//! replaces the main tree; on failure it is dropped.

use super::tree::SparseMerkleTree;
use super::path::SmtPath;

/// A speculative working copy of the SMT.
pub struct SmtSnapshot {
    inner: SparseMerkleTree,
}

impl SmtSnapshot {
    /// Create a snapshot from the current state of `tree`.
    pub fn create(tree: &SparseMerkleTree) -> Self {
        Self { inner: tree.deep_clone() }
    }

    /// Add a leaf to the snapshot.
    pub fn add_leaf(&mut self, path: SmtPath, value: Vec<u8>) -> Result<(), super::tree::SmtError> {
        self.inner.add_leaf(path, value)
    }

    /// Current root hash imprint (34 bytes).
    pub fn root_hash_imprint(&mut self) -> [u8; 34] {
        self.inner.root_hash_imprint()
    }

    /// Commit this snapshot to `target`, replacing its root.
    pub fn commit(self, target: &mut SparseMerkleTree) {
        *target = self.inner;
    }

    /// Discard the snapshot (drop without committing).
    pub fn discard(self) {
        // Nothing to do — ownership dropped here.
    }
}
