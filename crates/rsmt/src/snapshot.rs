//! Copy-on-write snapshot for the SMT.
//!
//! Phase 1: simple clone-based snapshot (O(n) per round but correct).
//! The snapshot is an independent deep copy of the tree.  On success it
//! replaces the main tree; on failure it is dropped.

use crate::tree::SparseMerkleTree;
use crate::path::SmtPath;

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

    /// Insert a batch and generate a consistency proof.
    ///
    /// Returns `(inserted_items, proof)` where `inserted_items` contains only
    /// the actually-inserted (path, value) pairs (duplicates excluded).
    pub fn batch_insert_with_proof(
        &mut self,
        batch: &[(SmtPath, Vec<u8>)],
    ) -> Result<(Vec<(SmtPath, Vec<u8>)>, super::consistency::ConsistencyProof), super::tree::SmtError> {
        super::consistency::batch_insert_with_proof(&mut self.inner, batch)
    }

    /// Current root hash imprint (34 bytes).
    pub fn root_hash_imprint(&mut self) -> [u8; 34] {
        self.inner.root_hash_imprint()
    }

    /// Commit this snapshot to `target`, replacing its root.
    pub fn commit(self, target: &mut SparseMerkleTree) {
        *target = self.inner;
    }

    /// Fork this snapshot into an independent copy for the next speculative block.
    ///
    /// The fork starts from the same state as `self`.  Both `self` and the fork
    /// can then diverge independently; only one is ultimately committed.
    pub fn fork(&self) -> Self {
        Self { inner: self.inner.deep_clone() }
    }

    /// Discard the snapshot (drop without committing).
    pub fn discard(self) {
        // Nothing to do — ownership dropped here.
    }
}
