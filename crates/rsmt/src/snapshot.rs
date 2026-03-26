//! Copy-on-write snapshot for the SMT.
//!
//! The snapshot is an O(1) Arc-clone of the tree root.  On success it
//! replaces the main tree; on failure it is dropped.

use crate::consistency::ConsistencyProof;
use crate::path::SmtKey;
use crate::tree::{SmtError, SparseMerkleTree};

/// A speculative working copy of the SMT.
pub struct SmtSnapshot {
    inner: SparseMerkleTree,
}

impl SmtSnapshot {
    /// Create a snapshot from the current state of `tree`.
    pub fn create(tree: &SparseMerkleTree) -> Self {
        Self {
            inner: tree.deep_clone(),
        }
    }

    /// Add a single leaf to the snapshot.
    pub fn add_leaf(&mut self, key: SmtKey, value: Vec<u8>) -> Result<(), SmtError> {
        self.inner.add_leaf(key, value)
    }

    /// Insert a batch without generating a proof (fast path).
    ///
    /// Returns only the actually-inserted `(key, value)` pairs.
    pub fn batch_insert(
        &mut self,
        batch: &[(SmtKey, Vec<u8>)],
    ) -> Result<Vec<(SmtKey, Vec<u8>)>, SmtError> {
        crate::consistency::batch_insert(&mut self.inner, batch)
    }

    /// Insert a batch and generate a consistency proof.
    ///
    /// Returns `(inserted_items, proof)`.
    pub fn batch_insert_with_proof(
        &mut self,
        batch: &[(SmtKey, Vec<u8>)],
    ) -> Result<(Vec<(SmtKey, Vec<u8>)>, ConsistencyProof), SmtError> {
        crate::consistency::batch_insert_with_proof(&mut self.inner, batch)
    }

    /// Current root hash (`None` for empty tree).
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.inner.root_hash()
    }

    /// Commit this snapshot to `target`, replacing its root.
    pub fn commit(self, target: &mut SparseMerkleTree) {
        *target = self.inner;
    }

    /// Fork this snapshot into an independent copy.
    pub fn fork(&self) -> Self {
        Self {
            inner: self.inner.deep_clone(),
        }
    }

    /// Discard the snapshot (drop without committing).
    pub fn discard(self) {
        // Ownership dropped here.
    }

    /// Access the inner tree (for proof generation, etc.).
    pub fn tree(&self) -> &SparseMerkleTree {
        &self.inner
    }
}
