//! Common trait for SMT store implementations.
use rsmt::{SmtError, SmtKey, InclusionProof};

/// A Sparse Merkle Tree store supporting snapshot-based speculative execution.
pub trait SmtStore: Send + 'static {
    type Snapshot: SmtStoreSnapshot<Store = Self> + Send + 'static;

    /// Current committed root hash (None = empty tree).
    fn root_hash(&self) -> Option<[u8; 32]>;

    /// Create a speculative snapshot starting from the current committed state.
    fn create_snapshot(&self) -> Self::Snapshot;

    /// Generate an inclusion proof for `key` from the committed state.
    fn get_inclusion_proof(&mut self, key: &SmtKey) -> anyhow::Result<InclusionProof>;

    /// Generate inclusion proofs for multiple keys in a single materialization.
    fn get_inclusion_proofs_batch(&mut self, keys: &[SmtKey]) -> anyhow::Result<Vec<InclusionProof>> {
        keys.iter()
            .map(|k| self.get_inclusion_proof(k))
            .collect()
    }

    /// Persist internal state for graceful shutdown.
    fn shutdown_persist(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// A speculative snapshot of an [`SmtStore`].
pub trait SmtStoreSnapshot: Send + 'static {
    type Store: SmtStore<Snapshot = Self>;

    /// Stage a leaf insertion.
    fn add_leaf(&mut self, key: SmtKey, value: Vec<u8>) -> Result<(), SmtError>;

    /// Compute the tentative root hash of the snapshot.
    fn root_hash(&mut self) -> anyhow::Result<Option<[u8; 32]>>;

    /// Fork this snapshot for speculative next-round insertion.
    fn fork(&mut self) -> Self;

    /// Commit all staged mutations to the store.
    fn commit(self, store: &mut Self::Store) -> anyhow::Result<()>;

    /// Discard all staged mutations without committing.
    fn discard(self);

    /// Insert a batch of (key, value) pairs, optionally producing a CBOR-encoded
    /// consistency proof. Returns `(inserted_flags, proof_cbor)` where
    /// `inserted_flags[i]` is true iff `batch[i]` was actually inserted
    /// (false = duplicate). `proof_cbor` is `Some` only when `with_proof = true`.
    fn insert_batch(
        &mut self,
        batch: &[(SmtKey, Vec<u8>)],
        _with_proof: bool,
    ) -> anyhow::Result<(Vec<bool>, Option<Vec<u8>>)> {
        let mut flags = vec![false; batch.len()];
        for (i, (key, value)) in batch.iter().enumerate() {
            match self.add_leaf(*key, value.clone()) {
                Ok(()) => flags[i] = true,
                Err(SmtError::DuplicateLeaf) => {}
                Err(e) => return Err(anyhow::anyhow!("add_leaf failed: {e}")),
            }
        }
        Ok((flags, None))
    }
}
