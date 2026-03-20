//! Common trait for SMT store implementations.
use rsmt::{SmtError, SmtPath, MerkleTreePath};

/// A Sparse Merkle Tree store supporting snapshot-based speculative execution.
pub trait SmtStore: Send + 'static {
    type Snapshot: SmtStoreSnapshot<Store = Self> + Send + 'static;

    /// Current committed root hash imprint (34 bytes: 0x0000 + 32-byte SHA256).
    fn root_hash_imprint(&self) -> [u8; 34];

    /// Create a speculative snapshot starting from the current committed state.
    fn create_snapshot(&self) -> Self::Snapshot;

    /// Generate an inclusion proof for `leaf_path` from the committed state.
    fn get_path(&mut self, leaf_path: &SmtPath) -> anyhow::Result<MerkleTreePath>;
}

/// A speculative snapshot of an [`SmtStore`].
pub trait SmtStoreSnapshot: Send + 'static {
    type Store: SmtStore<Snapshot = Self>;

    /// Stage a leaf insertion. Returns `Err(SmtError::DuplicateLeaf)` if the
    /// leaf already exists in this snapshot.
    fn add_leaf(&mut self, path: SmtPath, value: Vec<u8>) -> Result<(), SmtError>;

    /// Compute the tentative root hash of the snapshot.
    fn root_hash_imprint(&mut self) -> anyhow::Result<[u8; 34]>;

    /// Fork this snapshot for speculative next-round insertion.
    fn fork(&mut self) -> Self;

    /// Commit all staged mutations to the store.
    fn commit(self, store: &mut Self::Store) -> anyhow::Result<()>;

    /// Discard all staged mutations without committing.
    fn discard(self);

    /// Insert a batch of (path, value) pairs, optionally producing a CBOR-encoded
    /// consistency proof. Returns `(inserted_flags, proof_cbor)` where
    /// `inserted_flags[i]` is true iff `batch[i]` was actually inserted
    /// (false = duplicate). `proof_cbor` is `Some` only when `with_proof = true`
    /// AND this implementation supports single-pass proof generation.
    ///
    /// Default: inserts each item via `add_leaf`, returns no proof.
    fn insert_batch(
        &mut self,
        batch: &[(SmtPath, Vec<u8>)],
        _with_proof: bool,
    ) -> anyhow::Result<(Vec<bool>, Option<Vec<u8>>)> {
        let mut flags = vec![false; batch.len()];
        for (i, (path, value)) in batch.iter().enumerate() {
            match self.add_leaf(path.clone(), value.clone()) {
                Ok(()) => flags[i] = true,
                Err(SmtError::DuplicateLeaf) => {}
                Err(e) => return Err(anyhow::anyhow!("add_leaf failed: {e}")),
            }
        }
        Ok((flags, None))
    }
}
