//! Common trait for SMT store implementations.
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::Duration;

use rsmt::{InclusionProof, NonInclusionProofOutcome, SmtError, SmtHasher, SmtKey};

/// Maximum number of admitted proof lookups per certified snapshot.
///
/// The HTTP layer uses the same value as its in-flight admission limit, so an
/// adversary cannot build an unbounded queue in front of a proof worker.
pub const CERTIFIED_PROOF_MAX_IN_FLIGHT: usize = 16;
const CERTIFIED_SNAPSHOT_PIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Handle to an immutable SMT view pinned at a certified root.
///
/// The backend owns the actual view in a dedicated worker. For RocksDB this is
/// a database snapshot; for the in-memory backend it is an O(1) CoW tree clone.
/// Dropping all handles stops the worker after already-admitted lookups finish.
#[derive(Clone)]
pub struct CertifiedSmtSnapshot {
    root_hash: Option<[u8; 32]>,
    request_tx: SyncSender<ProofRequest>,
}

impl CertifiedSmtSnapshot {
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.root_hash
    }

    /// Generate a non-inclusion proof from this immutable view.
    ///
    /// This method blocks the calling thread; asynchronous callers should run
    /// it on a blocking executor after applying an admission limit.
    pub fn get_non_inclusion_proof(&self, key: SmtKey) -> anyhow::Result<NonInclusionProofOutcome> {
        let (respond_to, response) = mpsc::sync_channel(1);
        match self.request_tx.try_send(ProofRequest { key, respond_to }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(anyhow::anyhow!("certified SMT proof worker queue is full"))
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(anyhow::anyhow!("certified SMT proof worker stopped"))
            }
        }
        response
            .recv()
            .map_err(|_| anyhow::anyhow!("certified SMT proof worker dropped the response"))?
    }

    pub(crate) fn spawn_worker<F>(
        root_hash: Option<[u8; 32]>,
        thread_name: &str,
        worker: F,
    ) -> anyhow::Result<Self>
    where
        F: FnOnce(Receiver<ProofRequest>, SyncSender<Result<(), String>>) + Send + 'static,
    {
        let (request_tx, request_rx) = mpsc::sync_channel(CERTIFIED_PROOF_MAX_IN_FLIGHT);
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);
        std::thread::Builder::new()
            .name(thread_name.to_owned())
            .spawn(move || worker(request_rx, ready_tx))?;

        match ready_rx.recv_timeout(CERTIFIED_SNAPSHOT_PIN_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                root_hash,
                request_tx,
            }),
            Ok(Err(error)) => Err(anyhow::anyhow!(error)),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!(
                "certified SMT proof worker stopped during initialization"
            )),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!(
                "timed out pinning certified SMT proof snapshot"
            )),
        }
    }
}

pub(crate) struct ProofRequest {
    pub key: SmtKey,
    pub respond_to: SyncSender<anyhow::Result<NonInclusionProofOutcome>>,
}

/// A Sparse Merkle Tree store supporting snapshot-based speculative execution.
pub trait SmtStore: Send + 'static {
    type Snapshot: SmtStoreSnapshot<Store = Self> + Send + 'static;

    /// Current committed root hash (None = empty tree).
    fn root_hash(&self) -> Option<[u8; 32]>;

    /// Create a speculative snapshot starting from the current committed state.
    fn create_snapshot(&self) -> Self::Snapshot;

    /// Pin an immutable view of the current committed state for proof serving.
    ///
    /// The returned handle MUST continue to read the root visible at this call
    /// even after subsequent commits mutate the live store.
    fn create_certified_snapshot(&self) -> anyhow::Result<CertifiedSmtSnapshot>;

    /// Generate an inclusion proof for `key` from the committed state.
    fn get_inclusion_proof(&mut self, key: &SmtKey) -> anyhow::Result<InclusionProof>;

    /// Generate a non-inclusion proof from the committed state.
    ///
    /// Presence is returned as [`NonInclusionProofOutcome::StateIncluded`],
    /// distinct from storage failures and from an absence proof.
    fn get_non_inclusion_proof(&mut self, key: &SmtKey)
        -> anyhow::Result<NonInclusionProofOutcome>;

    /// Generate inclusion proofs for multiple keys in a single materialization.
    fn get_inclusion_proofs_batch(
        &mut self,
        keys: &[SmtKey],
    ) -> anyhow::Result<Vec<InclusionProof>> {
        keys.iter().map(|k| self.get_inclusion_proof(k)).collect()
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

    /// Like [`insert_batch`] but with a configurable hasher.
    ///
    /// The default delegates to [`insert_batch`] (SHA-256). Implementations
    /// that support configurable hashing override this to propagate `H`.
    fn insert_batch_with<H: SmtHasher>(
        &mut self,
        batch: &[(SmtKey, Vec<u8>)],
        with_proof: bool,
    ) -> anyhow::Result<(Vec<bool>, Option<Vec<u8>>)> {
        self.insert_batch(batch, with_proof)
    }
}
