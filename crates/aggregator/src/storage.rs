//! In-memory state store for the aggregator.
//!
//! `AggregatorState` is the central shared object:
//!   - Tracks the current block number.
//!   - Stores finalized record info (StateID → block + cert data).
//!   - Stores finalized block info (block number → root hash + UC CBOR).
//!   - Exposes a channel for submitting validated requests to the round manager.
//!   - Merkle inclusion proofs are pre-computed at finalization time.
//!   - Publishes an immutable certified SMT snapshot to a bounded proof service.

use dashmap::{mapref::entry::Entry, DashMap};
use smt_store::{CertifiedSmtSnapshot, CERTIFIED_PROOF_MAX_IN_FLIGHT};
use std::sync::atomic::{AtomicU64, Ordering};

/// Default request lifetime in seconds when the deployment sets none.
pub const DEFAULT_REQUEST_TTL_SECS: u64 = 3600;
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::debug;

use crate::api::cbor::CertDataFields;
use crate::smt::AGGREGATION_TREE_VALUE_SIZE;
use crate::validation::ValidatedRequest;

// ─── Store trait ──────────────────────────────────────────────────────────────

/// Persistence backend for finalized rounds.
pub trait Store: Send + Sync {
    fn persist_round(
        &self,
        block: &BlockInfo,
        records: &[FinalizedRecord],
        next_block_number: u64,
    ) -> anyhow::Result<()>;
}

// ─── WAL types ────────────────────────────────────────────────────────────────

/// One record within a pending-round WAL entry.
pub struct WalRecord {
    pub state_id: Vec<u8>,
    pub predicate_cbor: Vec<u8>,
    pub source_state_hash: Vec<u8>,
    pub transaction_hash: Vec<u8>,
    /// Exclusive certification request deadline in Unix seconds, or
    /// `None` when the service assigned one.
    pub expires_at: Option<u64>,
    /// Absolute deadline the request is held to, so recovery re-applies the
    /// same admission decision the original round made.
    pub effective_timeout: u64,
    pub witness: Vec<u8>,
}

/// WAL entry written to disk before a block is submitted to BFT Core.
///
/// Guarantees that after a crash the aggregator can reconstruct the batch
/// that was certified and apply it to the SMT on recovery.
pub struct PendingRound {
    pub block_number: u64,
    /// Reference time the round's leaf values were built from. Recovery must
    /// rebuild the same leaves, so it is written with the round rather than
    /// re-read from a certificate that has since moved on.
    pub reference_time: u64,
    pub prev_root: Option<[u8; 32]>,
    pub new_root: Option<[u8; 32]>,
    /// Consistency proof bytes sent to BFT Core (stored so recovery can re-submit
    /// the exact same proof rather than re-computing it from a potentially
    /// already-committed SMT state).
    pub zk_proof: Option<Vec<u8>>,
    pub new_leaves: u64,
    pub state_size: u64,
    /// Records that were actually inserted (not duplicates/dropped).
    pub inserted: Vec<WalRecord>,
}

/// Write-ahead log interface for in-flight rounds.
///
/// `write_pending_round` must be called (and succeed) before every BFT
/// submission.  The entry is cleared atomically inside `persist_round` — so
/// it exists if-and-only-if the round has not yet been durably committed.
pub trait WalStore: Send + Sync {
    fn write_pending_round(&self, round: &PendingRound) -> anyhow::Result<()>;
    fn load_pending_round(&self) -> anyhow::Result<Option<PendingRound>>;
    fn clear_pending_round(&self) -> anyhow::Result<()>;
}

// ─── RecoveredState ───────────────────────────────────────────────────────────

pub struct RecoveredState {
    pub block_number: u64,
    pub records: Vec<(String, RecordInfo)>, // (state_id_hex, RecordInfo)
    pub blocks: Vec<BlockInfo>,
}

// ─── Record info ─────────────────────────────────────────────────────────────

/// Data stored for each finalized StateID.
#[derive(Debug, Clone)]
pub struct RecordInfo {
    pub block_number: u64,
    /// Reference time of the round this record's leaf was created in; a
    /// verifier needs it to reproduce the certified leaf value.
    pub reference_time: u64,
    pub cert_data: CertDataFields,
    /// Pre-computed CBOR-encoded Merkle path.
    ///
    /// Always `Some` for finalized records (generated at finalization time).
    pub merkle_path_cbor: Option<Vec<u8>>,
}

// ─── Block info ───────────────────────────────────────────────────────────────

/// Data stored for each finalized block.
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub block_number: u64,
    /// 32-byte root hash (None = empty tree).
    pub root_hash: Option<[u8; 32]>,
    /// Raw CBOR bytes of the UnicityCertificate.
    pub uc_cbor: Vec<u8>,
}

// ─── Proof lookup results ─────────────────────────────────────────────────────

/// All data needed to build an inclusion proof response.
pub struct InclusionProofData {
    pub block_number: u64,
    pub reference_time: Option<u64>,
    pub cert_data: Option<CertDataFields>,
    pub merkle_path_cbor: Vec<u8>,
    pub uc_cbor: Vec<u8>,
}

/// Result of an inclusion-proof lookup.
pub enum InclusionProofLookup {
    /// The state is certified and its proof is available.
    Proof(InclusionProofData),
    /// A validated request for this state is awaiting certification.
    Pending,
    /// The aggregator has neither a certified record nor a pending request.
    NotFound,
}

/// All data needed to build a non-inclusion proof response against one
/// atomically selected certified state.
pub struct NonInclusionProofData {
    pub block_number: u64,
    pub certificate: Vec<u8>,
    pub uc_cbor: Vec<u8>,
}

/// Result of looking up a non-inclusion proof at the latest certified root.
pub enum NonInclusionProofLookup {
    /// No certified block is available yet.
    CertifiedStateUnavailable,
    /// The requested key is present, so a non-inclusion proof must not be returned.
    StateIncluded,
    /// The bounded proof service has reached its in-flight admission limit.
    Busy,
    /// A proof tied to the indicated block and Unicity Certificate.
    Proof(NonInclusionProofData),
}

/// One atomically published certified state used by the proof-serving plane.
struct CertifiedProofState {
    block: BlockInfo,
    smt: CertifiedSmtSnapshot,
}

// ─── AggregatorState ──────────────────────────────────────────────────────────

/// Central shared state of the aggregator (all fields are thread-safe).
pub struct AggregatorState {
    /// Current (next to be assigned) block number.
    block_number: RwLock<u64>,
    /// StateID (hex) → record info.
    records: DashMap<String, RecordInfo>,
    /// Validated requests accepted but not yet resolved by a certified round.
    pending_state_ids: DashMap<String, usize>,
    /// Block number → block info.
    blocks: DashMap<u64, BlockInfo>,
    /// Channel to submit validated requests to the round manager.
    request_tx: mpsc::Sender<ValidatedRequest>,
    /// Optional persistence backend.
    store: Option<Arc<dyn Store>>,
    /// Latest block metadata and immutable SMT view, replaced atomically.
    certified_proof_state: StdRwLock<Option<Arc<CertifiedProofState>>>,
    /// Admission control in front of the bounded proof worker queue.
    proof_permits: Arc<Semaphore>,
    /// Reference time a round starting now would pin, published by the round
    /// manager so admission can fail an already-expired request immediately.
    reference_time: AtomicU64,
    /// Default request lifetime in seconds, added to the reference time at
    /// admission when a request carries no explicit deadline.
    default_request_ttl: AtomicU64,
}

impl AggregatorState {
    pub fn new(
        request_tx: mpsc::Sender<ValidatedRequest>,
        store: Option<Arc<dyn Store>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            reference_time: AtomicU64::new(0),
            default_request_ttl: AtomicU64::new(DEFAULT_REQUEST_TTL_SECS),
            block_number: RwLock::new(1),
            records: DashMap::new(),
            pending_state_ids: DashMap::new(),
            blocks: DashMap::new(),
            request_tx,
            store,
            certified_proof_state: StdRwLock::new(None),
            proof_permits: Arc::new(Semaphore::new(CERTIFIED_PROOF_MAX_IN_FLIGHT)),
        })
    }

    // ── Block number ──────────────────────────────────────────────────────────

    pub async fn current_block_number(&self) -> u64 {
        *self.block_number.read().await
    }

    /// The reference time a round starting now would pin.
    pub fn reference_time(&self) -> u64 {
        self.reference_time.load(Ordering::Acquire)
    }

    /// Set the default request lifetime, in seconds.
    pub fn set_default_request_ttl(&self, seconds: u64) {
        self.default_request_ttl.store(
            if seconds == 0 {
                DEFAULT_REQUEST_TTL_SECS
            } else {
                seconds
            },
            Ordering::Release,
        );
    }

    /// The absolute deadline a request admitted now is held to.
    ///
    /// An explicit deadline is used verbatim; otherwise the service's default
    /// lifetime is added to the current reference time. The assigned value is
    /// service metadata and does not enter the transaction hash, so a requester
    /// that omits it needs no clock of its own. `None` means no
    /// consensus reference time is available yet.
    pub fn effective_timeout(&self, explicit: Option<u64>) -> Option<u64> {
        let reference_time = self.reference_time();
        if reference_time == 0 {
            return None;
        }
        match explicit {
            Some(timeout) => Some(timeout),
            None => reference_time.checked_add(self.default_request_ttl.load(Ordering::Acquire)),
        }
    }

    /// Publish the reference time rounds are currently pinning. It never moves
    /// backwards: a stale certificate arriving out of order must not undo a
    /// newer one.
    pub fn set_reference_time(&self, reference_time: u64) {
        let mut current = self.reference_time.load(Ordering::Acquire);
        while reference_time > current {
            match self.reference_time.compare_exchange_weak(
                current,
                reference_time,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    pub async fn increment_block_number(&self) -> u64 {
        let mut n = self.block_number.write().await;
        *n += 1;
        *n
    }

    /// Set the block number (used during initialization / recovery).
    pub async fn set_block_number(&self, n: u64) {
        *self.block_number.write().await = n;
    }

    // ── Recovery ──────────────────────────────────────────────────────────────

    pub async fn apply_recovered(&self, state: RecoveredState) {
        for (sid, record) in state.records {
            self.records.insert(sid, record);
        }
        for block in state.blocks {
            self.blocks.insert(block.block_number, block);
        }
        *self.block_number.write().await = state.block_number;
    }

    // ── Request submission ────────────────────────────────────────────────────

    pub async fn submit_request(&self, req: ValidatedRequest) -> anyhow::Result<()> {
        self.add_pending_state_id(&req.state_id_hex);
        let state_id_hex = req.state_id_hex.clone();
        match self.request_tx.send(req).await {
            Ok(()) => Ok(()),
            Err(_) => {
                self.resolve_state_id_hex(&state_id_hex);
                Err(anyhow::anyhow!("round manager channel closed"))
            }
        }
    }

    pub(crate) fn mark_pending_state_id(&self, state_id: &[u8]) {
        self.add_pending_state_id(&hex::encode(state_id));
    }

    /// Resolve pending status after a batch is certified or permanently dropped.
    pub(crate) fn resolve_requests(&self, requests: &[ValidatedRequest]) {
        for request in requests {
            self.resolve_state_id_hex(&request.state_id_hex);
        }
    }

    pub(crate) fn resolve_state_id_hex(&self, state_id_hex: &str) {
        if let Entry::Occupied(mut entry) = self.pending_state_ids.entry(state_id_hex.to_owned()) {
            if *entry.get() > 1 {
                *entry.get_mut() -= 1;
            } else {
                entry.remove();
            }
        }
    }

    fn add_pending_state_id(&self, state_id_hex: &str) {
        self.pending_state_ids
            .entry(state_id_hex.to_owned())
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    // ── Finalization ──────────────────────────────────────────────────────────

    /// Store all records from a finalized round.
    pub fn finalize_records(&self, records: Vec<FinalizedRecord>) {
        for r in records {
            debug!(state_id = %r.state_id_hex, block = r.block_number, "finalizing record");
            self.records.insert(
                r.state_id_hex,
                RecordInfo {
                    block_number: r.block_number,
                    reference_time: r.reference_time,
                    cert_data: r.cert_data,
                    merkle_path_cbor: r.merkle_path_cbor,
                },
            );
        }
    }

    pub fn finalize_block(&self, info: BlockInfo) {
        debug!(block = info.block_number, "finalizing block");
        self.blocks.insert(info.block_number, info);
    }

    /// Persist (if configured) and update in-memory state for a finalized round.
    pub async fn finalize_round(&self, block: BlockInfo, records: Vec<FinalizedRecord>) {
        if let Some(store) = &self.store {
            let next = block.block_number + 1;
            if let Err(e) = store.persist_round(&block, &records, next) {
                tracing::error!(block = block.block_number, err = %e, "RocksDB persist_round failed");
            }
        }
        self.finalize_records(records);
        self.finalize_block(block);
        let mut n = self.block_number.write().await;
        *n += 1;
    }

    // ── Lookups ───────────────────────────────────────────────────────────────

    pub async fn get_inclusion_proof(
        &self,
        state_id: &[u8],
    ) -> anyhow::Result<InclusionProofLookup> {
        let key = hex::encode(state_id);
        let record = match self.records.get(&key) {
            Some(r) => r.clone(),
            None if self.pending_state_ids.contains_key(&key) => {
                return Ok(InclusionProofLookup::Pending)
            }
            None => return Ok(InclusionProofLookup::NotFound),
        };

        let merkle_path_cbor = record.merkle_path_cbor.ok_or_else(|| {
            anyhow::anyhow!("finalized record is missing its inclusion certificate")
        })?;

        let block = self
            .blocks
            .get(&record.block_number)
            .map(|block| block.clone())
            .ok_or_else(|| anyhow::anyhow!("finalized record refers to a missing block"))?;

        Ok(InclusionProofLookup::Proof(InclusionProofData {
            block_number: record.block_number,
            reference_time: Some(record.reference_time),
            cert_data: Some(record.cert_data),
            merkle_path_cbor,
            uc_cbor: block.uc_cbor,
        }))
    }

    /// Atomically publish a root-pinned SMT view together with the certificate
    /// metadata that authenticates that exact root.
    pub(crate) fn publish_certified_snapshot(
        &self,
        block: BlockInfo,
        snapshot: CertifiedSmtSnapshot,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            block.root_hash == snapshot.root_hash(),
            "cannot publish mismatched certified block and SMT snapshot roots"
        );
        let mut slot = self
            .certified_proof_state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = Some(Arc::new(CertifiedProofState {
            block,
            smt: snapshot,
        }));
        Ok(())
    }

    /// Stop new lookups from selecting an older root while a newly certified
    /// root is being pinned and published. Already-admitted lookups retain the
    /// old immutable snapshot and remain valid snapshot statements.
    pub(crate) fn clear_certified_snapshot(&self) {
        let mut slot = self
            .certified_proof_state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = None;
    }

    /// Generate a proof outside the round-manager task using the latest
    /// atomically published certified snapshot.
    pub async fn get_non_inclusion_proof(
        &self,
        state_id: [u8; 32],
    ) -> anyhow::Result<NonInclusionProofLookup> {
        let Some(certified) = self
            .certified_proof_state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        else {
            return Ok(NonInclusionProofLookup::CertifiedStateUnavailable);
        };

        let permit = match Arc::clone(&self.proof_permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Ok(NonInclusionProofLookup::Busy),
        };
        let worker = certified.smt.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            worker.get_non_inclusion_proof(state_id)
        })
        .await
        .map_err(|error| anyhow::anyhow!("non-inclusion proof task failed: {error}"))??;

        match outcome {
            rsmt::NonInclusionProofOutcome::StateIncluded => {
                Ok(NonInclusionProofLookup::StateIncluded)
            }
            rsmt::NonInclusionProofOutcome::Proof(proof) => {
                anyhow::ensure!(
                    rsmt::verify_non_inclusion(
                        &proof,
                        certified.block.root_hash.as_ref(),
                        &state_id,
                    ),
                    "generated non-inclusion certificate did not reproduce the certified root"
                );
                if let Some(value) = proof.terminal_value() {
                    anyhow::ensure!(
                        value.len() == AGGREGATION_TREE_VALUE_SIZE,
                        "Unicity aggregation-tree terminal value must be \
                         {AGGREGATION_TREE_VALUE_SIZE} bytes, got {}",
                        value.len()
                    );
                }
                Ok(NonInclusionProofLookup::Proof(NonInclusionProofData {
                    block_number: certified.block.block_number,
                    certificate: proof.to_bytes(),
                    uc_cbor: certified.block.uc_cbor.clone(),
                }))
            }
        }
    }

    /// Latest certified block, used to publish a proof snapshot on startup.
    pub(crate) async fn latest_certified_block(&self) -> Option<BlockInfo> {
        let next = *self.block_number.read().await;
        let latest = next.checked_sub(1)?;
        self.blocks.get(&latest).map(|block| block.clone())
    }
}

// ─── FinalizedRecord (produced by RoundManager, consumed by AggregatorState) ─

pub struct FinalizedRecord {
    pub state_id_hex: String,
    pub block_number: u64,
    /// Reference time of the round this record's leaf was created in.
    pub reference_time: u64,
    pub cert_data: CertDataFields,
    /// Pre-computed Merkle path CBOR.
    ///
    /// Always `Some` for finalized records (generated at finalization time).
    pub merkle_path_cbor: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Omitting the deadline delegates assignment to the service: the deadline
    /// is the default lifetime added to the consensus reference time, so the
    /// requester needs no clock of its own. An explicit deadline is used
    /// verbatim, and neither value enters the transaction hash.
    #[test]
    fn effective_timeout_is_assigned_only_when_omitted() {
        let (tx, _rx) = mpsc::channel(1);
        let state = AggregatorState::new(tx, None);
        state.set_default_request_ttl(600);

        assert_eq!(state.effective_timeout(None), None, "no reference time yet");

        state.set_reference_time(1_755_000_000);
        assert_eq!(state.effective_timeout(None), Some(1_755_000_600));
        assert_eq!(
            state.effective_timeout(Some(1_755_000_005)),
            Some(1_755_000_005)
        );
    }

    /// A stale certificate arriving out of order must not undo a newer one.
    #[test]
    fn reference_time_never_moves_backwards() {
        let (tx, _rx) = mpsc::channel(1);
        let state = AggregatorState::new(tx, None);

        state.set_reference_time(1_755_000_000);
        state.set_reference_time(1_754_000_000);

        assert_eq!(state.reference_time(), 1_755_000_000);
    }

    /// Exclusive certification request deadline every fixture in this module uses.
    const TEST_EXPIRES_AT: u64 = 1_755_003_600;
    use smt_store::{MemSmt, SmtStore, SmtStoreSnapshot};

    fn request(state_id: [u8; 32]) -> ValidatedRequest {
        ValidatedRequest {
            state_id_hex: hex::encode(state_id),
            state_id: state_id.to_vec(),
            predicate_cbor: vec![1],
            source_state_hash: vec![2; 32],
            transaction_hash: vec![3; AGGREGATION_TREE_VALUE_SIZE],
            expires_at: Some(TEST_EXPIRES_AT),
            effective_timeout: TEST_EXPIRES_AT,
            witness: vec![4; 65],
            public_key: vec![5; 33],
        }
    }

    #[tokio::test]
    async fn inclusion_lookup_distinguishes_pending_from_unknown() {
        let (request_tx, mut request_rx) = mpsc::channel(2);
        let state = AggregatorState::new(request_tx, None);
        let state_id = [7u8; 32];

        state.submit_request(request(state_id)).await.unwrap();
        state.submit_request(request(state_id)).await.unwrap();
        assert!(matches!(
            state.get_inclusion_proof(&state_id).await.unwrap(),
            InclusionProofLookup::Pending
        ));

        let first = request_rx.recv().await.unwrap();
        state.resolve_requests(&[first]);
        assert!(matches!(
            state.get_inclusion_proof(&state_id).await.unwrap(),
            InclusionProofLookup::Pending
        ));

        let second = request_rx.recv().await.unwrap();
        state.resolve_requests(&[second]);
        assert!(matches!(
            state.get_inclusion_proof(&state_id).await.unwrap(),
            InclusionProofLookup::NotFound
        ));
    }

    #[tokio::test]
    async fn certified_snapshot_serves_explicit_relation_outcomes_with_admission_limit() {
        let (request_tx, _request_rx) = mpsc::channel(1);
        let state = AggregatorState::new(request_tx, None);
        let included_key = [0x11u8; 32];
        let absent_key = [0x22u8; 32];

        let mut smt = MemSmt::new();
        let mut mutation = smt.create_snapshot();
        mutation
            .add_leaf(included_key, vec![0x33; AGGREGATION_TREE_VALUE_SIZE])
            .unwrap();
        mutation.commit(&mut smt).unwrap();
        let root = smt.root_hash();
        state
            .publish_certified_snapshot(
                BlockInfo {
                    block_number: 1,
                    root_hash: root,
                    uc_cbor: vec![0xaa],
                },
                smt.create_certified_snapshot().unwrap(),
            )
            .unwrap();

        assert!(matches!(
            state.get_non_inclusion_proof(included_key).await.unwrap(),
            NonInclusionProofLookup::StateIncluded
        ));
        let NonInclusionProofLookup::Proof(proof_data) =
            state.get_non_inclusion_proof(absent_key).await.unwrap()
        else {
            panic!("absent key must produce a proof");
        };
        let proof = rsmt::NonInclusionProof::from_bytes(&proof_data.certificate).unwrap();
        assert!(rsmt::verify_non_inclusion(
            &proof,
            root.as_ref(),
            &absent_key
        ));

        let held_permits: Vec<_> = (0..CERTIFIED_PROOF_MAX_IN_FLIGHT)
            .map(|_| {
                Arc::clone(&state.proof_permits)
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect();
        assert!(matches!(
            state.get_non_inclusion_proof(absent_key).await.unwrap(),
            NonInclusionProofLookup::Busy
        ));
        drop(held_permits);
    }
}
