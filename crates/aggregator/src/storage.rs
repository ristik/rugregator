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
use smt_store::{
    CertifiedSmtSnapshot, InclusionBatchEntry, SnapshotError, CERTIFIED_PROOF_MAX_IN_FLIGHT,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Default request lifetime in seconds when the deployment sets none.
pub const DEFAULT_REQUEST_TTL_SECS: u64 = 3600;
use std::sync::{Arc, Mutex as StdMutex};
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
    /// The UC is the ordinary one of an unsharded partition (empty shard ID, no
    /// shard-tree siblings), so batch responses need no partition view.
    unsharded: bool,
    retained_at: Instant,
}

// ─── Retained certified-view catalog ──────────────────────────────────────────

/// Explicit bounds of the retained certified-view catalog and batch serving.
///
/// Defaults follow the batch-inclusion design (§5). The memory backend shares
/// structure between roots and RocksDB pins versions, so neither has a cheap
/// honest *byte* measure; the count and age caps are the enforced retention
/// bounds and `max_active_batches` bounds concurrent pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionLimits {
    /// Retained certified views, the latest included. One worker thread each.
    pub max_views: usize,
    /// Age after which a superseded view is dropped. The latest is never aged out.
    pub max_age: Duration,
    /// Concurrent batch requests, each holding one pinned view.
    pub max_active_batches: usize,
    /// Execution budget of one batch request.
    pub batch_timeout: Duration,
}

impl Default for RetentionLimits {
    fn default() -> Self {
        Self {
            max_views: 32,
            max_age: Duration::from_secs(300),
            max_active_batches: 8,
            batch_timeout: Duration::from_secs(5),
        }
    }
}

/// Pressure counters of the catalog, for operators and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CatalogStats {
    pub retained_views: usize,
    pub evicted_by_count: u64,
    pub evicted_by_age: u64,
    pub replaced_same_root: u64,
    pub rejected_busy: u64,
}

struct Catalog {
    limits: RetentionLimits,
    /// Oldest first; contains the latest view while it is published.
    retained: VecDeque<Arc<CertifiedProofState>>,
    /// `None` while a newly certified root is being pinned or if publication
    /// failed: latest is then unavailable, never an older view.
    latest: Option<Arc<CertifiedProofState>>,
    stats: CatalogStats,
}

impl Catalog {
    fn new(limits: RetentionLimits) -> Self {
        Self {
            limits,
            retained: VecDeque::new(),
            latest: None,
            stats: CatalogStats::default(),
        }
    }

    fn insert(&mut self, view: Arc<CertifiedProofState>) {
        // The newer certification of an equal root replaces the older attachment
        // wholesale: exact-root selection must return one coherent
        // block/UC/snapshot, never a mix.
        if let Some(root) = view.block.root_hash {
            let before = self.retained.len();
            self.retained.retain(|v| v.block.root_hash != Some(root));
            self.stats.replaced_same_root += (before - self.retained.len()) as u64;
        }
        self.retained.push_back(Arc::clone(&view));
        self.latest = Some(view);
        self.evict(Instant::now());
    }

    fn evict(&mut self, now: Instant) {
        let latest = self.latest.clone();
        let is_latest = |v: &Arc<CertifiedProofState>| {
            latest.as_ref().is_some_and(|l| Arc::ptr_eq(l, v))
        };
        let max_age = self.limits.max_age;
        let before = self.retained.len();
        self.retained
            .retain(|v| is_latest(v) || now.duration_since(v.retained_at) <= max_age);
        self.stats.evicted_by_age += (before - self.retained.len()) as u64;
        while self.retained.len() > self.limits.max_views.max(1) {
            let Some(pos) = self.retained.iter().position(|v| !is_latest(v)) else {
                break;
            };
            self.retained.remove(pos);
            self.stats.evicted_by_count += 1;
        }
    }
}

/// Which retained view a batch request selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewSelector {
    /// The latest certified view.
    Latest,
    /// The retained view with exactly this state root. Never falls back.
    Root([u8; 32]),
}

/// Why a pinned view could not serve a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyKind {
    /// The concurrent batch limit is reached.
    ActiveRequests,
    /// The selected view's worker queue is full.
    PinnedViews,
    /// The execution budget elapsed.
    Deadline,
}

/// Typed failure of a batch inclusion lookup.
#[derive(Debug)]
pub enum BatchProofError {
    /// No certified view is published as latest.
    NoFinalizedView,
    /// The requested exact root is not retained.
    ViewNotRetained,
    /// The selected view's UC is not an unsharded one; this unsharded-only
    /// capability does not serve it (and never invents a partition view).
    UnsupportedConfiguration,
    Busy(BusyKind),
    /// State IDs absent from the pinned view, classified per class with the
    /// offending request indexes (ascending).
    Absent(AbsentStates),
    /// Storage or consistency failure; the text is for logs only.
    Internal(anyhow::Error),
}

/// Absent-state classification of a batch (#209).
#[derive(Debug, PartialEq, Eq)]
pub struct AbsentStates {
    /// `state_pending`, `state_expired`, `state_unknown` (latest) or
    /// `state_not_in_root` (exact root).
    pub detail: &'static str,
    pub retryable: bool,
    /// Class name → ascending request indexes.
    pub indexes: BTreeMap<&'static str, Vec<usize>>,
}

/// One served leaf of a batch.
pub struct BatchProofItem {
    pub reference_time: u64,
    pub cert_data: CertDataFields,
    pub merkle_path_cbor: Vec<u8>,
}

/// Inclusion proofs of one batch, all against one pinned view.
pub struct BatchProofs {
    pub block_number: u64,
    pub uc_cbor: Vec<u8>,
    pub items: Vec<BatchProofItem>,
}

/// Bound on remembered expired state IDs and how long they are remembered.
const EXPIRED_MAX_ENTRIES: usize = 100_000;
const EXPIRED_TTL: Duration = Duration::from_secs(600);

/// Bounded best-effort memory of requests dropped because their deadline passed.
#[derive(Default)]
struct ExpiredSet {
    at: HashMap<String, Instant>,
    order: VecDeque<(Instant, String)>,
}

impl ExpiredSet {
    fn insert(&mut self, state_id_hex: &str, now: Instant) {
        self.prune(now);
        self.at.insert(state_id_hex.to_owned(), now);
        self.order.push_back((now, state_id_hex.to_owned()));
        while self.at.len() > EXPIRED_MAX_ENTRIES {
            self.pop_oldest();
        }
    }

    fn contains(&mut self, state_id_hex: &str, now: Instant) -> bool {
        self.prune(now);
        self.at.contains_key(state_id_hex)
    }

    fn remove(&mut self, state_id_hex: &str) {
        self.at.remove(state_id_hex);
    }

    fn prune(&mut self, now: Instant) {
        while let Some((t, _)) = self.order.front() {
            if now.duration_since(*t) <= EXPIRED_TTL {
                break;
            }
            self.pop_oldest();
        }
    }

    fn pop_oldest(&mut self) {
        if let Some((t, id)) = self.order.pop_front() {
            // A re-inserted ID has a newer order entry; only the entry matching
            // the stored time removes it.
            if self.at.get(&id) == Some(&t) {
                self.at.remove(&id);
            }
        }
    }
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
    /// Retained certified views and the latest pointer, replaced atomically.
    catalog: StdMutex<Catalog>,
    /// Admission control in front of the bounded proof worker queues, shared by
    /// single non-inclusion lookups and batches so more retained views cannot
    /// multiply proof concurrency.
    proof_permits: Arc<Semaphore>,
    /// Concurrent batch requests (each pins one view).
    batch_permits: Arc<Semaphore>,
    batch_permit_limit: std::sync::atomic::AtomicUsize,
    /// Requests dropped at their deadline (hint only, bounded).
    expired: StdMutex<ExpiredSet>,
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
            catalog: StdMutex::new(Catalog::new(RetentionLimits::default())),
            proof_permits: Arc::new(Semaphore::new(CERTIFIED_PROOF_MAX_IN_FLIGHT)),
            batch_permits: Arc::new(Semaphore::new(RetentionLimits::default().max_active_batches)),
            batch_permit_limit: std::sync::atomic::AtomicUsize::new(
                RetentionLimits::default().max_active_batches,
            ),
            expired: StdMutex::new(ExpiredSet::default()),
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
        {
            let mut expired = self
                .expired
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for r in &records {
                expired.remove(&r.state_id_hex);
            }
        }
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

    /// The latest finalized block, the one the "not certified" v2 answer carries (the
    /// counterpart of aggregator-go's latest finalized UC). `None` before the first block.
    pub async fn latest_finalized_block(&self) -> Option<BlockInfo> {
        let next = *self.block_number.read().await;
        let by_number = next
            .checked_sub(1)
            .filter(|n| *n > 0)
            .and_then(|n| self.blocks.get(&n).map(|b| b.clone()));
        // The published latest view is a finalized block as well (it is only absent while a
        // new root is being pinned, when the round counter is the better source).
        by_number.or_else(|| self.latest_view().map(|v| v.block.clone()))
    }

    /// Unauthenticated, node-local status hint of a state: `included` (a certified record
    /// exists), `pending`, `expired` (dropped at its deadline) or `unknown`. Never evidence
    /// about the state.
    pub fn proof_status_hint(&self, state_id: &[u8]) -> &'static str {
        let key = hex::encode(state_id);
        if self.records.contains_key(&key) {
            return "included";
        }
        self.absence_class(&key)
    }

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
    /// metadata that authenticates that exact root. It becomes the latest view
    /// and joins the bounded retained catalog.
    pub(crate) fn publish_certified_snapshot(
        &self,
        block: BlockInfo,
        snapshot: CertifiedSmtSnapshot,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            block.root_hash == snapshot.root_hash(),
            "cannot publish mismatched certified block and SMT snapshot roots"
        );
        let decoded = crate::api::cbor::decode_cbor_value(&block.uc_cbor);
        // A legacy `h''`-root certificate is not the canonical certified empty tree: never publish
        // it as a (non-inclusion) snapshot. Its bytes stay as they are; reset the stub data
        // directory to migrate (docs/stub-uc-migration.md).
        anyhow::ensure!(
            !(block.root_hash.is_none()
                && decoded
                    .as_ref()
                    .is_ok_and(crate::api::cbor::unicity_certificate_has_legacy_empty_root)),
            "block {} certifies the empty tree with a legacy empty-byte-string root; it cannot be \
             served as a canonical certified-empty snapshot",
            block.block_number
        );
        let unsharded = decoded
            .map(|uc| crate::api::cbor::unicity_certificate_is_unsharded(&uc))
            .unwrap_or(false);
        self.catalog().insert(Arc::new(CertifiedProofState {
            block,
            smt: snapshot,
            unsharded,
            retained_at: Instant::now(),
        }));
        Ok(())
    }

    /// Stop new lookups from selecting an older root as *latest* while a newly
    /// certified root is being pinned and published. Retained views stay
    /// available to exact-root requests, and already-admitted lookups keep
    /// their immutable snapshot, which remains a valid statement about its root.
    pub(crate) fn clear_certified_snapshot(&self) {
        self.catalog().latest = None;
    }

    fn catalog(&self) -> std::sync::MutexGuard<'_, Catalog> {
        self.catalog
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn latest_view(&self) -> Option<Arc<CertifiedProofState>> {
        self.catalog().latest.clone()
    }

    /// Replace the retention limits (startup configuration). Applies the new
    /// bounds to what is already retained.
    pub fn set_retention_limits(&self, limits: RetentionLimits) {
        let mut catalog = self.catalog();
        catalog.limits = limits;
        catalog.evict(Instant::now());
        drop(catalog);
        // Permits are only replaced while idle at startup.
        self.batch_permits_resize(limits.max_active_batches);
    }

    fn batch_permits_resize(&self, target: usize) {
        // Startup only: grow or shrink the idle semaphore to the configured size.
        let current = self.batch_permit_limit.load(Ordering::Acquire);
        if target > current {
            self.batch_permits.add_permits(target - current);
        } else if target < current {
            let _ = self.batch_permits.forget_permits(current - target);
        }
        self.batch_permit_limit.store(target, Ordering::Release);
    }

    pub fn retention_limits(&self) -> RetentionLimits {
        self.catalog().limits
    }

    /// Pressure counters of the retained catalog.
    pub fn catalog_stats(&self) -> CatalogStats {
        let catalog = self.catalog();
        CatalogStats {
            retained_views: catalog.retained.len(),
            ..catalog.stats
        }
    }

    /// Generate a proof outside the round-manager task using the latest
    /// atomically published certified snapshot.
    pub async fn get_non_inclusion_proof(
        &self,
        state_id: [u8; 32],
    ) -> anyhow::Result<NonInclusionProofLookup> {
        let Some(certified) = self.latest_view() else {
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

    // ── Expired hints ─────────────────────────────────────────────────────────

    /// Requests dropped because their deadline passed: remember them (bounded,
    /// best effort) and stop counting them pending.
    pub(crate) fn drop_expired_requests(&self, requests: &[ValidatedRequest]) {
        {
            let now = Instant::now();
            let mut expired = self
                .expired
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for request in requests {
                expired.insert(&request.state_id_hex, now);
            }
        }
        self.resolve_requests(requests);
    }

    /// Unauthenticated, node-local hint about a state with no certified proof.
    fn absence_class(&self, state_id_hex: &str) -> &'static str {
        if self.pending_state_ids.contains_key(state_id_hex) {
            return "pending";
        }
        let mut expired = self
            .expired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if expired.contains(state_id_hex, Instant::now()) {
            "expired"
        } else {
            "unknown"
        }
    }

    // ── Batch inclusion over a pinned view ────────────────────────────────────

    /// Serve inclusion proofs for `state_ids` (in request order) from one pinned
    /// certified view: the latest or an exact retained root.
    ///
    /// Proofs are rebuilt against the pinned root; a record's cached original
    /// path is never returned. The original certification data and leaf
    /// reference time are kept, so the leaf value reproduces the certified one.
    /// Any absent state fails the whole batch with a classified error.
    pub async fn get_inclusion_proofs_batch(
        &self,
        state_ids: &[[u8; 32]],
        selector: ViewSelector,
    ) -> Result<BatchProofs, BatchProofError> {
        let (limits, view) = {
            let catalog = self.catalog();
            let view = match selector {
                ViewSelector::Latest => catalog.latest.clone(),
                ViewSelector::Root(root) => catalog
                    .retained
                    .iter()
                    .rev()
                    .find(|v| v.block.root_hash == Some(root))
                    .cloned(),
            };
            (catalog.limits, view)
        };
        let Some(view) = view else {
            return Err(match selector {
                ViewSelector::Latest => BatchProofError::NoFinalizedView,
                ViewSelector::Root(_) => BatchProofError::ViewNotRetained,
            });
        };
        if !view.unsharded {
            return Err(BatchProofError::UnsupportedConfiguration);
        }
        // Admission: concurrent batches first, then the proof-work budget shared
        // with single non-inclusion lookups.
        let batch_permit = Arc::clone(&self.batch_permits)
            .try_acquire_owned()
            .map_err(|_| {
                self.catalog().stats.rejected_busy += 1;
                BatchProofError::Busy(BusyKind::ActiveRequests)
            })?;
        let proof_permit = Arc::clone(&self.proof_permits)
            .try_acquire_owned()
            .map_err(|_| {
                self.catalog().stats.rejected_busy += 1;
                BatchProofError::Busy(BusyKind::ActiveRequests)
            })?;

        let deadline = Instant::now() + limits.batch_timeout;
        let keys: Vec<rsmt::SmtKey> = state_ids.to_vec();
        let worker = view.smt.clone();
        let entries = tokio::task::spawn_blocking(move || {
            // Held until the worker answered or gave up, not until the caller
            // stopped waiting.
            let _permits = (batch_permit, proof_permit);
            worker.get_inclusion_batch(keys, deadline)
        })
        .await
        .map_err(|e| BatchProofError::Internal(anyhow::anyhow!("batch task failed: {e}")))?
        .map_err(|e| match e {
            SnapshotError::QueueFull => {
                self.catalog().stats.rejected_busy += 1;
                BatchProofError::Busy(BusyKind::PinnedViews)
            }
            SnapshotError::Deadline => BatchProofError::Busy(BusyKind::Deadline),
            other => BatchProofError::Internal(anyhow::anyhow!(other.to_string())),
        })?;
        if entries.len() != state_ids.len() {
            return Err(BatchProofError::Internal(anyhow::anyhow!(
                "snapshot worker returned {} entries for {} keys",
                entries.len(),
                state_ids.len()
            )));
        }
        let root = view.block.root_hash;

        let latest = matches!(selector, ViewSelector::Latest);
        let mut classes: BTreeMap<&'static str, Vec<usize>> = BTreeMap::new();
        let mut items = Vec::with_capacity(state_ids.len());
        for (i, (state_id, entry)) in state_ids.iter().zip(entries).enumerate() {
            let hex_id = hex::encode(state_id);
            let record = self.records.get(&hex_id).map(|r| r.clone());
            match entry {
                InclusionBatchEntry::Absent => {
                    let class = if !latest {
                        "not_in_root"
                    } else if record.is_some() {
                        // Finalized after the pinned latest view.
                        "pending"
                    } else {
                        self.absence_class(&hex_id)
                    };
                    classes.entry(class).or_default().push(i);
                }
                InclusionBatchEntry::Present { proof, value } => {
                    let record = record.ok_or_else(|| {
                        BatchProofError::Internal(anyhow::anyhow!(
                            "pinned view contains a leaf without a finalized record"
                        ))
                    })?;
                    let expected =
                        rsmt::leaf_value(&record.cert_data.transaction_hash, record.reference_time);
                    let root = root.ok_or_else(|| {
                        BatchProofError::Internal(anyhow::anyhow!("empty view holds a leaf"))
                    })?;
                    if value != expected.as_slice()
                        || !rsmt::verify_inclusion(&proof, &root, state_id, &value)
                    {
                        return Err(BatchProofError::Internal(anyhow::anyhow!(
                            "inclusion path does not reproduce the pinned root for the record"
                        )));
                    }
                    items.push(BatchProofItem {
                        reference_time: record.reference_time,
                        cert_data: record.cert_data,
                        merkle_path_cbor: proof.to_bytes(),
                    });
                }
            }
        }
        if !classes.is_empty() {
            let (detail, retryable) = if !latest {
                ("state_not_in_root", false)
            } else if classes.contains_key("unknown") {
                ("state_unknown", false)
            } else if classes.contains_key("expired") {
                ("state_expired", false)
            } else {
                ("state_pending", true)
            };
            return Err(BatchProofError::Absent(AbsentStates {
                detail,
                retryable,
                indexes: classes,
            }));
        }
        Ok(BatchProofs {
            block_number: view.block.block_number,
            uc_cbor: view.block.uc_cbor.clone(),
            items,
        })
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

    // ── Retained catalog and batch serving ────────────────────────────────────

    use crate::api::cbor::test_uc_cbor;

    const REF_TIME: u64 = 1_755_000_000;

    fn txh(seed: u8) -> Vec<u8> {
        vec![seed; AGGREGATION_TREE_VALUE_SIZE]
    }

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn finalized(seed: u8, block: u64) -> FinalizedRecord {
        FinalizedRecord {
            state_id_hex: hex::encode(key(seed)),
            block_number: block,
            reference_time: REF_TIME,
            cert_data: CertDataFields {
                predicate_cbor: vec![1],
                source_state_hash: vec![2; 32],
                transaction_hash: txh(seed),
                expires_at: Some(TEST_EXPIRES_AT),
                witness: vec![4; 65],
            },
            merkle_path_cbor: Some(vec![0xde, 0xad]), // never served by batches
        }
    }

    /// Add `seeds` to `smt` as one round and publish the resulting view as `block`.
    fn round(
        state: &AggregatorState,
        smt: &mut MemSmt,
        seeds: &[u8],
        block: u64,
        shard_id: &[u8],
    ) -> Option<[u8; 32]> {
        let mut mutation = smt.create_snapshot();
        for &seed in seeds {
            mutation
                .add_leaf(
                    key(seed),
                    rsmt::leaf_value(&txh(seed), REF_TIME).to_vec(),
                )
                .unwrap();
        }
        mutation.commit(smt).unwrap();
        state.finalize_records(seeds.iter().map(|&s| finalized(s, block)).collect());
        let root = smt.root_hash();
        state
            .publish_certified_snapshot(
                BlockInfo {
                    block_number: block,
                    root_hash: root,
                    uc_cbor: test_uc_cbor(root, shard_id, 0),
                },
                smt.create_certified_snapshot().unwrap(),
            )
            .unwrap();
        root
    }

    fn new_state() -> Arc<AggregatorState> {
        let (tx, rx) = mpsc::channel(64);
        std::mem::forget(rx); // keep the channel open for admission
        AggregatorState::new(tx, None)
    }

    fn assert_batch_verifies(batch: &BatchProofs, ids: &[[u8; 32]], root: [u8; 32]) {
        assert_eq!(batch.items.len(), ids.len());
        for (item, id) in batch.items.iter().zip(ids) {
            let proof = rsmt::InclusionProof::from_bytes(&item.merkle_path_cbor).unwrap();
            let value = rsmt::leaf_value(&item.cert_data.transaction_hash, item.reference_time);
            assert!(rsmt::verify_inclusion(&proof, &root, id, &value));
        }
    }

    #[tokio::test]
    async fn batches_pin_latest_and_exact_roots_without_falling_back() {
        let state = new_state();
        let mut smt = MemSmt::new();
        let root1 = round(&state, &mut smt, &[0x11, 0x91], 1, &[0x80]).unwrap();
        let root2 = round(&state, &mut smt, &[0x42], 2, &[0x80]).unwrap();
        assert_ne!(root1, root2);

        // Latest is the newest view and serves all three, in request order.
        let ids = [key(0x42), key(0x11), key(0x91)];
        let latest = state
            .get_inclusion_proofs_batch(&ids, ViewSelector::Latest)
            .await
            .unwrap();
        assert_eq!(latest.block_number, 2);
        assert_eq!(latest.uc_cbor, test_uc_cbor(Some(root2), &[0x80], 0));
        assert_batch_verifies(&latest, &ids, root2);
        // The original reference time and certification data are preserved, and
        // the cached original path of the record is not what is served.
        assert_eq!(latest.items[0].reference_time, REF_TIME);
        assert_ne!(latest.items[0].merkle_path_cbor, vec![0xde, 0xad]);

        // Exact root 1 serves its own leaves with block 1's UC ...
        let old_ids = [key(0x91), key(0x11)];
        let old = state
            .get_inclusion_proofs_batch(&old_ids, ViewSelector::Root(root1))
            .await
            .unwrap();
        assert_eq!(old.block_number, 1);
        assert_batch_verifies(&old, &old_ids, root1);

        // ... and a leaf created after that root is absent from it: not in root,
        // never silently served from the latest view.
        let Err(BatchProofError::Absent(absent)) = state
            .get_inclusion_proofs_batch(&[key(0x11), key(0x42)], ViewSelector::Root(root1))
            .await
        else {
            panic!("a later leaf must not be in the older root");
        };
        assert_eq!(absent.detail, "state_not_in_root");
        assert!(!absent.retryable);
        assert_eq!(absent.indexes["not_in_root"], vec![1]);

        // An unknown exact root never falls back to latest.
        assert!(matches!(
            state
                .get_inclusion_proofs_batch(&ids, ViewSelector::Root([0x77; 32]))
                .await,
            Err(BatchProofError::ViewNotRetained)
        ));

        // While a new latest is being pinned, latest is unavailable (never the
        // older view), but exact roots keep serving.
        state.clear_certified_snapshot();
        assert!(matches!(
            state
                .get_inclusion_proofs_batch(&ids, ViewSelector::Latest)
                .await,
            Err(BatchProofError::NoFinalizedView)
        ));
        state
            .get_inclusion_proofs_batch(&old_ids, ViewSelector::Root(root1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn absent_latest_states_are_classified_with_precedence_and_indexes() {
        let state = new_state();
        let mut smt = MemSmt::new();
        round(&state, &mut smt, &[0x11], 1, &[0x80]);

        // 0x22 pending (admitted), 0x33 expired (dropped at its deadline), 0x44 never seen.
        state.submit_request(request(key(0x22))).await.unwrap();
        state.submit_request(request(key(0x33))).await.unwrap();
        state.drop_expired_requests(&[request(key(0x33))]);
        let ids = [key(0x22), key(0x11), key(0x33), key(0x44)];

        let Err(BatchProofError::Absent(a)) = state
            .get_inclusion_proofs_batch(&ids, ViewSelector::Latest)
            .await
        else {
            panic!()
        };
        assert_eq!(a.detail, "state_unknown", "unknown > expired > pending");
        assert!(!a.retryable);
        assert_eq!(a.indexes["pending"], vec![0]);
        assert_eq!(a.indexes["expired"], vec![2]);
        assert_eq!(a.indexes["unknown"], vec![3]);
        assert!(!a.indexes.contains_key("not_in_root"));

        let Err(BatchProofError::Absent(a)) = state
            .get_inclusion_proofs_batch(&ids[..3], ViewSelector::Latest)
            .await
        else {
            panic!()
        };
        assert_eq!(a.detail, "state_expired");
        assert!(!a.retryable);

        let Err(BatchProofError::Absent(a)) = state
            .get_inclusion_proofs_batch(&ids[..2], ViewSelector::Latest)
            .await
        else {
            panic!()
        };
        assert_eq!(a.detail, "state_pending");
        assert!(a.retryable);

        // A record finalized after the pinned latest view is pending, whatever
        // the status memory says.
        state.finalize_records(vec![finalized(0x55, 2)]);
        let Err(BatchProofError::Absent(a)) = state
            .get_inclusion_proofs_batch(&[key(0x55)], ViewSelector::Latest)
            .await
        else {
            panic!()
        };
        assert_eq!(a.detail, "state_pending");

        // Exact-root absence is not_in_root even while the request is pending now.
        let root = state.latest_view().unwrap().block.root_hash.unwrap();
        let Err(BatchProofError::Absent(a)) = state
            .get_inclusion_proofs_batch(&[key(0x22)], ViewSelector::Root(root))
            .await
        else {
            panic!()
        };
        assert_eq!(a.detail, "state_not_in_root");
    }

    #[tokio::test]
    async fn finalizing_clears_the_expired_tombstone() {
        let state = new_state();
        state.drop_expired_requests(&[request(key(0x33))]);
        assert_eq!(state.absence_class(&hex::encode(key(0x33))), "expired");
        // Re-admitted: pending wins over the old tombstone.
        state.submit_request(request(key(0x33))).await.unwrap();
        assert_eq!(state.absence_class(&hex::encode(key(0x33))), "pending");
        state.finalize_records(vec![finalized(0x33, 1)]);
        state.resolve_state_id_hex(&hex::encode(key(0x33)));
        assert_eq!(state.absence_class(&hex::encode(key(0x33))), "unknown");
    }

    #[test]
    fn expired_memory_is_bounded_by_count_and_ttl() {
        let mut set = ExpiredSet::default();
        let t0 = Instant::now();
        for i in 0..(EXPIRED_MAX_ENTRIES + 10) {
            set.insert(&format!("{i:08}"), t0);
        }
        assert_eq!(set.at.len(), EXPIRED_MAX_ENTRIES, "count cap evicts the oldest");
        assert!(!set.contains("00000000", t0));
        assert!(set.contains(&format!("{:08}", EXPIRED_MAX_ENTRIES + 9), t0));
        // After the TTL everything is forgotten.
        let later = t0 + EXPIRED_TTL + Duration::from_secs(1);
        assert!(!set.contains(&format!("{:08}", EXPIRED_MAX_ENTRIES + 9), later));
        assert!(set.at.is_empty() && set.order.is_empty());
        // Re-inserting an ID refreshes it; the stale order entry must not drop it.
        let mut set = ExpiredSet::default();
        set.insert("a", t0);
        set.insert("a", t0 + Duration::from_secs(500));
        assert!(set.contains("a", t0 + EXPIRED_TTL + Duration::from_secs(1)));
    }

    #[test]
    fn catalog_retention_is_bounded_and_never_drops_the_latest() {
        let state = new_state();
        state.set_retention_limits(RetentionLimits {
            max_views: 3,
            ..RetentionLimits::default()
        });
        let mut smt = MemSmt::new();
        let roots: Vec<_> = (1..=5u8)
            .map(|i| round(&state, &mut smt, &[i], u64::from(i), &[0x80]).unwrap())
            .collect();
        let stats = state.catalog_stats();
        assert_eq!(stats.retained_views, 3);
        assert_eq!(stats.evicted_by_count, 2);
        let catalog = state.catalog();
        let retained: Vec<_> = catalog.retained.iter().filter_map(|v| v.block.root_hash).collect();
        assert_eq!(retained, roots[2..].to_vec());
        assert_eq!(catalog.latest.as_ref().unwrap().block.root_hash, Some(roots[4]));
        drop(catalog);

        // Age: with a zero budget every superseded view goes at the next publish,
        // the latest stays.
        state.set_retention_limits(RetentionLimits {
            max_age: Duration::ZERO,
            ..RetentionLimits::default()
        });
        std::thread::sleep(Duration::from_millis(2));
        let stats = state.catalog_stats();
        assert_eq!(stats.retained_views, 1);
        assert_eq!(stats.evicted_by_age, 2);
        assert_eq!(state.catalog().latest.as_ref().unwrap().block.root_hash, Some(roots[4]));
    }

    #[test]
    fn the_same_root_at_a_later_certification_replaces_its_attachment() {
        let state = new_state();
        let mut smt = MemSmt::new();
        let root = round(&state, &mut smt, &[0x11], 1, &[0x80]).unwrap();
        // An empty round certifies the same root again as block 2.
        round(&state, &mut smt, &[], 2, &[0x80]);
        let catalog = state.catalog();
        assert_eq!(catalog.retained.len(), 1);
        assert_eq!(catalog.stats.replaced_same_root, 1);
        let view = catalog.retained.back().unwrap();
        assert_eq!(view.block.root_hash, Some(root));
        assert_eq!(view.block.block_number, 2, "one coherent block/UC/snapshot");
    }

    #[tokio::test]
    async fn sharded_certificates_are_refused_never_given_a_view() {
        let state = new_state();
        let mut smt = MemSmt::new();
        round(&state, &mut smt, &[0x11], 1, &[0x40]); // shard "0"
        assert!(matches!(
            state
                .get_inclusion_proofs_batch(&[key(0x11)], ViewSelector::Latest)
                .await,
            Err(BatchProofError::UnsupportedConfiguration)
        ));
    }

    #[tokio::test]
    async fn batch_admission_is_bounded_and_released() {
        let state = new_state();
        let mut smt = MemSmt::new();
        round(&state, &mut smt, &[0x11], 1, &[0x80]);
        let limit = state.retention_limits().max_active_batches;
        let held: Vec<_> = (0..limit)
            .map(|_| Arc::clone(&state.batch_permits).try_acquire_owned().unwrap())
            .collect();
        assert!(matches!(
            state
                .get_inclusion_proofs_batch(&[key(0x11)], ViewSelector::Latest)
                .await,
            Err(BatchProofError::Busy(BusyKind::ActiveRequests))
        ));
        drop(held);
        // The shared proof-work budget also binds batches.
        let held: Vec<_> = (0..CERTIFIED_PROOF_MAX_IN_FLIGHT)
            .map(|_| Arc::clone(&state.proof_permits).try_acquire_owned().unwrap())
            .collect();
        assert!(matches!(
            state
                .get_inclusion_proofs_batch(&[key(0x11)], ViewSelector::Latest)
                .await,
            Err(BatchProofError::Busy(BusyKind::ActiveRequests))
        ));
        drop(held);
        state
            .get_inclusion_proofs_batch(&[key(0x11)], ViewSelector::Latest)
            .await
            .unwrap();
        assert_eq!(state.batch_permits.available_permits(), limit);
        assert_eq!(state.proof_permits.available_permits(), CERTIFIED_PROOF_MAX_IN_FLIGHT);
        assert!(state.catalog_stats().rejected_busy >= 2);
    }

    #[test]
    fn the_batch_limit_can_be_reconfigured_at_startup() {
        let state = new_state();
        state.set_retention_limits(RetentionLimits {
            max_active_batches: 2,
            ..RetentionLimits::default()
        });
        assert_eq!(state.batch_permits.available_permits(), 2);
        state.set_retention_limits(RetentionLimits {
            max_active_batches: 5,
            ..RetentionLimits::default()
        });
        assert_eq!(state.batch_permits.available_permits(), 5);
    }
}
