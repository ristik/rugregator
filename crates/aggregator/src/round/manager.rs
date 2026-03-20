//! Round manager – speculative round processing.
//!
//! State machine (in-memory path):
//! ```text
//! COLLECTING ──(timer | batch_limit)──> start_round_in_memory()
//!   acquires certified_smt lock briefly (snapshot creation), sends CR to BFT Core,
//!   forks snapshot for next block, returns immediately (self.inflight = Some).
//!
//! INFLIGHT ──(requests arrive)──> inserted speculatively into spec_snap
//!          ──(UC arrives via uc_rx)──> on_uc_result()
//!              Case A: commits proposed_snap to certified_smt (brief lock), finalizes block,
//!                      immediately promotes spec round (if non-empty).
//!              Case B: discards both snapshots, re-queues all requests.
//! ```
//!
//! Proof generation is NOT pre-computed.  HTTP handlers call
//! `AggregatorState::get_inclusion_proof`, which locks `certified_smt` and
//! calls `get_path` on the latest certified tree.  The path root always equals
//! the latest UC's `InputRecord.hash` by construction.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, info, warn, error};

use crate::config::RoundConfig;
use crate::smt::{SmtSnapshot, SparseMerkleTree, state_id_to_smt_path};
use crate::storage::{AggregatorState, BlockInfo, FinalizedRecord};
use crate::validation::ValidatedRequest;
use crate::validation::state_id::compute_cert_data_hash_imprint;
use crate::api::cbor::CertDataFields;
#[cfg(feature = "rocksdb-storage")]
use super::state::ProcessedRecord;
use async_trait::async_trait;

// ─── BftCommitter trait ───────────────────────────────────────────────────────

/// BFT Core interface.  Replace the stub with the real implementation once
/// BFT Core connectivity is in place.
#[async_trait]
pub trait BftCommitter: Send + Sync {
    /// Submit a block for certification.  Fire-and-forget; the UC arrives via
    /// `wait_for_uc`.
    async fn commit_block(
        &self,
        block_number: u64,
        new_root: &[u8; 34],
        prev_root: &[u8; 34],
        zk_proof: Option<Vec<u8>>,
    ) -> anyhow::Result<()>;

    /// Wait for the UnicityCertificate for `block_number`.
    /// Returns the raw CBOR bytes of the UC.
    async fn wait_for_uc(&self, block_number: u64) -> anyhow::Result<Vec<u8>>;
}

// ─── Stub implementation ──────────────────────────────────────────────────────

/// A test BFT committer that generates a self-signed UnicityCertificate.
///
/// Uses a hardcoded secp256k1 test private key.  The corresponding public key
/// (`STUB_PUBKEY_HEX`) must be configured in the e2e test's trust-base.json.
pub struct BftCommitterStub {
    /// Root hash captured in `commit_block`, consumed by `wait_for_uc`.
    pending_root: Mutex<[u8; 34]>,
}

impl BftCommitterStub {
    /// Test private key (32 bytes of 0x07).
    /// Matching compressed pubkey: 0x02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f
    const PRIVATE_KEY: [u8; 32] = [7u8; 32];
    /// Node ID used in the signatures map (must match trust-base.json).
    const NODE_ID: &'static str = "NODE";

    pub fn new() -> Self {
        Self { pending_root: Mutex::new([0u8; 34]) }
    }
}

#[async_trait]
impl BftCommitter for BftCommitterStub {
    async fn commit_block(
        &self,
        block_number: u64,
        new_root: &[u8; 34],
        _prev_root: &[u8; 34],
        _zk_proof: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        info!(block = block_number, root = %hex::encode(new_root), "BftCommitterStub: commit_block");
        *self.pending_root.lock().unwrap() = *new_root;
        Ok(())
    }

    async fn wait_for_uc(&self, block_number: u64) -> anyhow::Result<Vec<u8>> {
        let root = *self.pending_root.lock().unwrap();
        info!(block = block_number, "BftCommitterStub: generating stub UC");
        Ok(stub_generate_uc(block_number, &root, Self::PRIVATE_KEY, Self::NODE_ID))
    }
}

// ─── Stub UC generation ───────────────────────────────────────────────────────

/// Minimal CBOR helpers — produce standard CBOR bytes identical to the
/// TypeScript SDK's CborSerializer for the value ranges we use.

fn cbor_uint(n: u64) -> Vec<u8> {
    if n < 24 { vec![n as u8] }
    else if n < 0x100 { vec![0x18, n as u8] }
    else if n < 0x10000 { vec![0x19, (n >> 8) as u8, n as u8] }
    else if n < 0x1_0000_0000 {
        vec![0x1A, (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    } else {
        let mut v = vec![0x1B]; v.extend_from_slice(&n.to_be_bytes()); v
    }
}

fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let n = data.len();
    let mut hdr = if n < 24 { vec![0x40 | n as u8] }
        else if n < 0x100 { vec![0x58, n as u8] }
        else { vec![0x59, (n >> 8) as u8, n as u8] };
    hdr.extend_from_slice(data);
    hdr
}

fn cbor_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let n = b.len();
    let mut hdr = if n < 24 { vec![0x60 | n as u8] }
        else if n < 0x100 { vec![0x78, n as u8] }
        else { vec![0x79, (n >> 8) as u8, n as u8] };
    hdr.extend_from_slice(b);
    hdr
}

fn cbor_null() -> Vec<u8> { vec![0xF6] }

fn cbor_array(items: &[&[u8]]) -> Vec<u8> {
    let n = items.len();
    let mut v = if n < 24 { vec![0x80 | n as u8] }
        else { vec![0x98, n as u8] };
    for item in items { v.extend_from_slice(item); }
    v
}

fn cbor_map1(k: &[u8], val: &[u8]) -> Vec<u8> {
    let mut v = vec![0xA1];
    v.extend_from_slice(k);
    v.extend_from_slice(val);
    v
}

fn cbor_tag(tag: u64, data: &[u8]) -> Vec<u8> {
    let mut hdr = if tag < 24 { vec![0xC0 | tag as u8] }
        else if tag < 0x100 { vec![0xD8, tag as u8] }
        else if tag < 0x10000 { vec![0xD9, (tag >> 8) as u8, tag as u8] }
        else { vec![0xDA, (tag >> 24) as u8, (tag >> 16) as u8, (tag >> 8) as u8, tag as u8] };
    hdr.extend_from_slice(data);
    hdr
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Generate a minimal valid UnicityCertificate CBOR for stub use.
///
/// Structure mirrors the TypeScript `createUnicityCertificate` fixture:
/// - version, networkId, epoch, etc. = 0
/// - InputRecord.hash = new_root (34-byte imprint)
/// - shardConfigurationHash = 32 zero bytes
/// - ShardTreeCertificate: empty shard, no siblings
/// - UnicityTreeCertificate: version=0, partitionId=0, no steps
/// - UnicitySeal: signed by `private_key`, signatures keyed by `node_id`
fn stub_generate_uc(block_number: u64, new_root: &[u8; 34], private_key: [u8; 32], node_id: &str) -> Vec<u8> {
    use secp256k1::{Message, Secp256k1, SecretKey};

    // ── InputRecord (tag 1008) ────────────────────────────────────────────────
    let input_record_inner = cbor_array(&[
        &cbor_uint(0),           // version
        &cbor_uint(block_number),// roundNumber
        &cbor_uint(0),           // epoch
        &cbor_null(),            // previousHash
        &cbor_bytes(new_root),   // hash = 34-byte imprint
        &cbor_bytes(&[]),        // summaryValue = []
        &cbor_uint(0),           // timestamp
        &cbor_null(),            // blockHash
        &cbor_uint(0),           // sumOfEarnedFees
        &cbor_null(),            // executedTransactionsHash
    ]);
    let input_record_cbor = cbor_tag(1008, &input_record_inner);

    // ── shardConfigurationHash ────────────────────────────────────────────────
    let shard_config = [0u8; 32];

    // ── shardTreeCertificateRootHash ──────────────────────────────────────────
    // = SHA256(inputRecord.toCBOR() || encodeNull() || encodeByteString(shardConfigHash))
    let mut shard_root_preimage = Vec::new();
    shard_root_preimage.extend_from_slice(&input_record_cbor);
    shard_root_preimage.extend_from_slice(&cbor_null());
    shard_root_preimage.extend_from_slice(&cbor_bytes(&shard_config));
    let shard_root_hash: [u8; 32] = sha256(&shard_root_preimage);

    // ── sealHashValue ─────────────────────────────────────────────────────────
    // = SHA256(cbor_bytes([0x01]) || cbor_bytes([0,0,0,0]) || cbor_bytes(SHA256(cbor_bytes(shardRoot))))
    let inner_hash = sha256(&cbor_bytes(&shard_root_hash));
    let mut seal_hash_preimage = Vec::new();
    seal_hash_preimage.extend_from_slice(&cbor_bytes(&[0x01u8]));
    seal_hash_preimage.extend_from_slice(&cbor_bytes(&[0u8, 0, 0, 0]));
    seal_hash_preimage.extend_from_slice(&cbor_bytes(&inner_hash));
    let seal_hash_value: [u8; 32] = sha256(&seal_hash_preimage);

    // ── UnicitySeal WITHOUT signatures (for hash computation) ─────────────────
    let seal_no_sigs_inner = cbor_array(&[
        &cbor_uint(0),                   // version
        &cbor_uint(0),                   // networkId
        &cbor_uint(block_number),        // rootChainRoundNumber
        &cbor_uint(0),                   // epoch
        &cbor_uint(0),                   // timestamp
        &cbor_null(),                    // previousHash
        &cbor_bytes(&seal_hash_value),   // hash (32 bytes)
        &cbor_null(),                    // signatures = null
    ]);
    let seal_no_sigs_cbor = cbor_tag(1001, &seal_no_sigs_inner);

    // ── actual seal hash = SHA256(seal_without_sigs_cbor) ────────────────────
    let actual_seal_hash: [u8; 32] = sha256(&seal_no_sigs_cbor);

    // ── Sign with private key ─────────────────────────────────────────────────
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&private_key).expect("valid test key");
    let msg = Message::from_digest(actual_seal_hash);
    let (recovery_id, compact) = secp.sign_ecdsa_recoverable(&msg, &sk).serialize_compact();
    // Signature format: [R(32) || S(32) || V(1)] — 65 bytes
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&compact);
    sig_bytes[64] = recovery_id.to_i32() as u8;

    // ── UnicitySeal WITH signatures ───────────────────────────────────────────
    let sig_map = cbor_map1(&cbor_text(node_id), &cbor_bytes(&sig_bytes));
    let seal_inner = cbor_array(&[
        &cbor_uint(0),
        &cbor_uint(0),
        &cbor_uint(block_number),
        &cbor_uint(0),
        &cbor_uint(0),
        &cbor_null(),
        &cbor_bytes(&seal_hash_value),
        &sig_map,
    ]);
    let seal_cbor = cbor_tag(1001, &seal_inner);

    // ── ShardTreeCertificate ──────────────────────────────────────────────────
    let shard_tree_cert = cbor_array(&[
        &cbor_bytes(&[]),    // shard = empty bytes
        &cbor_array(&[]),    // siblingHashList = []
    ]);

    // ── UnicityTreeCertificate (tag 1014) ─────────────────────────────────────
    let utc_inner = cbor_array(&[
        &cbor_uint(0),   // version
        &cbor_uint(0),   // partitionIdentifier
        &cbor_array(&[]),// steps = []
    ]);
    let unicity_tree_cert = cbor_tag(1014, &utc_inner);

    // ── UnicityCertificate (tag 1007) ─────────────────────────────────────────
    let uc_inner = cbor_array(&[
        &cbor_uint(0),
        &input_record_cbor,
        &cbor_null(),
        &cbor_bytes(&shard_config),
        &shard_tree_cert,
        &unicity_tree_cert,
        &seal_cbor,
    ]);
    cbor_tag(1007, &uc_inner)
}

// ─── SmtBackend ───────────────────────────────────────────────────────────────

/// Selects the SMT implementation used by the round manager.
pub enum SmtBackend {
    /// Pure in-memory tree (shared with AggregatorState via `certified_smt`).
    InMemory,
    /// Disk-backed tree via RocksDB (enabled by `rocksdb-storage` feature).
    #[cfg(feature = "rocksdb-storage")]
    DiskBacked(crate::smt_disk::DiskBackedSmt),
}

// ─── InFlightRound ────────────────────────────────────────────────────────────

/// State of a round that has been proposed to BFT Core and is awaiting its UC.
///
/// While waiting, incoming requests are inserted speculatively into `spec_snap`
/// (a fork of `proposed_snap`).  On UC success both are kept; on rollback both
/// are discarded and all requests are re-queued.
struct InFlightRound {
    block_number: u64,
    /// New SMT root hash submitted for certification.
    new_root: [u8; 34],
    /// The snapshot that was proposed (committed on Case A success).
    proposed_snap: SmtSnapshot,
    /// Fork of `proposed_snap` accumulating the next block speculatively.
    spec_snap: SmtSnapshot,
    /// ALL requests attempted in this batch (for rollback re-queuing).
    submitted_batch: Vec<ValidatedRequest>,
    /// Requests successfully inserted into `proposed_snap` (for RecordInfo).
    inserted: Vec<ValidatedRequest>,
    /// ALL spec requests attempted (for rollback + next round).
    spec_batch: Vec<ValidatedRequest>,
    /// Spec requests successfully inserted into `spec_snap` (for RecordInfo).
    spec_inserted: Vec<ValidatedRequest>,
}

// ─── RoundManager ─────────────────────────────────────────────────────────────

pub struct RoundManager {
    config: RoundConfig,
    request_rx: mpsc::Receiver<ValidatedRequest>,
    pending: Vec<ValidatedRequest>,
    smt: SmtBackend,
    current_root: [u8; 34],
    state: Arc<AggregatorState>,
    bft: Arc<dyn BftCommitter>,
    /// Shared reference to the latest certified SMT (also held by AggregatorState).
    ///
    /// Updated (under the mutex) after each successful round finalization.
    /// HTTP handlers read this tree to generate on-demand inclusion proofs.
    certified_smt: Arc<tokio::sync::Mutex<SparseMerkleTree>>,
    /// In-flight round (Some while waiting for a UC from BFT Core).
    inflight: Option<InFlightRound>,
    /// Sender half of the UC notification channel (cloned into spawned tasks).
    uc_tx: mpsc::Sender<anyhow::Result<Vec<u8>>>,
    /// Receiver half of the UC notification channel.
    uc_rx: mpsc::Receiver<anyhow::Result<Vec<u8>>>,
}

impl RoundManager {
    pub fn new(
        config: RoundConfig,
        request_rx: mpsc::Receiver<ValidatedRequest>,
        state: Arc<AggregatorState>,
        bft: Arc<dyn BftCommitter>,
    ) -> Self {
        let certified_smt = state.certified_smt_arc();
        let initial_root = SparseMerkleTree::new().root_hash_imprint();
        let (uc_tx, uc_rx) = mpsc::channel(4);
        Self {
            config,
            request_rx,
            pending: Vec::new(),
            smt: SmtBackend::InMemory,
            current_root: initial_root,
            state,
            bft,
            certified_smt,
            inflight: None,
            uc_tx,
            uc_rx,
        }
    }

    pub fn new_with_smt(
        config: RoundConfig,
        request_rx: mpsc::Receiver<ValidatedRequest>,
        state: Arc<AggregatorState>,
        bft: Arc<dyn BftCommitter>,
        smt: SparseMerkleTree,
    ) -> Self {
        let certified_smt = state.certified_smt_arc();
        // Replace the empty tree in the Arc with the provided smt.
        // This is called before any tasks run, so try_lock always succeeds.
        let current_root = if let Ok(mut guard) = certified_smt.try_lock() {
            *guard = smt;
            guard.root_hash_imprint()
        } else {
            SparseMerkleTree::new().root_hash_imprint()
        };
        let (uc_tx, uc_rx) = mpsc::channel(4);
        Self {
            config, request_rx, pending: Vec::new(),
            smt: SmtBackend::InMemory, current_root, state, bft,
            certified_smt, inflight: None, uc_tx, uc_rx,
        }
    }

    #[cfg(feature = "rocksdb-storage")]
    pub fn new_with_disk_smt(
        config: RoundConfig,
        request_rx: mpsc::Receiver<ValidatedRequest>,
        state: Arc<AggregatorState>,
        bft: Arc<dyn BftCommitter>,
        mut store: crate::smt_disk::DiskBackedSmt,
    ) -> Self {
        let current_root = store.root_hash_imprint();
        let certified_smt = state.certified_smt_arc();
        let (uc_tx, uc_rx) = mpsc::channel(4);
        Self {
            config, request_rx, pending: Vec::new(),
            smt: SmtBackend::DiskBacked(store), current_root, state, bft,
            certified_smt, inflight: None, uc_tx, uc_rx,
        }
    }

    // ── Event loop ────────────────────────────────────────────────────────────

    /// Run the round manager event loop.
    pub async fn run(mut self) {
        let mut timer = time::interval(Duration::from_millis(self.config.round_duration_ms));
        timer.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    // Only start a new round when nothing is in-flight.
                    if self.inflight.is_none() && !self.pending.is_empty() {
                        self.start_round().await;
                    }
                }
                Some(req) = self.request_rx.recv() => {
                    if self.inflight.is_some() && matches!(self.smt, SmtBackend::InMemory) {
                        // In-flight: insert speculatively into the next block's snapshot.
                        self.insert_speculative(req);
                    } else {
                        self.pending.push(req);
                        if self.inflight.is_none() && self.pending.len() >= self.config.batch_limit {
                            self.start_round().await;
                        }
                    }
                }
                Some(uc_result) = self.uc_rx.recv() => {
                    self.on_uc_result(uc_result).await;
                }
            }
        }
    }

    // ── Round startup ─────────────────────────────────────────────────────────

    /// Kick off a new round from `self.pending`.
    ///
    /// For the in-memory path: non-blocking — sets `self.inflight` and returns.
    /// For the disk path: sequential — blocks until the round is fully finalized.
    async fn start_round(&mut self) {
        let batch: Vec<ValidatedRequest> = std::mem::take(&mut self.pending);
        if batch.is_empty() { return; }

        let block_number = self.state.current_block_number().await;
        info!(block = block_number, count = batch.len(), "starting round");

        match self.smt {
            SmtBackend::InMemory => {
                self.start_round_in_memory(batch, block_number).await;
            }
            #[cfg(feature = "rocksdb-storage")]
            SmtBackend::DiskBacked(_) => {
                let backend = std::mem::replace(&mut self.smt, SmtBackend::InMemory);
                if let SmtBackend::DiskBacked(store) = backend {
                    let new_store = self.process_round_disk(store, batch, block_number).await;
                    self.smt = SmtBackend::DiskBacked(new_store);
                }
            }
        }
    }

    /// Propose a round using the in-memory SMT (non-blocking).
    ///
    /// Briefly locks `certified_smt` to clone the current certified state into
    /// a snapshot, inserts `batch`, then forks the snapshot for speculative
    /// next-block work.  Spawns a task to await the UC and deliver it via
    /// `uc_rx`.  Sets `self.inflight` and returns.
    async fn start_round_in_memory(
        &mut self,
        batch: Vec<ValidatedRequest>,
        block_number: u64,
    ) {
        // Create snapshot from the latest certified state (brief mutex lock).
        let mut proposed_snap = {
            let smt = self.certified_smt.lock().await;
            SmtSnapshot::create(&*smt)
        };

        let mut inserted: Vec<ValidatedRequest> = Vec::with_capacity(batch.len());

        for req in &batch {
            let path       = state_id_to_smt_path(&req.state_id);
            let leaf_value = compute_cert_data_hash_imprint(
                &req.predicate_cbor, &req.source_state_hash,
                &req.transaction_hash, &req.witness,
            );
            match proposed_snap.add_leaf(path, leaf_value.to_vec()) {
                Ok(()) => { inserted.push(req.clone()); }
                Err(crate::smt::SmtError::DuplicateLeaf) => {
                    debug!(state_id = %hex::encode(&req.state_id), "skipping existing leaf");
                }
                Err(e) => {
                    warn!(state_id = %hex::encode(&req.state_id), err = %e, "leaf insert failed");
                }
            }
        }

        let new_root  = proposed_snap.root_hash_imprint();
        let prev_root = self.current_root;

        // Fork the proposed snapshot for speculative next-block work.
        let spec_snap = proposed_snap.fork();

        if let Err(e) = self.bft.commit_block(block_number, &new_root, &prev_root, None).await {
            error!(block = block_number, err = %e, "commit_block failed — rolling back");
            proposed_snap.discard();
            spec_snap.discard();
            self.pending.extend(batch);
            return;
        }

        // Spawn a task to await the UC and deliver it via the channel.
        let bft   = Arc::clone(&self.bft);
        let uc_tx = self.uc_tx.clone();
        tokio::spawn(async move {
            let result = bft.wait_for_uc(block_number).await;
            let _ = uc_tx.send(result).await;
        });

        info!(
            block = block_number, count = batch.len(), root = %hex::encode(new_root),
            "round proposed, waiting for UC (speculative next-block enabled)"
        );

        self.inflight = Some(InFlightRound {
            block_number,
            new_root,
            proposed_snap,
            spec_snap,
            submitted_batch: batch,
            inserted,
            spec_batch:    Vec::new(),
            spec_inserted: Vec::new(),
        });
    }

    /// Immediately start the next round from a pre-built speculative snapshot.
    ///
    /// Called after a successful UC when `spec_batch` is non-empty.  Avoids
    /// re-doing the SMT insertions already performed speculatively.
    async fn start_round_from_spec(
        &mut self,
        block_number: u64,
        mut spec_snap: SmtSnapshot,
        spec_batch: Vec<ValidatedRequest>,
        spec_inserted: Vec<ValidatedRequest>,
    ) {
        let new_root  = spec_snap.root_hash_imprint();
        let prev_root = self.current_root;
        let count     = spec_batch.len();

        // Fork for the layer after this one.
        let new_spec_snap = spec_snap.fork();

        if let Err(e) = self.bft.commit_block(block_number, &new_root, &prev_root, None).await {
            error!(block = block_number, err = %e, "commit_block (spec promotion) failed — rolling back");
            spec_snap.discard();
            new_spec_snap.discard();
            self.pending.extend(spec_batch);
            return;
        }

        let bft   = Arc::clone(&self.bft);
        let uc_tx = self.uc_tx.clone();
        tokio::spawn(async move {
            let result = bft.wait_for_uc(block_number).await;
            let _ = uc_tx.send(result).await;
        });

        info!(
            block = block_number, count, root = %hex::encode(new_root),
            "spec round promoted immediately, waiting for UC"
        );

        self.inflight = Some(InFlightRound {
            block_number,
            new_root,
            proposed_snap:  spec_snap,
            spec_snap:      new_spec_snap,
            submitted_batch: spec_batch,
            inserted:        spec_inserted,
            spec_batch:      Vec::new(),
            spec_inserted:   Vec::new(),
        });

        // Drain any pending requests into the new speculative layer.
        let pending = std::mem::take(&mut self.pending);
        for req in pending {
            self.insert_speculative(req);
        }
    }

    // ── Speculative insertion ─────────────────────────────────────────────────

    /// Insert `req` speculatively into the in-flight round's `spec_snap`.
    fn insert_speculative(&mut self, req: ValidatedRequest) {
        let inf = match self.inflight.as_mut() {
            Some(i) => i,
            None => { self.pending.push(req); return; }
        };

        let path       = state_id_to_smt_path(&req.state_id);
        let leaf_value = compute_cert_data_hash_imprint(
            &req.predicate_cbor, &req.source_state_hash,
            &req.transaction_hash, &req.witness,
        );

        match inf.spec_snap.add_leaf(path, leaf_value.to_vec()) {
            Ok(()) => {
                inf.spec_inserted.push(req.clone());
                inf.spec_batch.push(req);
            }
            Err(crate::smt::SmtError::DuplicateLeaf) => {
                debug!(state_id = %hex::encode(&req.state_id), "skipping duplicate in spec");
            }
            Err(e) => {
                warn!(state_id = %hex::encode(&req.state_id), err = %e, "spec leaf insert failed");
            }
        }
    }

    // ── UC arrival ────────────────────────────────────────────────────────────

    /// Handle the UC result for the current in-flight round.
    ///
    /// Case A (success): commits the proposed snapshot to `certified_smt` (briefly
    /// locking the mutex), builds `FinalizedRecord`s (no pre-computed paths),
    /// finalizes the block, then immediately promotes the speculative snapshot
    /// as the next round (if non-empty).
    ///
    /// Case B (failure): discards both snapshots, re-queues all requests.
    async fn on_uc_result(&mut self, uc_result: anyhow::Result<Vec<u8>>) {
        let inf = match self.inflight.take() {
            Some(i) => i,
            None => { warn!("UC arrived but no inflight round"); return; }
        };

        match uc_result {
            Ok(uc_cbor) => {
                // Commit the proposed snapshot to the shared certified SMT.
                // Proof generation in HTTP handlers will see this new root
                // = inf.new_root = what the UC certifies.
                {
                    let mut smt = self.certified_smt.lock().await;
                    inf.proposed_snap.commit(&mut *smt);
                }
                self.current_root = inf.new_root;

                // Build FinalizedRecord for each successfully inserted request.
                // merkle_path_cbor is None — generated on-demand at query time.
                let finalized: Vec<FinalizedRecord> = inf.inserted.iter()
                    .map(|req| FinalizedRecord {
                        state_id_hex: hex::encode(&req.state_id),
                        block_number: inf.block_number,
                        cert_data: CertDataFields {
                            predicate_cbor:    req.predicate_cbor.clone(),
                            source_state_hash: req.source_state_hash.clone(),
                            transaction_hash:  req.transaction_hash.clone(),
                            witness:           req.witness.clone(),
                        },
                        merkle_path_cbor: None,
                    })
                    .collect();

                let certified_count = finalized.len();
                let submitted_count = inf.submitted_batch.len();
                let spec_count      = inf.spec_batch.len();

                self.state.finalize_round(BlockInfo {
                    block_number: inf.block_number,
                    root_hash: inf.new_root,
                    uc_cbor,
                }, finalized).await;

                info!(
                    block      = inf.block_number,
                    root       = %hex::encode(inf.new_root),
                    certified  = certified_count,
                    submitted  = submitted_count,
                    spec_queued = spec_count,
                    "round finalized"
                );

                // Promote speculative work: immediately start the next round.
                if !inf.spec_batch.is_empty() {
                    let next_block = self.state.current_block_number().await;
                    self.start_round_from_spec(
                        next_block, inf.spec_snap, inf.spec_batch, inf.spec_inserted,
                    ).await;
                } else {
                    inf.spec_snap.discard();
                }
            }
            Err(e) => {
                // UC failed (repeat UC / rollback) — discard speculative work.
                error!(block = inf.block_number, err = %e, "UC failed — rolling back");
                inf.proposed_snap.discard();
                inf.spec_snap.discard();
                self.pending.extend(inf.submitted_batch);
                self.pending.extend(inf.spec_batch);
            }
        }
    }

    // ── Disk-backed path (sequential, no speculative execution) ───────────────

    #[cfg(feature = "rocksdb-storage")]
    async fn process_round_disk(
        &mut self,
        mut store: crate::smt_disk::DiskBackedSmt,
        batch: Vec<ValidatedRequest>,
        block_number: u64,
    ) -> crate::smt_disk::DiskBackedSmt {
        use crate::smt_disk::DiskSmtSnapshot;
        use crate::smt::proof::merkle_path_to_cbor;

        let mut snapshot = DiskSmtSnapshot::create(&mut store);
        let mut processed: Vec<ProcessedRecord> = Vec::with_capacity(batch.len());

        for req in &batch {
            let path      = state_id_to_smt_path(&req.state_id);
            let leaf_value = compute_cert_data_hash_imprint(
                &req.predicate_cbor, &req.source_state_hash,
                &req.transaction_hash, &req.witness,
            );

            match snapshot.add_leaf(path.clone(), leaf_value.to_vec()) {
                Ok(()) => {}
                Err(crate::smt::SmtError::DuplicateLeaf) => {
                    debug!(state_id = %hex::encode(&req.state_id), "skipping existing leaf (disk)");
                    continue;
                }
                Err(e) => {
                    warn!(state_id = %hex::encode(&req.state_id), err = %e, "leaf insertion failed (disk)");
                    continue;
                }
            }

            processed.push(ProcessedRecord {
                state_id_hex: hex::encode(&req.state_id),
                cert_data: CertDataFields {
                    predicate_cbor:    req.predicate_cbor.clone(),
                    source_state_hash: req.source_state_hash.clone(),
                    transaction_hash:  req.transaction_hash.clone(),
                    witness:           req.witness.clone(),
                },
            });
        }

        let new_root = match snapshot.root_hash_imprint() {
            Ok(r) => r,
            Err(e) => {
                error!(block = block_number, err = %e, "root_hash_imprint failed — rolling back");
                snapshot.discard();
                self.pending.extend(batch);
                return store;
            }
        };
        let prev_root = self.current_root;

        if let Err(e) = self.bft.commit_block(block_number, &new_root, &prev_root, None).await {
            error!(block = block_number, err = %e, "commit_block failed — rolling back");
            snapshot.discard();
            self.pending.extend(batch);
            return store;
        }

        let uc_cbor = match self.bft.wait_for_uc(block_number).await {
            Ok(uc) => uc,
            Err(e) => {
                error!(block = block_number, err = %e, "wait_for_uc failed — rolling back");
                snapshot.discard();
                self.pending.extend(batch);
                return store;
            }
        };

        // Commit overlay to DB.
        if let Err(e) = snapshot.commit(new_root) {
            error!(block = block_number, err = %e, "overlay commit failed");
            return store;
        }
        self.current_root = new_root;

        // Generate and store inclusion proofs (disk path: precomputed, cached).
        let finalized = self.generate_proofs_disk(&store, &processed, block_number);
        let certified_count = finalized.len();
        let submitted_count = batch.len();
        self.state.finalize_round(BlockInfo {
            block_number, root_hash: new_root, uc_cbor,
        }, finalized).await;

        info!(block = block_number, root = %hex::encode(new_root), certified = certified_count, submitted = submitted_count, "round finalized (disk)");
        store
    }

    #[cfg(feature = "rocksdb-storage")]
    fn generate_proofs_disk(
        &self,
        store:      &crate::smt_disk::DiskBackedSmt,
        processed:  &[ProcessedRecord],
        block_number: u64,
    ) -> Vec<FinalizedRecord> {
        use crate::smt_disk::overlay::Overlay;
        use crate::smt::proof::merkle_path_to_cbor;
        let empty = Overlay::new();
        let mut out = Vec::with_capacity(processed.len());

        for pr in processed {
            let state_id_bytes = hex::decode(&pr.state_id_hex).unwrap_or_default();
            let smt_path = state_id_to_smt_path(&state_id_bytes);

            let merkle_path = match store.get_path(&smt_path, &empty) {
                Ok(p) => p,
                Err(e) => { warn!(state_id = %pr.state_id_hex, err = %e, "get_path (disk) failed"); continue; }
            };
            let merkle_path_cbor = match merkle_path_to_cbor(&merkle_path) {
                Ok(b) => b,
                Err(e) => { warn!(state_id = %pr.state_id_hex, err = %e, "cbor encode failed"); continue; }
            };
            out.push(FinalizedRecord {
                state_id_hex: pr.state_id_hex.clone(),
                block_number,
                cert_data: pr.cert_data.clone(),
                merkle_path_cbor: Some(merkle_path_cbor),
            });
        }
        out
    }
}
