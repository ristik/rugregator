//! Round manager – speculative round processing.
//!
//! State machine:
//! ```text
//! COLLECTING ──(timer | batch_limit)──> start_round()
//!   creates snapshot, inserts batch, forks for speculative next-block work,
//!   sends to BFT Core, sets self.inflight.
//!
//! INFLIGHT ──(requests arrive)──> inserted speculatively into spec_snap
//!          ──(UC arrives via uc_rx)──> on_uc_result()
//!              Case A: commits proposed_snap, pre-computes proofs, finalizes block,
//!                      immediately promotes spec round (if non-empty).
//!              Case B: discards both snapshots, re-queues all requests.
//! ```

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Notify};
use tokio::time;
use tracing::{error, info, warn};

use super::state::ProcessedRecord;
use crate::api::cbor::CertDataFields;
use crate::config::RoundConfig;
use crate::smt::state_id_to_smt_key;
use crate::storage::{AggregatorState, BlockInfo, FinalizedRecord, PendingRound, WalRecord, WalStore};
use crate::validation::state_id::compute_cert_data_hash;
use crate::validation::ValidatedRequest;
use async_trait::async_trait;

use rayon::prelude::*;
use smt_store::{SmtStore, SmtStoreSnapshot};

// ─── BftCommitter trait ───────────────────────────────────────────────────────

/// BFT Core interface.
#[async_trait]
pub trait BftCommitter: Send + Sync {
    /// Submit a block for certification.
    async fn commit_block(
        &self,
        block_number: u64,
        new_root: Option<[u8; 32]>,
        prev_root: Option<[u8; 32]>,
        zk_proof: Option<Vec<u8>>,
        block_size: u64,
        state_size: u64,
    ) -> anyhow::Result<()>;

    /// Wait for the UnicityCertificate for `block_number`.
    async fn wait_for_uc(&self, block_number: u64) -> anyhow::Result<Vec<u8>>;
}

// ─── Stub implementation ──────────────────────────────────────────────────────

pub struct BftCommitterStub {
    pending_root: Mutex<Option<[u8; 32]>>,
}

impl BftCommitterStub {
    const PRIVATE_KEY: [u8; 32] = [7u8; 32];
    const NODE_ID: &'static str = "NODE";

    pub fn new() -> Self {
        Self {
            pending_root: Mutex::new(None),
        }
    }
}

#[async_trait]
impl BftCommitter for BftCommitterStub {
    async fn commit_block(
        &self,
        block_number: u64,
        new_root: Option<[u8; 32]>,
        _prev_root: Option<[u8; 32]>,
        _zk_proof: Option<Vec<u8>>,
        _block_size: u64,
        _state_size: u64,
    ) -> anyhow::Result<()> {
        let root_hex = new_root.map(|r| hex::encode(r)).unwrap_or_else(|| "empty".into());
        info!(block = block_number, root = %root_hex, "BftCommitterStub: commit_block");
        *self.pending_root.lock().unwrap() = new_root;
        Ok(())
    }

    async fn wait_for_uc(&self, block_number: u64) -> anyhow::Result<Vec<u8>> {
        let root = *self.pending_root.lock().unwrap();
        info!(block = block_number, "BftCommitterStub: generating stub UC");
        Ok(stub_generate_uc(
            block_number,
            root.as_ref(),
            Self::PRIVATE_KEY,
            Self::NODE_ID,
        ))
    }
}

// ─── Stub UC generation ───────────────────────────────────────────────────────

fn cbor_uint(n: u64) -> Vec<u8> {
    if n < 24 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x18, n as u8]
    } else if n < 0x10000 {
        vec![0x19, (n >> 8) as u8, n as u8]
    } else if n < 0x1_0000_0000 {
        vec![
            0x1A,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ]
    } else {
        let mut v = vec![0x1B];
        v.extend_from_slice(&n.to_be_bytes());
        v
    }
}

fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let n = data.len();
    let mut hdr = if n < 24 {
        vec![0x40 | n as u8]
    } else if n < 0x100 {
        vec![0x58, n as u8]
    } else {
        vec![0x59, (n >> 8) as u8, n as u8]
    };
    hdr.extend_from_slice(data);
    hdr
}

fn cbor_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let n = b.len();
    let mut hdr = if n < 24 {
        vec![0x60 | n as u8]
    } else if n < 0x100 {
        vec![0x78, n as u8]
    } else {
        vec![0x79, (n >> 8) as u8, n as u8]
    };
    hdr.extend_from_slice(b);
    hdr
}

fn cbor_null() -> Vec<u8> {
    vec![0xF6]
}

fn cbor_array(items: &[&[u8]]) -> Vec<u8> {
    let n = items.len();
    let mut v = if n < 24 {
        vec![0x80 | n as u8]
    } else {
        vec![0x98, n as u8]
    };
    for item in items {
        v.extend_from_slice(item);
    }
    v
}

fn cbor_map1(k: &[u8], val: &[u8]) -> Vec<u8> {
    let mut v = vec![0xA1];
    v.extend_from_slice(k);
    v.extend_from_slice(val);
    v
}

fn cbor_tag(tag: u64, data: &[u8]) -> Vec<u8> {
    let mut hdr = if tag < 24 {
        vec![0xC0 | tag as u8]
    } else if tag < 0x100 {
        vec![0xD8, tag as u8]
    } else if tag < 0x10000 {
        vec![0xD9, (tag >> 8) as u8, tag as u8]
    } else {
        vec![
            0xDA,
            (tag >> 24) as u8,
            (tag >> 16) as u8,
            (tag >> 8) as u8,
            tag as u8,
        ]
    };
    hdr.extend_from_slice(data);
    hdr
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

fn stub_generate_uc(
    block_number: u64,
    new_root: Option<&[u8; 32]>,
    private_key: [u8; 32],
    node_id: &str,
) -> Vec<u8> {
    use secp256k1::{Message, Secp256k1, SecretKey};

    let root_bytes: &[u8] = match new_root {
        Some(r) => r.as_slice(),
        None => &[],
    };

    let input_record_inner = cbor_array(&[
        &cbor_uint(0),
        &cbor_uint(block_number),
        &cbor_uint(0),
        &cbor_null(),
        &cbor_bytes(root_bytes),
        &cbor_bytes(&[]),
        &cbor_uint(0),
        &cbor_null(),
        &cbor_uint(0),
        &cbor_null(),
    ]);
    let input_record_cbor = cbor_tag(1008, &input_record_inner);

    let shard_config = [0u8; 32];

    let mut shard_root_preimage = Vec::new();
    shard_root_preimage.extend_from_slice(&input_record_cbor);
    shard_root_preimage.extend_from_slice(&cbor_null());
    shard_root_preimage.extend_from_slice(&cbor_bytes(&shard_config));
    let shard_root_hash: [u8; 32] = sha256(&shard_root_preimage);

    let inner_hash = sha256(&cbor_bytes(&shard_root_hash));
    let mut seal_hash_preimage = Vec::new();
    seal_hash_preimage.extend_from_slice(&cbor_bytes(&[0x01u8]));
    seal_hash_preimage.extend_from_slice(&cbor_bytes(&[0u8, 0, 0, 0]));
    seal_hash_preimage.extend_from_slice(&cbor_bytes(&inner_hash));
    let seal_hash_value: [u8; 32] = sha256(&seal_hash_preimage);

    let seal_no_sigs_inner = cbor_array(&[
        &cbor_uint(0),
        &cbor_uint(0),
        &cbor_uint(block_number),
        &cbor_uint(0),
        &cbor_uint(0),
        &cbor_null(),
        &cbor_bytes(&seal_hash_value),
        &cbor_null(),
    ]);
    let seal_no_sigs_cbor = cbor_tag(1001, &seal_no_sigs_inner);

    let actual_seal_hash: [u8; 32] = sha256(&seal_no_sigs_cbor);

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&private_key).expect("valid test key");
    let msg = Message::from_digest(actual_seal_hash);
    let (recovery_id, compact) = secp.sign_ecdsa_recoverable(&msg, &sk).serialize_compact();
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&compact);
    sig_bytes[64] = recovery_id.to_i32() as u8;

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

    let shard_tree_cert = cbor_array(&[&cbor_bytes(&[]), &cbor_array(&[])]);

    let utc_inner = cbor_array(&[&cbor_uint(0), &cbor_uint(0), &cbor_array(&[])]);
    let unicity_tree_cert = cbor_tag(1014, &utc_inner);

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

// ─── InFlightRound ────────────────────────────────────────────────────────────

/// Speculative next-round state, living alongside the inflight round.
///
/// - `Collecting`: `spec_snap` is a fresh fork off the inflight round's
///   `proposed_snap`; requests arriving during the UC wait accumulate in
///   `buffer` without touching the tree. When the round timer ticks or
///   `buffer.len() >= batch_limit`, [`RoundManager::prepare_spec`] runs a
///   single `insert_batch_with_proof` pass on `spec_snap` and transitions
///   to [`SpecState::Prepared`].
/// - `Prepared`: the speculative round's tree update **and** its
///   consistency-proof envelope have been computed in one pass. It is
///   waiting for the inflight round's UC so it can be submitted to BFT.
enum SpecState<S: SmtStore> {
    Collecting {
        snap: S::Snapshot,
        buffer: Vec<ValidatedRequest>,
    },
    Prepared {
        snap: S::Snapshot,
        new_root: Option<[u8; 32]>,
        zk_proof: Option<Vec<u8>>,
        batch: Vec<ValidatedRequest>,
        inserted: Vec<ProcessedRecord>,
        dropped: usize,
    },
}

impl<S: SmtStore> SpecState<S> {
    fn discard(self) {
        match self {
            SpecState::Collecting { snap, .. } => snap.discard(),
            SpecState::Prepared { snap, .. } => snap.discard(),
        }
    }
}

/// State of a round that has been proposed to BFT Core and is awaiting its UC.
struct InFlightRound<S: SmtStore> {
    block_number: u64,
    new_root: Option<[u8; 32]>,
    proposed_snap: S::Snapshot,
    spec: SpecState<S>,
    submitted_batch: Vec<ValidatedRequest>,
    inserted: Vec<ProcessedRecord>,
    dropped: usize,
}

// ─── RoundManager ─────────────────────────────────────────────────────────────

pub struct RoundManager<S: SmtStore> {
    config: RoundConfig,
    request_rx: mpsc::Receiver<ValidatedRequest>,
    pending: Vec<ValidatedRequest>,
    smt: S,
    current_root: Option<[u8; 32]>,
    /// Total number of leaves committed to the SMT (across all rounds).
    leaf_count: u64,
    state: Arc<AggregatorState>,
    bft: Arc<dyn BftCommitter>,
    inflight: Option<InFlightRound<S>>,
    uc_tx: mpsc::Sender<anyhow::Result<Vec<u8>>>,
    uc_rx: mpsc::Receiver<anyhow::Result<Vec<u8>>>,
    shutdown_notify: Arc<Notify>,
    /// Write-ahead log: written before every BFT submission, cleared atomically
    /// with `persist_round`.  `None` for in-memory (non-persistent) backends.
    wal: Option<Arc<dyn WalStore>>,
}

impl RoundManager<smt_store::MemSmt> {
    /// Create a new in-memory round manager.
    pub fn new(
        config: RoundConfig,
        request_rx: mpsc::Receiver<ValidatedRequest>,
        state: Arc<AggregatorState>,
        bft: Arc<dyn BftCommitter>,
    ) -> Self {
        Self::with_smt(config, request_rx, state, bft, smt_store::MemSmt::new())
    }
}

impl RoundManager<smt_store::DiskSmt> {
    /// Create a round manager backed by a disk SMT.
    pub fn new_with_disk_smt(
        config: RoundConfig,
        request_rx: mpsc::Receiver<ValidatedRequest>,
        state: Arc<AggregatorState>,
        bft: Arc<dyn BftCommitter>,
        store: smt_store::DiskSmt,
    ) -> Self {
        Self::with_smt(config, request_rx, state, bft, store)
    }
}

impl<S: SmtStore> RoundManager<S> {
    /// Generic constructor — works with any `SmtStore` implementation.
    pub fn with_smt(
        config: RoundConfig,
        request_rx: mpsc::Receiver<ValidatedRequest>,
        state: Arc<AggregatorState>,
        bft: Arc<dyn BftCommitter>,
        smt: S,
    ) -> Self {
        let current_root = smt.root_hash();
        let (uc_tx, uc_rx) = mpsc::channel(4);
        Self {
            config,
            request_rx,
            pending: Vec::new(),
            smt,
            current_root,
            leaf_count: 0,
            state,
            bft,
            inflight: None,
            uc_tx,
            uc_rx,
            shutdown_notify: Arc::new(Notify::new()),
            wal: None,
        }
    }

    /// Attach a write-ahead log store.  Call this for disk-backed backends
    /// to enable pre-BFT crash safety.
    pub fn with_wal(mut self, wal: Arc<dyn WalStore>) -> Self {
        self.wal = Some(wal);
        self
    }

    /// Get a handle that can be used to signal graceful shutdown.
    pub fn shutdown_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.shutdown_notify)
    }

    /// Run the round manager event loop.
    pub async fn run(mut self) {
        // On startup, replay any round that was in-flight when the process last crashed.
        self.recover_pending_round().await;

        let mut timer = time::interval(Duration::from_millis(self.config.round_duration_ms));
        timer.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    self.on_timer_tick().await;
                }
                Some(req) = self.request_rx.recv() => {
                    self.handle_new_request(req).await;
                }
                Some(uc_result) = self.uc_rx.recv() => {
                    self.on_uc_result(uc_result).await;
                }
                _ = self.shutdown_notify.notified() => {
                    info!("shutdown signal received, stopping round manager");
                    break;
                }
            }
        }

        // Discard any in-flight round — its state hasn't been committed.
        if let Some(inf) = self.inflight.take() {
            warn!(
                block = inf.block_number,
                "discarding in-flight round on shutdown"
            );
            inf.proposed_snap.discard();
            inf.spec.discard();
        }

        // Persist SMT state (meaningful for mem-leaves-x shutdown snapshot).
        match self.smt.shutdown_persist() {
            Ok(()) => info!("SMT shutdown persist completed"),
            Err(e) => error!(err = %e, "SMT shutdown persist failed"),
        }
    }

    // ── WAL recovery ──────────────────────────────────────────────────────────

    /// If a WAL entry exists from a previous crashed run, replay the round.
    ///
    /// Recovery strategy:
    /// - Re-insert the same batch into the SMT (idempotent if already committed).
    /// - Re-submit to BFT Core using the stored block number, roots, and proof.
    /// - The normal `on_uc_result` path then commits and clears the WAL.
    async fn recover_pending_round(&mut self) {
        let wal = match &self.wal {
            Some(w) => Arc::clone(w),
            None    => return,
        };

        let pending = match wal.load_pending_round() {
            Ok(Some(p)) => p,
            Ok(None)    => return,
            Err(e) => {
                error!(err = %e, "WAL: failed to load pending round on startup");
                return;
            }
        };

        let current_block = self.state.current_block_number().await;
        if pending.block_number < current_block {
            // Round was already committed (block number advanced past it).
            warn!(block = pending.block_number, "WAL: stale entry for already-committed block, clearing");
            if let Err(e) = wal.clear_pending_round() {
                error!(err = %e, "WAL: failed to clear stale entry");
            }
            return;
        }

        warn!(
            block = pending.block_number,
            count = pending.inserted.len(),
            "WAL: recovering in-flight round from previous run"
        );

        // Reconstruct SMT pairs.  If the SMT was already committed before the crash
        // these insertions will all be no-ops (DuplicateLeaf), leaving the root intact.
        let pairs: Vec<(rsmt::SmtKey, Vec<u8>)> = pending.inserted.iter().map(|r| {
            (
                state_id_to_smt_key(&r.state_id),
                compute_cert_data_hash(
                    &r.predicate_cbor,
                    &r.source_state_hash,
                    &r.transaction_hash,
                    &r.witness,
                ).to_vec(),
            )
        }).collect();

        let mut proposed_snap = self.smt.create_snapshot();
        // We don't need a new consistency proof here; use the one stored in the WAL.
        if let Err(e) = proposed_snap.insert_batch(&pairs, false) {
            error!(block = pending.block_number, err = %e, "WAL recovery: insert_batch failed");
            proposed_snap.discard();
            return;
        }

        let recovered_root = match proposed_snap.root_hash() {
            Ok(r) => r,
            Err(e) => {
                error!(block = pending.block_number, err = %e, "WAL recovery: root_hash failed");
                proposed_snap.discard();
                return;
            }
        };

        if recovered_root != pending.new_root {
            warn!(
                block    = pending.block_number,
                expected = ?pending.new_root.map(hex::encode),
                got      = ?recovered_root.map(hex::encode),
                "WAL recovery: root hash mismatch after re-insertion"
            );
        }

        // Reconstruct ProcessedRecord list from the WAL records.
        let inserted: Vec<ProcessedRecord> = pending.inserted.iter().map(|r| ProcessedRecord {
            state_id_hex: hex::encode(&r.state_id),
            cert_data: CertDataFields {
                predicate_cbor:    r.predicate_cbor.clone(),
                source_state_hash: r.source_state_hash.clone(),
                transaction_hash:  r.transaction_hash.clone(),
                witness:           r.witness.clone(),
            },
        }).collect();

        let spec_snap = proposed_snap.fork();

        // WAL entry already exists from the previous run — no need to re-write.
        if let Err(e) = self.bft.commit_block(
            pending.block_number,
            pending.new_root,   // use the stored root, not the recomputed one
            pending.prev_root,
            pending.zk_proof.clone(),
            pending.new_leaves,
            pending.state_size,
        ).await {
            error!(block = pending.block_number, err = %e, "WAL recovery: commit_block failed");
            proposed_snap.discard();
            spec_snap.discard();
            // Clear the WAL so we don't loop on every startup.
            if let Err(ce) = wal.clear_pending_round() {
                error!(err = %ce, "WAL recovery: failed to clear WAL after commit_block failure");
            }
            return;
        }

        let bft = Arc::clone(&self.bft);
        let uc_tx = self.uc_tx.clone();
        let block_number = pending.block_number;
        tokio::spawn(async move {
            let result = bft.wait_for_uc(block_number).await;
            let _ = uc_tx.send(result).await;
        });

        info!(block = pending.block_number, "WAL recovery: re-submitted to BFT Core, waiting for UC");

        self.inflight = Some(InFlightRound {
            block_number:  pending.block_number,
            new_root:      pending.new_root,
            proposed_snap,
            spec: SpecState::Collecting {
                snap: spec_snap,
                buffer: Vec::new(),
            },
            submitted_batch: Vec::new(),  // original requests not re-available after crash
            inserted,
            dropped:         0,
        });
    }

    async fn handle_new_request(&mut self, req: ValidatedRequest) {
        // Inflight round present: route to the speculative buffer (while it
        // is still collecting) or to `self.pending` (after prep, to seed the
        // round-after-next). Collection happens continuously.
        if let Some(inf) = self.inflight.as_mut() {
            match &mut inf.spec {
                SpecState::Collecting { buffer, .. } => {
                    buffer.push(req);
                    if buffer.len() >= self.config.batch_limit {
                        self.prepare_spec().await;
                    }
                }
                SpecState::Prepared { .. } => {
                    self.pending.push(req);
                }
            }
            return;
        }

        // No inflight round: standard collecting path that feeds start_round.
        self.pending.push(req);
        if self.pending.len() >= self.config.batch_limit {
            self.start_round().await;
        }
    }

    /// Timer tick: either kick off a new round or prepare a speculative one.
    async fn on_timer_tick(&mut self) {
        match self.inflight.as_ref() {
            None => {
                if !self.pending.is_empty() {
                    self.start_round().await;
                }
            }
            Some(inf) => {
                // Only Collecting specs need prep; Prepared specs are waiting
                // on the inflight UC. Prep is skipped for an empty buffer —
                // nothing to insert, nothing to prove.
                if let SpecState::Collecting { buffer, .. } = &inf.spec {
                    if !buffer.is_empty() {
                        self.prepare_spec().await;
                    }
                }
            }
        }
    }

    // ── Round startup ─────────────────────────────────────────────────────────

    async fn start_round(&mut self) {
        let batch = std::mem::take(&mut self.pending);
        if batch.is_empty() {
            return;
        }

        let block_number = self.state.current_block_number().await;
        info!(block = block_number, count = batch.len(), "starting round");

        // Build (key, leaf_value) pairs.
        let pairs: Vec<(rsmt::SmtKey, Vec<u8>)> = batch
            .par_iter()
            .map(|req| {
                (
                    state_id_to_smt_key(&req.state_id),
                    compute_cert_data_hash(
                        &req.predicate_cbor,
                        &req.source_state_hash,
                        &req.transaction_hash,
                        &req.witness,
                    )
                    .to_vec(),
                )
            })
            .collect();

        let mut proposed_snap = self.smt.create_snapshot();

        let (flags, zk_proof) =
            match proposed_snap.insert_batch(&pairs, self.config.consistency_proofs) {
                Ok(r) => r,
                Err(e) => {
                    warn!(block = block_number, err = %e, "insert_batch failed — discarding round");
                    proposed_snap.discard();
                    self.pending.extend(batch);
                    return;
                }
            };

        let inserted: Vec<ProcessedRecord> = batch
            .iter()
            .zip(flags.iter())
            .filter(|(_, &inserted)| inserted)
            .map(|(req, _)| ProcessedRecord {
                state_id_hex: hex::encode(&req.state_id),
                cert_data: CertDataFields {
                    predicate_cbor: req.predicate_cbor.clone(),
                    source_state_hash: req.source_state_hash.clone(),
                    transaction_hash: req.transaction_hash.clone(),
                    witness: req.witness.clone(),
                },
            })
            .collect();

        let new_root = match proposed_snap.root_hash() {
            Ok(r) => r,
            Err(e) => {
                warn!(block = block_number, err = %e, "root_hash failed — discarding round");
                proposed_snap.discard();
                self.pending.extend(batch);
                return;
            }
        };
        let prev_root = self.current_root;
        let dropped = batch.len() - inserted.len();

        // Fork for speculative next-round work.
        let spec_snap = proposed_snap.fork();

        let new_leaves = inserted.len() as u64;
        let state_size = self.leaf_count + new_leaves;

        // Write WAL before BFT submission so the batch is durable on disk.
        // If this fails, abort the round rather than submit without crash protection.
        if let Some(wal) = &self.wal {
            let wal_entry = PendingRound {
                block_number,
                prev_root,
                new_root,
                zk_proof: zk_proof.clone(),
                new_leaves,
                state_size,
                inserted: inserted.iter().map(|r| WalRecord {
                    state_id:          hex::decode(&r.state_id_hex).unwrap_or_default(),
                    predicate_cbor:    r.cert_data.predicate_cbor.clone(),
                    source_state_hash: r.cert_data.source_state_hash.clone(),
                    transaction_hash:  r.cert_data.transaction_hash.clone(),
                    witness:           r.cert_data.witness.clone(),
                }).collect(),
            };
            if let Err(e) = wal.write_pending_round(&wal_entry) {
                error!(block = block_number, err = %e, "WAL write failed — aborting round");
                proposed_snap.discard();
                spec_snap.discard();
                self.pending.extend(batch);
                return;
            }
        }

        if let Err(e) = self
            .bft
            .commit_block(
                block_number,
                new_root,
                prev_root,
                zk_proof,
                new_leaves,
                state_size,
            )
            .await
        {
            error!(block = block_number, err = %e, "commit_block failed — rolling back");
            proposed_snap.discard();
            spec_snap.discard();
            self.pending.extend(batch);
            return;
        }

        // Spawn a task to await the UC.
        let bft = Arc::clone(&self.bft);
        let uc_tx = self.uc_tx.clone();
        tokio::spawn(async move {
            let result = bft.wait_for_uc(block_number).await;
            let _ = uc_tx.send(result).await;
        });

        let root_hex = new_root.map(hex::encode).unwrap_or_else(|| "empty".into());
        info!(
            block = block_number, count = batch.len(), root = %root_hex,
            "round proposed, waiting for UC"
        );

        self.inflight = Some(InFlightRound {
            block_number,
            new_root,
            proposed_snap,
            spec: SpecState::Collecting {
                snap: spec_snap,
                buffer: Vec::new(),
            },
            submitted_batch: batch,
            inserted,
            dropped,
        });

        // Seed the new inflight round's speculative buffer with any requests
        // that accumulated in self.pending after a prior spec-prep finished
        // but before this round was submitted.
        self.drain_pending_into_spec_buffer();
    }

    /// Move any pending requests into the current inflight's spec buffer
    /// (if it's still collecting). No-op otherwise.
    fn drain_pending_into_spec_buffer(&mut self) {
        let inf = match self.inflight.as_mut() {
            Some(i) => i,
            None => return,
        };
        if let SpecState::Collecting { buffer, .. } = &mut inf.spec {
            if !self.pending.is_empty() {
                buffer.extend(std::mem::take(&mut self.pending));
            }
        }
    }

    // ── Speculative round preparation / submission ───────────────────────────

    /// Transition the current inflight round's spec state from Collecting to
    /// Prepared by running a single `insert_batch_with_proof` pass on
    /// `spec_snap`. This produces both the tree update and the consistency
    /// proof in one pass, while the inflight round is still waiting for its
    /// UC. Called when the round timer ticks or the buffer fills up.
    async fn prepare_spec(&mut self) {
        // Take the inflight out by value so we can destructure its spec
        // state without fighting the borrow checker.
        let mut inf = match self.inflight.take() {
            Some(i) => i,
            None => return,
        };

        let (mut snap, buffer) = match inf.spec {
            SpecState::Collecting { snap, buffer } => (snap, buffer),
            prepared @ SpecState::Prepared { .. } => {
                // Already prepared — nothing to do.
                inf.spec = prepared;
                self.inflight = Some(inf);
                return;
            }
        };

        if buffer.is_empty() {
            inf.spec = SpecState::Collecting { snap, buffer };
            self.inflight = Some(inf);
            return;
        }

        let block_number = inf.block_number.saturating_add(1);
        let count = buffer.len();

        // Build (key, value) pairs in parallel, mirroring start_round.
        let pairs: Vec<(rsmt::SmtKey, Vec<u8>)> = buffer
            .par_iter()
            .map(|req| {
                (
                    state_id_to_smt_key(&req.state_id),
                    compute_cert_data_hash(
                        &req.predicate_cbor,
                        &req.source_state_hash,
                        &req.transaction_hash,
                        &req.witness,
                    )
                    .to_vec(),
                )
            })
            .collect();

        let (flags, zk_proof) =
            match snap.insert_batch(&pairs, self.config.consistency_proofs) {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        block = block_number,
                        err = %e,
                        "spec prep insert_batch failed — requeuing buffer"
                    );
                    snap.discard();
                    self.pending.extend(buffer);
                    // Replace spec with a fresh empty Collecting fork so the
                    // next wave of requests can still accumulate.
                    inf.spec = SpecState::Collecting {
                        snap: inf.proposed_snap.fork(),
                        buffer: Vec::new(),
                    };
                    self.inflight = Some(inf);
                    return;
                }
            };

        let inserted: Vec<ProcessedRecord> = buffer
            .iter()
            .zip(flags.iter())
            .filter(|(_, &ok)| ok)
            .map(|(req, _)| ProcessedRecord {
                state_id_hex: hex::encode(&req.state_id),
                cert_data: CertDataFields {
                    predicate_cbor: req.predicate_cbor.clone(),
                    source_state_hash: req.source_state_hash.clone(),
                    transaction_hash: req.transaction_hash.clone(),
                    witness: req.witness.clone(),
                },
            })
            .collect();

        let new_root = match snap.root_hash() {
            Ok(r) => r,
            Err(e) => {
                error!(block = block_number, err = %e, "spec prep root_hash failed");
                snap.discard();
                self.pending.extend(buffer);
                inf.spec = SpecState::Collecting {
                    snap: inf.proposed_snap.fork(),
                    buffer: Vec::new(),
                };
                self.inflight = Some(inf);
                return;
            }
        };
        let dropped = buffer.len() - inserted.len();

        info!(
            count,
            dropped,
            root = %new_root.map(hex::encode).unwrap_or_else(|| "empty".into()),
            "spec round prepared (awaiting UC of previous round)"
        );

        inf.spec = SpecState::Prepared {
            snap,
            new_root,
            zk_proof,
            batch: buffer,
            inserted,
            dropped,
        };
        self.inflight = Some(inf);
    }

    /// Submit an already-Prepared speculative round to BFT Core and turn it
    /// into the new inflight round. Called right after the previous round's
    /// UC has been committed.
    async fn submit_prepared_spec(
        &mut self,
        block_number: u64,
        mut snap: S::Snapshot,
        new_root: Option<[u8; 32]>,
        zk_proof: Option<Vec<u8>>,
        batch: Vec<ValidatedRequest>,
        inserted: Vec<ProcessedRecord>,
        dropped: usize,
    ) {
        let prev_root = self.current_root;
        let new_leaves = inserted.len() as u64;
        let state_size = self.leaf_count + new_leaves;
        let new_spec_snap = snap.fork();

        if let Some(wal) = &self.wal {
            let wal_entry = PendingRound {
                block_number,
                prev_root,
                new_root,
                zk_proof: zk_proof.clone(),
                new_leaves,
                state_size,
                inserted: inserted
                    .iter()
                    .map(|r| WalRecord {
                        state_id: hex::decode(&r.state_id_hex).unwrap_or_default(),
                        predicate_cbor: r.cert_data.predicate_cbor.clone(),
                        source_state_hash: r.cert_data.source_state_hash.clone(),
                        transaction_hash: r.cert_data.transaction_hash.clone(),
                        witness: r.cert_data.witness.clone(),
                    })
                    .collect(),
            };
            if let Err(e) = wal.write_pending_round(&wal_entry) {
                error!(block = block_number, err = %e, "WAL write failed (spec submit) — aborting round");
                snap.discard();
                new_spec_snap.discard();
                self.pending.extend(batch);
                return;
            }
        }

        if let Err(e) = self
            .bft
            .commit_block(
                block_number,
                new_root,
                prev_root,
                zk_proof,
                new_leaves,
                state_size,
            )
            .await
        {
            error!(block = block_number, err = %e, "commit_block (spec submit) failed — rolling back");
            snap.discard();
            new_spec_snap.discard();
            self.pending.extend(batch);
            return;
        }

        let bft = Arc::clone(&self.bft);
        let uc_tx = self.uc_tx.clone();
        tokio::spawn(async move {
            let result = bft.wait_for_uc(block_number).await;
            let _ = uc_tx.send(result).await;
        });

        let root_hex = new_root.map(hex::encode).unwrap_or_else(|| "empty".into());
        info!(
            block = block_number,
            count = batch.len(),
            root = %root_hex,
            "prepared spec round submitted, waiting for UC"
        );

        self.inflight = Some(InFlightRound {
            block_number,
            new_root,
            proposed_snap: snap,
            spec: SpecState::Collecting {
                snap: new_spec_snap,
                buffer: Vec::new(),
            },
            submitted_batch: batch,
            inserted,
            dropped,
        });

        // Requests that accumulated in self.pending after spec prep seed the
        // new inflight round's speculative buffer.
        self.drain_pending_into_spec_buffer();
    }

    // ── UC arrival ────────────────────────────────────────────────────────────

    async fn on_uc_result(&mut self, uc_result: anyhow::Result<Vec<u8>>) {
        let inf = match self.inflight.take() {
            Some(i) => i,
            None => {
                warn!("UC arrived but no inflight round");
                return;
            }
        };

        match uc_result {
            Ok(uc_cbor) => {
                // Commit the proposed snapshot.
                if let Err(e) = inf.proposed_snap.commit(&mut self.smt) {
                    error!(block = inf.block_number, err = %e, "snapshot commit failed — requeuing");
                    self.pending.extend(inf.submitted_batch);
                    match inf.spec {
                        SpecState::Collecting { snap, buffer } => {
                            snap.discard();
                            self.pending.extend(buffer);
                        }
                        SpecState::Prepared { snap, batch, .. } => {
                            snap.discard();
                            self.pending.extend(batch);
                        }
                    }
                    return;
                }
                self.current_root = inf.new_root;
                self.leaf_count += inf.inserted.len() as u64;

                // Generate proofs from committed store.
                let finalized = self.generate_proofs(inf.inserted, inf.block_number);

                let unique_count = finalized.len();
                let dropped_count = inf.dropped;

                let root_hex = inf.new_root.map(hex::encode).unwrap_or_else(|| "empty".into());
                self.state
                    .finalize_round(
                        BlockInfo {
                            block_number: inf.block_number,
                            root_hash: inf.new_root,
                            uc_cbor,
                        },
                        finalized,
                    )
                    .await;

                info!(
                    block   = inf.block_number,
                    root    = %root_hex,
                    unique  = unique_count,
                    dropped = dropped_count,
                    "round finalized"
                );

                // Continue with the speculative round, if any.
                match inf.spec {
                    SpecState::Prepared {
                        snap,
                        new_root,
                        zk_proof,
                        batch,
                        inserted,
                        dropped,
                    } => {
                        let next_block = self.state.current_block_number().await;
                        self.submit_prepared_spec(
                            next_block, snap, new_root, zk_proof, batch, inserted, dropped,
                        )
                        .await;
                    }
                    SpecState::Collecting { snap, buffer } => {
                        // Spec was still accumulating (timer hadn't ticked and
                        // batch_limit wasn't reached). Drop the old fork and
                        // requeue its buffer; the next start_round() will pick
                        // them up into a fresh speculative snapshot over the
                        // newly committed state.
                        snap.discard();
                        let mut merged = buffer;
                        merged.extend(std::mem::take(&mut self.pending));
                        self.pending = merged;
                        if !self.pending.is_empty() {
                            self.start_round().await;
                        }
                    }
                }
            }
            Err(e) => {
                error!(block = inf.block_number, err = %e, "UC failed — rolling back");
                inf.proposed_snap.discard();
                self.pending.extend(inf.submitted_batch);
                match inf.spec {
                    SpecState::Collecting { snap, buffer } => {
                        snap.discard();
                        self.pending.extend(buffer);
                    }
                    SpecState::Prepared { snap, batch, .. } => {
                        snap.discard();
                        self.pending.extend(batch);
                    }
                }
            }
        }
    }

    // ── Proof generation ──────────────────────────────────────────────────────

    fn generate_proofs(
        &mut self,
        processed: Vec<ProcessedRecord>,
        block_number: u64,
    ) -> Vec<FinalizedRecord> {
        // Decode state_ids → SmtKeys; track which indices are valid.
        let mut valid: Vec<(usize, rsmt::SmtKey)> = Vec::with_capacity(processed.len());
        let mut keys: Vec<rsmt::SmtKey> = Vec::with_capacity(processed.len());
        for (i, r) in processed.iter().enumerate() {
            match hex::decode(&r.state_id_hex) {
                Ok(b) => {
                    let key = state_id_to_smt_key(&b);
                    keys.push(key);
                    valid.push((i, key));
                }
                Err(e) => {
                    warn!("invalid state_id_hex: {e}");
                }
            }
        }

        // Single batch materialization for all proofs.
        let proofs = match self.smt.get_inclusion_proofs_batch(&keys) {
            Ok(ps) => ps,
            Err(e) => {
                warn!(block = block_number, err = %e, "get_inclusion_proofs_batch failed");
                return Vec::new();
            }
        };

        let mut out = Vec::with_capacity(processed.len());
        let processed_vec: Vec<ProcessedRecord> = processed.into_iter().collect();
        for (j, (orig_idx, _key)) in valid.into_iter().enumerate() {
            let proof_bytes = proofs[j].to_bytes();
            out.push(FinalizedRecord {
                state_id_hex: processed_vec[orig_idx].state_id_hex.clone(),
                block_number,
                cert_data: processed_vec[orig_idx].cert_data.clone(),
                merkle_path_cbor: Some(proof_bytes),
            });
        }
        out
    }
}
