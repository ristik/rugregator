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
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, info, warn, error};

use crate::config::RoundConfig;
use crate::smt::{state_id_to_smt_path};
use crate::storage::{AggregatorState, BlockInfo, FinalizedRecord};
use crate::validation::ValidatedRequest;
use crate::validation::state_id::compute_cert_data_hash_imprint;
use crate::api::cbor::CertDataFields;
use super::state::ProcessedRecord;
use async_trait::async_trait;

use smt_store::{SmtStore, SmtStoreSnapshot};

// ─── BftCommitter trait ───────────────────────────────────────────────────────

/// BFT Core interface.
#[async_trait]
pub trait BftCommitter: Send + Sync {
    /// Submit a block for certification.
    async fn commit_block(
        &self,
        block_number: u64,
        new_root: &[u8; 34],
        prev_root: &[u8; 34],
        zk_proof: Option<Vec<u8>>,
    ) -> anyhow::Result<()>;

    /// Wait for the UnicityCertificate for `block_number`.
    async fn wait_for_uc(&self, block_number: u64) -> anyhow::Result<Vec<u8>>;
}

// ─── Stub implementation ──────────────────────────────────────────────────────

pub struct BftCommitterStub {
    pending_root: Mutex<[u8; 34]>,
}

impl BftCommitterStub {
    const PRIVATE_KEY: [u8; 32] = [7u8; 32];
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

fn stub_generate_uc(block_number: u64, new_root: &[u8; 34], private_key: [u8; 32], node_id: &str) -> Vec<u8> {
    use secp256k1::{Message, Secp256k1, SecretKey};

    let input_record_inner = cbor_array(&[
        &cbor_uint(0),
        &cbor_uint(block_number),
        &cbor_uint(0),
        &cbor_null(),
        &cbor_bytes(new_root),
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

    let shard_tree_cert = cbor_array(&[
        &cbor_bytes(&[]),
        &cbor_array(&[]),
    ]);

    let utc_inner = cbor_array(&[
        &cbor_uint(0),
        &cbor_uint(0),
        &cbor_array(&[]),
    ]);
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

/// State of a round that has been proposed to BFT Core and is awaiting its UC.
struct InFlightRound<S: SmtStore> {
    block_number:    u64,
    new_root:        [u8; 34],
    proposed_snap:   S::Snapshot,
    spec_snap:       S::Snapshot,
    submitted_batch: Vec<ValidatedRequest>,
    inserted:        Vec<ProcessedRecord>,
    spec_batch:      Vec<ValidatedRequest>,
    spec_inserted:   Vec<ProcessedRecord>,
}

// ─── RoundManager ─────────────────────────────────────────────────────────────

pub struct RoundManager<S: SmtStore> {
    config:       RoundConfig,
    request_rx:   mpsc::Receiver<ValidatedRequest>,
    pending:      Vec<ValidatedRequest>,
    smt:          S,
    current_root: [u8; 34],
    state:        Arc<AggregatorState>,
    bft:          Arc<dyn BftCommitter>,
    inflight:     Option<InFlightRound<S>>,
    uc_tx:        mpsc::Sender<anyhow::Result<Vec<u8>>>,
    uc_rx:        mpsc::Receiver<anyhow::Result<Vec<u8>>>,
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
        let current_root = smt.root_hash_imprint();
        let (uc_tx, uc_rx) = mpsc::channel(4);
        Self {
            config,
            request_rx,
            pending: Vec::new(),
            smt,
            current_root,
            state,
            bft,
            inflight: None,
            uc_tx,
            uc_rx,
        }
    }

    fn no_round_inflight(&self) -> bool {
        self.inflight.is_none()
    }

    /// Run the round manager event loop.
    pub async fn run(mut self) {
        let mut timer = time::interval(Duration::from_millis(self.config.round_duration_ms));
        timer.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    if self.no_round_inflight() && !self.pending.is_empty() {
                        self.start_round().await;
                    }
                }
                Some(req) = self.request_rx.recv() => {
                    self.handle_new_request(req).await;
                }
                Some(uc_result) = self.uc_rx.recv() => {
                    self.on_uc_result(uc_result).await;
                }
            }
        }
    }

    async fn handle_new_request(&mut self, req: ValidatedRequest) {
        if self.inflight.is_some() {
            self.insert_speculative(req);
            return;
        }
        self.pending.push(req);
        if self.no_round_inflight() && self.pending.len() >= self.config.batch_limit {
            self.start_round().await;
        }
    }

    // ── Round startup ─────────────────────────────────────────────────────────

    async fn start_round(&mut self) {
        let batch = std::mem::take(&mut self.pending);
        if batch.is_empty() { return; }

        let block_number = self.state.current_block_number().await;
        info!(block = block_number, count = batch.len(), "starting round");

        // Build (path, leaf_value) pairs.
        let pairs: Vec<(crate::smt::SmtPath, Vec<u8>)> = batch.iter().map(|req| {
            (
                state_id_to_smt_path(&req.state_id),
                compute_cert_data_hash_imprint(
                    &req.predicate_cbor, &req.source_state_hash,
                    &req.transaction_hash, &req.witness,
                ).to_vec(),
            )
        }).collect();

        let mut proposed_snap = self.smt.create_snapshot();

        let (flags, zk_proof) = match proposed_snap.insert_batch(&pairs, self.config.consistency_proofs) {
            Ok(r) => r,
            Err(e) => {
                warn!(block = block_number, err = %e, "insert_batch failed — discarding round");
                proposed_snap.discard();
                self.pending.extend(batch);
                return;
            }
        };

        let inserted: Vec<ProcessedRecord> = batch.iter().zip(flags.iter())
            .filter(|(_, &inserted)| inserted)
            .map(|(req, _)| ProcessedRecord {
                state_id_hex: hex::encode(&req.state_id),
                cert_data: CertDataFields {
                    predicate_cbor:    req.predicate_cbor.clone(),
                    source_state_hash: req.source_state_hash.clone(),
                    transaction_hash:  req.transaction_hash.clone(),
                    witness:           req.witness.clone(),
                },
            })
            .collect();

        let new_root = match proposed_snap.root_hash_imprint() {
            Ok(r) => r,
            Err(e) => {
                warn!(block = block_number, err = %e, "root_hash_imprint failed — discarding round");
                proposed_snap.discard();
                self.pending.extend(batch);
                return;
            }
        };
        let prev_root = self.current_root;

        // Fork for speculative next-round work.
        let spec_snap = proposed_snap.fork();

        if let Err(e) = self.bft.commit_block(block_number, &new_root, &prev_root, zk_proof).await {
            error!(block = block_number, err = %e, "commit_block failed — rolling back");
            proposed_snap.discard();
            spec_snap.discard();
            self.pending.extend(batch);
            return;
        }

        // Spawn a task to await the UC.
        let bft   = Arc::clone(&self.bft);
        let uc_tx = self.uc_tx.clone();
        tokio::spawn(async move {
            let result = bft.wait_for_uc(block_number).await;
            let _ = uc_tx.send(result).await;
        });

        info!(
            block = block_number, count = batch.len(), root = %hex::encode(new_root),
            "round proposed, waiting for UC"
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
    async fn start_round_from_spec(
        &mut self,
        block_number: u64,
        mut spec_snap: S::Snapshot,
        spec_batch: Vec<ValidatedRequest>,
        spec_inserted: Vec<ProcessedRecord>,
    ) {
        let new_root = match spec_snap.root_hash_imprint() {
            Ok(r) => r,
            Err(e) => {
                error!(block = block_number, err = %e, "spec root_hash_imprint failed");
                spec_snap.discard();
                self.pending.extend(spec_batch);
                return;
            }
        };
        let prev_root = self.current_root;
        let count = spec_batch.len();

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
            proposed_snap:   spec_snap,
            spec_snap:       new_spec_snap,
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

    fn insert_speculative(&mut self, req: ValidatedRequest) {
        let inf = match self.inflight.as_mut() {
            Some(i) => i,
            None => { self.pending.push(req); return; }
        };

        let path  = state_id_to_smt_path(&req.state_id);
        let value = compute_cert_data_hash_imprint(
            &req.predicate_cbor, &req.source_state_hash,
            &req.transaction_hash, &req.witness,
        );

        match inf.spec_snap.add_leaf(path, value.to_vec()) {
            Ok(()) => {
                inf.spec_inserted.push(ProcessedRecord {
                    state_id_hex: hex::encode(&req.state_id),
                    cert_data: CertDataFields {
                        predicate_cbor:    req.predicate_cbor.clone(),
                        source_state_hash: req.source_state_hash.clone(),
                        transaction_hash:  req.transaction_hash.clone(),
                        witness:           req.witness.clone(),
                    },
                });
                inf.spec_batch.push(req);
            }
            Err(rsmt::SmtError::DuplicateLeaf) => {
                debug!(state_id = %hex::encode(&req.state_id), "skipping duplicate in spec");
            }
            Err(e) => {
                warn!(state_id = %hex::encode(&req.state_id), err = %e, "spec leaf insert failed");
            }
        }
    }

    // ── UC arrival ────────────────────────────────────────────────────────────

    async fn on_uc_result(&mut self, uc_result: anyhow::Result<Vec<u8>>) {
        let inf = match self.inflight.take() {
            Some(i) => i,
            None => { warn!("UC arrived but no inflight round"); return; }
        };

        match uc_result {
            Ok(uc_cbor) => {
                // Commit the proposed snapshot.
                if let Err(e) = inf.proposed_snap.commit(&mut self.smt) {
                    error!(block = inf.block_number, err = %e, "snapshot commit failed — requeuing");
                    self.pending.extend(inf.submitted_batch);
                    self.pending.extend(inf.spec_batch);
                    return;
                }
                self.current_root = inf.new_root;

                // Generate proofs from committed store.
                let finalized = self.generate_proofs(inf.inserted, inf.block_number);

                let certified_count = finalized.len();
                let submitted_count = inf.submitted_batch.len();
                let spec_count      = inf.spec_batch.len();

                self.state.finalize_round(BlockInfo {
                    block_number: inf.block_number,
                    root_hash: inf.new_root,
                    uc_cbor,
                }, finalized).await;

                info!(
                    block       = inf.block_number,
                    root        = %hex::encode(inf.new_root),
                    certified   = certified_count,
                    submitted   = submitted_count,
                    spec_queued = spec_count,
                    "round finalized"
                );

                if !inf.spec_batch.is_empty() {
                    let next_block = self.state.current_block_number().await;
                    self.start_round_from_spec(
                        next_block, inf.spec_snap, inf.spec_batch, inf.spec_inserted,
                    ).await;
                } else {
                    inf.spec_snap.discard();
                    // Start a new round if there are pending requests.
                    let pending = std::mem::take(&mut self.pending);
                    if !pending.is_empty() {
                        self.pending = pending;
                        self.start_round().await;
                    }
                }
            }
            Err(e) => {
                error!(block = inf.block_number, err = %e, "UC failed — rolling back");
                inf.proposed_snap.discard();
                inf.spec_snap.discard();
                self.pending.extend(inf.submitted_batch);
                self.pending.extend(inf.spec_batch);
            }
        }
    }

    // ── Proof generation ──────────────────────────────────────────────────────

    fn generate_proofs(&mut self, processed: Vec<ProcessedRecord>, block_number: u64) -> Vec<FinalizedRecord> {
        use rsmt::proof::merkle_path_to_cbor;

        // Decode state_ids and build paths up front; track which indices are valid.
        let mut valid: Vec<(usize, Vec<u8>)> = Vec::with_capacity(processed.len());
        let mut paths = Vec::with_capacity(processed.len());
        for (i, r) in processed.iter().enumerate() {
            match hex::decode(&r.state_id_hex) {
                Ok(b) => {
                    paths.push(state_id_to_smt_path(&b));
                    valid.push((i, b));
                }
                Err(e) => { warn!("invalid state_id_hex: {e}"); }
            }
        }

        // Single batch materialization for all proofs.
        let merkle_paths = match self.smt.get_paths_batch(&paths) {
            Ok(ps) => ps,
            Err(e) => {
                warn!(block = block_number, err = %e, "get_paths_batch failed");
                return Vec::new();
            }
        };

        let mut out = Vec::with_capacity(processed.len());
        let processed_vec: Vec<ProcessedRecord> = processed.into_iter().collect();
        for (j, (orig_idx, _state_id)) in valid.into_iter().enumerate() {
            let merkle_path_cbor = match merkle_path_to_cbor(&merkle_paths[j]) {
                Ok(c) => c,
                Err(e) => { warn!(err = %e, "merkle_path_to_cbor failed"); continue; }
            };
            out.push(FinalizedRecord {
                state_id_hex: processed_vec[orig_idx].state_id_hex.clone(),
                block_number,
                cert_data: processed_vec[orig_idx].cert_data.clone(),
                merkle_path_cbor: Some(merkle_path_cbor),
            });
        }
        out
    }
}
