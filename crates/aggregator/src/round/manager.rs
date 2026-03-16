//! Round manager – sequential (non-speculative) round processing.
//!
//! State machine:
//! ```text
//! COLLECTING ──(timer | batch_limit)──> PROCESSING
//!           ──> CERTIFYING ──(UC received)──> FINALIZING ──> COLLECTING
//! ```
//!
//! BFT Core integration is via the `BftCommitter` trait.  A stub implementation
//! is provided for testing; replace with the real libp2p-based committer.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, info, warn, error};

use crate::config::RoundConfig;
use crate::smt::{SmtSnapshot, SparseMerkleTree, state_id_to_smt_path, MerkleTreePath};
use crate::smt::proof::merkle_path_to_cbor;
use crate::storage::{AggregatorState, BlockInfo, FinalizedRecord};
use crate::validation::ValidatedRequest;
use crate::validation::state_id::compute_cert_data_hash_imprint;
use crate::api::cbor::CertDataFields;
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

/// A no-op BFT committer for testing without BFT Core connectivity.
pub struct BftCommitterStub;

#[async_trait]
impl BftCommitter for BftCommitterStub {
    async fn commit_block(
        &self,
        block_number: u64,
        new_root: &[u8; 34],
        _prev_root: &[u8; 34],
        _zk_proof: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        info!(block = block_number, root = %hex::encode(new_root), "BftCommitterStub: commit_block (no-op)");
        Ok(())
    }

    async fn wait_for_uc(&self, block_number: u64) -> anyhow::Result<Vec<u8>> {
        // Return a placeholder UC (empty bytes).
        info!(block = block_number, "BftCommitterStub: wait_for_uc → stub UC");
        // Build a minimal valid CBOR bytes array so the storage doesn't choke.
        // Real implementation would return the actual UC from BFT Core.
        Ok(vec![]) // empty = stub
    }
}

// ─── RoundManager ─────────────────────────────────────────────────────────────

pub struct RoundManager {
    config: RoundConfig,
    request_rx: mpsc::Receiver<ValidatedRequest>,
    pending: Vec<ValidatedRequest>,
    smt: SparseMerkleTree,
    current_root: [u8; 34],
    state: Arc<AggregatorState>,
    bft: Arc<dyn BftCommitter>,
}

impl RoundManager {
    pub fn new(
        config: RoundConfig,
        request_rx: mpsc::Receiver<ValidatedRequest>,
        state: Arc<AggregatorState>,
        bft: Arc<dyn BftCommitter>,
    ) -> Self {
        let mut smt = SparseMerkleTree::new();
        let initial_root = smt.root_hash_imprint();
        Self {
            config,
            request_rx,
            pending: Vec::new(),
            smt,
            current_root: initial_root,
            state,
            bft,
        }
    }

    /// Run the round manager event loop.  This task owns the SMT.
    pub async fn run(mut self) {
        let mut timer = time::interval(Duration::from_millis(self.config.round_duration_ms));
        timer.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    if !self.pending.is_empty() {
                        self.process_round().await;
                    }
                }
                Some(req) = self.request_rx.recv() => {
                    self.pending.push(req);
                    if self.pending.len() >= self.config.batch_limit {
                        self.process_round().await;
                    }
                }
            }
        }
    }

    async fn process_round(&mut self) {
        let batch: Vec<ValidatedRequest> = std::mem::take(&mut self.pending);
        if batch.is_empty() {
            return;
        }

        let block_number = self.state.current_block_number().await;
        info!(block = block_number, count = batch.len(), "processing round");

        // ── Build speculative snapshot ────────────────────────────────────────
        let mut snapshot = SmtSnapshot::create(&self.smt);
        let mut processed: Vec<ProcessedRecord> = Vec::with_capacity(batch.len());

        for req in &batch {
            // Compute the SMT path and leaf value.
            let path = state_id_to_smt_path(&req.state_id);
            let leaf_value = compute_cert_data_hash_imprint(
                &req.predicate_cbor,
                &req.source_state_hash,
                &req.transaction_hash,
                &req.witness,
            );

            match snapshot.add_leaf(path.clone(), leaf_value.to_vec()) {
                Ok(()) => {}
                Err(crate::smt::SmtError::DuplicateLeaf) => {
                    // Leaf already exists at this path — add-only tree, skip silently.
                    debug!(state_id = %hex::encode(&req.state_id), "skipping existing leaf");
                    continue;
                }
                Err(e) => {
                    warn!(state_id = %hex::encode(&req.state_id), err = %e, "leaf insertion failed");
                    continue;
                }
            }

            processed.push(ProcessedRecord {
                state_id_hex: hex::encode(&req.state_id),
                cert_data: CertDataFields {
                    predicate_cbor: req.predicate_cbor.clone(),
                    source_state_hash: req.source_state_hash.clone(),
                    transaction_hash: req.transaction_hash.clone(),
                    witness: req.witness.clone(),
                },
                merkle_path: MerkleTreePath {
                    root: String::new(), // will be filled after commit
                    steps: vec![],
                },
            });
        }

        let new_root = snapshot.root_hash_imprint();
        let prev_root = self.current_root;

        // ── Submit to BFT Core ────────────────────────────────────────────────
        if let Err(e) = self.bft.commit_block(block_number, &new_root, &prev_root, None).await {
            error!(block = block_number, err = %e, "commit_block failed — rolling back");
            snapshot.discard();
            // Re-queue all requests.
            self.pending.extend(batch);
            return;
        }

        // ── Wait for UC ───────────────────────────────────────────────────────
        let uc_cbor = match self.bft.wait_for_uc(block_number).await {
            Ok(uc) => uc,
            Err(e) => {
                error!(block = block_number, err = %e, "wait_for_uc failed — rolling back");
                snapshot.discard();
                self.pending.extend(batch);
                return;
            }
        };

        // ── Commit snapshot ───────────────────────────────────────────────────
        snapshot.commit(&mut self.smt);
        self.current_root = new_root;

        // ── Generate inclusion proofs and finalize ────────────────────────────
        let mut finalized_records: Vec<FinalizedRecord> = Vec::with_capacity(processed.len());

        for pr in &processed {
            // Re-derive the path from the state_id hex.
            let state_id_bytes = hex::decode(&pr.state_id_hex).unwrap_or_default();
            let smt_path = state_id_to_smt_path(&state_id_bytes);

            let merkle_path = match self.smt.get_path(&smt_path) {
                Ok(p) => p,
                Err(e) => {
                    warn!(state_id = %pr.state_id_hex, err = %e, "get_path failed after commit");
                    continue;
                }
            };

            let merkle_path_cbor = match merkle_path_to_cbor(&merkle_path) {
                Ok(b) => b,
                Err(e) => {
                    warn!(state_id = %pr.state_id_hex, err = %e, "merkle_path CBOR encode failed");
                    continue;
                }
            };

            finalized_records.push(FinalizedRecord {
                state_id_hex: pr.state_id_hex.clone(),
                block_number,
                cert_data: pr.cert_data.clone(),
                merkle_path_cbor,
            });
        }

        // Store finalized records and block info.
        self.state.finalize_records(finalized_records);
        self.state.finalize_block(BlockInfo {
            block_number,
            root_hash: new_root,
            uc_cbor,
        });

        // Advance block number.
        self.state.increment_block_number().await;

        info!(
            block = block_number,
            root = %hex::encode(new_root),
            "round finalized"
        );
    }
}
