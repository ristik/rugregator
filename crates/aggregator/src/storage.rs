//! In-memory state store for the aggregator.
//!
//! `AggregatorState` is the central shared object:
//!   - Tracks the current block number.
//!   - Stores finalized record info (StateID → block + cert data).
//!   - Stores finalized block info (block number → root hash + UC CBOR).
//!   - Exposes a channel for submitting validated requests to the round manager.
//!   - Holds a shared reference to the latest certified SMT for on-demand proof generation.

use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::debug;

use crate::smt::{SparseMerkleTree, state_id_to_smt_path};
use crate::smt::proof::merkle_path_to_cbor;
use crate::validation::ValidatedRequest;
use crate::api::cbor::CertDataFields;

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

// ─── RecoveredState ───────────────────────────────────────────────────────────

pub struct RecoveredState {
    pub block_number: u64,
    pub records: Vec<(String, RecordInfo)>,  // (state_id_hex, RecordInfo)
    pub blocks: Vec<BlockInfo>,
}

// ─── Record info ─────────────────────────────────────────────────────────────

/// Data stored for each finalized StateID.
#[derive(Debug, Clone)]
pub struct RecordInfo {
    pub block_number: u64,
    pub cert_data: CertDataFields,
    /// Pre-computed CBOR-encoded Merkle path.
    ///
    /// `Some` only for disk-backed records (generated at finalization time).
    /// `None` for in-memory records — the path is generated on-demand from
    /// the latest certified SMT state so it is always valid against the
    /// current root hash in the latest UC.
    pub merkle_path_cbor: Option<Vec<u8>>,
}

// ─── Block info ───────────────────────────────────────────────────────────────

/// Data stored for each finalized block.
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub block_number: u64,
    /// 34-byte root hash imprint.
    pub root_hash: [u8; 34],
    /// Raw CBOR bytes of the UnicityCertificate.
    pub uc_cbor: Vec<u8>,
}

// ─── Inclusion proof result ───────────────────────────────────────────────────

/// All data needed to build an inclusion proof response.
pub struct InclusionProofData {
    pub block_number: u64,
    pub cert_data: Option<CertDataFields>,
    pub merkle_path_cbor: Vec<u8>,
    pub uc_cbor: Vec<u8>,
}

// ─── AggregatorState ──────────────────────────────────────────────────────────

/// Central shared state of the aggregator (all fields are thread-safe).
pub struct AggregatorState {
    /// Current (next to be assigned) block number.
    block_number: RwLock<u64>,
    /// StateID (hex) → record info.
    records: DashMap<String, RecordInfo>,
    /// Block number → block info.
    blocks: DashMap<u64, BlockInfo>,
    /// Channel to submit validated requests to the round manager.
    request_tx: mpsc::Sender<ValidatedRequest>,
    /// Optional persistence backend.
    store: Option<Arc<dyn Store>>,
    /// Latest certified SMT state, shared with the round manager.
    ///
    /// Used exclusively for on-demand inclusion proof generation for the
    /// in-memory path.  The round manager holds a clone of this Arc and
    /// updates the tree (under the mutex) after each round is finalized.
    ///
    /// Invariant: `smt.root_hash_imprint() == latest_uc.IR.hash`.
    certified_smt: Arc<Mutex<SparseMerkleTree>>,
}

impl AggregatorState {
    pub fn new(request_tx: mpsc::Sender<ValidatedRequest>, store: Option<Arc<dyn Store>>) -> Arc<Self> {
        Arc::new(Self {
            block_number: RwLock::new(1),
            records: DashMap::new(),
            blocks: DashMap::new(),
            request_tx,
            store,
            certified_smt: Arc::new(Mutex::new(SparseMerkleTree::new())),
        })
    }

    /// Return a clone of the certified-SMT Arc for the round manager to share.
    pub fn certified_smt_arc(&self) -> Arc<Mutex<SparseMerkleTree>> {
        Arc::clone(&self.certified_smt)
    }

    // ── Block number ──────────────────────────────────────────────────────────

    pub async fn current_block_number(&self) -> u64 {
        *self.block_number.read().await
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
        self.request_tx
            .send(req)
            .await
            .map_err(|_| anyhow::anyhow!("round manager channel closed"))?;
        Ok(())
    }

    // ── Finalization ──────────────────────────────────────────────────────────

    /// Store all records from a finalized round.
    pub fn finalize_records(&self, records: Vec<FinalizedRecord>) {
        for r in records {
            debug!(state_id = %r.state_id_hex, block = r.block_number, "finalizing record");
            self.records.insert(r.state_id_hex, RecordInfo {
                block_number: r.block_number,
                cert_data: r.cert_data,
                merkle_path_cbor: r.merkle_path_cbor,
            });
        }
    }

    pub fn finalize_block(&self, info: BlockInfo) {
        debug!(block = info.block_number, "finalizing block");
        self.blocks.insert(info.block_number, info);
    }

    /// Persist (if configured) and update in-memory state for a finalized round.
    /// Called from RoundManager after snapshot commit and proof generation.
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
    ) -> anyhow::Result<Option<InclusionProofData>> {
        let key = hex::encode(state_id);
        let record = match self.records.get(&key) {
            Some(r) => r.clone(),
            None => return Ok(None),
        };

        if let Some(precomputed_path) = record.merkle_path_cbor {
            // Disk path: use the precomputed path with the block's own UC.
            let block = match self.blocks.get(&record.block_number) {
                Some(b) => b.clone(),
                None => return Ok(None),
            };
            return Ok(Some(InclusionProofData {
                block_number: record.block_number,
                cert_data: Some(record.cert_data),
                merkle_path_cbor: precomputed_path,
                uc_cbor: block.uc_cbor,
            }));
        }

        // In-memory path: generate proof on-demand from the latest certified SMT.
        // The path hashes up to the current certified root = latest UC's InputRecord.hash.
        let latest_block_num = self.block_number.read().await.saturating_sub(1);
        let block = match self.blocks.get(&latest_block_num) {
            Some(b) => b.clone(),
            None => return Ok(None), // no blocks finalized yet
        };

        let smt_path = state_id_to_smt_path(state_id);
        let merkle_path = {
            let mut smt = self.certified_smt.lock().await;
            smt.get_path(&smt_path)
                .map_err(|e| anyhow::anyhow!("get_path failed: {e}"))?
        };
        let merkle_path_cbor = merkle_path_to_cbor(&merkle_path)
            .map_err(|e| anyhow::anyhow!("merkle path encode failed: {e}"))?;

        Ok(Some(InclusionProofData {
            block_number: latest_block_num,
            cert_data: Some(record.cert_data),
            merkle_path_cbor,
            uc_cbor: block.uc_cbor,
        }))
    }
}

// ─── FinalizedRecord (produced by RoundManager, consumed by AggregatorState) ─

pub struct FinalizedRecord {
    pub state_id_hex: String,
    pub block_number: u64,
    pub cert_data: CertDataFields,
    /// Pre-computed Merkle path CBOR.
    ///
    /// `Some` for disk-backed path (generated at finalization time).
    /// `None` for in-memory path (generated on-demand from certified SMT).
    pub merkle_path_cbor: Option<Vec<u8>>,
}
