//! In-memory state store for the aggregator.
//!
//! `AggregatorState` is the central shared object:
//!   - Tracks the current block number.
//!   - Stores finalized record info (StateID → block + cert data).
//!   - Stores finalized block info (block number → root hash + UC CBOR).
//!   - Exposes a channel for submitting validated requests to the round manager.
//!   - Merkle proofs are pre-computed at finalization time and stored in RecordInfo.

use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::debug;

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
    /// Always `Some` for finalized records (generated at finalization time).
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
}

impl AggregatorState {
    pub fn new(request_tx: mpsc::Sender<ValidatedRequest>, store: Option<Arc<dyn Store>>) -> Arc<Self> {
        Arc::new(Self {
            block_number: RwLock::new(1),
            records: DashMap::new(),
            blocks: DashMap::new(),
            request_tx,
            store,
        })
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

        let merkle_path_cbor = match record.merkle_path_cbor {
            Some(p) => p,
            None => return Ok(None), // still pending (shouldn't happen after finalization)
        };

        let block = match self.blocks.get(&record.block_number) {
            Some(b) => b.clone(),
            None => return Ok(None),
        };

        Ok(Some(InclusionProofData {
            block_number: record.block_number,
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
    /// Always `Some` for finalized records (generated at finalization time).
    pub merkle_path_cbor: Option<Vec<u8>>,
}
