//! Round state tracking.

use crate::validation::ValidatedRequest;
use crate::smt::proof::MerkleTreePath;
use crate::api::cbor::CertDataFields;

/// Lifecycle state of a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundPhase {
    /// Accepting new certification requests.
    Collecting,
    /// Processing the current batch (computing SMT).
    Processing,
    /// Waiting for the UnicityCertificate from BFT Core.
    Certifying,
    /// Committing the certified block to state.
    Finalizing,
}

/// Metadata about a pending (uncertified) batch.
pub struct PendingBatch {
    /// The requests in this batch.
    pub requests: Vec<ValidatedRequest>,
    /// The new root hash imprint after all insertions.
    pub new_root_hash: [u8; 34],
    /// The previous (committed) root hash.
    pub prev_root_hash: [u8; 34],
    /// The block number this batch was processed for.
    pub block_number: u64,
}

/// A record that was processed as part of this batch.
pub struct ProcessedRecord {
    pub state_id_hex: String,
    pub cert_data: CertDataFields,
    pub merkle_path: MerkleTreePath,
}
