//! Round state tracking.

use crate::api::cbor::CertDataFields;

/// A record that was processed as part of a batch (disk path only).
///
/// For the in-memory path, `ValidatedRequest` is used directly to build
/// `FinalizedRecord`; proofs are generated on-demand at query time.
pub struct ProcessedRecord {
    pub state_id_hex: String,
    pub cert_data: CertDataFields,
}
