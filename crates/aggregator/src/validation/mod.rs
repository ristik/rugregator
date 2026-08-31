//! Request validation pipeline.

pub mod predicate;
pub mod signature;
pub mod state_id;

use thiserror::Error;

use crate::smt::AGGREGATION_TREE_VALUE_SIZE;

pub use predicate::{validate_pay_to_public_key, PredicateError};
pub use signature::{verify_signature, SignatureError};
pub use state_id::{compute_sig_data_hash, compute_state_id, validate_state_id};

// ─── Validation status (matches Go ValidationStatus) ─────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationStatus {
    Success,
    StateIdMismatch,
    SignatureVerificationFailed,
    InvalidSignatureFormat,
    InvalidPublicKeyFormat,
    InvalidSourceStateHashFormat,
    InvalidTransactionHashFormat,
    InvalidOwnerPredicate,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStatus::Success => write!(f, "SUCCESS"),
            ValidationStatus::StateIdMismatch => write!(f, "STATE_ID_MISMATCH"),
            ValidationStatus::SignatureVerificationFailed => {
                write!(f, "SIGNATURE_VERIFICATION_FAILED")
            }
            ValidationStatus::InvalidSignatureFormat => write!(f, "INVALID_SIGNATURE_FORMAT"),
            ValidationStatus::InvalidPublicKeyFormat => write!(f, "INVALID_PUBLIC_KEY_FORMAT"),
            ValidationStatus::InvalidSourceStateHashFormat => {
                write!(f, "INVALID_SOURCE_STATE_HASH_FORMAT")
            }
            ValidationStatus::InvalidTransactionHashFormat => {
                write!(f, "INVALID_TRANSACTION_HASH_FORMAT")
            }
            ValidationStatus::InvalidOwnerPredicate => write!(f, "INVALID_OWNER_PREDICATE"),
        }
    }
}

#[derive(Debug, Error)]
#[error("{status}: {message}")]
pub struct ValidationError {
    pub status: ValidationStatus,
    pub message: String,
}

// ─── Parsed + validated request ──────────────────────────────────────────────

/// A certification request that has passed all validation checks.
#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    /// Raw 32-byte StateID (hash, not imprint).
    pub state_id: Vec<u8>,
    /// Lower-hex encoding of `state_id`, computed once here (on the parallel
    /// HTTP handler task) so downstream code — in particular the single
    /// `RoundManager` task, which would otherwise redo this for every request
    /// in a batch — can reuse it instead of re-deriving it from raw bytes.
    pub state_id_hex: String,
    /// Re-encoded CBOR of the Predicate (for hashing).
    pub predicate_cbor: Vec<u8>,
    /// Raw 32-byte source-state hash.
    pub source_state_hash: Vec<u8>,
    /// Raw 32-byte transaction hash.
    pub transaction_hash: Vec<u8>,
    /// Exclusive certification request deadline in Unix seconds, or
    /// `None` when the requester leaves the deadline to the service.
    /// The transaction hash commits to it only when it is explicit.
    pub expires_at: Option<u64>,
    /// Absolute deadline the request is actually held to: the explicit timeout
    /// when there is one, otherwise the service's default lifetime added to the
    /// reference time at admission. It is service metadata and does not enter
    /// the transaction hash.
    pub effective_timeout: u64,
    /// 65-byte secp256k1 witness (signature).
    pub witness: Vec<u8>,
    /// 33-byte compressed secp256k1 public key.
    pub public_key: Vec<u8>,
}

// ─── Full validation pipeline ─────────────────────────────────────────────────

/// Validate a certification request and return a `ValidatedRequest` if it
/// passes all checks.
///
/// Matches Go `CertificationRequestValidator.Validate`.
pub fn validate_request(
    state_id: &[u8],
    predicate_cbor: &[u8],
    engine: u64,
    code: &[u8],
    params: &[u8],
    source_state_hash: &[u8],
    transaction_hash: &[u8],
    expires_at: Option<u64>,
    effective_timeout: u64,
    witness: &[u8],
) -> Result<ValidatedRequest, ValidationError> {
    // 1. Validate predicate.
    let pred = validate_pay_to_public_key(engine, code, params).map_err(|e| ValidationError {
        status: ValidationStatus::InvalidOwnerPredicate,
        message: e.to_string(),
    })?;

    // 2. Validate source state hash length (must be 32 bytes).
    if source_state_hash.len() != 32 {
        return Err(ValidationError {
            status: ValidationStatus::InvalidSourceStateHashFormat,
            message: format!(
                "source state hash must be 32 bytes, got {}",
                source_state_hash.len()
            ),
        });
    }

    // 3. Validate StateID.
    if !validate_state_id(state_id, predicate_cbor, source_state_hash) {
        return Err(ValidationError {
            status: ValidationStatus::StateIdMismatch,
            message: "state ID does not match expected value".into(),
        });
    }

    // 4. Validate signature format.
    if witness.len() != 65 {
        return Err(ValidationError {
            status: ValidationStatus::InvalidSignatureFormat,
            message: format!("witness must be 65 bytes, got {}", witness.len()),
        });
    }

    // 5. Validate transaction hash length.
    if transaction_hash.len() != AGGREGATION_TREE_VALUE_SIZE {
        return Err(ValidationError {
            status: ValidationStatus::InvalidTransactionHashFormat,
            message: format!(
                "transaction hash must be {AGGREGATION_TREE_VALUE_SIZE} bytes, got {}",
                transaction_hash.len()
            ),
        });
    }

    // 6. Verify signature.
    let sig_hash = compute_sig_data_hash(source_state_hash, transaction_hash);
    verify_signature(&sig_hash, witness, &pred.public_key).map_err(|e| ValidationError {
        status: ValidationStatus::SignatureVerificationFailed,
        message: e.to_string(),
    })?;

    Ok(ValidatedRequest {
        state_id_hex: hex::encode(state_id),
        state_id: state_id.to_vec(),
        predicate_cbor: predicate_cbor.to_vec(),
        source_state_hash: source_state_hash.to_vec(),
        transaction_hash: transaction_hash.to_vec(),
        expires_at,
        effective_timeout,
        witness: witness.to_vec(),
        public_key: pred.public_key,
    })
}
