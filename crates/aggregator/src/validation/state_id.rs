//! StateID computation and validation.
//!
//! StateID = SHA256( CBOR_ARRAY(2) || predicate_cbor_bytes || CBOR_BYTES(source_state_hash) )
//!
//! Matches Go `CreateStateID` / `StateIDDataHash` and the `CertDataHash` function.

use sha2::{Digest, Sha256};
use crate::smt::hash::{cbor_array, cbor_bytes};
use crate::smt::SmtKey;

/// Compute the raw 32-byte StateID hash from the CBOR-encoded predicate and
/// the source-state hash.
///
/// `predicate_cbor` is the raw CBOR bytes of the Predicate struct
/// (CBOR array `[engine: uint, code: bytes, params: bytes]`).
/// `source_state_hash` is the 32-byte raw hash.
///
/// Matches Go `StateIDDataHash`:
/// ```text
/// SHA256( CBOR_ARRAY(2) || predicate_cbor || CBOR_BYTES(source_state_hash) )
/// ```
pub fn compute_state_id(predicate_cbor: &[u8], source_state_hash: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cbor_array(2));
    // Note: predicate bytes are added RAW (not wrapped in CBOR_BYTES).
    h.update(predicate_cbor);
    h.update(cbor_bytes(source_state_hash));
    h.finalize().into()
}

/// Validate that the provided StateID matches the expected value.
pub fn validate_state_id(
    state_id: &[u8],
    predicate_cbor: &[u8],
    source_state_hash: &[u8],
) -> bool {
    let expected = compute_state_id(predicate_cbor, source_state_hash);
    state_id == expected
}

/// Compute the `SigDataHash` used for signature verification.
///
/// `SHA256( CBOR_ARRAY(2) || CBOR_BYTES(source_state_hash) || CBOR_BYTES(transaction_hash) )`
pub fn compute_sig_data_hash(source_state_hash: &[u8], transaction_hash: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cbor_array(2));
    h.update(cbor_bytes(source_state_hash));
    h.update(cbor_bytes(transaction_hash));
    h.finalize().into()
}

/// Compute the `CertDataHash` (32 bytes) used as the SMT leaf value.
///
/// ```text
/// SHA256( CBOR_ARRAY(4)
///         || predicate_cbor          (raw, not wrapped)
///         || CBOR_BYTES(source_state_hash)
///         || CBOR_BYTES(transaction_hash)
///         || CBOR_BYTES(witness)
///       )
/// ```
pub fn compute_cert_data_hash(
    predicate_cbor: &[u8],
    source_state_hash: &[u8],
    transaction_hash: &[u8],
    witness: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cbor_array(4));
    h.update(predicate_cbor);         // raw CBOR bytes (not wrapped)
    h.update(cbor_bytes(source_state_hash));
    h.update(cbor_bytes(transaction_hash));
    h.update(cbor_bytes(witness));
    h.finalize().into()
}

/// Convert a raw StateID byte slice to an [`SmtKey`].
pub fn state_id_to_smt_key(state_id: &[u8]) -> SmtKey {
    crate::smt::state_id_to_smt_key(state_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn predicate_cbor_p2pk(pubkey: &[u8]) -> Vec<u8> {
        // CBOR Array [1, bytes([0x01]), bytes(pubkey)]
        // Manually build to match fxamacker/cbor output.
        let mut out = Vec::new();
        out.push(0x83); // array(3)
        out.push(0x01); // uint(1) — engine
        out.push(0x41); out.push(0x01); // bytes(1): [0x01] — code
        // params: pubkey (33 bytes) → 0x58 0x21 <33 bytes>
        out.push(0x58); out.push(0x21);
        out.extend_from_slice(pubkey);
        out
    }

    #[test]
    fn state_id_deterministic() {
        let pk = [2u8; 33];
        let pred = predicate_cbor_p2pk(&pk);
        let ssh = [0u8; 32];
        let id1 = compute_state_id(&pred, &ssh);
        let id2 = compute_state_id(&pred, &ssh);
        assert_eq!(id1, id2);
    }

    #[test]
    fn validate_state_id_correct() {
        let pk = [2u8; 33];
        let pred = predicate_cbor_p2pk(&pk);
        let ssh = [1u8; 32];
        let id = compute_state_id(&pred, &ssh);
        assert!(validate_state_id(&id, &pred, &ssh));
    }

    #[test]
    fn validate_state_id_wrong() {
        let pk = [2u8; 33];
        let pred = predicate_cbor_p2pk(&pk);
        let id = compute_state_id(&pred, &[0u8; 32]);
        // Different source hash → mismatch
        assert!(!validate_state_id(&id, &pred, &[1u8; 32]));
    }

    #[test]
    fn cert_data_hash_is_32_bytes() {
        let h = compute_cert_data_hash(&[0x83, 0x01], &[0u8; 32], &[0u8; 32], &[0u8; 65]);
        assert_eq!(h.len(), 32);
    }
}
