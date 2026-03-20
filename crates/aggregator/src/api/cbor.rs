//! CBOR serialization helpers for the client wire protocol.
//!
//! The client sends certification requests as hex-encoded CBOR.
//! The aggregator responds with hex-encoded CBOR for inclusion proofs.
//!
//! Deserialization uses `ciborium::Value` for flexibility; serialization
//! builds `ciborium::Value` trees and encodes them.

use ciborium::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CborError {
    #[error("CBOR decode error: {0}")]
    Decode(String),
    #[error("CBOR encode error: {0}")]
    Encode(String),
    #[error("unexpected CBOR type at {path}: {msg}")]
    TypeMismatch { path: String, msg: String },
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

// ─── Low-level Value extraction helpers ──────────────────────────────────────

pub fn val_as_bytes(v: &Value, path: &str) -> Result<Vec<u8>, CborError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("expected bytes, got {:?}", v),
        }),
    }
}

pub fn val_as_array<'a>(v: &'a Value, path: &str) -> Result<&'a Vec<Value>, CborError> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("expected array, got {:?}", v),
        }),
    }
}

pub fn val_as_u64(v: &Value, path: &str) -> Result<u64, CborError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            Ok(n as u64)
        }
        _ => Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("expected integer, got {:?}", v),
        }),
    }
}

pub fn val_as_bool(v: &Value, path: &str) -> Result<bool, CborError> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("expected bool, got {:?}", v),
        }),
    }
}

// ─── Decode helpers ───────────────────────────────────────────────────────────

pub fn decode_cbor_value(data: &[u8]) -> Result<Value, CborError> {
    ciborium::de::from_reader(data).map_err(|e| CborError::Decode(e.to_string()))
}

pub fn encode_cbor_value(v: &Value) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(v, &mut buf).map_err(|e| CborError::Encode(e.to_string()))?;
    Ok(buf)
}

// ─── Parsed CertificationRequest ─────────────────────────────────────────────

/// Fields extracted from a raw CBOR-decoded CertificationRequest.
#[derive(Debug, Clone)]
pub struct ParsedCertificationRequest {
    /// Raw 32-byte StateID.
    pub state_id: Vec<u8>,
    /// Re-encoded CBOR bytes of the Predicate (for hashing).
    pub predicate_cbor: Vec<u8>,
    /// Predicate engine value.
    pub engine: u64,
    /// Predicate code bytes.
    pub code: Vec<u8>,
    /// Predicate params (public key).
    pub params: Vec<u8>,
    /// 32-byte source-state hash.
    pub source_state_hash: Vec<u8>,
    /// 32-byte transaction hash.
    pub transaction_hash: Vec<u8>,
    /// 65-byte witness.
    pub witness: Vec<u8>,
}

/// Deserialize a hex-encoded CBOR CertificationRequest string.
///
/// Wire format (CBOR array):
/// ```text
/// [
///   StateID: bytes(32),
///   CertificationData: [
///     Predicate: [engine: uint, code: bytes, params: bytes],
///     SourceStateHash: bytes(32),
///     TransactionHash: bytes(32),
///     Witness: bytes(65),
///   ],
///   Receipt: bool,
///   AggregateRequestCount: uint,
/// ]
/// ```
pub fn parse_certification_request(hex_cbor: &str) -> Result<ParsedCertificationRequest, CborError> {
    let raw = hex::decode(hex_cbor)?;
    parse_certification_request_bytes(&raw)
}

pub fn parse_certification_request_bytes(raw: &[u8]) -> Result<ParsedCertificationRequest, CborError> {
    let val = decode_cbor_value(raw)?;
    let arr = val_as_array(&val, "CertificationRequest")?;
    if arr.len() < 3 {
        return Err(CborError::TypeMismatch {
            path: "CertificationRequest".into(),
            msg: format!("expected ≥3 elements, got {}", arr.len()),
        });
    }

    // StateID
    let state_id = val_as_bytes(&arr[0], "StateID")?;

    // CertificationData
    let cd_arr = val_as_array(&arr[1], "CertificationData")?;
    if cd_arr.len() < 4 {
        return Err(CborError::TypeMismatch {
            path: "CertificationData".into(),
            msg: format!("expected ≥4 elements, got {}", cd_arr.len()),
        });
    }

    // Predicate — re-encode to get raw CBOR bytes for hashing.
    let pred_val = &cd_arr[0];
    let predicate_cbor = encode_cbor_value(pred_val)?;
    let pred_arr = val_as_array(pred_val, "Predicate")?;
    if pred_arr.len() < 3 {
        return Err(CborError::TypeMismatch {
            path: "Predicate".into(),
            msg: format!("expected ≥3 elements, got {}", pred_arr.len()),
        });
    }
    let engine = val_as_u64(&pred_arr[0], "Predicate.engine")?;
    let code = val_as_bytes(&pred_arr[1], "Predicate.code")?;
    let params = val_as_bytes(&pred_arr[2], "Predicate.params")?;

    let source_state_hash = val_as_bytes(&cd_arr[1], "SourceStateHash")?;
    let transaction_hash = val_as_bytes(&cd_arr[2], "TransactionHash")?;
    let witness = val_as_bytes(&cd_arr[3], "Witness")?;

    Ok(ParsedCertificationRequest {
        state_id,
        predicate_cbor,
        engine,
        code,
        params,
        source_state_hash,
        transaction_hash,
        witness,
    })
}

// ─── Encode inclusion proof response ─────────────────────────────────────────

/// Encode an inclusion proof response as hex-encoded CBOR.
///
/// Wire format:
/// ```text
/// CBOR_ARRAY(2) [
///   blockNumber: uint,
///   CBOR_ARRAY(3) [           -- InclusionProofV2
///     certificationData: null | CBOR_ARRAY(4)[predicate, ssh, txh, witness],
///     merkleTreePath: CBOR_ARRAY(2)[root_bytes, [[path_bytes, data|null], ...]],
///     unicityCertificate: bytes,
///   ]
/// ]
/// ```
pub fn encode_inclusion_proof_response(
    block_number: u64,
    cert_data: Option<&CertDataFields>,
    merkle_path_cbor: &[u8],  // already CBOR-encoded MerkleTreePath
    uc_cbor: &[u8],           // raw CBOR bytes of the UnicityCertificate
) -> Result<String, CborError> {
    // Decode the already-encoded MerkleTreePath CBOR back to Value for embedding.
    let path_val = decode_cbor_value(merkle_path_cbor)?;

    let cert_val = match cert_data {
        None => Value::Null,
        Some(cd) => build_cert_data_value(cd),
    };

    // uc_cbor is already a tagged CBOR value (tag 1007 + array) from BFT Core.
    // Decode it back to a Value so it is embedded directly (not wrapped in bytes).
    let uc_val = decode_cbor_value(uc_cbor)?;

    let proof_val = Value::Array(vec![cert_val, path_val, uc_val]);

    let response_val = Value::Array(vec![
        Value::Integer(ciborium::value::Integer::from(block_number)),
        proof_val,
    ]);

    let cbor = encode_cbor_value(&response_val)?;
    Ok(hex::encode(cbor))
}

/// Fields needed to encode CertificationData in the inclusion proof.
#[derive(Debug, Clone)]
pub struct CertDataFields {
    pub predicate_cbor: Vec<u8>, // raw predicate CBOR (decoded, for embedding)
    pub source_state_hash: Vec<u8>,
    pub transaction_hash: Vec<u8>,
    pub witness: Vec<u8>,
}

fn build_cert_data_value(cd: &CertDataFields) -> Value {
    // Predicate is embedded as its parsed CBOR value (not double-wrapped).
    let pred_val = decode_cbor_value(&cd.predicate_cbor)
        .unwrap_or(Value::Null);
    Value::Array(vec![
        pred_val,
        Value::Bytes(cd.source_state_hash.clone()),
        Value::Bytes(cd.transaction_hash.clone()),
        Value::Bytes(cd.witness.clone()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_cbor_value() {
        // CBOR uint 42 = 0x182a
        let raw = vec![0x18, 0x2a];
        let val = decode_cbor_value(&raw).unwrap();
        assert_eq!(val_as_u64(&val, "test").unwrap(), 42);
    }

    #[test]
    fn roundtrip_encode_decode() {
        let val = Value::Integer(ciborium::value::Integer::from(99u64));
        let enc = encode_cbor_value(&val).unwrap();
        let dec = decode_cbor_value(&enc).unwrap();
        assert_eq!(val_as_u64(&dec, "test").unwrap(), 99);
    }
}
