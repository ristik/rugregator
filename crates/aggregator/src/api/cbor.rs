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
            u64::try_from(n).map_err(|_| CborError::TypeMismatch {
                path: path.into(),
                msg: format!("expected non-negative integer, got {n}"),
            })
        }
        _ => Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("expected integer, got {:?}", v),
        }),
    }
}

pub(crate) const UNICITY_CERTIFICATE_TAG: u64 = 39001;
pub(crate) const INPUT_RECORD_TAG: u64 = 39002;
pub(crate) const SHARD_TREE_CERTIFICATE_TAG: u64 = 39003;
pub(crate) const UNICITY_TREE_CERTIFICATE_TAG: u64 = 39004;
pub(crate) const UNICITY_SEAL_TAG: u64 = 39005;
const CERTIFICATION_REQUEST_TAG: u64 = 39030;
const CERTIFICATION_DATA_TAG: u64 = 39031;
const PREDICATE_TAG: u64 = 39032;
pub const INCLUSION_PROOF_TAG: u64 = 39033;
/// CBOR tag for the relation-specific non-inclusion proof object.
pub const NON_INCLUSION_PROOF_TAG: u64 = 39034;
const VERSION: u64 = 1;
/// The only accepted CertificationData wire version. One version, one element
/// count: `expiresAt` holds its slot as CBOR null when the requester left the
/// deadline to the service.
const CERT_DATA_VERSION: u64 = 2;
const CERT_DATA_FIELD_COUNT: usize = 6;

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
    let mut remaining = data;
    let value =
        ciborium::de::from_reader(&mut remaining).map_err(|e| CborError::Decode(e.to_string()))?;
    if !remaining.is_empty() {
        return Err(CborError::Decode("trailing bytes after CBOR value".into()));
    }
    Ok(value)
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
    /// 32-byte transaction hash. It commits to `timeout`, so the witness signs
    /// the timeout along with the rest of the transaction.
    pub transaction_hash: Vec<u8>,
    /// Exclusive certification request deadline in Unix seconds, or
    /// `None` when the requester leaves the deadline to the service.
    pub expires_at: Option<u64>,
    /// 65-byte witness.
    pub witness: Vec<u8>,
}

/// Deserialize a hex-encoded CBOR CertificationRequest string.
///
/// Canonical wire format:
/// ```text
/// #6.39030([
///   1,
///   StateID: bytes(32),
///   #6.39031([
///     2,
///     #6.39032([engine: uint, code: bytes, params: bytes]),
///     SourceStateHash: bytes(32),
///     TransactionHash: bytes(32),
///     ExpiresAt: uint | null,
///     Witness: bytes(65),
///   ]),
///   0,
/// ])
/// ```
///
/// CertificationData has one version and one element count. `ExpiresAt` keeps
/// its position as CBOR null when the requester leaves the deadline to the
/// service.
pub fn parse_certification_request(
    hex_cbor: &str,
) -> Result<ParsedCertificationRequest, CborError> {
    let raw = hex::decode(hex_cbor)?;
    parse_certification_request_bytes(&raw)
}

pub fn parse_certification_request_bytes(
    raw: &[u8],
) -> Result<ParsedCertificationRequest, CborError> {
    let val = decode_cbor_value(raw)?;
    // SDK requests are deterministic CBOR. Re-encoding the array/tag-only
    // structure is a simple canonicality check at this trust boundary.
    if encode_cbor_value(&val)? != raw {
        return Err(CborError::Decode(
            "CertificationRequest is not canonical CBOR".into(),
        ));
    }
    parse_certification_request_v1(&val)
}

fn parse_certification_request_v1(val: &Value) -> Result<ParsedCertificationRequest, CborError> {
    let request = val_as_tag(val, CERTIFICATION_REQUEST_TAG, "CertificationRequest")?;
    let arr = val_as_exact_array(request, 4, "CertificationRequest")?;
    require_version(&arr[0], VERSION, "CertificationRequest.version")?;

    let state_id = val_as_bytes(&arr[1], "StateID")?;
    let cert = val_as_tag(&arr[2], CERTIFICATION_DATA_TAG, "CertificationData")?;
    let cert_arr = val_as_exact_array(cert, CERT_DATA_FIELD_COUNT, "CertificationData")?;
    require_version(&cert_arr[0], CERT_DATA_VERSION, "CertificationData.version")?;

    let predicate = &cert_arr[1];
    let predicate_inner = val_as_tag(predicate, PREDICATE_TAG, "Predicate")?;
    let predicate_arr = val_as_exact_array(predicate_inner, 3, "Predicate")?;
    let predicate_cbor = encode_cbor_value(predicate)?;
    let engine = val_as_u64(&predicate_arr[0], "Predicate.engine")?;
    let code = val_as_bytes(&predicate_arr[1], "Predicate.code")?;
    let params = val_as_bytes(&predicate_arr[2], "Predicate.params")?;

    let source_state_hash = val_as_bytes(&cert_arr[2], "SourceStateHash")?;
    let transaction_hash = val_as_bytes(&cert_arr[3], "TransactionHash")?;
    let expires_at = match &cert_arr[4] {
        Value::Null => None,
        v => Some(val_as_u64(v, "ExpiresAt")?),
    };
    let witness = val_as_bytes(&cert_arr[5], "Witness")?;
    if val_as_u64(&arr[3], "CertificationRequest.reserved")? != 0 {
        return Err(CborError::TypeMismatch {
            path: "CertificationRequest.reserved".into(),
            msg: "expected zero".into(),
        });
    }

    Ok(ParsedCertificationRequest {
        state_id,
        predicate_cbor,
        engine,
        code,
        params,
        source_state_hash,
        transaction_hash,
        expires_at,
        witness,
    })
}

fn val_as_tag<'a>(v: &'a Value, expected: u64, path: &str) -> Result<&'a Value, CborError> {
    match v {
        Value::Tag(tag, inner) if *tag == expected => Ok(inner),
        Value::Tag(tag, _) => Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("expected CBOR tag {expected}, got {tag}"),
        }),
        _ => Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("expected CBOR tag {expected}, got {v:?}"),
        }),
    }
}

fn val_as_exact_array<'a>(
    v: &'a Value,
    expected: usize,
    path: &str,
) -> Result<&'a Vec<Value>, CborError> {
    let arr = val_as_array(v, path)?;
    if arr.len() != expected {
        return Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("expected {expected} elements, got {}", arr.len()),
        });
    }
    Ok(arr)
}

fn require_version(v: &Value, expected: u64, path: &str) -> Result<(), CborError> {
    let actual = val_as_u64(v, path)?;
    if actual != expected {
        return Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("unsupported version {actual}"),
        });
    }
    Ok(())
}

fn versioned_tagged_array<'a>(
    value: &'a Value,
    tag: u64,
    length: usize,
    path: &str,
) -> Result<&'a Vec<Value>, CborError> {
    let inner = val_as_tag(value, tag, path)?;
    let fields = val_as_exact_array(inner, length, path)?;
    require_version(&fields[0], VERSION, &format!("{path}.version"))?;
    Ok(fields)
}

fn optional_bytes(value: &Value, path: &str) -> Result<(), CborError> {
    if matches!(value, Value::Null) {
        return Ok(());
    }
    val_as_bytes(value, path).map(|_| ())
}

fn require_byte_length(value: &Value, length: usize, path: &str) -> Result<(), CborError> {
    let bytes = val_as_bytes(value, path)?;
    if bytes.len() != length {
        return Err(CborError::TypeMismatch {
            path: path.into(),
            msg: format!("expected {length} bytes, got {}", bytes.len()),
        });
    }
    Ok(())
}

fn require_u32(value: &Value, path: &str) -> Result<(), CborError> {
    let number = val_as_u64(value, path)?;
    if number > u32::MAX as u64 {
        return Err(CborError::TypeMismatch {
            path: path.into(),
            msg: "value exceeds uint32".into(),
        });
    }
    Ok(())
}

/// Validate the one current, SDK-owned Unicity Certificate wire profile and
/// return its certified aggregation-tree root.
///
/// Checking every nested versioned tag and field shape here prevents an opaque
/// BFT payload from reintroducing a second hashing/signature profile through
/// either proof endpoint. Cryptographic trust-base verification remains the
/// client's responsibility.
pub(crate) fn unicity_certificate_state_root(value: &Value) -> Result<Option<[u8; 32]>, CborError> {
    let uc = versioned_tagged_array(value, UNICITY_CERTIFICATE_TAG, 7, "UnicityCertificate")?;
    let input = versioned_tagged_array(&uc[1], INPUT_RECORD_TAG, 10, "InputRecord")?;
    val_as_u64(&input[1], "InputRecord.roundNumber")?;
    val_as_u64(&input[2], "InputRecord.epoch")?;
    optional_bytes(&input[3], "InputRecord.previousHash")?;
    let state_root = match val_as_bytes(&input[4], "InputRecord.hash")?.as_slice() {
        [] => None,
        bytes if bytes.len() == 32 => Some(bytes.try_into().expect("length checked")),
        bytes => {
            return Err(CborError::TypeMismatch {
                path: "InputRecord.hash".into(),
                msg: format!("expected zero or 32 bytes, got {}", bytes.len()),
            })
        }
    };
    val_as_bytes(&input[5], "InputRecord.summaryValue")?;
    val_as_u64(&input[6], "InputRecord.timestamp")?;
    optional_bytes(&input[7], "InputRecord.blockHash")?;
    val_as_u64(&input[8], "InputRecord.sumOfEarnedFees")?;
    optional_bytes(&input[9], "InputRecord.executedTransactionsHash")?;

    optional_bytes(&uc[2], "UnicityCertificate.technicalRecordHash")?;
    val_as_bytes(&uc[3], "UnicityCertificate.shardConfigurationHash")?;

    let shard = versioned_tagged_array(
        &uc[4],
        SHARD_TREE_CERTIFICATE_TAG,
        3,
        "ShardTreeCertificate",
    )?;
    let shard_id = val_as_bytes(&shard[1], "ShardTreeCertificate.shard")?;
    if shard_id.last().copied().unwrap_or(0) == 0 {
        return Err(CborError::TypeMismatch {
            path: "ShardTreeCertificate.shard".into(),
            msg: "invalid ShardId end-marker encoding".into(),
        });
    }
    for sibling in val_as_array(&shard[2], "ShardTreeCertificate.siblingHashList")? {
        require_byte_length(sibling, 32, "ShardTreeCertificate.siblingHash")?;
    }

    let unicity_tree = versioned_tagged_array(
        &uc[5],
        UNICITY_TREE_CERTIFICATE_TAG,
        3,
        "UnicityTreeCertificate",
    )?;
    require_u32(
        &unicity_tree[1],
        "UnicityTreeCertificate.partitionIdentifier",
    )?;
    for step in val_as_array(&unicity_tree[2], "UnicityTreeCertificate.steps")? {
        let step = val_as_exact_array(step, 2, "UnicityTreeCertificate.step")?;
        require_u32(&step[0], "UnicityTreeCertificate.step.key")?;
        require_byte_length(&step[1], 32, "UnicityTreeCertificate.step.hash")?;
    }

    let seal = versioned_tagged_array(&uc[6], UNICITY_SEAL_TAG, 8, "UnicitySeal")?;
    let network_id = val_as_u64(&seal[1], "UnicitySeal.networkId")?;
    if !(1..=u16::MAX as u64).contains(&network_id) {
        return Err(CborError::TypeMismatch {
            path: "UnicitySeal.networkId".into(),
            msg: "expected value in 1..=65535".into(),
        });
    }
    val_as_u64(&seal[2], "UnicitySeal.rootChainRoundNumber")?;
    val_as_u64(&seal[3], "UnicitySeal.epoch")?;
    val_as_u64(&seal[4], "UnicitySeal.timestamp")?;
    optional_bytes(&seal[5], "UnicitySeal.previousHash")?;
    require_byte_length(&seal[6], 32, "UnicitySeal.hash")?;
    match &seal[7] {
        Value::Null => {}
        Value::Map(signatures) => {
            for (node_id, signature) in signatures {
                if !matches!(node_id, Value::Text(_)) {
                    return Err(CborError::TypeMismatch {
                        path: "UnicitySeal.signatures.nodeId".into(),
                        msg: "expected text".into(),
                    });
                }
                require_byte_length(signature, 65, "UnicitySeal.signatures.signature")?;
            }
        }
        value => {
            return Err(CborError::TypeMismatch {
                path: "UnicitySeal.signatures".into(),
                msg: format!("expected null or map, got {value:?}"),
            })
        }
    }

    Ok(state_root)
}

/// Return the timestamp in the certificate's input record. This is the
/// reference time the newly certified leaves must have been built from.
pub(crate) fn unicity_certificate_reference_time(value: &Value) -> Result<u64, CborError> {
    let uc = versioned_tagged_array(value, UNICITY_CERTIFICATE_TAG, 7, "UnicityCertificate")?;
    let input = versioned_tagged_array(&uc[1], INPUT_RECORD_TAG, 10, "InputRecord")?;
    val_as_u64(&input[6], "InputRecord.timestamp")
}

/// Return the seal timestamp that becomes the next round's reference time.
#[cfg(test)]
pub(crate) fn unicity_certificate_next_reference_time(value: &Value) -> Result<u64, CborError> {
    let uc = versioned_tagged_array(value, UNICITY_CERTIFICATE_TAG, 7, "UnicityCertificate")?;
    let seal = versioned_tagged_array(&uc[6], UNICITY_SEAL_TAG, 8, "UnicitySeal")?;
    val_as_u64(&seal[4], "UnicitySeal.timestamp")
}

pub(crate) fn validate_unicity_certificate_value(value: &Value) -> Result<(), CborError> {
    unicity_certificate_state_root(value).map(|_| ())
}

fn decode_unicity_certificate_value(data: &[u8]) -> Result<Value, CborError> {
    let value = decode_cbor_value(data)?;
    validate_unicity_certificate_value(&value)?;
    Ok(value)
}

// ─── Encode inclusion proof response ─────────────────────────────────────────

/// Encode an inclusion proof response as hex-encoded CBOR.
///
/// Wire format:
/// ```text
/// CBOR_ARRAY(2) [
///   blockNumber: uint,
///   #6.39033([               -- InclusionProof
///     1,
///     certificationData: null | #6.39031([2, predicate, ssh, txh, expiresAt, witness]),
///     referenceTime: null | uint,
///     inclusionCertificate: null | bytes,
///     unicityCertificate: #6.39001(...),
///   ])
/// ]
/// ```
#[allow(clippy::too_many_arguments)]
pub fn encode_inclusion_proof_response(
    block_number: u64,
    cert_data: Option<&CertDataFields>,
    reference_time: Option<u64>, // reference time the certified leaf was built from
    merkle_path_cbor: &[u8],     // raw InclusionCertificate bytes
    uc_cbor: &[u8],              // raw CBOR bytes of the UnicityCertificate
) -> Result<String, CborError> {
    let path_val = Value::Bytes(merkle_path_cbor.to_vec());

    let cert_val = match cert_data {
        None => Value::Null,
        Some(cd) => build_cert_data_value(cd)?,
    };

    // Embed the already-encoded certificate directly, after enforcing the one
    // canonical profile shared by inclusion and non-inclusion responses.
    let uc_val = decode_unicity_certificate_value(uc_cbor)?;

    // The reference time cannot be recovered from the embedded certificate:
    // proofs are served against the current certified root, whose input record
    // time is the latest round's rather than the one the leaf was created
    // under. A verifier needs the carried value to reproduce the leaf.
    let reference_time_val = match reference_time {
        None => Value::Null,
        Some(t) => Value::Integer(ciborium::value::Integer::from(t)),
    };

    let proof_val = Value::Tag(
        INCLUSION_PROOF_TAG,
        Box::new(Value::Array(vec![
            Value::Integer(ciborium::value::Integer::from(VERSION)),
            cert_val,
            reference_time_val,
            path_val,
            uc_val,
        ])),
    );

    let response_val = Value::Array(vec![
        Value::Integer(ciborium::value::Integer::from(block_number)),
        proof_val,
    ]);

    let cbor = encode_cbor_value(&response_val)?;
    Ok(hex::encode(cbor))
}

// ─── Encode non-inclusion proof response ────────────────────────────────────

/// Encode `[blockNumber, NonInclusionProof]` as a hex-encoded CBOR value.
///
/// `NonInclusionProof` is tag 39034 over
/// `[version = 1, nonInclusionCertificate: bytes, unicityCertificate]`.
/// The certificate bytes are empty only for an empty certified SMT.
pub fn encode_non_inclusion_proof_response(
    block_number: u64,
    certificate: &[u8],
    uc_cbor: &[u8],
) -> Result<String, CborError> {
    let uc_val = decode_unicity_certificate_value(uc_cbor)?;
    let proof_val = Value::Tag(
        NON_INCLUSION_PROOF_TAG,
        Box::new(Value::Array(vec![
            Value::Integer(ciborium::value::Integer::from(VERSION)),
            Value::Bytes(certificate.to_vec()),
            uc_val,
        ])),
    );
    let response_val = Value::Array(vec![
        Value::Integer(ciborium::value::Integer::from(block_number)),
        proof_val,
    ]);
    Ok(hex::encode(encode_cbor_value(&response_val)?))
}

/// Fields needed to encode CertificationData in the inclusion proof.
#[derive(Debug, Clone)]
pub struct CertDataFields {
    pub predicate_cbor: Vec<u8>, // raw predicate CBOR (decoded, for embedding)
    pub source_state_hash: Vec<u8>,
    pub transaction_hash: Vec<u8>,
    /// Exclusive certification request deadline in Unix seconds, or
    /// `None` when the requester leaves the deadline to the service.
    pub expires_at: Option<u64>,
    pub witness: Vec<u8>,
}

fn build_cert_data_value(cd: &CertDataFields) -> Result<Value, CborError> {
    // Predicate is embedded as its parsed CBOR value (not double-wrapped).
    let pred_val = decode_cbor_value(&cd.predicate_cbor)?;
    let predicate = val_as_tag(&pred_val, PREDICATE_TAG, "Predicate")?;
    val_as_exact_array(predicate, 3, "Predicate")?;
    // One shape: the deadline holds its slot either way, so re-encoding cannot
    // change the element count and the transaction hash stays reproducible.
    let fields = vec![
        Value::Integer(ciborium::value::Integer::from(CERT_DATA_VERSION)),
        pred_val,
        Value::Bytes(cd.source_state_hash.clone()),
        Value::Bytes(cd.transaction_hash.clone()),
        match cd.expires_at {
            None => Value::Null,
            Some(expires_at) => Value::Integer(ciborium::value::Integer::from(expires_at)),
        },
        Value::Bytes(cd.witness.clone()),
    ];

    Ok(Value::Tag(
        CERTIFICATION_DATA_TAG,
        Box::new(Value::Array(fields)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exclusive certification request deadline every fixture in this module uses.
    const TEST_EXPIRES_AT: u64 = 1_755_003_600;

    fn uint(value: u64) -> Value {
        Value::Integer(ciborium::value::Integer::from(value))
    }

    fn canonical_uc() -> Value {
        Value::Tag(
            UNICITY_CERTIFICATE_TAG,
            Box::new(Value::Array(vec![
                uint(VERSION),
                Value::Tag(
                    INPUT_RECORD_TAG,
                    Box::new(Value::Array(vec![
                        uint(VERSION),
                        uint(7),
                        uint(0),
                        Value::Null,
                        Value::Bytes(vec![0x11; 32]),
                        Value::Bytes(vec![]),
                        uint(0),
                        Value::Null,
                        uint(0),
                        Value::Null,
                    ])),
                ),
                Value::Null,
                Value::Bytes(vec![0x22; 32]),
                Value::Tag(
                    SHARD_TREE_CERTIFICATE_TAG,
                    Box::new(Value::Array(vec![
                        uint(VERSION),
                        Value::Bytes(vec![0x80]),
                        Value::Array(vec![]),
                    ])),
                ),
                Value::Tag(
                    UNICITY_TREE_CERTIFICATE_TAG,
                    Box::new(Value::Array(vec![
                        uint(VERSION),
                        uint(0),
                        Value::Array(vec![]),
                    ])),
                ),
                Value::Tag(
                    UNICITY_SEAL_TAG,
                    Box::new(Value::Array(vec![
                        uint(VERSION),
                        uint(3),
                        uint(7),
                        uint(0),
                        uint(0),
                        Value::Null,
                        Value::Bytes(vec![0x33; 32]),
                        Value::Null,
                    ])),
                ),
            ])),
        )
    }

    /// The certification request the JS, Java, Rust and Go SDKs all produce for
    /// the shared cross-implementation vector when the requester leaves the
    /// deadline to the service: `expiresAt` holds its slot as CBOR null.
    const ABSENT_DEADLINE_REQUEST: &str = "d9987684015820ffb36b55de9bfaf48b766d1f4e041a6c5d35ba23b402ea2a56a6c7692cb8f81ad998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820c034e096d7bdf71ba759558663b5cafb7279ecb7e284443e5e6cbce0461aceeef6584154ca6b19a7dbcae7a6adc38af5c8672f81943ecaf51345436684299b4b7ac81a57db2653f32048981e37913db4749ca08d998d1fac4a52ab5579988bc2c50de90000";

    /// The same request with a sender-chosen deadline in that slot. Same
    /// version, same element count; the transaction hash commits to whichever
    /// value the slot holds.
    const V2_REQUEST: &str = "d9987684015820ffb36b55de9bfaf48b766d1f4e041a6c5d35ba23b402ea2a56a6c7692cb8f81ad998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f9635075820e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e6152415820ed275ff0a0694d1b61ec22f13914a431569220ba7f2f043d7940aac78d02c2f91a689b2cc0584111f0f7929d70e0e32db9159b7e23b6e0043502bc36609728e9dc0353251c241a7b1adb047c9234cd77ed519c409048a6c8bc247f0262c1f161b03d6fee49426e0000";

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

    #[test]
    fn decoder_rejects_trailing_data_and_negative_unsigned_values() {
        assert!(decode_cbor_value(&[0x01, 0x02]).is_err());
        let negative = decode_cbor_value(&[0x20]).unwrap();
        assert!(val_as_u64(&negative, "unsigned").is_err());
    }

    /// The deadline sits between the transaction hash and the witness, and is
    /// read from that fixed position rather than inferred from the shape.
    #[test]
    fn parses_explicit_timeout_certification_request() {
        let request = hex::decode(V2_REQUEST).unwrap();
        let parsed = parse_certification_request_bytes(&request).unwrap();

        assert_eq!(parsed.expires_at, Some(1_755_000_000));
        assert_eq!(parsed.witness.len(), 65);
    }

    /// Re-encoding a parsed request reproduces the CertificationData bytes it
    /// arrived as. An inclusion proof carrying anything else would present a
    /// CertificationData the request's transaction hash does not commit to,
    /// and every SDK would reject the proof.
    #[test]
    fn re_encoding_preserves_the_certification_data_bytes() {
        for request in [ABSENT_DEADLINE_REQUEST, V2_REQUEST] {
            let bytes = hex::decode(request).unwrap();
            let parsed = parse_certification_request_bytes(&bytes).unwrap();

            let cert_data = CertDataFields {
                predicate_cbor: parsed.predicate_cbor.clone(),
                source_state_hash: parsed.source_state_hash.clone(),
                transaction_hash: parsed.transaction_hash.clone(),
                expires_at: parsed.expires_at,
                witness: parsed.witness.clone(),
            };
            let encoded = hex::encode(
                encode_cbor_value(&build_cert_data_value(&cert_data).unwrap()).unwrap(),
            );

            assert!(
                request.contains(&encoded),
                "re-encoded {encoded} is not the CertificationData of {request}"
            );
        }
    }

    /// There is one version and one element count. Anything else is rejected,
    /// including the retired encodings that omitted the deadline slot.
    #[test]
    fn rejects_any_other_certification_data_version() {
        for mutated in [
            ABSENT_DEADLINE_REQUEST.replace("d998778602", "d998778601"),
            ABSENT_DEADLINE_REQUEST.replace("d998778602", "d998778603"),
            V2_REQUEST.replace("d998778602", "d998778601"),
        ] {
            let bytes = hex::decode(mutated).unwrap();

            assert!(parse_certification_request_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn parses_versioned_sdk_certification_request_golden_vector() {
        let request = hex::decode(ABSENT_DEADLINE_REQUEST).unwrap();
        let parsed = parse_certification_request_bytes(&request).unwrap();

        assert_eq!(
            hex::encode(parsed.state_id),
            "ffb36b55de9bfaf48b766d1f4e041a6c5d35ba23b402ea2a56a6c7692cb8f81a"
        );
        assert_eq!(parsed.engine, 1);
        assert_eq!(parsed.code, vec![1]);
        assert_eq!(parsed.params.len(), 33);
        assert_eq!(parsed.source_state_hash.len(), 32);
        assert_eq!(parsed.transaction_hash.len(), 32);
        assert_eq!(parsed.expires_at, None);
        assert_eq!(parsed.witness.len(), 65);

        let mut trailing = request;
        trailing.push(0);
        assert!(parse_certification_request_bytes(&trailing).is_err());

        let untagged = encode_cbor_value(&Value::Array(vec![])).unwrap();
        assert!(parse_certification_request_bytes(&untagged).is_err());
    }

    #[test]
    fn proof_responses_use_relation_specific_tags_and_embed_canonical_uc() {
        let uc = canonical_uc();
        let uc_cbor = encode_cbor_value(&uc).unwrap();
        let certificate = vec![0xa5; 96];
        let encoded = encode_non_inclusion_proof_response(7, &certificate, &uc_cbor).unwrap();
        let response = decode_cbor_value(&hex::decode(encoded).unwrap()).unwrap();
        let response = val_as_exact_array(&response, 2, "response").unwrap();
        assert_eq!(val_as_u64(&response[0], "block").unwrap(), 7);
        let proof = val_as_tag(&response[1], NON_INCLUSION_PROOF_TAG, "proof").unwrap();
        let proof = val_as_exact_array(proof, 3, "proof").unwrap();
        assert_eq!(val_as_u64(&proof[0], "version").unwrap(), 1);
        assert_eq!(val_as_bytes(&proof[1], "certificate").unwrap(), certificate);
        assert_eq!(proof[2], uc);

        let predicate = Value::Tag(
            PREDICATE_TAG,
            Box::new(Value::Array(vec![
                uint(1),
                Value::Bytes(vec![1]),
                Value::Bytes(vec![2; 33]),
            ])),
        );
        let cert_data = CertDataFields {
            predicate_cbor: encode_cbor_value(&predicate).unwrap(),
            source_state_hash: vec![3; 32],
            transaction_hash: vec![4; 32],
            expires_at: Some(TEST_EXPIRES_AT),
            witness: vec![5; 65],
        };
        let encoded = encode_inclusion_proof_response(
            8,
            Some(&cert_data),
            Some(1_755_000_000),
            &[0xa6; 96],
            &uc_cbor,
        )
        .unwrap();
        let response = decode_cbor_value(&hex::decode(encoded).unwrap()).unwrap();
        let response = val_as_exact_array(&response, 2, "response").unwrap();
        assert_eq!(val_as_u64(&response[0], "block").unwrap(), 8);
        let proof = val_as_tag(&response[1], INCLUSION_PROOF_TAG, "proof").unwrap();
        let proof = val_as_exact_array(proof, 5, "proof").unwrap();
        assert_eq!(val_as_u64(&proof[0], "version").unwrap(), VERSION);
        assert!(val_as_tag(&proof[1], CERTIFICATION_DATA_TAG, "certification data").is_ok());
        assert_eq!(
            val_as_u64(&proof[2], "reference time").unwrap(),
            1_755_000_000
        );
        assert_eq!(
            val_as_bytes(&proof[3], "certificate").unwrap(),
            vec![0xa6; 96]
        );
        assert_eq!(proof[4], uc);
    }

    #[test]
    fn proof_responses_reject_the_legacy_uc_profile() {
        let legacy_uc = Value::Tag(1007, Box::new(Value::Array(vec![])));
        let legacy_uc = encode_cbor_value(&legacy_uc).unwrap();

        assert!(encode_non_inclusion_proof_response(1, &[], &legacy_uc).is_err());
        assert!(encode_inclusion_proof_response(1, None, None, &[], &legacy_uc).is_err());

        let mut mixed_profile = canonical_uc();
        let Value::Tag(_, uc) = &mut mixed_profile else {
            unreachable!()
        };
        let Value::Array(fields) = uc.as_mut() else {
            unreachable!()
        };
        let Value::Tag(_, input_record) = &fields[1] else {
            unreachable!()
        };
        fields[1] = Value::Tag(1008, input_record.clone());
        let mixed_profile = encode_cbor_value(&mixed_profile).unwrap();

        assert!(encode_non_inclusion_proof_response(1, &[], &mixed_profile).is_err());
        assert!(encode_inclusion_proof_response(1, None, None, &[], &mixed_profile).is_err());
    }
}
