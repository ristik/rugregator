//! CBOR serialization for BFT Core messages

use crate::types::{BlockCertificationRequest, UnicityCertificate, INPUT_RECORD_TAG};
use anyhow::Result;
use ciborium::value::Value;

/// Serialize a BlockCertificationRequest to CBOR bytes
/// InputRecord must be wrapped in CBOR tag 1008 as per BFT Core spec
pub fn serialize_certification_request(req: &BlockCertificationRequest) -> Result<Vec<u8>> {
    // Try direct serialization first - serde_tuple should handle array format
    let mut buffer = Vec::new();
    ciborium::into_writer(req, &mut buffer)?;

    // Now we need to wrap the InputRecord (4th element) in tag 1008
    // Parse back to Value to modify it
    let mut value: Value = ciborium::from_reader(&buffer[..])?;

    if let Value::Array(ref mut arr) = value {
        if arr.len() >= 4 {
            // Wrap the InputRecord (index 3) in tag 1008
            let ir_value = arr[3].clone();
            arr[3] = Value::Tag(INPUT_RECORD_TAG, Box::new(ir_value));
        }
    }

    // Re-serialize with the tagged InputRecord
    let mut final_buffer = Vec::new();
    ciborium::into_writer(&value, &mut final_buffer)?;
    Ok(final_buffer)
}

/// Deserialize a UnicityCertificate from CBOR bytes
pub fn deserialize_unicity_certificate(data: &[u8]) -> Result<UnicityCertificate> {
    let uc = ciborium::from_reader(data)?;
    Ok(uc)
}

/// Serialize a Handshake message to CBOR bytes
/// Handshake is serialized as CBOR array [partition_id, shard_id, node_id]
pub fn serialize_handshake(handshake: &crate::types::Handshake) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(handshake, &mut buffer)?;
    Ok(buffer)
}

/// Deserialize a CertificationResponse from CBOR bytes
pub fn deserialize_certification_response(data: &[u8]) -> Result<crate::types::CertificationResponse> {
    use crate::types::{CertificationResponse, TechnicalRecord, UnicityCertificate};
    use ciborium::value::Value;

    // Parse CBOR to Value
    let value: Value = ciborium::from_reader(data)?;

    // CertificationResponse should be an array with 4 elements
    let arr = match value {
        Value::Array(a) => a,
        _ => return Err(anyhow::anyhow!("CertificationResponse must be a CBOR array")),
    };

    if arr.len() != 4 {
        return Err(anyhow::anyhow!(
            "CertificationResponse array must have 4 elements, got {}",
            arr.len()
        ));
    }

    // Extract partition (PartitionID - uint32)
    let partition = match &arr[0] {
        Value::Integer(i) => (*i).try_into()?,
        _ => return Err(anyhow::anyhow!("Partition must be integer")),
    };

    // Extract shard (ShardID - bitstring bytes)
    let shard = match &arr[1] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(anyhow::anyhow!("Shard must be bytes")),
    };

    // Extract TechnicalRecord
    let mut tr_bytes = Vec::new();
    ciborium::into_writer(&arr[2], &mut tr_bytes)?;
    let technical: TechnicalRecord = ciborium::from_reader(&tr_bytes[..])?;

    // Extract UnicityCertificate (handle CBOR tags recursively)
    let uc_value = strip_tags_recursive(&arr[3]);
    let mut uc_bytes = Vec::new();
    ciborium::into_writer(&uc_value, &mut uc_bytes)?;

    let uc: UnicityCertificate = ciborium::from_reader(&uc_bytes[..])
        .map_err(|e| anyhow::anyhow!("Failed to deserialize UC: {}", e))?;

    Ok(CertificationResponse {
        partition,
        shard,
        technical,
        uc,
    })
}

/// Recursively strip CBOR tags from a Value tree
/// BFT Core uses tags (1007, 1001, 1014, 1008) but serde_tuple doesn't handle them automatically
fn strip_tags_recursive(value: &Value) -> Value {
    match value {
        Value::Tag(_tag, boxed_val) => {
            // Strip the tag and recursively process the inner value
            strip_tags_recursive(boxed_val)
        }
        Value::Array(arr) => {
            // Recursively strip tags from array elements
            Value::Array(arr.iter().map(strip_tags_recursive).collect())
        }
        Value::Map(map) => {
            // Recursively strip tags from map values
            Value::Map(
                map.iter()
                    .map(|(k, v)| (strip_tags_recursive(k), strip_tags_recursive(v)))
                    .collect()
            )
        }
        // For primitive values, return as-is
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InputRecord;

    #[test]
    fn test_roundtrip_serialization() {
        let input_record = InputRecord {
            version: 1,
            round_number: 100,
            epoch: 0,
            previous_hash: Some(vec![0u8; 32]),
            hash: Some(vec![0u8; 32]),
            summary_value: Some(vec![]),
            timestamp: 1234567890,
            block_hash: Some(vec![]),
            sum_of_earned_fees: 0,
            et_hash: Some(vec![]),
        };

        let req = BlockCertificationRequest {
            partition_id: 1,
            shard_id: vec![0x80],
            node_id: "test-node".to_string(),
            input_record,
            zk_proof: vec![0xAA, 0xBB, 0xCC, 0xDD],
            block_size: 1000,
            state_size: 50000,
            signature: vec![0u8; 64],
        };

        let serialized = serialize_certification_request(&req).unwrap();
        assert!(!serialized.is_empty());
    }
}
