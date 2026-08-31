//! JSON-RPC method handlers.

use std::sync::Arc;
use tracing::{info, warn};

use super::cbor::{
    encode_inclusion_proof_response, encode_non_inclusion_proof_response,
    parse_certification_request,
};
use super::types::{
    BlockHeightResponse, CertificationResponse, GetInclusionProofParams,
    GetNonInclusionProofParams, JsonRpcError,
};
use crate::storage::{AggregatorState, InclusionProofLookup, NonInclusionProofLookup};

// ─── certification_request ────────────────────────────────────────────────────

/// Handle `certification_request`.
///
/// Params: a single JSON string value — hex-encoded CBOR of the CertificationRequest.
pub async fn handle_certification_request(
    params: serde_json::Value,
    state: Arc<AggregatorState>,
) -> Result<serde_json::Value, JsonRpcError> {
    // Params is a JSON string containing the hex-encoded CBOR.
    let hex_str = match &params {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) if a.len() == 1 => match &a[0] {
            serde_json::Value::String(s) => s.clone(),
            _ => {
                return Err(JsonRpcError::invalid_params(
                    "params[0] must be a hex string",
                ))
            }
        },
        _ => return Err(JsonRpcError::invalid_params("params must be a hex string")),
    };

    // Parse CBOR.
    let parsed = parse_certification_request(&hex_str)
        .map_err(|e| JsonRpcError::invalid_params(format!("failed to parse CBOR: {e}")))?;

    // Assign the deadline before validating so the same value is enforced at
    // admission and again when the leaf is materialised. Without a consensus
    // reference time there is nothing to assign or check against.
    let effective_timeout = match state.effective_timeout(parsed.expires_at) {
        Some(t) => t,
        None => {
            return Err(JsonRpcError {
                code: JsonRpcError::INVALID_PARAMS,
                message: "SERVICE_NOT_READY".into(),
                data: Some("no consensus reference time available yet".into()),
            })
        }
    };

    // Validate.
    let validated = crate::validation::validate_request(
        &parsed.state_id,
        &parsed.predicate_cbor,
        parsed.engine,
        &parsed.code,
        &parsed.params,
        &parsed.source_state_hash,
        &parsed.transaction_hash,
        parsed.expires_at,
        effective_timeout,
        &parsed.witness,
    )
    .map_err(|e| {
        info!(status = %e.status, "certification_request rejected");
        // Return the validation status string as the error message (matching Go behavior).
        JsonRpcError {
            code: JsonRpcError::INVALID_PARAMS,
            message: e.status.to_string(),
            data: Some(e.message),
        }
    })?;

    // Fail fast on a request that is already expired against the reference time
    // rounds are currently pinning. The authoritative check runs again where the
    // leaf is materialised, against that round's pinned reference time.
    let reference_time = state.reference_time();
    if reference_time >= effective_timeout {
        info!(
            state_id = %validated.state_id_hex,
            timeout = effective_timeout,
            reference_time,
            "certification_request expired"
        );
        return Err(JsonRpcError {
            code: JsonRpcError::INVALID_PARAMS,
            message: "REQUEST_EXPIRED".into(),
            data: Some("round reference time has reached the request deadline".into()),
        });
    }

    // Submit to round manager.
    state.submit_request(validated).await.map_err(|e| {
        warn!("failed to submit request: {e}");
        JsonRpcError::internal(e.to_string())
    })?;

    let resp = CertificationResponse::success();
    Ok(serde_json::to_value(resp).unwrap())
}

// ─── get_non_inclusion_proof.v1 ─────────────────────────────────────────────

/// Handle `get_non_inclusion_proof.v1` against the latest certified SMT root.
///
/// The path is generated from a root-pinned SMT snapshot published atomically
/// with its block and UC. A present key is an explicit relation error, never a
/// malformed or nullable "proof" response.
pub async fn handle_get_non_inclusion_proof_v1(
    params: serde_json::Value,
    state: Arc<AggregatorState>,
) -> Result<serde_json::Value, JsonRpcError> {
    let p: GetNonInclusionProofParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid params: {e}")))?;
    let bytes = hex::decode(&p.state_id)
        .map_err(|_| JsonRpcError::invalid_params("stateId must be a hex string"))?;
    let state_id: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        JsonRpcError::invalid_params(format!(
            "stateId must decode to exactly 32 bytes, got {}",
            v.len()
        ))
    })?;

    let lookup = state
        .get_non_inclusion_proof(state_id)
        .await
        .map_err(|e| JsonRpcError::internal(e.to_string()))?;
    match lookup {
        NonInclusionProofLookup::CertifiedStateUnavailable => Err(JsonRpcError::not_found()),
        NonInclusionProofLookup::StateIncluded => Err(JsonRpcError::state_included()),
        NonInclusionProofLookup::Busy => Err(JsonRpcError::server_busy()),
        NonInclusionProofLookup::Proof(proof) => {
            let encoded = encode_non_inclusion_proof_response(
                proof.block_number,
                &proof.certificate,
                &proof.uc_cbor,
            )
            .map_err(|e| JsonRpcError::internal(e.to_string()))?;
            Ok(serde_json::Value::String(encoded))
        }
    }
}

// ─── get_inclusion_proof.v2 ───────────────────────────────────────────────────

/// Handle `get_inclusion_proof.v2`.
///
/// Params: `{ "stateId": "<hex>" }`.
pub async fn handle_get_inclusion_proof_v2(
    params: serde_json::Value,
    state: Arc<AggregatorState>,
) -> Result<serde_json::Value, JsonRpcError> {
    let p: GetInclusionProofParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid params: {e}")))?;

    let state_id_bytes = hex::decode(&p.state_id)
        .map_err(|_| JsonRpcError::invalid_params("stateId must be a hex string"))?;

    let proof = state
        .get_inclusion_proof(&state_id_bytes)
        .await
        .map_err(|e| JsonRpcError::internal(e.to_string()))?;

    match proof {
        InclusionProofLookup::NotFound => Err(JsonRpcError::not_found()),
        InclusionProofLookup::Pending => Err(JsonRpcError::inclusion_pending()),
        InclusionProofLookup::Proof(p) => {
            let hex_cbor = encode_inclusion_proof_response(
                p.block_number,
                p.cert_data.as_ref(),
                p.reference_time,
                &p.merkle_path_cbor,
                &p.uc_cbor,
            )
            .map_err(|e| JsonRpcError::internal(e.to_string()))?;
            Ok(serde_json::Value::String(hex_cbor))
        }
    }
}

// ─── get_block_height ─────────────────────────────────────────────────────────

/// Handle `get_block_height`.
pub async fn handle_get_block_height(
    _params: serde_json::Value,
    state: Arc<AggregatorState>,
) -> Result<serde_json::Value, JsonRpcError> {
    let block_number = state.current_block_number().await;
    let resp = BlockHeightResponse {
        block_number: block_number.to_string(),
    };
    Ok(serde_json::to_value(resp).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exclusive certification request deadline every fixture in this module uses.
    const TEST_EXPIRES_AT: u64 = 1_755_003_600;
    use tokio::sync::mpsc;

    fn validated_request(state_id: [u8; 32]) -> crate::validation::ValidatedRequest {
        crate::validation::ValidatedRequest {
            state_id_hex: hex::encode(state_id),
            state_id: state_id.to_vec(),
            predicate_cbor: vec![1],
            source_state_hash: vec![2; 32],
            transaction_hash: vec![3; crate::smt::AGGREGATION_TREE_VALUE_SIZE],
            expires_at: Some(TEST_EXPIRES_AT),
            effective_timeout: TEST_EXPIRES_AT,
            witness: vec![4; 65],
            public_key: vec![5; 33],
        }
    }

    #[tokio::test]
    async fn inclusion_handler_distinguishes_pending_and_unknown_ids() {
        let (request_tx, _request_rx) = mpsc::channel(1);
        let state = AggregatorState::new(request_tx, None);
        let pending_id = [0x11u8; 32];
        state
            .submit_request(validated_request(pending_id))
            .await
            .unwrap();

        let pending = handle_get_inclusion_proof_v2(
            serde_json::json!({ "stateId": hex::encode(pending_id) }),
            Arc::clone(&state),
        )
        .await
        .unwrap_err();
        assert_eq!(pending.code, JsonRpcError::INCLUSION_PENDING);

        let unknown = handle_get_inclusion_proof_v2(
            serde_json::json!({ "stateId": hex::encode([0x22u8; 32]) }),
            state,
        )
        .await
        .unwrap_err();
        assert_eq!(unknown.code, JsonRpcError::NOT_FOUND);
    }
}
