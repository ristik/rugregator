//! JSON-RPC method handlers.

use std::sync::Arc;
use tracing::{debug, warn};

use crate::storage::AggregatorState;
use super::cbor::{encode_inclusion_proof_response, parse_certification_request};
use super::types::{
    BlockHeightResponse, CertificationResponse, GetInclusionProofParams, JsonRpcError,
};

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
        serde_json::Value::Array(a) if a.len() == 1 => {
            match &a[0] {
                serde_json::Value::String(s) => s.clone(),
                _ => return Err(JsonRpcError::invalid_params("params[0] must be a hex string")),
            }
        }
        _ => return Err(JsonRpcError::invalid_params("params must be a hex string")),
    };

    // Parse CBOR.
    let parsed = parse_certification_request(&hex_str).map_err(|e| {
        JsonRpcError::invalid_params(format!("failed to parse CBOR: {e}"))
    })?;

    // Validate.
    let validated = crate::validation::validate_request(
        &parsed.state_id,
        &parsed.predicate_cbor,
        parsed.engine,
        &parsed.code,
        &parsed.params,
        &parsed.source_state_hash,
        &parsed.transaction_hash,
        &parsed.witness,
    )
    .map_err(|e| {
        debug!("certification_request validation failed: {}", e.status);
        // Return the validation status string as the error message (matching Go behavior).
        JsonRpcError {
            code: JsonRpcError::INVALID_PARAMS,
            message: e.status.to_string(),
            data: Some(e.message),
        }
    })?;

    // Submit to round manager.
    state.submit_request(validated).await.map_err(|e| {
        warn!("failed to submit request: {e}");
        JsonRpcError::internal(e.to_string())
    })?;

    let resp = CertificationResponse::success();
    Ok(serde_json::to_value(resp).unwrap())
}

// ─── get_inclusion_proof.v2 ───────────────────────────────────────────────────

/// Handle `get_inclusion_proof.v2`.
///
/// Params: `{ "stateId": "<hex>" }`.
pub async fn handle_get_inclusion_proof_v2(
    params: serde_json::Value,
    state: Arc<AggregatorState>,
) -> Result<serde_json::Value, JsonRpcError> {
    let p: GetInclusionProofParams = serde_json::from_value(params).map_err(|e| {
        JsonRpcError::invalid_params(format!("invalid params: {e}"))
    })?;

    let state_id_bytes = hex::decode(&p.state_id).map_err(|_| {
        JsonRpcError::invalid_params("stateId must be a hex string")
    })?;

    let proof = state.get_inclusion_proof(&state_id_bytes).await.map_err(|e| {
        JsonRpcError::internal(e.to_string())
    })?;

    match proof {
        None => {
            // Not yet certified — return NOT_FOUND error so SDK retries.
            Err(JsonRpcError::not_found())
        }
        Some(p) => {
            let hex_cbor = encode_inclusion_proof_response(
                p.block_number,
                p.cert_data.as_ref(),
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
