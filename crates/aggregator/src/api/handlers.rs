//! JSON-RPC method handlers.

use std::sync::Arc;
use tracing::{info, warn};

use super::cbor::{
    encode_empty_inclusion_proof_response, encode_inclusion_proof_response,
    encode_non_inclusion_proof_response, parse_certification_request,
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
            data: Some(e.message.into()),
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

    // The hint is read before the proof: a state that finalizes in between returns its proof
    // (included wins), never "unknown" for a state that has one.
    let hint = p
        .include_status
        .then(|| state.proof_status_hint(&state_id_bytes));

    let proof = state
        .get_inclusion_proof(&state_id_bytes)
        .await
        .map_err(|e| JsonRpcError::internal(e.to_string()))?;

    let (hex_cbor, status) = match proof {
        InclusionProofLookup::Proof(p) => (
            encode_inclusion_proof_response(
                p.block_number,
                p.cert_data.as_ref(),
                p.reference_time,
                &p.merkle_path_cbor,
                &p.uc_cbor,
            )
            .map_err(|e| JsonRpcError::internal(e.to_string()))?,
            "included",
        ),
        // Pending, unknown and expired states get aggregator-go's answer: a normal result
        // with the empty proof (no certificate) under the latest finalized block's UC. The
        // client polls on; only the optional status hint tells the cases apart.
        InclusionProofLookup::Pending | InclusionProofLookup::NotFound => {
            let Some(block) = state.latest_finalized_block().await else {
                // Only the instant between startup and the initial empty-tree block: there is
                // no certificate to carry yet. aggregator-go's typed retryable error.
                return Err(JsonRpcError::detailed(
                    JsonRpcError::PROOF_UNAVAILABLE,
                    "Proof unavailable",
                    "proof_unavailable",
                    "no_finalized_view",
                    true,
                    None,
                    None,
                ));
            };
            (
                encode_empty_inclusion_proof_response(block.block_number, &block.uc_cbor)
                    .map_err(|e| JsonRpcError::internal(e.to_string()))?,
                hint.filter(|h| *h != "included").unwrap_or("unknown"),
            )
        }
    };
    match hint {
        None => Ok(serde_json::Value::String(hex_cbor)),
        Some(_) => Ok(serde_json::json!({ "proof": hex_cbor, "status": status })),
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

    /// aggregator-go's empty-proof answer (`testdata/longpoll/golden/v2-nowait.json`,
    /// case `not-included-bare`, aggregator-go long-poll b885e76) and its block number.
    const GOLDEN: &str = include_str!("../../testdata/longpoll/v2-empty-proof.json");

    fn golden() -> (String, u64) {
        let v: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
        (
            v["emptyProofHex"].as_str().unwrap().to_owned(),
            v["blockNumber"].as_u64().unwrap(),
        )
    }

    /// A UC rugregator's own canonical profile accepts.
    fn test_uc() -> Vec<u8> {
        crate::api::cbor::test_uc_cbor(None, &[0x80], 0)
    }

    #[test]
    fn empty_answer_has_the_aggregator_go_golden_framing() {
        // The golden's UC is a Go test fixture (null summary value) that rugregator's strict
        // UC profile rightly refuses, so the comparison covers everything around the UC:
        // `[block, #6.39033([1, null, null, null, UC])]` is byte-identical up to the UC.
        let (golden_hex, block) = golden();
        let mine = encode_empty_inclusion_proof_response(block, &test_uc()).unwrap();
        let prefix = "8209d998798501f6f6f6"; // array(2), 9, tag 39033, array(5), 1, null, null, null
        assert!(golden_hex.starts_with(prefix));
        assert!(mine.starts_with(prefix), "{mine}");
        // and the UC follows as the tagged certificate in both
        assert!(golden_hex[prefix.len()..].starts_with("d99859"));
        assert!(mine[prefix.len()..].starts_with("d99859"));
    }

    async fn state_with_block(
        blocks: u64,
    ) -> (
        Arc<AggregatorState>,
        mpsc::Receiver<crate::validation::ValidatedRequest>,
    ) {
        let (request_tx, request_rx) = mpsc::channel(8);
        let state = AggregatorState::new(request_tx, None);
        for n in 1..=blocks {
            state
                .finalize_round(
                    crate::storage::BlockInfo {
                        block_number: n,
                        root_hash: None,
                        uc_cbor: test_uc(),
                    },
                    vec![],
                )
                .await;
        }
        (state, request_rx)
    }

    async fn v2(state: &Arc<AggregatorState>, id: [u8; 32], status: bool) -> serde_json::Value {
        let params = if status {
            serde_json::json!({ "stateId": hex::encode(id), "includeStatus": true })
        } else {
            serde_json::json!({ "stateId": hex::encode(id) })
        };
        handle_get_inclusion_proof_v2(params, Arc::clone(state))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn pending_unknown_and_expired_get_the_empty_result_not_an_error() {
        let (state, _rx) = state_with_block(9).await;
        let pending_id = [0x11u8; 32];
        state
            .submit_request(validated_request(pending_id))
            .await
            .unwrap();
        let expired_id = [0x33u8; 32];
        state.drop_expired_requests(&[validated_request(expired_id)]);
        let golden_hex = encode_empty_inclusion_proof_response(9, &test_uc()).unwrap();

        for id in [pending_id, [0x22u8; 32], expired_id] {
            // bare: the very same hex string for every not-certified state
            let r = v2(&state, id, false).await;
            assert_eq!(r, serde_json::Value::String(golden_hex.clone()));
        }
        // with status: {proof, status}, proof unchanged
        for (id, want) in [
            (pending_id, "pending"),
            ([0x22u8; 32], "unknown"),
            (expired_id, "expired"),
        ] {
            let r = v2(&state, id, true).await;
            assert_eq!(r["proof"], serde_json::Value::String(golden_hex.clone()));
            assert_eq!(r["status"], want);
            assert_eq!(r.as_object().unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn the_empty_answer_carries_the_latest_finalized_block_number() {
        let (state, _rx) = state_with_block(3).await;
        let r = v2(&state, [0x22u8; 32], false).await;
        let bytes = hex::decode(r.as_str().unwrap()).unwrap();
        let ciborium::value::Value::Array(top) =
            crate::api::cbor::decode_cbor_value(&bytes).unwrap()
        else {
            panic!()
        };
        assert_eq!(top[0], ciborium::value::Value::Integer(3u64.into()));
    }

    #[tokio::test]
    async fn before_the_first_block_every_not_certified_state_gets_the_typed_error() {
        let (state, _rx) = state_with_block(0).await;
        state
            .submit_request(validated_request([0x11u8; 32]))
            .await
            .unwrap();
        for status in [false, true] {
            for id in [[0x22u8; 32], [0x11u8; 32]] {
                let e = handle_get_inclusion_proof_v2(
                    serde_json::json!({ "stateId": hex::encode(id), "includeStatus": status }),
                    Arc::clone(&state),
                )
                .await
                .unwrap_err();
                assert_eq!(e.code, JsonRpcError::PROOF_UNAVAILABLE);
                let d = e.data.unwrap();
                assert_eq!(
                    (
                        d["reason"].as_str(),
                        d["detail"].as_str(),
                        d["retryable"].as_bool()
                    ),
                    (
                        Some("proof_unavailable"),
                        Some("no_finalized_view"),
                        Some(true)
                    )
                );
            }
        }
    }

    #[tokio::test]
    async fn a_certified_state_keeps_the_full_proof_and_reports_included() {
        let (state, _rx) = state_with_block(1).await;
        let id = [0x44u8; 32];
        state.finalize_records(vec![crate::storage::FinalizedRecord {
            state_id_hex: hex::encode(id),
            block_number: 1,
            reference_time: 7,
            cert_data: crate::api::cbor::CertDataFields {
                predicate_cbor: vec![0xd9, 0x98, 0x78, 0x83, 0x01, 0x41, 0x01, 0x41, 0x01],
                source_state_hash: vec![2; 32],
                transaction_hash: vec![3; crate::smt::AGGREGATION_TREE_VALUE_SIZE],
                expires_at: Some(TEST_EXPIRES_AT),
                witness: vec![4; 65],
            },
            merkle_path_cbor: Some(vec![0x80]),
        }]);
        let bare = v2(&state, id, false).await;
        let with = v2(&state, id, true).await;
        assert_ne!(
            bare.as_str().unwrap(),
            golden().0,
            "a certified state is not the empty answer"
        );
        assert_eq!(with["proof"], bare, "status never changes the proof bytes");
        assert_eq!(with["status"], "included");
    }

    #[tokio::test]
    async fn include_status_must_be_a_boolean() {
        let (state, _rx) = state_with_block(1).await;
        let e = handle_get_inclusion_proof_v2(
            serde_json::json!({ "stateId": hex::encode([1u8; 32]), "includeStatus": "yes" }),
            state,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, JsonRpcError::INVALID_PARAMS);
    }
}
