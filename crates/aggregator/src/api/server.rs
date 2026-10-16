//! axum HTTP server and JSON-RPC dispatch.

use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use tracing::debug;

use super::batch::handle_get_inclusion_proofs_v1;
use super::handlers::{
    handle_certification_request, handle_get_block_height, handle_get_inclusion_proof_v2,
    handle_get_non_inclusion_proof_v1,
};
use super::types::{batch_limits, JsonRpcError, JsonRpcResponse};
use crate::storage::AggregatorState;

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn build_router(state: Arc<AggregatorState>) -> Router {
    Router::new()
        .route("/", post(jsonrpc_handler))
        .route("/health", get(health_handler))
        .with_state(state)
}

// ─── Health endpoint ──────────────────────────────────────────────────────────

async fn health_handler(State(state): State<Arc<AggregatorState>>) -> impl IntoResponse {
    let block = state.current_block_number().await;
    Json(json!({
        "status": "ok",
        "blockNumber": block.to_string(),
    }))
}

// ─── JSON-RPC dispatcher ──────────────────────────────────────────────────────

/// Method with Go-compatible per-method request/response limits.
const BATCH_METHOD: &str = "get_inclusion_proofs.v1";

/// Request envelope with `params` and `id` left undecoded, so method-limited
/// requests can validate the original ID encoding and params size.
#[derive(serde::Deserialize)]
struct RawEnvelope<'a> {
    jsonrpc: String,
    method: String,
    #[serde(borrow, default)]
    params: Option<&'a serde_json::value::RawValue>,
    #[serde(borrow, default)]
    id: Option<&'a serde_json::value::RawValue>,
}

async fn jsonrpc_handler(State(state): State<Arc<AggregatorState>>, body: Bytes) -> Response {
    let (status, text) = dispatch(state, &body).await;
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        text,
    )
        .into_response()
}

fn error_text(id: serde_json::Value, err: JsonRpcError) -> String {
    serde_json::to_string(&JsonRpcResponse::error(id, err)).expect("error response serializes")
}

/// A method-limited request ID is a JSON string or number within the limit.
fn valid_raw_id(raw: Option<&serde_json::value::RawValue>) -> bool {
    let Some(raw) = raw else { return false };
    let text = raw.get();
    text.len() <= batch_limits::MAX_ID_BYTES
        && matches!(text.as_bytes().first(), Some(b'"' | b'-' | b'0'..=b'9'))
}

/// Decode and serve one request body. Returns the HTTP status and the JSON text.
///
/// Legacy methods behave as before (`params` decoded to a value, any ID). The
/// batch method has its own limits: body 64 KiB, params 32 KiB, ID 128 encoded
/// bytes, response 8 MiB, enforced before any work and while building output.
pub async fn dispatch(state: Arc<AggregatorState>, body: &[u8]) -> (StatusCode, String) {
    use serde::Deserialize;
    let mut de = serde_json::Deserializer::from_slice(body);
    let parsed = RawEnvelope::deserialize(&mut de);
    // Anything but whitespace after the request object.
    let trailing = parsed.is_ok() && de.end().is_err();
    let env: RawEnvelope = match parsed {
        Ok(env) if !trailing || env.method == BATCH_METHOD => env,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                error_text(
                    serde_json::Value::Null,
                    JsonRpcError {
                        code: JsonRpcError::PARSE_ERROR,
                        message: "parse error".into(),
                        data: None,
                    },
                ),
            )
        }
    };

    if env.method == BATCH_METHOD {
        return dispatch_batch(state, body, env, trailing).await;
    }

    let id: serde_json::Value = env
        .id
        .and_then(|raw| serde_json::from_str(raw.get()).ok())
        .unwrap_or_default();
    let params: serde_json::Value = env
        .params
        .and_then(|raw| serde_json::from_str(raw.get()).ok())
        .unwrap_or_default();

    if env.jsonrpc != "2.0" {
        let err = JsonRpcError {
            code: JsonRpcError::INVALID_REQUEST,
            message: "jsonrpc must be \"2.0\"".into(),
            data: None,
        };
        return (StatusCode::OK, error_text(id, err));
    }

    debug!(method = %env.method, "JSON-RPC request");

    let result = match env.method.as_str() {
        "certification_request" => handle_certification_request(params, state).await,
        "get_inclusion_proof.v2" => handle_get_inclusion_proof_v2(params, state).await,
        "get_non_inclusion_proof.v1" => handle_get_non_inclusion_proof_v1(params, state).await,
        "get_block_height" => handle_get_block_height(params, state).await,
        _ => Err(JsonRpcError::method_not_found(&env.method)),
    };

    match result {
        Ok(val) => {
            let resp = JsonRpcResponse::success(id, val);
            (
                StatusCode::OK,
                serde_json::to_string(&resp).expect("response serializes"),
            )
        }
        // Unknown identifiers fail fast. Pending certification has its own
        // JSON-RPC code and remains a 200 response so clients can poll only
        // states the server has actually accepted.
        Err(e) if e.is_not_found() => (StatusCode::NOT_FOUND, error_text(id, e)),
        Err(e) if e.is_server_busy() => (StatusCode::TOO_MANY_REQUESTS, error_text(id, e)),
        Err(e) => (StatusCode::OK, error_text(id, e)),
    }
}

async fn dispatch_batch(
    state: Arc<AggregatorState>,
    body: &[u8],
    env: RawEnvelope<'_>,
    trailing: bool,
) -> (StatusCode, String) {
    let id_ok = valid_raw_id(env.id);
    // An invalid or oversized ID is never echoed.
    let id: serde_json::Value = if id_ok {
        env.id
            .and_then(|raw| serde_json::from_str(raw.get()).ok())
            .unwrap_or_default()
    } else {
        serde_json::Value::Null
    };
    // Go order (`pkg/jsonrpc/handler.go`): envelope validity, then trailing
    // data, then the whole-body size; all answered with HTTP 200. The outer
    // body ceiling (axum's default limit) is the only 413.
    let invalid_envelope = || {
        (
            StatusCode::OK,
            error_text(
                id.clone(),
                JsonRpcError::detailed(
                    JsonRpcError::INVALID_REQUEST,
                    "Invalid Request",
                    "invalid_request",
                    "invalid_envelope",
                    false,
                    None,
                    None,
                ),
            ),
        )
    };
    if env.jsonrpc != "2.0" || env.method.is_empty() || trailing {
        return invalid_envelope();
    }
    if body.len() > batch_limits::MAX_REQUEST_BYTES {
        return (
            StatusCode::OK,
            error_text(
                id,
                JsonRpcError::limit_exceeded("request_bytes", batch_limits::MAX_REQUEST_BYTES),
            ),
        );
    }
    if !id_ok {
        return (
            StatusCode::OK,
            error_text(
                serde_json::Value::Null,
                JsonRpcError::invalid_request_detail("invalid_id"),
            ),
        );
    }
    let raw_params = env.params.map(|p| p.get()).unwrap_or("");
    if raw_params.len() > batch_limits::MAX_PARAMS_BYTES {
        return (
            StatusCode::OK,
            error_text(
                id,
                JsonRpcError::limit_exceeded("request_bytes", batch_limits::MAX_PARAMS_BYTES),
            ),
        );
    }
    debug!(method = BATCH_METHOD, "JSON-RPC request");

    // `{"jsonrpc":"2.0","result":` + result + `,"id":` + id + `}` + newline.
    let id_text = serde_json::to_string(&id).expect("id serializes");
    let overhead = r#"{"jsonrpc":"2.0","result":,"id":}"#.len() + id_text.len() + 1;
    let max_result = batch_limits::MAX_RESPONSE_BYTES.saturating_sub(overhead);

    match handle_get_inclusion_proofs_v1(raw_params, max_result, state).await {
        Ok(result) => (
            StatusCode::OK,
            format!(r#"{{"jsonrpc":"2.0","result":{result},"id":{id_text}}}"#),
        ),
        Err(e) => (StatusCode::OK, error_text(id, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::cbor::{test_uc_cbor, CertDataFields};
    use crate::storage::{BlockInfo, FinalizedRecord};
    use serde_json::{json, Value};
    use smt_store::{MemSmt, SmtStore, SmtStoreSnapshot};
    use tokio::sync::mpsc;

    const REF_TIME: u64 = 1_755_000_000;

    fn txh(seed: u8) -> Vec<u8> {
        vec![seed; crate::smt::AGGREGATION_TREE_VALUE_SIZE]
    }

    /// A state serving one unsharded view holding `seeds` as block 1.
    fn serving_state(seeds: &[u8]) -> (Arc<AggregatorState>, [u8; 32]) {
        let (tx, _rx) = mpsc::channel(1);
        let state = AggregatorState::new(tx, None);
        let mut smt = MemSmt::new();
        let mut m = smt.create_snapshot();
        for &s in seeds {
            m.add_leaf([s; 32], rsmt::leaf_value(&txh(s), REF_TIME).to_vec())
                .unwrap();
        }
        m.commit(&mut smt).unwrap();
        state.finalize_records(
            seeds
                .iter()
                .map(|&s| FinalizedRecord {
                    state_id_hex: hex::encode([s; 32]),
                    block_number: 1,
                    reference_time: REF_TIME,
                    cert_data: CertDataFields {
                        predicate_cbor: vec![0xd9, 0x98, 0x78, 0x83, 0x01, 0x41, 0x01, 0x41, 0x01],
                        source_state_hash: vec![2; 32],
                        transaction_hash: txh(s),
                        expires_at: Some(REF_TIME + 3600),
                        witness: vec![4; 65],
                    },
                    merkle_path_cbor: None,
                })
                .collect(),
        );
        let root = smt.root_hash().unwrap();
        state
            .publish_certified_snapshot(
                BlockInfo {
                    block_number: 1,
                    root_hash: Some(root),
                    uc_cbor: test_uc_cbor(Some(root), &[0x80], 0),
                },
                smt.create_certified_snapshot().unwrap(),
            )
            .unwrap();
        (state, root)
    }

    async fn call(state: &Arc<AggregatorState>, req: Value) -> (StatusCode, Value) {
        let (status, text) = dispatch(Arc::clone(state), req.to_string().as_bytes()).await;
        (status, serde_json::from_str(&text).unwrap())
    }

    fn batch(id: Value, params: Value) -> Value {
        json!({"jsonrpc":"2.0","id":id,"method":"get_inclusion_proofs.v1","params":params})
    }

    #[tokio::test]
    async fn batch_result_has_only_proofs_and_never_a_partition_view() {
        let (state, _) = serving_state(&[0x11, 0x22]);
        let ids = [hex::encode([0x22; 32]), hex::encode([0x11; 32])];
        let (status, resp) = call(&state, batch(json!(7), json!({"stateIds": ids}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["id"], json!(7));
        assert!(resp.get("error").is_none());
        let result = resp["result"].as_object().unwrap();
        assert_eq!(result.keys().collect::<Vec<_>>(), ["proofs"]);
        let proofs = result["proofs"].as_array().unwrap();
        assert_eq!(proofs.len(), 2);
        for p in proofs {
            // [blockNumber, #6.39033([1, certData, referenceTime, path, uc])]
            let bytes = hex::decode(p.as_str().unwrap()).unwrap();
            let v = crate::api::cbor::decode_cbor_value(&bytes).unwrap();
            let ciborium::value::Value::Array(top) = v else { panic!() };
            assert_eq!(top[0], ciborium::value::Value::Integer(1u64.into()));
        }
        // The result is exactly what the string-built response parses to, with
        // the explicit latest selector too.
        let (_, again) = call(&state, batch(json!("a"), json!({"stateIds": ids, "stateRoot": "latest"}))).await;
        assert_eq!(again["result"], resp["result"]);
        assert_eq!(again["id"], json!("a"));
    }

    #[tokio::test]
    async fn valid_latest_wait_is_ignored_with_byte_identical_result_and_no_echo() {
        let (state, _) = serving_state(&[0x11, 0x22]);
        let ids = [hex::encode([0x22; 32]), hex::encode([0x11; 32])];
        let body = |extra: &str| {
            format!(
                r#"{{"jsonrpc":"2.0","id":7,"method":"get_inclusion_proofs.v1","params":{{"stateIds":["{}","{}"]{extra}}}}}"#,
                ids[0], ids[1]
            )
        };
        let (s0, plain) = dispatch(Arc::clone(&state), body("").as_bytes()).await;
        for extra in [r#","waitMs":0"#, r#","waitMs":20000"#, r#","waitMs":9007199254740991"#, r#","waitMs":5,"stateRoot":"latest""#] {
            let (s1, with) = dispatch(Arc::clone(&state), body(extra).as_bytes()).await;
            assert_eq!((s1, &with), (s0, &plain), "{extra}");
            assert!(!with.contains("waitedMs"));
        }
        // An absent id is the same pending/unknown error with no echo either.
        let miss = hex::encode([0x99; 32]);
        let req = |extra: &str| json!({"jsonrpc":"2.0","id":1,"method":"get_inclusion_proofs.v1",
            "params": serde_json::from_str::<Value>(&format!(r#"{{"stateIds":["{miss}"]{extra}}}"#)).unwrap()}).to_string();
        let (_, e0) = dispatch(Arc::clone(&state), req("").as_bytes()).await;
        let (_, e1) = dispatch(Arc::clone(&state), req(r#","waitMs":3000"#).as_bytes()).await;
        assert_eq!(e0, e1);
        assert!(!e1.contains("waitedMs"));
    }

    #[tokio::test]
    async fn invalid_batch_waits_are_malformed_params_without_echo() {
        let (state, root) = serving_state(&[0x11]);
        let present = hex::encode([0x11; 32]);
        for params in [
            format!(r#"{{"stateIds":["{present}"],"waitMs":-1}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":"5"}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":1,"waitMs":1}}"#),
            format!(r#"{{"stateIds":["{present}"],"stateRoot":"{}","waitMs":0}}"#, hex::encode(root)),
        ] {
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"get_inclusion_proofs.v1","params":{params}}}"#);
            let (_, text) = dispatch(Arc::clone(&state), body.as_bytes()).await;
            let resp: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(resp["error"]["code"], json!(-32602), "{params}");
            assert_eq!(resp["error"]["data"]["reason"], json!("invalid_request"));
            assert_eq!(resp["error"]["data"]["detail"], json!("malformed_params"));
            assert!(resp["error"]["data"].get("waitedMs").is_none());
        }
    }

    #[tokio::test]
    async fn batch_errors_use_the_go_codes_and_structured_data() {
        let (state, root) = serving_state(&[0x11]);
        let present = hex::encode([0x11; 32]);
        let absent = hex::encode([0x99; 32]);
        let err = |resp: &Value| {
            let e = &resp["error"];
            (
                e["code"].as_i64().unwrap(),
                e["data"]["reason"].as_str().unwrap_or("").to_owned(),
                e["data"]["detail"].as_str().unwrap_or("").to_owned(),
                e["data"]["retryable"].as_bool(),
            )
        };
        // never-seen state on latest
        let (_, r) = call(&state, batch(json!(1), json!({"stateIds":[present, absent]}))).await;
        assert_eq!(err(&r), (-32008, "proof_unavailable".into(), "state_unknown".into(), Some(false)));
        assert_eq!(r["error"]["data"]["indexes"], json!({"unknown":[1]}));
        // exact root, absent leaf
        let (_, r) = call(&state, batch(json!(1), json!({"stateIds":[absent], "stateRoot": hex::encode(root)}))).await;
        assert_eq!(err(&r), (-32008, "proof_unavailable".into(), "state_not_in_root".into(), Some(false)));
        assert_eq!(r["error"]["data"]["indexes"], json!({"not_in_root":[0]}));
        // exact root not retained
        let (_, r) = call(&state, batch(json!(1), json!({"stateIds":[present], "stateRoot": hex::encode([5u8; 32])}))).await;
        assert_eq!(err(&r), (-32008, "proof_unavailable".into(), "view_not_retained".into(), Some(true)));
        // no latest view
        state.clear_certified_snapshot();
        let (_, r) = call(&state, batch(json!(1), json!({"stateIds":[present]}))).await;
        assert_eq!(err(&r), (-32008, "proof_unavailable".into(), "no_finalized_view".into(), Some(true)));
        // invalid params
        let (_, r) = call(&state, batch(json!(1), json!({"stateIds":["zz"]}))).await;
        assert_eq!(err(&r), (-32602, "invalid_request".into(), "invalid_state_id".into(), Some(false)));
        assert_eq!(r["error"]["message"], json!("Invalid params"));
        // 257 ids
        let many: Vec<_> = (0..257u16)
            .map(|i| {
                let mut b = [0u8; 32];
                b[..2].copy_from_slice(&i.to_be_bytes());
                hex::encode(b)
            })
            .collect();
        let (_, r) = call(&state, batch(json!(1), json!({"stateIds": many}))).await;
        assert_eq!(err(&r), (-32007, "limit_exceeded".into(), "state_count".into(), Some(false)));
        assert_eq!(r["error"]["data"]["limit"], json!(256));
    }

    #[tokio::test]
    async fn batch_request_limits_precede_any_work() {
        let (state, _) = serving_state(&[0x11]);
        let present = hex::encode([0x11; 32]);
        // ID: absent, null, bool, object, over 128 encoded bytes -> invalid_id, never echoed.
        for bad in [
            json!({"jsonrpc":"2.0","method":"get_inclusion_proofs.v1","params":{"stateIds":[present]}}),
            batch(Value::Null, json!({"stateIds":[present]})),
            batch(json!(true), json!({"stateIds":[present]})),
            batch(json!({"a":1}), json!({"stateIds":[present]})),
            batch(json!("x".repeat(127)), json!({"stateIds":[present]})), // 129 encoded bytes
        ] {
            let (status, r) = call(&state, bad.clone()).await;
            assert_eq!(status, StatusCode::OK, "{bad}");
            assert_eq!(r["error"]["code"], json!(-32602), "{bad}");
            assert_eq!(r["error"]["data"]["detail"], json!("invalid_id"), "{bad}");
            assert_eq!(r["id"], Value::Null);
        }
        // exactly 128 encoded bytes is fine
        let (_, r) = call(&state, batch(json!("x".repeat(126)), json!({"stateIds":[present]}))).await;
        assert!(r.get("error").is_none(), "{r}");
        // numeric id echoes as a number
        let (_, r) = call(&state, batch(json!(-3), json!({"stateIds":[present]}))).await;
        assert_eq!(r["id"], json!(-3));

        // Whole body over 64 KiB: 413 + limit_exceeded/request_bytes, id echoed.
        let padded = batch(json!(5), json!({"stateIds":[present], "pad": "a".repeat(70_000)}));
        let (status, r) = call(&state, padded).await;
        assert_eq!(status, StatusCode::OK, "Go answers limit errors with HTTP 200");
        assert_eq!(r["error"]["code"], json!(-32007));
        assert_eq!(r["error"]["data"]["detail"], json!("request_bytes"));
        assert_eq!(r["error"]["data"]["limit"], json!(batch_limits::MAX_REQUEST_BYTES));
        assert_eq!(r["id"], json!(5));
        // Params over 32 KiB but body under 64 KiB.
        let padded = batch(json!(5), json!({"stateIds":[present], "pad": "a".repeat(40_000)}));
        let (status, r) = call(&state, padded).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(r["error"]["data"]["limit"], json!(batch_limits::MAX_PARAMS_BYTES));
        // Trailing data after the envelope: invalid_envelope, HTTP 200 (not -32700/400).
        let mut body = batch(json!(6), json!({"stateIds":[present]})).to_string();
        body.push_str(" x");
        let (status, text) = dispatch(state.clone(), body.as_bytes()).await;
        let r: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(r["error"]["code"], json!(-32600));
        assert_eq!(r["error"]["data"]["detail"], json!("invalid_envelope"));
        assert_eq!(r["id"], json!(6));
        // Trailing whitespace is fine.
        let ws = format!("{}  \n", batch(json!(6), json!({"stateIds":[present]})));
        let (_, text) = dispatch(state.clone(), ws.as_bytes()).await;
        assert!(serde_json::from_str::<Value>(&text).unwrap().get("error").is_none());
        // Empty method on the batch path cannot happen; legacy trailing data stays a parse error.
        let legacy = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block_height\",\"params\":{}} x";
        let (status, text) = dispatch(state.clone(), legacy).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(text.contains("-32700"));
        // Wrong jsonrpc version.
        let (_, r) = call(&state, json!({"jsonrpc":"1.0","id":1,"method":"get_inclusion_proofs.v1","params":{}})).await;
        assert_eq!(r["error"]["code"], json!(-32600));
        assert_eq!(r["error"]["data"]["detail"], json!("invalid_envelope"));
    }

    #[tokio::test]
    async fn oversized_responses_fail_while_building_without_partial_output() {
        let (state, _) = serving_state(&[0x11, 0x22, 0x33]);
        let ids = json!({"stateIds":[hex::encode([0x11;32]), hex::encode([0x22;32]), hex::encode([0x33;32])]}).to_string();
        let full = crate::api::batch::handle_get_inclusion_proofs_v1(&ids, usize::MAX, Arc::clone(&state))
            .await
            .unwrap();
        // Exactly the full size fits; one byte less is rejected.
        crate::api::batch::handle_get_inclusion_proofs_v1(&ids, full.len(), Arc::clone(&state))
            .await
            .unwrap();
        let e = crate::api::batch::handle_get_inclusion_proofs_v1(&ids, full.len() - 1, state)
            .await
            .unwrap_err();
        assert_eq!(e.code, -32007);
        let d = e.data.unwrap();
        assert_eq!(d["detail"], json!("response_bytes"));
        assert_eq!(d["limit"], json!(batch_limits::MAX_RESPONSE_BYTES));
    }

    #[tokio::test]
    async fn legacy_methods_keep_their_behaviour() {
        let (state, _) = serving_state(&[0x11]);
        let (status, r) = call(&state, json!({"jsonrpc":"2.0","id":9,"method":"get_block_height","params":{}})).await;
        assert_eq!((status, &r["id"]), (StatusCode::OK, &json!(9)));
        assert!(r["result"]["blockNumber"].is_string());
        let (status, r) = call(&state, json!({"jsonrpc":"2.0","id":"s","method":"get_inclusion_proof.v2","params":{"stateId": hex::encode([0x77;32])}})).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(r["error"]["code"], json!(-32020));
        let (status, r) = call(&state, json!({"jsonrpc":"2.0","id":1,"method":"nope","params":{}})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(r["error"]["code"], json!(-32601));
        // String-valued error data stays a string.
        let (_, r) = call(&state, json!({"jsonrpc":"2.0","id":1,"method":"certification_request","params":"zz"})).await;
        assert_eq!(r["error"]["code"], json!(-32602));
        let (status, text) = dispatch(state, b"{not json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(text.contains("-32700"));
    }
}
