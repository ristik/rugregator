//! axum HTTP server and JSON-RPC dispatch.

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use tracing::debug;

use super::batch::handle_get_inclusion_proofs_v1_waited;
use super::handlers::{
    handle_certification_request, handle_get_block_height, handle_get_inclusion_proof_v2,
    handle_get_inclusion_proof_v2_waited, handle_get_non_inclusion_proof_v1,
};
use super::transport::ConnCtx;
use super::types::{batch_limits, JsonRpcError, JsonRpcResponse};
use crate::longpoll::{scan_wait_ms, ActiveHandle, ActiveSlot, WaitScan, WRITE_RESERVE};
use crate::storage::AggregatorState;
use tokio::time::Instant;

// ─── Router ───────────────────────────────────────────────────────────────────

pub fn build_router(state: Arc<AggregatorState>) -> Router {
    Router::new()
        .route("/", post(jsonrpc_handler).options(preflight_handler))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
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

async fn metrics_handler(State(state): State<Arc<AggregatorState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.longpoll().render_metrics(),
    )
}

/// Request headers browsers may send (aggregator-go `CORSAllowHeaders`).
const CORS_ALLOW_HEADERS: &str = "Content-Type, Authorization, X-API-Key, X-State-ID";
/// Response header browsers must be allowed to read (the overload answer's `Retry-After`).
const CORS_EXPOSE_HEADERS: &str = "Retry-After";

/// CORS headers of the JSON-RPC route (also on error answers).
fn set_cors(headers: &mut axum::http::HeaderMap, methods: &'static str) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(methods),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(CORS_ALLOW_HEADERS),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(CORS_EXPOSE_HEADERS),
    );
}

/// One complete JSON body with its `Content-Length`, `Cache-Control: no-store` (proof, status and
/// error answers change over time: proxies and caches must not keep them), and the CORS headers;
/// every `503` also carries `Retry-After: 1`. The single response path of the JSON-RPC route.
fn json_response(
    status: StatusCode,
    text: String,
    held: Option<ActiveHandle>,
    conn: Option<Arc<ConnCtx>>,
    write_deadline: Instant,
) -> Response {
    let length = text.len();
    // Armed before the first byte is framed or flushed: the write deadline applies to a large
    // chunk in socket backpressure and to replies which hold no budget unit alike.
    if let Some(conn) = conn.as_ref() {
        conn.arm_write(held, write_deadline);
    }
    let mut response = Response::new(axum::body::Body::from(Bytes::from(text)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if status == StatusCode::SERVICE_UNAVAILABLE {
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    set_cors(headers, "POST, OPTIONS");
    response
}

/// Request body ceiling (aggregator-go's JSON-RPC server accepts up to 16 MiB; the methods that
/// have their own, smaller limits enforce them after this one).
const MAX_BODY_BYTES: usize = 16 << 20;

/// The JSON-RPC route.
///
/// Order matters: the request is admitted to the global active-work budget and its absolute
/// 30 s lifetime starts *before* the body is read; body collection, the application work and the
/// transport write are each bounded inside that lifetime, and the budget unit stays held (or
/// travels into a proof worker) until the response has been written to the socket.
async fn jsonrpc_handler(
    State(state): State<Arc<AggregatorState>>,
    conn: Option<Extension<Arc<ConnCtx>>>,
    request: axum::http::Request<axum::body::Body>,
) -> Response {
    use http_body_util::{BodyExt, LengthLimitError, Limited};
    let started = Instant::now();
    let reg = Arc::clone(state.longpoll());
    let conn = conn.map(|Extension(c)| c);
    let hard = started + reg.budget();
    let write_deadline = hard;
    // The global budget C. When it is exhausted the request is refused before anything is read
    // or parsed: HTTP 503 + `Retry-After: 1`, a `-32006 busy` body with a null id.
    let Some(handle) = reg.gate().acquire_handle() else {
        let err = JsonRpcError::detailed(
            JsonRpcError::CONCURRENCY_LIMIT,
            "Concurrency limit exceeded",
            "busy",
            "active_requests",
            true,
            None,
            None,
        );
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            error_text(serde_json::Value::Null, err),
            None,
            conn,
            write_deadline,
        );
    };
    let slot = ActiveSlot::new(Some(handle));
    let reply = |status: StatusCode, text: String, slot: &ActiveSlot| {
        json_response(status, text, slot.take(), conn.clone(), write_deadline)
    };

    // The body is read here, not by an extractor, so that an oversized one gets the same JSON
    // `limit_exceeded` answer (and headers) as every other error instead of a plain-text 413.
    // Only the length limit is a 413; any other read failure (client abort, bad chunking) is a
    // parse error, as in aggregator-go. A slow body is cut at the body deadline.
    let body_deadline = started
        + reg
            .body_timeout()
            .min(reg.budget().saturating_sub(WRITE_RESERVE));
    let collected = tokio::time::timeout_at(
        body_deadline,
        Limited::new(request.into_body(), MAX_BODY_BYTES).collect(),
    )
    .await;
    let body = match collected {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                error_text(
                    serde_json::Value::Null,
                    JsonRpcError::limit_exceeded("request_bytes", MAX_BODY_BYTES),
                ),
                &slot,
            )
        }
        Ok(Err(_)) => {
            return reply(
                StatusCode::BAD_REQUEST,
                error_text(
                    serde_json::Value::Null,
                    JsonRpcError {
                        code: JsonRpcError::PARSE_ERROR,
                        message: "parse error".into(),
                        data: None,
                    },
                ),
                &slot,
            )
        }
        Err(_) => {
            return reply(
                StatusCode::REQUEST_TIMEOUT,
                error_text(
                    serde_json::Value::Null,
                    JsonRpcError::limit_exceeded("request_timeout", 0),
                ),
                &slot,
            )
        }
    };
    // The application lifetime: the whole read-and-wait ends in time for the write. Cancelling
    // the future drops it; work already handed to a proof worker keeps its accounting there.
    let app_deadline = hard.checked_sub(WRITE_RESERVE).unwrap_or(hard);
    match tokio::time::timeout_at(app_deadline, dispatch_with(state, &body, started, &slot)).await {
        Ok((status, text)) => reply(status, text, &slot),
        Err(_) => reply(
            StatusCode::SERVICE_UNAVAILABLE,
            error_text(serde_json::Value::Null, JsonRpcError::busy_deadline()),
            &slot,
        ),
    }
}

/// CORS preflight of the JSON-RPC route.
async fn preflight_handler() -> Response {
    let mut response = StatusCode::OK.into_response();
    set_cors(response.headers_mut(), "GET, POST, OPTIONS");
    response
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
    dispatch_with(state, body, Instant::now(), &ActiveSlot::default()).await
}

/// [`dispatch`] with the request's admission time (the absolute budget of any wait counts from
/// it) and its active-work slot (released while the request parks).
pub async fn dispatch_with(
    state: Arc<AggregatorState>,
    body: &[u8],
    started: Instant,
    slot: &ActiveSlot,
) -> (StatusCode, String) {
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
        return dispatch_batch(state, body, env, trailing, started, slot).await;
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

    // v2 opt-in: a `waitMs` found in the raw params (the decoded value above has lost duplicate
    // keys and the numeric spelling). Absent keeps every legacy byte.
    let mut v2_wait = None;
    if env.method == "get_inclusion_proof.v2" {
        let raw_params = env.params.map(|p| p.get()).unwrap_or("");
        // A cheap substring test first: requests which cannot carry the member are not scanned.
        let scan = if raw_params.contains("waitMs") || raw_params.contains("\\u") {
            scan_wait_ms(raw_params)
        } else {
            WaitScan::Absent
        };
        if scan != WaitScan::Absent {
            // Opt-in requests (valid wait or not) are bounded like the batch method, before any
            // value validation: 64 KiB request, 32 KiB params, 128 encoded ID bytes. A preflight
            // rejection carries no echo.
            if body.len() > batch_limits::MAX_REQUEST_BYTES {
                return (
                    StatusCode::OK,
                    error_text(
                        serde_json::Value::Null,
                        JsonRpcError::limit_exceeded(
                            "request_bytes",
                            batch_limits::MAX_REQUEST_BYTES,
                        ),
                    ),
                );
            }
            if !valid_raw_id(env.id) {
                return (
                    StatusCode::OK,
                    error_text(
                        serde_json::Value::Null,
                        JsonRpcError::invalid_request_detail("invalid_id"),
                    ),
                );
            }
            if raw_params.len() > batch_limits::MAX_PARAMS_BYTES {
                return (
                    StatusCode::OK,
                    error_text(
                        id,
                        JsonRpcError::limit_exceeded(
                            "request_bytes",
                            batch_limits::MAX_PARAMS_BYTES,
                        ),
                    ),
                );
            }
        }
        match scan {
            WaitScan::Absent => {}
            WaitScan::Invalid => {
                // Not a wait, but a wait-bearing object: the validation code, with the zero echo.
                return (
                    StatusCode::OK,
                    error_text(
                        id,
                        JsonRpcError::validation(format!(
                            "Invalid parameters: waitMs must be a non-negative integer no greater than {}",
                            crate::longpoll::MAX_WAIT_MS
                        ))
                        .with_waited(0),
                    ),
                );
            }
            WaitScan::Valid(w) => v2_wait = Some(w),
        }
    }

    let result = match env.method.as_str() {
        "certification_request" => handle_certification_request(params, state).await,
        "get_inclusion_proof.v2" => match v2_wait {
            Some(w) => handle_get_inclusion_proof_v2_waited(params, w, state, started, slot).await,
            None => handle_get_inclusion_proof_v2(params, state).await,
        },
        "get_non_inclusion_proof.v1" => {
            handle_get_non_inclusion_proof_v1(params, state, slot).await
        }
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
        Err(e) if e.code == JsonRpcError::CONCURRENCY_LIMIT => {
            (StatusCode::SERVICE_UNAVAILABLE, error_text(id, e))
        }
        Err(e) => (StatusCode::OK, error_text(id, e)),
    }
}

async fn dispatch_batch(
    state: Arc<AggregatorState>,
    body: &[u8],
    env: RawEnvelope<'_>,
    trailing: bool,
    started: Instant,
    slot: &ActiveSlot,
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
    // Request, ID and params-size preflight rejections never carry the long-poll echo, whatever
    // the params hold; the echo starts with value validation, inside the handler.
    let raw_params = env.params.map(|p| p.get()).unwrap_or("");
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

    match handle_get_inclusion_proofs_v1_waited(raw_params, max_result, state, started, slot).await
    {
        Ok(result) => (
            StatusCode::OK,
            format!(r#"{{"jsonrpc":"2.0","result":{result},"id":{id_text}}}"#),
        ),
        // `-32006` is HTTP 503 + `Retry-After: 1` (aggregator-go); the body is unchanged.
        Err(e) if is_opt_in_overload(&e) => (StatusCode::SERVICE_UNAVAILABLE, error_text(id, e)),
        Err(e) => (StatusCode::OK, error_text(id, e)),
    }
}

/// Echo zero on a handled error of a request whose params object carries a `waitMs` member.
fn echo_zero(e: JsonRpcError, scan: WaitScan) -> JsonRpcError {
    if scan == WaitScan::Absent {
        e
    } else {
        e.with_waited(0)
    }
}

/// `-32006` of a wait-bearing request (resume overload, or the pools busy during its reads) is
/// the overload answer: HTTP 503 + `Retry-After`. The same code on a request without `waitMs`
/// keeps its legacy HTTP 200.
fn is_opt_in_overload(e: &JsonRpcError) -> bool {
    e.code == JsonRpcError::CONCURRENCY_LIMIT
        && e.data.as_ref().is_some_and(|d| d.get("waitedMs").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::cbor::{test_uc_cbor, CertDataFields};
    use crate::longpoll::WaitScan;
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
                    merkle_path_cbor: Some(vec![0x80]),
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
            let ciborium::value::Value::Array(top) = v else {
                panic!()
            };
            assert_eq!(top[0], ciborium::value::Value::Integer(1u64.into()));
        }
        // The result is exactly what the string-built response parses to, with
        // the explicit latest selector too.
        let (_, again) = call(
            &state,
            batch(json!("a"), json!({"stateIds": ids, "stateRoot": "latest"})),
        )
        .await;
        assert_eq!(again["result"], resp["result"]);
        assert_eq!(again["id"], json!("a"));
    }

    fn batch_body(ids: &[String], extra: &str) -> String {
        let list = ids
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"get_inclusion_proofs.v1","params":{{"stateIds":[{list}]{extra}}}}}"#
        )
    }

    #[tokio::test]
    async fn omitted_wait_is_byte_identical_and_a_present_zero_adds_only_the_echo() {
        let (state, _) = serving_state(&[0x11, 0x22]);
        let ids = [hex::encode([0x22; 32]), hex::encode([0x11; 32])];
        let (s0, plain) = dispatch(Arc::clone(&state), batch_body(&ids, "").as_bytes()).await;
        assert!(!plain.contains("waitedMs"));
        // "stateRoot":"latest" alone is still no opt-in.
        let (_, latest) = dispatch(
            Arc::clone(&state),
            batch_body(&ids, r#","stateRoot":"latest""#).as_bytes(),
        )
        .await;
        assert_eq!(latest, plain);
        // Every present wait, zero included, is the same result plus result.waitedMs.
        for extra in [
            r#","waitMs":0"#,
            r#","waitMs":20000"#,
            r#","waitMs":9007199254740991"#,
            r#","waitMs":5,"stateRoot":"latest""#,
        ] {
            let (s1, with) = dispatch(Arc::clone(&state), batch_body(&ids, extra).as_bytes()).await;
            assert_eq!(s1, s0, "{extra}");
            let (a, b): (Value, Value) = (
                serde_json::from_str(&plain).unwrap(),
                serde_json::from_str(&with).unwrap(),
            );
            assert_eq!(
                b["result"]["waitedMs"],
                json!(0),
                "{extra}: everything is included, nothing waited"
            );
            let mut stripped = b.clone();
            stripped["result"]
                .as_object_mut()
                .unwrap()
                .remove("waitedMs");
            assert_eq!(stripped, a, "{extra}");
        }
        // A never-seen id: unknown ends the wait at once, with the echo in error.data.
        let miss = hex::encode([0x99; 32]);
        let (_, e0) = call(&state, batch(json!(1), json!({"stateIds":[miss]}))).await;
        let (_, e1) = call(
            &state,
            batch(json!(1), json!({"stateIds":[miss], "waitMs": 3000})),
        )
        .await;
        assert!(e0["error"]["data"].get("waitedMs").is_none());
        assert_eq!(e1["error"]["data"]["waitedMs"], json!(0));
        assert_eq!(e1["error"]["data"]["detail"], json!("state_unknown"));
        let mut e1s = e1.clone();
        e1s["error"]["data"]
            .as_object_mut()
            .unwrap()
            .remove("waitedMs");
        assert_eq!(e1s, e0);
    }

    #[tokio::test]
    async fn invalid_waits_are_not_waits_and_recognised_ones_echo_zero_on_validation_errors() {
        let (state, root) = serving_state(&[0x11]);
        let present = hex::encode([0x11; 32]);
        // Invalid wait: malformed_params; the params object is wait-bearing, so it echoes 0.
        for params in [
            format!(r#"{{"stateIds":["{present}"],"waitMs":-1}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":-0}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":"5"}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":null}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":1.5}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":1e3}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":9007199254740992}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":1,"waitMs":1}}"#),
            format!(r#"{{"stateIds":["{present}"],"waitMs":1,"waitMs":1}}"#),
        ] {
            let body = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"get_inclusion_proofs.v1","params":{params}}}"#
            );
            let (_, text) = dispatch(Arc::clone(&state), body.as_bytes()).await;
            let resp: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(resp["error"]["code"], json!(-32602), "{params}");
            assert_eq!(
                resp["error"]["data"]["detail"],
                json!("malformed_params"),
                "{params}"
            );
            assert_eq!(resp["error"]["data"]["waitedMs"], json!(0), "{params}");
        }
        // A valid wait next to another defect: the defect, with the echo (it is what tells a
        // client this server understands waitMs). Exact root + any wait is malformed_params.
        for (params, detail) in [
            (
                format!(
                    r#"{{"stateIds":["{present}"],"stateRoot":"{}","waitMs":0}}"#,
                    hex::encode(root)
                ),
                "malformed_params",
            ),
            (
                format!(
                    r#"{{"stateIds":["{present}"],"stateRoot":"{}","waitMs":9000}}"#,
                    hex::encode(root)
                ),
                "malformed_params",
            ),
            (
                format!(r#"{{"stateIds":["{present}"],"waitMs":5,"extra":1}}"#),
                "malformed_params",
            ),
            (
                r#"{"stateIds":["abcd"],"waitMs":5000}"#.to_owned(),
                "invalid_state_id",
            ),
        ] {
            let body = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"get_inclusion_proofs.v1","params":{params}}}"#
            );
            let (_, text) = dispatch(Arc::clone(&state), body.as_bytes()).await;
            let resp: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(resp["error"]["code"], json!(-32602), "{params}");
            assert_eq!(resp["error"]["data"]["detail"], json!(detail), "{params}");
            assert_eq!(resp["error"]["data"]["waitedMs"], json!(0), "{params}");
        }
    }

    #[tokio::test]
    async fn v2_wait_shapes_and_errors() {
        let (state, root) = serving_state(&[0x11]);
        state.finalize_block(BlockInfo {
            block_number: 1,
            root_hash: Some(root),
            uc_cbor: test_uc_cbor(Some(root), &[0x80], 0),
        });
        let v2 = |params: Value| json!({"jsonrpc":"2.0","id":3,"method":"get_inclusion_proof.v2","params":params});
        let id = hex::encode([0x11; 32]);
        let bare = call(&state, v2(json!({"stateId": id}))).await.1;
        assert!(bare["result"].is_string());
        let proof = bare["result"].as_str().unwrap().to_owned();
        // wait-only: {proof, waitedMs}; wait+status adds status; includeStatus alone is unchanged.
        let (_, r) = call(&state, v2(json!({"stateId": id, "waitMs": 5000}))).await;
        assert_eq!(r["result"], json!({"proof": proof, "waitedMs": 0}));
        let (_, r) = call(
            &state,
            v2(json!({"stateId": id, "waitMs": 5000, "includeStatus": true})),
        )
        .await;
        assert_eq!(
            r["result"],
            json!({"proof": proof, "status": "included", "waitedMs": 0})
        );
        let (_, r) = call(&state, v2(json!({"stateId": id, "includeStatus": true}))).await;
        assert_eq!(r["result"], json!({"proof": proof, "status": "included"}));
        // validation errors of a recognised wait echo zero (data absent becomes an object)
        let (_, r) = call(&state, v2(json!({"stateId": "abcd", "waitMs": 5000}))).await;
        assert_eq!(r["error"]["code"], json!(-32000));
        assert_eq!(r["error"]["data"], json!({"waitedMs": 0}));
        let (_, r) = call(
            &state,
            v2(json!({"stateId": id, "waitMs": 5000, "includeStatus": "yes"})),
        )
        .await;
        assert_eq!(r["error"]["code"], json!(-32602));
        assert_eq!(r["error"]["data"], json!({"waitedMs": 0}));
        // an invalid wait is not a wait but the object is wait-bearing: -32000 with the zero echo
        for raw in [
            "-1",
            "-0",
            "1.5",
            "1e3",
            "\"5\"",
            "null",
            "true",
            "9007199254740992",
            "[1]",
        ] {
            let body = format!(
                r#"{{"jsonrpc":"2.0","id":3,"method":"get_inclusion_proof.v2","params":{{"stateId":"{id}","waitMs":{raw}}}}}"#
            );
            let (_, text) = dispatch(Arc::clone(&state), body.as_bytes()).await;
            let r: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(r["error"]["code"], json!(-32000), "{raw}");
            assert_eq!(r["error"]["data"], json!({"waitedMs": 0}), "{raw}");
        }
        let dup = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"get_inclusion_proof.v2","params":{{"stateId":"{id}","waitMs":1,"waitMs":2}}}}"#
        );
        let (_, text) = dispatch(Arc::clone(&state), dup.as_bytes()).await;
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap()["error"]["code"],
            json!(-32000)
        );
        // unknown spelling is just an ignored member, byte-identical to the bare call
        let (_, r) = call(&state, v2(json!({"stateId": id, "waitms": 5000}))).await;
        assert_eq!(r["result"], json!(proof));
        // opt-in v2 is bounded like the batch method
        let (_, r) = call(
            &state,
            v2(json!({"stateId": id, "waitMs": 1, "pad": "a".repeat(70_000)})),
        )
        .await;
        assert_eq!(r["error"]["data"]["detail"], json!("request_bytes"));
        assert!(
            r["error"]["data"].get("waitedMs").is_none(),
            "preflight rejections carry no echo"
        );
        assert_eq!(r["id"], Value::Null);
        let (_, r) = call(&state, json!({"jsonrpc":"2.0","id":{"a":1},"method":"get_inclusion_proof.v2","params":{"stateId": id, "waitMs": 1}})).await;
        assert_eq!(r["error"]["data"]["detail"], json!("invalid_id"));
        let (_, r) = call(
            &state,
            v2(json!({"stateId": id, "waitMs": 1, "pad": "a".repeat(40_000)})),
        )
        .await;
        assert_eq!(
            r["error"]["data"]["limit"],
            json!(batch_limits::MAX_PARAMS_BYTES)
        );
        assert!(r["error"]["data"].get("waitedMs").is_none());
        // an invalid wait is bounded by the same preflight, before its value is validated
        let (_, r) = call(
            &state,
            v2(json!({"stateId": id, "waitMs": -1, "pad": "a".repeat(40_000)})),
        )
        .await;
        assert_eq!(r["error"]["data"]["detail"], json!("request_bytes"));
        assert!(r["error"]["data"].get("waitedMs").is_none());
        let (_, r) = call(
            &state,
            v2(json!({"stateId": id, "waitMs": "x", "pad": "a".repeat(70_000)})),
        )
        .await;
        assert_eq!(r["error"]["data"]["detail"], json!("request_bytes"));
        assert!(r["error"]["data"].get("waitedMs").is_none());
        // ... and an invalid wait inside the limits still echoes zero (validation, not preflight)
        let (_, r) = call(&state, v2(json!({"stateId": id, "waitMs": -1}))).await;
        assert_eq!(r["error"]["data"], json!({"waitedMs": 0}));
        // the same limits on the batch method never echo
        let big = |extra: Value| {
            let mut p = json!({"stateIds": [id], "pad": "a".repeat(40_000)});
            p.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            batch(json!(3), p)
        };
        let (_, r) = call(&state, big(json!({"waitMs": 5}))).await;
        assert_eq!(r["error"]["data"]["detail"], json!("request_bytes"));
        assert!(r["error"]["data"].get("waitedMs").is_none());
        let (_, r) = call(&state, big(json!({"waitMs": -1}))).await;
        assert_eq!(r["error"]["data"]["detail"], json!("request_bytes"));
        assert!(r["error"]["data"].get("waitedMs").is_none());
        let (_, r) = call(&state, big(json!({}))).await;
        assert!(r["error"]["data"].get("waitedMs").is_none());
        // without waitMs the legacy path stays unbounded by the opt-in limits
        let (_, r) = call(
            &state,
            v2(json!({"stateId": id, "pad": "a".repeat(70_000)})),
        )
        .await;
        assert_eq!(r["result"], json!(proof));
    }

    #[tokio::test]
    async fn the_echo_is_counted_by_the_bounded_serializer() {
        let (state, _) = serving_state(&[0x11, 0x22]);
        let ids = json!({"stateIds":[hex::encode([0x11;32]), hex::encode([0x22;32])], "waitMs": 0})
            .to_string();
        let full =
            crate::api::batch::handle_get_inclusion_proofs_v1(&ids, usize::MAX, Arc::clone(&state))
                .await
                .unwrap();
        assert!(full.ends_with(r#"],"waitedMs":0}"#), "{full}");
        crate::api::batch::handle_get_inclusion_proofs_v1(&ids, full.len(), Arc::clone(&state))
            .await
            .unwrap();
        let e = crate::api::batch::handle_get_inclusion_proofs_v1(&ids, full.len() - 1, state)
            .await
            .unwrap_err();
        assert_eq!(e.code, -32007);
        assert_eq!(e.data.unwrap()["waitedMs"], json!(0));
    }

    #[test]
    fn frozen_params_cases_classify_identically_for_both_methods() {
        let doc: Value =
            serde_json::from_str(include_str!("../../testdata/longpoll/params.json")).unwrap();
        let mut seen = 0;
        for c in doc["cases"].as_array().unwrap() {
            let params = c["params"].as_str().unwrap();
            let scan = crate::longpoll::scan_wait_ms(params);
            let batch_ok = crate::api::batch::parse_params(params).is_ok();
            if c["valid"] == json!(true) {
                match c["waitMs"].as_u64() {
                    Some(w) => assert_eq!(scan, WaitScan::Valid(w), "{}", c["name"]),
                    None => assert_eq!(scan, WaitScan::Absent, "{}", c["name"]),
                }
                if c["method"] == json!("get_inclusion_proofs.v1") {
                    assert!(batch_ok, "{}", c["name"]);
                }
            } else {
                if c["method"] == json!("get_inclusion_proofs.v1") {
                    assert!(!batch_ok, "{}", c["name"]);
                }
                // v2: anything which is not a valid wait is Invalid, or a non-object/other defect
                if c["method"] == json!("get_inclusion_proof.v2") {
                    assert_ne!(scan, WaitScan::Absent, "{}", c["name"]);
                }
            }
            seen += 1;
        }
        assert!(seen >= 70, "{seen}");
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
        let (_, r) = call(
            &state,
            batch(json!(1), json!({"stateIds":[present, absent]})),
        )
        .await;
        assert_eq!(
            err(&r),
            (
                -32008,
                "proof_unavailable".into(),
                "state_unknown".into(),
                Some(false)
            )
        );
        assert_eq!(r["error"]["data"]["indexes"], json!({"unknown":[1]}));
        // exact root, absent leaf
        let (_, r) = call(
            &state,
            batch(
                json!(1),
                json!({"stateIds":[absent], "stateRoot": hex::encode(root)}),
            ),
        )
        .await;
        assert_eq!(
            err(&r),
            (
                -32008,
                "proof_unavailable".into(),
                "state_not_in_root".into(),
                Some(false)
            )
        );
        assert_eq!(r["error"]["data"]["indexes"], json!({"not_in_root":[0]}));
        // exact root not retained
        let (_, r) = call(
            &state,
            batch(
                json!(1),
                json!({"stateIds":[present], "stateRoot": hex::encode([5u8; 32])}),
            ),
        )
        .await;
        assert_eq!(
            err(&r),
            (
                -32008,
                "proof_unavailable".into(),
                "view_not_retained".into(),
                Some(true)
            )
        );
        // no latest view
        state.clear_certified_snapshot();
        let (_, r) = call(&state, batch(json!(1), json!({"stateIds":[present]}))).await;
        assert_eq!(
            err(&r),
            (
                -32008,
                "proof_unavailable".into(),
                "no_finalized_view".into(),
                Some(true)
            )
        );
        // invalid params
        let (_, r) = call(&state, batch(json!(1), json!({"stateIds":["zz"]}))).await;
        assert_eq!(
            err(&r),
            (
                -32602,
                "invalid_request".into(),
                "invalid_state_id".into(),
                Some(false)
            )
        );
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
        assert_eq!(
            err(&r),
            (
                -32007,
                "limit_exceeded".into(),
                "state_count".into(),
                Some(false)
            )
        );
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
        let (_, r) = call(
            &state,
            batch(json!("x".repeat(126)), json!({"stateIds":[present]})),
        )
        .await;
        assert!(r.get("error").is_none(), "{r}");
        // numeric id echoes as a number
        let (_, r) = call(&state, batch(json!(-3), json!({"stateIds":[present]}))).await;
        assert_eq!(r["id"], json!(-3));

        // Whole body over 64 KiB: 413 + limit_exceeded/request_bytes, id echoed.
        let padded = batch(
            json!(5),
            json!({"stateIds":[present], "pad": "a".repeat(70_000)}),
        );
        let (status, r) = call(&state, padded).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "Go answers limit errors with HTTP 200"
        );
        assert_eq!(r["error"]["code"], json!(-32007));
        assert_eq!(r["error"]["data"]["detail"], json!("request_bytes"));
        assert_eq!(
            r["error"]["data"]["limit"],
            json!(batch_limits::MAX_REQUEST_BYTES)
        );
        assert_eq!(r["id"], json!(5));
        // Params over 32 KiB but body under 64 KiB.
        let padded = batch(
            json!(5),
            json!({"stateIds":[present], "pad": "a".repeat(40_000)}),
        );
        let (status, r) = call(&state, padded).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            r["error"]["data"]["limit"],
            json!(batch_limits::MAX_PARAMS_BYTES)
        );
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
        assert!(serde_json::from_str::<Value>(&text)
            .unwrap()
            .get("error")
            .is_none());
        // Empty method on the batch path cannot happen; legacy trailing data stays a parse error.
        let legacy =
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block_height\",\"params\":{}} x";
        let (status, text) = dispatch(state.clone(), legacy).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(text.contains("-32700"));
        // Wrong jsonrpc version.
        let (_, r) = call(
            &state,
            json!({"jsonrpc":"1.0","id":1,"method":"get_inclusion_proofs.v1","params":{}}),
        )
        .await;
        assert_eq!(r["error"]["code"], json!(-32600));
        assert_eq!(r["error"]["data"]["detail"], json!("invalid_envelope"));
    }

    #[tokio::test]
    async fn oversized_responses_fail_while_building_without_partial_output() {
        let (state, _) = serving_state(&[0x11, 0x22, 0x33]);
        let ids = json!({"stateIds":[hex::encode([0x11;32]), hex::encode([0x22;32]), hex::encode([0x33;32])]}).to_string();
        let full =
            crate::api::batch::handle_get_inclusion_proofs_v1(&ids, usize::MAX, Arc::clone(&state))
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

    /// One request through the real router, so the HTTP layer (headers, status) is exercised.
    async fn http(
        state: &Arc<AggregatorState>,
        method: &str,
        body: String,
    ) -> axum::http::Response<axum::body::Body> {
        use tower::ServiceExt;
        let request = axum::http::Request::builder()
            .method(method)
            .uri("/")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        build_router(Arc::clone(state))
            .oneshot(request)
            .await
            .unwrap()
    }

    async fn read_body(response: axum::http::Response<axum::body::Body>) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn every_json_rpc_response_carries_content_length_no_store_and_cors() {
        let (state, _) = serving_state(&[0x11]);
        let present = hex::encode([0x11; 32]);
        let bodies = [
            batch(json!(1), json!({"stateIds":[present]})).to_string(), // result
            batch(json!(2), json!({"stateIds":["zz"]})).to_string(),    // batch error
            json!({"jsonrpc":"2.0","id":3,"method":"get_block_height","params":{}}).to_string(),
            json!({"jsonrpc":"2.0","id":4,"method":"nope","params":{}}).to_string(), // error
            "{not json".to_owned(),                                                  // 400
        ];
        for body in bodies {
            let response = http(&state, "POST", body.clone()).await;
            let headers = response.headers().clone();
            let bytes = read_body(response).await;
            assert_eq!(
                headers.get("content-length").unwrap().to_str().unwrap(),
                bytes.len().to_string(),
                "{body}"
            );
            assert_eq!(headers.get("cache-control").unwrap(), "no-store");
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
            assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
            assert_eq!(
                headers.get("access-control-expose-headers").unwrap(),
                "Retry-After"
            );
            assert_eq!(
                headers.get("access-control-allow-methods").unwrap(),
                "POST, OPTIONS"
            );
            assert_eq!(
                headers.get("access-control-allow-headers").unwrap(),
                "Content-Type, Authorization, X-API-Key, X-State-ID"
            );
        }
    }

    #[tokio::test]
    async fn preflight_is_answered_with_cors_headers_and_health_has_none() {
        use tower::ServiceExt;
        let (state, _) = serving_state(&[0x11]);
        let response = http(&state, "OPTIONS", String::new()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        assert_eq!(
            headers.get("access-control-allow-methods").unwrap(),
            "GET, POST, OPTIONS"
        );
        assert_eq!(
            headers.get("access-control-allow-headers").unwrap(),
            "Content-Type, Authorization, X-API-Key, X-State-ID"
        );
        assert_eq!(
            headers.get("access-control-expose-headers").unwrap(),
            "Retry-After"
        );
        // CORS is for the JSON-RPC route only (health is not a browser API)
        let request = axum::http::Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = build_router(Arc::clone(&state))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }

    /// The headers every answer carries, whatever its status.
    fn assert_rpc_headers(headers: &axum::http::HeaderMap, body_len: usize) {
        assert_eq!(
            headers.get("content-length").unwrap().to_str().unwrap(),
            body_len.to_string()
        );
        assert_eq!(headers.get("cache-control").unwrap(), "no-store");
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
        assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
        assert_eq!(
            headers.get("access-control-allow-methods").unwrap(),
            "POST, OPTIONS"
        );
        assert_eq!(
            headers.get("access-control-allow-headers").unwrap(),
            "Content-Type, Authorization, X-API-Key, X-State-ID"
        );
        assert_eq!(
            headers.get("access-control-expose-headers").unwrap(),
            "Retry-After"
        );
    }

    #[tokio::test]
    async fn an_oversized_body_is_a_json_413_with_the_same_headers() {
        let (state, _) = serving_state(&[0x11]);
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"get_block_height","params":{{"pad":"{}"}}}}"#,
            "a".repeat(MAX_BODY_BYTES)
        );
        let response = http(&state, "POST", body).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let headers = response.headers().clone();
        let bytes = read_body(response).await;
        assert_rpc_headers(&headers, bytes.len());
        let r: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r["error"]["code"], json!(-32007));
        assert_eq!(r["error"]["data"]["reason"], json!("limit_exceeded"));
        assert_eq!(r["error"]["data"]["detail"], json!("request_bytes"));
        assert_eq!(r["error"]["data"]["limit"], json!(MAX_BODY_BYTES));
        assert_eq!(r["id"], Value::Null);
        // a body above axum's old 2 MiB default but under the ceiling is served
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"get_block_height","params":{{"pad":"{}"}}}}"#,
            "a".repeat(3 << 20)
        );
        assert_eq!(http(&state, "POST", body).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_body_that_fails_while_reading_is_a_parse_error_not_a_413() {
        use tower::ServiceExt;
        let (state, _) = serving_state(&[0x11]);
        let stream = futures::stream::iter(vec![
            Ok(axum::body::Bytes::from_static(b"{\"jsonrpc\"")),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "client abort",
            )),
        ]);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .body(axum::body::Body::from_stream(stream))
            .unwrap();
        let response = build_router(Arc::clone(&state))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let headers = response.headers().clone();
        let bytes = read_body(response).await;
        assert_rpc_headers(&headers, bytes.len());
        let r: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r["error"]["code"], json!(-32700));
    }

    #[tokio::test]
    async fn non_inclusion_errors_keep_their_status_and_carry_headers_and_data() {
        let (tx, _rx) = mpsc::channel(1);
        let empty = AggregatorState::new(tx, None); // no finalized view yet
        let ni = |id: u64| {
            json!({"jsonrpc":"2.0","id":id,"method":"get_non_inclusion_proof.v1",
                   "params":{"stateId": hex::encode([0x77; 32])}})
            .to_string()
        };
        // -32020: no certified snapshot -> 404
        let response = http(&empty, "POST", ni(1)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let headers = response.headers().clone();
        let bytes = read_body(response).await;
        assert_rpc_headers(&headers, bytes.len());
        let r: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r["error"]["code"], json!(-32020));
        assert_eq!(r["error"]["data"]["reason"], json!("proof_unavailable"));
        assert_eq!(r["error"]["data"]["detail"], json!("no_finalized_view"));
        assert_eq!(r["error"]["data"]["retryable"], json!(true));
        // -32023: the proof service is busy -> 429
        let (state, _) = serving_state(&[0x11]);
        let held: Vec<_> = (0..smt_store::CERTIFIED_PROOF_MAX_IN_FLIGHT)
            .map(|_| state.proof_pool().try_acquire(0).unwrap())
            .collect();
        let response = http(&state, "POST", ni(2)).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let headers = response.headers().clone();
        let bytes = read_body(response).await;
        assert_rpc_headers(&headers, bytes.len());
        let r: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r["error"]["code"], json!(-32023));
        assert_eq!(r["error"]["data"]["reason"], json!("busy"));
        assert_eq!(r["error"]["data"]["detail"], json!("active_requests"));
        drop(held);
    }

    #[tokio::test]
    async fn legacy_methods_keep_their_behaviour() {
        let (state, _) = serving_state(&[0x11]);
        let (status, r) = call(
            &state,
            json!({"jsonrpc":"2.0","id":9,"method":"get_block_height","params":{}}),
        )
        .await;
        assert_eq!((status, &r["id"]), (StatusCode::OK, &json!(9)));
        assert!(r["result"]["blockNumber"].is_string());
        let (status, r) = call(&state, json!({"jsonrpc":"2.0","id":"s","method":"get_inclusion_proof.v2","params":{"stateId": hex::encode([0x77;32])}})).await;
        // an unknown state is a normal result (aggregator-go's empty-proof answer), not -32020/404
        assert_eq!(status, StatusCode::OK);
        assert!(r.get("error").is_none() && r["result"].is_string(), "{r}");
        let (status, r) = call(
            &state,
            json!({"jsonrpc":"2.0","id":1,"method":"nope","params":{}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(r["error"]["code"], json!(-32601));
        // String-valued error data stays a string.
        let (_, r) = call(
            &state,
            json!({"jsonrpc":"2.0","id":1,"method":"certification_request","params":"zz"}),
        )
        .await;
        assert_eq!(r["error"]["code"], json!(-32602));
        let (status, text) = dispatch(state, b"{not json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(text.contains("-32700"));
    }

    /// Replays the stateless error cases of aggregator-go's revision-4 echo corpus (#271): every
    /// validation error of a wait-bearing call echoes zero (invalid, duplicate, escaped and
    /// reordered `waitMs` included); preflight rejections do not. Cases which need server state
    /// (pending, included, busy, ...) are covered by the integration tests.
    #[tokio::test]
    async fn echo_corpus_validation_and_preflight_cases_match_the_server() {
        let corpus: Value =
            serde_json::from_str(include_str!("../../testdata/longpoll/echo.json")).unwrap();
        let (state, root) = serving_state(&[0x11]);
        state.finalize_block(BlockInfo {
            block_number: 1,
            root_hash: Some(root),
            uc_cbor: test_uc_cbor(Some(root), &[0x80], 0),
        });
        let stateless = |name: &str| {
            name.contains("error-validation")
                || name.contains("error-invalid-wait")
                || name.contains("validation-error-with-recognized-wait")
                || name.contains("unknown-member-with-valid-wait")
                || name.contains("exact-root-with-wait")
                || name.contains("batch/invalid-wait")
        };
        let mut replayed = 0;
        for case in corpus["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            if !stateless(name) {
                continue;
            }
            let req = &case["request"];
            let body = if let Some(raw) = case.get("rawRequest").and_then(|r| r.as_str()) {
                raw.to_owned()
            } else if let Some(raw) = case.get("rawParams").and_then(|r| r.as_str()) {
                format!(
                    r#"{{"jsonrpc":"2.0","id":{},"method":{},"params":{raw}}}"#,
                    req["id"], req["method"]
                )
            } else {
                req.to_string()
            };
            let (_, text) = dispatch(Arc::clone(&state), body.as_bytes()).await;
            let got: Value = serde_json::from_str(&text).unwrap();
            let want = &case["response"];
            assert_eq!(got["id"], want["id"], "{name}");
            assert_eq!(
                got["error"]["code"], want["error"]["code"],
                "{name}: {text}"
            );
            assert_eq!(
                got["error"]["data"], want["error"]["data"],
                "{name}: {text}"
            );
            if req["method"] == json!("get_inclusion_proofs.v1") {
                assert_eq!(got["error"]["message"], want["error"]["message"], "{name}");
            }
            replayed += 1;
        }
        // the exact intended set: 5 v2 validation/invalid-wait echoes + 4 more v2 spellings, the
        // batch validation cases and the two no-echo preflight cases (19 in revision 4)
        assert_eq!(replayed, 19, "corpus cases replayed");
    }

    /// The write deadline is armed when the response is built, whether or not the request holds a
    /// budget unit (an overload refusal holds none) and before anything is framed or flushed.
    #[test]
    fn every_response_arms_its_write_deadline_with_or_without_a_unit() {
        let ctx = Arc::new(ConnCtx::default());
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let _r = json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "{}".into(),
            None,
            Some(Arc::clone(&ctx)),
            deadline,
        );
        assert_eq!(ctx.armed_deadline(), Some(deadline));
        let ctx2 = Arc::new(ConnCtx::default());
        let big = "x".repeat(2 << 20);
        let _r = json_response(StatusCode::OK, big, None, Some(Arc::clone(&ctx2)), deadline);
        assert_eq!(
            ctx2.armed_deadline(),
            Some(deadline),
            "a large body is armed before it is polled"
        );
    }
}
