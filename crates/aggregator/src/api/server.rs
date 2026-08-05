//! axum HTTP server and JSON-RPC dispatch.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use tracing::debug;

use super::handlers::{
    handle_certification_request, handle_get_block_height, handle_get_inclusion_proof_v2,
    handle_get_non_inclusion_proof_v1,
};
use super::types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
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

async fn jsonrpc_handler(
    State(state): State<Arc<AggregatorState>>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    if req.jsonrpc != "2.0" {
        let err = JsonRpcError {
            code: JsonRpcError::INVALID_REQUEST,
            message: "jsonrpc must be \"2.0\"".into(),
            data: None,
        };
        let resp = JsonRpcResponse::error(req.id, err);
        return (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()));
    }

    debug!(method = %req.method, "JSON-RPC request");

    let result = match req.method.as_str() {
        "certification_request" => handle_certification_request(req.params, state).await,
        "get_inclusion_proof.v2" => handle_get_inclusion_proof_v2(req.params, state).await,
        "get_non_inclusion_proof.v1" => handle_get_non_inclusion_proof_v1(req.params, state).await,
        "get_block_height" => handle_get_block_height(req.params, state).await,
        _ => Err(JsonRpcError::method_not_found(&req.method)),
    };

    match result {
        Ok(val) => {
            let resp = JsonRpcResponse::success(req.id, val);
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
        Err(e) if e.is_not_found() => {
            // Unknown identifiers fail fast. Pending certification has its own
            // JSON-RPC code and remains a 200 response so clients can poll only
            // states the server has actually accepted.
            let resp = JsonRpcResponse::error(req.id, e);
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::to_value(resp).unwrap()),
            )
        }
        Err(e) if e.is_server_busy() => {
            let resp = JsonRpcResponse::error(req.id, e);
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::to_value(resp).unwrap()),
            )
        }
        Err(e) => {
            let resp = JsonRpcResponse::error(req.id, e);
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
    }
}
