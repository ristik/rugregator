//! JSON-RPC wire types for the aggregator API.

use serde::{Deserialize, Serialize};

// ─── JSON-RPC envelope ────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    #[serde(default)]
    pub id: serde_json::Value,
}

/// A JSON-RPC 2.0 response (success or error).
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }
    pub fn error(id: serde_json::Value, err: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(err),
            id,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    /// A plain string for the legacy errors, a structured object for the
    /// Go-compatible batch errors (`reason`, `detail`, `retryable`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    // JSON-RPC 2.0 reserves -32000..-32099 for implementation-defined server
    // errors. Within that range the Unicity aggregators split the space:
    //
    //   -32000..-32019  implementation-private. aggregator-go allocates
    //                   -32000..-32006 here, so nothing shared may use them.
    //   -32020..-32039  shared proof-lookup states, below. These describe the
    //                   protocol rather than one implementation, so another
    //                   aggregator can adopt them verbatim and a client can
    //                   read them without knowing which server it reached.
    //
    /// The aggregator has no record of this state id: neither certified nor
    /// pending. Maps to HTTP 404.
    pub const NOT_FOUND: i32 = -32020;
    /// Historical: `get_inclusion_proof.v2` used to answer a pending state with this
    /// error. It now returns aggregator-go's empty-proof result (or the typed
    /// `no_finalized_view` before the first finalized block), so no method emits the code
    /// any more; clients keep handling it for older servers.
    pub const INCLUSION_PENDING: i32 = -32021;
    /// The requested state is already in the certified tree, so the requested
    /// non-inclusion relation is false.
    pub const STATE_INCLUDED: i32 = -32022;
    /// The bounded proof service has no free admission slot.
    pub const SERVER_BUSY: i32 = -32023;

    // Go-compatible codes of `get_inclusion_proofs.v1`. They fall in the
    // implementation-private range on purpose: the batch method is specified by
    // aggregator-go's wire contract, and its structured `data` carries the
    // reason and detail a client branches on.
    pub const DATABASE_ERROR: i32 = -32004;
    pub const CONCURRENCY_LIMIT: i32 = -32006;
    pub const LIMIT_EXCEEDED: i32 = -32007;
    pub const PROOF_UNAVAILABLE: i32 = -32008;

    /// A Go-compatible error with structured `data`.
    pub fn detailed(
        code: i32,
        message: &str,
        reason: &str,
        detail: &str,
        retryable: bool,
        limit: Option<usize>,
        indexes: Option<&std::collections::BTreeMap<&'static str, Vec<usize>>>,
    ) -> Self {
        let mut data = serde_json::Map::new();
        data.insert("reason".into(), reason.into());
        data.insert("detail".into(), detail.into());
        data.insert("retryable".into(), retryable.into());
        if let Some(limit) = limit {
            data.insert("limit".into(), limit.into());
        }
        if let Some(indexes) = indexes.filter(|i| !i.is_empty()) {
            data.insert("indexes".into(), serde_json::json!(indexes));
        }
        Self {
            code,
            message: message.into(),
            data: Some(serde_json::Value::Object(data)),
        }
    }
    pub fn invalid_request_detail(detail: &str) -> Self {
        Self::detailed(Self::INVALID_PARAMS, "Invalid params", "invalid_request", detail, false, None, None)
    }
    pub fn limit_exceeded(detail: &str, limit: usize) -> Self {
        Self::detailed(Self::LIMIT_EXCEEDED, "Limit exceeded", "limit_exceeded", detail, false, Some(limit), None)
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self {
            code: Self::INVALID_PARAMS,
            message: msg.into(),
            data: None,
        }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            code: Self::INTERNAL_ERROR,
            message: msg.into(),
            data: None,
        }
    }
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: Self::METHOD_NOT_FOUND,
            message: format!("method not found: {method}"),
            data: None,
        }
    }
    pub fn not_found() -> Self {
        Self {
            code: Self::NOT_FOUND,
            message: "not found".into(),
            data: None,
        }
    }
    pub fn state_included() -> Self {
        Self {
            code: Self::STATE_INCLUDED,
            message: "state is already included".into(),
            data: None,
        }
    }
    pub fn server_busy() -> Self {
        Self {
            code: Self::SERVER_BUSY,
            message: "proof service is busy".into(),
            data: None,
        }
    }
    pub fn is_not_found(&self) -> bool {
        self.code == Self::NOT_FOUND
    }
    pub fn is_server_busy(&self) -> bool {
        self.code == Self::SERVER_BUSY
    }
}

// ─── certification_request ────────────────────────────────────────────────────

/// Response for `certification_request`.
#[derive(Debug, Serialize)]
pub struct CertificationResponse {
    pub status: String,
}

impl CertificationResponse {
    pub fn success() -> Self {
        Self {
            status: "SUCCESS".into(),
        }
    }
    pub fn failure(msg: &str) -> Self {
        Self { status: msg.into() }
    }
}

// ─── get_inclusion_proof.v2 ───────────────────────────────────────────────────

/// Params for `get_inclusion_proof.v2`.
#[derive(Debug, Deserialize)]
pub struct GetInclusionProofParams {
    #[serde(rename = "stateId")]
    pub state_id: String, // hex-encoded state ID
    /// Ask for the `{proof, status}` object instead of the bare hex string.
    #[serde(rename = "includeStatus", default)]
    pub include_status: bool,
}

// ─── get_inclusion_proofs.v1 limits ───────────────────────────────────────────

/// Admission limits of `get_inclusion_proofs.v1`, identical to aggregator-go's
/// `pkg/api/inclusion_proofs.go`.
pub mod batch_limits {
    pub const MAX_STATE_IDS: usize = 256;
    pub const MAX_PARAMS_BYTES: usize = 32 << 10;
    pub const MAX_REQUEST_BYTES: usize = 64 << 10;
    pub const MAX_ID_BYTES: usize = 128;
    pub const MAX_RESPONSE_BYTES: usize = 8 << 20;
}

// ─── get_non_inclusion_proof.v1 ─────────────────────────────────────────────

/// Params for `get_non_inclusion_proof.v1`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetNonInclusionProofParams {
    #[serde(rename = "stateId")]
    pub state_id: String,
}

// ─── get_block_height ─────────────────────────────────────────────────────────

/// Response for `get_block_height`.
#[derive(Debug, Serialize)]
pub struct BlockHeightResponse {
    #[serde(rename = "blockNumber")]
    pub block_number: String, // decimal string
}
