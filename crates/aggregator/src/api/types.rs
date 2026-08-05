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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl JsonRpcError {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    /// Application-level "not found" — maps to HTTP 404.
    pub const NOT_FOUND: i32 = -32001;
    /// The requested state is already in the certified tree, so the requested
    /// non-inclusion relation is false.
    pub const STATE_INCLUDED: i32 = -32002;
    /// A known certification request has not reached a certified block yet.
    pub const INCLUSION_PENDING: i32 = -32003;
    /// The bounded proof service has no free admission slot.
    pub const SERVER_BUSY: i32 = -32004;

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
    pub fn inclusion_pending() -> Self {
        Self {
            code: Self::INCLUSION_PENDING,
            message: "certification is pending".into(),
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
