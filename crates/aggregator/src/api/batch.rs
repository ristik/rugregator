//! `get_inclusion_proofs.v1`: Go-compatible batch inclusion proofs for the
//! unsharded service.
//!
//! The wire is aggregator-go's (`pkg/api/inclusion_proofs.go`,
//! `docs/inclusion-proofs-batch.md`) **without** the `partitionView` field: this
//! service only serves a UC whose shard is the empty shard with no shard-tree
//! siblings, which authenticates its complete one-leaf shard tree by itself.
//! Clients consume such a response through the direct-UC path and never decode a
//! view. A UC that is not of that form is refused as `unsupported_configuration`.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use super::cbor::encode_inclusion_proof_response;
use super::types::{batch_limits as limits, JsonRpcError};
use crate::storage::{AggregatorState, BatchProofError, BusyKind, ViewSelector};

/// Decoded params of `get_inclusion_proofs.v1`.
#[derive(Debug, PartialEq, Eq)]
pub struct BatchParams {
    pub state_ids: Vec<[u8; 32]>,
    pub selector: ViewSelector,
}

// Typed parse failures travel through serde's error as "ni:<detail>" so the
// visitors can stay plain serde code.
const MARK: &str = "ni:";

fn fail<E: de::Error>(detail: &str) -> E {
    E::custom(format!("{MARK}{detail}{MARK}"))
}

fn detail_of(err: &serde_json::Error) -> String {
    let text = err.to_string();
    match text.find(MARK) {
        Some(start) => {
            let rest = &text[start + MARK.len()..];
            rest.split(MARK)
                .next()
                .unwrap_or("malformed_params")
                .to_owned()
        }
        None => "malformed_params".to_owned(),
    }
}

/// 32-byte hex with optional `0x`/`0X`, any hex case.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(s).ok()?.try_into().ok()
}

struct IdsSeed;

impl<'de> DeserializeSeed<'de> for IdsSeed {
    type Value = Vec<[u8; 32]>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<[u8; 32]>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array of state IDs")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut ids: Vec<[u8; 32]> = Vec::new();
                let mut seen = HashSet::new();
                // Counted element by element: more than the limit is rejected
                // before the vector can grow past it.
                while let Some(s) = {
                    if ids.len() == limits::MAX_STATE_IDS {
                        // Is there one more element?
                        if seq.next_element::<de::IgnoredAny>()?.is_some() {
                            return Err(fail("state_count"));
                        }
                        None
                    } else {
                        seq.next_element::<String>()?
                    }
                } {
                    let id = parse_hex32(&s).ok_or_else(|| fail("invalid_state_id"))?;
                    if !seen.insert(id) {
                        return Err(fail("duplicate_state_id"));
                    }
                    ids.push(id);
                }
                Ok(ids)
            }
        }
        d.deserialize_seq(V)
    }
}

struct ParamsVisitor;

impl<'de> Visitor<'de> for ParamsVisitor {
    type Value = BatchParams;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a params object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut ids: Option<Vec<[u8; 32]>> = None;
        let mut selector: Option<ViewSelector> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "stateIds" => {
                    if ids.is_some() {
                        return Err(fail("malformed_params"));
                    }
                    ids = Some(map.next_value_seed(IdsSeed)?);
                }
                "stateRoot" => {
                    if selector.is_some() {
                        return Err(fail("malformed_params"));
                    }
                    // null, numbers etc. are an invalid root, not a malformed object.
                    let raw: serde_json::Value = map.next_value()?;
                    let s = raw.as_str().ok_or_else(|| fail("invalid_state_root"))?;
                    selector = Some(if s == "latest" {
                        ViewSelector::Latest
                    } else if s.is_empty() || s.eq_ignore_ascii_case("latest") {
                        return Err(fail("invalid_state_root"));
                    } else {
                        ViewSelector::Root(
                            parse_hex32(s).ok_or_else(|| fail("invalid_state_root"))?,
                        )
                    });
                }
                _ => return Err(fail("malformed_params")),
            }
        }
        let state_ids = ids
            .filter(|i| !i.is_empty())
            .ok_or_else(|| fail("malformed_params"))?;
        Ok(BatchParams {
            state_ids,
            selector: selector.unwrap_or(ViewSelector::Latest),
        })
    }
}

/// Strictly decode the params object: no unknown or duplicate fields, 1..=256
/// distinct 32-byte IDs, `stateRoot` omitted/`"latest"`/64 hex digits.
pub fn parse_params(raw: &str) -> Result<BatchParams, JsonRpcError> {
    if raw.len() > limits::MAX_PARAMS_BYTES {
        return Err(JsonRpcError::limit_exceeded(
            "request_bytes",
            limits::MAX_PARAMS_BYTES,
        ));
    }
    let mut de = serde_json::Deserializer::from_str(raw);
    let parsed = de.deserialize_map(ParamsVisitor).and_then(|p| {
        de.end()?; // trailing data
        Ok(p)
    });
    parsed.map_err(|e| {
        let detail = detail_of(&e);
        if detail == "state_count" {
            JsonRpcError::limit_exceeded("state_count", limits::MAX_STATE_IDS)
        } else {
            JsonRpcError::invalid_request_detail(&detail)
        }
    })
}

/// Map a storage failure to the Go-compatible error.
fn map_error(err: BatchProofError) -> JsonRpcError {
    use JsonRpcError as E;
    let unavailable = |detail: &str, retryable: bool| {
        E::detailed(
            E::PROOF_UNAVAILABLE,
            "Proof unavailable",
            "proof_unavailable",
            detail,
            retryable,
            None,
            None,
        )
    };
    match err {
        BatchProofError::NoFinalizedView => unavailable("no_finalized_view", true),
        BatchProofError::ViewNotRetained => unavailable("view_not_retained", true),
        BatchProofError::UnsupportedConfiguration => {
            unavailable("unsupported_configuration", false)
        }
        BatchProofError::Busy(kind) => {
            let detail = match kind {
                BusyKind::ActiveRequests => "active_requests",
                BusyKind::PinnedViews => "pinned_views",
                BusyKind::Deadline => "deadline",
            };
            E::detailed(
                E::CONCURRENCY_LIMIT,
                "Concurrency limit exceeded",
                "busy",
                detail,
                true,
                None,
                None,
            )
        }
        BatchProofError::Absent(a) => E::detailed(
            E::PROOF_UNAVAILABLE,
            "Proof unavailable",
            "proof_unavailable",
            a.detail,
            a.retryable,
            None,
            Some(&a.indexes),
        ),
        BatchProofError::Internal(e) => {
            // Never expose storage text.
            tracing::error!(err = %e, "get_inclusion_proofs.v1 failed");
            E {
                code: E::DATABASE_ERROR,
                message: "Database error".into(),
                data: None,
            }
        }
    }
}

/// Handle `get_inclusion_proofs.v1`. Returns the serialized `result` JSON
/// (`{"proofs":[...]}`), built element by element so the response never exceeds
/// `max_result_bytes`: an over-limit batch fails with `response_bytes` after at
/// most one element beyond the limit has been encoded.
pub async fn handle_get_inclusion_proofs_v1(
    raw_params: &str,
    max_result_bytes: usize,
    state: Arc<AggregatorState>,
) -> Result<String, JsonRpcError> {
    let params = parse_params(raw_params)?;
    let batch = state
        .get_inclusion_proofs_batch(&params.state_ids, params.selector)
        .await
        .map_err(map_error)?;

    let mut out = String::from(r#"{"proofs":["#);
    for (i, item) in batch.items.iter().enumerate() {
        let hex_cbor = encode_inclusion_proof_response(
            batch.block_number,
            Some(&item.cert_data),
            Some(item.reference_time),
            &item.merkle_path_cbor,
            &batch.uc_cbor,
        )
        .map_err(|e| {
            tracing::error!(err = %e, "get_inclusion_proofs.v1 encoding failed");
            JsonRpcError {
                code: JsonRpcError::DATABASE_ERROR,
                message: "Database error".into(),
                data: None,
            }
        })?;
        // element + quotes + comma, plus the closing "]}".
        if out.len() + hex_cbor.len() + 3 + 2 > max_result_bytes {
            return Err(JsonRpcError::limit_exceeded(
                "response_bytes",
                limits::MAX_RESPONSE_BYTES,
            ));
        }
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&hex_cbor);
        out.push('"');
    }
    out.push_str("]}");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::batch_limits;
    use serde_json::json;

    fn id(b: u8) -> String {
        hex::encode([b; 32])
    }

    fn detail(raw: &str) -> (i32, String) {
        let e = parse_params(raw).unwrap_err();
        let d = e.data.unwrap();
        (e.code, d["detail"].as_str().unwrap().to_owned())
    }

    #[test]
    fn parses_ids_in_order_with_optional_prefix_and_any_case() {
        let upper = id(0xab).to_uppercase();
        let raw = json!({"stateIds": [id(1), format!("0x{}", id(2)), upper]}).to_string();
        let p = parse_params(&raw).unwrap();
        assert_eq!(p.state_ids, vec![[1; 32], [2; 32], [0xab; 32]]);
        assert_eq!(p.selector, ViewSelector::Latest, "omitted selects latest");
    }

    #[test]
    fn selects_latest_or_an_exact_root_and_rejects_everything_else() {
        let ok = |root: serde_json::Value| {
            parse_params(&json!({"stateIds": [id(1)], "stateRoot": root}).to_string())
        };
        assert_eq!(ok(json!("latest")).unwrap().selector, ViewSelector::Latest);
        assert_eq!(
            ok(json!(id(9))).unwrap().selector,
            ViewSelector::Root([9; 32])
        );
        assert_eq!(
            ok(json!(format!("0X{}", id(9).to_uppercase())))
                .unwrap()
                .selector,
            ViewSelector::Root([9; 32])
        );
        for bad in [
            json!(null),
            json!(""),
            json!("LATEST"),
            json!("Latest"),
            json!("tip"),
            json!(7),
            json!("ab"),
            json!(format!("{}00", id(9))),
        ] {
            let raw = json!({"stateIds": [id(1)], "stateRoot": bad}).to_string();
            assert_eq!(detail(&raw), (-32602, "invalid_state_root".into()), "{bad}");
        }
    }

    #[test]
    fn rejects_malformed_params_with_the_go_details() {
        let m = (-32602, "malformed_params".to_string());
        assert_eq!(detail("[]"), m);
        assert_eq!(detail("null"), m);
        assert_eq!(detail("\"x\""), m);
        assert_eq!(detail("{}"), m, "stateIds is required");
        assert_eq!(detail(r#"{"stateIds":[]}"#), m, "1..256");
        assert_eq!(detail(r#"{"stateIds":null}"#), m);
        assert_eq!(detail(r#"{"stateIds":"x"}"#), m);
        assert_eq!(
            detail(&json!({"stateIds":[1]}).to_string()),
            m,
            "entries are strings"
        );
        // Unknown and duplicate fields, trailing data.
        assert_eq!(detail(&json!({"stateIds":[id(1)],"x":1}).to_string()), m);
        assert_eq!(
            detail(&format!(
                r#"{{"stateIds":["{0}"],"stateIds":["{0}"]}}"#,
                id(1)
            )),
            m
        );
        assert_eq!(
            detail(&format!(
                r#"{{"stateIds":["{0}"],"stateRoot":"latest","stateRoot":"latest"}}"#,
                id(1)
            )),
            m
        );
        assert_eq!(detail(&format!(r#"{{"stateIds":["{}"]}} x"#, id(1))), m);
        assert_eq!(detail(&format!(r#"{{"stateIds":["{}"]}}{{}}"#, id(1))), m);
    }

    #[test]
    fn rejects_invalid_and_duplicate_state_ids() {
        let bad = |s: String| detail(&json!({"stateIds":[s]}).to_string());
        let inv = (-32602, "invalid_state_id".to_string());
        assert_eq!(bad("zz".repeat(32)), inv);
        assert_eq!(bad("ab".repeat(31)), inv);
        assert_eq!(bad("ab".repeat(33)), inv);
        assert_eq!(bad(String::new()), inv);
        // Duplicates are decided on decoded bytes, so aliases collide.
        let raw =
            json!({"stateIds":[id(0xab), format!("0x{}", id(0xab).to_uppercase())]}).to_string();
        assert_eq!(detail(&raw), (-32602, "duplicate_state_id".into()));
    }

    #[test]
    fn enforces_the_count_and_params_size_limits() {
        let ids = |k: usize| -> Vec<String> {
            (0..k)
                .map(|i| {
                    let mut b = [0u8; 32];
                    b[..2].copy_from_slice(&(i as u16).to_be_bytes());
                    hex::encode(b)
                })
                .collect()
        };
        let n = |k: usize| json!({ "stateIds": ids(k) }).to_string();
        assert_eq!(parse_params(&n(256)).unwrap().state_ids.len(), 256);
        let e = parse_params(&n(257)).unwrap_err();
        assert_eq!(e.code, -32007);
        let d = e.data.unwrap();
        assert_eq!(
            (
                d["reason"].as_str(),
                d["detail"].as_str(),
                d["limit"].as_u64()
            ),
            (Some("limit_exceeded"), Some("state_count"), Some(256))
        );
        assert_eq!(d["retryable"], json!(false));

        // The count is decided before decoding the rest: junk after the 257th
        // element is never inspected.
        let raw = format!(
            r#"{{"stateIds":[{},"zz"]}}"#,
            ids(256)
                .iter()
                .map(|i| format!("\"{i}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(parse_params(&raw).unwrap_err().code, -32007);

        let big = format!(
            r#"{{"stateIds":["{}"],"pad":"{}"}}"#,
            id(1),
            "a".repeat(batch_limits::MAX_PARAMS_BYTES)
        );
        let e = parse_params(&big).unwrap_err();
        assert_eq!(e.code, -32007);
        assert_eq!(e.data.unwrap()["detail"], json!("request_bytes"));
    }
}
