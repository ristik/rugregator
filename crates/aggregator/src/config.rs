//! Configuration for the aggregator (CLI + env + defaults).

use clap::{Parser, ValueEnum};
use std::str::FromStr;

/// Canonical BFT Core shard bitstring, including its end marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardId(Vec<u8>);

impl ShardId {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for ShardId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hex = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);
        let bytes = hex::decode(hex).map_err(|e| format!("invalid shard ID hex: {e}"))?;
        if bytes.last().copied().unwrap_or(0) == 0 {
            return Err("shard ID must contain a final end-marker bit".into());
        }
        Ok(Self(bytes))
    }
}

/// Consistency proof mode attached to each BFT Core certification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ConsistencyProofMode {
    /// No proof attached (default).
    Off,
    /// Hash-based `aggregator_rsmt_v1` envelope — O(j·d) size.
    Rsmt,
    /// SP1 ZK proof — constant size.  Requires `--features zk`.
    Zk,
}

/// Unicity Aggregator (Rust implementation).
#[derive(Debug, Parser, Clone)]
#[command(
    name = "aggregator",
    about = "Unicity Aggregator — Rust implementation"
)]
pub struct Config {
    /// Listen address (host:port).
    #[arg(long, env = "AGGREGATOR_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: String,

    /// Round duration in milliseconds.
    #[arg(long, env = "AGGREGATOR_ROUND_DURATION_MS", default_value_t = 1000)]
    pub round_duration_ms: u64,

    /// Maximum requests per round (soft limit before forcing a new round).
    #[arg(long, env = "AGGREGATOR_BATCH_LIMIT", default_value_t = 1000)]
    pub batch_limit: usize,

    /// Default request lifetime in seconds, assigned when a certification
    /// request carries no explicit deadline. Measured in consensus reference
    /// time, so a requester that omits it needs no clock of its own.
    #[arg(
        long,
        env = "AGGREGATOR_DEFAULT_REQUEST_TTL_SECS",
        default_value_t = 3600
    )]
    pub default_request_ttl_secs: u64,

    /// BFT Core mode: "stub" (no real BFT Core) or "live".
    #[arg(long, env = "AGGREGATOR_BFT_MODE", default_value = "stub")]
    pub bft_mode: String,

    // ── Live BFT Core connectivity (used when bft_mode = "live") ─────────────
    /// BFT Core partition ID (u32).
    #[arg(long, env = "AGGREGATOR_PARTITION_ID", default_value_t = 1)]
    pub partition_id: u32,

    /// BFT Core shard ID in canonical end-marker encoding (e.g. 0x80 for the default shard).
    #[arg(long, env = "AGGREGATOR_SHARD_ID", default_value = "0x80")]
    pub shard_id: ShardId,

    /// BFT Core root node peer ID (libp2p multihash string).
    #[arg(long, env = "AGGREGATOR_BFT_PEER_ID", default_value = "")]
    pub bft_peer_id: String,

    /// BFT Core root node multiaddr (e.g. "/ip4/127.0.0.1/tcp/26652").
    #[arg(
        long,
        env = "AGGREGATOR_BFT_ADDR",
        default_value = "/ip4/127.0.0.1/tcp/26652"
    )]
    pub bft_addr: String,

    /// Our libp2p listen address.
    #[arg(
        long,
        env = "AGGREGATOR_P2P_ADDR",
        default_value = "/ip4/0.0.0.0/tcp/0"
    )]
    pub p2p_addr: String,

    /// Hex-encoded secp256k1 private key (32 bytes) for libp2p auth (PeerId).
    #[arg(long, env = "AGGREGATOR_AUTH_KEY", default_value = "")]
    pub auth_key_hex: String,

    /// Hex-encoded secp256k1 private key (32 bytes) for signing cert requests.
    #[arg(long, env = "AGGREGATOR_SIG_KEY", default_value = "")]
    pub sig_key_hex: String,

    /// Path to RocksDB data directory.  Empty string = in-memory only.
    #[arg(long, env = "AGGREGATOR_DB_PATH", default_value = "")]
    pub db_path: String,

    /// RocksDB block cache size in megabytes for the SMT nodes column family.
    /// Set to 0 to use RocksDB's default (~8 MB).
    #[arg(long, env = "AGGREGATOR_CACHE_MB", default_value_t = 0)]
    pub cache_mb: usize,

    /// Consistency proof mode sent to BFT Core with each round.
    ///
    /// - `off`  — no proof; `zk_proof` field is null (default).
    /// - `rsmt` — hash-based envelope (aggregator_rsmt_v1); O(j·d) size.
    /// - `zk`   — SP1 ZK proof; constant size.  Requires the binary to be
    ///            compiled with `--features zk`.
    #[arg(
        long,
        env = "AGGREGATOR_CONSISTENCY_PROOF_MODE",
        default_value = "off",
        value_enum
    )]
    pub consistency_proof_mode: ConsistencyProofMode,

    /// SP1 proof kind (used when consistency-proof-mode = zk).
    ///
    /// Valid values: `core`, `compressed`, `groth16`, `plonk`.
    #[arg(long, env = "AGGREGATOR_ZK_PROOF_KIND", default_value = "compressed")]
    pub zk_proof_kind: String,

    /// SMT backend selection.
    ///
    /// - `"mem"`          — pure in-memory; state lost on restart
    /// - `"mem-leaves"`   — in-memory + persist leaf values (requires `--db-path`);
    ///                      on restart replays all leaves to rebuild the tree
    /// - `"mem-leaves-x"` — like `mem-leaves`, but on graceful shutdown (SIGINT/SIGTERM)
    ///                      saves internal nodes for faster recovery on next startup
    /// - `"mem-full"`     — in-memory + persist leaves and internal nodes (requires `--db-path`);
    ///                      on restart loads the full node tree directly
    /// - `"disk"`         — fully disk-backed SMT (default when `--db-path` is set)
    ///
    /// Defaults to `"disk"` when `--db-path` is non-empty, `"mem"` otherwise.
    #[arg(long, env = "AGGREGATOR_SMT_BACKEND", default_value = "")]
    pub smt_backend: String,

    /// UC inactivity timeout in milliseconds.  If no UnicityCertificate is
    /// received within this period the aggregator re-sends the handshake to
    /// BFT Core to refresh its subscription.
    ///
    /// BFT Core sends repeat UCs every T2 interval; this timeout is a safety
    /// net for when those stop arriving (e.g. silent connection loss).  Set to
    /// at least 3× T2 so normal repeat-UC delivery is never mistaken for
    /// inactivity.
    #[arg(long, env = "AGGREGATOR_UC_TIMEOUT_MS", default_value_t = 15000)]
    pub uc_timeout_ms: u64,

    /// Use InputRecord.Hash from the last UC as PreviousHash in cert requests,
    /// instead of the aggregator's actual previous SMT root.
    ///
    /// Without this flag the aggregator sends its real previous root hash as
    /// PreviousHash, which MUST form a continuous chain with the hashes
    /// certified by BFT Core.  Enable this flag only for testing scenarios
    /// where we're too lazy to reset the BFT Core between stateless aggr. runs.
    #[arg(
        long,
        env = "AGGREGATOR_FAKE_STATE_TRANSITIONS",
        default_value_t = false
    )]
    pub fake_state_transitions: bool,

    /// Log level filter (e.g. "info", "debug", "warn").
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_level: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_id_defaults_and_accepts_distinct_bitstrings() {
        let default = Config::try_parse_from(["aggregator"]).unwrap();
        assert_eq!(default.shard_id.as_bytes(), &[0x80]);
        let left = Config::try_parse_from(["aggregator", "--shard-id", "0x40"]).unwrap();
        let right = Config::try_parse_from(["aggregator", "--shard-id", "0xc0"]).unwrap();
        assert_eq!(left.shard_id.as_bytes(), &[0x40]);
        assert_eq!(right.shard_id.as_bytes(), &[0xc0]);
    }

    #[test]
    fn shard_id_rejects_missing_or_invalid_end_marker() {
        for value in ["", "0x", "0x00", "0x8000", "0xgg", "0x8"] {
            assert!(
                Config::try_parse_from(["aggregator", "--shard-id", value]).is_err(),
                "{value}"
            );
        }
    }
}

/// Round-manager-specific config derived from `Config`.
#[derive(Debug, Clone)]
pub struct RoundConfig {
    pub round_duration_ms: u64,
    pub batch_limit: usize,
    pub proof_mode: ConsistencyProofMode,
    /// SP1 proof kind string ("core" | "compressed" | "groth16" | "plonk").
    pub zk_proof_kind: String,
}

impl From<&Config> for RoundConfig {
    fn from(c: &Config) -> Self {
        Self {
            round_duration_ms: c.round_duration_ms,
            batch_limit: c.batch_limit,
            proof_mode: c.consistency_proof_mode,
            zk_proof_kind: c.zk_proof_kind.clone(),
        }
    }
}
