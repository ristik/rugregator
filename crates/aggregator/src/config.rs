//! Configuration for the aggregator (CLI + env + defaults).

use clap::Parser;

/// Unicity Aggregator (Rust implementation).
#[derive(Debug, Parser, Clone)]
#[command(name = "aggregator", about = "Unicity Aggregator — Rust implementation")]
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

    /// BFT Core mode: "stub" (no real BFT Core) or "live".
    #[arg(long, env = "AGGREGATOR_BFT_MODE", default_value = "stub")]
    pub bft_mode: String,

    // ── Live BFT Core connectivity (used when bft_mode = "live") ─────────────

    /// BFT Core partition ID (u32).
    #[arg(long, env = "AGGREGATOR_PARTITION_ID", default_value_t = 1)]
    pub partition_id: u32,

    /// BFT Core root node peer ID (libp2p multihash string).
    #[arg(long, env = "AGGREGATOR_BFT_PEER_ID", default_value = "")]
    pub bft_peer_id: String,

    /// BFT Core root node multiaddr (e.g. "/ip4/127.0.0.1/tcp/26652").
    #[arg(long, env = "AGGREGATOR_BFT_ADDR", default_value = "/ip4/127.0.0.1/tcp/26652")]
    pub bft_addr: String,

    /// Our libp2p listen address.
    #[arg(long, env = "AGGREGATOR_P2P_ADDR", default_value = "/ip4/0.0.0.0/tcp/0")]
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

    /// Disk-backed SMT node cache capacity (number of nodes).
    #[arg(long, env = "AGGREGATOR_CACHE_CAPACITY", default_value_t = 500_000)]
    pub cache_capacity: usize,

    /// Log level filter (e.g. "info", "debug", "warn").
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    pub log_level: String,
}

/// Round-manager-specific config derived from `Config`.
#[derive(Debug, Clone)]
pub struct RoundConfig {
    pub round_duration_ms: u64,
    pub batch_limit: usize,
}

impl From<&Config> for RoundConfig {
    fn from(c: &Config) -> Self {
        Self {
            round_duration_ms: c.round_duration_ms,
            batch_limit: c.batch_limit,
        }
    }
}
