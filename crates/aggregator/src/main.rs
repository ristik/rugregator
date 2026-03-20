//! Aggregator entry point.

use std::sync::Arc;
use clap::Parser;
use tokio::sync::mpsc;
use tracing::info;

use uni_aggregator::{
    api::build_router,
    config::{Config, RoundConfig},
    round::{BftCommitter, BftCommitterStub, LiveBftCommitter, LiveBftConfig, RoundManager},
    storage::AggregatorState,
};
use smt_store::SmtStore as _;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&cfg.log_level)
        .init();

    info!("Unicity Aggregator starting (Rust)");
    info!(listen = %cfg.listen, round_ms = cfg.round_duration_ms, batch = cfg.batch_limit, mode = %cfg.bft_mode);

    let (req_tx, req_rx) = mpsc::channel(10_000);

    let bft: Arc<dyn BftCommitter> = match cfg.bft_mode.as_str() {
        "stub" | "test" => {
            info!("BFT mode: stub");
            Arc::new(BftCommitterStub::new())
        }
        "live" => {
            info!("BFT mode: live — connecting to BFT Core");
            let peer_id: libp2p::PeerId = cfg.bft_peer_id.parse()
                .map_err(|e| anyhow::anyhow!("invalid bft_peer_id '{}': {e}", cfg.bft_peer_id))?;
            let bft_addr: libp2p::Multiaddr = cfg.bft_addr.parse()
                .map_err(|e| anyhow::anyhow!("invalid bft_addr '{}': {e}", cfg.bft_addr))?;
            let p2p_addr: libp2p::Multiaddr = cfg.p2p_addr.parse()
                .map_err(|e| anyhow::anyhow!("invalid p2p_addr '{}': {e}", cfg.p2p_addr))?;
            let auth_key = hex::decode(&cfg.auth_key_hex)
                .map_err(|e| anyhow::anyhow!("invalid auth_key_hex: {e}"))?;
            let sig_key = hex::decode(&cfg.sig_key_hex)
                .map_err(|e| anyhow::anyhow!("invalid sig_key_hex: {e}"))?;

            let live_cfg = LiveBftConfig {
                partition_id: cfg.partition_id,
                bft_peer_id: peer_id,
                bft_addr,
                listen_addr: p2p_addr,
                auth_key_bytes: auth_key,
                sig_key_bytes: sig_key,
            };
            Arc::new(LiveBftCommitter::start(live_cfg)?)
        }
        other => anyhow::bail!("unknown bft_mode: {other} (supported: stub, live)"),
    };

    let round_cfg = RoundConfig::from(&cfg);

    // Resolve the effective backend: default to "disk" when a DB path is set,
    // "mem" when no DB path is provided.
    let smt_backend = if cfg.smt_backend.is_empty() {
        if cfg.db_path.is_empty() { "mem" } else { "disk" }
    } else {
        cfg.smt_backend.as_str()
    };

    // Backends that require a DB path.
    if matches!(smt_backend, "disk" | "mem-leaves" | "mem-full") && cfg.db_path.is_empty() {
        anyhow::bail!("smt-backend '{}' requires --db-path to be set", smt_backend);
    }

    let state = if cfg.db_path.is_empty() {
        // Pure in-memory, no DB.
        let state = AggregatorState::new(req_tx, None);
        let rm = RoundManager::new(round_cfg, req_rx, Arc::clone(&state), bft);
        tokio::spawn(async move { rm.run().await; });
        state
    } else {
        use uni_aggregator::storage_rocksdb::RocksDbStore;
        use smt_store::{DiskSmt, MemSmt};
        use smt_store::mem::PersistMode;

        info!(path = %cfg.db_path, "opening RocksDB");
        let (store, arc_db) = RocksDbStore::open(&cfg.db_path)?;
        let store = Arc::new(store);

        let recovered = store.recover()?;
        info!(records = recovered.records.len(), blocks = recovered.blocks.len(),
              block_number = recovered.block_number, "recovered from RocksDB");

        let state = AggregatorState::new(req_tx, Some(store as Arc<dyn uni_aggregator::storage::Store>));
        state.apply_recovered(recovered).await;

        match smt_backend {
            "disk" => {
                let disk_smt = DiskSmt::open(arc_db, cfg.cache_capacity)?;
                info!(root = %hex::encode(disk_smt.root_hash_imprint()), "disk-backed SMT ready");
                let rm = RoundManager::new_with_disk_smt(round_cfg, req_rx, Arc::clone(&state), bft, disk_smt);
                tokio::spawn(async move { rm.run().await; });
            }
            "mem-leaves" => {
                let mem_smt = MemSmt::open(arc_db, PersistMode::LeavesOnly)?;
                info!(root = %hex::encode(mem_smt.root_hash_imprint()), "in-memory SMT (leaves-only) ready");
                let rm = RoundManager::with_smt(round_cfg, req_rx, Arc::clone(&state), bft, mem_smt);
                tokio::spawn(async move { rm.run().await; });
            }
            "mem-full" => {
                let mem_smt = MemSmt::open(arc_db, PersistMode::Full)?;
                info!(root = %hex::encode(mem_smt.root_hash_imprint()), "in-memory SMT (full-nodes) ready");
                let rm = RoundManager::with_smt(round_cfg, req_rx, Arc::clone(&state), bft, mem_smt);
                tokio::spawn(async move { rm.run().await; });
            }
            "mem" => {
                let mem_smt = MemSmt::open(arc_db, PersistMode::None)?;
                info!("in-memory SMT (no persistence) with DB ready");
                let rm = RoundManager::with_smt(round_cfg, req_rx, Arc::clone(&state), bft, mem_smt);
                tokio::spawn(async move { rm.run().await; });
            }
            other => anyhow::bail!("unknown smt-backend: '{other}' (supported: disk, mem, mem-leaves, mem-full)"),
        }

        state
    };

    let router = build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    info!(listen = %cfg.listen, "HTTP server ready");
    axum::serve(listener, router).await?;

    Ok(())
}
