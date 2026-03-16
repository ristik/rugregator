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
            Arc::new(BftCommitterStub)
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

    #[cfg(feature = "rocksdb-storage")]
    let (state, round_manager) = if !cfg.db_path.is_empty() {
        use uni_aggregator::storage_rocksdb::RocksDbStore;
        use uni_aggregator::smt::{SparseMerkleTree, state_id_to_smt_path};
        use uni_aggregator::validation::state_id::compute_cert_data_hash_imprint;

        info!(path = %cfg.db_path, "opening RocksDB");
        let store = Arc::new(RocksDbStore::open(&cfg.db_path)?);
        let recovered = store.recover()?;
        info!(records = recovered.records.len(), blocks = recovered.blocks.len(),
              block_number = recovered.block_number, "recovered from RocksDB");

        let mut smt = SparseMerkleTree::new();
        for (state_id_hex, record_info) in &recovered.records {
            let bytes = hex::decode(state_id_hex)?;
            let path = state_id_to_smt_path(&bytes);
            let leaf = compute_cert_data_hash_imprint(
                &record_info.cert_data.predicate_cbor,
                &record_info.cert_data.source_state_hash,
                &record_info.cert_data.transaction_hash,
                &record_info.cert_data.witness,
            );
            let _ = smt.add_leaf(path, leaf.to_vec());
        }

        let state = AggregatorState::new(req_tx, Some(store as Arc<dyn uni_aggregator::storage::Store>));
        state.apply_recovered(recovered).await;

        let rm = RoundManager::new_with_smt(round_cfg, req_rx, Arc::clone(&state), bft, smt);
        (state, rm)
    } else {
        let state = AggregatorState::new(req_tx, None);
        let rm = RoundManager::new(round_cfg, req_rx, Arc::clone(&state), bft);
        (state, rm)
    };

    #[cfg(not(feature = "rocksdb-storage"))]
    let (state, round_manager) = {
        let state = AggregatorState::new(req_tx, None);
        let rm = RoundManager::new(round_cfg, req_rx, Arc::clone(&state), bft);
        (state, rm)
    };

    tokio::spawn(async move { round_manager.run().await; });

    let router = build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    info!(listen = %cfg.listen, "HTTP server ready");
    axum::serve(listener, router).await?;

    Ok(())
}
