//! Prints the stub BFT mode's explicit test trust anchor, or a deterministic
//! fixture of stub certificates for cross-implementation verification.
//!
//! ```text
//! stub-anchor trust-base [--partition-id N]   # RootTrustBase JSON (SDK shape)
//! stub-anchor fixture    [--partition-id N]   # trust base + certificates + expectations
//! ```
//!
//! The anchor is test-only (its private key is a published constant).

use uni_aggregator::round::stub_uc::{self, StubUcParams};

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let mut partition_id = stub_uc::DEFAULT_PARTITION_ID;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--partition-id" => {
                partition_id = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|v| *v != 0)
                    .unwrap_or_else(|| usage("--partition-id needs a positive integer"));
            }
            _ => usage(&format!("unknown argument {a}")),
        }
    }
    match cmd.as_str() {
        "trust-base" => println!(
            "{}",
            serde_json::to_string_pretty(&stub_uc::trust_base_json()).unwrap()
        ),
        "fixture" => println!(
            "{}",
            serde_json::to_string_pretty(&fixture(partition_id)).unwrap()
        ),
        _ => usage("expected `trust-base` or `fixture`"),
    }
}

fn usage(msg: &str) -> ! {
    eprintln!("{msg}\nusage: stub-anchor (trust-base|fixture) [--partition-id N]");
    std::process::exit(2);
}

/// Blocks covering a first block, a changed state, an unchanged state (no
/// block hash) and the empty tree (empty state hash) on both sides.
fn fixture(partition_id: u32) -> serde_json::Value {
    let roots: [Option<[u8; 32]>; 6] = [
        Some([0xA1; 32]),
        Some([0xB2; 32]),
        Some([0xB2; 32]),
        None,
        None,
        Some([0xC3; 32]),
    ];
    let mut ucs = Vec::new();
    let mut prev: Option<[u8; 32]> = None;
    let mut prev_seal: Option<[u8; 32]> = None;
    for (i, root) in roots.iter().enumerate() {
        let block_number = i as u64 + 1;
        let uc = stub_uc::generate(&StubUcParams {
            partition_id,
            block_number,
            prev_root: prev.as_ref(),
            new_root: root.as_ref(),
            reference_time: 1_755_000_000 + i as u64,
            seal_timestamp: 1_755_000_001 + i as u64,
            prev_seal_hash: prev_seal.as_ref(),
        });
        ucs.push(serde_json::json!({
            "blockNumber": block_number,
            "stateRoot": root.map(hex::encode),
            "previousStateRoot": prev.map(hex::encode),
            "referenceTime": 1_755_000_000 + i as u64,
            "unicityCertificate": hex::encode(&uc.cbor),
        }));
        prev = *root;
        prev_seal = Some(uc.seal_hash);
    }
    serde_json::json!({
        "partitionId": partition_id,
        "shardId": "",
        "shardConfHash": hex::encode(stub_uc::shard_conf_hash(partition_id)),
        "trustBase": stub_uc::trust_base_json(),
        "certificates": ucs,
    })
}
