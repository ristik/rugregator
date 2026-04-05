//! Emit cross-language fixtures for the aggregator_rsmt_v1 envelope format.
//!
//! Usage:
//!     cargo run --example dump_envelope_fixtures -- <out_dir>
//!
//! Writes `fixtures.json` into `<out_dir>` (directory must already exist).
//! The Go verifier loads this file from
//! `bft-core/rootchain/consensus/zkverifier/rsmt/testdata/fixtures.json` to
//! keep both implementations in lockstep.
//!
//! Each fixture captures the inputs to a successful `Verify` call:
//!   - `prev_root`: hex-encoded previous root, or empty string for nil.
//!   - `new_root` : hex-encoded new root (empty string means nil tree).
//!   - `envelope` : hex-encoded `aggregator_rsmt_v1` wire payload.

use rsmt::consistency::{batch_insert_with_proof, encode_aggregator_envelope_v1};
use rsmt::path::SmtKey;
use rsmt::tree::SparseMerkleTree;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn opt_hex(h: Option<[u8; 32]>) -> String {
    match h {
        Some(x) => hex(&x),
        None => String::new(),
    }
}

fn mk_key(prefix: u8, tag: u8) -> SmtKey {
    let mut k = [0u8; 32];
    k[0] = prefix;
    k[31] = tag;
    k
}

struct Fixture {
    name: &'static str,
    prev_root: String,
    new_root: String,
    envelope: String,
}

fn scenario_empty() -> Fixture {
    // Empty batch against an empty tree: envelope has zero leaves and zero
    // opcodes; prev == new == nil.
    let envelope = encode_aggregator_envelope_v1(&[], &vec![]);
    Fixture {
        name: "empty_batch_empty_tree",
        prev_root: String::new(),
        new_root: String::new(),
        envelope: hex(&envelope),
    }
}

fn scenario_single_leaf() -> Fixture {
    let mut tree = SparseMerkleTree::new();
    let k = mk_key(0x05, 0x00);
    let v = b"hello".to_vec();
    let (pairs, proof) = batch_insert_with_proof(&mut tree, &[(k, v)]).unwrap();
    let envelope = encode_aggregator_envelope_v1(&pairs, &proof);
    Fixture {
        name: "single_leaf_into_empty",
        prev_root: String::new(),
        new_root: opt_hex(tree.root_hash()),
        envelope: hex(&envelope),
    }
}

fn scenario_two_leaves() -> Fixture {
    let mut tree = SparseMerkleTree::new();
    // Two keys that diverge early: byte 0 = 0x00 vs 0x80 (differ in MSB, bit 7).
    let k0 = mk_key(0x00, 0x01);
    let k1 = mk_key(0x80, 0x02);
    let (pairs, proof) = batch_insert_with_proof(
        &mut tree,
        &[(k0, b"v0".to_vec()), (k1, b"v1".to_vec())],
    )
    .unwrap();
    let envelope = encode_aggregator_envelope_v1(&pairs, &proof);
    Fixture {
        name: "two_leaves_into_empty",
        prev_root: String::new(),
        new_root: opt_hex(tree.root_hash()),
        envelope: hex(&envelope),
    }
}

fn scenario_insert_into_existing() -> Fixture {
    // Build a 3-leaf tree, then insert 2 more leaves in a second batch.
    let mut tree = SparseMerkleTree::new();
    let seed = [
        (mk_key(0x10, 0x01), b"a".to_vec()),
        (mk_key(0x20, 0x02), b"b".to_vec()),
        (mk_key(0x30, 0x03), b"c".to_vec()),
    ];
    batch_insert_with_proof(&mut tree, &seed).unwrap();
    let prev = tree.root_hash();

    let new_batch = [
        (mk_key(0x40, 0x04), b"d".to_vec()),
        (mk_key(0x50, 0x05), b"e".to_vec()),
    ];
    let (pairs, proof) = batch_insert_with_proof(&mut tree, &new_batch).unwrap();
    let envelope = encode_aggregator_envelope_v1(&pairs, &proof);
    Fixture {
        name: "insert_into_existing",
        prev_root: opt_hex(prev),
        new_root: opt_hex(tree.root_hash()),
        envelope: hex(&envelope),
    }
}

fn scenario_large_batch() -> Fixture {
    // Insert 50 leaves into an empty tree to exercise multi-level trees.
    let mut tree = SparseMerkleTree::new();
    let mut batch = Vec::new();
    for i in 0u8..50 {
        let mut k = [0u8; 32];
        k[0] = i.wrapping_mul(17);
        k[15] = i;
        k[31] = 0xAA;
        batch.push((k, vec![i, i ^ 0x55, i.wrapping_add(1)]));
    }
    let (pairs, proof) = batch_insert_with_proof(&mut tree, &batch).unwrap();
    let envelope = encode_aggregator_envelope_v1(&pairs, &proof);
    Fixture {
        name: "fifty_leaves_into_empty",
        prev_root: String::new(),
        new_root: opt_hex(tree.root_hash()),
        envelope: hex(&envelope),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: dump_envelope_fixtures <out_dir>");
        std::process::exit(2);
    }
    let out_dir = std::path::PathBuf::from(&args[1]);

    let fixtures = [
        scenario_empty(),
        scenario_single_leaf(),
        scenario_two_leaves(),
        scenario_insert_into_existing(),
        scenario_large_batch(),
    ];

    // Hand-rolled JSON to avoid a serde_json dev-dep.
    let mut s = String::new();
    s.push_str("{\n  \"fixtures\": [\n");
    for (i, f) in fixtures.iter().enumerate() {
        s.push_str("    {\n");
        s.push_str(&format!("      \"name\": \"{}\",\n", f.name));
        s.push_str(&format!("      \"prev_root\": \"{}\",\n", f.prev_root));
        s.push_str(&format!("      \"new_root\": \"{}\",\n", f.new_root));
        s.push_str(&format!("      \"envelope\": \"{}\"\n", f.envelope));
        s.push_str(if i + 1 == fixtures.len() { "    }\n" } else { "    },\n" });
    }
    s.push_str("  ]\n}\n");

    let out = out_dir.join("fixtures.json");
    std::fs::write(&out, s).expect("write fixtures.json");
    println!("wrote {}", out.display());
}
