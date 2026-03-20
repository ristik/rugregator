//! Materialize a partial in-memory SMT from RocksDB, guided by a batch of keys.

use std::sync::{Arc, Mutex};
use num_bigint::BigUint;
use rocksdb::DB;
use rsmt::{Branch, SparseMerkleTree};
use rsmt::path::{bit_at, path_len, SmtPath};
use rsmt::node_serde::{TAG_LEAF, TAG_NODE, deserialize_leaf, deserialize_node};

use super::node_key::NodeKey;
use super::overlay::Overlay;
use super::cache::NodeCache;

pub const CF_SMT_NODES: &str = "smt_nodes";

// ─── Public entry-points ──────────────────────────────────────────────────────

/// Materialize a partial SMT for a batch insertion.
pub fn materialize_for_batch(
    db:             &Arc<DB>,
    cache:          &Arc<Mutex<NodeCache>>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    batch:          &[(SmtPath, Vec<u8>)],
    key_length:     usize,
) -> anyhow::Result<(SparseMerkleTree, Vec<NodeKey>)> {
    let root_nk = NodeKey::root();
    let mut visited = Vec::new();

    let root_bytes = match load_bytes(db, cache, own_overlay, parent_overlay, &root_nk)? {
        None => {
            return Ok((SparseMerkleTree::with_key_length(key_length), vec![]));
        }
        Some(b) => b,
    };
    visited.push(root_nk);

    let (mut root_node, has_left, has_right) = deserialize_node(&root_bytes);
    let n_path = path_len(&root_node.path);
    let split  = n_path;

    let root_prefix_bits = extract_node_prefix_bits(&root_node.path, n_path);
    let base_acc = root_prefix_bits.clone();

    root_node.left  = if has_left  { materialize_at_split(db, cache, own_overlay, parent_overlay, split, false, batch, &base_acc, &mut visited)? } else { None };
    root_node.right = if has_right { materialize_at_split(db, cache, own_overlay, parent_overlay, split, true,  batch, &base_acc, &mut visited)? } else { None };

    let smt = SparseMerkleTree { key_length, root: root_node, parent_mode: false };
    Ok((smt, visited))
}

/// Materialize a partial SMT for a single-leaf proof generation.
pub fn materialize_for_proof(
    db:             &Arc<DB>,
    cache:          &Arc<Mutex<NodeCache>>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    leaf_key:       &SmtPath,
    key_length:     usize,
) -> anyhow::Result<SparseMerkleTree> {
    let batch = vec![(leaf_key.clone(), vec![])];
    let (smt, _) = materialize_for_batch(db, cache, own_overlay, parent_overlay, &batch, key_length)?;
    Ok(smt)
}

// ─── Core recursive materializer ──────────────────────────────────────────────

fn materialize_at_split(
    db:             &Arc<DB>,
    cache:          &Arc<Mutex<NodeCache>>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    split:          usize,
    is_right:       bool,
    batch:          &[(SmtPath, Vec<u8>)],
    acc:            &BigUint,
    visited:        &mut Vec<NodeKey>,
) -> anyhow::Result<Option<std::sync::Arc<rsmt::Branch>>> {
    let child_batch: Vec<_> = batch.iter()
        .filter(|(k, _)| bit_at(k, split) == (is_right as u8))
        .cloned()
        .collect();

    let child_acc = if is_right {
        acc | (BigUint::from(1u8) << split)
    } else {
        acc.clone()
    };
    let child_nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

    if child_batch.is_empty() {
        return load_as_stub(db, cache, own_overlay, parent_overlay, child_nk);
    }

    materialize_subtree(db, cache, own_overlay, parent_overlay, child_nk, &child_batch, split, &child_acc, visited)
}

fn materialize_subtree(
    db:             &Arc<DB>,
    cache:          &Arc<Mutex<NodeCache>>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             NodeKey,
    batch:          &[(SmtPath, Vec<u8>)],
    start_bit:      usize,
    acc:            &BigUint,
    visited:        &mut Vec<NodeKey>,
) -> anyhow::Result<Option<std::sync::Arc<rsmt::Branch>>> {
    let bytes = match load_bytes(db, cache, own_overlay, parent_overlay, &nk)? {
        None => return Ok(None),
        Some(b) => b,
    };
    visited.push(nk);

    if bytes[0] == TAG_LEAF {
        let mut leaf_br = deserialize_leaf(&bytes);
        if leaf_br.hash_cache.is_none() {
            use rsmt::tree::calc_leaf_hash;
            leaf_br.hash_cache = Some(calc_leaf_hash(&mut leaf_br));
        }
        return Ok(Some(std::sync::Arc::new(Branch::Leaf(leaf_br))));
    }

    debug_assert_eq!(bytes[0], TAG_NODE);
    let (mut node, has_left, has_right) = deserialize_node(&bytes);
    let n_path = path_len(&node.path);

    let prefix_bits = extract_node_prefix_bits(&node.path, n_path);
    let base_acc = acc | (prefix_bits << start_bit);
    let split = start_bit + n_path;

    node.left  = if has_left  { materialize_at_split(db, cache, own_overlay, parent_overlay, split, false, batch, &base_acc, visited)? } else { None };
    node.right = if has_right { materialize_at_split(db, cache, own_overlay, parent_overlay, split, true,  batch, &base_acc, visited)? } else { None };

    if node.hash_cache.is_none() {
        use rsmt::tree::calc_node_hash;
        calc_node_hash(&mut node);
    }
    Ok(Some(std::sync::Arc::new(Branch::Node(node))))
}

fn load_as_stub(
    db:             &Arc<DB>,
    cache:          &Arc<Mutex<NodeCache>>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             NodeKey,
) -> anyhow::Result<Option<std::sync::Arc<rsmt::Branch>>> {
    let bytes = match load_bytes(db, cache, own_overlay, parent_overlay, &nk)? {
        None => return Ok(None),
        Some(b) => b,
    };
    let hash = extract_hash_from_bytes(&bytes)?;
    Ok(Some(std::sync::Arc::new(Branch::Stub(hash))))
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

/// Load node bytes, checking overlays before cache/DB.
pub fn load_bytes(
    db:             &Arc<DB>,
    cache:          &Arc<Mutex<NodeCache>>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             &NodeKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    // 1. Own overlay first.
    if let Some(opt) = own_overlay.get(nk) {
        return Ok(opt.map(|b| b.to_vec()));
    }
    // 2. Parent overlay (for forked/speculative snapshots).
    if let Some(parent) = parent_overlay {
        if let Some(opt) = parent.get(nk) {
            return Ok(opt.map(|b| b.to_vec()));
        }
    }
    // 3. Cache.
    {
        let mut c = cache.lock().unwrap();
        if let Some(bytes) = c.get(nk) {
            return Ok(Some(bytes.clone()));
        }
    }
    // 4. RocksDB.
    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    match db.get_cf(&cf, nk.as_bytes())? {
        None => Ok(None),
        Some(v) => {
            let bytes = v.to_vec();
            cache.lock().unwrap().put(nk.clone(), bytes.clone());
            Ok(Some(bytes))
        }
    }
}

// ─── Bit-extraction helpers ───────────────────────────────────────────────────

pub fn extract_node_prefix_bits(path: &SmtPath, n_common: usize) -> BigUint {
    if n_common == 0 {
        return BigUint::ZERO;
    }
    let mask = (BigUint::from(1u8) << n_common) - BigUint::from(1u8);
    path & &mask
}

fn extract_hash_from_bytes(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    if bytes[0] == TAG_LEAF {
        let leaf = deserialize_leaf(bytes);
        leaf.hash_cache.ok_or_else(|| anyhow::anyhow!(
            "leaf has no hash_cache — commit root hash before using as Stub"
        ))
    } else if bytes[0] == TAG_NODE {
        let (node, _, _) = deserialize_node(bytes);
        node.hash_cache.ok_or_else(|| anyhow::anyhow!(
            "node has no hash_cache — commit root hash before using as Stub"
        ))
    } else {
        anyhow::bail!("unknown node type byte 0x{:02x}", bytes[0])
    }
}
