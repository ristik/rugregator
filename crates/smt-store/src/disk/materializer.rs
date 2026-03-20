//! Materialize a partial in-memory SMT from RocksDB, guided by a batch of keys.
//!
//! Optimizations over the naive per-node approach:
//! - Routing uses `&[&SmtPath]` references (no BigUint cloning at each level)
//! - CF handle resolved once and threaded through recursion
//! - Relies on RocksDB's built-in block cache (no app-level cache layer)

use std::sync::Arc;
use num_bigint::BigUint;
use rocksdb::DB;
use rsmt::{Branch, SparseMerkleTree};
use rsmt::path::{bit_at, path_len, SmtPath};
use rsmt::node_serde::{TAG_LEAF, TAG_NODE, deserialize_leaf, deserialize_node};

use super::node_key::NodeKey;
use super::overlay::Overlay;

pub const CF_SMT_NODES: &str = "smt_nodes";

// ─── Public entry-points ──────────────────────────────────────────────────────

/// Materialize a partial SMT for a batch insertion.
pub fn materialize_for_batch(
    db:             &Arc<DB>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    batch:          &[(SmtPath, Vec<u8>)],
    key_length:     usize,
) -> anyhow::Result<SparseMerkleTree> {
    let paths: Vec<&SmtPath> = batch.iter().map(|(k, _)| k).collect();
    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    materialize_inner(db, &cf, own_overlay, parent_overlay, &paths, key_length)
}

/// Materialize a partial SMT for a single-leaf proof generation.
pub fn materialize_for_proof(
    db:             &Arc<DB>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    leaf_key:       &SmtPath,
    key_length:     usize,
) -> anyhow::Result<SparseMerkleTree> {
    let paths = [leaf_key];
    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    materialize_inner(db, &cf, own_overlay, parent_overlay, &paths, key_length)
}

/// Materialize a partial SMT covering multiple paths — for batch proof generation.
pub fn materialize_for_paths(
    db:             &Arc<DB>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    paths:          &[SmtPath],
    key_length:     usize,
) -> anyhow::Result<SparseMerkleTree> {
    let path_refs: Vec<&SmtPath> = paths.iter().collect();
    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    materialize_inner(db, &cf, own_overlay, parent_overlay, &path_refs, key_length)
}

/// Load node bytes, checking overlays → RocksDB.
pub fn load_bytes(
    db:             &Arc<DB>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             &NodeKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    load_node(db, &cf, own_overlay, parent_overlay, nk)
}

// ─── Core implementation ─────────────────────────────────────────────────────

fn materialize_inner(
    db:             &DB,
    cf:             &impl rocksdb::AsColumnFamilyRef,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    paths:          &[&SmtPath],
    key_length:     usize,
) -> anyhow::Result<SparseMerkleTree> {
    let root_nk = NodeKey::root();

    let root_bytes = match load_node(db, cf, own_overlay, parent_overlay, &root_nk)? {
        None => return Ok(SparseMerkleTree::with_key_length(key_length)),
        Some(b) => b,
    };

    let (mut root_node, has_left, has_right) = deserialize_node(&root_bytes);
    let n_path = path_len(&root_node.path);
    let split  = n_path;
    let base_acc = extract_node_prefix_bits(&root_node.path, n_path);

    root_node.left  = if has_left  { route_child(db, cf, own_overlay, parent_overlay, split, false, paths, &base_acc)? } else { None };
    root_node.right = if has_right { route_child(db, cf, own_overlay, parent_overlay, split, true,  paths, &base_acc)? } else { None };

    Ok(SparseMerkleTree { key_length, root: root_node, parent_mode: false })
}

/// Filter paths by routing bit, then materialize or load as stub.
fn route_child(
    db:             &DB,
    cf:             &impl rocksdb::AsColumnFamilyRef,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    split:          usize,
    is_right:       bool,
    paths:          &[&SmtPath],
    acc:            &BigUint,
) -> anyhow::Result<Option<Arc<Branch>>> {
    let child_paths: Vec<&SmtPath> = paths.iter()
        .filter(|p| bit_at(p, split) == (is_right as u8))
        .copied()
        .collect();

    let child_acc = if is_right {
        acc | (BigUint::from(1u8) << split)
    } else {
        acc.clone()
    };
    let child_nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

    if child_paths.is_empty() {
        return load_stub(db, cf, own_overlay, parent_overlay, child_nk);
    }

    materialize_subtree(db, cf, own_overlay, parent_overlay, child_nk, &child_paths, split, &child_acc)
}

fn materialize_subtree(
    db:             &DB,
    cf:             &impl rocksdb::AsColumnFamilyRef,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             NodeKey,
    paths:          &[&SmtPath],
    start_bit:      usize,
    acc:            &BigUint,
) -> anyhow::Result<Option<Arc<Branch>>> {
    let bytes = match load_node(db, cf, own_overlay, parent_overlay, &nk)? {
        None => return Ok(None),
        Some(b) => b,
    };

    if bytes[0] == TAG_LEAF {
        let mut leaf = deserialize_leaf(&bytes);
        if leaf.hash_cache.is_none() {
            use rsmt::tree::calc_leaf_hash;
            leaf.hash_cache = Some(calc_leaf_hash(&mut leaf));
        }
        return Ok(Some(Arc::new(Branch::Leaf(leaf))));
    }

    debug_assert_eq!(bytes[0], TAG_NODE);
    let (mut node, has_left, has_right) = deserialize_node(&bytes);
    let n_path = path_len(&node.path);

    let prefix_bits = extract_node_prefix_bits(&node.path, n_path);
    let base_acc = acc | (prefix_bits << start_bit);
    let split = start_bit + n_path;

    node.left  = if has_left  { route_child(db, cf, own_overlay, parent_overlay, split, false, paths, &base_acc)? } else { None };
    node.right = if has_right { route_child(db, cf, own_overlay, parent_overlay, split, true,  paths, &base_acc)? } else { None };

    if node.hash_cache.is_none() {
        use rsmt::tree::calc_node_hash;
        calc_node_hash(&mut node);
    }
    Ok(Some(Arc::new(Branch::Node(node))))
}

fn load_stub(
    db:             &DB,
    cf:             &impl rocksdb::AsColumnFamilyRef,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             NodeKey,
) -> anyhow::Result<Option<Arc<Branch>>> {
    let bytes = match load_node(db, cf, own_overlay, parent_overlay, &nk)? {
        None => return Ok(None),
        Some(b) => b,
    };
    let hash = extract_hash_from_bytes(&bytes)?;
    Ok(Some(Arc::new(Branch::Stub(hash))))
}

// ─── Node loading (overlay → RocksDB) ───────────────────────────────────────

fn load_node(
    db:             &DB,
    cf:             &impl rocksdb::AsColumnFamilyRef,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             &NodeKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    // 1. Own overlay.
    if let Some(opt) = own_overlay.get(nk) {
        return Ok(opt.map(|b| b.to_vec()));
    }
    // 2. Parent overlay (forked snapshots).
    if let Some(parent) = parent_overlay {
        if let Some(opt) = parent.get(nk) {
            return Ok(opt.map(|b| b.to_vec()));
        }
    }
    // 3. RocksDB (uses its built-in block cache).
    match db.get_cf(cf, nk.as_bytes())? {
        None => Ok(None),
        Some(v) => Ok(Some(v.to_vec())),
    }
}

// ─── Bit-extraction helpers ─────────────────────────────────────────────────

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
