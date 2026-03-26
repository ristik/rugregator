//! Materialize a partial in-memory SMT from RocksDB, guided by a batch of keys.

use std::sync::Arc;
use rocksdb::DB;
use rsmt::{Branch, SparseMerkleTree, branch_hash};
use rsmt::path::{key_bit_at, SmtKey};
use rsmt::node_serde::{TAG_LEAF, TAG_NODE, deserialize_leaf, deserialize_node};

use super::node_key::{NodeKey, PrefixBits, prefix_set_bit, prefix_copy_path};
use super::overlay::Overlay;

pub const CF_SMT_NODES: &str = "smt_nodes";

// ─── Public entry-points ──────────────────────────────────────────────────────

/// Materialize a partial SMT for a batch insertion.
pub fn materialize_for_batch(
    db:             &Arc<DB>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    batch:          &[(SmtKey, Vec<u8>)],
) -> anyhow::Result<SparseMerkleTree> {
    let keys: Vec<&SmtKey> = batch.iter().map(|(k, _)| k).collect();
    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    materialize_inner(db, &cf, own_overlay, parent_overlay, &keys)
}

/// Materialize a partial SMT for a single-leaf proof generation.
pub fn materialize_for_proof(
    db:             &Arc<DB>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    leaf_key:       &SmtKey,
) -> anyhow::Result<SparseMerkleTree> {
    let keys = [leaf_key];
    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    materialize_inner(db, &cf, own_overlay, parent_overlay, &keys)
}

/// Materialize a partial SMT covering multiple keys — for batch proof generation.
pub fn materialize_for_keys(
    db:             &Arc<DB>,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    keys:           &[SmtKey],
) -> anyhow::Result<SparseMerkleTree> {
    let key_refs: Vec<&SmtKey> = keys.iter().collect();
    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    materialize_inner(db, &cf, own_overlay, parent_overlay, &key_refs)
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
    keys:           &[&SmtKey],
) -> anyhow::Result<SparseMerkleTree> {
    let root_nk = NodeKey::root();

    let root_bytes = match load_node(db, cf, own_overlay, parent_overlay, &root_nk)? {
        None => return Ok(SparseMerkleTree::new()),
        Some(b) => b,
    };

    if root_bytes[0] == TAG_LEAF {
        let leaf = deserialize_leaf(&root_bytes);
        let mut tree = SparseMerkleTree::new();
        tree.root = Some(Arc::new(Branch::Leaf(leaf)));
        return Ok(tree);
    }

    let mut root_node = deserialize_node(&root_bytes);
    let n_path = root_node.path.path_len();
    let split = n_path;
    let mut base_acc: PrefixBits = [0u8; 32];
    prefix_copy_path(&mut base_acc, 0, &root_node.path);

    root_node.left = route_child(db, cf, own_overlay, parent_overlay, split, false, keys, &base_acc)?;
    root_node.right = route_child(db, cf, own_overlay, parent_overlay, split, true, keys, &base_acc)?;

    // Recompute hash if missing.
    if root_node.hash.is_none() {
        let lh = branch_hash(&root_node.left);
        let rh = branch_hash(&root_node.right);
        root_node.hash = Some(rsmt::hash_node(&lh, &rh, root_node.depth));
    }

    let mut tree = SparseMerkleTree::new();
    tree.root = Some(Arc::new(Branch::Node(root_node)));
    Ok(tree)
}

/// Filter keys by routing bit, then materialize or load as stub.
fn route_child(
    db:             &DB,
    cf:             &impl rocksdb::AsColumnFamilyRef,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    split:          usize,
    is_right:       bool,
    keys:           &[&SmtKey],
    acc:            &PrefixBits,
) -> anyhow::Result<Arc<Branch>> {
    let child_keys: Vec<&SmtKey> = keys.iter()
        .filter(|k| key_bit_at(k, split) == (is_right as u8))
        .copied()
        .collect();

    let mut child_acc = *acc;
    if is_right {
        prefix_set_bit(&mut child_acc, split);
    }
    let child_nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

    if child_keys.is_empty() {
        return load_stub(db, cf, own_overlay, parent_overlay, child_nk);
    }

    materialize_subtree(db, cf, own_overlay, parent_overlay, child_nk, &child_keys, split, &child_acc)
}

fn materialize_subtree(
    db:             &DB,
    cf:             &impl rocksdb::AsColumnFamilyRef,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             NodeKey,
    keys:           &[&SmtKey],
    start_bit:      usize,
    acc:            &PrefixBits,
) -> anyhow::Result<Arc<Branch>> {
    let bytes = match load_node(db, cf, own_overlay, parent_overlay, &nk)? {
        None => return Ok(Arc::new(Branch::Stub([0u8; 32]))),
        Some(b) => b,
    };

    if bytes[0] == TAG_LEAF {
        let leaf = deserialize_leaf(&bytes);
        return Ok(Arc::new(Branch::Leaf(leaf)));
    }

    debug_assert_eq!(bytes[0], TAG_NODE);
    let mut node = deserialize_node(&bytes);
    let n_path = node.path.path_len();

    let mut base_acc = *acc;
    prefix_copy_path(&mut base_acc, start_bit + 1, &node.path);
    let split = start_bit + 1 + n_path;

    node.left = route_child(db, cf, own_overlay, parent_overlay, split, false, keys, &base_acc)?;
    node.right = route_child(db, cf, own_overlay, parent_overlay, split, true, keys, &base_acc)?;

    if node.hash.is_none() {
        let lh = branch_hash(&node.left);
        let rh = branch_hash(&node.right);
        node.hash = Some(rsmt::hash_node(&lh, &rh, node.depth));
    }
    Ok(Arc::new(Branch::Node(node)))
}

fn load_stub(
    db:             &DB,
    cf:             &impl rocksdb::AsColumnFamilyRef,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             NodeKey,
) -> anyhow::Result<Arc<Branch>> {
    let bytes = match load_node(db, cf, own_overlay, parent_overlay, &nk)? {
        None => return Ok(Arc::new(Branch::Stub([0u8; 32]))),
        Some(b) => b,
    };
    let hash = extract_hash_from_bytes(&bytes)?;
    Ok(Arc::new(Branch::Stub(hash)))
}

// ─── Node loading (overlay → RocksDB) ───────────────────────────────────────

fn load_node(
    db:             &DB,
    cf:             &impl rocksdb::AsColumnFamilyRef,
    own_overlay:    &Overlay,
    parent_overlay: Option<&Overlay>,
    nk:             &NodeKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    if let Some(opt) = own_overlay.get(nk) {
        return Ok(opt.map(|b| b.to_vec()));
    }
    if let Some(parent) = parent_overlay {
        if let Some(opt) = parent.get(nk) {
            return Ok(opt.map(|b| b.to_vec()));
        }
    }
    match db.get_cf(cf, nk.as_bytes())? {
        None => Ok(None),
        Some(v) => Ok(Some(v.to_vec())),
    }
}

fn extract_hash_from_bytes(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    if bytes[0] == TAG_LEAF {
        let leaf = deserialize_leaf(bytes);
        Ok(leaf.hash)
    } else if bytes[0] == TAG_NODE {
        let node = deserialize_node(bytes);
        node.hash.ok_or_else(|| anyhow::anyhow!(
            "node has no hash — commit root hash before using as Stub"
        ))
    } else {
        anyhow::bail!("unknown node type byte 0x{:02x}", bytes[0])
    }
}
