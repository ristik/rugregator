//! Materialize a partial in-memory SMT from RocksDB, guided by a batch of keys.

use rocksdb::{Snapshot, DB};
use rsmt::node_serde::{deserialize_leaf, deserialize_node, TAG_LEAF, TAG_NODE};
use rsmt::path::{key_bit_at, SmtKey};
use rsmt::{branch_hash, Branch, SparseMerkleTree};
use std::sync::Arc;

use super::node_key::{prefix_copy_path, prefix_set_bit, NodeKey, PrefixBits};
use super::overlay::Overlay;

pub const CF_SMT_NODES: &str = "smt_nodes";

/// Read-only source of committed SMT nodes.
///
/// Normal mutation paths read the live database. Certified proof workers use
/// [`SnapshotNodeReader`] so every node read belongs to the RocksDB sequence
/// pinned when the corresponding root was committed.
pub trait NodeReader: Sync {
    fn get_node(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
}

impl NodeReader for Arc<DB> {
    fn get_node(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let cf = self
            .cf_handle(CF_SMT_NODES)
            .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
        Ok(self.get_cf(&cf, key)?.map(|value| value.to_vec()))
    }
}

/// Node reader backed by one immutable RocksDB snapshot.
pub struct SnapshotNodeReader<'db, 'snapshot> {
    db: &'db DB,
    snapshot: &'snapshot Snapshot<'db>,
}

impl<'db, 'snapshot> SnapshotNodeReader<'db, 'snapshot> {
    pub fn new(db: &'db DB, snapshot: &'snapshot Snapshot<'db>) -> Self {
        Self { db, snapshot }
    }
}

impl NodeReader for SnapshotNodeReader<'_, '_> {
    fn get_node(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let cf = self
            .db
            .cf_handle(CF_SMT_NODES)
            .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
        Ok(self.snapshot.get_cf(&cf, key)?.map(|value| value.to_vec()))
    }
}

// ─── Public entry-points ──────────────────────────────────────────────────────

/// Materialize a partial SMT for a batch insertion.
pub fn materialize_for_batch<R: NodeReader + ?Sized>(
    db: &R,
    own_overlay: &Overlay,
    parent_overlay: Option<&Overlay>,
    batch: &[(SmtKey, Vec<u8>)],
) -> anyhow::Result<SparseMerkleTree> {
    let keys: Vec<&SmtKey> = batch.iter().map(|(k, _)| k).collect();
    materialize_inner(db, own_overlay, parent_overlay, &keys)
}

/// Materialize a partial SMT for a single-leaf proof generation.
pub fn materialize_for_proof<R: NodeReader + ?Sized>(
    db: &R,
    own_overlay: &Overlay,
    parent_overlay: Option<&Overlay>,
    leaf_key: &SmtKey,
) -> anyhow::Result<SparseMerkleTree> {
    let keys = [leaf_key];
    materialize_inner(db, own_overlay, parent_overlay, &keys)
}

/// Materialize a partial SMT covering multiple keys — for batch proof generation.
pub fn materialize_for_keys<R: NodeReader + ?Sized>(
    db: &R,
    own_overlay: &Overlay,
    parent_overlay: Option<&Overlay>,
    keys: &[SmtKey],
) -> anyhow::Result<SparseMerkleTree> {
    let key_refs: Vec<&SmtKey> = keys.iter().collect();
    materialize_inner(db, own_overlay, parent_overlay, &key_refs)
}

/// Load node bytes, checking overlays → RocksDB.
pub fn load_bytes<R: NodeReader + ?Sized>(
    db: &R,
    own_overlay: &Overlay,
    parent_overlay: Option<&Overlay>,
    nk: &NodeKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    load_node(db, own_overlay, parent_overlay, nk)
}

// ─── Core implementation ─────────────────────────────────────────────────────

fn materialize_inner<R: NodeReader + ?Sized>(
    db: &R,
    own_overlay: &Overlay,
    parent_overlay: Option<&Overlay>,
    keys: &[&SmtKey],
) -> anyhow::Result<SparseMerkleTree> {
    let root_nk = NodeKey::root();

    let root_bytes = match load_node(db, own_overlay, parent_overlay, &root_nk)? {
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

    // Parallelize left/right subtree loads when both sides have keys to visit.
    // Each side accesses disjoint node key prefixes and only reads overlays/DB.
    let has_left = keys.iter().any(|k| key_bit_at(k, split) == 0);
    let has_right = keys.iter().any(|k| key_bit_at(k, split) == 1);
    if has_left && has_right {
        let (left_res, right_res) = rayon::join(
            || {
                route_child(
                    db,
                    own_overlay,
                    parent_overlay,
                    split,
                    false,
                    keys,
                    &base_acc,
                )
            },
            || {
                route_child(
                    db,
                    own_overlay,
                    parent_overlay,
                    split,
                    true,
                    keys,
                    &base_acc,
                )
            },
        );
        root_node.left = left_res?;
        root_node.right = right_res?;
    } else {
        root_node.left = route_child(
            db,
            own_overlay,
            parent_overlay,
            split,
            false,
            keys,
            &base_acc,
        )?;
        root_node.right = route_child(
            db,
            own_overlay,
            parent_overlay,
            split,
            true,
            keys,
            &base_acc,
        )?;
    }

    // Recompute hash if missing.
    if root_node.hash.is_none() {
        let lh = branch_hash(&root_node.left);
        let rh = branch_hash(&root_node.right);
        root_node.hash = Some(rsmt::hash_node(
            &lh,
            &rh,
            root_node.depth,
            &root_node.region,
        ));
    }

    let mut tree = SparseMerkleTree::new();
    tree.root = Some(Arc::new(Branch::Node(root_node)));
    Ok(tree)
}

/// Filter keys by routing bit, then materialize or load as stub.
fn route_child<R: NodeReader + ?Sized>(
    db: &R,
    own_overlay: &Overlay,
    parent_overlay: Option<&Overlay>,
    split: usize,
    is_right: bool,
    keys: &[&SmtKey],
    acc: &PrefixBits,
) -> anyhow::Result<Arc<Branch>> {
    let child_keys: Vec<&SmtKey> = keys
        .iter()
        .filter(|k| key_bit_at(k, split) == (is_right as u8))
        .copied()
        .collect();

    let mut child_acc = *acc;
    if is_right {
        prefix_set_bit(&mut child_acc, split);
    }
    let child_nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

    if child_keys.is_empty() {
        return load_stub(db, own_overlay, parent_overlay, child_nk);
    }

    materialize_subtree(
        db,
        own_overlay,
        parent_overlay,
        child_nk,
        &child_keys,
        split,
        &child_acc,
    )
}

fn materialize_subtree<R: NodeReader + ?Sized>(
    db: &R,
    own_overlay: &Overlay,
    parent_overlay: Option<&Overlay>,
    nk: NodeKey,
    keys: &[&SmtKey],
    start_bit: usize,
    acc: &PrefixBits,
) -> anyhow::Result<Arc<Branch>> {
    let bytes = match load_node(db, own_overlay, parent_overlay, &nk)? {
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

    let has_left = keys.iter().any(|k| key_bit_at(k, split) == 0);
    let has_right = keys.iter().any(|k| key_bit_at(k, split) == 1);
    if has_left && has_right {
        let (left_res, right_res) = rayon::join(
            || {
                route_child(
                    db,
                    own_overlay,
                    parent_overlay,
                    split,
                    false,
                    keys,
                    &base_acc,
                )
            },
            || {
                route_child(
                    db,
                    own_overlay,
                    parent_overlay,
                    split,
                    true,
                    keys,
                    &base_acc,
                )
            },
        );
        node.left = left_res?;
        node.right = right_res?;
    } else {
        node.left = route_child(
            db,
            own_overlay,
            parent_overlay,
            split,
            false,
            keys,
            &base_acc,
        )?;
        node.right = route_child(
            db,
            own_overlay,
            parent_overlay,
            split,
            true,
            keys,
            &base_acc,
        )?;
    }

    if node.hash.is_none() {
        let lh = branch_hash(&node.left);
        let rh = branch_hash(&node.right);
        node.hash = Some(rsmt::hash_node(&lh, &rh, node.depth, &node.region));
    }
    Ok(Arc::new(Branch::Node(node)))
}

fn load_stub<R: NodeReader + ?Sized>(
    db: &R,
    own_overlay: &Overlay,
    parent_overlay: Option<&Overlay>,
    nk: NodeKey,
) -> anyhow::Result<Arc<Branch>> {
    let bytes = match load_node(db, own_overlay, parent_overlay, &nk)? {
        None => return Ok(Arc::new(Branch::Stub([0u8; 32]))),
        Some(b) => b,
    };
    let hash = extract_hash_from_bytes(&bytes)?;
    Ok(Arc::new(Branch::Stub(hash)))
}

// ─── Node loading (overlay → RocksDB) ───────────────────────────────────────

fn load_node<R: NodeReader + ?Sized>(
    db: &R,
    own_overlay: &Overlay,
    parent_overlay: Option<&Overlay>,
    nk: &NodeKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    if let Some(opt) = own_overlay.get(nk) {
        return Ok(opt.map(|b| b.to_vec()));
    }
    if let Some(parent) = parent_overlay {
        if let Some(opt) = parent.get(nk) {
            return Ok(opt.map(|b| b.to_vec()));
        }
    }
    db.get_node(nk.as_bytes())
}

fn extract_hash_from_bytes(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    if bytes[0] == TAG_LEAF {
        let leaf = deserialize_leaf(bytes);
        Ok(leaf.hash)
    } else if bytes[0] == TAG_NODE {
        let node = deserialize_node(bytes);
        node.hash.ok_or_else(|| {
            anyhow::anyhow!("node has no hash — commit root hash before using as Stub")
        })
    } else {
        anyhow::bail!("unknown node type byte 0x{:02x}", bytes[0])
    }
}
