//! In-memory SMT with optional RocksDB persistence.

use std::sync::Arc;

use rocksdb::{DB, WriteBatch};
use rsmt::{
    Branch, SmtError, SmtKey, InclusionProof, SparseMerkleTree, SmtSnapshot,
    encode_aggregator_envelope_v1, branch_hash,
};
use rsmt::consistency::batch_insert;
use rsmt::node_serde::{TAG_LEAF, TAG_NODE, deserialize_leaf, deserialize_node, serialize_leaf, serialize_node};

use crate::traits::{SmtStore, SmtStoreSnapshot};
use crate::disk::materializer::CF_SMT_NODES;
use crate::disk::node_key::{NodeKey, PrefixBits, prefix_set_bit, prefix_copy_path};
use rsmt::path::{get_sort_key, key_bit_at};

const CF_SMT_META:       &str = "smt_meta";
pub const CF_SMT_LEAVES: &str = "smt_leaves";
const KEY_ROOT_HASH: &[u8] = b"root_hash";

// ─── PersistMode ──────────────────────────────────────────────────────────────

/// How the in-memory SMT persists its state to RocksDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistMode {
    /// No persistence. Data is lost on restart.
    None,
    /// Persist leaf values only (`CF_SMT_LEAVES`, append-only).
    /// On restart: replay all leaves to rebuild the tree and verify the root.
    LeavesOnly,
    /// Persist leaves + all internal nodes (`CF_SMT_NODES`).
    Full,
    /// Like `LeavesOnly` during normal operation, but on graceful shutdown
    /// persists the entire in-memory tree for fast recovery.
    LeavesWithShutdownSnapshot,
}

// ─── MemSmt ───────────────────────────────────────────────────────────────────

pub struct MemSmt {
    pub(crate) tree: SparseMerkleTree,
    /// Pre-computed root hash (updated on each commit).
    current_root: Option<[u8; 32]>,
    db: Option<Arc<DB>>,
    persist_mode: PersistMode,
}

impl MemSmt {
    /// Create a new in-memory SMT (no persistence).
    pub fn new() -> Self {
        let tree = SparseMerkleTree::new();
        Self { tree, current_root: None, db: None, persist_mode: PersistMode::None }
    }

    /// Open a DB-backed in-memory SMT, recovering state according to `persist_mode`.
    pub fn open(db: Arc<DB>, persist_mode: PersistMode) -> anyhow::Result<Self> {
        match persist_mode {
            PersistMode::None => {
                let tree = SparseMerkleTree::new();
                Ok(Self { tree, current_root: None, db: Some(db), persist_mode })
            }

            PersistMode::LeavesOnly | PersistMode::LeavesWithShutdownSnapshot => {
                let committed_root = read_root_hash(&db)?;

                let (tree, recovery_kind) = if has_full_node_data(&db) {
                    let t = load_full_tree(&db)?;
                    delete_all_nodes(&db)?;
                    (t, "full-tree")
                } else {
                    let leaves = load_all_leaves(&db)?;
                    let mut t = SparseMerkleTree::new();
                    if !leaves.is_empty() {
                        batch_insert(&mut t, &leaves)
                            .map_err(|e| anyhow::anyhow!("SMT leaf replay failed: {e}"))?;
                    }
                    (t, "leaf-replay")
                };

                let current_root = tree.root_hash();
                if let Some(committed) = committed_root {
                    if current_root != Some(committed) {
                        anyhow::bail!(
                            "SMT root mismatch after {} recovery: \
                             persisted={}, rebuilt={}",
                            recovery_kind,
                            hex::encode(committed),
                            hex::encode(current_root.unwrap_or([0u8; 32])),
                        );
                    }
                }
                tracing::info!(recovery = recovery_kind, "SMT recovery completed");
                Ok(Self { tree, current_root, db: Some(db), persist_mode })
            }

            PersistMode::Full => {
                let committed_root = read_root_hash(&db)?;
                let tree = load_full_tree(&db)?;
                let current_root = tree.root_hash();
                if let Some(committed) = committed_root {
                    if current_root != Some(committed) {
                        anyhow::bail!(
                            "SMT root mismatch after full-node recovery: \
                             persisted={}, loaded={}",
                            hex::encode(committed),
                            hex::encode(current_root.unwrap_or([0u8; 32])),
                        );
                    }
                }
                Ok(Self { tree, current_root, db: Some(db), persist_mode })
            }
        }
    }
}

impl Default for MemSmt {
    fn default() -> Self {
        Self::new()
    }
}

impl MemSmt {
    pub fn shutdown_persist(&mut self) -> anyhow::Result<()> {
        if self.persist_mode != PersistMode::LeavesWithShutdownSnapshot {
            return Ok(());
        }
        let db = match &self.db {
            Some(db) => db.clone(),
            None => return Ok(()),
        };
        persist_entire_tree(&db, &self.tree, self.current_root)
    }
}

impl SmtStore for MemSmt {
    type Snapshot = MemSmtSnapshot;

    fn root_hash(&self) -> Option<[u8; 32]> {
        self.current_root
    }

    fn create_snapshot(&self) -> MemSmtSnapshot {
        MemSmtSnapshot {
            inner: SmtSnapshot::create(&self.tree),
            pending: Vec::new(),
        }
    }

    fn get_inclusion_proof(&mut self, key: &SmtKey) -> anyhow::Result<InclusionProof> {
        self.tree.get_inclusion_proof(key).map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn shutdown_persist(&mut self) -> anyhow::Result<()> {
        self.shutdown_persist()
    }
}

// ─── MemSmtSnapshot ───────────────────────────────────────────────────────────

pub struct MemSmtSnapshot {
    pub(crate) inner: SmtSnapshot,
    /// Leaves inserted in this snapshot (for persistence on commit).
    pub(crate) pending: Vec<(SmtKey, Vec<u8>)>,
}

impl SmtStoreSnapshot for MemSmtSnapshot {
    type Store = MemSmt;

    fn add_leaf(&mut self, key: SmtKey, value: Vec<u8>) -> Result<(), SmtError> {
        let result = self.inner.add_leaf(key, value.clone());
        if result.is_ok() {
            self.pending.push((key, value));
        }
        result
    }

    fn root_hash(&mut self) -> anyhow::Result<Option<[u8; 32]>> {
        Ok(self.inner.root_hash())
    }

    fn fork(&mut self) -> Self {
        MemSmtSnapshot {
            inner: SmtSnapshot::fork(&self.inner),
            pending: Vec::new(),
        }
    }

    fn commit(self, store: &mut MemSmt) -> anyhow::Result<()> {
        let MemSmtSnapshot { inner, pending } = self;

        if store.persist_mode == PersistMode::None || store.db.is_none() {
            inner.commit(&mut store.tree);
            store.current_root = store.tree.root_hash();
            return Ok(());
        }

        let db = store.db.as_ref().unwrap().clone();

        match store.persist_mode {
            PersistMode::None => unreachable!(),

            PersistMode::LeavesOnly | PersistMode::LeavesWithShutdownSnapshot => {
                inner.commit(&mut store.tree);
                store.current_root = store.tree.root_hash();
                persist_leaves_and_root(&db, &pending, store.current_root)?;
            }

            PersistMode::Full => {
                inner.commit(&mut store.tree);
                store.current_root = store.tree.root_hash();
                persist_full(&db, &pending, &store.tree, store.current_root)?;
            }
        }
        Ok(())
    }

    fn discard(self) {}

    fn insert_batch(
        &mut self,
        batch: &[(SmtKey, Vec<u8>)],
        with_proof: bool,
    ) -> anyhow::Result<(Vec<bool>, Option<Vec<u8>>)> {
        if with_proof {
            match self.inner.batch_insert_with_proof(batch) {
                Ok((inserted_pairs, proof)) => {
                    let inserted_set: std::collections::HashSet<SmtKey> =
                        inserted_pairs.iter().map(|(k, _)| *k).collect();
                    let mut seen = std::collections::HashSet::new();
                    let flags: Vec<bool> = batch.iter()
                        .map(|(k, _)| inserted_set.contains(k) && seen.insert(*k))
                        .collect();
                    // Build the aggregator_rsmt_v1 envelope while we still
                    // hold the sorted inserted pairs; this is the wire form
                    // the BFT Core verifier expects.
                    let envelope = encode_aggregator_envelope_v1(&inserted_pairs, &proof);
                    self.pending.extend(inserted_pairs);
                    Ok((flags, Some(envelope)))
                }
                Err(e) => Err(anyhow::anyhow!("batch_insert_with_proof failed: {e}")),
            }
        } else {
            match self.inner.batch_insert(batch) {
                Ok(inserted_pairs) => {
                    let inserted_set: std::collections::HashSet<SmtKey> =
                        inserted_pairs.iter().map(|(k, _)| *k).collect();
                    let mut seen = std::collections::HashSet::new();
                    let flags: Vec<bool> = batch.iter()
                        .map(|(k, _)| inserted_set.contains(k) && seen.insert(*k))
                        .collect();
                    self.pending.extend(inserted_pairs);
                    Ok((flags, None))
                }
                Err(e) => Err(anyhow::anyhow!("batch_insert failed: {e}")),
            }
        }
    }

    fn insert_batch_with<H: rsmt::SmtHasher>(
        &mut self,
        batch: &[(SmtKey, Vec<u8>)],
        with_proof: bool,
    ) -> anyhow::Result<(Vec<bool>, Option<Vec<u8>>)> {
        if with_proof {
            match self.inner.batch_insert_with_proof_with::<H>(batch) {
                Ok((inserted_pairs, proof)) => {
                    let inserted_set: std::collections::HashSet<SmtKey> =
                        inserted_pairs.iter().map(|(k, _)| *k).collect();
                    let mut seen = std::collections::HashSet::new();
                    let flags: Vec<bool> = batch.iter()
                        .map(|(k, _)| inserted_set.contains(k) && seen.insert(*k))
                        .collect();
                    let envelope = encode_aggregator_envelope_v1(&inserted_pairs, &proof);
                    self.pending.extend(inserted_pairs);
                    Ok((flags, Some(envelope)))
                }
                Err(e) => Err(anyhow::anyhow!("batch_insert_with_proof_with failed: {e}")),
            }
        } else {
            match self.inner.batch_insert_with::<H>(batch) {
                Ok(inserted_pairs) => {
                    let inserted_set: std::collections::HashSet<SmtKey> =
                        inserted_pairs.iter().map(|(k, _)| *k).collect();
                    let mut seen = std::collections::HashSet::new();
                    let flags: Vec<bool> = batch.iter()
                        .map(|(k, _)| inserted_set.contains(k) && seen.insert(*k))
                        .collect();
                    self.pending.extend(inserted_pairs);
                    Ok((flags, None))
                }
                Err(e) => Err(anyhow::anyhow!("batch_insert_with failed: {e}")),
            }
        }
    }
}

// ─── Persistence helpers ──────────────────────────────────────────────────────

fn persist_leaves_and_root(
    db: &DB,
    pending: &[(SmtKey, Vec<u8>)],
    root: Option<[u8; 32]>,
) -> anyhow::Result<()> {
    let cf_leaves = db.cf_handle(CF_SMT_LEAVES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_LEAVES))?;
    let cf_meta = db.cf_handle(CF_SMT_META)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_META))?;

    let mut batch = WriteBatch::default();
    for (key, value) in pending {
        batch.put_cf(&cf_leaves, key, value);
    }
    if let Some(h) = root {
        batch.put_cf(&cf_meta, KEY_ROOT_HASH, &h);
    }
    db.write(batch)?;
    Ok(())
}

/// Persist only the nodes on the paths to the newly inserted leaves.
///
/// Walks the tree recursively, but only recurses into subtrees that contain
/// at least one pending key.  This is O(batch_size × depth) per round rather
/// than O(tree_size), keeping commit time bounded by the batch rather than the
/// total tree size.
///
/// Stale NodeKeys left by node-splits are harmless: `load_full_tree` navigates
/// by computed keys and never scans, so unreachable stale entries are ignored.
fn persist_full(
    db: &DB,
    pending: &[(SmtKey, Vec<u8>)],
    tree: &SparseMerkleTree,
    root: Option<[u8; 32]>,
) -> anyhow::Result<()> {
    let cf_leaves = db.cf_handle(CF_SMT_LEAVES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_LEAVES))?;
    let cf_nodes = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    let cf_meta = db.cf_handle(CF_SMT_META)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_META))?;

    let mut batch = WriteBatch::default();

    for (key, value) in pending {
        batch.put_cf(&cf_leaves, key, value);
    }

    // Sort pending keys by LSB-first traversal order so partition_point_keys
    // can binary-search at each tree level.
    let mut sorted_keys: Vec<SmtKey> = pending.iter().map(|(k, _)| *k).collect();
    sorted_keys.sort_by(|a, b| get_sort_key(a).cmp(&get_sort_key(b)));

    if let Some(root_arc) = &tree.root {
        persist_delta_node(
            root_arc,
            NodeKey::root(),
            0,
            &[0u8; 32],
            &sorted_keys,
            &cf_nodes,
            &mut batch,
        );
    }

    if let Some(h) = root {
        batch.put_cf(&cf_meta, KEY_ROOT_HASH, &h);
    }
    db.write(batch)?;
    Ok(())
}

/// Recursive delta-walk: write this node and recurse only into subtrees that
/// contain at least one pending key.
fn persist_delta_node(
    branch: &Arc<Branch>,
    nk: NodeKey,
    start_bit: usize,
    acc: &PrefixBits,
    pending: &[SmtKey],
    cf: &impl rocksdb::AsColumnFamilyRef,
    batch: &mut WriteBatch,
) {
    if pending.is_empty() {
        return;
    }

    match branch.as_ref() {
        Branch::Leaf(l) => {
            batch.put_cf(cf, nk.as_bytes(), &serialize_leaf(l));
        }
        Branch::Node(n) => {
            batch.put_cf(cf, nk.as_bytes(), &serialize_node(n));

            let n_path = n.path.path_len();
            let mut base_acc = *acc;
            prefix_copy_path(&mut base_acc, start_bit, &n.path);
            let split = start_bit + n_path;

            // Binary-search partition: keys with bit `split` = 0 go left.
            let mid = partition_point_keys(pending, split);

            // Left child.
            let left_nk = NodeKey::from_depth_and_prefix(split + 1, &base_acc);
            persist_delta_node(
                &n.left, left_nk, split + 1, &base_acc,
                &pending[..mid], cf, batch,
            );

            // Right child.
            let mut right_acc = base_acc;
            prefix_set_bit(&mut right_acc, split);
            let right_nk = NodeKey::from_depth_and_prefix(split + 1, &right_acc);
            persist_delta_node(
                &n.right, right_nk, split + 1, &right_acc,
                &pending[mid..], cf, batch,
            );
        }
        Branch::Stub(_) => {}
    }
}

/// Binary search: first index in `keys` where `key_bit_at(key, split) == 1`.
/// Requires keys are sorted by `get_sort_key` (LSB-first order).
fn partition_point_keys(keys: &[SmtKey], split: usize) -> usize {
    let mut lo = 0;
    let mut hi = keys.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if key_bit_at(&keys[mid], split) == 1 {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

// ─── Full-tree recovery ───────────────────────────────────────────────────────

fn load_full_tree(db: &DB) -> anyhow::Result<SparseMerkleTree> {
    let cf = match db.cf_handle(CF_SMT_NODES) {
        None => return Ok(SparseMerkleTree::new()),
        Some(c) => c,
    };
    let root_bytes = match db.get_cf(&cf, NodeKey::root().as_bytes())? {
        None => return Ok(SparseMerkleTree::new()),
        Some(b) => b.to_vec(),
    };

    if root_bytes[0] == TAG_LEAF {
        let leaf = deserialize_leaf(&root_bytes);
        let mut tree = SparseMerkleTree::new();
        tree.root = Some(Arc::new(Branch::Leaf(leaf)));
        return Ok(tree);
    }

    let mut root_node = deserialize_node(&root_bytes);
    let n_path = root_node.path.path_len();
    let mut acc: PrefixBits = [0u8; 32];
    prefix_copy_path(&mut acc, 0, &root_node.path);
    let split = n_path;

    root_node.left = load_full_branch(db, false, split, &acc)?;
    root_node.right = load_full_branch(db, true, split, &acc)?;

    // Recompute hash.
    let lh = branch_hash(&root_node.left);
    let rh = branch_hash(&root_node.right);
    root_node.hash = Some(rsmt::hash_node(&lh, &rh, root_node.depth));

    let mut tree = SparseMerkleTree::new();
    tree.root = Some(Arc::new(Branch::Node(root_node)));
    Ok(tree)
}

fn load_full_branch(
    db: &DB,
    is_right: bool,
    split: usize,
    acc: &PrefixBits,
) -> anyhow::Result<Arc<Branch>> {
    let mut child_acc = *acc;
    if is_right {
        prefix_set_bit(&mut child_acc, split);
    }
    let nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    let bytes = match db.get_cf(&cf, nk.as_bytes())? {
        None => return Ok(Arc::new(Branch::Stub([0u8; 32]))),
        Some(b) => b.to_vec(),
    };

    if bytes[0] == TAG_LEAF {
        let leaf = deserialize_leaf(&bytes);
        return Ok(Arc::new(Branch::Leaf(leaf)));
    }

    debug_assert_eq!(bytes[0], TAG_NODE);
    let mut node = deserialize_node(&bytes);
    let n_path = node.path.path_len();
    let mut base_acc = child_acc;
    prefix_copy_path(&mut base_acc, split + 1, &node.path);
    let node_split = split + 1 + n_path;

    node.left = load_full_branch(db, false, node_split, &base_acc)?;
    node.right = load_full_branch(db, true, node_split, &base_acc)?;

    let lh = branch_hash(&node.left);
    let rh = branch_hash(&node.right);
    node.hash = Some(rsmt::hash_node(&lh, &rh, node.depth));

    Ok(Arc::new(Branch::Node(node)))
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

fn read_root_hash(db: &DB) -> anyhow::Result<Option<[u8; 32]>> {
    let cf = match db.cf_handle(CF_SMT_META) {
        None => return Ok(None),
        Some(c) => c,
    };
    match db.get_cf(&cf, KEY_ROOT_HASH)? {
        None => Ok(None),
        Some(v) if v.len() == 32 => Ok(Some(v[..].try_into().unwrap())),
        // Legacy 34-byte imprint: skip the 2-byte prefix.
        Some(v) if v.len() == 34 => Ok(Some(v[2..].try_into().unwrap())),
        Some(v) => anyhow::bail!("unexpected root hash length: {}", v.len()),
    }
}

fn load_all_leaves(db: &DB) -> anyhow::Result<Vec<(SmtKey, Vec<u8>)>> {
    let cf = match db.cf_handle(CF_SMT_LEAVES) {
        None => return Ok(vec![]),
        Some(c) => c,
    };
    let mut leaves = Vec::new();
    for item in db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
        let (key_bytes, value) = item?;
        if key_bytes.len() != 32 {
            continue; // skip legacy entries
        }
        let mut key: SmtKey = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        leaves.push((key, value.to_vec()));
    }
    Ok(leaves)
}

fn has_full_node_data(db: &DB) -> bool {
    let cf = match db.cf_handle(CF_SMT_NODES) {
        None => return false,
        Some(c) => c,
    };
    db.get_cf(&cf, NodeKey::root().as_bytes())
        .ok()
        .flatten()
        .is_some()
}

fn delete_all_nodes(db: &DB) -> anyhow::Result<()> {
    let cf = match db.cf_handle(CF_SMT_NODES) {
        None => return Ok(()),
        Some(c) => c,
    };
    let mut batch = WriteBatch::default();
    for item in db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
        let (key, _) = item?;
        batch.delete_cf(&cf, &key);
    }
    db.write(batch)?;
    Ok(())
}

fn persist_entire_tree(
    db: &DB,
    tree: &SparseMerkleTree,
    root: Option<[u8; 32]>,
) -> anyhow::Result<()> {
    let cf_nodes = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    let cf_meta = db.cf_handle(CF_SMT_META)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_META))?;

    let mut batch = WriteBatch::default();
    let mut node_count: u64 = 0;

    if let Some(root_arc) = &tree.root {
        let root_nk = NodeKey::root();
        match root_arc.as_ref() {
            Branch::Node(n) => {
                batch.put_cf(&cf_nodes, root_nk.as_bytes(), &serialize_node(n));
                node_count += 1;
                let mut acc: PrefixBits = [0u8; 32];
                prefix_copy_path(&mut acc, 0, &n.path);
                let split = n.path.path_len();

                persist_entire_branch(&n.left, false, split, &acc, &cf_nodes, &mut batch, &mut node_count);
                persist_entire_branch(&n.right, true, split, &acc, &cf_nodes, &mut batch, &mut node_count);
            }
            Branch::Leaf(l) => {
                batch.put_cf(&cf_nodes, root_nk.as_bytes(), &serialize_leaf(l));
                node_count += 1;
            }
            Branch::Stub(_) => {}
        }
    }

    if let Some(h) = root {
        batch.put_cf(&cf_meta, KEY_ROOT_HASH, &h);
    }
    db.write(batch)?;
    tracing::info!(nodes = node_count, "shutdown snapshot written to CF_SMT_NODES");
    Ok(())
}

fn persist_entire_branch(
    branch: &Arc<Branch>,
    is_right: bool,
    split: usize,
    acc: &PrefixBits,
    cf: &impl rocksdb::AsColumnFamilyRef,
    batch: &mut WriteBatch,
    node_count: &mut u64,
) {
    let mut child_acc = *acc;
    if is_right {
        prefix_set_bit(&mut child_acc, split);
    }
    let nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

    match branch.as_ref() {
        Branch::Leaf(l) => {
            batch.put_cf(cf, nk.as_bytes(), &serialize_leaf(l));
            *node_count += 1;
        }
        Branch::Node(n) => {
            batch.put_cf(cf, nk.as_bytes(), &serialize_node(n));
            *node_count += 1;

            let n_path = n.path.path_len();
            let mut base_acc = child_acc;
            prefix_copy_path(&mut base_acc, split + 1, &n.path);
            let node_split = split + 1 + n_path;

            persist_entire_branch(&n.left, false, node_split, &base_acc, cf, batch, node_count);
            persist_entire_branch(&n.right, true, node_split, &base_acc, cf, batch, node_count);
        }
        Branch::Stub(_) => {}
    }
}
