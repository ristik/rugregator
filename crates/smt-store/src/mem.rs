//! In-memory SMT with optional RocksDB persistence.

use std::sync::Arc;

use num_bigint::BigUint;
use rocksdb::{DB, WriteBatch};
use rsmt::{
    Branch, SmtError, SmtPath, MerkleTreePath, SparseMerkleTree, SmtSnapshot,
    consistency_proof_to_cbor, KEY_LENGTH, calc_leaf_hash, calc_node_hash,
};
use rsmt::consistency::batch_insert;
use rsmt::node_serde::{TAG_LEAF, TAG_NODE, deserialize_leaf, deserialize_node};
use rsmt::path::path_len;

use crate::traits::{SmtStore, SmtStoreSnapshot};
use crate::disk::materializer::{CF_SMT_NODES, extract_node_prefix_bits};
use crate::disk::node_key::NodeKey;
use crate::disk::overlay::Overlay;
use crate::disk::persister::persist_tree;

const CF_SMT_META:   &str = "smt_meta";
const CF_SMT_LEAVES: &str = "smt_leaves";
const KEY_ROOT_HASH: &[u8] = b"root_hash";

// ─── PersistMode ──────────────────────────────────────────────────────────────

/// How the in-memory SMT persists its state to RocksDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistMode {
    /// No persistence. Data is lost on restart.
    /// BFT Core partition state must also be reset after a restart.
    None,
    /// Persist leaf values only (`CF_SMT_LEAVES`, append-only).
    /// On restart: replay all leaves to rebuild the tree and verify the root.
    LeavesOnly,
    /// Persist leaves + all internal nodes (`CF_SMT_NODES`).
    /// Internal nodes are updated immediately: obsolete keys are tombstoned
    /// at commit time by comparing old vs new node-key sets.
    /// On restart: load the full node tree directly from `CF_SMT_NODES`.
    Full,
}

// ─── MemSmt ───────────────────────────────────────────────────────────────────

pub struct MemSmt {
    pub(crate) tree: SparseMerkleTree,
    /// Pre-computed root hash (updated on each commit).
    current_root: [u8; 34],
    db: Option<Arc<DB>>,
    persist_mode: PersistMode,
}

impl MemSmt {
    /// Create a new in-memory SMT (no persistence).
    pub fn new() -> Self {
        let mut tree = SparseMerkleTree::new();
        let current_root = tree.root_hash_imprint();
        Self { tree, current_root, db: None, persist_mode: PersistMode::None }
    }

    /// Open a DB-backed in-memory SMT, recovering state according to `persist_mode`.
    ///
    /// - `PersistMode::None`: starts fresh (DB not used for SMT data).
    /// - `PersistMode::LeavesOnly`: replays all leaves from `CF_SMT_LEAVES`,
    ///   then asserts the rebuilt root matches `CF_SMT_META`.
    /// - `PersistMode::Full`: loads the full node tree from `CF_SMT_NODES`
    ///   directly, then asserts the loaded root matches `CF_SMT_META`.
    pub fn open(db: Arc<DB>, persist_mode: PersistMode) -> anyhow::Result<Self> {
        match persist_mode {
            PersistMode::None => {
                let mut tree = SparseMerkleTree::new();
                let current_root = tree.root_hash_imprint();
                Ok(Self { tree, current_root, db: Some(db), persist_mode })
            }

            PersistMode::LeavesOnly => {
                let committed_root = read_root_hash(&db)?;
                let leaves = load_all_leaves(&db)?;
                let mut tree = SparseMerkleTree::new();
                if !leaves.is_empty() {
                    batch_insert(&mut tree, &leaves)
                        .map_err(|e| anyhow::anyhow!("SMT leaf replay failed: {e}"))?;
                    if let Some(committed) = committed_root {
                        let actual = tree.root_hash_imprint();
                        if actual != committed {
                            anyhow::bail!(
                                "SMT root mismatch after leaf replay: \
                                 persisted={}, rebuilt={}",
                                hex::encode(committed),
                                hex::encode(actual),
                            );
                        }
                    }
                }
                let current_root = tree.root_hash_imprint();
                Ok(Self { tree, current_root, db: Some(db), persist_mode })
            }

            PersistMode::Full => {
                let committed_root = read_root_hash(&db)?;
                let mut tree = load_full_tree(&db)?;
                let current_root = tree.root_hash_imprint();
                if let Some(committed) = committed_root {
                    if current_root != committed {
                        anyhow::bail!(
                            "SMT root mismatch after full-node recovery: \
                             persisted={}, loaded={}",
                            hex::encode(committed),
                            hex::encode(current_root),
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

impl SmtStore for MemSmt {
    type Snapshot = MemSmtSnapshot;

    fn root_hash_imprint(&self) -> [u8; 34] {
        self.current_root
    }

    fn create_snapshot(&self) -> MemSmtSnapshot {
        MemSmtSnapshot {
            inner: SmtSnapshot::create(&self.tree),
            pending: Vec::new(),
        }
    }

    fn get_path(&mut self, leaf_path: &SmtPath) -> anyhow::Result<MerkleTreePath> {
        self.tree.get_path(leaf_path).map_err(|e| anyhow::anyhow!("{e}"))
    }
}

// ─── MemSmtSnapshot ───────────────────────────────────────────────────────────

pub struct MemSmtSnapshot {
    pub(crate) inner: SmtSnapshot,
    /// Leaves inserted in this snapshot (for persistence on commit).
    pub(crate) pending: Vec<(SmtPath, Vec<u8>)>,
}

impl SmtStoreSnapshot for MemSmtSnapshot {
    type Store = MemSmt;

    fn add_leaf(&mut self, path: SmtPath, value: Vec<u8>) -> Result<(), SmtError> {
        let result = self.inner.add_leaf(path.clone(), value.clone());
        if result.is_ok() {
            self.pending.push((path, value));
        }
        result
    }

    fn root_hash_imprint(&mut self) -> anyhow::Result<[u8; 34]> {
        Ok(self.inner.root_hash_imprint())
    }

    fn fork(&mut self) -> Self {
        MemSmtSnapshot {
            inner: SmtSnapshot::fork(&self.inner),
            pending: Vec::new(),
        }
    }

    fn commit(self, store: &mut MemSmt) -> anyhow::Result<()> {
        let MemSmtSnapshot { inner, pending } = self;

        // Fast path: no persistence configured.
        if store.persist_mode == PersistMode::None || store.db.is_none() {
            inner.commit(&mut store.tree);
            store.current_root = store.tree.root_hash_imprint();
            return Ok(());
        }

        // Clone the Arc to avoid overlapping borrows of store fields.
        let db = store.db.as_ref().unwrap().clone();

        match store.persist_mode {
            PersistMode::None => unreachable!(),

            PersistMode::LeavesOnly => {
                inner.commit(&mut store.tree);
                store.current_root = store.tree.root_hash_imprint();
                persist_leaves_and_root(&db, &pending, store.current_root)?;
            }

            PersistMode::Full => {
                let old_keys = collect_all_node_keys(&store.tree);
                inner.commit(&mut store.tree);
                store.current_root = store.tree.root_hash_imprint();
                persist_full(&db, &pending, &old_keys, &mut store.tree, store.current_root)?;
            }
        }
        Ok(())
    }

    fn discard(self) {}

    fn insert_batch(
        &mut self,
        batch: &[(SmtPath, Vec<u8>)],
        with_proof: bool,
    ) -> anyhow::Result<(Vec<bool>, Option<Vec<u8>>)> {
        if with_proof {
            match self.inner.batch_insert_with_proof(batch) {
                Ok((inserted_pairs, proof)) => {
                    let inserted_set: std::collections::HashSet<_> =
                        inserted_pairs.iter().map(|(p, _)| p.clone()).collect();
                    let flags: Vec<bool> = batch.iter().map(|(p, _)| inserted_set.contains(p)).collect();
                    self.pending.extend(inserted_pairs);
                    let proof_cbor = consistency_proof_to_cbor(&proof);
                    Ok((flags, Some(proof_cbor)))
                }
                Err(e) => Err(anyhow::anyhow!("batch_insert_with_proof failed: {e}")),
            }
        } else {
            let mut flags = vec![false; batch.len()];
            for (i, (path, value)) in batch.iter().enumerate() {
                match self.add_leaf(path.clone(), value.clone()) {
                    Ok(()) => flags[i] = true,
                    Err(SmtError::DuplicateLeaf) => {}
                    Err(e) => return Err(anyhow::anyhow!("{e}")),
                }
            }
            Ok((flags, None))
        }
    }
}

// ─── Persistence helpers ──────────────────────────────────────────────────────

/// Write pending leaves to `CF_SMT_LEAVES` and update the committed root in
/// `CF_SMT_META` — a single atomic `WriteBatch`.
fn persist_leaves_and_root(
    db: &DB,
    pending: &[(SmtPath, Vec<u8>)],
    root: [u8; 34],
) -> anyhow::Result<()> {
    let cf_leaves = db.cf_handle(CF_SMT_LEAVES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_LEAVES))?;
    let cf_meta = db.cf_handle(CF_SMT_META)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_META))?;

    let mut batch = WriteBatch::default();
    for (path, value) in pending {
        batch.put_cf(&cf_leaves, path.to_bytes_be(), value);
    }
    batch.put_cf(&cf_meta, KEY_ROOT_HASH, &root);
    db.write(batch)?;
    Ok(())
}

/// Serialize all tree nodes into `CF_SMT_NODES`, tombstone orphaned nodes,
/// append leaves to `CF_SMT_LEAVES`, and update `CF_SMT_META` — all atomically.
fn persist_full(
    db: &DB,
    pending: &[(SmtPath, Vec<u8>)],
    old_keys: &[NodeKey],
    tree: &mut SparseMerkleTree,
    root: [u8; 34],
) -> anyhow::Result<()> {
    let cf_leaves = db.cf_handle(CF_SMT_LEAVES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_LEAVES))?;
    let cf_nodes = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    let cf_meta = db.cf_handle(CF_SMT_META)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_META))?;

    // Walk the post-commit tree: serialize all nodes and compute tombstones.
    let mut overlay = Overlay::new();
    persist_tree(tree, old_keys, &mut overlay);

    let mut batch = WriteBatch::default();
    for (path, value) in pending {
        batch.put_cf(&cf_leaves, path.to_bytes_be(), value);
    }
    for (key, val_opt) in overlay.into_nodes() {
        match val_opt {
            Some(val) => batch.put_cf(&cf_nodes, &key, &val),
            None      => batch.delete_cf(&cf_nodes, &key),
        }
    }
    batch.put_cf(&cf_meta, KEY_ROOT_HASH, &root);
    db.write(batch)?;
    Ok(())
}

// ─── Node-key collection ──────────────────────────────────────────────────────

/// Collect all `NodeKey`s currently in the tree (pre-commit snapshot).
/// Used by `Full` mode to determine which nodes became orphaned after a round.
fn collect_all_node_keys(tree: &SparseMerkleTree) -> Vec<NodeKey> {
    let mut keys = Vec::new();
    keys.push(NodeKey::root());

    let n_path = path_len(&tree.root.path);
    let acc    = extract_node_prefix_bits(&tree.root.path, n_path);
    let split  = n_path;

    if let Some(left) = &tree.root.left {
        collect_branch_keys(left, false, split, &acc, &mut keys);
    }
    if let Some(right) = &tree.root.right {
        collect_branch_keys(right, true, split, &acc, &mut keys);
    }
    keys
}

fn collect_branch_keys(
    branch:   &Arc<Branch>,
    is_right: bool,
    split:    usize,
    acc:      &BigUint,
    keys:     &mut Vec<NodeKey>,
) {
    let child_acc = if is_right {
        acc | (BigUint::from(1u8) << split)
    } else {
        acc.clone()
    };
    keys.push(NodeKey::from_depth_and_prefix(split + 1, &child_acc));

    if let Branch::Node(n) = branch.as_ref() {
        let n_path      = path_len(&n.path);
        let prefix_bits = extract_node_prefix_bits(&n.path, n_path);
        let base_acc    = &child_acc | (prefix_bits << split);
        let node_split  = split + n_path;

        if let Some(left) = &n.left {
            collect_branch_keys(left, false, node_split, &base_acc, keys);
        }
        if let Some(right) = &n.right {
            collect_branch_keys(right, true, node_split, &base_acc, keys);
        }
    }
}

// ─── Full-tree recovery ───────────────────────────────────────────────────────

/// Reconstruct the full in-memory SMT from `CF_SMT_NODES`.
/// Returns an empty tree if the column family is absent or the root is missing.
fn load_full_tree(db: &DB) -> anyhow::Result<SparseMerkleTree> {
    let cf = match db.cf_handle(CF_SMT_NODES) {
        None    => return Ok(SparseMerkleTree::new()),
        Some(c) => c,
    };
    let root_bytes = match db.get_cf(&cf, NodeKey::root().as_bytes())? {
        None    => return Ok(SparseMerkleTree::new()),
        Some(b) => b.to_vec(),
    };

    let (mut root_node, has_left, has_right) = deserialize_node(&root_bytes);
    let n_path = path_len(&root_node.path);
    let acc    = extract_node_prefix_bits(&root_node.path, n_path);
    let split  = n_path;

    root_node.left  = if has_left  { load_full_branch(db, false, split, &acc)? } else { None };
    root_node.right = if has_right { load_full_branch(db, true,  split, &acc)? } else { None };

    calc_node_hash(&mut root_node);

    Ok(SparseMerkleTree { key_length: KEY_LENGTH, root: root_node, parent_mode: false })
}

/// Recursively load a branch (and all its descendants) from `CF_SMT_NODES`.
fn load_full_branch(
    db:       &DB,
    is_right: bool,
    split:    usize,
    acc:      &BigUint,
) -> anyhow::Result<Option<Arc<Branch>>> {
    let child_acc = if is_right {
        acc | (BigUint::from(1u8) << split)
    } else {
        acc.clone()
    };
    let nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    let bytes = match db.get_cf(&cf, nk.as_bytes())? {
        None    => return Ok(None),
        Some(b) => b.to_vec(),
    };

    if bytes[0] == TAG_LEAF {
        let mut leaf = deserialize_leaf(&bytes);
        if leaf.hash_cache.is_none() {
            leaf.hash_cache = Some(calc_leaf_hash(&mut leaf));
        }
        return Ok(Some(Arc::new(Branch::Leaf(leaf))));
    }

    debug_assert_eq!(bytes[0], TAG_NODE);
    let (mut node, has_left, has_right) = deserialize_node(&bytes);
    let n_path      = path_len(&node.path);
    let prefix_bits = extract_node_prefix_bits(&node.path, n_path);
    let base_acc    = &child_acc | (prefix_bits << split);
    let node_split  = split + n_path;

    node.left  = if has_left  { load_full_branch(db, false, node_split, &base_acc)? } else { None };
    node.right = if has_right { load_full_branch(db, true,  node_split, &base_acc)? } else { None };

    calc_node_hash(&mut node);

    Ok(Some(Arc::new(Branch::Node(node))))
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

fn read_root_hash(db: &DB) -> anyhow::Result<Option<[u8; 34]>> {
    let cf = match db.cf_handle(CF_SMT_META) {
        None    => return Ok(None),
        Some(c) => c,
    };
    match db.get_cf(&cf, KEY_ROOT_HASH)? {
        None => Ok(None),
        Some(v) if v.len() == 34 => Ok(Some(v[..].try_into().unwrap())),
        Some(v) => anyhow::bail!("unexpected root hash length: {}", v.len()),
    }
}

fn load_all_leaves(db: &DB) -> anyhow::Result<Vec<(SmtPath, Vec<u8>)>> {
    let cf = match db.cf_handle(CF_SMT_LEAVES) {
        None    => return Ok(vec![]),
        Some(c) => c,
    };
    let mut leaves = Vec::new();
    for item in db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
        let (key, value) = item?;
        let path = BigUint::from_bytes_be(&key);
        leaves.push((path, value.to_vec()));
    }
    Ok(leaves)
}
