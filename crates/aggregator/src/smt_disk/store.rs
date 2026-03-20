//! Disk-backed SMT store: coordinates materialization, rsmt operations,
//! persistence, and commits.
//!
//! `DiskBackedSmt` is the main entry point for all disk-backed SMT operations.
//! It is single-threaded (owned by the RoundManager) and does NOT need an
//! internal mutex for writes.  The cache IS shared (via `Arc<Mutex<NodeCache>>`)
//! so that future read-path sharing is possible.

use std::sync::{Arc, Mutex};
use rocksdb::{DB, WriteBatch};
use rsmt::path::SmtPath;
use rsmt::proof::MerkleTreePath;
use rsmt::calc_node_hash;
use rsmt::hash::build_imprint;
use rsmt::consistency::batch_insert;

use super::overlay::Overlay;
use super::cache::NodeCache;
use super::materializer::{CF_SMT_NODES, materialize_for_batch, materialize_for_proof};
use super::persister::persist_tree;

pub const CF_SMT_META: &str = "smt_meta";
const KEY_ROOT_HASH: &[u8] = b"root_hash";

// ─── DiskBackedSmt ────────────────────────────────────────────────────────────

/// Disk-backed Sparse Merkle Tree: persists leaves and internal nodes in
/// RocksDB, with a bounded LRU cache for recently accessed nodes.
pub struct DiskBackedSmt {
    pub db:            Arc<DB>,
    pub cache:         Arc<Mutex<NodeCache>>,
    pub key_length:    usize,
    /// Committed root hash (None = empty tree).
    pub current_root:  Option<[u8; 32]>,
}

impl DiskBackedSmt {
    /// Open an existing DB, reading the committed root hash from `smt_meta`.
    pub fn open(db: Arc<DB>, cache_capacity: usize) -> anyhow::Result<Self> {
        let cache = Arc::new(Mutex::new(NodeCache::new(cache_capacity)));
        let current_root = read_root_hash(&db)?;
        Ok(Self {
            db,
            cache,
            key_length: rsmt::tree::KEY_LENGTH,
            current_root,
        })
    }

    /// Insert a batch without generating a consistency proof.
    ///
    /// Returns `(new_root_imprint, overlay)`.  The overlay must be committed
    /// (or discarded) by the caller.
    pub fn batch_insert_round(
        &self,
        batch: &[(SmtPath, Vec<u8>)],
    ) -> anyhow::Result<([u8; 34], Overlay)> {
        let empty_overlay = Overlay::new();

        // 1. Materialize the partial tree.
        let (mut smt, old_keys) = materialize_for_batch(
            &self.db, &self.cache, &empty_overlay, None, batch, self.key_length,
        )?;

        // 2. Run rsmt batch insertion.
        batch_insert(&mut smt, batch)?;

        // 3. Compute new root hash.
        let raw = calc_node_hash(&mut smt.root);
        let imprint = build_imprint(&raw);

        // 4. Persist the new tree to overlay.
        let mut overlay = Overlay::new();
        persist_tree(&mut smt, &old_keys, &mut overlay);

        Ok((imprint, overlay))
    }

    /// Generate an inclusion proof for `leaf_key`.
    pub fn get_path(
        &self,
        leaf_key: &SmtPath,
        overlay: &Overlay,
    ) -> anyhow::Result<MerkleTreePath> {
        let mut smt = materialize_for_proof(
            &self.db, &self.cache, overlay, None, leaf_key, self.key_length,
        )?;
        smt.get_path(leaf_key).map_err(|e| anyhow::anyhow!("get_path: {e}"))
    }

    /// Commit an overlay to RocksDB and update the root hash.
    /// Call this after BFT success.
    pub fn commit_overlay(
        &mut self,
        overlay: Overlay,
        new_root: [u8; 34],
    ) -> anyhow::Result<()> {
        let cf_nodes = self.db.cf_handle(CF_SMT_NODES)
            .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
        let cf_meta  = self.db.cf_handle(CF_SMT_META)
            .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_META))?;

        let mut batch = WriteBatch::default();
        let mut cache_guard = self.cache.lock().unwrap();

        for (key, val_opt) in overlay.into_nodes() {
            match val_opt {
                Some(val) => {
                    batch.put_cf(&cf_nodes, &key, &val);
                    cache_guard.put_raw(key, val);
                }
                None => {
                    batch.delete_cf(&cf_nodes, &key);
                    cache_guard.evict_raw(&key);
                }
            }
        }

        // Persist only the raw 32-byte hash (imprint is 34 bytes with 0x00,0x00 prefix).
        batch.put_cf(&cf_meta, KEY_ROOT_HASH, &new_root);
        drop(cache_guard);
        self.db.write(batch)?;

        // Extract raw hash from imprint.
        let raw: [u8; 32] = new_root[2..].try_into().expect("imprint is 34 bytes");
        self.current_root = Some(raw);
        Ok(())
    }

    /// Return the committed root hash as a 34-byte imprint.
    pub fn root_hash_imprint(&self) -> [u8; 34] {
        match self.current_root {
            None    => build_imprint(&[0u8; 32]),
            Some(h) => build_imprint(&h),
        }
    }
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

fn read_root_hash(db: &DB) -> anyhow::Result<Option<[u8; 32]>> {
    let cf = match db.cf_handle(CF_SMT_META) {
        None    => return Ok(None),
        Some(c) => c,
    };
    match db.get_cf(&cf, KEY_ROOT_HASH)? {
        None => Ok(None),
        Some(v) => {
            if v.len() == 34 {
                // stored as imprint: skip 2-byte prefix
                let raw: [u8; 32] = v[2..].try_into()?;
                Ok(Some(raw))
            } else if v.len() == 32 {
                let raw: [u8; 32] = v[..].try_into()?;
                Ok(Some(raw))
            } else {
                anyhow::bail!("unexpected root hash length: {}", v.len())
            }
        }
    }
}
