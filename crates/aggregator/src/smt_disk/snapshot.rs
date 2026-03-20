//! Disk-backed speculative snapshot for one round.
//!
//! Unlike `SmtSnapshot` (which CoW-clones the in-memory tree root),
//! `DiskSmtSnapshot` accumulates pending insertions into an in-memory overlay
//! and only touches RocksDB at commit time.
//!
//! ## Speculative execution (fork)
//!
//! `fork()` creates a child snapshot that reads through the parent's flushed
//! overlay (`parent_overlay`) before hitting the cache or DB.  This lets the
//! speculative next-round work run while waiting for the BFT UC without
//! performing any DB writes.
//!
//! Read priority inside the child:
//! ```text
//! own_overlay → parent_overlay → LRU cache → RocksDB
//! ```
//!
//! When the proposed round commits its overlay to DB, the `parent_overlay`
//! entries are now in the DB — the child's subsequent reads are equivalent
//! whether they go through `parent_overlay` or directly to DB.
//!
//! ## Duplicate detection
//!
//! Within a single round, duplicates are detected via `pending_set`.
//! Duplicates already present in the committed DB (or parent overlay) are
//! detected lazily by rsmt's `batch_insert` during `flush_pending`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use rocksdb::DB;
use rsmt::path::SmtPath;
use rsmt::tree::SmtError;
use rsmt::hash::build_imprint;
use rsmt::tree::calc_node_hash;
use rsmt::consistency::batch_insert;

use super::store::DiskBackedSmt;
use super::overlay::Overlay;
use super::cache::NodeCache;
use super::materializer::materialize_for_batch;
use super::persister::persist_tree;

/// Speculative working copy of the disk-backed SMT for one round.
///
/// Owns all the resources it needs (no lifetime constraint on the store).
/// Can be stored in `InFlightDiskRound` while waiting for a UC.
pub struct DiskSmtSnapshot {
    db:             Arc<DB>,
    cache:          Arc<Mutex<NodeCache>>,
    key_length:     usize,
    /// Mutations accumulated by this snapshot.
    own_overlay:    Overlay,
    /// Parent snapshot's flushed overlay (read-through for forked snapshots).
    /// `None` for snapshots created directly from a committed DB state.
    parent_overlay: Option<Arc<Overlay>>,
    /// Keys inserted in this round (for within-round duplicate detection).
    pending_set:    HashSet<SmtPath>,
    /// Pending items not yet flushed to overlay.
    pending:        Vec<(SmtPath, Vec<u8>)>,
    /// Cached root hash after the most recent flush; None = pending not flushed yet.
    cached_root:    Option<[u8; 34]>,
}

impl DiskSmtSnapshot {
    /// Create a snapshot from the current committed state of `store`.
    pub fn create(store: &DiskBackedSmt) -> Self {
        Self {
            db:             Arc::clone(&store.db),
            cache:          Arc::clone(&store.cache),
            key_length:     store.key_length,
            own_overlay:    Overlay::new(),
            parent_overlay: None,
            pending_set:    HashSet::new(),
            pending:        Vec::new(),
            cached_root:    Some(store.root_hash_imprint()),
        }
    }

    /// Add a single leaf to the snapshot (deferred; flushed at root_hash or commit).
    ///
    /// Returns `SmtError::DuplicateLeaf` if the same key was already inserted
    /// in this round.
    pub fn add_leaf(&mut self, path: SmtPath, value: Vec<u8>) -> Result<(), SmtError> {
        if self.pending_set.contains(&path) {
            return Err(SmtError::DuplicateLeaf);
        }
        self.pending_set.insert(path.clone());
        self.pending.push((path, value));
        self.cached_root = None;
        Ok(())
    }

    /// Current working root hash imprint (34 bytes).
    /// Flushes pending items if needed.
    pub fn root_hash_imprint(&mut self) -> anyhow::Result<[u8; 34]> {
        self.flush_pending()?;
        Ok(self.cached_root.unwrap_or_else(|| {
            // Empty tree.
            build_imprint(&[0u8; 32])
        }))
    }

    /// Fork this snapshot into a speculative copy for the next round.
    ///
    /// Must be called after `root_hash_imprint()` (or `flush_pending()`) so
    /// that `own_overlay` reflects all insertions so far.
    ///
    /// The fork inherits this snapshot's flushed overlay as a read-through
    /// base (`parent_overlay`).  The fork itself starts with an empty
    /// `own_overlay` and accumulates only its own new mutations.
    ///
    /// Cost: O(own_overlay_size) — clones the overlay HashMap.
    pub fn fork(&mut self) -> Self {
        // Ensure all pending are in own_overlay before sharing.
        if let Err(e) = self.flush_pending() {
            tracing::warn!("DiskSmtSnapshot::fork: flush_pending failed: {e}");
        }
        // Share a clone of own_overlay as the parent for the fork.
        let parent = Arc::new(self.own_overlay.clone());
        Self {
            db:             Arc::clone(&self.db),
            cache:          Arc::clone(&self.cache),
            key_length:     self.key_length,
            own_overlay:    Overlay::new(),
            parent_overlay: Some(parent),
            pending_set:    HashSet::new(),
            pending:        Vec::new(),
            cached_root:    self.cached_root,
        }
    }

    /// Commit this snapshot to `store`.
    ///
    /// Flushes any remaining pending items, then atomically writes
    /// `own_overlay` to RocksDB and updates `store.current_root`.
    ///
    /// The `parent_overlay` (if any) is assumed to have already been committed
    /// to DB by a prior call (i.e. the proposed round was committed before
    /// promoting the spec round).
    pub fn commit(mut self, store: &mut DiskBackedSmt, new_root: [u8; 34]) -> anyhow::Result<()> {
        self.flush_pending()?;
        store.commit_overlay(self.own_overlay, new_root)
    }

    /// Discard this snapshot without committing.
    pub fn discard(self) {
        // own_overlay, pending, and parent_overlay (Arc) are all dropped here.
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    fn flush_pending(&mut self) -> anyhow::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);

        let parent = self.parent_overlay.as_deref();

        let (mut smt, old_keys) = materialize_for_batch(
            &self.db,
            &self.cache,
            &self.own_overlay,
            parent,
            &pending,
            self.key_length,
        )?;

        batch_insert(&mut smt, &pending)?;

        let raw  = calc_node_hash(&mut smt.root);
        let root = build_imprint(&raw);

        persist_tree(&mut smt, &old_keys, &mut self.own_overlay);

        self.cached_root = Some(root);
        Ok(())
    }
}
