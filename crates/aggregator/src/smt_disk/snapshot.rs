//! Disk-backed speculative snapshot for one round.
//!
//! Unlike `SmtSnapshot` (which deep-clones the entire in-memory tree),
//! `DiskSmtSnapshot` accumulates pending insertions and a write overlay.
//! Nothing touches the committed DB state until `commit()` is called.
//!
//! ## Duplicate detection
//!
//! Within a single round, duplicates are detected via `pending_set`.
//! Duplicates that already exist in the committed DB are detected lazily by
//! rsmt's `batch_insert` (they will be silently skipped at flush time).

use std::collections::HashSet;
use rsmt::path::SmtPath;
use rsmt::tree::SmtError;
use rsmt::hash::build_imprint;
use rsmt::tree::calc_node_hash;
use rsmt::consistency::batch_insert;

use super::store::DiskBackedSmt;
use super::overlay::Overlay;
use super::materializer::materialize_for_batch;
use super::persister::persist_tree;

/// Speculative working copy of the disk-backed SMT for one round.
pub struct DiskSmtSnapshot<'a> {
    store:       &'a mut DiskBackedSmt,
    /// Mutations accumulated so far (flushed on demand).
    overlay:     Overlay,
    /// Keys inserted in this round (for within-round duplicate detection).
    pending_set: HashSet<SmtPath>,
    /// Pending items not yet flushed to overlay.
    pending:     Vec<(SmtPath, Vec<u8>)>,
    /// Cached root hash after the most recent flush; None = pending not flushed yet.
    cached_root: Option<[u8; 34]>,
}

impl<'a> DiskSmtSnapshot<'a> {
    /// Create a snapshot bound to `store`.
    pub fn create(store: &'a mut DiskBackedSmt) -> Self {
        let initial_root = store.root_hash_imprint();
        Self {
            store,
            overlay:     Overlay::new(),
            pending_set: HashSet::new(),
            pending:     Vec::new(),
            cached_root: Some(initial_root),
        }
    }

    /// Add a single leaf to the snapshot (deferred; flushed at root_hash or commit).
    ///
    /// Returns `SmtError::DuplicateLeaf` if the same key was already inserted
    /// in this round.  DB-level duplicates are detected during the flush.
    pub fn add_leaf(&mut self, path: SmtPath, value: Vec<u8>) -> Result<(), SmtError> {
        if self.pending_set.contains(&path) {
            return Err(SmtError::DuplicateLeaf);
        }
        self.pending_set.insert(path.clone());
        self.pending.push((path, value));
        self.cached_root = None; // pending not yet reflected in root
        Ok(())
    }

    /// Current working root hash imprint (34 bytes).
    /// Flushes pending items if needed.
    pub fn root_hash_imprint(&mut self) -> anyhow::Result<[u8; 34]> {
        self.flush_pending()?;
        Ok(self.cached_root.unwrap_or_else(|| self.store.root_hash_imprint()))
    }

    /// Commit this snapshot to the store.
    /// Flushes any pending items and atomically writes the overlay to RocksDB.
    pub fn commit(mut self, new_root: [u8; 34]) -> anyhow::Result<()> {
        self.flush_pending()?;
        let overlay = self.overlay;
        self.store.commit_overlay(overlay, new_root)
    }

    /// Discard this snapshot without committing.
    pub fn discard(self) {
        // overlay and pending are dropped.
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    fn flush_pending(&mut self) -> anyhow::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);

        // Materialize using the current overlay so we see items from previous flushes.
        let (mut smt, old_keys) = materialize_for_batch(
            &self.store.db,
            &self.store.cache,
            &self.overlay,
            &pending,
            self.store.key_length,
        )?;

        batch_insert(&mut smt, &pending)?;

        let raw  = calc_node_hash(&mut smt.root);
        let root = build_imprint(&raw);

        persist_tree(&mut smt, &old_keys, &mut self.overlay);

        self.cached_root = Some(root);
        Ok(())
    }
}
