//! Disk-backed speculative snapshot for one round.

use std::collections::HashSet;
use std::sync::Arc;
use rocksdb::DB;
use rsmt::path::SmtPath;
use rsmt::tree::SmtError;
use rsmt::hash::build_imprint;
use rsmt::tree::calc_node_hash;
use rsmt::consistency::batch_insert;

use super::store::DiskSmt;
use super::overlay::Overlay;
use super::materializer::materialize_for_batch;
use super::persister::persist_modified;

/// Speculative working copy of the disk-backed SMT for one round.
pub struct DiskSmtSnapshot {
    db:             Arc<DB>,
    key_length:     usize,
    own_overlay:    Overlay,
    parent_overlay: Option<Arc<Overlay>>,
    pending_set:    HashSet<SmtPath>,
    pending:        Vec<(SmtPath, Vec<u8>)>,
    pub(crate) cached_root: Option<[u8; 34]>,
}

impl DiskSmtSnapshot {
    /// Create a snapshot from the current committed state of `store`.
    pub fn create(store: &DiskSmt) -> Self {
        Self {
            db:             Arc::clone(&store.db),
            key_length:     store.key_length,
            own_overlay:    Overlay::new(),
            parent_overlay: None,
            pending_set:    HashSet::new(),
            pending:        Vec::new(),
            cached_root:    Some(store.root_hash_imprint()),
        }
    }

    /// Add a single leaf to the snapshot (deferred).
    pub fn add_leaf_inner(&mut self, path: SmtPath, value: Vec<u8>) -> Result<(), SmtError> {
        if self.pending_set.contains(&path) {
            return Err(SmtError::DuplicateLeaf);
        }
        self.pending_set.insert(path.clone());
        self.pending.push((path, value));
        self.cached_root = None;
        Ok(())
    }

    /// Current working root hash imprint (34 bytes).
    pub fn root_hash_imprint_inner(&mut self) -> anyhow::Result<[u8; 34]> {
        self.flush_pending()?;
        Ok(self.cached_root.unwrap_or_else(|| build_imprint(&[0u8; 32])))
    }

    /// Fork this snapshot into a speculative copy for the next round.
    pub fn fork_inner(&mut self) -> Self {
        if let Err(e) = self.flush_pending() {
            tracing::warn!("DiskSmtSnapshot::fork: flush_pending failed: {e}");
        }
        let parent = Arc::new(self.own_overlay.clone());
        Self {
            db:             Arc::clone(&self.db),
            key_length:     self.key_length,
            own_overlay:    Overlay::new(),
            parent_overlay: Some(parent),
            pending_set:    HashSet::new(),
            pending:        Vec::new(),
            cached_root:    self.cached_root,
        }
    }

    /// Commit this snapshot to `store`.
    pub fn commit_inner(mut self, store: &mut DiskSmt, new_root: [u8; 34]) -> anyhow::Result<()> {
        self.flush_pending()?;
        store.commit_overlay(self.own_overlay, new_root)
    }

    /// Discard this snapshot without committing.
    pub fn discard_inner(self) {
        // own_overlay, pending, and parent_overlay (Arc) are all dropped here.
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    fn flush_pending(&mut self) -> anyhow::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);

        let parent = self.parent_overlay.as_deref();

        let mut smt = materialize_for_batch(
            &self.db,
            &self.own_overlay,
            parent,
            &pending,
            self.key_length,
        )?;

        batch_insert(&mut smt, &pending)?;

        let raw  = calc_node_hash(&mut smt.root);
        let root = build_imprint(&raw);

        persist_modified(&mut smt, &mut self.own_overlay);

        self.cached_root = Some(root);
        Ok(())
    }
}

impl crate::traits::SmtStoreSnapshot for DiskSmtSnapshot {
    type Store = DiskSmt;

    fn add_leaf(&mut self, path: SmtPath, value: Vec<u8>) -> Result<(), SmtError> {
        self.add_leaf_inner(path, value)
    }

    fn root_hash_imprint(&mut self) -> anyhow::Result<[u8; 34]> {
        self.root_hash_imprint_inner()
    }

    fn fork(&mut self) -> Self {
        self.fork_inner()
    }

    fn commit(self, store: &mut DiskSmt) -> anyhow::Result<()> {
        let root = self.cached_root.unwrap_or_else(|| store.root_hash_imprint());
        self.commit_inner(store, root)
    }

    fn discard(self) {
        self.discard_inner()
    }
}
