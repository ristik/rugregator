//! Disk-backed speculative snapshot for one round.

use std::collections::HashSet;
use std::sync::Arc;
use rocksdb::DB;
use rsmt::path::SmtKey;
use rsmt::tree::SmtError;
use rsmt::SmtHasher;
use rsmt::consistency::{batch_insert, batch_insert_with};

use super::store::DiskSmt;
use super::overlay::Overlay;
use super::materializer::materialize_for_batch;
use super::persister::persist_modified;

/// Speculative working copy of the disk-backed SMT for one round.
pub struct DiskSmtSnapshot {
    db:             Arc<DB>,
    own_overlay:    Overlay,
    parent_overlay: Option<Arc<Overlay>>,
    pending_set:    HashSet<SmtKey>,
    pending:        Vec<(SmtKey, Vec<u8>)>,
    pub(crate) cached_root: Option<Option<[u8; 32]>>,
}

impl DiskSmtSnapshot {
    /// Create a snapshot from the current committed state of `store`.
    pub fn create(store: &DiskSmt) -> Self {
        Self {
            db:             Arc::clone(&store.db),
            own_overlay:    Overlay::new(),
            parent_overlay: None,
            pending_set:    HashSet::new(),
            pending:        Vec::new(),
            cached_root:    Some(store.current_root),
        }
    }

    /// Add a single leaf to the snapshot (deferred).
    pub fn add_leaf_inner(&mut self, key: SmtKey, value: Vec<u8>) -> Result<(), SmtError> {
        if self.pending_set.contains(&key) {
            return Err(SmtError::DuplicateLeaf);
        }
        self.pending_set.insert(key);
        self.pending.push((key, value));
        self.cached_root = None;
        Ok(())
    }

    /// Current working root hash.
    pub fn root_hash_inner(&mut self) -> anyhow::Result<Option<[u8; 32]>> {
        self.flush_pending()?;
        Ok(self.cached_root.flatten())
    }

    /// Fork this snapshot into a speculative copy for the next round.
    pub fn fork_inner(&mut self) -> Self {
        if let Err(e) = self.flush_pending() {
            tracing::warn!("DiskSmtSnapshot::fork: flush_pending failed: {e}");
        }
        let parent = Arc::new(self.own_overlay.clone());
        Self {
            db:             Arc::clone(&self.db),
            own_overlay:    Overlay::new(),
            parent_overlay: Some(parent),
            pending_set:    HashSet::new(),
            pending:        Vec::new(),
            cached_root:    self.cached_root,
        }
    }

    /// Commit this snapshot to `store`.
    pub fn commit_inner(mut self, store: &mut DiskSmt, new_root: Option<[u8; 32]>) -> anyhow::Result<()> {
        self.flush_pending()?;
        store.commit_overlay(self.own_overlay, new_root)
    }

    /// Discard this snapshot without committing.
    pub fn discard_inner(self) {}

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
        )?;

        batch_insert(&mut smt, &pending)?;

        let root = smt.root_hash();
        persist_modified(&smt, &mut self.own_overlay);

        self.cached_root = Some(root);

        Ok(())
    }

    fn flush_pending_with<H: SmtHasher>(&mut self) -> anyhow::Result<()> {
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
        )?;

        batch_insert_with::<H>(&mut smt, &pending)?;

        let root = smt.root_hash();
        persist_modified(&smt, &mut self.own_overlay);

        self.cached_root = Some(root);

        Ok(())
    }
}

impl crate::traits::SmtStoreSnapshot for DiskSmtSnapshot {
    type Store = DiskSmt;

    fn add_leaf(&mut self, key: SmtKey, value: Vec<u8>) -> Result<(), SmtError> {
        self.add_leaf_inner(key, value)
    }

    fn root_hash(&mut self) -> anyhow::Result<Option<[u8; 32]>> {
        self.root_hash_inner()
    }

    fn fork(&mut self) -> Self {
        self.fork_inner()
    }

    fn commit(self, store: &mut DiskSmt) -> anyhow::Result<()> {
        let root = self.cached_root.flatten().or(store.current_root);
        self.commit_inner(store, root)
    }

    fn discard(self) {
        self.discard_inner()
    }

    fn insert_batch_with<H: SmtHasher>(
        &mut self,
        batch: &[(SmtKey, Vec<u8>)],
        _with_proof: bool,
    ) -> anyhow::Result<(Vec<bool>, Option<Vec<u8>>)> {
        let mut flags = vec![false; batch.len()];
        for (i, (key, value)) in batch.iter().enumerate() {
            match self.add_leaf_inner(*key, value.clone()) {
                Ok(()) => flags[i] = true,
                Err(rsmt::tree::SmtError::DuplicateLeaf) => {}
                Err(e) => return Err(anyhow::anyhow!("add_leaf failed: {e}")),
            }
        }
        self.flush_pending_with::<H>()?;
        Ok((flags, None))
    }
}
