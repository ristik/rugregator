//! Disk-backed speculative snapshot for one round.

use rocksdb::DB;
use rsmt::consistency::{
    batch_insert, batch_insert_with, batch_insert_with_proof_with, encode_aggregator_envelope_v1,
};
use rsmt::path::SmtKey;
use rsmt::tree::SmtError;
use rsmt::SmtHasher;
use std::collections::HashSet;
use std::sync::Arc;

use super::materializer::materialize_for_batch;
use super::overlay::Overlay;
use super::persister::persist_modified;
use super::store::DiskSmt;

/// Speculative working copy of the disk-backed SMT for one round.
pub struct DiskSmtSnapshot {
    db: Arc<DB>,
    own_overlay: Overlay,
    parent_overlay: Option<Arc<Overlay>>,
    pending_set: HashSet<SmtKey>,
    pending: Vec<(SmtKey, Vec<u8>)>,
    pub(crate) cached_root: Option<Option<[u8; 32]>>,
}

impl DiskSmtSnapshot {
    /// Create a snapshot from the current committed state of `store`.
    pub fn create(store: &DiskSmt) -> Self {
        Self {
            db: Arc::clone(&store.db),
            own_overlay: Overlay::new(),
            parent_overlay: None,
            pending_set: HashSet::new(),
            pending: Vec::new(),
            cached_root: Some(store.current_root),
        }
    }

    /// Add a single leaf to the snapshot (deferred).
    pub fn add_leaf_inner(&mut self, key: SmtKey, value: Vec<u8>) -> Result<(), SmtError> {
        if self.pending_set.contains(&key) {
            return Err(SmtError::DuplicateLeaf);
        }

        // Verify leaf does not exist in the DB / overlays to accurately drop duplicates
        // before deferring to the pending batch.
        let parent = self.parent_overlay.as_deref();
        let smt = super::materializer::materialize_for_proof(
            &self.db,
            &self.own_overlay,
            parent,
            &key,
        ).map_err(|e| {
            tracing::error!("materialize_for_proof failed in add_leaf: {e}");
            rsmt::tree::SmtError::LeafNotFound
        })?;

        if smt.find_leaf(&key).is_some() {
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
            db: Arc::clone(&self.db),
            own_overlay: Overlay::new(),
            parent_overlay: Some(parent),
            pending_set: HashSet::new(),
            pending: Vec::new(),
            cached_root: self.cached_root,
        }
    }

    /// Commit this snapshot to `store`.
    pub fn commit_inner(
        mut self,
        store: &mut DiskSmt,
        new_root: Option<[u8; 32]>,
    ) -> anyhow::Result<()> {
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

        let mut smt = materialize_for_batch(&self.db, &self.own_overlay, parent, &pending)?;

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

        let mut smt = materialize_for_batch(&self.db, &self.own_overlay, parent, &pending)?;

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

    fn insert_batch(
        &mut self,
        batch: &[(SmtKey, Vec<u8>)],
        with_proof: bool,
    ) -> anyhow::Result<(Vec<bool>, Option<Vec<u8>>)> {
        // Delegate to the hasher-generic path so the aggregator envelope is
        // produced for the disk backend too. Without this override, the
        // trait default would silently fall back to an add_leaf loop that
        // returns None for the proof and breaks BFT Core verification.
        self.insert_batch_with::<rsmt::Sha256Hasher>(batch, with_proof)
    }

    fn insert_batch_with<H: SmtHasher>(
        &mut self,
        batch: &[(SmtKey, Vec<u8>)],
        with_proof: bool,
    ) -> anyhow::Result<(Vec<bool>, Option<Vec<u8>>)> {
        // Flush any previously deferred leaves so that own_overlay is up to date.
        self.flush_pending_with::<H>()?;

        let mut flags = vec![false; batch.len()];
        let mut unique_pending = Vec::new();
        let mut batch_idx_map = Vec::new();

        for (i, (key, value)) in batch.iter().enumerate() {
            // Prevent intra-batch and intra-round duplicates
            if !self.pending_set.contains(key) {
                self.pending_set.insert(*key);
                unique_pending.push((*key, value.clone()));
                batch_idx_map.push(i);
            }
        }

        if unique_pending.is_empty() {
            return Ok((flags, None));
        }

        let parent = self.parent_overlay.as_deref();
        let mut smt = materialize_for_batch(&self.db, &self.own_overlay, parent, &unique_pending)?;

        let (inserted_pairs, proof_opt) = if with_proof {
            let (pairs, p) = batch_insert_with_proof_with::<H>(&mut smt, &unique_pending)?;
            // Bundle the sorted batch with the opcode stream into the
            // aggregator_rsmt_v1 envelope expected by BFT Core.
            let envelope = encode_aggregator_envelope_v1(&pairs, &p);
            (pairs, Some(envelope))
        } else {
            let pairs = batch_insert_with::<H>(&mut smt, &unique_pending)?;
            (pairs, None)
        };

        // Map inserted_pairs back to original batch indices in O(N).
        let inserted_set: std::collections::HashSet<SmtKey> =
            inserted_pairs.iter().map(|(k, _)| *k).collect();
        for (i, (key, _)) in unique_pending.iter().enumerate() {
            if inserted_set.contains(key) {
                flags[batch_idx_map[i]] = true;
            }
        }

        let root = smt.root_hash();
        persist_modified(&smt, &mut self.own_overlay);
        self.cached_root = Some(root);

        Ok((flags, proof_opt))
    }
}
