//! Disk-backed SMT store: coordinates materialization, rsmt operations,
//! persistence, and commits.

use rocksdb::{Snapshot, WriteBatch, DB};
use rsmt::consistency::batch_insert;
use rsmt::path::SmtKey;
use rsmt::proof::InclusionProof;
use rsmt::NonInclusionProofOutcome;
use std::sync::Arc;

use super::materializer::{
    materialize_for_batch, materialize_for_keys, materialize_for_proof, SnapshotNodeReader,
    CF_SMT_NODES,
};
use super::overlay::Overlay;
use super::persister::persist_modified;
use crate::traits::CertifiedSmtSnapshot;

pub const CF_SMT_META: &str = "smt_meta";
const KEY_ROOT_HASH: &[u8] = b"root_hash";

// ─── DiskSmt ──────────────────────────────────────────────────────────────────

/// Disk-backed Sparse Merkle Tree.
pub struct DiskSmt {
    pub db: Arc<DB>,
    /// Committed root hash (None = empty tree).
    pub current_root: Option<[u8; 32]>,
}

impl DiskSmt {
    /// Open an existing DB, reading the committed root hash from `smt_meta`.
    pub fn open(db: Arc<DB>, _cache_capacity: usize) -> anyhow::Result<Self> {
        let current_root = read_root_hash(&db)?;
        Ok(Self { db, current_root })
    }

    /// Insert a batch without generating a consistency proof.
    ///
    /// Returns `(new_root, overlay)`. The overlay must be committed (or discarded).
    pub fn batch_insert_round(
        &self,
        batch: &[(SmtKey, Vec<u8>)],
    ) -> anyhow::Result<(Option<[u8; 32]>, Overlay)> {
        let empty_overlay = Overlay::new();

        let mut smt = materialize_for_batch(&self.db, &empty_overlay, None, batch)?;

        batch_insert(&mut smt, batch)?;

        let root = smt.root_hash();
        let mut overlay = Overlay::new();
        persist_modified(&smt, &mut overlay);

        Ok((root, overlay))
    }

    /// Generate an inclusion proof for `key`.
    pub fn get_inclusion_proof(
        &self,
        key: &SmtKey,
        overlay: &Overlay,
    ) -> anyhow::Result<InclusionProof> {
        let smt = materialize_for_proof(&self.db, overlay, None, key)?;
        smt.get_inclusion_proof(key)
            .map_err(|e| anyhow::anyhow!("get_inclusion_proof: {e}"))
    }

    /// Generate a non-inclusion proof for `key` from the live committed state.
    pub fn get_non_inclusion_proof(
        &self,
        key: &SmtKey,
        overlay: &Overlay,
    ) -> anyhow::Result<NonInclusionProofOutcome> {
        let smt = materialize_for_proof(&self.db, overlay, None, key)?;
        smt.get_non_inclusion_proof(key)
            .map_err(|error| anyhow::anyhow!("get_non_inclusion_proof: {error}"))
    }

    /// Generate inclusion proofs for multiple keys.
    pub fn get_inclusion_proofs_batch(
        &mut self,
        keys: &[SmtKey],
    ) -> anyhow::Result<Vec<InclusionProof>> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        let empty = Overlay::new();
        let smt = materialize_for_keys(&self.db, &empty, None, keys)?;
        keys.iter()
            .map(|k| {
                smt.get_inclusion_proof(k)
                    .map_err(|e| anyhow::anyhow!("get_inclusion_proof: {e}"))
            })
            .collect()
    }

    /// Commit an overlay to RocksDB and update the root hash.
    pub fn commit_overlay(
        &mut self,
        overlay: Overlay,
        new_root: Option<[u8; 32]>,
    ) -> anyhow::Result<()> {
        let cf_nodes = self
            .db
            .cf_handle(CF_SMT_NODES)
            .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
        let cf_meta = self
            .db
            .cf_handle(CF_SMT_META)
            .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_META))?;

        let mut batch = WriteBatch::default();

        for (key, val_opt) in overlay.into_nodes() {
            match val_opt {
                Some(val) => batch.put_cf(&cf_nodes, &key, &val),
                None => batch.delete_cf(&cf_nodes, &key),
            }
        }

        if let Some(h) = new_root {
            batch.put_cf(&cf_meta, KEY_ROOT_HASH, &h);
        }
        self.db.write(batch)?;
        self.current_root = new_root;
        Ok(())
    }

    /// Return the committed root hash.
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.current_root
    }
}

impl crate::traits::SmtStore for DiskSmt {
    type Snapshot = super::snapshot::DiskSmtSnapshot;

    fn root_hash(&self) -> Option<[u8; 32]> {
        self.root_hash()
    }

    fn create_snapshot(&self) -> super::snapshot::DiskSmtSnapshot {
        super::snapshot::DiskSmtSnapshot::create(self)
    }

    fn create_certified_snapshot(&self) -> anyhow::Result<CertifiedSmtSnapshot> {
        let db = Arc::clone(&self.db);
        let root = self.current_root;
        CertifiedSmtSnapshot::spawn_worker(root, "smt-proof-rocksdb", move |requests, ready| {
            let snapshot = db.snapshot();
            let pinned_root = match read_root_hash_from_snapshot(db.as_ref(), &snapshot) {
                Ok(pinned_root) => pinned_root,
                Err(error) => {
                    let _ = ready.send(Err(format!(
                        "failed to read root from certified RocksDB snapshot: {error}"
                    )));
                    return;
                }
            };
            if pinned_root != root {
                let _ = ready.send(Err(format!(
                    "certified RocksDB snapshot root mismatch: expected {:?}, got {:?}",
                    root.map(hex::encode),
                    pinned_root.map(hex::encode),
                )));
                return;
            }

            let reader = SnapshotNodeReader::new(db.as_ref(), &snapshot);
            if ready.send(Ok(())).is_err() {
                return;
            }
            let empty_overlay = Overlay::new();
            for request in requests {
                let result = materialize_for_proof(&reader, &empty_overlay, None, &request.key)
                    .and_then(|tree| {
                        tree.get_non_inclusion_proof(&request.key)
                            .map_err(|error| anyhow::anyhow!(error))
                    });
                let _ = request.respond_to.send(result);
            }
        })
    }

    fn get_inclusion_proof(&mut self, key: &SmtKey) -> anyhow::Result<InclusionProof> {
        let empty_overlay = Overlay::new();
        DiskSmt::get_inclusion_proof(self, key, &empty_overlay)
    }

    fn get_non_inclusion_proof(
        &mut self,
        key: &SmtKey,
    ) -> anyhow::Result<NonInclusionProofOutcome> {
        let empty_overlay = Overlay::new();
        DiskSmt::get_non_inclusion_proof(self, key, &empty_overlay)
    }

    fn get_inclusion_proofs_batch(
        &mut self,
        keys: &[SmtKey],
    ) -> anyhow::Result<Vec<InclusionProof>> {
        DiskSmt::get_inclusion_proofs_batch(self, keys)
    }
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

fn read_root_hash(db: &DB) -> anyhow::Result<Option<[u8; 32]>> {
    let cf = match db.cf_handle(CF_SMT_META) {
        None => return Ok(None),
        Some(c) => c,
    };
    decode_root_hash(db.get_cf(&cf, KEY_ROOT_HASH)?)
}

fn read_root_hash_from_snapshot(
    db: &DB,
    snapshot: &Snapshot<'_>,
) -> anyhow::Result<Option<[u8; 32]>> {
    let cf = match db.cf_handle(CF_SMT_META) {
        None => return Ok(None),
        Some(cf) => cf,
    };
    decode_root_hash(snapshot.get_cf(&cf, KEY_ROOT_HASH)?)
}

fn decode_root_hash(value: Option<Vec<u8>>) -> anyhow::Result<Option<[u8; 32]>> {
    match value {
        None => Ok(None),
        Some(value) if value.len() == 32 => Ok(Some(value[..].try_into()?)),
        Some(value) if value.len() == 34 => Ok(Some(value[2..].try_into()?)),
        Some(value) => anyhow::bail!("unexpected root hash length: {}", value.len()),
    }
}
