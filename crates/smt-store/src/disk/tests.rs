//! Integration tests for the disk-backed SMT.

#![cfg(test)]

use std::sync::Arc;
use rsmt::path::SmtKey;
use rsmt::{SparseMerkleTree, consistency::batch_insert as mem_batch_insert, verify_inclusion};
use rocksdb::{DB, Options, ColumnFamilyDescriptor, DBCompressionType};

use super::store::{DiskSmt, CF_SMT_META};
use super::materializer::CF_SMT_NODES;

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn open_test_db(dir: &tempfile::TempDir) -> Arc<DB> {
    let path = dir.path().to_str().unwrap();
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    let mut node_opts = Options::default();
    node_opts.set_compression_type(DBCompressionType::Lz4);

    let cfs = [
        ColumnFamilyDescriptor::new("records",   Options::default()),
        ColumnFamilyDescriptor::new("blocks",    Options::default()),
        ColumnFamilyDescriptor::new("meta",      Options::default()),
        ColumnFamilyDescriptor::new(CF_SMT_NODES, node_opts),
        ColumnFamilyDescriptor::new(CF_SMT_META,  Options::default()),
    ];
    Arc::new(DB::open_cf_descriptors(&opts, path, cfs.into_iter()).unwrap())
}

fn make_key(byte: u8) -> SmtKey {
    let mut k = [0u8; 32];
    k[0] = byte;
    k
}

fn batch(n: u8) -> Vec<(SmtKey, Vec<u8>)> {
    (1..=n).map(|i| (make_key(i), vec![i; 32])).collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn root_hash_equivalence_single_batch() {
    let dir = tempfile::tempdir().unwrap();
    let db  = open_test_db(&dir);

    let pairs = batch(8);

    // In-memory reference.
    let mut mem_smt = SparseMerkleTree::new();
    mem_batch_insert(&mut mem_smt, &pairs).unwrap();
    let expected_root = mem_smt.root_hash();

    // Disk-backed.
    let mut disk = DiskSmt::open(db, 10_000).unwrap();
    let (new_root, overlay) = disk.batch_insert_round(&pairs).unwrap();
    disk.commit_overlay(overlay, new_root).unwrap();

    assert_eq!(new_root, expected_root, "disk root must match in-memory root");
}

#[test]
fn root_hash_equivalence_multi_round() {
    let dir   = tempfile::tempdir().unwrap();
    let db    = open_test_db(&dir);
    let mut disk = DiskSmt::open(db, 10_000).unwrap();

    let mut mem_smt = SparseMerkleTree::new();

    for r in 0u8..5 {
        let pairs: Vec<_> = (0u8..10).map(|i| (make_key(r*10+i), vec![r*10+i; 32])).collect();

        // In-memory.
        mem_batch_insert(&mut mem_smt, &pairs).unwrap();
        let expected = mem_smt.root_hash();

        // Disk-backed.
        let (new_root, overlay) = disk.batch_insert_round(&pairs).unwrap();
        disk.commit_overlay(overlay, new_root).unwrap();

        assert_eq!(new_root, expected, "round {r}: disk root must match in-memory");
    }
}

#[test]
fn rollback_leaves_db_unchanged() {
    let dir   = tempfile::tempdir().unwrap();
    let db    = open_test_db(&dir);
    let mut disk = DiskSmt::open(Arc::clone(&db), 10_000).unwrap();

    // Initial insert.
    let pairs1 = batch(4);
    let (root1, overlay1) = disk.batch_insert_round(&pairs1).unwrap();
    disk.commit_overlay(overlay1, root1).unwrap();

    let committed_root = disk.root_hash();

    // Speculative insert — discard.
    let pairs2 = batch(8);
    let (_new_root, _overlay2) = disk.batch_insert_round(&pairs2).unwrap();

    // Re-open from DB.
    let disk2 = DiskSmt::open(db, 10_000).unwrap();
    assert_eq!(disk2.root_hash(), committed_root,
        "root hash must be unchanged after discarded overlay");
}

#[test]
fn commit_then_reload_root_survives() {
    let dir = tempfile::tempdir().unwrap();
    let pairs = batch(6);
    let committed_root;

    {
        let db   = open_test_db(&dir);
        let mut disk = DiskSmt::open(db, 1_000).unwrap();
        let (root, overlay) = disk.batch_insert_round(&pairs).unwrap();
        disk.commit_overlay(overlay, root).unwrap();
        committed_root = root;
    }

    {
        let db = open_test_db(&dir);
        let disk = DiskSmt::open(db, 1_000).unwrap();
        assert_eq!(disk.root_hash(), committed_root,
            "root hash must survive DB reopen");
    }
}

#[test]
fn proof_equivalence() {
    let dir   = tempfile::tempdir().unwrap();
    let db    = open_test_db(&dir);
    let mut disk = DiskSmt::open(db, 10_000).unwrap();

    let pairs = batch(4);

    // In-memory reference.
    let mut mem_smt = SparseMerkleTree::new();
    mem_batch_insert(&mut mem_smt, &pairs).unwrap();
    let mem_root = mem_smt.root_hash().unwrap();

    // Disk-backed insert and commit.
    let (root, overlay) = disk.batch_insert_round(&pairs).unwrap();
    disk.commit_overlay(overlay, root).unwrap();

    use super::overlay::Overlay;
    let empty = Overlay::new();

    // Compare proofs for each inserted leaf.
    for (key, value) in &pairs {
        let mem_proof  = mem_smt.get_inclusion_proof(key).unwrap();
        let disk_proof = disk.get_inclusion_proof(key, &empty).unwrap();

        // Both proofs should verify against the same root.
        assert!(verify_inclusion(&mem_proof, &mem_root, key, value));
        assert!(verify_inclusion(&disk_proof, &root.unwrap(), key, value));

        // Proofs should be identical.
        assert_eq!(mem_proof.bitmap, disk_proof.bitmap, "bitmap mismatch for key");
        assert_eq!(mem_proof.siblings, disk_proof.siblings, "siblings mismatch for key");
    }
}
