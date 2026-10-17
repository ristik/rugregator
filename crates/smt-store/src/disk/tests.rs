//! Integration tests for the disk-backed SMT.

#![cfg(test)]

use rocksdb::{ColumnFamilyDescriptor, DBCompressionType, Options, DB};
use rsmt::path::SmtKey;
use rsmt::{
    consistency::batch_insert as mem_batch_insert, verify_inclusion, verify_non_inclusion,
    NonInclusionProofOutcome, SparseMerkleTree,
};
use std::sync::Arc;

use super::materializer::CF_SMT_NODES;
use super::store::{DiskSmt, CF_SMT_META};
use crate::traits::SmtStore;

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn open_test_db(dir: &tempfile::TempDir) -> Arc<DB> {
    let path = dir.path().to_str().unwrap();
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    let mut node_opts = Options::default();
    node_opts.set_compression_type(DBCompressionType::Lz4);

    let cfs = [
        ColumnFamilyDescriptor::new("records", Options::default()),
        ColumnFamilyDescriptor::new("blocks", Options::default()),
        ColumnFamilyDescriptor::new("meta", Options::default()),
        ColumnFamilyDescriptor::new(CF_SMT_NODES, node_opts),
        ColumnFamilyDescriptor::new(CF_SMT_META, Options::default()),
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
    let db = open_test_db(&dir);

    let pairs = batch(8);

    // In-memory reference.
    let mut mem_smt = SparseMerkleTree::new();
    mem_batch_insert(&mut mem_smt, &pairs).unwrap();
    let expected_root = mem_smt.root_hash();

    // Disk-backed.
    let mut disk = DiskSmt::open(db, 10_000).unwrap();
    let (new_root, overlay) = disk.batch_insert_round(&pairs).unwrap();
    disk.commit_overlay(overlay, new_root).unwrap();

    assert_eq!(
        new_root, expected_root,
        "disk root must match in-memory root"
    );
}

#[test]
fn root_hash_equivalence_multi_round() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_test_db(&dir);
    let mut disk = DiskSmt::open(db, 10_000).unwrap();

    let mut mem_smt = SparseMerkleTree::new();

    for r in 0u8..5 {
        let pairs: Vec<_> = (0u8..10)
            .map(|i| (make_key(r * 10 + i), vec![r * 10 + i; 32]))
            .collect();

        // In-memory.
        mem_batch_insert(&mut mem_smt, &pairs).unwrap();
        let expected = mem_smt.root_hash();

        // Disk-backed.
        let (new_root, overlay) = disk.batch_insert_round(&pairs).unwrap();
        disk.commit_overlay(overlay, new_root).unwrap();

        assert_eq!(
            new_root, expected,
            "round {r}: disk root must match in-memory"
        );
    }
}

#[test]
fn rollback_leaves_db_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_test_db(&dir);
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
    assert_eq!(
        disk2.root_hash(),
        committed_root,
        "root hash must be unchanged after discarded overlay"
    );
}

#[test]
fn commit_then_reload_root_survives() {
    let dir = tempfile::tempdir().unwrap();
    let pairs = batch(6);
    let committed_root;

    {
        let db = open_test_db(&dir);
        let mut disk = DiskSmt::open(db, 1_000).unwrap();
        let (root, overlay) = disk.batch_insert_round(&pairs).unwrap();
        disk.commit_overlay(overlay, root).unwrap();
        committed_root = root;
    }

    {
        let db = open_test_db(&dir);
        let disk = DiskSmt::open(db, 1_000).unwrap();
        assert_eq!(
            disk.root_hash(),
            committed_root,
            "root hash must survive DB reopen"
        );
    }
}

#[test]
fn proof_equivalence() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_test_db(&dir);
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
        let mem_proof = mem_smt.get_inclusion_proof(key).unwrap();
        let disk_proof = disk.get_inclusion_proof(key, &empty).unwrap();

        // Both proofs should verify against the same root.
        assert!(verify_inclusion(&mem_proof, &mem_root, key, value));
        assert!(verify_inclusion(&disk_proof, &root.unwrap(), key, value));

        // Proofs should be identical.
        assert_eq!(
            mem_proof.bitmap, disk_proof.bitmap,
            "bitmap mismatch for key"
        );
        assert_eq!(
            mem_proof.siblings, disk_proof.siblings,
            "siblings mismatch for key"
        );
    }
}

#[test]
fn non_inclusion_proof_equivalence() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_test_db(&dir);
    let mut disk = DiskSmt::open(db, 10_000).unwrap();
    let pairs = batch(8);

    let mut memory = SparseMerkleTree::new();
    mem_batch_insert(&mut memory, &pairs).unwrap();
    let root = memory.root_hash().unwrap();

    let (disk_root, overlay) = disk.batch_insert_round(&pairs).unwrap();
    disk.commit_overlay(overlay, disk_root).unwrap();

    let target = make_key(0x80);
    let NonInclusionProofOutcome::Proof(memory_proof) =
        memory.get_non_inclusion_proof(&target).unwrap()
    else {
        panic!("target is absent");
    };
    let NonInclusionProofOutcome::Proof(disk_proof) = disk
        .get_non_inclusion_proof(&target, &super::overlay::Overlay::new())
        .unwrap()
    else {
        panic!("target is absent");
    };

    assert_eq!(memory_proof, disk_proof);
    assert!(verify_non_inclusion(&disk_proof, Some(&root), &target));
    assert!(disk
        .get_non_inclusion_proof(&make_key(1), &super::overlay::Overlay::new())
        .is_ok_and(|outcome| outcome == NonInclusionProofOutcome::StateIncluded));
}

#[test]
fn certified_snapshot_remains_bound_to_old_root_after_commit() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_test_db(&dir);
    let mut disk = DiskSmt::open(db, 10_000).unwrap();

    let old_key = make_key(0x00);
    let (old_root, overlay) = disk
        .batch_insert_round(&[(old_key, vec![1u8; 32])])
        .unwrap();
    disk.commit_overlay(overlay, old_root).unwrap();
    let old_root = old_root.unwrap();
    let certified = disk.create_certified_snapshot().unwrap();

    let new_key = make_key(0x80);
    let (new_root, overlay) = disk
        .batch_insert_round(&[(new_key, vec![2u8; 32])])
        .unwrap();
    disk.commit_overlay(overlay, new_root).unwrap();

    let NonInclusionProofOutcome::Proof(proof) = certified
        .get_non_inclusion_proof(new_key)
        .expect("old snapshot proof")
    else {
        panic!("new key must be absent from old certified root");
    };
    assert!(verify_non_inclusion(&proof, Some(&old_root), &new_key));
    assert_eq!(certified.root_hash(), Some(old_root));
    assert_eq!(
        disk.get_non_inclusion_proof(&new_key, &super::overlay::Overlay::new())
            .unwrap(),
        NonInclusionProofOutcome::StateIncluded
    );
}

// ─── Inclusion batches on pinned views ───────────────────────────────────────

mod batch {
    use super::*;
    use crate::disk::materializer::{materialize_for_proof, NodeReader};
    use crate::disk::overlay::Overlay;
    use crate::disk::store::disk_inclusion_batch;
    use crate::traits::{InclusionBatchEntry, SnapshotError};
    use crate::MemSmt;
    use crate::SmtStoreSnapshot;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// Deterministic pseudo-random 32-byte keys (splitmix-style), spread over the key space.
    fn keys(n: usize, seed: u64) -> Vec<SmtKey> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                let mut k = [0u8; 32];
                for chunk in k.chunks_mut(8) {
                    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
                    let mut z = x;
                    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                    chunk.copy_from_slice(&(z ^ (z >> 31)).to_be_bytes());
                }
                k
            })
            .collect()
    }

    fn leaf_pairs(ks: &[SmtKey]) -> Vec<(SmtKey, Vec<u8>)> {
        ks.iter().map(|k| (*k, vec![k[0] ^ 0x5a; 32])).collect()
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn commit(disk: &mut DiskSmt, pairs: &[(SmtKey, Vec<u8>)]) -> [u8; 32] {
        let (root, overlay) = disk.batch_insert_round(pairs).unwrap();
        disk.commit_overlay(overlay, root).unwrap();
        root.unwrap()
    }

    #[test]
    fn memory_and_disk_batches_agree_and_verify_against_the_pinned_root() {
        let dir = tempfile::tempdir().unwrap();
        let mut disk = DiskSmt::open(open_test_db(&dir), 10_000).unwrap();
        let present = keys(200, 1);
        let pairs = leaf_pairs(&present);
        let root = commit(&mut disk, &pairs);
        let mut mem = MemSmt::new();
        let mut m = mem.create_snapshot();
        for (k, v) in &pairs {
            m.add_leaf(*k, v.clone()).unwrap();
        }
        m.commit(&mut mem).unwrap();
        assert_eq!(mem.root_hash(), Some(root));

        // Mixed request: present keys interleaved with absent ones, in a fixed order.
        let absent = keys(100, 999);
        let request: Vec<SmtKey> = present
            .iter()
            .take(100)
            .zip(&absent)
            .flat_map(|(p, a)| [*a, *p])
            .take(256)
            .collect();
        let from_disk = disk
            .create_certified_snapshot()
            .unwrap()
            .get_inclusion_batch(request.clone(), far())
            .unwrap();
        let from_mem = mem
            .create_certified_snapshot()
            .unwrap()
            .get_inclusion_batch(request.clone(), far())
            .unwrap();
        assert_eq!(from_disk, from_mem, "same entries from both backends");
        for (key, entry) in request.iter().zip(&from_disk) {
            match entry {
                InclusionBatchEntry::Present { proof, value } => {
                    assert!(present.contains(key));
                    assert_eq!(value, &vec![key[0] ^ 0x5a; 32]);
                    assert!(verify_inclusion(proof, &root, key, value));
                }
                InclusionBatchEntry::Absent => assert!(!present.contains(key)),
            }
        }
    }

    #[test]
    fn a_pinned_batch_view_ignores_later_commits() {
        let dir = tempfile::tempdir().unwrap();
        let mut disk = DiskSmt::open(open_test_db(&dir), 10_000).unwrap();
        let ks = keys(20, 3);
        let old_root = commit(&mut disk, &leaf_pairs(&ks[..10]));
        let pinned = disk.create_certified_snapshot().unwrap();
        let new_root = commit(&mut disk, &leaf_pairs(&ks[10..]));
        assert_ne!(old_root, new_root);

        let got = pinned.get_inclusion_batch(ks.clone(), far()).unwrap();
        for (i, entry) in got.iter().enumerate() {
            match (i < 10, entry) {
                (true, InclusionBatchEntry::Present { proof, value }) => {
                    assert!(verify_inclusion(proof, &old_root, &ks[i], value));
                }
                (false, InclusionBatchEntry::Absent) => {}
                _ => panic!("key {i} must follow the pinned root"),
            }
        }
    }

    #[test]
    fn empty_views_answer_absent_and_bad_requests_are_typed() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskSmt::open(open_test_db(&dir), 10_000).unwrap();
        let empty = disk.create_certified_snapshot().unwrap();
        let ks = keys(3, 4);
        assert!(empty
            .get_inclusion_batch(ks.clone(), far())
            .unwrap()
            .iter()
            .all(|e| *e == InclusionBatchEntry::Absent));

        assert!(matches!(
            empty.get_inclusion_batch(vec![], far()),
            Err(SnapshotError::Invalid(_))
        ));
        assert!(matches!(
            empty.get_inclusion_batch(keys(257, 5), far()),
            Err(SnapshotError::Invalid(_))
        ));
        // A deadline that has passed is never worked on.
        assert!(matches!(
            empty.get_inclusion_batch(ks, Instant::now() - Duration::from_millis(1)),
            Err(SnapshotError::Deadline)
        ));
    }

    /// Counts node reads.
    struct Counting<'a, R: NodeReader>(&'a R, AtomicUsize);

    impl<R: NodeReader> NodeReader for Counting<'_, R> {
        fn get_node(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
            self.1.fetch_add(1, Ordering::Relaxed);
            self.0.get_node(key)
        }
    }

    /// Hardware-independent cost: a batch reads the union of the paths, so
    /// shared prefixes are read once instead of once per key.
    #[test]
    fn batch_reads_the_union_of_paths_not_one_path_per_key() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_test_db(&dir);
        let mut disk = DiskSmt::open(Arc::clone(&db), 10_000).unwrap();
        let ks = keys(2_000, 7);
        commit(&mut disk, &leaf_pairs(&ks));
        let request: Vec<SmtKey> = ks.iter().step_by(31).copied().take(64).collect();
        assert_eq!(request.len(), 64);

        let reader = Counting(&db, AtomicUsize::new(0));
        let entries = disk_inclusion_batch(&reader, &Overlay::new(), &request, far()).unwrap();
        assert!(entries
            .iter()
            .all(|e| matches!(e, InclusionBatchEntry::Present { .. })));
        let union_reads = reader.1.load(Ordering::Relaxed);

        let single = Counting(&db, AtomicUsize::new(0));
        for key in &request {
            materialize_for_proof(&single, &Overlay::new(), None, key).unwrap();
        }
        let per_key_reads = single.1.load(Ordering::Relaxed);
        assert!(
            union_reads * 2 <= per_key_reads,
            "union {union_reads} should be well under per-key {per_key_reads}"
        );
        // And bounded by what the paths hold: at most the node count of 64 paths.
        assert!(union_reads <= per_key_reads);
    }
}
