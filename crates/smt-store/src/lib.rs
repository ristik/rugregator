pub mod disk;
pub mod mem;
pub mod traits;

pub use disk::{DiskSmt, DiskSmtSnapshot};
pub use mem::{MemSmt, MemSmtSnapshot, PersistMode};
pub use traits::{CertifiedSmtSnapshot, SmtStore, SmtStoreSnapshot, CERTIFIED_PROOF_MAX_IN_FLIGHT};

use rsmt::SmtKey;

/// Derive the values a round actually stores from the batch it declares.
///
/// The batch carries transaction hashes; the tree stores
/// `leaf_value(transactionHash, reference_time)`, which binds the round's
/// reference time to the leaf rather than leaving it a property of whichever
/// inclusion proof later establishes it.
pub fn derive_batch(batch: &[(SmtKey, Vec<u8>)], reference_time: u64) -> Vec<(SmtKey, Vec<u8>)> {
    batch
        .iter()
        .map(|(k, v)| (*k, rsmt::leaf_value(v, reference_time).to_vec()))
        .collect()
}

/// Map the inserted (derived) pairs back to the values the batch declared, in
/// insertion order.
///
/// The `aggregator_rsmt_v1` envelope declares transaction hashes so BFT Core
/// re-derives the stored leaf values from the reference time it already
/// enforces; a shard that built its tree under any other reference time
/// produces a root the Core does not reproduce.
pub fn declared_batch(
    inserted: &[(SmtKey, Vec<u8>)],
    declared: &[(SmtKey, Vec<u8>)],
) -> Vec<(SmtKey, Vec<u8>)> {
    let by_key: std::collections::HashMap<SmtKey, &Vec<u8>> =
        declared.iter().map(|(k, v)| (*k, v)).collect();
    inserted
        .iter()
        .map(|(k, stored)| {
            let value = by_key.get(k).map(|v| (*v).clone()).unwrap_or_else(|| {
                debug_assert!(false, "inserted key absent from the declared batch");
                stored.clone()
            });
            (*k, value)
        })
        .collect()
}

/// Count persisted leaves in a RocksDB instance, regardless of which backend
/// wrote the data.
///
/// - `mem-leaves` and `mem-full` write leaf values to `CF_SMT_LEAVES` (checked
///   first; O(n) iteration).
/// - `disk` does not write to `CF_SMT_LEAVES`; instead its leaves are stored as
///   TAG_LEAF entries inside `CF_SMT_NODES` (counted by scanning that CF).
pub fn count_db_leaves(db: &rocksdb::DB) -> usize {
    use disk::materializer::CF_SMT_NODES;
    use rsmt::node_serde::TAG_LEAF;

    // mem-leaves / mem-full path.
    if let Some(cf) = db.cf_handle(mem::CF_SMT_LEAVES) {
        let n = db.iterator_cf(&cf, rocksdb::IteratorMode::Start).count();
        if n > 0 {
            return n;
        }
    }

    // disk path: count TAG_LEAF entries in CF_SMT_NODES.
    if let Some(cf) = db.cf_handle(CF_SMT_NODES) {
        return db
            .iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .filter(|item| {
                item.as_ref()
                    .map(|(_, v)| v.first() == Some(&TAG_LEAF))
                    .unwrap_or(false)
            })
            .count();
    }

    0
}
