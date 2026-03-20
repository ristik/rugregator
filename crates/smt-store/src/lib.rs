pub mod disk;
pub mod mem;
pub mod traits;

pub use disk::{DiskSmt, DiskSmtSnapshot};
pub use mem::{MemSmt, MemSmtSnapshot, PersistMode};
pub use traits::{SmtStore, SmtStoreSnapshot};

/// Count persisted leaves in a RocksDB instance, regardless of which backend
/// wrote the data.
///
/// - `mem-leaves` and `mem-full` write leaf values to `CF_SMT_LEAVES` (checked
///   first; O(n) iteration).
/// - `disk` does not write to `CF_SMT_LEAVES`; instead its leaves are stored as
///   TAG_LEAF entries inside `CF_SMT_NODES` (counted by scanning that CF).
pub fn count_db_leaves(db: &rocksdb::DB) -> usize {
    use rsmt::node_serde::TAG_LEAF;
    use disk::materializer::CF_SMT_NODES;

    // mem-leaves / mem-full path.
    if let Some(cf) = db.cf_handle(mem::CF_SMT_LEAVES) {
        let n = db.iterator_cf(&cf, rocksdb::IteratorMode::Start).count();
        if n > 0 {
            return n;
        }
    }

    // disk path: count TAG_LEAF entries in CF_SMT_NODES.
    if let Some(cf) = db.cf_handle(CF_SMT_NODES) {
        return db.iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .filter(|item| {
                item.as_ref()
                    .map(|(_, v)| v.first() == Some(&TAG_LEAF))
                    .unwrap_or(false)
            })
            .count();
    }

    0
}
