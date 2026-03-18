//! Disk-backed SMT storage layer.
//!
//! Provides `DiskBackedSmt` and `DiskSmtSnapshot` — drop-in replacements for
//! the in-memory `SparseMerkleTree` + `SmtSnapshot` pair, backed by RocksDB.
//!
//! All files in this module are compiled only when the `rocksdb-storage`
//! feature is enabled.

pub mod cache;
pub mod materializer;
pub mod node_key;
pub mod overlay;
pub mod persister;
pub mod snapshot;
pub mod store;
pub mod tests;

pub use snapshot::DiskSmtSnapshot;
pub use store::DiskBackedSmt;
