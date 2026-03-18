//! In-memory mutation buffer for a speculative round.
//!
//! All writes go into the overlay.  Reads check overlay → cache → RocksDB.
//! On BFT success: `commit` flushes via `WriteBatch`.
//! On BFT failure: `drop` discards everything.

use std::collections::HashMap;
use super::node_key::NodeKey;

/// Speculative write buffer for one round's SMT mutations.
#[derive(Debug, Default)]
pub struct Overlay {
    /// NodeKey bytes → Some(serialized node) | None (tombstone)
    nodes: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Overlay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Write or overwrite a node.
    pub fn put(&mut self, key: &NodeKey, data: Vec<u8>) {
        self.nodes.insert(key.as_bytes().to_vec(), Some(data));
    }

    /// Tombstone a node (marks for deletion on commit).
    pub fn delete(&mut self, key: &NodeKey) {
        self.nodes.insert(key.as_bytes().to_vec(), None);
    }

    /// Probe the overlay.
    /// - `None`        → key not touched in this overlay
    /// - `Some(None)`  → key tombstoned (delete on commit)
    /// - `Some(Some)` → key present with this data
    pub fn get(&self, key: &NodeKey) -> Option<Option<&[u8]>> {
        self.nodes.get(key.as_bytes()).map(|v| v.as_deref())
    }

    /// Consume the overlay, producing iterators for the commit phase.
    pub fn into_nodes(self) -> HashMap<Vec<u8>, Option<Vec<u8>>> {
        self.nodes
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}
