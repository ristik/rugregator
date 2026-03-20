//! Bounded LRU cache for deserialized SMT node bytes.
//!
//! Keyed by `NodeKey` bytes; values are the raw serialized node data
//! (same format as stored in RocksDB).  Deserialization happens at the
//! call site when the bytes are used.

use lru::LruCache;
use std::num::NonZeroUsize;
use super::node_key::NodeKey;

pub struct NodeCache {
    inner: LruCache<Vec<u8>, Vec<u8>>,
}

impl NodeCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self { inner: LruCache::new(cap) }
    }

    /// Retrieve cached bytes for `key` (promotes to MRU).
    pub fn get(&mut self, key: &NodeKey) -> Option<&Vec<u8>> {
        self.inner.get(key.as_bytes())
    }

    /// Insert serialized node bytes into the cache.
    pub fn put(&mut self, key: NodeKey, data: Vec<u8>) {
        self.inner.put(key.into_bytes(), data);
    }

    /// Insert by raw key bytes (used during commit to sync cache with DB).
    pub fn put_raw(&mut self, key: Vec<u8>, data: Vec<u8>) {
        self.inner.put(key, data);
    }

    /// Remove a key from the cache (called when a node is tombstoned).
    pub fn evict_raw(&mut self, key: &[u8]) {
        self.inner.pop(key);
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}
