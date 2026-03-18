# Disk-Backed SMT: Scaling Beyond Memory

## Context

The in-memory SMT cannot hold production-scale data. We need to persist leaves and internal nodes in RocksDB and load them on demand. After each batch + root computation, in-memory nodes are pushed to a cache layer that is eventually evicted. Speculative round mutations are held in an overlay and committed atomically on BFT success, or discarded on failure.

The Go aggregator uses MongoDB to persist **only leaves**, rebuilding the full tree on startup. Our requirement goes further: persist **internal nodes too**, so startup doesn't require replaying all leaves, and so the working set in memory is bounded by batch size + cache, not total tree size.

---

## Architecture: "Materialize Before, Persist After"

rsmt's algorithms (`build_tree`, `insert_node`, `calc_node_hash`, `generate_path`) all operate on `Box<Branch>` via direct pointer chasing. Rewriting them to be generic over a storage backend would be a massive, error-prone refactor. Instead:

1. **Before** an operation: the disk layer loads all needed nodes into a partial in-memory tree, with `Branch::Stub(hash)` for untouched siblings.
2. **During**: rsmt's unmodified algorithms run against this in-memory tree.
3. **After**: the disk layer diffs the result, writes mutations to an overlay, and pushes committed nodes to RocksDB + cache.

This keeps rsmt as a pure data-structure crate. All RocksDB code lives in the aggregator crate behind `#[cfg(feature = "rocksdb-storage")]`.

---

## Key Design Decisions

### Node addressing

Leaves are keyed by `original_path.to_bytes_be()` (35 bytes, unique per leaf). Internal nodes are keyed by the **absolute bit-path from root** — the concatenation of all routing decisions (prefix bits + routing bit at each level). This is computed during top-down traversal. Path-based keys are stable across mutations (unlike content-addressed hashes) and require no secondary index.

### Stub nodes

Add `Branch::Stub([u8; 32])` to rsmt behind `#[cfg(feature = "disk-backed")]`. When materializing a sub-tree, siblings of the traversal path are represented as Stubs carrying only their cached hash. `calc_branch_hash` returns the hash directly; no recursion into disk. This is the minimal change to rsmt needed.

### Snapshot / rollback

A write `Overlay` (`HashMap<NodeKey, Option<Vec<u8>>>`) captures all mutations from a round. Reads check overlay first, then cache, then RocksDB. On **commit**: overlay is flushed via `WriteBatch` and entries pushed to cache. On **rollback**: overlay is dropped — no RocksDB state was touched.

### Caching

Bounded LRU cache keyed by `NodeKey`, valued by deserialized `Branch`. On commit, all written nodes enter the cache. Proof generation for recently-inserted leaves hits cache for siblings along the path, avoiding disk reads.

---

## RocksDB Schema

Existing CFs (`records`, `blocks`, `meta`) are unchanged.

| CF | Key | Value | Purpose |
|----|-----|-------|---------|
| `smt_leaves` | `original_path.to_bytes_be()` (35 B) | Serialized `LeafBranch` (no children) | Leaf data |
| `smt_nodes` | Absolute bit-path bytes (variable) | Serialized `NodeBranch` metadata (flags, path, hash, has_left/right — no children inline) | Internal node data |
| `smt_meta` | `b"root_hash"` | 32 bytes | Current committed root hash |

Bloom filters on `smt_leaves` and `smt_nodes` for fast negative lookups. LZ4 compression on `smt_nodes`.

---

## Materialization

### For batch_insert (round processing)

1. Sort batch keys.
2. Walk the tree structure top-down from root, following paths dictated by the batch keys. Many keys share prefixes — the union of their paths forms a sub-tree.
3. Collect all `NodeKey`s along these paths (including siblings at each level — needed for hash computation).
4. Issue a single `multi_get_cf` for all keys.
5. Deserialize and assemble an in-memory `SparseMerkleTree` with `Stub` nodes for out-of-path siblings.
6. Hand this tree to rsmt's `batch_insert`.

### For get_path (proof generation)

A single root-to-leaf path plus sibling hashes. Walk top-down following the key's bits, collecting node keys. Check cache first; only issue RocksDB reads for misses. Siblings are represented as `Stub(hash)`.

### Persisting after mutation

Walk the in-memory working tree top-down, computing `NodeKey` for each node. Compare against the set of keys that were materialized. New or changed nodes → upserts. Keys present before but absent after (due to path-compression restructuring) → deletes. All go into the overlay.

---

## File Changes

### Phase A: rsmt additions (minimal, non-breaking)

**`crates/rsmt/Cargo.toml`**
- Add feature `disk-backed = []` (no deps needed).

**`crates/rsmt/src/types.rs`**
- Add `Branch::Stub([u8; 32])` behind `#[cfg(feature = "disk-backed")]`.
- Update `is_leaf()`, `path()` to handle Stub (panic — stubs must not be navigated into).

**`crates/rsmt/src/tree.rs`**
- `calc_branch_hash`: return stored hash for Stub.
- `clone_branch`: clone Stub trivially.
- `find_leaf_in_branch_ref`: return error for Stub.
- `build_tree`: Stub should never appear as `branch` argument (panic guard).

**`crates/rsmt/src/consistency.rs`**
- `branch_hash_immut` (line 411): Stub.clone() already works, `calc_branch_hash` returns hash.
- `insert_node`: when an existing node's untouched subtree is a Stub, the `S` opcode emits its hash — already correct since `calc_branch_hash(Stub) = hash`.

**`crates/rsmt/src/node_serde.rs`** (new)
- `serialize_leaf(l: &LeafBranch) -> Vec<u8>`
- `deserialize_leaf(bytes: &[u8]) -> LeafBranch`
- `serialize_node_meta(n: &NodeBranch) -> Vec<u8>` (path, flags, hash_cache, has_left/right — no children)
- `deserialize_node_meta(bytes: &[u8]) -> (NodeBranch_sans_children, bool, bool)` (returns node + has_left + has_right flags)
- Compact binary format (not CBOR): flags byte, varint-prefixed path bytes, optional 32-byte hash, varint-prefixed value for leaves.

**`crates/rsmt/src/lib.rs`**
- `#[cfg(feature = "disk-backed")] pub mod node_serde;`

### Phase B: Aggregator disk-backed SMT infrastructure

All new files under `crates/aggregator/src/smt_disk/`, feature-gated.

**`smt_disk/mod.rs`** — Module root, re-exports.

**`smt_disk/node_key.rs`** — `NodeKey` type. Encodes absolute bit-path as a byte vector. Methods: `root()`, `child_left(prefix_bits)`, `child_right(prefix_bits)`, `to_bytes()`, `from_bytes()`. Used as RocksDB key for `smt_nodes` CF.

**`smt_disk/overlay.rs`** — `Overlay` struct. Two `HashMap<Vec<u8>, Option<Vec<u8>>>` (leaves, nodes). Methods: `put_leaf`, `put_node`, `delete_node`, `get_leaf`, `get_node`. `commit(db) -> WriteBatch`. `discard(self)` = drop.

**`smt_disk/cache.rs`** — `NodeCache` wrapping `lru::LruCache`. Separate caches for leaves and node metadata. Configurable capacity. Methods: `get_leaf`, `put_leaf`, `get_node`, `put_node`.

**`smt_disk/materializer.rs`** — Core logic.
- `materialize_for_batch(db, cache, overlay, root_hash, batch_keys) -> SparseMerkleTree` — Walks tree structure top-down using batch keys to determine paths. Issues `multi_get_cf`. Builds partial in-memory tree with Stubs.
- `materialize_for_proof(db, cache, overlay, root_hash, leaf_key) -> SparseMerkleTree` — Single path materialization for proof generation.
- `collect_needed_keys(db, cache, overlay, batch_keys) -> Vec<NodeKey>` — Pre-scan to determine which keys to fetch.

**`smt_disk/persister.rs`** — After mutation.
- `diff_and_record(old_keys: HashSet<NodeKey>, working_tree: &SparseMerkleTree) -> Overlay` — Walks tree top-down, computes new NodeKeys, produces overlay of upserts/deletes.
- `walk_tree_keys(tree: &SparseMerkleTree) -> HashMap<NodeKey, &Branch>` — Enumerate all nodes with their keys.

**`smt_disk/store.rs`** — `DiskBackedSmt` struct.
- Fields: `db: Arc<DB>`, `cache: Arc<Mutex<NodeCache>>`, `key_length: usize`, `current_root_hash: Option<[u8; 32]>`.
- `open(db, cache_capacity) -> Self` — Reads root hash from `smt_meta`.
- `batch_insert(&self, batch) -> Result<(new_root_hash, overlay)>` — Materialize → rsmt batch_insert → diff → return overlay.
- `batch_insert_with_proof(&self, batch) -> Result<(new_root_hash, overlay, proof)>` — Same + consistency proof.
- `get_path(&self, leaf_key) -> Result<MerkleTreePath>` — Materialize single path → rsmt get_path.
- `commit_overlay(&self, overlay)` — Flush to RocksDB WriteBatch + push to cache + update root hash in smt_meta.
- `root_hash_imprint(&self) -> [u8; 34]` — From cached root hash.

**`smt_disk/snapshot.rs`** — `DiskSmtSnapshot`.
- `create(store)` — No deep clone; just holds `Arc<DiskBackedSmt>` + empty overlay.
- `add_leaf(path, value)` — Materialize path, insert, record in overlay.
- `batch_insert(batch)` — Materialize batch paths, insert all, record in overlay.
- `root_hash_imprint()` — Returns working tree's root.
- `commit(self)` — Calls `store.commit_overlay(self.overlay)`.
- `discard(self)` — Drops overlay.

### Phase C: Integration

**`crates/aggregator/Cargo.toml`**
- Add `lru = "0.12"` dependency.
- Update `rocksdb-storage` feature to also enable `rsmt/disk-backed`.

**`crates/aggregator/src/storage_rocksdb.rs`**
- Add `smt_leaves`, `smt_nodes`, `smt_meta` CFs to `RocksDbStore::open()`.

**`crates/aggregator/src/round/manager.rs`**
- Add `SmtBackend` enum: `InMemory(SparseMerkleTree) | DiskBacked(Arc<DiskBackedSmt>)`.
- `process_round` dispatches between in-memory `SmtSnapshot` and disk `DiskSmtSnapshot`.
- Proof generation dispatches similarly: in-memory `tree.get_path()` vs `store.get_path()`.

**`crates/aggregator/src/config.rs`**
- Add `--cache-capacity` option (default: 1_000_000 entries).

**`crates/aggregator/src/main.rs`**
- When `rocksdb-storage` + non-empty `db_path`: open `DiskBackedSmt` from existing DB. Verify root hash matches latest block. No leaf replay needed.
- Pass `SmtBackend::DiskBacked(store)` to `RoundManager`.

**`crates/aggregator/src/lib.rs`**
- `#[cfg(feature = "rocksdb-storage")] pub mod smt_disk;`

### Phase D: Testing & perf

**`crates/rsmt/src/node_serde.rs`** — Unit tests for serialization roundtrips of leaves and node metadata.

**`crates/aggregator/src/smt_disk/tests.rs`**
- Root hash equivalence: N leaves inserted disk-backed produces same root as in-memory.
- Rollback: create snapshot, insert, discard, verify tree unchanged on disk.
- Commit: insert, commit, re-open DB, verify root hash and proof generation.
- Proof equivalence: disk-backed proofs match in-memory proofs byte-for-byte.

**`crates/aggregator/src/bin/perf_test.rs`**
- Add `--disk` flag + `--cache-capacity` option.
- When set, use `DiskBackedSmt` with a temp directory.
- Report cache hit rate alongside throughput/latency.

---

## Implementation Order

1. **Phase A** first — the `Branch::Stub` variant and `node_serde` module in rsmt. Small, testable independently.
2. **Phase B** — the `smt_disk` module in aggregator. Build bottom-up: `node_key` → `overlay` → `cache` → `materializer` → `persister` → `store` → `snapshot`. Each layer testable in isolation.
3. **Phase C** — wire into `RoundManager` and `main.rs`. Integration tests.
4. **Phase D** — perf testing, tuning cache capacity and RocksDB options.

---

## Verification

1. `cargo test -p rsmt` — all existing tests pass (Stub behind feature flag, no impact).
2. `cargo test -p rsmt --features disk-backed` — serialization roundtrip tests pass.
3. `cargo test -p uni-aggregator --features rocksdb-storage` — disk-backed integration tests: root hash equivalence, rollback, commit+reload, proof equivalence.
4. `cargo run --release -p uni-aggregator --bin perf-test -- --disk --rounds 4 --batch-sizes 1000,5000` — throughput comparison in-memory vs disk-backed.
5. Manual: start aggregator with `--db-path /tmp/agg-db`, submit requests, kill, restart, verify block number and proofs survive.
