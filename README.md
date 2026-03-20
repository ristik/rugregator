# Unicity Aggregator — Rust

An experimental aggregation node for the [Unicity](https://unicity.network) network. Accepts client transaction certification requests, batches them into rounds, proposes each round's state transition to BFT Core for certification, and returns verifiable inclusion proofs backed by a Radix / Sparse Merkle Tree (SMT).

This is a Rust reimplementation of `aggregator-go`, producing **wire-identical** outputs: same SMT root hashes, same CBOR encoding, same proof structure, but with real secure state transitions and optional consistency proofs for trustless operation.

Focus areas:
- Consistency proofs for every round of operation
- Scaling beyond available system memory (fully disk-backed SMT)
- Speculative execution of the next round while waiting for BFT certification
- Configurable persistence — trade off restart speed vs. memory footprint

---

## Architecture

```
clients  ──POST /──>  JSON-RPC server  ──mpsc──>  RoundManager<S: SmtStore>
                                                        │
                       AggregatorState  <───────────────┤  commit certified state
                            │                           │
                     DashMap<StateID,                   ├─ BFT Core (libp2p)
                       RecordInfo>                      │
                            │                      SmtStore (generic)
                     get_inclusion_proof            ├─ MemSmt   (all in RAM)
                                                    └─ DiskSmt  (RocksDB-backed)
```

**Request flow:**

1. `POST /` — JSON-RPC 2.0 dispatch
2. `certification_request` — hex-CBOR payload → predicate + signature + StateID validation → queued in `RoundManager` via `mpsc`
3. `RoundManager` — collects requests, fires a round on a timer (default 1 s) or batch-size limit; creates an SMT snapshot, inserts leaves, proposes root hash to BFT Core, awaits the Unicity Certificate (UC)
4. On UC success — commits snapshot, stores finalized records; on UC failure — discards snapshot, re-queues requests
5. `get_inclusion_proof.v2` — returns `[blockNumber, [certData, merklePathCbor, ucCbor]]` from the certified SMT

**Speculative execution:** while waiting for the UC (~1.5 s), the next block's requests are inserted speculatively into a forked snapshot. On UC success the speculative snapshot is immediately promoted, eliminating dead time between rounds. On UC failure both snapshots are discarded and all requests are re-queued. The disk-backed path additionally uses a layered overlay so the speculative snapshot can read the proposed round's uncommitted mutations without any RocksDB writes.

### Workspace crates

| Crate | Description |
|-------|-------------|
| `crates/rsmt` | Standalone Sparse Merkle Tree library — path-compressed 272-bit Patricia trie, Go-compatible hashing, consistency proofs, serialisation. No async, no I/O. |
| `crates/smt-store` | SMT storage backends behind a common `SmtStore` / `SmtStoreSnapshot` trait. Contains `MemSmt` (fully in-memory, optional DB persistence) and `DiskSmt` (lazy disk-backed via RocksDB). |
| `crates/aggregator` | The aggregator service — HTTP API, generic `RoundManager<S: SmtStore>`, BFT Core connectivity, application-level RocksDB persistence. |

---

## Prerequisites

| Tool | Minimum version | Notes |
|------|----------------|-------|
| Rust | 1.75 | `rustup update stable` |
| C compiler | any | required by `secp256k1-sys` and `librocksdb-sys` |
| CMake | 3.x | required by `librocksdb-sys` |
| Clang / LLVM | any | required by `bindgen` (RocksDB) |

On macOS all dependencies arrive via Xcode Command Line Tools + Homebrew (`brew install cmake llvm`). On Debian/Ubuntu: `apt install build-essential cmake clang`.

> **Note:** RocksDB is always compiled. The first build compiles librocksdb from source and takes several minutes. Subsequent builds are incremental.

---

## Build

```bash
# Build everything
cargo build --workspace

# Release build
cargo build --workspace --release
```

---

## Running

### Stub BFT mode (no external dependencies)

The fastest way to bring up a standalone aggregator for development or testing:

```bash
cargo run --release -p uni-aggregator --bin aggregator -- \
  --bft-mode stub \
  --listen 0.0.0.0:8080 \
  --round-duration-ms 800 \
  --batch-limit 50000
```

The stub BFT committer signs its own UCs with a hardcoded test key — no BFT Core process needed. With no `--db-path` the aggregator runs fully in-memory; state is lost on restart.

### SMT backend selection

Use `--smt-backend` to choose how the SMT tree is stored and recovered. All four modes share the same `RoundManager<S: SmtStore>` code path.

| Backend | Flag | Requires `--db-path` | Restart behaviour |
|---------|------|---------------------|-------------------|
| Pure in-memory | `--smt-backend mem` | No | State lost on restart; BFT partition state must be reset too |
| In-memory + leaf persistence | `--smt-backend mem-leaves` | Yes | Replays all leaves from `smt_leaves` CF to rebuild tree; verifies root hash |
| In-memory + full persistence | `--smt-backend mem-full` | Yes | Loads complete node tree from `smt_nodes` CF directly; faster restart than `mem-leaves` |
| Fully disk-backed | `--smt-backend disk` | Yes | Only root hash loaded at start; nodes materialised on demand from RocksDB |

When `--smt-backend` is omitted it defaults to `disk` if `--db-path` is set, `mem` otherwise.

```bash
# In-memory with leaf persistence (good balance for medium trees)
cargo run --release -p uni-aggregator --bin aggregator -- \
  --bft-mode stub \
  --db-path /var/lib/aggregator/db \
  --smt-backend mem-leaves

# In-memory with full node persistence (fastest restart)
cargo run --release -p uni-aggregator --bin aggregator -- \
  --bft-mode stub \
  --db-path /var/lib/aggregator/db \
  --smt-backend mem-full

# Fully disk-backed (unbounded tree size, working set bounded by cache)
cargo run --release -p uni-aggregator --bin aggregator -- \
  --bft-mode stub \
  --db-path /var/lib/aggregator/db \
  --smt-backend disk \
  --cache-capacity 1000000
```

### Live BFT Core

```bash
cargo run --release -p uni-aggregator --bin aggregator -- \
  --bft-mode live \
  --bft-peer-id  <BFT_CORE_PEER_ID> \
  --bft-addr     /ip4/<BFT_HOST>/tcp/26652 \
  --p2p-addr     /ip4/0.0.0.0/tcp/0 \
  --auth-key-hex <32-byte-hex-secp256k1-auth-key> \
  --sig-key-hex  <32-byte-hex-secp256k1-signing-key> \
  --partition-id 1 \
  --db-path      /var/lib/aggregator/db \
  --smt-backend  disk \
  --consistency-proofs
```

### Configuration reference

All flags are also readable from environment variables (`AGGREGATOR_*`):

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | `AGGREGATOR_LISTEN` | `0.0.0.0:8080` | HTTP listen address |
| `--round-duration-ms` | `AGGREGATOR_ROUND_DURATION_MS` | `1000` | Round timer (ms) |
| `--batch-limit` | `AGGREGATOR_BATCH_LIMIT` | `1000` | Max requests per round |
| `--bft-mode` | `AGGREGATOR_BFT_MODE` | `stub` | `stub` or `live` |
| `--consistency-proofs` | `AGGREGATOR_CONSISTENCY_PROOFS` | `false` | Attach consistency proof to each CR |
| `--db-path` | `AGGREGATOR_DB_PATH` | _(empty)_ | RocksDB directory; empty = in-memory only |
| `--smt-backend` | `AGGREGATOR_SMT_BACKEND` | _(auto)_ | `mem`, `mem-leaves`, `mem-full`, or `disk` |
| `--cache-capacity` | `AGGREGATOR_CACHE_CAPACITY` | `500000` | Disk-SMT LRU node cache size (nodes) |
| `--partition-id` | `AGGREGATOR_PARTITION_ID` | `1` | BFT Core partition ID |
| `--bft-peer-id` | `AGGREGATOR_BFT_PEER_ID` | | BFT Core root node peer ID |
| `--bft-addr` | `AGGREGATOR_BFT_ADDR` | `/ip4/127.0.0.1/tcp/26652` | BFT Core multiaddr |
| `--p2p-addr` | `AGGREGATOR_P2P_ADDR` | `/ip4/0.0.0.0/tcp/0` | Our libp2p listen multiaddr |
| `--auth-key-hex` | `AGGREGATOR_AUTH_KEY` | | secp256k1 key for libp2p identity |
| `--sig-key-hex` | `AGGREGATOR_SIG_KEY` | | secp256k1 key for signing CRs |
| `--log-level` | `RUST_LOG` | `info` | `trace`, `debug`, `info`, `warn`, `error` |

---

## Bootstrap procedure

Starting a fresh node against a live BFT Core network:

1. **Provision keys.** Generate two secp256k1 private keys — one for libp2p identity (`auth-key`) and one for signing Certification Requests (`sig-key`). The BFT Core operator must register the signing key's public key in the network's trust base for your `partition-id`.

2. **Obtain the BFT Core peer ID and address** from the network operator. The peer ID is a libp2p multihash (base58, `12D3...` format).

3. **Create the data directory:**
   ```bash
   mkdir -p /var/lib/aggregator/db
   ```

4. **Start the aggregator.** On first start with an empty `--db-path` the aggregator begins at block 1 with an empty SMT and immediately connects to BFT Core. BFT Core delivers a sync UC that establishes the initial round number and certified state hash.

5. **Verify connectivity:**
   ```bash
   curl http://localhost:8080/health
   # {"status":"ok","blockNumber":"1"}
   ```
   The block number advances by 1 each time a round is certified.

6. **Recovery after restart.** Stop the aggregator at any time and restart with the same `--db-path` and `--smt-backend`. Recovery behaviour depends on the backend — see the table above.

---

## API

All methods are JSON-RPC 2.0 over `POST /`.

### `certification_request`

Submit a state transition for certification.

```json
{"jsonrpc":"2.0","id":1,"method":"certification_request","params":"<hex-encoded CBOR>"}
```

Response (success): `{"jsonrpc":"2.0","id":1,"result":{"status":"OK"}}`

### `get_inclusion_proof.v2`

Retrieve a certified inclusion proof.

```json
{"jsonrpc":"2.0","id":2,"method":"get_inclusion_proof.v2","params":{"stateId":"<hex>"}}
```

Returns a hex-encoded CBOR value: `[blockNumber, [certData, merklePathCbor, ucCbor]]`.
Returns HTTP 404 while the state is pending certification (SDK retries automatically).

### `get_block_height`

```json
{"jsonrpc":"2.0","id":3,"method":"get_block_height","params":null}
```

---

## Tests

```bash
# All tests
cargo test --workspace

# SMT library only
cargo test -p rsmt

# Aggregator only
cargo test -p uni-aggregator

# SMT storage backends
cargo test -p smt-store

# Run a specific test
cargo test -p rsmt consistency::tests::two_leaf_consistency
cargo test -p smt-store disk::tests::proof_equivalence
```

---

## Performance benchmarks

### SMT-only benchmark

Measures raw insertion throughput and proof-generation latency for each SMT backend in isolation, with no BFT Core or HTTP overhead.

```bash
# In-memory (default)
cargo run --release -p uni-aggregator --bin perf-test -- \
  --rounds 6 --batch-sizes 1000,5000,10000

# Disk-backed
cargo run --release -p uni-aggregator --bin perf-test -- \
  --backend disk --cache-capacity 500000 \
  --rounds 6 --batch-sizes 1000,5000,10000

# In-memory with full node persistence
cargo run --release -p uni-aggregator --bin perf-test -- \
  --backend mem-full \
  --rounds 6 --batch-sizes 1000,5000,10000

# CSV output for plotting
cargo run --release -p uni-aggregator --bin perf-test -- \
  --backend disk --rounds 8 --batch-sizes 1000,5000,10000,25000 --csv
```

Each run inserts batches cumulatively so tree size grows across rounds, revealing how throughput degrades as the working set grows.

Reported columns:

| Column | Description |
|--------|-------------|
| `pre_fill` | Leaves already in the tree before this batch |
| `inserted` | Leaves actually inserted (duplicates skipped) |
| `leaves/s` | Insertion throughput |
| `insert` | Time to insert + compute root hash |
| `commit` | Time to persist the round (RocksDB write for disk/mem-full/mem-leaves) |
| `proof p50/p95` | Inclusion proof generation latency percentiles |

### E2E benchmark (stub BFT, local client)

```bash
# Terminal 1 — start aggregator
cargo run --release -p uni-aggregator --bin aggregator -- \
  --bft-mode stub \
  --round-duration-ms 800 \
  --batch-limit 50000 \
  --listen 0.0.0.0:8080

# Terminal 2 — run load generator (TypeScript SDK)
cd state-transition-sdk
npm install && npm run build
node dist/examples/load-test.js --url http://localhost:8080 --concurrency 200 --requests 10000
```

Watch round size and certified throughput in the aggregator logs:
```
INFO round finalized  block=12 root=0x… certified=847 submitted=847 spec_queued=312
```

`certified` = requests included in the finalized block.
`spec_queued` = requests already inserted speculatively into the next block (zero idle time between rounds).

---

## Standout features

### O(1) copy-on-write snapshots

The SMT tree uses `Arc<Branch>` children everywhere. `SmtSnapshot::create()` and `fork()` are O(1): they clone two Arc reference counts at the root rather than deep-copying the tree. Modified nodes are path-copied (`Arc::make_mut` unwraps shared nodes in-place; clones only when shared), so speculative execution adds at most O(batch_size × tree_depth) new allocations per round — not another copy of the entire tree.

Peak memory during a speculative round is roughly 1× tree size + O(batch). Without CoW it would be 2–3× tree size.

### Generic `RoundManager<S: SmtStore>`

All four SMT backends (`mem`, `mem-leaves`, `mem-full`, `disk`) share a single `RoundManager<S>` implementation. The `SmtStore` / `SmtStoreSnapshot` trait pair abstracts over snapshot creation, speculative fork/commit/discard, batch insertion, and proof generation. Switching backends is a one-line config change with zero code duplication.

### Configurable SMT persistence

`MemSmt` supports three persistence modes, selectable at startup:

- **`None`** (`--smt-backend mem`): no writes to RocksDB; fastest per-round commit, but no crash recovery. BFT Core partition state must also be reset on restart.
- **`LeavesOnly`** (`--smt-backend mem-leaves`): leaf values are appended to the `smt_leaves` column family on every commit. On restart, all leaves are replayed through `batch_insert` to reconstruct the tree, and the resulting root is compared against the last certified root stored in `smt_meta`. Recovery time is O(n × log n) in the number of leaves.
- **`Full`** (`--smt-backend mem-full`): leaves and all internal nodes are written to `smt_nodes` on every commit. Nodes that become orphaned during a round (when an existing node is pushed down by a new sibling) are **immediately tombstoned** at commit time by diffing the pre-commit and post-commit node-key sets. On restart, the full tree is loaded directly from `smt_nodes` — O(n) I/O, no recomputation.

### Consistency proofs for trustless operation

Every Certification Request sent to BFT Core can optionally carry a **consistency proof** — a compact CBOR-encoded witness that the new SMT root was derived from the previous certified root by appending only the declared leaves, with no deletions or modifications.

Enable with `--consistency-proofs`:

**What it proves:** Let `h₀` be the root certified in the last UC and `h₁` be the root in the current Certification Request. The proof witnesses the exact set of (StateID, value) leaves appended to the tree going from `h₀` to `h₁`. A verifier can replay the proof to independently compute both `h₀` and `h₁` and confirm they match the Input Record hashes in consecutive UCs.

**How it works:** The round manager calls `batch_insert_with_proof` (in `crates/rsmt/src/consistency.rs`) instead of the plain `batch_insert`. This performs the same tree mutation in one pass while recording a flat pre-order opcode sequence (`ProofOp`):

| Opcode | Meaning |
|--------|---------|
| `S(hash)` | Unchanged subtree — carries its hash without traversal |
| `N(path)` | New junction node created by this batch |
| `Nx(path)` | Existing node traversed |
| `L(key)` | New leaf inserted |
| `Bl{old, key, val}` | Border leaf repositioned by the insertion |
| `Bns{old, new, lh, rh}` | Border node whose common prefix was shortened |

The opcode stream is CBOR-encoded and attached to the CR as the `zk_proof` field. BFT Core validators can verify it with `verify_consistency` before including the round in the certified ledger.

### Scaling beyond RAM (`--smt-backend disk`)

The in-memory SMT holds the entire tree in a heap-allocated Patricia trie. At ~200 bytes per node this exhausts a 16 GB machine at roughly 80 million leaves.

The disk-backed SMT uses a **materialise → insert → persist** cycle:

1. **Before** each round: `materializer` loads only the nodes on the batch keys' paths from RocksDB (plus sibling hashes as `Branch::Stub` stubs). All other nodes remain on disk.
2. **During**: `batch_insert` runs on the partial in-memory tree. Stubs act as opaque leaf hashes — they are never traversed, only their cached hash is used. Arc-based copy-on-write ensures only modified path nodes are cloned.
3. **After**: `persister` walks the modified tree, diffs it against the originally loaded set, and writes mutations to an `Overlay` (`HashMap<NodeKey, Option<bytes>>`).

On **BFT success**: `commit_overlay` flushes the overlay to a single RocksDB `WriteBatch` (atomic) and updates the LRU cache.
On **BFT rollback**: the overlay is dropped — RocksDB is never touched.

**Speculative execution** for the disk path uses a layered overlay:

```
proposed_snap  ──fork()──>  spec_snap
   own_overlay               own_overlay  (new mutations)
                             parent_overlay → proposed_snap's overlay (Arc clone)
```

The spec snapshot reads `own_overlay → parent_overlay → LRU cache → RocksDB`, seeing the proposed round's uncommitted mutations without any DB writes.

**Memory usage is bounded by batch size + cache size**, not total tree size. A 50 000-leaf batch against a 500 million-leaf tree materialises only ~50 000 × tree_depth ≈ 14 million nodes.

**Startup:** reads only the committed root hash from `smt_meta` — no leaf replay, no tree reconstruction.

---

## Project structure

```
rugregator/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── rsmt/                     # Standalone SMT library
│   │   └── src/
│   │       ├── tree.rs           # Core insertion, hash caching
│   │       ├── path.rs           # 272-bit sentinel-encoded paths
│   │       ├── hash.rs           # Go-compatible SHA-256 / CBOR hashing
│   │       ├── snapshot.rs       # O(1) copy-on-write snapshots (fork/commit/discard)
│   │       ├── consistency.rs    # batch_insert_with_proof, ProofOp, CBOR encoding
│   │       ├── proof.rs          # get_path, MerkleTreePath, CBOR wire format
│   │       ├── node_serde.rs     # Compact binary node serialisation
│   │       └── types.rs          # Branch, LeafBranch, NodeBranch, Stub
│   ├── smt-store/                # SMT storage backends
│   │   └── src/
│   │       ├── traits.rs         # SmtStore + SmtStoreSnapshot traits
│   │       ├── mem.rs            # MemSmt — fully in-memory (PersistMode: None/LeavesOnly/Full)
│   │       └── disk/
│   │           ├── store.rs      # DiskSmt — main disk-backed entry point
│   │           ├── materializer.rs # Partial tree loading from RocksDB
│   │           ├── persister.rs  # Post-mutation write-back
│   │           ├── overlay.rs    # Speculative write buffer
│   │           ├── cache.rs      # LRU node cache
│   │           ├── snapshot.rs   # DiskSmtSnapshot (layered overlays)
│   │           ├── node_key.rs   # Absolute bit-path DB keys
│   │           └── tests.rs      # Equivalence, rollback, restart, proof tests
│   └── aggregator/
│       └── src/
│           ├── main.rs           # Entry point, CLI, SMT backend wiring
│           ├── config.rs         # Config (--smt-backend and all other flags)
│           ├── storage.rs        # AggregatorState, on-demand proof generation
│           ├── storage_rocksdb.rs# RocksDB Store impl (records, blocks, meta CFs)
│           ├── api/              # HTTP server, JSON-RPC handlers, CBOR types
│           ├── round/
│           │   ├── manager.rs    # RoundManager<S: SmtStore>, speculative execution
│           │   ├── live_committer.rs  # libp2p BFT Core connectivity
│           │   └── state.rs      # ProcessedRecord
│           ├── validation/       # Predicate, StateID, signature checks
│           └── bin/
│               └── perf_test.rs  # SMT benchmark across all backends
├── aggregator-go/                # Go reference implementation
└── state-transition-sdk/         # TypeScript client SDK
```
