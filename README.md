# Unicity Aggregator — Rust

An experimental aggregation node for the [Unicity](https://unicity.network) network. Accepts client transaction certification requests, batches them into rounds, proposes each round's state transition to BFT Core for certification, and returns verifiable inclusion proofs backed by a Radix / Sparse Merkle Tree (SMT).

This is a Rust reimplementation of `aggregator-go`, producing **wire-identical** outputs: same SMT root hashes, same CBOR encoding, same proof structure, but with real secure state transitions and optional consistency proofs for trustless operation.

The focus is on following features:
- Producing consistency poofs for every round of operation,
- Scaling beyond available system memory,
- speculative execution of next round while waiting for certification,
- better devex than current async submit request, poll for response until ready model (todo)
- Study if breaking changes to data structures are necessary

---

## Architecture

```
clients  ──POST /──>  JSON-RPC server  ──mpsc──>  RoundManager
                                                       │
                      AggregatorState  <───────────────┤  commit certified state
                           │                           │
                    DashMap<StateID,                   ├─ BFT Core (libp2p)
                      RecordInfo>                      │
                           │                       SparseMerkleTree
                    get_inclusion_proof                (in-memory or RocksDB-backed)
```

**Request flow:**

1. `POST /` — JSON-RPC 2.0 dispatch
2. `certification_request` — hex-CBOR payload → predicate + signature + StateID validation → queued in `RoundManager` via `mpsc`
3. `RoundManager` — collects requests, fires a round on a timer (default 1 s) or batch-size limit; creates an SMT snapshot, inserts leaves, proposes root hash to BFT Core, awaits the Unicity Certificate (UC)
4. On UC success — commits snapshot, stores finalized records; on repeat UC (rollback) — discards snapshot, re-queues requests
5. `get_inclusion_proof.v2` — returns `[blockNumber, [certData, merklePathCbor, ucCbor]]` from the certified SMT

**Speculative execution (both paths):** while waiting for the UC (~1.5 s), the next block's requests are inserted speculatively into a forked snapshot. On UC success the speculative snapshot is immediately promoted, eliminating dead time between rounds. On UC failure both snapshots are discarded and all requests are re-queued. The disk-backed path additionally uses a layered overlay so the speculative snapshot can read the proposed round's uncommitted mutations without any RocksDB writes.

### Workspace crates

| Crate | Description |
|-------|-------------|
| `crates/rsmt` | Standalone Sparse Merkle Tree library — path-compressed 272-bit Patricia trie, Go-compatible hashing, consistency proofs, serialisation. No async, no I/O. |
| `crates/aggregator` | The aggregator service — HTTP API, round management, BFT Core connectivity, RocksDB persistence. |

---

## Prerequisites

| Tool | Minimum version | Notes |
|------|----------------|-------|
| Rust | 1.75 | `rustup update stable` |
| C compiler | any | required by `secp256k1-sys` and `librocksdb-sys` |
| CMake | 3.x | required by `librocksdb-sys` (RocksDB feature only) |
| Clang / LLVM | any | required by `bindgen` (RocksDB feature only) |

On macOS all dependencies arrive via Xcode Command Line Tools + Homebrew (`brew install cmake llvm`). On Debian/Ubuntu: `apt install build-essential cmake clang`.

---

## Build

```bash
# Base build (in-memory SMT, no RocksDB)
cargo build --workspace

# Release build
cargo build --workspace --release

# With RocksDB persistence and disk-backed SMT (requires cmake + clang)
cargo build --workspace --release --features rocksdb-storage
```

> **Note:** The first build with `rocksdb-storage` compiles librocksdb from source and takes several minutes. Subsequent builds are incremental.

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

The stub BFT committer signs its own UCs with a hardcoded test key — no BFT Core process needed.

### In-memory with persistence

```bash
cargo run --release --features rocksdb-storage -p uni-aggregator --bin aggregator -- \
  --bft-mode stub \
  --db-path /var/lib/aggregator/db \
  --cache-capacity 1000000
```

On restart the aggregator recovers block number, records, and SMT root from RocksDB automatically. No leaf replay is needed — internal nodes are persisted alongside leaves.

### Live BFT Core

```bash
cargo run --release --features rocksdb-storage -p uni-aggregator --bin aggregator -- \
  --bft-mode live \
  --bft-peer-id  <BFT_CORE_PEER_ID> \
  --bft-addr     /ip4/<BFT_HOST>/tcp/26652 \
  --p2p-addr     /ip4/0.0.0.0/tcp/0 \
  --auth-key-hex <32-byte-hex-secp256k1-auth-key> \
  --sig-key-hex  <32-byte-hex-secp256k1-signing-key> \
  --partition-id 1 \
  --db-path      /var/lib/aggregator/db \
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
| `--cache-capacity` | `AGGREGATOR_CACHE_CAPACITY` | `500000` | Disk-SMT LRU node cache size |
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
   The block number advances by 1 each time a round is certified. Watch it climb in the logs.

6. **Recovery after restart.** Stop the aggregator at any time and restart with the same `--db-path`. The aggregator reads the persisted block number and SMT root, reconnects to BFT Core, and continues from where it left off — no replay needed.

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
# All tests (both crates)
cargo test --workspace

# SMT crate only
cargo test -p rsmt

# Aggregator crate only
cargo test -p uni-aggregator

# With RocksDB disk-backed SMT integration tests
cargo test --workspace --features rocksdb-storage

# Run a specific test
cargo test -p rsmt consistency::tests::two_leaf_consistency
cargo test -p uni-aggregator smt_disk::tests::proof_equivalence
```

---

## Performance benchmarks

### SMT-only benchmark

Measures raw insertion throughput and proof-generation latency for the in-memory or disk-backed SMT in isolation, with no BFT Core or HTTP overhead.

```bash
# In-memory (default)
cargo run --release -p uni-aggregator --bin perf-test -- \
  --rounds 6 --batch-sizes 1000,5000,10000

# Disk-backed (requires rocksdb-storage feature)
cargo run --release --features rocksdb-storage -p uni-aggregator --bin perf-test -- \
  --disk --cache-capacity 500000 \
  --rounds 6 --batch-sizes 1000,5000,10000

# CSV output for plotting
cargo run --release --features rocksdb-storage -p uni-aggregator --bin perf-test -- \
  --disk --rounds 8 --batch-sizes 1000,5000,10000,25000 --csv
```

Each run inserts batches cumulatively so tree size grows across rounds, revealing how throughput degrades as the working set grows. The disk-backed mode additionally reports commit latency (RocksDB write) separately from insertion.

Reported columns:

| Column | Description |
|--------|-------------|
| `pre_fill` | Leaves already in the tree before this batch |
| `inserted` | Leaves actually inserted (duplicates skipped) |
| `leaves/s` | Insertion throughput |
| `insert` | Time to insert + compute root hash (in-memory) / materialise + insert + persist to overlay (disk) |
| `commit` | Root computation time (in-memory) / RocksDB write time (disk) |
| `proof p50/p95` | Inclusion proof generation latency percentiles |

### E2E benchmark (stub BFT, local client)

Start the aggregator in stub BFT mode, then drive it with a load generator. The [State Transition SDK](state-transition-sdk/) provides a TypeScript client; the Go client in `aggregator-go/examples/client/` also works.

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

### E2E benchmark (live BFT Core)

With a real BFT Core node running on your network:

1. Start the aggregator in live mode (see [Running](#running) above).
2. Point a load generator at the aggregator's HTTP endpoint.
3. Monitor BFT Core round latency (typically 1–2 s per round) and per-round throughput.

Key metrics to watch:
- **Round throughput**: `certified / round_duration` — how many state transitions are certified per second end-to-end
- **Speculative fill rate**: if `spec_queued > 0` in most rounds, the aggregator is fully pipelining; the BFT latency is completely hidden

---

## Standout features

### O(1) copy-on-write snapshots

The SMT tree uses `Arc<Branch>` children everywhere. `SmtSnapshot::create()` and `fork()` are O(1): they clone two Arc reference counts at the root rather than deep-copying the tree. Modified nodes are path-copied (`Arc::try_unwrap` unwraps shared nodes in-place; clones only when shared), so speculative execution adds at most O(batch_size × tree_depth) new allocations per round — not another copy of the entire tree.

Peak memory during a speculative round is roughly 1× tree size + O(batch). Without CoW it would be 2–3× tree size.

### Consistency proofs for trustless operation

Every Certification Request sent to BFT Core can optionally carry a **consistency proof** — a compact CBOR-encoded witness that the new SMT root was derived from the previous certified root by appending only the declared leaves, with no deletions or modifications.

Enable with `--consistency-proofs`:

```bash
cargo run --release --features rocksdb-storage -p uni-aggregator --bin aggregator -- \
  --bft-mode live --consistency-proofs …
```

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

Without this proof, the only guarantee a client has is that the aggregator's claimed root hash was signed by a BFT quorum — the aggregator could have silently dropped or modified leaves. With the proof, every state transition included in a block is individually verifiable from the public ledger.

### Scaling beyond RAM

The in-memory SMT holds the entire tree in a heap-allocated Patricia trie. At ~200 bytes per node (path + hash + pointers) this exhausts a 16 GB machine at roughly 80 million leaves.

Enable the disk-backed SMT with `--features rocksdb-storage` and `--db-path`:

```bash
cargo run --release --features rocksdb-storage -p uni-aggregator --bin aggregator -- \
  --db-path /data/aggregator/smt \
  --cache-capacity 2000000 \
  …
```

**Architecture (materialize-before / persist-after):**

The rsmt algorithms operate on an in-memory tree of `Arc<Branch>` nodes. The disk layer wraps them with a materialize → insert → persist cycle:

1. **Before** each round: `materializer` loads only the nodes on the batch keys' paths from RocksDB (plus sibling hashes as `Branch::Stub` stubs). All other nodes remain on disk.
2. **During**: `batch_insert` runs on the partial in-memory tree. Stubs act as opaque leaf hashes — they are never traversed, only their cached hash is used. Arc-based copy-on-write ensures only modified path nodes are cloned; unchanged subtrees share memory.
3. **After**: `persister` walks the modified tree, diffs it against the originally loaded set, and writes mutations to an `Overlay` (`HashMap<NodeKey, Option<bytes>>`).

On **BFT success**: `commit_overlay` flushes the overlay to a single RocksDB `WriteBatch` (atomic) and updates the LRU cache.
On **BFT rollback**: the overlay is dropped — RocksDB is never touched.

**Speculative execution for the disk path** uses a layered overlay:

```
proposed_snap  ──fork()──>  spec_snap
   own_overlay               own_overlay  (new mutations)
                             parent_overlay → proposed_snap's overlay (Arc clone)
```

The spec snapshot materializes nodes by reading `own_overlay → parent_overlay → LRU cache → RocksDB`, so it can see the proposed round's uncommitted mutations without any DB writes. When the UC arrives:
- **Success**: proposed overlay → RocksDB; spec overlay promoted to next proposed; new spec forked.
- **Failure**: both overlays discarded; all requests re-queued.

**Memory usage is bounded by batch size + cache size**, not total tree size. A 50 000-leaf batch touching a tree of 500 million leaves materialises only ~50 000 × tree_depth ≈ 14 million nodes — most of which are siblings collapsed to hashes.

The LRU cache (`--cache-capacity`) keeps recently accessed nodes warm. After the initial cold-start, proof generation for recently inserted leaves typically hits cache for all sibling hashes along the path, avoiding disk reads.

**Startup:** the aggregator reads the committed root hash from `smt_meta` CF in RocksDB and is immediately ready to propose — no leaf replay, no tree reconstruction.

---

## Project structure

```
rugregator/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── rsmt/                     # Standalone SMT library
│   │   └── src/
│   │       ├── tree.rs           # Core insertion, hash caching, deep_clone
│   │       ├── path.rs           # 272-bit sentinel-encoded paths
│   │       ├── hash.rs           # Go-compatible SHA-256 / CBOR hashing
│   │       ├── snapshot.rs       # O(1) copy-on-write snapshots (fork/commit/discard)
│   │       ├── consistency.rs    # batch_insert_with_proof, ProofOp, CBOR encoding
│   │       ├── proof.rs          # get_path, MerkleTreePath, CBOR wire format
│   │       ├── node_serde.rs     # Compact binary node serialisation (for disk)
│   │       └── types.rs          # Branch, LeafBranch, NodeBranch (Arc<Branch> children), Stub
│   └── aggregator/
│       └── src/
│           ├── main.rs           # Entry point, CLI, wiring
│           ├── config.rs         # Config + RoundConfig
│           ├── storage.rs        # AggregatorState, on-demand proof generation
│           ├── storage_rocksdb.rs# RocksDB Store impl
│           ├── api/              # HTTP server, JSON-RPC handlers, CBOR types
│           ├── round/
│           │   ├── manager.rs    # RoundManager, speculative execution, BftCommitter
│           │   ├── live_committer.rs  # libp2p BFT Core connectivity
│           │   └── state.rs      # ProcessedRecord
│           ├── smt/              # Re-exports rsmt wholesale
│           ├── smt_disk/         # Disk-backed SMT layer (rocksdb-storage feature)
│           │   ├── store.rs      # DiskBackedSmt — main entry point
│           │   ├── materializer.rs # Partial tree loading
│           │   ├── persister.rs  # Post-mutation write-back
│           │   ├── overlay.rs    # Speculative write buffer
│           │   ├── cache.rs      # LRU node cache
│           │   ├── snapshot.rs   # DiskSmtSnapshot (create/fork/commit/discard, layered overlays)
│           │   ├── node_key.rs   # Absolute bit-path DB keys
│           │   └── tests.rs      # Equivalence, rollback, restart, proof tests
│           ├── validation/       # Predicate, StateID, signature checks
│           └── bin/
│               └── perf_test.rs  # SMT benchmark (in-memory and disk)
├── aggregator-go/                # Go reference implementation
├── state-transition-sdk/         # TypeScript client SDK
└── wild-puzzling-castle.md       # Disk-backed SMT design doc
```
