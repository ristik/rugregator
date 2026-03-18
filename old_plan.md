# Rugregator: Rust Aggregator Implementation Plan

## Context

Replace the Go aggregator (`aggregator-go/`) with a Rust implementation that:
- Receives certification requests from TypeScript SDK clients via JSON-RPC/HTTP
- Batches them into a Sparse Merkle Tree (path-compressed Patricia trie)
- Certifies the SMT root via BFT Core (using existing `crates/bft-committer`)
- Returns inclusion proofs to clients
- Must be wire-compatible with `state-transition-sdk` (TypeScript)

---

## 1. Workspace & Module Structure

```
Cargo.toml                          (workspace)
crates/
  bft-committer/                    (existing, reused as-is)
  aggregator/
    Cargo.toml
    src/
      main.rs                       entry point, tokio runtime, config
      lib.rs                        re-exports
      config.rs                     CLI (clap) + env + TOML config
      smt/
        mod.rs
        path.rs                     sentinel-encoded BigUint path ops
        hash.rs                     Go-compatible leaf/node hashing (CBOR helpers)
        types.rs                    LeafBranch, NodeBranch, Branch enum
        tree.rs                     SparseMerkleTree: insert, find, root hash
        proof.rs                    inclusion proof generation (MerkleTreePath)
        snapshot.rs                 copy-on-write snapshot for speculative processing
        consistency.rs              [feature: consistency-proofs] opcode proof gen
      api/
        mod.rs
        server.rs                   axum HTTP server, JSON-RPC dispatch
        types.rs                    CertificationRequest, CertificationData, Predicate, StateId wire types
        cbor.rs                     CBOR ser/deser for client wire protocol
        handlers.rs                 certification_request, get_inclusion_proof.v2, get_block_height
      round/
        mod.rs
        manager.rs                  RoundManager: collect, process, certify, finalize
        state.rs                    Block metadata, pending request tracking, rollback
      validation/
        mod.rs
        predicate.rs                PayToPublicKey verification (engine=1, code=[1], 33-byte key)
        signature.rs                secp256k1 ECDSA verify
        state_id.rs                 StateID recomputation & check
      storage.rs                    in-memory stores (blocks, records); [feature: rocksdb] persistent
```

### Key dependencies
| Purpose | Crate |
|---------|-------|
| HTTP | `axum` + `tower` |
| JSON-RPC | hand-rolled (3 methods, straightforward) |
| CBOR | `ciborium` (matches bft-committer) |
| Hash | `sha2` (default); `blake3` feature-gated |
| Crypto | `secp256k1` (sig verification) |
| BigInt | `num-bigint` + `num-traits` |
| Async | `tokio` |
| Logging | `tracing` + `tracing-subscriber` |
| Config | `clap` + `serde` |

### Feature flags (`Cargo.toml`)
```toml
[features]
default = []
consistency-proofs = []
rocksdb-storage = ["dep:rocksdb"]
parallel = ["dep:rayon"]
blake3-hash = ["dep:blake3"]
```

---

## 2. SMT Implementation (Critical Path)

### 2.1 Path Encoding

Sentinel-bit encoding identical to Go and Python: `path(k, bits) = (1 << k) | bits`

```rust
type SmtPath = num_bigint::BigUint;

fn path_len(p: &SmtPath) -> usize { p.bits() as usize - 1 }
fn path_as_bytes(p: &SmtPath) -> Vec<u8> { p.to_bytes_be() }  // matches Go BigintEncode
fn remaining_path(key: &SmtPath, start_bit: usize, depth: usize) -> SmtPath {
    (BigUint::one() << (depth - start_bit)) | (key >> start_bit)
}
```

Key length = 272 bits (standalone mode). Root path = `BigUint::from(1u8)`.

### 2.2 StateID to SMT Path

From `aggregator-go/pkg/api/state_id.go:46-61`:
```rust
fn state_id_to_smt_path(state_id: &[u8]) -> BigUint {
    let padded = if state_id.len() == 32 {
        let mut buf = vec![0u8; 34]; buf[2..].copy_from_slice(state_id); buf
    } else { state_id.to_vec() };
    let mut key_bytes = vec![0x01];  // sentinel prefix preserving leading zeros
    key_bytes.extend_from_slice(&padded);
    BigUint::from_bytes_be(&key_bytes)
}
```

### 2.3 Hash Functions (Go-compatible)

From `aggregator-go/internal/smt/smt.go:281-373` and `pkg/api/cbor.go`:

**Leaf**: `SHA256( CborArray(2) || CborBytes(path_bytes) || CborBytes(value) )`
**Node**: `SHA256( CborArray(3) || CborBytes(path_bytes) || CborBytes_or_Null(left) || CborBytes_or_Null(right) )`

The CBOR is constructed incrementally (not full ciborium encoding) using manual header bytes:
```rust
fn cbor_head(major: u8, n: usize) -> Vec<u8> { /* standard CBOR length prefix */ }
fn cbor_array(n: usize) -> Vec<u8> { cbor_head(4, n) }
fn cbor_bytes(data: &[u8]) -> Vec<u8> { [cbor_head(2, data.len()), data].concat() }
fn cbor_null() -> Vec<u8> { vec![0xf6] }
```

Hash imprint format: `[algo_msb(0), algo_lsb(0), ...32_byte_hash]` (34 bytes).

### 2.4 Node Types

```rust
enum Branch {
    Leaf(LeafBranch),
    Node(NodeBranch),
}
struct LeafBranch { path: SmtPath, value: Vec<u8>, hash_cache: Option<[u8;32]> }
struct NodeBranch { path: SmtPath, left: Option<Box<Branch>>, right: Option<Box<Branch>>,
                    hash_cache: Option<[u8;32]>, is_root: bool }
```

### 2.5 Tree Operations

**Insert** follows Go's `buildTree` logic exactly:
1. `calculateCommonPath(remainingPath, branch.path)` - longest common prefix via LSB-first bit comparison
2. If leaf collision: split into NodeBranch with both leaves as children, paths shortened by common prefix
3. If node split in middle: create new NodeBranch, old becomes child
4. Recurse down left/right based on direction bit after common prefix

**Batch insert** (`AddLeaves`): iterates individual `AddLeaf` calls (matching Go). The Python batch algorithm is for consistency proofs (phase 2).

**Copy-on-write snapshots**: `CreateSnapshot()` shares root pointer; mutations clone nodes on the path from root to modification point.

### 2.6 Inclusion Proof Generation

From `aggregator-go/internal/smt/smt.go:597-701`:

Returns `MerkleTreePath { root: hex_imprint, steps: [MerkleTreeStep { path: bigint_decimal_string, data: hex_hash|null }] }`.

Steps are leaf-to-root. Leaf step has `(leaf.path_as_decimal, leaf.value_as_hex)`. Node steps have `(node.path_as_decimal, sibling_hash_as_hex|null)`.

### 2.7 CBOR Wire Format for MerkleTreePath

From `aggregator-go/pkg/api/smt_cbor.go`:
```
CBOR array [
  root: byte_string (raw imprint bytes),
  steps: array of [
    path: byte_string (BigInt.Bytes() big-endian),
    data: byte_string | null
  ]
]
```

---

## 3. API Layer

### 3.1 JSON-RPC Server (axum)

Single route `POST /` with JSON-RPC 2.0. Health endpoint `GET /health`.

### 3.2 Methods

| Method | Params | Response |
|--------|--------|----------|
| `certification_request` | hex-encoded CBOR string | `{status: "SUCCESS"\|...}` |
| `get_inclusion_proof.v2` | `{stateId: "<hex>"}` | hex-encoded CBOR of `[blockNumber, InclusionProof]` |
| `get_block_height` | `{}` | `{blockNumber: "<N>"}` |

### 3.3 CertificationRequest Deserialization

Hex string -> bytes -> CBOR array `[StateId(32 bytes), CertificationData([Predicate, SourceStateHash(32), TransactionHash(32), Witness(65)]), bool, uint]`

Predicate is CBOR array `[engine: uint, code: bstr, params: bstr]` encoded via `fxamacker/cbor` with `toarray` tag — must match exactly using `ciborium` + `serde_tuple`.

### 3.4 Validation (from `aggregator-go/internal/signing/certification_request_validator.go`)

1. Predicate: engine=1, code=[0x01], params=33-byte compressed secp256k1 pubkey
2. SourceStateHash: exactly 32 bytes
3. TransactionHash: exactly 32 bytes
4. Witness: exactly 65 bytes
5. StateID = SHA256(CborArray(2) || Cbor.Marshal(predicate) || CborBytes(sourceStateHash)).RawHash — must equal provided StateID
6. Signature: verify secp256k1 over SHA256(CborArray(2) || CborBytes(sourceStateHash) || CborBytes(transactionHash))

### 3.5 Leaf Value for SMT

`CertDataHash` = SHA256(CborArray(4) || Cbor.Marshal(predicate) || CborBytes(sourceStateHash) || CborBytes(transactionHash) || CborBytes(witness)).GetImprint()` — this 34-byte imprint is the leaf value.

### 3.6 InclusionProof Response

CBOR array: `[blockNumber: uint, [certificationData: CborBytes|null, merkleTreePath: CborBytes, unicityCertificate: CborBytes]]`

---

## 4. Concurrency Model

```
HTTP handlers (N tokio tasks)
    |
    | mpsc::Sender<ValidatedRequest>
    v
RoundManager (1 tokio task, select! loop)
    |--- round timer ticks -> process batch
    |--- request_rx.recv() -> accumulate
    |--- uc_rx.recv() -> finalize/rollback
    |
    v
BftCommitter (existing crate, async)
    |
    v
BFT Core (external Go service)
```

**Shared state:**
- `Arc<RwLock<SparseMerkleTree>>` — read lock for inclusion proofs, write lock only during snapshot commit
- `Arc<RwLock<BlockStore>>` — block number -> (root_hash, UC)
- `Arc<DashMap<StateId, RecordInfo>>` — StateID -> (block_number, cert_data) for dedup and proof lookup

### Speculative Pipeline

```
Round N: [collect] -> [insert snapshot N] -> [submit BFT] ──> UC arrives
Round N+1 (speculative): [collect] -> [insert snapshot N+1 (forked from N)]
                                       |
                          On UC(N) valid: commit snapshot N, rebase N+1
                          On UC(N) fail:  discard N and N+1, re-queue requests
```

Start with non-speculative (sequential) processing. Add speculative after core works.

---

## 5. Round Management

### Lifecycle
```
COLLECTING ──(timer/batch_limit)──> PROCESSING ──> CERTIFYING ──(UC)──> FINALIZING ──> COLLECTING
```

**Config**: `round_duration` (default 1s), `batch_limit` (default 1000), `max_per_round` (default 10000)

### RoundManager fields
```rust
struct RoundManager {
    request_rx: mpsc::Receiver<ValidatedRequest>,
    smt: Arc<RwLock<SparseMerkleTree>>,
    bft_committer: BftCommitter,
    block_store: Arc<RwLock<BlockStore>>,
    record_store: Arc<DashMap<Vec<u8>, RecordInfo>>,
    current_block_number: u64,
    pending: Vec<ValidatedRequest>,
    current_snapshot: Option<SmtSnapshot>,
    uc_rx: mpsc::Receiver<(UnicityCertificate, TechnicalRecord)>,
}
```

### Batch processing
1. Drain `pending` requests
2. Create snapshot from main tree (or speculative chain)
3. For each request: convert StateID -> SMT path, compute CertDataHash -> leaf value, `snapshot.AddLeaf(path, value)`
4. Get root hash imprint from snapshot
5. Call `bft_committer.commit_block(block_num, block_hash, prev_state_root, new_state_root, zk_proof)`

### Finalization (on UC callback)
1. `bft_committer.validate_uc(&uc)` -> if `Valid`:
   - `bft_committer.handle_uc_received(&uc, technical_record.round)`
   - Commit snapshot to main tree
   - Store block metadata (block_number, root_hash, UC bytes)
   - Store record entries (StateID -> block_number, cert_data)
   - Increment block number
2. If `Repeat` (timeout): update round state, keep current snapshot, re-submit
3. If `RoundMismatch`: discard snapshot, re-queue requests

---

## 6. Rollback

The snapshot/COW design makes rollback trivial:
- **Success**: `snapshot.commit()` replaces main tree root pointer
- **Failure**: drop snapshot (no side effects on main tree), re-queue pending requests
- Speculative snapshots (chained): if parent fails, all children are also discarded

---

## 7. Roadmap Feature Details

### Phase 1: Core Aggregator
- SMT with Go-compatible hashing
- JSON-RPC API (3 methods)
- Request validation
- Sequential round processing (no speculation)
- BFT Core integration via bft-committer
- In-memory stores

### Phase 2: Consistency Proofs (`#[cfg(feature = "consistency-proofs")]`)
- Switch from Go-style individual `AddLeaf` to Python-style `batch_insert` with proof generation
- Proof opcodes: S, N, L, BL, BNS (flat list, pre-order traversal)
- Proof passed as `zk_proof` in `BlockCertificationRequest`
- Verification via `synchronized_proof_eval` (for self-test)
- Tree shape must remain identical (same Patricia trie for same keys)

### Phase 3: RocksDB Persistence (`#[cfg(feature = "rocksdb-storage")]`)
- Two column families: `leaves` (path -> value) and `nodes` (path -> serialized node)
- Atomic `WriteBatch` after each committed round
- LRU cache for recently accessed nodes (configurable size)
- `MultiGet` at round start for batch efficiency
- Rollback = don't write the batch

### Phase 4: Parallel Processing (`#[cfg(feature = "parallel")]`)
- Rayon for subtree sharding during batch insert
- Split sorted batch at root: left/right subtrees processed in parallel
- Thread count configurable
- Needs careful design if combined with consistency proofs

### Phase 5: Performance Testing
- Dedicated binary `cargo run --release --bin perf-test`
- Generate N random certification requests
- Measure: insertion throughput, proof latency (p50/p95/p99), memory
- Compare against Go aggregator

### Phase 6: Callback-based Responses
- Replace polling with server-push (WebSocket or SSE)
- Needs SDK-side changes too

### Phase 7: Configurable Hash
- `SmtHasher` trait abstracting hash function
- Runtime selection via config (SHA256 default, Blake3 option)

---

## 8. Testing Strategy

### Unit tests
1. **CBOR helpers**: verify `cbor_array`, `cbor_bytes`, `cbor_null` produce exact bytes
2. **Path encoding**: `path_as_bytes`, `path_len`, `calculateCommonPath` against known Go outputs
3. **Hash functions**: `hash_leaf`, `hash_node` cross-validated with Go test vectors
4. **SMT operations**: insert known keys, verify root hash matches Go
5. **Proof generation**: verify MerkleTreePath matches Go for same tree state
6. **Validation**: predicate, signature, StateID checks with known valid/invalid inputs
7. **Wire format**: CBOR encode/decode CertificationRequest, InclusionProofResponse, verify byte-exact match with SDK

### Integration tests
1. **BFT Core**: start single-node Go BFT Core, full certification round-trip
2. **SDK compatibility**: run TypeScript SDK tests against Rust aggregator (submit + poll proof)
3. **Round lifecycle**: multi-round batches, verify block heights, all proofs valid

### Test environment setup
- Single-node BFT Core from `bft-core/` (Go binary)
- Rust aggregator connects via libp2p
- TypeScript SDK sends requests to HTTP endpoint

### Cross-validation approach
Generate test vectors by running Go aggregator with known inputs, capture:
- SMT root hash after each batch
- Inclusion proof for specific StateIDs
- CBOR-encoded responses
Then verify Rust produces identical outputs.

---

## 9. Critical Compatibility Files

| What | File |
|------|------|
| SMT insert + proof | `aggregator-go/internal/smt/smt.go` |
| CBOR helpers | `aggregator-go/pkg/api/cbor.go` |
| Hashing | `aggregator-go/pkg/api/hash.go` |
| BigInt encoding | `aggregator-go/pkg/api/bigint.go` |
| StateID/path conversion | `aggregator-go/pkg/api/state_id.go` |
| MerkleTreePath CBOR | `aggregator-go/pkg/api/smt_cbor.go` |
| CertDataHash, SigDataHash | `aggregator-go/pkg/api/certification_request.go` |
| Predicate type | `aggregator-go/pkg/api/predicate.go` |
| Request validation | `aggregator-go/internal/signing/certification_request_validator.go` |
| BFT integration | `crates/bft-committer/src/committer.rs` |
| SDK wire protocol | `state-transition-sdk/src/api/` |

---

## 10. Implementation Order

1. `smt/hash.rs` + `smt/path.rs` — CBOR helpers and Go-compatible hashing (with unit tests against Go vectors)
2. `smt/types.rs` + `smt/tree.rs` — node types, `AddLeaf`, `calculateCommonPath`, root hash
3. `smt/proof.rs` — inclusion proof generation
4. `validation/` — predicate, signature, StateID checks
5. `api/types.rs` + `api/cbor.rs` — wire protocol types and CBOR ser/deser
6. `api/server.rs` + `api/handlers.rs` — JSON-RPC server
7. `round/manager.rs` + `round/state.rs` — round lifecycle (sequential first)
8. `main.rs` + `config.rs` — wire everything, BFT committer integration
9. `smt/snapshot.rs` — COW snapshots, speculative processing
10. Integration tests with BFT Core + SDK
