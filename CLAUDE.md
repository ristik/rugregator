# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```bash
# Build everything
cargo build --workspace

# Build release
cargo build --workspace --release

# Run all tests
cargo test --workspace

# Test a single crate
cargo test -p rsmt
cargo test -p uni-aggregator

# Run a single test by name (substring match)
cargo test -p rsmt consistency::tests::two_leaf_consistency
cargo test -p uni-aggregator smt::

# Run the aggregator (stub BFT mode, no external dependencies)
cargo run -p uni-aggregator --bin aggregator -- --bft-mode stub

# Run the performance benchmark
cargo run --release -p uni-aggregator --bin perf-test -- --rounds 4 --batch-sizes 1000,5000
```

## Architecture

This is a Rust reimplementation of `aggregator-go/`, a blockchain aggregation service for the Unicity network. It must produce wire-identical outputs to the Go implementation (same SMT root hashes, same CBOR encoding, same proof structure).

### Workspace crates

- **`crates/rsmt`** — Standalone Sparse Merkle Tree library. Go-compatible path-compressed Patricia trie with 272-bit keys (sentinel-encoded `BigUint`). No async, no application logic.
- **`crates/aggregator`** — The aggregator service. Re-exports `rsmt` wholesale via `pub use rsmt::*` in `smt/mod.rs`.

### SMT (rsmt crate)

The tree uses sentinel-bit path encoding identical to the Go implementation: `path(k, bits) = (1 << k) | bits`. Key length is 272 bits.

`SmtSnapshot` provides copy-on-write snapshots: `SmtSnapshot::create(tree)` starts a speculative round; `snap.commit(tree)` atomically applies it on BFT success; dropping the snapshot discards it on failure.

Two batch-insert modes share one internal algorithm:
- `batch_insert(tree, batch)` — inserts only, no overhead
- `batch_insert_with_proof(tree, batch)` — also returns a `ConsistencyProof` (flat pre-order opcode list for BFT's `zk_proof` field)

Consistency proof opcodes: `S` (unchanged subtree hash), `N` (new junction — pass-through in verifier), `Nx` (existing node traversed — always `hash_node`), `L` (new leaf), `Bl` (border leaf), `Bns` (border node shortened). The `N`/`Nx` distinction is critical: Go always calls `hash_node()` even on single-child nodes, so existing nodes never short-circuit.

### Aggregator service

Request flow:
1. HTTP `POST /` → JSON-RPC dispatch (`api/server.rs`)
2. `certification_request`: deserialize hex-CBOR → validate predicate + signature + StateID → send `ValidatedRequest` to `RoundManager` via `mpsc`
3. `RoundManager` (single tokio task) collects requests, fires a round on timer/batch limit, creates `SmtSnapshot`, inserts leaves, submits root to BFT Core, awaits UC, commits snapshot, stores records
4. `get_inclusion_proof.v2`: reads from `AggregatorState` stores, returns CBOR `[blockNumber, [certData, merklePathCbor, ucCbor]]`

State is shared as `Arc<AggregatorState>` between HTTP handlers and the round manager. `AggregatorState` contains a `DashMap` for record lookup and `RwLock<BlockStore>` for block metadata.

### BFT Core integration

`BftCommitter` trait in `round/manager.rs`. Two implementations:
- `BftCommitterStub` — no-op, immediately returns a dummy UC (for `--bft-mode stub`)
- `LiveBftCommitter` (`round/live_committer.rs`) — real libp2p-based connection to BFT Core Go service

### Validation pipeline (`validation/`)

1. **Predicate**: engine=1, code=`[0x01]`, params=33-byte compressed secp256k1 pubkey
2. **StateID**: must equal `SHA256(CborArray(2) || cbor(predicate) || CborBytes(sourceStateHash))` as a 32-byte raw hash
3. **Signature**: secp256k1 over `SHA256(CborArray(2) || CborBytes(sourceStateHash) || CborBytes(transactionHash))`

Leaf value stored in the SMT is `CertDataHash`: `SHA256(CborArray(4) || cbor(predicate) || CborBytes(ssh) || CborBytes(txh) || CborBytes(witness))` as a 34-byte imprint.

### Go compatibility

CBOR is hand-assembled (not via ciborium's value API) to exactly match Go's `fxamacker/cbor` output. Hash inputs are constructed as `SHA256(cbor_array_header || cbor_bytes(field1) || ...)` — concatenated raw bytes, not a serialized CBOR value. See `rsmt/hash.rs` for leaf/node hash implementations and `aggregator/api/cbor.rs` for wire types.

The Go aggregator reference is in `aggregator-go/`. Cross-validate any SMT or hashing changes against its test vectors.
