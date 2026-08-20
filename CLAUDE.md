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

This is a Rust reimplementation of `aggregator-go/`, a blockchain nullifier aggregation service for the Unicity network. It is not compatible with the implementation as the SMT tree structure, proof formats are completely different.

### Workspace crates

- **`crates/rsmt`** — Standalone Sparse Merkle Tree library implementing RSMT v6a (path-compressed Patricia trie, 256-bit keys, region-committing node hashes). No async, no application logic.
- **`crates/aggregator`** — The aggregator service. Re-exports `rsmt` wholesale via `pub use rsmt::*` in `smt/mod.rs`.

### SMT (rsmt crate) — RSMT v6a

A path-compressed radix trie (Patricia trie) over 256-bit keys, following the Unicity Yellowpaper's "Radix Sparse Merkle Trees" (RSMT v6a) format. Keys and regions are read as big-endian (MSB-first) bit strings: bit 0 is the MSB of byte 0.

**Hashing**: `hash_leaf(key, value) = H(0x00 ‖ key ‖ value)`; `hash_node(left, right, depth, region) = H(0x01 ‖ depth ‖ region ‖ left ‖ right)`. `region` is the absolute key prefix `[0..depth)` shared by every descendant key, packed into 32 bytes with bits `depth..256` cleared — an absolute property of the node, like `depth`, unaffected by edge splits above it. `NodeBranch.path` (`CompressedPath`) is a separate, purely local navigation aid — the common-prefix bits between a node and its parent — and is never hashed.

`SmtSnapshot` provides copy-on-write snapshots: `SmtSnapshot::create(tree)` starts a speculative round; `snap.commit(tree)` atomically applies it on BFT success; dropping the snapshot discards it on failure.

Two batch-insert modes share one internal algorithm:
- `batch_insert(tree, batch)` — inserts only, no overhead
- `batch_insert_with_proof(tree, batch)` — also returns a `ConsistencyProof` (flat post-order opcode list for BFT's `zk_proof` field)

Consistency proof opcodes (5): `S(h)` opaque preserved subtree (valid only under a pre-existing parent junction), `L` new leaf (consumed from sorted batch), `N(depth)` junction over the two preceding stack entries, `O(depth, region, left, right)` a preserved junction opened one level, `O_L(key, value)` a preserved leaf opened. `O`/`O_L` are required whenever a preserved subtree becomes the child of a junction created this round (an edge split, including the leaf-merge case) — an opaque `S` may never attach to a new edge, since the verifier needs the opened preimage to check the new edge against the child's authenticated depth and region. See `crates/rsmt-verify/src/consistency.rs` for the full stack-machine verifier.

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

Leaf value stored in the SMT is `SHA256(CborArray(2) || CborBytes(txh) || CborUint(tau))`, 32 raw bytes, where `tau` is the reference time of the round the request was validated in (`InputRecord.timestamp`, taken from the previous unicity seal). The batch a round declares to BFT Core carries the transaction hash instead, and the Core re-derives the stored value from the reference time it already enforces — see `rsmt-verify/src/leaf_value.rs`.

### Go compatibility

CBOR is hand-assembled (not via ciborium's value API) to exactly match Go's `fxamacker/cbor` output for the validation-pipeline hashes above (StateID, CertDataHash, signature preimage). Hash inputs are constructed as `SHA256(cbor_array_header || cbor_bytes(field1) || ...)` — concatenated raw bytes, not a serialized CBOR value. See `aggregator/validation/state_id.rs` for these hash constructions and `aggregator/api/cbor.rs` for wire types.

This is unrelated to the SMT tree's own leaf/node hashing (`rsmt/hash.rs`, `rsmt-verify/hash.rs`), which is plain domain-separated concatenation, not CBOR-based — see the "SMT (rsmt crate)" section above. The RSMT v6a hash formula (region + depth commitment, big-endian bit order) now matches `aggregator-go`'s `internal/smt`/`internal/smt/disk` implementation, which shipped the same v6a upgrade; the consistency-proof opcode stream, however, has no Go counterpart — `aggregator-go` does not implement consistency proofs at all. Cross-validate any SMT hashing changes against `aggregator-go/internal/smt` where a comparison point exists.
