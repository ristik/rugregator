# Stub BFT mode: native-valid certificates, anchor and migration

`--bft-mode stub` stands in for BFT Core. Its unicity certificates (UCs) are
checked by the same verifiers as real ones — Go `UnicityCertificate.Verify`, the
aggregator-go consolidation client and both state-transition SDKs — so the stub
issues certificates that are valid under the **native** rules instead of asking
verifiers to tolerate malformed ones. No verifier is relaxed.

## Profile (`crates/aggregator/src/round/stub_uc.rs`)

| Field | Value |
|---|---|
| partition | `--partition-id` (default **1**); 0 is refused |
| shard | the empty shard ID, no sibling hashes (`--shard-id` must be `0x80`) |
| network / epoch / epoch start | 3 (LOCAL) / 1 / root round 1; shard and root epoch are both 1 |
| shard round, seal root round | the block number (blocks start at 1, so every seal is at or after the epoch start) |
| `InputRecord.hash` / `previousHash` | the aggregator root (empty bytes for an empty tree) / the previous block's root (`null` before the first state) |
| `InputRecord.blockHash` | present exactly when the state changed (native `InputRecord.IsValid`), `null` otherwise |
| `trHash` | SHA-256 of the technical record `[block+1, 1, "NODE", statHash, feeHash]`, 32 bytes, never null |
| `shardConfHash` | SHA-256 of `"rugregator-stub-shard-conf/v1" ‖ partition ‖ network ‖ epoch`; `stub-anchor fixture` prints it |
| unicity tree | single partition: seal hash = `H(0x01 ‖ key ‖ H(shardRoot))`, no hash steps |
| seal | signed over the unsigned seal by the single root node `NODE`; `previousHash` chains the previous seal hash |

## The explicit test trust anchor

```sh
cargo run -q -p uni-aggregator --bin stub-anchor -- trust-base [--partition-id N]
```

prints the matching `RootTrustBase` JSON (the shape the SDKs load): network 3,
epoch 1, epoch start 1, one node `NODE`, quorum 1. Its private key is a
published constant, so **this anchor is for tests only**. Never configure it as
the trust base of a real network.

`stub-anchor fixture` prints the anchor together with deterministic
certificates (first state, changed state, unchanged state, empty tree on both
sides) for cross-implementation verification.

## Verification

`scripts/interop/native-uc` verifies every fixture certificate with the Go
implementation: decode, `UnicityCertificate.Verify` against the anchor with the
expected partition, empty shard and configuration hash, the strict
trust-base seal verifier, an aggregator-go consolidation `Session`, a
byte-identical native re-encoding, the technical-record hash, and the state
hash. See that directory for the command. The Rust and JS SDK checks are
described in the PR.

## Existing experimental data

Certificates issued by earlier stub builds (partition 0, null `trHash`, epoch
0, zero configuration hash) are **not** repaired in transit: relabelling a
signed UC would invalidate its signature, and padding the hash would be a forgery.
Native verifiers and secure batch clients reject them, and rejecting them is
correct.

The aggregator logs a warning at startup when the latest recovered
certificate carries a legacy marker (`round::stub_uc::legacy_stub_marker`;
real certificates never do). Choose one:

1. **Reset (recommended for test data).** Stop the aggregator, delete its
   `--db-path` directory (or restart without one for the in-memory mode) and
   start again. Block numbers restart at 1; clients must re-submit. All
   certificates are then native-valid and match the anchor.
2. **Keep the data, decline secure batching for it.** Leave the directory as it
   is. Legacy single-proof responses keep working for clients that do not verify
   natively; secure batch capability must not be advertised for blocks whose UC
   `legacy_stub_marker` reports. Blocks issued after the upgrade are native-valid,
   but a restored tree mixes both kinds until a reset, so a latest-root batch can
   only be trusted after a reset.

Real (live) deployments are unaffected: their certificates are already
native-valid and need neither the stub nor the anchor.
