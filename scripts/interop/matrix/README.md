# Interop matrix (servers × clients)

Cross-implementation loopback matrix for the batch inclusion proof, non-inclusion and error-envelope
paths. Evidence and findings: `orchestration/interop.md`; last results: `results/` (JSON lines per
server × client, `matrix.md`).

| | |
|---|---|
| S1 | rugregator `batch-inclusion` (stub BFT, native-valid stub UCs and the explicit test anchor) |
| S2 | aggregator-go with a real single-shard (unsharded) bft-core root, `s2/` |
| C1 | Go reference client (`pkg/consolidation/client`, `pkg/noninclusion`), `go/main.go` |
| C2 | Rust SDK (`ProofClient`, `HttpAggregatorClient`, NI verification), `rust/interop_matrix.rs` |
| C3 | JS SDK (`ProofConsolidator`, `AggregatorClient`, `verifyNonInclusion`), `js/InteropMatrixTest.ts` |

Each driver prints one JSON line per scenario (`PASS|FAIL|N-A` + evidence). Scenarios: 1 submit/wait
(1b: request as `cmd/commitment` builds it), 2 consolidation through `get_inclusion_proofs.v1` latest (direct
unsharded path: one request, no partition view), 3 exact root (3b: evicted root), 4 status hints and
`data.indexes` (4b: expired), 5 non-inclusion (absent, present, every single-bit tamper), 6 error envelope
(`envelope_cases.json`).

```sh
cargo build --release -p uni-aggregator --bins           # S1 (and stub-anchor)
export AGG_GO_DIR=…/aggregator-go SDK_RUST_DIR=…/state-transition-sdk-rust SDK_JS_DIR=…/state-transition-sdk-js
(cd "$SDK_JS_DIR" && npm ci)
scripts/interop/matrix/run.sh s1 go rust js              # starts a fresh S1 per client
S2_DATA=$HOME/ix-s2-data AGG_GO_DIR=$AGG_GO_DIR scripts/interop/matrix/s2/s2.sh up   # prints the trust base path
S2_TRUSTBASE=$HOME/ix-s2-data/genesis/trust-base.json scripts/interop/matrix/run.sh s2 go rust js
scripts/interop/matrix/s2/s2.sh down
python3 scripts/interop/matrix/report.py scripts/interop/matrix/results
```

`run.sh` copies each driver into the client checkout (`cmd/interop-matrix/`, `tests/interop_matrix.rs`,
`tests/interop/`), the only way to reach the Go `internal/` packages and the SDK test utilities without
committing workstation paths. Remove those files afterwards (`git status` in the checkout).
`s2.sh up` takes the shared Docker lock (`/tmp/uc-docker.lock`) and holds it until `down`; its data directory must be
under `$HOME` (the colima VM mounts only the home directory) and the stack avoids the RocksDB image build.
The Go client needs the G4 direct unsharded path (aggregator-go #217; contained in `non-inclusion`).
