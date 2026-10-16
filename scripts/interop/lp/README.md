# Long-poll interop (servers × clients)

Rust driver (`rust/interop_lp.rs`), `run.sh`, `go-commitment.sh` (Go A4 `cmd/commitment`), `report.py` (L1 byte comparison of two servers). Results and
analysis: `orchestration/interop-lp.md`; raw lines in `results/`. The JS runner lives in state-transition-sdk-js (`scripts/lp-interop`, `compat/released-3.0.1`).

Servers are the ones of `../matrix` (S1 = this repo, S2 via `../matrix/s2/s2.sh`, which now also passes `LONG_POLL_MAX_WAITERS` through). See `run.sh` for the environment.
Scenarios: L1 raw no-wait requests (compare two servers with `report.py`), L2 happy path, L3 timeout/deadline, L4 batch, L5 fallback, L6 cap 0, L7 open-loop measurement
(`IX_N`, `IX_RATE`).

## Recipe and notes
- Exact revisions of the committed results: `results/VERSIONS`. Run order: start one stack (`../matrix/s2/s2.sh up`, optionally `LONG_POLL_MAX_WAITERS=0`), then
  `SDK_RUST_DIR=… S2_TRUSTBASE=… run.sh s2lp` (and `IX_SCEN=L7 IX_N=200 IX_RATE=10 run.sh s2lp` ×3 for the measurement; copy `s2lp-L7-rust.jsonl` to `…-repN-…`
  between repetitions), `report.py results s2base s2lp`, `AGG_GO_DIR=… IX_URL=… go-commitment.sh <label> 3`, then `s2.sh down`.
- `run.sh` exits non-zero when the driver exits non-zero, prints no result line, or any line is `FAIL`; a driver panic is reported as a `FAIL` line of that scenario
  (the others still run). It refuses to overwrite a different `$SDK_RUST_DIR/tests/interop_lp.rs`, removes its copy and its temp dir on every exit path, and refuses
  to start S1 when the port already answers.
- The Rust build creates a `target/` inside `SDK_RUST_DIR` (~1 GB): delete it after the run (disk rule: one Rust target per repo).
- `results/*-go.jsonl` use the same `status` field as the Rust lines (`PASS` iff the proof was verified).
