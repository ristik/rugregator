# Long-poll interop (servers × clients)

Rust driver (`rust/interop_lp.rs`), `run.sh`, `go-commitment.sh` (Go A4 `cmd/commitment`), `report.py` (L1 byte comparison of two servers). Results and
analysis: `orchestration/interop-lp.md`; raw lines in `results/`. The JS runner lives in state-transition-sdk-js (`scripts/lp-interop`, `compat/released-3.0.1`).

Servers are the ones of `../matrix` (S1 = this repo, S2 via `../matrix/s2/s2.sh`, which now also passes `LONG_POLL_MAX_WAITERS` through). See `run.sh` for the environment.
Scenarios: L1 raw no-wait requests (compare two servers with `report.py`), L2 happy path, L3 timeout/deadline, L4 batch, L5 fallback, L6 cap 0, L7 open-loop measurement
(`IX_N`, `IX_RATE`).
