| scenario | S1 rugregator × Go | S1 rugregator × JS | S1 rugregator × Rust | S2 aggregator-go × Go | S2 aggregator-go × JS | S2 aggregator-go × Rust |
|---|---|---|---|---|---|---|
| 1 submit and wait | PASS | PASS | PASS | PASS | PASS | PASS |
| 1b reference-tool request (aggregateRequestCount=1) | PASS | N-A | N-A | PASS | N-A | N-A |
| 2 consolidate latest (direct unsharded) | PASS | PASS | PASS | PASS | PASS | PASS |
| 3 exact root (retained, other-state, unknown) | PASS | PASS | PASS | PASS | PASS | PASS |
| 3b evicted root | PASS | PASS | PASS | PASS | PASS | PASS |
| 4 status hints (pending/unknown) and data.indexes | PASS | PASS | PASS | PASS | PASS | PASS |
| 4b expired hint | N-A | N-A | N-A | PASS | PASS | PASS |
| 5 non-inclusion (absent, present, tampered) | PASS | PASS | PASS | PASS | PASS | PASS |
| 6 error envelope (limits, malformed params) | PASS | PASS | PASS | PASS | PASS | PASS |

totals: N-A=7, PASS=47
