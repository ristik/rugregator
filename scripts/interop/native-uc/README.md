# Native verification of stub certificates

```sh
cargo run -q -p uni-aggregator --bin stub-anchor -- fixture > /tmp/stub-fixture.json
cd scripts/interop/native-uc && STUB_FIXTURE=/tmp/stub-fixture.json go test ./...
```

Verifies with bft-go-base `UnicityCertificate.Verify`, the strict trust-base seal verifier
and an aggregator-go consolidation session (pinned to a pushed commit in `go.mod`). Without
`STUB_FIXTURE` the test is skipped.
