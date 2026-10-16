# SDK checks of the stub fixture

Copy into a checkout of the SDK and run with `STUB_FIXTURE` set to the output of
`stub-anchor fixture` (see `../native-uc/README.md`). Verified against
`state-transition-sdk-rust` and `state-transition-sdk-js` at `origin/non-inclusion`.

```sh
# Rust: cp rust_stub_fixture.rs <sdk-rust>/tests/stub_fixture.rs
STUB_FIXTURE=... cargo test --test stub_fixture
# JS:   cp js_StubFixtureTest.ts <sdk-js>/tests/unit/stub/StubFixtureTest.ts
STUB_FIXTURE=... npx jest --testPathPatterns=tests/unit/stub --coverage=false
```

Each decodes every certificate, checks the canonical re-encoding, a 32-byte technical
record hash, the partition, the path to the seal hash, and the seal under the strict trust
base policy (network, epoch, epoch start, quorum signature).
