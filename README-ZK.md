# ZK Consistency Proofs

The rugregator aggregator can attach a consistency proof to every certification request it submits to BFT Core. Three modes are available:

| Mode | Flag value | Proof size | Rust FFI required (BFT Core) |
|------|-----------|-----------|------------------------------|
| Off | `off` | none | no |
| RSMT (hash-based) | `rsmt` | O(batch) | no |
| ZK (SP1 6.0.2) | `zk` | ~constant | yes |

RSMT mode is the simplest path to correctness: BFT Core recomputes the SMT roots deterministically from the sorted leaf set embedded in the proof. ZK mode compresses that same proof to a fixed-size SP1 proof, which is more bandwidth-efficient at large batch sizes but requires computationally heavy ZK proving.

---

## rugregator

### Build — RSMT mode (default)

No extra flags. The `rsmt` mode uses only pure-Rust code and is always compiled in.

```bash
cargo build --workspace --release
```

### Build — ZK mode

ZK mode requires the `aggregator/zk` feature. At build time this pulls in three things:

1. **SP1 toolchain** — cross-compiles the guest ELF for `riscv32im-succinct-zkvm-elf`.
2. **Go toolchain** (≥ 1.21, CGO enabled) — compiles the gnark Groth16/Plonk library into a static archive so that SNARK wrapping runs fully in-process with no Docker dependency.
3. **Rust `sp1-sdk 6.0.2`** — links everything together.

```bash
# Install SP1 toolchain (one-time)
curl -L https://sp1up.succinct.xyz | bash
sp1up

# Go must be in PATH and CGO must be available (default on Linux/macOS)
go version   # should print go1.21 or later

# Build with ZK support
cargo build --workspace --features uni-aggregator/zk --release
```

The build compiles the guest ELF, compiles the gnark Go library, and embeds both in the aggregator binary.

**Circuit artifacts:** On the first Groth16/Plonk proof the prover downloads the circuit keys (~300 MB) from S3 and caches them in `~/.sp1/circuits/groth16/<version>/`. Subsequent runs use the cache. Set `SP1_GROTH16_CIRCUIT_PATH` to a pre-populated directory to skip the download.

#### Generate the verifying key

The verifying key (`vkey.bin`) is a cryptographic identifier of the guest program. Generate it once per guest version and distribute it in authentic way to BFT Core operators.

```bash
cargo run --release --features uni-aggregator/zk --bin extract-vkey -- --out vkey.bin
```


---

### Configure rugregator

All options can be set via CLI flags or environment variables.

#### RSMT mode

```bash
# CLI
aggregator \
  --consistency-proof-mode rsmt \
  --round-duration-ms 1000 \
  ...

# Environment
AGGREGATOR_CONSISTENCY_PROOF_MODE=rsmt
```

No additional flags are needed for RSMT mode. Round duration can remain at the default.

#### ZK mode

```bash
# CLI
aggregator \
  --consistency-proof-mode zk \
  --zk-proof-kind groth16 \
  --round-duration-ms 60000 \
  ...

# Environment
AGGREGATOR_CONSISTENCY_PROOF_MODE=zk
AGGREGATOR_ZK_PROOF_KIND=compressed          # core | compressed | groth16 | plonk
AGGREGATOR_ROUND_DURATION_MS=60000
AGGREGATOR_UC_TIMEOUT_MS=1200000
AGGREGATOR_BATCH_LIMIT=200
```

**Proof kinds and trade-offs:**

| Kind | Proving time (CPU) | Proof size | BFT Core verify time |
|------|--------------------|------------|----------------------|
| `core` | fastest | largest (~10 MB) | ~10 ms |
| `compressed` | slow | ~1.2 MB    | ~5 ms    |
| `groth16` | slowest | ~260 bytes | ~1 ms    |
| `plonk` | slowest   | ~900 bytes | ~1 ms    |

**Memory:** SP1 runs multiple worker goroutines in parallel.  Each worker holds roughly 3 GB of proving state.  The defaults (4 core workers + 4 buffer slots) peak at **~24 GB**.  Control the memory footprint with environment variables. Set them before starting the aggregator; if using provided test scripts then in `e2e-data/aggregator.env` or in shell env as below:

```bash
# Less memory (~16 GB machine)
export SP1_WORKER_NUM_CORE_WORKERS=2
export SP1_WORKER_CORE_BUFFER_SIZE=1
```

TODO: sp1's git main has new parameters `SP1CoreOpts.memory_limit` / environment var. `MEMORY_LIMIT`, try these when released. 

**Round duration:** ZK proving on a CPU can take minutes for large batches, but larger batches are more efficient. Set `--round-duration-ms` (and `--uc-timeout-ms` and BFT Core's `T2` timeout) accordingly.

**Pipelining:** the aggregator starts proving round N in a background thread while round N+1 collects requests. The certification request for round N is submitted only after the proof is ready. This means the effective round latency is `max(collection_time, proving_time)`.

---

## BFT Core

BFT Core is a separate project. Currently the necessary functionality is in branch 'l2' of [the project.](https://github.com/unicitynetwork/bft-core).

### Build — RSMT mode

No Rust FFI required. The pure-Go RSMT verifier is always compiled in.

```bash
git clone https://github.com/unicitynetwork/bft-core.git
cd bft-core
git checkout l2
make build
```

### Build — ZK mode

ZK mode requires building the `aggregator-zk-verifier-ffi` Rust crate (SP1 6.0.2) and linking it into the Go binary.

```bash
cd bft-core

# Build the Rust FFI library (requires cargo / Rust toolchain)
make build-aggregator-zk-ffi

# Build the Go binary with the new build tag
make build ZKVERIFIER_AGGREGATOR_ZK_FFI=1
```

Or in a single command:

```bash
make build-with-aggregator-zk-ffi
```

To build with both the existing SP1/LightClient FFI verifiers and the aggregator ZK verifier:

```bash
make build-with-all-ffi
```

The resulting binary at `build/ubft` has all three verifiers linked in.

---

### Configure BFT Core

BFT Core selects a verifier per partition via partition-level params (stored in the rootchain). The relevant keys are:

| Param key | Description |
|-----------|-------------|
| `proof_type` | Which verifier to use for this partition |
| `vkey_path` | Path to `vkey.bin` on the BFT Core node (ZK mode only) |

#### RSMT mode

Set `proof_type=aggregator_rsmt_v1` on the partition. No `vkey_path` needed.

The RSMT verifier recomputes SMT roots from the sorted leaf + opcode stream embedded in the proof. Verification is deterministic and requires no external key material.

Example partition config fragment:

```json
{
  "proof_type": "aggregator_rsmt_v1"
}
```

#### ZK mode

1. Copy `vkey.bin` (generated by `extract-vkey` above) to each BFT Core node, e.g. `/etc/ubft/vkey.bin`.
2. Set `proof_type=aggregator_zk_v1` and `vkey_path=/etc/ubft/vkey.bin` on the partition.
3. Run the binary built with `-tags zkverifier_aggregator_zk_ffi`.

Example partition config fragment:

```json
"partitionParams": {
  "proof_type": "aggregator_zk_v1",
  "vkey_path": "e2e-data/root-node/vkey.bin"
},
```

**Important:** `vkey.bin` must correspond to the exact guest program ELF embedded in the aggregator binary. If the aggregator is rebuilt (guest program changes), a new `vkey.bin` must be generated and distributed to all BFT Core nodes before switching over.

#### Off mode (no proof)

```json
{
  "proof_type": "none"
}
```

or omit `proof_type` entirely. BFT Core will accept any block without verifying a consistency proof. Useful during initial rollout or for m-of-n validator setups.

Also, set the `t2timeout` (in microseconds, like 500000000000) in e2e-data/root-node/shard-conf-1_0.json and if bft-core setup is already generated then run it and then

```bash
tsx scripts/upload-partition-config.ts e2e-data/root-node/shard-conf-1_0.json
```

Example shard configuration:
```json
{
  "version": 1,
  "networkId": 3,
  "partitionId": 1,
  "shardId": "0x80",
  "partitionTypeId": 1,
  "typeIdLength": 8,
  "unitIdLength": 256,
  "summaryTrustBase": "",
  "t2timeout": 500000000000,
  "feeCreditBill": null,
  "partitionParams": {
    "proof_type": "aggregator_zk_v1",
    "vkey_path": "e2e-data/root-node/vkey.bin"
  },
  "epoch": 1,
  "epochStart": 100,
  "validators": [
    {
      "nodeId": "16Uiu2HAmKoZx5gzmbtr2zCvwML5Kwd16P4wTNJyT45qVncLvqpXV",
      "sigKey": "0x039af3b40cf749b10e1e85d5c8952c59da84a247b6f96f54d26f411ef932269066",
      "stake": 1
    }
  ]
}
```

---

## Precompile Verification / Micro-benchmarking

The `check-syscalls` tool runs the SP1 guest in *execute* mode (no proof generated, completes in
seconds) and inspects the `SHA_COMPRESS` / `SHA_EXTEND` syscall counts from the execution report.

The proving time is dominated by use `sha2::Sha256`.  The
`[patch.crates-io]` in `zk-guest/Cargo.toml` replaces the standard `sha2` crate with an
SP1-patched version that routes SHA-256 calls to the zkVM precompile.  If that patch is missing
or misresolved, the guest falls back to pure-Rust SHA-256: proofs are still correct but
instruction counts are much higher, and proving slower.

The tool also doubles as a **micro-benchmark**: fix `--seed` and `--batch-size` /
`--prefill-size` and record instruction counts across algorithmic changes in a reproducible way.

```bash
cargo run -p zk-host --features prove --bin check-syscalls -- --batch-size 100 --prefill-size 10000
```

If the precompile is **not** active (missing patch), instruction counts will be 10–50× higher
and both SHA counts will be 0.  The tool exits with code 1 in that case.

**Comparing algorithm variants:** run with identical flags before and after your change and
compare the `instructions` line.  Use `--verbose` to see which other syscalls
(e.g. EC, bignum operations) change.

NOTE: SP1 6.0.3 (latest at the time of writing) does not have functional SHA2 precompiles. See the
workaround in `crates/rsmt-verify/src/hash.rs`.

---
