//! `check-syscalls` — verify that the SP1 guest uses the SHA-256 precompile
//! and report instruction counts for micro-benchmarking.
//!
//! The guest program relies on the zkVM's built-in SHA-256 precompile
//! (`SHA_COMPRESS` / `SHA_EXTEND` syscalls).  If the `[patch.crates-io]` in
//! `zk-guest/Cargo.toml` is missing or misresolved, the guest silently falls
//! back to pure-Rust SHA-256: proofs are still correct but cycle counts are
//! 10–50× higher, making proving impractical.
//!
//! This tool runs the guest in *execute* mode (no proof generated, completes
//! in seconds) and inspects the syscall counts from the execution report.
//!
//! It also doubles as a **micro-benchmark**: fix `--seed` and vary
//! `--batch-size` / `--prefill-size` to compare instruction counts across
//! algorithm changes.
//!
//! # Usage
//!
//! ```sh
//! # Quick precompile check (100 leaves, empty tree)
//! cargo run -p zk-host --features prove --bin check-syscalls
//!
//! # Realistic non-empty tree, reproducible seed
//! cargo run -p zk-host --features prove --bin check-syscalls -- \
//!     --prefill-size 1000 --batch-size 200 --seed 7
//!
//! # Full syscall dump
//! cargo run -p zk-host --features prove --bin check-syscalls -- --verbose
//! ```

use anyhow::Context;
use clap::Parser;
use rsmt::{batch_insert, batch_insert_with_proof, SparseMerkleTree};
use rsmt_verify::encode_aggregator_envelope_v1;
use sp1_core_executor::SyscallCode;
use sp1_sdk::blocking::{Prover, ProverClient};
use sp1_sdk::{ExecutionReport, SP1Stdin};

/// The compiled guest ELF, embedded at build time by `sp1-build`.
const GUEST_ELF: sp1_sdk::Elf = sp1_sdk::include_elf!("zk-guest-program");

#[derive(Parser)]
#[command(
    name = "check-syscalls",
    about = "Verify SHA-256 precompile is active in the SP1 guest and report instruction counts"
)]
struct Args {
    /// Number of leaves to insert in the measured batch.
    #[arg(long, default_value_t = 100)]
    batch_size: usize,

    /// Number of leaves to insert into the tree *before* the measured batch
    /// (simulates a non-empty tree for more realistic benchmarking).
    #[arg(long, default_value_t = 0)]
    prefill_size: usize,

    /// Seed for deterministic leaf generation.
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Print every non-zero syscall count, not just SHA-256.
    #[arg(long)]
    verbose: bool,
}

/// Generate a deterministic 32-byte SMT key from seed + index.
///
/// Layout: seed[8] || index[8] || seed_xor_index[8] || index_hi[8]
/// This gives good key-space distribution without any hash dependency.
fn leaf_key(seed: u64, index: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0..8].copy_from_slice(&seed.to_le_bytes());
    key[8..16].copy_from_slice(&index.to_le_bytes());
    key[16..24].copy_from_slice(&(seed ^ index.wrapping_mul(0x9e37_79b9_7f4a_7c15)).to_le_bytes());
    key[24..32].copy_from_slice(&(index.wrapping_add(seed.rotate_right(17))).to_le_bytes());
    key
}

/// Generate a deterministic 32-byte value from seed + index.
fn leaf_value(seed: u64, index: u64) -> Vec<u8> {
    let mut val = [0u8; 32];
    val[0..8].copy_from_slice(&(seed.wrapping_add(index)).to_le_bytes());
    val[8..16].copy_from_slice(&index.to_le_bytes());
    val[16..24].copy_from_slice(&seed.to_le_bytes());
    val[24..32].copy_from_slice(&(index ^ seed).to_le_bytes());
    val.to_vec()
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // ── Build synthetic leaves ────────────────────────────────────────────────

    let prefill: Vec<([u8; 32], Vec<u8>)> = (0..args.prefill_size as u64)
        .map(|i| (leaf_key(args.seed, i), leaf_value(args.seed, i)))
        .collect();

    let batch: Vec<([u8; 32], Vec<u8>)> = (args.prefill_size as u64
        ..args.prefill_size as u64 + args.batch_size as u64)
        .map(|i| (leaf_key(args.seed, i), leaf_value(args.seed, i)))
        .collect();

    // ── Build SMT, prefill, then insert batch with proof ─────────────────────

    let mut tree = SparseMerkleTree::new();

    if !prefill.is_empty() {
        eprint!("Prefilling tree with {} leaves… ", args.prefill_size);
        batch_insert(&mut tree, &prefill).context("prefill insert failed")?;
        eprintln!("done");
    }

    let prev_root: [u8; 32] = tree.root_hash().unwrap_or([0u8; 32]);

    eprint!("Inserting batch of {} leaves with proof… ", args.batch_size);
    let (sorted_batch, proof) =
        batch_insert_with_proof(&mut tree, &batch).context("batch insert failed")?;
    eprintln!("done");

    let new_root: [u8; 32] = tree
        .root_hash()
        .context("tree has no root after batch insert")?;

    // ── Encode guest stdin: prev_root || new_root || envelope ─────────────────

    let envelope = encode_aggregator_envelope_v1(&sorted_batch, &proof);

    let mut buf = Vec::with_capacity(64 + envelope.len());
    buf.extend_from_slice(&prev_root);
    buf.extend_from_slice(&new_root);
    buf.extend_from_slice(&envelope);

    let mut stdin = SP1Stdin::new();
    stdin.write::<Vec<u8>>(&buf);

    // ── Execute guest (no proof) ──────────────────────────────────────────────

    eprintln!("Executing guest program (no proof)…");
    let client = ProverClient::builder().cpu().build();
    let (_, report): (_, ExecutionReport) = client
        .execute(GUEST_ELF, stdin)
        .run()
        .context("SP1 guest execution failed")?;

    // ── Report ────────────────────────────────────────────────────────────────

    let compress = report.syscall_counts[SyscallCode::SHA_COMPRESS];
    let extend = report.syscall_counts[SyscallCode::SHA_EXTEND];
    let instrs = report.total_instruction_count();
    let syscalls = report.total_syscall_count();

    println!();
    println!(
        "prefill={prefill}  batch={batch}  seed={seed}",
        prefill = args.prefill_size,
        batch = args.batch_size,
        seed = args.seed,
    );
    println!("instructions : {instrs}");
    println!("syscalls     : {syscalls}");
    println!(
        "SHA_COMPRESS : {compress}  {}",
        if compress > 0 { "✓" } else { "✗" }
    );
    println!(
        "SHA_EXTEND   : {extend}  {}",
        if extend > 0 { "✓" } else { "✗" }
    );

    if args.verbose {
        println!();
        println!("Non-zero syscall counts:");
        for (syscall, &count) in report.syscall_counts.iter() {
            if count > 0 {
                println!("  {syscall:<30} : {count}");
            }
        }
    }

    println!();
    if compress > 0 && extend > 0 {
        println!("Precompile active.");
        Ok(())
    } else {
        eprintln!(
            "ERROR: SHA-256 precompile not used (SHA_COMPRESS={compress}, SHA_EXTEND={extend}).\n\
             Check [patch.crates-io] in zk-guest/Cargo.toml."
        );
        std::process::exit(1);
    }
}
