//! `extract-vkey` — print the SP1 guest program's verifying key.
//!
//! Outputs the 32-byte vkey hash to stdout and writes the full bincode
//! `SP1VerifyingKey` to a file (default: `vkey.bin`).
//!
//! The hash is the identity commitment; put it in documentation or config as a
//! human-readable fingerprint.  The binary file is what `aggregator-zk-verifier-ffi`
//! loads at BFT Core startup for actual proof verification.
//!
//! # Usage
//!
//! ```sh
//! cargo run -p zk-host --features prove --bin extract-vkey -- --out vkey.bin
//! ```

use clap::Parser;
use std::path::PathBuf;
use zk_host::Prover;

#[derive(Parser)]
#[command(
    name = "extract-vkey",
    about = "Extract the SP1 guest program verifying key"
)]
struct Args {
    /// Output path for the full bincode verifying key file.
    #[arg(long, default_value = "vkey.bin")]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    eprintln!("Setting up SP1 prover (this may take a few seconds)…");
    let prover = Prover::new()?;

    let hash = prover.vkey_bytes32();
    println!("vkey hash: 0x{}", hex::encode(hash));

    let vkey_bytes = prover.vkey_bytes()?;
    std::fs::write(&args.out, &vkey_bytes)?;
    eprintln!("Verifying key written to {}", args.out.display());
    eprintln!("({} bytes)", vkey_bytes.len());

    Ok(())
}
