//! SP1 guest program: verify an `aggregator_rsmt_v1` consistency proof.
//!
//! # Input (stdin)
//!
//! A single `Vec<u8>` containing:
//! ```text
//! [0..32]   prev_root       — previous SMT root (all-zeros = empty tree)
//! [32..64]  new_root        — new SMT root after batch insertion
//! [64..72]  reference_time  — round reference time (big-endian u64)
//! [72..]    envelope        — aggregator_rsmt_v1 wire bytes
//! ```
//!
//! A zero prev/new root means `None` (empty tree).  Both being identical with
//! an empty envelope is the no-op case and is accepted.
//!
//! # Public outputs (committed)
//!
//! ```text
//! [0..32]   prev_root       ([u8; 32])
//! [32..64]  new_root        ([u8; 32])
//! [64..72]  reference_time  (big-endian u64)
//! ```
//!
//! The reference time is public because the batch is not. In the hash-based
//! instantiation BFT Core derives each leaf value from the batch it receives;
//! here it receives no batch, so the circuit performs that derivation
//! internally and exposes the reference time for the Core to check against
//! `CR.IR.t`. Without this the ZK instantiation would leave the reference time
//! asserted by the shard while the hash-based one enforces it, and a
//! deployment could weaken the guarantee by changing instantiation alone.
//!
//! # Security
//!
//! The guest asserts that `verify_consistency` returns `true`.  A failed
//! assertion makes the proof non-generatable, so BFT Core will never see an
//! invalid proof.

#![no_main]
sp1_zkvm::entrypoint!(main);

use rsmt_verify::{decode_aggregator_envelope_v1, verify_consistency};

/// All-zero hash treated as `None` (empty tree).
fn root_opt(bytes: [u8; 32]) -> Option<[u8; 32]> {
    if bytes == [0u8; 32] { None } else { Some(bytes) }
}

pub fn main() {
    // Read the single combined input buffer.
    let input: Vec<u8> = sp1_zkvm::io::read();

    assert!(input.len() >= 72, "input too short: need at least 72 bytes");

    let mut prev_root = [0u8; 32];
    let mut new_root  = [0u8; 32];
    let mut reference_time_bytes = [0u8; 8];
    prev_root.copy_from_slice(&input[0..32]);
    new_root .copy_from_slice(&input[32..64]);
    reference_time_bytes.copy_from_slice(&input[64..72]);
    let reference_time = u64::from_be_bytes(reference_time_bytes);
    let envelope = &input[72..];

    // Decode the envelope: (leaves, opcode stream).
    let (leaves, proof) = decode_aggregator_envelope_v1(envelope)
        .expect("envelope decode failed");

    // Verify the consistency proof (SHA-256 accelerated via SP1 precompile).
    // The envelope declares transaction hashes; the verifier derives each
    // stored leaf value from the reference time committed below.
    let ok = verify_consistency(
        &proof,
        root_opt(prev_root),
        root_opt(new_root),
        &leaves,
        reference_time,
    );
    assert!(ok, "consistency proof verification failed");

    // Commit public outputs: prev_root || new_root || reference_time (72 bytes).
    sp1_zkvm::io::commit_slice(&prev_root);
    sp1_zkvm::io::commit_slice(&new_root);
    sp1_zkvm::io::commit_slice(&reference_time_bytes);
}
