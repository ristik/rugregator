//! SP1 prover host for aggregator ZK consistency proofs.
//!
//! Compile with `--features prove` to enable the real SP1 prover.
//! Without the feature, only stub types are provided and calling `prove`
//! returns an error.
//!
//! # Proof wire format
//!
//! The bytes returned by [`Prover::prove`] are a `bincode`-serialised
//! `SP1ProofWithPublicValues`.  The `aggregator-zk-verifier-ffi` BFT Core
//! library expects exactly this format.
//!
//! # Public values layout
//!
//! ```text
//! offset  size  field
//! 0       32    prev_root  ([u8; 32])
//! 32      32    new_root   ([u8; 32])
//! ```

#[cfg(feature = "prove")]
mod prover_impl;
#[cfg(not(feature = "prove"))]
mod prover_stub;

#[cfg(feature = "prove")]
pub use prover_impl::{Prover, ZkProofKind};
#[cfg(not(feature = "prove"))]
pub use prover_stub::{Prover, ZkProofKind};
