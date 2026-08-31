//! `no_std`-compatible verifier for the rugregator Sparse Merkle Tree
//! consistency proof.
//!
//! This crate contains the verification half of the SMT consistency proof
//! protocol.  It is intentionally kept minimal so it can compile to a
//! `riscv32im-succinct-zkvm-elf` SP1 guest without any `std` dependency.
//!
//! # Public surface
//!
//! - **Primitives:** [`SmtKey`], [`KEY_BITS`], [`key_bit_at`], [`prefix_region`]
//! - **Hash:** [`SmtHasher`], [`Sha256Hasher`]
//! - **Aggregation profile:** [`leaf_value`]
//! - **Proof types:** [`ProofOp`], [`ConsistencyProof`]
//! - **Verification:** [`verify_consistency`], [`verify_consistency_with`]
//! - **Wire encoding:** [`consistency_proof_to_bytes`], [`encode_aggregator_envelope_v1`]
//! - **Wire decoding:** [`decode_aggregator_envelope_v1`], [`EnvelopeError`]

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod consistency;
pub mod hash;
pub mod leaf_value;
pub mod path;

pub use consistency::{
    consistency_proof_to_bytes, decode_aggregator_envelope_v1, encode_aggregator_envelope_v1,
    verify_consistency, verify_consistency_with, ConsistencyProof, EnvelopeError, ProofOp,
};
pub use hash::{Sha256Hasher, SmtHasher};
pub use leaf_value::leaf_value;
pub use path::{key_bit_at, prefix_region, SmtKey, KEY_BITS};
