//! `no_std`-compatible verifier for the rugregator Sparse Merkle Tree
//! consistency proof.
//!
//! This crate contains the verification half of the SMT consistency proof
//! protocol.  It is intentionally kept minimal so it can compile to a
//! `riscv32im-succinct-zkvm-elf` SP1 guest without any `std` dependency.
//!
//! # Public surface
//!
//! - **Primitives:** [`SmtKey`], [`KEY_BITS`], [`get_sort_key`], [`key_bit_at`]
//! - **Hash:** [`SmtHasher`], [`Sha256Hasher`]
//! - **Proof types:** [`ProofOp`], [`ConsistencyProof`]
//! - **Verification:** [`verify_consistency`], [`verify_consistency_with`]
//! - **Wire encoding:** [`consistency_proof_to_bytes`], [`encode_aggregator_envelope_v1`]
//! - **Wire decoding:** [`decode_aggregator_envelope_v1`], [`EnvelopeError`]

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod consistency;
pub mod hash;
pub mod path;

pub use consistency::{
    consistency_proof_to_bytes, decode_aggregator_envelope_v1, encode_aggregator_envelope_v1,
    verify_consistency, verify_consistency_with, ConsistencyProof, EnvelopeError, ProofOp,
};
pub use hash::{Sha256Hasher, SmtHasher};
pub use path::{get_sort_key, key_bit_at, SmtKey, KEY_BITS};
