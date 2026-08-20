//! Radix Sparse Merkle Tree — path-compressed with 256-bit keys.

pub mod consistency;
pub mod hash;
pub mod node_serde;
pub mod path;
pub mod proof;
pub mod snapshot;
pub mod tree;
pub mod types;

// Re-export verifier primitives from the no_std-compatible sub-crate so that
// external callers continue to use `rsmt::` paths unchanged.
pub use rsmt_verify::{
    consistency_proof_to_bytes, decode_aggregator_envelope_v1, encode_aggregator_envelope_v1,
    key_bit_at, leaf_value, prefix_region, verify_consistency, verify_consistency_with,
    ConsistencyProof, EnvelopeError, ProofOp, Sha256Hasher, SmtHasher, SmtKey, KEY_BITS,
};

pub use consistency::{
    batch_insert, batch_insert_with, batch_insert_with_proof, batch_insert_with_proof_with,
};
pub use hash::{hash_leaf, hash_node, Blake2bHasher, Blake2sHasher};
pub use path::CompressedPath;
pub use proof::{
    verify_inclusion, verify_non_inclusion, InclusionProof, NonInclusionProof,
    NonInclusionProofOutcome,
};
pub use snapshot::SmtSnapshot;
pub use tree::{SmtError, SparseMerkleTree};
pub use types::{branch_hash, Branch, LeafBranch, NodeBranch};
