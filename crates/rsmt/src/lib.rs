//! Radix Sparse Merkle Tree — path-compressed with 256-bit keys.

pub mod consistency;
pub mod hash;
pub mod node_serde;
pub mod path;
pub mod proof;
pub mod snapshot;
pub mod tree;
pub mod types;

pub use consistency::{
    batch_insert, batch_insert_with, batch_insert_with_proof, batch_insert_with_proof_with,
    consistency_proof_to_bytes, consistency_proof_to_cbor, encode_aggregator_envelope_v1,
    verify_consistency, verify_consistency_with,
    ConsistencyProof, ProofOp,
};
pub use hash::{hash_leaf, hash_node, Blake2bHasher, Blake2sHasher, Sha256Hasher, SmtHasher};
pub use path::{get_sort_key, key_bit_at, CompressedPath, SmtKey, KEY_BITS};
pub use proof::{verify_inclusion, InclusionProof};
pub use snapshot::SmtSnapshot;
pub use tree::{SmtError, SparseMerkleTree};
pub use types::{branch_hash, Branch, LeafBranch, NodeBranch};
