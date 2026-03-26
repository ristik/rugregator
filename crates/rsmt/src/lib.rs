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
    batch_insert, batch_insert_with_proof, consistency_proof_to_cbor, verify_consistency,
    ConsistencyProof, ProofOp,
};
pub use hash::{hash_leaf, hash_node};
pub use path::{get_sort_key, key_bit_at, CompressedPath, SmtKey, KEY_BITS};
pub use proof::{verify_inclusion, InclusionProof};
pub use snapshot::SmtSnapshot;
pub use tree::{SmtError, SparseMerkleTree};
pub use types::{branch_hash, Branch, LeafBranch, NodeBranch};
