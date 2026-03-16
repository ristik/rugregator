//! Radix Sparse Merkle Tree — Go-compatible path-compressed Patricia trie.

pub mod consistency;
pub mod hash;
pub mod path;
pub mod proof;
pub mod snapshot;
pub mod tree;
pub mod types;

pub use consistency::{
    batch_insert, batch_insert_with_proof, verify_consistency,
    ConsistencyProof, ProofOp, synchronized_proof_eval,
};
pub use hash::{build_imprint, cbor_array, cbor_bytes, cbor_null, hash_leaf, hash_node};
pub use path::{calculate_common_path, path_as_bytes, path_len, root_path, state_id_to_smt_path, SmtPath};
pub use num_bigint::BigUint;
pub use proof::{merkle_path_from_cbor, merkle_path_to_cbor, MerkleTreePath, MerkleTreeStep};
pub use snapshot::SmtSnapshot;
pub use tree::{SmtError, SparseMerkleTree, KEY_LENGTH};
