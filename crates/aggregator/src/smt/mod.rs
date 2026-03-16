//! Sparse Merkle Tree implementation, Go-compatible.

pub mod hash;
pub mod path;
pub mod proof;
pub mod snapshot;
pub mod tree;
pub mod types;

pub use hash::{build_imprint, cbor_array, cbor_bytes, cbor_null};
pub use path::{calculate_common_path, path_len, root_path, state_id_to_smt_path, SmtPath};
pub use proof::{merkle_path_from_cbor, merkle_path_to_cbor, MerkleTreePath, MerkleTreeStep};
pub use snapshot::SmtSnapshot;
pub use tree::{SmtError, SparseMerkleTree, KEY_LENGTH};
