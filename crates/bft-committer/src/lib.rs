//! BFT Core L1 Integration Layer
//!
//! This crate provides the integration between uni-evm L2 and the BFT Core L1.
//! It handles:
//! - CBOR serialization of BlockCertificationRequest messages
//! - libp2p networking to BFT Core root chain nodes
//! - Signature handling with secp256k1
//! - Processing UnicityCertificate responses

pub mod types;
pub mod cbor;
pub mod network;
pub mod committer;
pub mod storage;

pub use committer::{BftCommitter, BftCommitterConfig};
pub use network::{BftCoreClient, BftCoreHandle};
pub use storage::UcStorage;
pub use types::{BlockCertificationRequest, InputRecord, UnicityCertificate};
