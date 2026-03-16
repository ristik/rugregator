//! Unicity Aggregator – Rust implementation.
//!
//! This crate provides:
//! - A Go-compatible Sparse Merkle Tree (`smt`)
//! - Request validation (`validation`)
//! - JSON-RPC HTTP API (`api`)
//! - Round management (`round`)
//! - In-memory state store (`storage`)
//! - Configuration (`config`)

pub mod api;
pub mod config;
pub mod round;
pub mod smt;
pub mod storage;
pub mod storage_rocksdb;
pub mod validation;
