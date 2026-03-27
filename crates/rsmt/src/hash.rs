//! SMT hash functions — domain-separated SHA-256 (default) or Blake3.
//!
//! **Leaf:**  `H(0x00 || key_32B || value)`
//! **Node:**  `H(0x01 || depth_1B || left_hash_32B || right_hash_32B)`
//!
//! The hash algorithm is selected via the [`SmtHasher`] trait.  Use
//! [`Sha256Hasher`] (the default) for compatibility with existing deployments,
//! or [`Blake3Hasher`] for ~3–4× faster hashing.

use sha2::{Digest, Sha256};
use crate::path::SmtKey;

// ─── Trait ───────────────────────────────────────────────────────────────────

/// A zero-sized type that provides the two SMT hash functions.
///
/// Implementors must be `Copy` so they can be used as type parameters
/// without any runtime state.
pub trait SmtHasher: Copy + Send + Sync + 'static {
    /// Hash a leaf: `H(0x00 || key || value)`.
    fn hash_leaf(key: &SmtKey, value: &[u8]) -> [u8; 32];
    /// Hash an internal node: `H(0x01 || depth || left_hash || right_hash)`.
    fn hash_node(left: &[u8; 32], right: &[u8; 32], depth: u8) -> [u8; 32];
}

// ─── SHA-256 (default) ────────────────────────────────────────────────────────

/// Domain-separated SHA-256 hasher.  This is the default and produces the
/// same hashes as existing deployments.
#[derive(Copy, Clone, Debug, Default)]
pub struct Sha256Hasher;

impl SmtHasher for Sha256Hasher {
    #[inline]
    fn hash_leaf(key: &SmtKey, value: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00]);
        h.update(key);
        h.update(value);
        h.finalize().into()
    }

    #[inline]
    fn hash_node(left: &[u8; 32], right: &[u8; 32], depth: u8) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x01, depth]);
        h.update(left);
        h.update(right);
        h.finalize().into()
    }
}

// ─── Blake3 ──────────────────────────────────────────────────────────────────

/// Domain-separated Blake3 hasher.  Produces different hashes than
/// [`Sha256Hasher`] but is ~3–4× faster on modern hardware.
#[derive(Copy, Clone, Debug, Default)]
pub struct Blake3Hasher;

impl SmtHasher for Blake3Hasher {
    #[inline]
    fn hash_leaf(key: &SmtKey, value: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&[0x00]);
        h.update(key);
        h.update(value);
        *h.finalize().as_bytes()
    }

    #[inline]
    fn hash_node(left: &[u8; 32], right: &[u8; 32], depth: u8) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&[0x01, depth]);
        h.update(left);
        h.update(right);
        *h.finalize().as_bytes()
    }
}

// ─── Convenience free functions (default SHA-256) ────────────────────────────

/// Hash a leaf with SHA-256: `SHA256(0x00 || key || value)`.
#[inline]
pub fn hash_leaf(key: &SmtKey, value: &[u8]) -> [u8; 32] {
    Sha256Hasher::hash_leaf(key, value)
}

/// Hash an internal node with SHA-256: `SHA256(0x01 || depth || left || right)`.
#[inline]
pub fn hash_node(left: &[u8; 32], right: &[u8; 32], depth: u8) -> [u8; 32] {
    Sha256Hasher::hash_node(left, right, depth)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn check_hasher<H: SmtHasher>() {
        let key = [1u8; 32];

        // Deterministic
        assert_eq!(H::hash_leaf(&key, b"hello"), H::hash_leaf(&key, b"hello"));
        assert_ne!(H::hash_leaf(&key, b"hello"), H::hash_leaf(&key, b"world"));

        // Domain separation: leaf vs node prefixes differ
        let lh = H::hash_leaf(&[0u8; 32], &[0u8; 64]);
        let nh = H::hash_node(&[0u8; 32], &[0u8; 32], 0);
        assert_ne!(lh, nh);

        // Depth matters
        let l = [1u8; 32];
        let r = [2u8; 32];
        assert_ne!(H::hash_node(&l, &r, 0), H::hash_node(&l, &r, 1));

        // Order matters
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(H::hash_node(&a, &b, 5), H::hash_node(&b, &a, 5));

        // Key matters
        assert_ne!(H::hash_leaf(&[0u8; 32], b"v"), H::hash_leaf(&[1u8; 32], b"v"));
    }

    #[test]
    fn sha256_hasher() {
        check_hasher::<Sha256Hasher>();
    }

    #[test]
    fn blake3_hasher() {
        check_hasher::<Blake3Hasher>();
    }

    #[test]
    fn sha256_and_blake3_differ() {
        let key = [1u8; 32];
        assert_ne!(
            Sha256Hasher::hash_leaf(&key, b"test"),
            Blake3Hasher::hash_leaf(&key, b"test"),
        );
    }

    #[test]
    fn free_functions_match_sha256() {
        let key = [1u8; 32];
        assert_eq!(hash_leaf(&key, b"v"), Sha256Hasher::hash_leaf(&key, b"v"));
        assert_eq!(
            hash_node(&[1u8; 32], &[2u8; 32], 7),
            Sha256Hasher::hash_node(&[1u8; 32], &[2u8; 32], 7),
        );
    }
}
