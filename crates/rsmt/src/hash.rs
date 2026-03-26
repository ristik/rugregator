//! SMT hash functions — domain-separated SHA-256.
//!
//! **Leaf:**  `SHA256(0x00 || key_32B || value)`
//! **Node:**  `SHA256(0x01 || depth_1B || left_hash_32B || right_hash_32B)`

use sha2::{Digest, Sha256};
use crate::path::SmtKey;

/// Hash a leaf: `SHA256(0x00 || key || value)`.
#[inline]
pub fn hash_leaf(key: &SmtKey, value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(key);
    h.update(value);
    h.finalize().into()
}

/// Hash an internal node: `SHA256(0x01 || depth || left_hash || right_hash)`.
#[inline]
pub fn hash_node(left: &[u8; 32], right: &[u8; 32], depth: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update([depth]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_leaf_deterministic() {
        let key = [1u8; 32];
        let h1 = hash_leaf(&key, b"hello");
        let h2 = hash_leaf(&key, b"hello");
        assert_eq!(h1, h2);
        let h3 = hash_leaf(&key, b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn hash_leaf_domain_separation() {
        // Leaf and node hashes must never collide even with crafted inputs,
        // because the first byte differs (0x00 vs 0x01).
        let key = [0u8; 32];
        let lh = hash_leaf(&key, &[0u8; 64]);
        let nh = hash_node(&[0u8; 32], &[0u8; 32], 0);
        assert_ne!(lh, nh);
    }

    #[test]
    fn hash_node_depth_matters() {
        let l = [1u8; 32];
        let r = [2u8; 32];
        let h0 = hash_node(&l, &r, 0);
        let h1 = hash_node(&l, &r, 1);
        assert_ne!(h0, h1);
    }

    #[test]
    fn hash_node_order_matters() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(hash_node(&a, &b, 5), hash_node(&b, &a, 5));
    }

    #[test]
    fn hash_leaf_key_matters() {
        let k1 = [0u8; 32];
        let k2 = [1u8; 32];
        assert_ne!(hash_leaf(&k1, b"v"), hash_leaf(&k2, b"v"));
    }
}
