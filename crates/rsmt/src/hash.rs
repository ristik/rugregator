//! Go-compatible SMT hashing.
//!
//! Hash functions use hand-rolled CBOR encoding (identical to Go's helpers in
//! `aggregator-go/pkg/api/cbor.go` and `hash.go`) followed by SHA-256.
//!
//! **Leaf:**  `SHA256( CBOR_ARRAY(2) || CBOR_BYTES(path) || CBOR_BYTES(value) )`
//! **Node:**  `SHA256( CBOR_ARRAY(3) || CBOR_BYTES(path) || (CBOR_BYTES(left)|NULL) || (CBOR_BYTES(right)|NULL) )`
//!
//! The **imprint** is `[0x00, 0x00, ...32_raw_sha256_bytes...]` (34 bytes).
//! Algorithm ID 0 = SHA-256 (matching `api.SHA256 = 0` in Go).

use sha2::{Digest, Sha256};
use crate::path::{SmtPath, path_as_bytes};

/// SHA-256 algorithm ID as stored in an imprint (0x0000).
pub const ALGO_SHA256: u16 = 0;

// ─── Imprint ─────────────────────────────────────────────────────────────────

/// Build a 34-byte imprint from a 32-byte SHA-256 digest.
pub fn build_imprint(raw: &[u8; 32]) -> [u8; 34] {
    let mut imp = [0u8; 34];
    imp[0] = (ALGO_SHA256 >> 8) as u8;
    imp[1] = (ALGO_SHA256 & 0xff) as u8;
    imp[2..].copy_from_slice(raw);
    imp
}

/// Build a 34-byte imprint from a raw-hash slice (panics if not 32 bytes).
pub fn build_imprint_from_slice(raw: &[u8]) -> [u8; 34] {
    let arr: [u8; 32] = raw.try_into().expect("hash must be 32 bytes");
    build_imprint(&arr)
}

// ─── Manual CBOR helpers (matches aggregator-go/pkg/api/cbor.go) ─────────────

/// CBOR head: major type `major` (3 bits) with integer parameter `n`.
fn cbor_tag(major: u8, n: usize) -> Vec<u8> {
    let m = major << 5;
    if n <= 23 {
        vec![m | n as u8]
    } else if n <= 0xff {
        vec![m | 24, n as u8]
    } else if n <= 0xffff {
        vec![m | 25, (n >> 8) as u8, (n & 0xff) as u8]
    } else if n <= 0xffff_ffff {
        vec![
            m | 26,
            (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8,
        ]
    } else {
        vec![
            m | 27,
            (n >> 56) as u8, (n >> 48) as u8, (n >> 40) as u8, (n >> 32) as u8,
            (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8,
        ]
    }
}

/// CBOR array header for `n` elements (major type 4).
pub fn cbor_array(n: usize) -> Vec<u8> {
    cbor_tag(4, n)
}

/// CBOR byte-string header + payload (major type 2).
pub fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = cbor_tag(2, data.len());
    out.extend_from_slice(data);
    out
}

/// CBOR null value (major type 7, simple value 22 → 0xf6).
pub fn cbor_null() -> Vec<u8> {
    vec![0xf6]
}

// ─── SMT hash functions ───────────────────────────────────────────────────────

/// Hash a leaf node.
///
/// `SHA256( CBOR_ARRAY(2) || CBOR_BYTES(path_bytes) || CBOR_BYTES(value) )`
pub fn hash_leaf(path: &SmtPath, value: &[u8]) -> [u8; 32] {
    let path_bytes = path_as_bytes(path);
    let mut h = Sha256::new();
    h.update(cbor_array(2));
    h.update(cbor_bytes(&path_bytes));
    h.update(cbor_bytes(value));
    h.finalize().into()
}

/// Hash an internal node.
///
/// `SHA256( CBOR_ARRAY(3) || CBOR_BYTES(path) || child_or_null || child_or_null )`
pub fn hash_node(
    path: &SmtPath,
    left: Option<&[u8; 32]>,
    right: Option<&[u8; 32]>,
) -> [u8; 32] {
    let path_bytes = path_as_bytes(path);
    let mut h = Sha256::new();
    h.update(cbor_array(3));
    h.update(cbor_bytes(&path_bytes));
    match left {
        Some(l) => h.update(cbor_bytes(l)),
        None => h.update(cbor_null()),
    }
    match right {
        Some(r) => h.update(cbor_bytes(r)),
        None => h.update(cbor_null()),
    }
    h.finalize().into()
}

/// Hash the SMT root (monolithic mode): uses path `BigUint(1)` shifted for the
/// root hash step.  In monolithic mode the root path IS `BigUint(1)`, so this
/// is just `hash_node(&BigUint(1), left, right)`.
pub fn hash_root(left: Option<&[u8; 32]>, right: Option<&[u8; 32]>) -> [u8; 32] {
    use num_bigint::BigUint;
    use num_traits::One;
    hash_node(&BigUint::one(), left, right)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn cbor_array_headers() {
        assert_eq!(cbor_array(2), vec![0x82]);
        assert_eq!(cbor_array(3), vec![0x83]);
        assert_eq!(cbor_array(4), vec![0x84]);
        assert_eq!(cbor_array(24), vec![0x98, 24]);
    }

    #[test]
    fn cbor_bytes_empty() {
        assert_eq!(cbor_bytes(&[]), vec![0x40]);
    }

    #[test]
    fn cbor_bytes_one_byte() {
        // 0x41 = major type 2, len 1
        assert_eq!(cbor_bytes(&[0xab]), vec![0x41, 0xab]);
    }

    #[test]
    fn cbor_null_value() {
        assert_eq!(cbor_null(), vec![0xf6]);
    }

    #[test]
    fn imprint_structure() {
        let raw = [0u8; 32];
        let imp = build_imprint(&raw);
        assert_eq!(imp[0], 0x00);
        assert_eq!(imp[1], 0x00);
        assert_eq!(&imp[2..], &[0u8; 32]);
    }

    #[test]
    fn hash_leaf_deterministic() {
        use num_bigint::BigUint;
        use num_traits::One;
        let p = BigUint::one();
        let h1 = hash_leaf(&p, b"hello");
        let h2 = hash_leaf(&p, b"hello");
        assert_eq!(h1, h2);
        let h3 = hash_leaf(&p, b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn hash_node_with_nulls() {
        use num_bigint::BigUint;
        use num_traits::One;
        // Just ensure it doesn't panic
        let _h = hash_node(&BigUint::one(), None, None);
    }
}
