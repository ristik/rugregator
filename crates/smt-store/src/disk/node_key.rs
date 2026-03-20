//! Absolute bit-path key for addressing SMT nodes in RocksDB.
//!
//! A `NodeKey` encodes the absolute position of a node in the tree:
//! the sequence of routing decisions (common-prefix bits + routing bit)
//! accumulated from root to this node.
//!
//! Encoding: `[depth_lo, depth_hi, prefix_bytes...]`
//! - `depth` (u16, little-endian): number of bits in the prefix
//! - `prefix_bytes`: `ceil(depth/8)` bytes, LSB of bit-0 is in byte 0 bit 0
//!   (matches `bit_at` from rsmt::path)
//!
//! Root is a special sentinel: `[0xFF, 0xFF]` (depth = u16::MAX).

use num_bigint::BigUint;
use num_traits::Zero;

/// Absolute bit-path key for an SMT node in RocksDB.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeKey(Vec<u8>);

impl NodeKey {
    /// The root node's key (special sentinel, no prefix bits).
    pub fn root() -> Self {
        NodeKey(vec![0xFF, 0xFF])
    }

    /// Is this the root key?
    pub fn is_root(&self) -> bool {
        self.0.len() == 2 && self.0[0] == 0xFF && self.0[1] == 0xFF
    }

    /// Create a NodeKey from the absolute accumulated prefix.
    ///
    /// `depth` = number of routing bits accumulated from root (exclusive of
    /// root itself, which uses `NodeKey::root()`).
    ///
    /// `prefix` = BigUint where bit `i` (LSB = 0) is the routing decision at
    /// tree-depth `i`.  Bits at positions ≥ `depth` are ignored.
    pub fn from_depth_and_prefix(depth: usize, prefix: &BigUint) -> Self {
        let mut out = Vec::with_capacity(2 + (depth + 7) / 8);
        // depth as u16 LE
        let d = depth as u16;
        out.push((d & 0xFF) as u8);
        out.push((d >> 8) as u8);
        if depth > 0 {
            let byte_count = (depth + 7) / 8;
            if prefix.is_zero() {
                out.extend(std::iter::repeat(0u8).take(byte_count));
            } else {
                // to_bytes_le = LSB-first, matching bit_at's byte layout
                let mut bytes = prefix.to_bytes_le();
                bytes.resize(byte_count, 0);
                out.extend_from_slice(&bytes);
            }
        }
        NodeKey(out)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_sentinel() {
        let k = NodeKey::root();
        assert!(k.is_root());
    }

    #[test]
    fn depth_zero_not_root() {
        // depth=0 with empty prefix is NOT the root sentinel
        let k = NodeKey::from_depth_and_prefix(0, &BigUint::ZERO);
        assert!(!k.is_root());
        assert_eq!(k.as_bytes(), &[0, 0]);
    }

    #[test]
    fn distinct_left_right_depth1() {
        let left  = NodeKey::from_depth_and_prefix(1, &BigUint::from(0u8)); // bit 0 = 0
        let right = NodeKey::from_depth_and_prefix(1, &BigUint::from(1u8)); // bit 0 = 1
        assert_ne!(left, right);
        // depth bytes: [1, 0]; prefix: [0] vs [1]
        assert_eq!(left.as_bytes(),  &[1, 0, 0]);
        assert_eq!(right.as_bytes(), &[1, 0, 1]);
    }

    #[test]
    fn deeper_key() {
        // depth=9 prefix = bits 0..8: bit0=1, bit8=1 → value 0b1_0000_0001 = 257
        let prefix = BigUint::from(257u32);
        let k = NodeKey::from_depth_and_prefix(9, &prefix);
        // depth LE: [9, 0]; prefix: 2 bytes LE of 257 = [1, 1]
        assert_eq!(k.as_bytes(), &[9, 0, 1, 1]);
    }
}
