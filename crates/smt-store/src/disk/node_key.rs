//! Absolute bit-path key for addressing SMT nodes in RocksDB.
//!
//! A `NodeKey` encodes the absolute position of a node in the tree:
//! the sequence of routing decisions (common-prefix bits + routing bit)
//! accumulated from root to this node.
//!
//! Encoding: `[depth_lo, depth_hi, prefix_bytes...]`
//! - `depth` (u16, little-endian): number of bits in the prefix
//! - `prefix_bytes`: `ceil(depth/8)` bytes, LSB of bit-0 is in byte 0 bit 0
//!   (matches `key_bit_at` from rsmt::path)
//!
//! Root is a special sentinel: `[0xFF, 0xFF]` (depth = u16::MAX).

/// A 256-bit prefix accumulator (used as `BigUint` replacement).
pub type PrefixBits = [u8; 32];

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
    /// `prefix` = bit array where bit `i` (LSB-first) is the routing decision
    /// at tree-depth `i`. Bits at positions >= `depth` are ignored.
    pub fn from_depth_and_prefix(depth: usize, prefix: &PrefixBits) -> Self {
        let byte_count = (depth + 7) / 8;
        let mut out = Vec::with_capacity(2 + byte_count);
        let d = depth as u16;
        out.push((d & 0xFF) as u8);
        out.push((d >> 8) as u8);
        if depth > 0 {
            out.extend_from_slice(&prefix[..byte_count]);
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

// ─── PrefixBits helpers ─────────────────────────────────────────────────────

/// Set bit at `pos` in a prefix accumulator.
#[inline]
pub fn prefix_set_bit(acc: &mut PrefixBits, pos: usize) {
    acc[pos / 8] |= 1 << (pos % 8);
}

/// Get bit at `pos` in a prefix accumulator.
#[inline]
pub fn prefix_get_bit(acc: &PrefixBits, pos: usize) -> u8 {
    (acc[pos / 8] >> (pos % 8)) & 1
}

/// Copy bits from a CompressedPath into the accumulator starting at `start_bit`.
pub fn prefix_copy_path(acc: &mut PrefixBits, start_bit: usize, path: &rsmt::path::CompressedPath) {
    for i in 0..path.path_len() {
        if path.bit_at(i) != 0 {
            prefix_set_bit(acc, start_bit + i);
        }
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
        let prefix = [0u8; 32];
        let k = NodeKey::from_depth_and_prefix(0, &prefix);
        assert!(!k.is_root());
        assert_eq!(k.as_bytes(), &[0, 0]);
    }

    #[test]
    fn distinct_left_right_depth1() {
        let mut left_p = [0u8; 32];
        let mut right_p = [0u8; 32];
        right_p[0] = 1; // bit 0 = 1
        let left = NodeKey::from_depth_and_prefix(1, &left_p);
        let right = NodeKey::from_depth_and_prefix(1, &right_p);
        assert_ne!(left, right);
        assert_eq!(left.as_bytes(), &[1, 0, 0]);
        assert_eq!(right.as_bytes(), &[1, 0, 1]);
    }

    #[test]
    fn deeper_key() {
        // depth=9 prefix = bit0=1, bit8=1 → byte[0]=1, byte[1]=1
        let mut prefix = [0u8; 32];
        prefix[0] = 1; // bit 0
        prefix[1] = 1; // bit 8
        let k = NodeKey::from_depth_and_prefix(9, &prefix);
        assert_eq!(k.as_bytes(), &[9, 0, 1, 1]);
    }
}
