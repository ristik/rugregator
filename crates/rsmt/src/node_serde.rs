//! Compact binary serialization for SMT branches (leaves and internal nodes).
//!
//! Used by the disk-backed storage layer in the aggregator.
//!
//! Format:
//! - First byte: type tag (0 = internal node, 1 = leaf)
//! - Remainder: type-specific fields (see below)
//!
//! **Internal node** (`[0x00, flags, path_bytes..., hash?]`):
//! - flags (u8): bit 0 = has_left, bit 1 = has_right, bit 2 = is_root, bit 3 = has_hash
//! - path: varint length + bytes_be of SmtPath BigUint
//! - hash_cache (optional, 32 bytes): if FLAG_HAS_HASH
//!
//! **Leaf** (`[0x01, flags, path_bytes..., orig_path..., value..., hash?]`):
//! - flags (u8): bit 0 = is_child, bit 1 = has_hash
//! - path: varint length + bytes_be
//! - original_path: varint length + bytes_be
//! - value: varint length + bytes
//! - hash_cache (optional, 32 bytes): if FLAG_HAS_HASH

use num_bigint::BigUint;
use crate::path::SmtPath;
use crate::types::{LeafBranch, NodeBranch};

// ─── Type tags ────────────────────────────────────────────────────────────────

pub const TAG_NODE: u8 = 0;
pub const TAG_LEAF: u8 = 1;

// ─── Node flags ──────────────────────────────────────────────────────────────

const NODE_FLAG_HAS_LEFT:  u8 = 0x01;
const NODE_FLAG_HAS_RIGHT: u8 = 0x02;
const NODE_FLAG_IS_ROOT:   u8 = 0x04;
const NODE_FLAG_HAS_HASH:  u8 = 0x08;

// ─── Leaf flags ───────────────────────────────────────────────────────────────

const LEAF_FLAG_IS_CHILD:  u8 = 0x01;
const LEAF_FLAG_HAS_HASH:  u8 = 0x02;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Serialize an internal node (metadata only; children not included).
pub fn serialize_node(n: &NodeBranch) -> Vec<u8> {
    let mut out = vec![TAG_NODE];
    let mut flags = 0u8;
    if n.left.is_some()        { flags |= NODE_FLAG_HAS_LEFT; }
    if n.right.is_some()       { flags |= NODE_FLAG_HAS_RIGHT; }
    if n.is_root               { flags |= NODE_FLAG_IS_ROOT; }
    if n.hash_cache.is_some()  { flags |= NODE_FLAG_HAS_HASH; }
    out.push(flags);
    write_path(&mut out, &n.path);
    if let Some(h) = n.hash_cache {
        out.extend_from_slice(&h);
    }
    out
}

/// Deserialize an internal node (children are None; caller reconstructs from DB).
/// Returns `(NodeBranch_without_children, has_left, has_right)`.
pub fn deserialize_node(data: &[u8]) -> (NodeBranch, bool, bool) {
    debug_assert_eq!(data[0], TAG_NODE);
    let mut pos = 1usize;
    let flags = data[pos]; pos += 1;
    let has_left   = flags & NODE_FLAG_HAS_LEFT  != 0;
    let has_right  = flags & NODE_FLAG_HAS_RIGHT != 0;
    let is_root    = flags & NODE_FLAG_IS_ROOT   != 0;
    let has_hash   = flags & NODE_FLAG_HAS_HASH  != 0;
    let path = read_path(data, &mut pos);
    let hash_cache = if has_hash {
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[pos..pos + 32]);
        Some(h)
    } else {
        None
    };
    let n = NodeBranch { path, left: None, right: None, is_root, hash_cache };
    (n, has_left, has_right)
}

/// Serialize a leaf (full data including value).
pub fn serialize_leaf(l: &LeafBranch) -> Vec<u8> {
    let mut out = vec![TAG_LEAF];
    let mut flags = 0u8;
    if l.is_child             { flags |= LEAF_FLAG_IS_CHILD; }
    if l.hash_cache.is_some() { flags |= LEAF_FLAG_HAS_HASH; }
    out.push(flags);
    write_path(&mut out, &l.path);
    write_path(&mut out, &l.original_path);
    write_varint(&mut out, l.value.len() as u64);
    out.extend_from_slice(&l.value);
    if let Some(h) = l.hash_cache {
        out.extend_from_slice(&h);
    }
    out
}

/// Deserialize a leaf.
pub fn deserialize_leaf(data: &[u8]) -> LeafBranch {
    debug_assert_eq!(data[0], TAG_LEAF);
    let mut pos = 1usize;
    let flags = data[pos]; pos += 1;
    let is_child = flags & LEAF_FLAG_IS_CHILD != 0;
    let has_hash = flags & LEAF_FLAG_HAS_HASH != 0;
    let path          = read_path(data, &mut pos);
    let original_path = read_path(data, &mut pos);
    let value_len     = read_varint(data, &mut pos) as usize;
    let value = data[pos..pos + value_len].to_vec();
    pos += value_len;
    let hash_cache = if has_hash {
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[pos..pos + 32]);
        Some(h)
    } else {
        None
    };
    LeafBranch { path, original_path, value, is_child, hash_cache }
}

/// Returns the type tag byte from serialized data.
pub fn tag(data: &[u8]) -> u8 {
    data[0]
}

// ─── SmtPath helpers ─────────────────────────────────────────────────────────

fn write_path(out: &mut Vec<u8>, path: &SmtPath) {
    let bytes = path.to_bytes_be();
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(&bytes);
}

fn read_path(data: &[u8], pos: &mut usize) -> SmtPath {
    let len = read_varint(data, pos) as usize;
    let bytes = &data[*pos..*pos + len];
    *pos += len;
    BigUint::from_bytes_be(bytes)
}

// ─── Varint helpers ───────────────────────────────────────────────────────────

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}

fn read_varint(data: &[u8], pos: &mut usize) -> u64 {
    let mut result = 0u64;
    let mut shift  = 0u32;
    loop {
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 { break; }
    }
    result
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use crate::path::state_id_to_smt_path;

    fn test_path(byte: u8) -> SmtPath {
        let mut id = [0u8; 32];
        id[31] = byte;
        state_id_to_smt_path(&id)
    }

    #[test]
    fn leaf_roundtrip() {
        let path = test_path(42);
        let orig = test_path(42);
        let leaf = LeafBranch {
            path: path.clone(),
            original_path: orig.clone(),
            value: vec![0xAB; 34],
            is_child: false,
            hash_cache: Some([0x12; 32]),
        };
        let bytes = serialize_leaf(&leaf);
        assert_eq!(tag(&bytes), TAG_LEAF);
        let decoded = deserialize_leaf(&bytes);
        assert_eq!(decoded.path, leaf.path);
        assert_eq!(decoded.original_path, leaf.original_path);
        assert_eq!(decoded.value, leaf.value);
        assert_eq!(decoded.is_child, leaf.is_child);
        assert_eq!(decoded.hash_cache, leaf.hash_cache);
    }

    #[test]
    fn leaf_roundtrip_no_hash() {
        let path = test_path(7);
        let leaf = LeafBranch {
            path: path.clone(),
            original_path: path.clone(),
            value: vec![1, 2, 3],
            is_child: true,
            hash_cache: None,
        };
        let bytes = serialize_leaf(&leaf);
        let decoded = deserialize_leaf(&bytes);
        assert_eq!(decoded.hash_cache, None);
        assert!(decoded.is_child);
    }

    #[test]
    fn node_roundtrip() {
        use crate::types::NodeBranch;
        let node = NodeBranch {
            path: BigUint::from(0b1101u8),
            left: None,
            right: None,
            is_root: true,
            hash_cache: Some([0xFF; 32]),
        };
        let bytes = serialize_node(&node);
        assert_eq!(tag(&bytes), TAG_NODE);
        let (decoded, has_left, has_right) = deserialize_node(&bytes);
        assert_eq!(decoded.path, node.path);
        assert_eq!(decoded.is_root, true);
        assert_eq!(decoded.hash_cache, Some([0xFF; 32]));
        assert!(!has_left);
        assert!(!has_right);
    }

    #[test]
    fn node_roundtrip_with_children_flags() {
        use crate::types::{Branch, NodeBranch, LeafBranch};
        let leaf = Box::new(Branch::Leaf(LeafBranch {
            path: test_path(1),
            original_path: test_path(1),
            value: vec![],
            is_child: false,
            hash_cache: None,
        }));
        let node = NodeBranch {
            path: BigUint::from(3u8),
            left: Some(leaf.clone()),
            right: Some(leaf),
            is_root: false,
            hash_cache: None,
        };
        let bytes = serialize_node(&node);
        let (_, has_left, has_right) = deserialize_node(&bytes);
        assert!(has_left);
        assert!(has_right);
    }
}
