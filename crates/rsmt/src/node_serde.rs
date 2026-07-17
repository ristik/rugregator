//! Compact binary serialization for SMT branches (leaves and internal nodes).
//!
//! Used by the disk-backed storage layer.
//!
//! Format:
//! - First byte: type tag (0 = internal node, 1 = leaf)
//!
//! **Internal node** (`[0x00, flags, depth_1B, region_32B, path_len_1B, path_bits..., hash_32B?]`):
//! - flags (u8): bit 0 = has_hash
//! - depth (u8)
//! - region (32 bytes): absolute key prefix `[0..depth)`, MSB-first packed with
//!   bits `depth..256` cleared (RSMT v6a region commitment — hashed, unlike `path`)
//! - path_len (u8): number of common-prefix bits (local navigation aid, not hashed)
//! - path_bits: ceil(path_len / 8) bytes
//! - hash (optional, 32 bytes): present if FLAG_HAS_HASH
//!
//! **Leaf** (`[0x01, key_32B, varint(value_len), value_bytes, hash_32B]`):
//! - key: 32 bytes
//! - value_len: varint-encoded
//! - value: variable length
//! - hash: 32 bytes (always present — computed at construction)

use crate::path::{CompressedPath, SmtKey};
use crate::types::{LeafBranch, NodeBranch};

// ─── Type tags ────────────────────────────────────────────────────────────────

pub const TAG_NODE: u8 = 0;
pub const TAG_LEAF: u8 = 1;

// ─── Node flags ──────────────────────────────────────────────────────────────

const FLAG_HAS_HASH: u8 = 0x01;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Serialize an internal node (metadata only; children stored separately).
pub fn serialize_node(n: &NodeBranch) -> Vec<u8> {
    let path_bytes = n.path.as_bytes();
    let path_len = n.path.path_len();

    let mut out = Vec::with_capacity(1 + 1 + 1 + 32 + 1 + path_bytes.len() + 32);
    out.push(TAG_NODE);

    let mut flags = 0u8;
    if n.hash.is_some() {
        flags |= FLAG_HAS_HASH;
    }
    out.push(flags);
    out.push(n.depth);
    out.extend_from_slice(&n.region);
    out.push(path_len as u8);
    out.extend_from_slice(path_bytes);

    if let Some(h) = n.hash {
        out.extend_from_slice(&h);
    }
    out
}

/// Deserialize an internal node (children are not included; caller
/// reconstructs them from DB).
pub fn deserialize_node(data: &[u8]) -> NodeBranch {
    debug_assert_eq!(data[0], TAG_NODE);
    let mut pos = 1usize;

    let flags = data[pos];
    pos += 1;
    let has_hash = flags & FLAG_HAS_HASH != 0;

    let depth = data[pos];
    pos += 1;

    let mut region = [0u8; 32];
    region.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    let path_len = data[pos];
    pos += 1;

    let path_n_bytes = (path_len as usize + 7) / 8;
    let path = CompressedPath::from_raw(path_len, &data[pos..pos + path_n_bytes]);
    pos += path_n_bytes;

    let hash = if has_hash {
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[pos..pos + 32]);
        Some(h)
    } else {
        None
    };

    NodeBranch {
        path,
        // Children are placeholders — caller must attach from DB.
        left: std::sync::Arc::new(crate::types::Branch::Stub([0u8; 32])),
        right: std::sync::Arc::new(crate::types::Branch::Stub([0u8; 32])),
        depth,
        region,
        hash,
    }
}

/// Serialize a leaf (full data including value).
pub fn serialize_leaf(l: &LeafBranch) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 5 + l.value.len() + 32);
    out.push(TAG_LEAF);
    out.extend_from_slice(&l.key);
    write_varint(&mut out, l.value.len() as u64);
    out.extend_from_slice(&l.value);
    out.extend_from_slice(&l.hash);
    out
}

/// Deserialize a leaf.
pub fn deserialize_leaf(data: &[u8]) -> LeafBranch {
    debug_assert_eq!(data[0], TAG_LEAF);
    let mut pos = 1usize;

    let mut key: SmtKey = [0u8; 32];
    key.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    let value_len = read_varint(data, &mut pos) as usize;
    let value = data[pos..pos + value_len].to_vec();
    pos += value_len;

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[pos..pos + 32]);

    LeafBranch { key, value, hash }
}

/// Returns the type tag byte from serialized data.
#[inline]
pub fn tag(data: &[u8]) -> u8 {
    data[0]
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
    let mut shift = 0u32;
    loop {
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    result
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_leaf;
    use crate::path::CompressedPath;
    use crate::types::{LeafBranch, NodeBranch};
    use std::sync::Arc;

    fn make_key(byte: u8) -> SmtKey {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    #[test]
    fn leaf_roundtrip() {
        let key = make_key(42);
        let value = vec![0xAB; 34];
        let leaf = LeafBranch::new(key, value.clone());
        let bytes = serialize_leaf(&leaf);
        assert_eq!(tag(&bytes), TAG_LEAF);
        let decoded = deserialize_leaf(&bytes);
        assert_eq!(decoded.key, key);
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.hash, leaf.hash);
    }

    #[test]
    fn leaf_roundtrip_empty_value() {
        let key = make_key(7);
        let leaf = LeafBranch::new(key, vec![]);
        let bytes = serialize_leaf(&leaf);
        let decoded = deserialize_leaf(&bytes);
        assert_eq!(decoded.key, key);
        assert!(decoded.value.is_empty());
        assert_eq!(decoded.hash, hash_leaf(&key, &[]));
    }

    #[test]
    fn node_roundtrip_with_hash() {
        let key = make_key(0b1010_0101);
        let path = CompressedPath::from_key_range(&key, 0, 5);
        let region = crate::path::prefix_region(&key, 5);
        let node = NodeBranch {
            path: path.clone(),
            left: Arc::new(crate::types::Branch::Stub([0x11; 32])),
            right: Arc::new(crate::types::Branch::Stub([0x22; 32])),
            depth: 42,
            region,
            hash: Some([0xFF; 32]),
        };
        let bytes = serialize_node(&node);
        assert_eq!(tag(&bytes), TAG_NODE);
        let decoded = deserialize_node(&bytes);
        assert_eq!(decoded.path, path);
        assert_eq!(decoded.depth, 42);
        assert_eq!(decoded.region, region);
        assert_eq!(decoded.hash, Some([0xFF; 32]));
    }

    #[test]
    fn node_roundtrip_no_hash() {
        let path = CompressedPath::empty();
        let region = [0u8; 32];
        let node = NodeBranch {
            path,
            left: Arc::new(crate::types::Branch::Stub([0; 32])),
            right: Arc::new(crate::types::Branch::Stub([0; 32])),
            depth: 0,
            region,
            hash: None,
        };
        let bytes = serialize_node(&node);
        let decoded = deserialize_node(&bytes);
        assert_eq!(decoded.path, CompressedPath::empty());
        assert_eq!(decoded.depth, 0);
        assert_eq!(decoded.region, region);
        assert_eq!(decoded.hash, None);
    }

    #[test]
    fn node_roundtrip_long_path() {
        let mut key = [0u8; 32];
        key[0] = 0xFF;
        key[1] = 0xAA;
        key[2] = 0x55;
        let path = CompressedPath::from_key_range(&key, 0, 20);
        let region = crate::path::prefix_region(&key, 200);
        let node = NodeBranch {
            path: path.clone(),
            left: Arc::new(crate::types::Branch::Stub([0; 32])),
            right: Arc::new(crate::types::Branch::Stub([0; 32])),
            depth: 200,
            region,
            hash: Some([0x42; 32]),
        };
        let bytes = serialize_node(&node);
        let decoded = deserialize_node(&bytes);
        assert_eq!(decoded.path, path);
        assert_eq!(decoded.depth, 200);
        assert_eq!(decoded.region, region);
        assert_eq!(decoded.hash, Some([0x42; 32]));
    }
}
