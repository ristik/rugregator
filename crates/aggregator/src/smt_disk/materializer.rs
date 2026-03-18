//! Materialize a partial in-memory SMT from RocksDB, guided by a batch of keys.
//!
//! ## Strategy
//!
//! Only the nodes along the batch keys' paths (plus one-level siblings for
//! hash computation) are loaded.  Every untouched sibling subtree is
//! represented as a `Branch::Stub(hash)` — rsmt's algorithms never recurse
//! into a Stub; they only call `calc_branch_hash` which returns the stored
//! hash directly.
//!
//! ## NodeKey accumulation
//!
//! Accumulated prefix (`acc`) carries the absolute routing-bit values from
//! root to the current position:
//! - bit `i` of `acc` = the routing decision made at tree-depth `i`
//!
//! A child whose routing bit is at `split`:
//! ```text
//! child_acc  = acc | (is_right << split)
//! child_nk   = NodeKey::from_depth_and_prefix(split + 1, child_acc)
//! ```

use std::sync::{Arc, Mutex};
use num_bigint::BigUint;
use rocksdb::DB;
use rsmt::{Branch, SparseMerkleTree};
use rsmt::path::{bit_at, path_len, SmtPath};
use rsmt::node_serde::{TAG_LEAF, TAG_NODE, deserialize_leaf, deserialize_node};

use super::node_key::NodeKey;
use super::overlay::Overlay;
use super::cache::NodeCache;

pub const CF_SMT_NODES: &str = "smt_nodes";

// ─── Public entry-points ──────────────────────────────────────────────────────

/// Materialize a partial SMT for a batch insertion.
///
/// Returns `(working_tree, visited_node_keys)`.
/// The working tree has `Branch::Stub` for untouched branches.
/// `visited_node_keys` = all node keys loaded from DB during materialization
/// (used by the persister to compute deletes after mutation).
pub fn materialize_for_batch(
    db:         &Arc<DB>,
    cache:      &Arc<Mutex<NodeCache>>,
    overlay:    &Overlay,
    batch:      &[(SmtPath, Vec<u8>)],
    key_length: usize,
) -> anyhow::Result<(SparseMerkleTree, Vec<NodeKey>)> {
    let root_nk = NodeKey::root();
    let mut visited = Vec::new();

    let root_bytes = match load_bytes(db, cache, overlay, &root_nk)? {
        None => {
            // Empty tree.
            return Ok((SparseMerkleTree::with_key_length(key_length), vec![]));
        }
        Some(b) => b,
    };
    visited.push(root_nk);

    // Root is always an internal node.
    let (mut root_node, has_left, has_right) = deserialize_node(&root_bytes);
    let n_path = path_len(&root_node.path);
    let split  = n_path; // root start_bit = 0, so split = 0 + n_path = n_path

    // Common-prefix bits of root node, placed at absolute bit positions 0..n_path-1.
    let root_prefix_bits = extract_node_prefix_bits(&root_node.path, n_path);
    let base_acc = root_prefix_bits.clone(); // acc = 0 | (root_prefix << 0) = root_prefix

    root_node.left  = if has_left  { materialize_at_split(db, cache, overlay, split, false, batch, &base_acc, &mut visited)? } else { None };
    root_node.right = if has_right { materialize_at_split(db, cache, overlay, split, true,  batch, &base_acc, &mut visited)? } else { None };

    let smt = SparseMerkleTree { key_length, root: root_node, parent_mode: false };
    Ok((smt, visited))
}

/// Materialize a partial SMT for a single-leaf proof generation.
pub fn materialize_for_proof(
    db:         &Arc<DB>,
    cache:      &Arc<Mutex<NodeCache>>,
    overlay:    &Overlay,
    leaf_key:   &SmtPath,
    key_length: usize,
) -> anyhow::Result<SparseMerkleTree> {
    // Treat the single key as a one-item batch.
    let batch = vec![(leaf_key.clone(), vec![])];
    let (smt, _) = materialize_for_batch(db, cache, overlay, &batch, key_length)?;
    Ok(smt)
}

// ─── Core recursive materializer ──────────────────────────────────────────────

/// Materialize the child whose routing bit is at `split`.
/// `is_right` = 1 if the child is accessed via the right branch.
/// `acc` = accumulated absolute prefix up to (but not including) bit `split`.
fn materialize_at_split(
    db:       &Arc<DB>,
    cache:    &Arc<Mutex<NodeCache>>,
    overlay:  &Overlay,
    split:    usize,         // routing bit position
    is_right: bool,
    batch:    &[(SmtPath, Vec<u8>)],
    acc:      &BigUint,      // bits 0..split-1 (common prefix of parent)
    visited:  &mut Vec<NodeKey>,
) -> anyhow::Result<Option<Box<Branch>>> {
    // Filter batch to keys that route to this side.
    let child_batch: Vec<_> = batch.iter()
        .filter(|(k, _)| bit_at(k, split) == (is_right as u8))
        .cloned()
        .collect();

    // Compute child's accumulated prefix and NodeKey.
    let child_acc = if is_right {
        acc | (BigUint::from(1u8) << split)
    } else {
        acc.clone()
    };
    let child_nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

    if child_batch.is_empty() {
        // No batch keys go here → load just for hash, create Stub.
        return load_as_stub(db, cache, overlay, child_nk);
    }

    materialize_subtree(db, cache, overlay, child_nk, &child_batch, split, &child_acc, visited)
}

/// Materialize the subtree rooted at `nk`.
/// `start_bit` = routing bit position that led us here (= split of parent).
/// `acc`       = accumulated prefix bits 0..start_bit (inclusive of routing bit).
fn materialize_subtree(
    db:        &Arc<DB>,
    cache:     &Arc<Mutex<NodeCache>>,
    overlay:   &Overlay,
    nk:        NodeKey,
    batch:     &[(SmtPath, Vec<u8>)],
    start_bit: usize,
    acc:       &BigUint,
    visited:   &mut Vec<NodeKey>,
) -> anyhow::Result<Option<Box<Branch>>> {
    let bytes = match load_bytes(db, cache, overlay, &nk)? {
        None => return Ok(None),
        Some(b) => b,
    };
    visited.push(nk);

    if bytes[0] == TAG_LEAF {
        let leaf = deserialize_leaf(&bytes);
        return Ok(Some(Box::new(Branch::Leaf(leaf))));
    }

    debug_assert_eq!(bytes[0], TAG_NODE);
    let (mut node, has_left, has_right) = deserialize_node(&bytes);
    let n_path = path_len(&node.path);

    // Go convention: child's start_bit = parent's split (routing bit not pre-consumed).
    // The node's common-prefix bits sit at absolute positions start_bit..start_bit+n_path-1.
    let prefix_bits = extract_node_prefix_bits(&node.path, n_path);
    let base_acc = acc | (prefix_bits << start_bit);
    let split = start_bit + n_path; // routing bit for children

    node.left  = if has_left  { materialize_at_split(db, cache, overlay, split, false, batch, &base_acc, visited)? } else { None };
    node.right = if has_right { materialize_at_split(db, cache, overlay, split, true,  batch, &base_acc, visited)? } else { None };

    Ok(Some(Box::new(Branch::Node(node))))
}

/// Load a node just to get its hash for a `Branch::Stub`.
fn load_as_stub(
    db:      &Arc<DB>,
    cache:   &Arc<Mutex<NodeCache>>,
    overlay: &Overlay,
    nk:      NodeKey,
) -> anyhow::Result<Option<Box<Branch>>> {
    let bytes = match load_bytes(db, cache, overlay, &nk)? {
        None => return Ok(None),
        Some(b) => b,
    };
    let hash = extract_hash_from_bytes(&bytes)?;
    Ok(Some(Box::new(Branch::Stub(hash))))
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

pub fn load_bytes(
    db:      &Arc<DB>,
    cache:   &Arc<Mutex<NodeCache>>,
    overlay: &Overlay,
    nk:      &NodeKey,
) -> anyhow::Result<Option<Vec<u8>>> {
    // Overlay first.
    if let Some(opt) = overlay.get(nk) {
        return Ok(opt.map(|b| b.to_vec()));
    }
    // Cache.
    {
        let mut c = cache.lock().unwrap();
        if let Some(bytes) = c.get(nk) {
            return Ok(Some(bytes.clone()));
        }
    }
    // RocksDB.
    let cf = db.cf_handle(CF_SMT_NODES)
        .ok_or_else(|| anyhow::anyhow!("CF '{}' not found", CF_SMT_NODES))?;
    match db.get_cf(&cf, nk.as_bytes())? {
        None => Ok(None),
        Some(v) => {
            let bytes = v.to_vec();
            cache.lock().unwrap().put(nk.clone(), bytes.clone());
            Ok(Some(bytes))
        }
    }
}

// ─── Bit-extraction helpers ───────────────────────────────────────────────────

/// Extract the `n_common` data bits from a sentinel-encoded path.
/// Returns the lower `n_common` bits as a BigUint (bit 0 = LSB).
pub fn extract_node_prefix_bits(path: &SmtPath, n_common: usize) -> BigUint {
    if n_common == 0 {
        return BigUint::ZERO;
    }
    let mask = (BigUint::from(1u8) << n_common) - BigUint::from(1u8);
    path & &mask
}

fn extract_hash_from_bytes(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    if bytes[0] == TAG_LEAF {
        let leaf = deserialize_leaf(bytes);
        leaf.hash_cache.ok_or_else(|| anyhow::anyhow!(
            "leaf has no hash_cache — commit root hash before using as Stub"
        ))
    } else if bytes[0] == TAG_NODE {
        let (node, _, _) = deserialize_node(bytes);
        node.hash_cache.ok_or_else(|| anyhow::anyhow!(
            "node has no hash_cache — commit root hash before using as Stub"
        ))
    } else {
        anyhow::bail!("unknown node type byte 0x{:02x}", bytes[0])
    }
}
