//! After-mutation persistence: walk the modified tree and write to overlay.
//!
//! After rsmt's `batch_insert` modifies the materialized tree, we:
//! 1. Force-compute all hash caches by traversing the root.
//! 2. Walk the new tree top-down, computing each node's NodeKey.
//! 3. Serialize each node and put it in the overlay (upsert).
//! 4. Tombstone old NodeKeys that no longer appear in the tree.
//!
//! ## NodeKey computation during persist
//!
//! Mirrors the materializer's NodeKey scheme:
//! - Root: `NodeKey::root()` (special sentinel)
//! - For each non-root node at routing-bit `split` with acc prefix `acc`:
//!   `child_nk = NodeKey::from_depth_and_prefix(split + 1, child_acc)`

use std::collections::HashSet;
use num_bigint::BigUint;
use rsmt::{Branch, SparseMerkleTree};
use rsmt::path::path_len;
use rsmt::node_serde::{serialize_leaf, serialize_node};
use rsmt::tree::calc_node_hash;
use rsmt::calc_leaf_hash;

use super::node_key::NodeKey;
use super::overlay::Overlay;
use super::materializer::extract_node_prefix_bits;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Walk the modified SMT, serialize every node, and populate `overlay`.
///
/// Fills all `hash_cache` fields first (by computing root hash).
/// Tombstones entries from `old_keys` that are absent from the new tree.
pub fn persist_tree(
    smt:      &mut SparseMerkleTree,
    old_keys: &[NodeKey],
    overlay:  &mut Overlay,
) {
    // Fill all hash caches.
    calc_node_hash(&mut smt.root);

    let mut new_keys: HashSet<Vec<u8>> = HashSet::new();

    // Persist root.
    let root_nk = NodeKey::root();
    overlay.put(&root_nk, serialize_node(&smt.root));
    new_keys.insert(root_nk.into_bytes());

    // Walk children. Root has start_bit=0 and its n_path common prefix bits
    // sit at absolute positions 0..n_path-1.
    let n_path      = path_len(&smt.root.path);
    let prefix_bits = extract_node_prefix_bits(&smt.root.path, n_path);
    let base_acc    = prefix_bits; // acc = 0 | (prefix << 0) = prefix
    let split       = n_path;      // routing bit for root's children

    if let Some(left) = &mut smt.root.left {
        persist_branch(left, false, split, &base_acc, overlay, &mut new_keys);
    }
    if let Some(right) = &mut smt.root.right {
        persist_branch(right, true, split, &base_acc, overlay, &mut new_keys);
    }

    // Tombstone old keys no longer in the tree.
    for old_nk in old_keys {
        if !new_keys.contains(old_nk.as_bytes()) {
            overlay.delete(old_nk);
        }
    }
}

// ─── Recursive helper ────────────────────────────────────────────────────────

/// Persist the branch that is the `is_right` child accessed via routing bit `split`.
fn persist_branch(
    branch:  &mut Branch,
    is_right: bool,
    split:    usize,      // routing bit position for this branch
    acc:      &BigUint,   // accumulated prefix up to (not including) bit `split`
    overlay:  &mut Overlay,
    new_keys: &mut HashSet<Vec<u8>>,
) {
    let child_acc = if is_right {
        acc | (BigUint::from(1u8) << split)
    } else {
        acc.clone()
    };
    let nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

    match branch {
        Branch::Leaf(l) => {
            // Ensure hash is populated.
            if l.hash_cache.is_none() {
                l.hash_cache = Some(calc_leaf_hash(l));
            }
            overlay.put(&nk, serialize_leaf(l));
            new_keys.insert(nk.into_bytes());
        }

        Branch::Node(n) => {
            // Ensure hash is populated.
            calc_node_hash(n);

            let n_path      = path_len(&n.path);
            let prefix_bits = extract_node_prefix_bits(&n.path, n_path);
            // Go convention: child's start_bit = parent's split (routing bit not pre-consumed).
            // This node's common-prefix bits sit at absolute positions split..split+n_path-1.
            let base_acc = &child_acc | (prefix_bits << split);
            let node_split = split + n_path;

            overlay.put(&nk, serialize_node(n));
            new_keys.insert(nk.into_bytes());

            if let Some(left) = &mut n.left {
                persist_branch(left, false, node_split, &base_acc, overlay, new_keys);
            }
            if let Some(right) = &mut n.right {
                persist_branch(right, true, node_split, &base_acc, overlay, new_keys);
            }
        }

        Branch::Stub(_) => {
            // Stub = untouched existing subtree.  Its content is already in DB.
            // Record the key as "present" so we don't tombstone it.
            // Note: descendants of this stub that were in old_keys are also
            // implicitly preserved — they weren't in `old_keys` to begin with
            // (we only load nodes we actually traverse during materialization).
            new_keys.insert(nk.into_bytes());
        }
    }
}
