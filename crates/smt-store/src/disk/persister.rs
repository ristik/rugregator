//! After-mutation persistence: walk the modified tree and write to overlay.

use std::collections::HashSet;
use std::sync::Arc;
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

    let n_path      = path_len(&smt.root.path);
    let prefix_bits = extract_node_prefix_bits(&smt.root.path, n_path);
    let base_acc    = prefix_bits;
    let split       = n_path;

    if let Some(left) = &mut smt.root.left {
        persist_branch(Arc::make_mut(left), false, split, &base_acc, overlay, &mut new_keys);
    }
    if let Some(right) = &mut smt.root.right {
        persist_branch(Arc::make_mut(right), true, split, &base_acc, overlay, &mut new_keys);
    }

    // Tombstone old keys no longer in the tree.
    for old_nk in old_keys {
        if !new_keys.contains(old_nk.as_bytes()) {
            overlay.delete(old_nk);
        }
    }
}

// ─── Recursive helper ────────────────────────────────────────────────────────

fn persist_branch(
    branch:  &mut Branch,
    is_right: bool,
    split:    usize,
    acc:      &BigUint,
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
            if l.hash_cache.is_none() {
                l.hash_cache = Some(calc_leaf_hash(l));
            }
            overlay.put(&nk, serialize_leaf(l));
            new_keys.insert(nk.into_bytes());
        }

        Branch::Node(n) => {
            calc_node_hash(n);

            let n_path      = path_len(&n.path);
            let prefix_bits = extract_node_prefix_bits(&n.path, n_path);
            let base_acc = &child_acc | (prefix_bits << split);
            let node_split = split + n_path;

            overlay.put(&nk, serialize_node(n));
            new_keys.insert(nk.into_bytes());

            if let Some(left) = &mut n.left {
                persist_branch(Arc::make_mut(left), false, node_split, &base_acc, overlay, new_keys);
            }
            if let Some(right) = &mut n.right {
                persist_branch(Arc::make_mut(right), true, node_split, &base_acc, overlay, new_keys);
            }
        }

        Branch::Stub(_) => {
            // Stub = untouched existing subtree.
            new_keys.insert(nk.into_bytes());
        }
    }
}
