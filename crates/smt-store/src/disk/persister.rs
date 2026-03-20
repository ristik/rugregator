//! After-mutation persistence: walk the modified tree and write to overlay.
//!
//! `persist_modified` is the primary entry-point.  It writes only non-Stub
//! (i.e. actually modified) nodes.  Since the SMT is insert-only, no nodes
//! are ever orphaned, so tombstoning is unnecessary.

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

/// Walk the post-insertion tree and serialize every non-Stub node into `overlay`.
///
/// Stubs represent untouched subtrees already persisted in RocksDB and are
/// skipped.  No tombstoning is performed: in an insert-only tree, NodeKeys
/// are only ever created or updated in-place (never orphaned).
pub fn persist_modified(
    smt:     &mut SparseMerkleTree,
    overlay: &mut Overlay,
) {
    calc_node_hash(&mut smt.root);

    let root_nk = NodeKey::root();
    overlay.put(&root_nk, serialize_node(&smt.root));

    let n_path   = path_len(&smt.root.path);
    let base_acc = extract_node_prefix_bits(&smt.root.path, n_path);
    let split    = n_path;

    if let Some(left) = &mut smt.root.left {
        persist_branch_modified(Arc::make_mut(left), false, split, &base_acc, overlay);
    }
    if let Some(right) = &mut smt.root.right {
        persist_branch_modified(Arc::make_mut(right), true, split, &base_acc, overlay);
    }
}

// ─── Recursive helper ────────────────────────────────────────────────────────

fn persist_branch_modified(
    branch:   &mut Branch,
    is_right: bool,
    split:    usize,
    acc:      &BigUint,
    overlay:  &mut Overlay,
) {
    match branch {
        Branch::Stub(_) => {
            // Already in DB — nothing to write.
        }

        Branch::Leaf(l) => {
            let child_acc = if is_right {
                acc | (BigUint::from(1u8) << split)
            } else {
                acc.clone()
            };
            let nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);
            if l.hash_cache.is_none() {
                l.hash_cache = Some(calc_leaf_hash(l));
            }
            overlay.put(&nk, serialize_leaf(l));
        }

        Branch::Node(n) => {
            calc_node_hash(n);

            let child_acc = if is_right {
                acc | (BigUint::from(1u8) << split)
            } else {
                acc.clone()
            };
            let nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

            let n_path      = path_len(&n.path);
            let prefix_bits = extract_node_prefix_bits(&n.path, n_path);
            let base_acc    = &child_acc | (prefix_bits << split);
            let node_split  = split + n_path;

            overlay.put(&nk, serialize_node(n));

            if let Some(left) = &mut n.left {
                persist_branch_modified(Arc::make_mut(left), false, node_split, &base_acc, overlay);
            }
            if let Some(right) = &mut n.right {
                persist_branch_modified(Arc::make_mut(right), true, node_split, &base_acc, overlay);
            }
        }
    }
}
