//! After-mutation persistence: walk the modified tree and write to overlay.

use std::sync::Arc;
use rsmt::{Branch, SparseMerkleTree};
use rsmt::node_serde::{serialize_leaf, serialize_node};

use super::node_key::{NodeKey, PrefixBits, prefix_set_bit, prefix_copy_path};
use super::overlay::Overlay;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Walk the post-insertion tree and serialize every non-Stub node into `overlay`.
pub fn persist_modified(
    smt:     &SparseMerkleTree,
    overlay: &mut Overlay,
) {
    let Some(root_arc) = &smt.root else { return };

    let root_nk = NodeKey::root();

    match root_arc.as_ref() {
        Branch::Node(n) => {
            overlay.put(&root_nk, serialize_node(n));

            let mut acc: PrefixBits = [0u8; 32];
            prefix_copy_path(&mut acc, 0, &n.path);
            let split = n.path.path_len();

            persist_branch_modified(&n.left, false, split, &acc, overlay);
            persist_branch_modified(&n.right, true, split, &acc, overlay);
        }
        Branch::Leaf(l) => {
            overlay.put(&root_nk, serialize_leaf(l));
        }
        Branch::Stub(_) => {}
    }
}

// ─── Recursive helper ────────────────────────────────────────────────────────

fn persist_branch_modified(
    branch:   &Arc<Branch>,
    is_right: bool,
    split:    usize,
    acc:      &PrefixBits,
    overlay:  &mut Overlay,
) {
    match branch.as_ref() {
        Branch::Stub(_) => {
            // Already in DB — nothing to write.
        }

        Branch::Leaf(l) => {
            let mut child_acc = *acc;
            if is_right {
                prefix_set_bit(&mut child_acc, split);
            }
            let nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);
            overlay.put(&nk, serialize_leaf(l));
        }

        Branch::Node(n) => {
            let mut child_acc = *acc;
            if is_right {
                prefix_set_bit(&mut child_acc, split);
            }
            let nk = NodeKey::from_depth_and_prefix(split + 1, &child_acc);

            let n_path = n.path.path_len();
            let mut base_acc = child_acc;
            prefix_copy_path(&mut base_acc, split + 1, &n.path);
            let node_split = split + 1 + n_path;

            overlay.put(&nk, serialize_node(n));

            persist_branch_modified(&n.left, false, node_split, &base_acc, overlay);
            persist_branch_modified(&n.right, true, node_split, &base_acc, overlay);
        }
    }
}
