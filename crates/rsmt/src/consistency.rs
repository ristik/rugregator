//! Consistency proofs for the Sparse Merkle Tree.
//!
//! Two public entry-points:
//!
//! - [`batch_insert`]            — fast insert, no proof overhead.
//! - [`batch_insert_with_proof`] — insert + generate post-order consistency proof.
//!
//! Both default to SHA-256; use the `_with::<H>` variants to select a hasher.
//!
//! ## Proof format (post-order, RSMT v6a — 5 opcodes)
//!
//! The proof is a flat stream from big-endian (MSB-first) post-order traversal:
//!
//! | Opcode         | Stream encoding                    | Meaning |
//! |-----------------|-------------------------------------|---------|
//! | `S`             | `['S', hash]`                       | Opaque preserved subtree — only valid where the parent junction already existed pre-round. |
//! | `L`              | `['L']`                             | New leaf — consumer pops from sorted batch. |
//! | `N`              | `['N', depth]`                      | Junction at depth. Two children precede (left, right). |
//! | `O`              | `['O', depth, region, lh, rh]`      | Preserved junction, opened one level — required when it becomes the child of a junction created this round. |
//! | `O_L`            | `['OL', key, value]`                | Preserved leaf, opened (same "new parent" trigger as `O`). |
//!
//! ## Generation
//!
//! A post-order traversal of the touched part of the post-state tree, threading
//! a `parent_new` flag through the recursion (mirrors the Yellowpaper's
//! `rsmt6a` prototype): a subtree left untouched by this round's batch is
//! emitted opaquely (`S`) if its parent junction already existed pre-round,
//! or opened (`O` / `O_L`) if it has just become the child of a junction
//! created this round (an edge split, including the leaf-merge case).
//!
//! ## Verification (region-aware stack machine)
//!
//! See `rsmt_verify::consistency::verify_consistency_with` for the full
//! algorithm (stack of `(h_pre, h_post, advice)` triples, region derived from
//! advised children at each `N`).
//!
//! ## Wire format (binary)
//!
//! [`consistency_proof_to_bytes`] encodes the proof as a flat byte slice —
//! see `rsmt_verify::consistency` for the per-opcode byte layout.

use std::collections::HashMap;
use std::sync::Arc;

use rayon;
use rsmt_verify::{Sha256Hasher, SmtHasher, SmtKey};
use crate::path::{key_bit_at, prefix_region, CompressedPath, KEY_BITS};
use crate::tree::{SmtError, SparseMerkleTree};
use crate::types::{branch_hash, make_leaf, make_node, Branch, NodeBranch};

// Re-export the types now living in rsmt-verify so that `crate::consistency::*`
// imports still resolve for the test module in this file.
pub use rsmt_verify::{
    ProofOp, ConsistencyProof,
    verify_consistency, verify_consistency_with,
    consistency_proof_to_bytes, encode_aggregator_envelope_v1,
};

/// Minimum batch slice size to spawn a rayon parallel task.
/// Below this threshold sequential execution is faster (rayon overhead ~1 µs).
const PAR_THRESHOLD: usize = 64;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Insert a batch using SHA-256 (default), no proof.
pub fn batch_insert(
    tree: &mut SparseMerkleTree,
    batch: &[(SmtKey, Vec<u8>)],
) -> Result<Vec<(SmtKey, Vec<u8>)>, SmtError> {
    batch_insert_with::<Sha256Hasher>(tree, batch)
}

/// Insert a batch using the given hasher, no proof.
pub fn batch_insert_with<H: SmtHasher>(
    tree: &mut SparseMerkleTree,
    batch: &[(SmtKey, Vec<u8>)],
) -> Result<Vec<(SmtKey, Vec<u8>)>, SmtError> {
    let (items, _) = run_batch::<H>(tree, batch, false)?;
    Ok(items)
}

/// Insert a batch using SHA-256 (default) and generate a consistency proof.
pub fn batch_insert_with_proof(
    tree: &mut SparseMerkleTree,
    batch: &[(SmtKey, Vec<u8>)],
) -> Result<(Vec<(SmtKey, Vec<u8>)>, ConsistencyProof), SmtError> {
    batch_insert_with_proof_with::<Sha256Hasher>(tree, batch)
}

/// Insert a batch using the given hasher and generate a consistency proof.
pub fn batch_insert_with_proof_with<H: SmtHasher>(
    tree: &mut SparseMerkleTree,
    batch: &[(SmtKey, Vec<u8>)],
) -> Result<(Vec<(SmtKey, Vec<u8>)>, ConsistencyProof), SmtError> {
    run_batch::<H>(tree, batch, true)
}

// ─── Core algorithm ───────────────────────────────────────────────────────────

fn run_batch<H: SmtHasher>(
    tree: &mut SparseMerkleTree,
    batch: &[(SmtKey, Vec<u8>)],
    with_proof: bool,
) -> Result<(Vec<(SmtKey, Vec<u8>)>, ConsistencyProof), SmtError> {
    let mut seen: HashMap<SmtKey, ()> = HashMap::new();
    let mut new_items: Vec<(SmtKey, Vec<u8>)> = Vec::new();
    for (k, v) in batch {
        if seen.contains_key(k) {
            continue;
        }
        seen.insert(*k, ());
        if tree.find_leaf(k).is_some() {
            continue;
        }
        new_items.push((*k, v.clone()));
    }

    if new_items.is_empty() {
        // For an empty inserted set old_root == new_root, so verify_consistency
        // short-circuits before reading the proof. Return [] regardless.
        return Ok((vec![], vec![]));
    }

    // RSMT v6a: plain key order is traversal order (rsmt_sort_key(k) = k).
    new_items.sort_by(|a, b| a.0.cmp(&b.0));

    let mut proof = Vec::new();
    let old_root = tree.root.take();
    let proof_out = if with_proof { Some(&mut proof) } else { None };
    let new_root = insert_proof::<H>(old_root, &new_items, 0, new_items.len(), 0, false, proof_out);
    tree.root = new_root;

    Ok((new_items, proof))
}

// ─── emit_preserved ───────────────────────────────────────────────────────────

/// A subtree untouched this round: opaque under a pre-existing junction,
/// opened one level under a junction created this round (the split edge).
fn emit_preserved(branch: &Branch, parent_new: bool, out: &mut Vec<ProofOp>) {
    if !parent_new {
        out.push(ProofOp::S(branch_hash(branch)));
        return;
    }
    match branch {
        Branch::Leaf(l) => out.push(ProofOp::OL {
            key: l.key,
            value: l.value.clone(),
        }),
        Branch::Node(n) => out.push(ProofOp::O {
            depth: n.depth,
            region: n.region,
            left: branch_hash(&n.left),
            right: branch_hash(&n.right),
        }),
        Branch::Stub(_) => {
            panic!("emit_preserved: encountered Stub — materialize from disk first");
        }
    }
}

// ─── insert_proof ─────────────────────────────────────────────────────────────

fn insert_proof<H: SmtHasher>(
    node_opt: Option<Arc<Branch>>,
    batch: &[(SmtKey, Vec<u8>)],
    start: usize,
    end: usize,
    start_bit: usize,
    parent_new: bool,
    proof_out: Option<&mut Vec<ProofOp>>,
) -> Option<Arc<Branch>> {
    if start == end {
        if let Some(p) = proof_out {
            // node_opt is always Some here: internal nodes always have two
            // non-None children, and node_split_proof guarantees the
            // batch-only side is non-empty.
            let branch = node_opt.as_deref().expect("preserved subtree unreachable");
            emit_preserved(branch, parent_new, p);
        }
        return node_opt;
    }

    let Some(arc) = node_opt else {
        return Some(build_subtree::<H>(
            batch, start, end, start_bit, proof_out, &HashMap::new(),
        ));
    };

    let b = match Arc::try_unwrap(arc) {
        Ok(b) => b,
        Err(a) => (*a).clone(),
    };

    match b {
        Branch::Leaf(leaf) => {
            let frozen: HashMap<SmtKey, [u8; 32]> =
                [(leaf.key, leaf.hash)].into_iter().collect();
            let mut mixed: Vec<(SmtKey, Vec<u8>)> = batch[start..end].to_vec();
            mixed.push((leaf.key, leaf.value));
            mixed.sort_by(|a, b| a.0.cmp(&b.0));
            Some(build_subtree::<H>(&mixed, 0, mixed.len(), start_bit, proof_out, &frozen))
        }

        Branch::Node(node) => {
            let n_path = node.path.path_len();
            let region = node.region;
            let node_prefix_matches = |key: &SmtKey| -> usize {
                first_divergence_in_prefix(&node.path, key, start_bit)
            };

            let mut first_div = n_path;
            let d_start = node_prefix_matches(&batch[start].0);
            if d_start < first_div { first_div = d_start; }
            let d_end = node_prefix_matches(&batch[end - 1].0);
            if d_end < first_div { first_div = d_end; }

            if first_div < n_path {
                return Some(node_split_proof::<H>(
                    node, batch, start, end, start_bit, first_div, proof_out,
                ));
            }

            let split = start_bit + n_path;
            let mid = partition_point(batch, start, end, split);

            match proof_out {
                None => {
                    let (new_left, new_right) = if end - start >= PAR_THRESHOLD {
                        let left_arc  = node.left.clone();
                        let right_arc = node.right.clone();
                        rayon::join(
                            || insert_proof::<H>(Some(left_arc),  batch, start, mid, split + 1, false, None),
                            || insert_proof::<H>(Some(right_arc), batch, mid,   end, split + 1, false, None),
                        )
                    } else {
                        let l = insert_proof::<H>(Some(node.left),  batch, start, mid, split + 1, false, None);
                        let r = insert_proof::<H>(Some(node.right), batch, mid,   end, split + 1, false, None);
                        (l, r)
                    };
                    Some(make_node::<H>(
                        node.path,
                        new_left.expect("left child"),
                        new_right.expect("right child"),
                        split as u8,
                        region,
                    ))
                }
                Some(p) => {
                    let (new_left, new_right, lp, rp) = if end - start >= PAR_THRESHOLD {
                        let left_arc  = node.left.clone();
                        let right_arc = node.right.clone();
                        let ((nl, lp), (nr, rp)) = rayon::join(
                            || {
                                let mut lp = Vec::new();
                                let nl = insert_proof::<H>(Some(left_arc),  batch, start, mid, split + 1, false, Some(&mut lp));
                                (nl, lp)
                            },
                            || {
                                let mut rp = Vec::new();
                                let nr = insert_proof::<H>(Some(right_arc), batch, mid,   end, split + 1, false, Some(&mut rp));
                                (nr, rp)
                            },
                        );
                        (nl, nr, lp, rp)
                    } else {
                        let mut lp = Vec::new();
                        let mut rp = Vec::new();
                        let nl = insert_proof::<H>(Some(node.left),  batch, start, mid, split + 1, false, Some(&mut lp));
                        let nr = insert_proof::<H>(Some(node.right), batch, mid,   end, split + 1, false, Some(&mut rp));
                        (nl, nr, lp, rp)
                    };
                    p.extend(lp);
                    p.extend(rp);
                    p.push(ProofOp::N(split as u8));
                    Some(make_node::<H>(
                        node.path,
                        new_left.expect("left child"),
                        new_right.expect("right child"),
                        split as u8,
                        region,
                    ))
                }
            }
        }

        Branch::Stub(_) => {
            panic!("insert_proof: encountered Stub — materialize from disk first");
        }
    }
}

// ─── build_subtree ────────────────────────────────────────────────────────────

fn build_subtree<H: SmtHasher>(
    batch: &[(SmtKey, Vec<u8>)],
    start: usize,
    end: usize,
    start_bit: usize,
    proof_out: Option<&mut Vec<ProofOp>>,
    frozen: &HashMap<SmtKey, [u8; 32]>,
) -> Arc<Branch> {
    debug_assert!(end > start);

    if end - start == 1 {
        let (k, v) = &batch[start];
        if let Some(p) = proof_out {
            if frozen.contains_key(k) {
                // Every leaf `build_subtree` touches becomes a child of a
                // freshly built junction, so a frozen (preserved) leaf must
                // always be presented opened.
                p.push(ProofOp::OL { key: *k, value: v.clone() });
            } else {
                p.push(ProofOp::L);
            }
        }
        return make_leaf::<H>(*k, v.clone());
    }

    let xor = xor_keys(&batch[start].0, &batch[end - 1].0);
    let split = first_set_bit_from(&xor, start_bit);
    let mid = partition_point(batch, start, end, split);

    debug_assert!(mid > start && mid < end,
        "trivial partition at split={split} start={start} mid={mid} end={end}");

    let n_common = split - start_bit;
    let cp = CompressedPath::from_key_range(&batch[start].0, start_bit, n_common);
    let region = prefix_region(&batch[start].0, split);

    match proof_out {
        None => {
            let (ln, rn) = if end - start >= PAR_THRESHOLD {
                rayon::join(
                    || build_subtree::<H>(batch, start, mid, split + 1, None, frozen),
                    || build_subtree::<H>(batch, mid,   end, split + 1, None, frozen),
                )
            } else {
                let l = build_subtree::<H>(batch, start, mid, split + 1, None, frozen);
                let r = build_subtree::<H>(batch, mid,   end, split + 1, None, frozen);
                (l, r)
            };
            make_node::<H>(cp, ln, rn, split as u8, region)
        }
        Some(p) => {
            let (ln, rn, lp, rp) = if end - start >= PAR_THRESHOLD {
                let ((ln, lp), (rn, rp)) = rayon::join(
                    || {
                        let mut lp = Vec::new();
                        let l = build_subtree::<H>(batch, start, mid, split + 1, Some(&mut lp), frozen);
                        (l, lp)
                    },
                    || {
                        let mut rp = Vec::new();
                        let r = build_subtree::<H>(batch, mid,   end, split + 1, Some(&mut rp), frozen);
                        (r, rp)
                    },
                );
                (ln, rn, lp, rp)
            } else {
                let mut lp = Vec::new();
                let mut rp = Vec::new();
                let ln = build_subtree::<H>(batch, start, mid, split + 1, Some(&mut lp), frozen);
                let rn = build_subtree::<H>(batch, mid,   end, split + 1, Some(&mut rp), frozen);
                (ln, rn, lp, rp)
            };
            p.extend(lp);
            p.extend(rp);
            p.push(ProofOp::N(split as u8));
            make_node::<H>(cp, ln, rn, split as u8, region)
        }
    }
}

// ─── node_split_proof ────────────────────────────────────────────────────────

fn node_split_proof<H: SmtHasher>(
    mut node: NodeBranch,
    batch: &[(SmtKey, Vec<u8>)],
    start: usize,
    end: usize,
    start_bit: usize,
    first_div: usize,
    proof_out: Option<&mut Vec<ProofOp>>,
) -> Arc<Branch> {
    let n_path = node.path.path_len();
    let n_common = first_div;
    let new_split = start_bit + n_common;
    let old_dir = node.path.bit_at(n_common);

    let remaining = n_path - n_common - 1;
    node.path = CompressedPath::from_key_range_with_path_bits(&node.path, n_common + 1, remaining);
    node.hash = None;
    let lh = branch_hash(&node.left);
    let rh = branch_hash(&node.right);
    // node.depth and node.region are absolute properties of the preserved
    // node and are unchanged by the split.
    node.hash = Some(H::hash_node(&lh, &rh, node.depth, &node.region));

    let new_cp = CompressedPath::from_key_range(&batch[start].0, start_bit, n_common);
    let new_region = prefix_region(&batch[start].0, new_split);
    let mid = partition_point(batch, start, end, new_split);
    let old_node: Option<Arc<Branch>> = Some(Arc::new(Branch::Node(node)));

    match proof_out {
        None => {
            let (new_left, new_right) = if end - start >= PAR_THRESHOLD {
                if old_dir == 0 {
                    let old_node_r = old_node;
                    rayon::join(
                        || insert_proof::<H>(old_node_r, batch, start, mid, new_split + 1, true, None),
                        || insert_proof::<H>(None,       batch, mid,   end, new_split + 1, true, None),
                    )
                } else {
                    let old_node_r = old_node;
                    rayon::join(
                        || insert_proof::<H>(None,       batch, start, mid, new_split + 1, true, None),
                        || insert_proof::<H>(old_node_r, batch, mid,   end, new_split + 1, true, None),
                    )
                }
            } else if old_dir == 0 {
                let nl = insert_proof::<H>(old_node, batch, start, mid, new_split + 1, true, None);
                let nr = insert_proof::<H>(None,     batch, mid,   end, new_split + 1, true, None);
                (nl, nr)
            } else {
                let nl = insert_proof::<H>(None,     batch, start, mid, new_split + 1, true, None);
                let nr = insert_proof::<H>(old_node, batch, mid,   end, new_split + 1, true, None);
                (nl, nr)
            };
            make_node::<H>(
                new_cp,
                new_left.expect("left child"),
                new_right.expect("right child"),
                new_split as u8,
                new_region,
            )
        }
        Some(p) => {
            let (new_left, new_right, lp, rp) = if end - start >= PAR_THRESHOLD {
                let ((nl, lp), (nr, rp)) = if old_dir == 0 {
                    let old_node_r = old_node;
                    rayon::join(
                        || {
                            let mut lp = Vec::new();
                            let nl = insert_proof::<H>(old_node_r, batch, start, mid, new_split + 1, true, Some(&mut lp));
                            (nl, lp)
                        },
                        || {
                            let mut rp = Vec::new();
                            let nr = insert_proof::<H>(None, batch, mid, end, new_split + 1, true, Some(&mut rp));
                            (nr, rp)
                        },
                    )
                } else {
                    let old_node_r = old_node;
                    rayon::join(
                        || {
                            let mut lp = Vec::new();
                            let nl = insert_proof::<H>(None, batch, start, mid, new_split + 1, true, Some(&mut lp));
                            (nl, lp)
                        },
                        || {
                            let mut rp = Vec::new();
                            let nr = insert_proof::<H>(old_node_r, batch, mid, end, new_split + 1, true, Some(&mut rp));
                            (nr, rp)
                        },
                    )
                };
                (nl, nr, lp, rp)
            } else {
                let mut lp = Vec::new();
                let mut rp = Vec::new();
                let (nl, nr) = if old_dir == 0 {
                    let nl = insert_proof::<H>(old_node, batch, start, mid, new_split + 1, true, Some(&mut lp));
                    let nr = insert_proof::<H>(None,     batch, mid,   end, new_split + 1, true, Some(&mut rp));
                    (nl, nr)
                } else {
                    let nl = insert_proof::<H>(None,     batch, start, mid, new_split + 1, true, Some(&mut lp));
                    let nr = insert_proof::<H>(old_node, batch, mid,   end, new_split + 1, true, Some(&mut rp));
                    (nl, nr)
                };
                (nl, nr, lp, rp)
            };
            p.extend(lp);
            p.extend(rp);
            p.push(ProofOp::N(new_split as u8));
            make_node::<H>(
                new_cp,
                new_left.expect("left child"),
                new_right.expect("right child"),
                new_split as u8,
                new_region,
            )
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[inline]
fn xor_keys(a: &SmtKey, b: &SmtKey) -> SmtKey {
    let mut out = [0u8; 32];
    for i in 0..32 { out[i] = a[i] ^ b[i]; }
    out
}

/// First set bit at or after `start_bit`, in MSB-first bit order (bit 0 =
/// MSB of byte 0). Fast-path equivalent of scanning `key_bit_at` upward.
fn first_set_bit_from(key: &SmtKey, start_bit: usize) -> usize {
    let byte_idx = start_bit / 8;
    let bit_off  = start_bit % 8;
    if byte_idx < 32 {
        // Keep only bits at MSB-first offsets >= bit_off within this byte.
        let masked = key[byte_idx] & (0xffu8 >> bit_off);
        if masked != 0 {
            return byte_idx * 8 + masked.leading_zeros() as usize;
        }
    }
    for i in (byte_idx + 1)..32 {
        if key[i] != 0 {
            return i * 8 + key[i].leading_zeros() as usize;
        }
    }
    KEY_BITS
}

fn partition_point(batch: &[(SmtKey, Vec<u8>)], start: usize, end: usize, split: usize) -> usize {
    let mut lo = start;
    let mut hi = end;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if key_bit_at(&batch[mid].0, split) == 1 { hi = mid; } else { lo = mid + 1; }
    }
    lo
}

fn first_divergence_in_prefix(path: &CompressedPath, key: &SmtKey, start_bit: usize) -> usize {
    let n = path.path_len();
    for i in 0..n {
        if path.bit_at(i) != key_bit_at(key, start_bit + i) { return i; }
    }
    n
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Blake2bHasher, Blake2sHasher, Sha256Hasher};

    fn make_key(byte: u8) -> SmtKey {
        let mut k = [0u8; 32]; k[0] = byte; k
    }

    fn check<H: SmtHasher>(tree: &mut SparseMerkleTree, batch: Vec<(SmtKey, Vec<u8>)>, label: &str) {
        let old = tree.root_hash();
        let (items, proof) = batch_insert_with_proof_with::<H>(tree, &batch).unwrap();
        let new = tree.root_hash();
        assert!(
            verify_consistency_with::<H>(&proof, old, new, &items),
            "{label}: consistency verification failed"
        );
    }

    fn run_suite<H: SmtHasher>() {
        // root matches sequential add_leaf
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let pairs: Vec<_> = (1u8..=8).map(|i| (make_key(i), vec![i; 32])).collect();
        for (k, v) in &pairs { t1.add_leaf_with::<H>(*k, v.clone()).unwrap(); }
        batch_insert_with::<H>(&mut t2, &pairs).unwrap();
        assert_eq!(t1.root_hash(), t2.root_hash());

        // single leaf
        let mut tree = SparseMerkleTree::new();
        check::<H>(&mut tree, vec![(make_key(1), vec![0xab; 32])], "single");

        // two leaves
        let mut tree = SparseMerkleTree::new();
        check::<H>(&mut tree, vec![(make_key(1), vec![1;32]), (make_key(2), vec![2;32])], "two");

        // border leaf: edge split, exercises O/OL emission
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<H>(make_key(1), vec![1;32]).unwrap();
        check::<H>(&mut tree, vec![(make_key(3), vec![3;32])], "border_leaf");

        // duplicate skipped
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<H>(make_key(5), vec![5;32]).unwrap();
        let old = tree.root_hash();
        let (items, proof) = batch_insert_with_proof_with::<H>(
            &mut tree,
            &[(make_key(5), vec![99;32]), (make_key(7), vec![7;32])],
        ).unwrap();
        assert_eq!(items.len(), 1);
        let new = tree.root_hash();
        assert!(verify_consistency_with::<H>(&proof, old, new, &items));

        // multi-round
        let mut tree = SparseMerkleTree::new();
        for r in 0u8..5 {
            let b: Vec<_> = (0u8..10).map(|i| (make_key(r*10+i), vec![r*10+i;32])).collect();
            check::<H>(&mut tree, b, &format!("round {r}"));
        }

        // fast batch matches with_proof
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let pairs: Vec<_> = (1u8..=16).map(|i| (make_key(i), vec![i;32])).collect();
        batch_insert_with::<H>(&mut t1, &pairs).unwrap();
        batch_insert_with_proof_with::<H>(&mut t2, &pairs).unwrap();
        assert_eq!(t1.root_hash(), t2.root_hash());

        // binary encoding non-empty
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<H>(make_key(1), vec![1;32]).unwrap();
        let batch: Vec<_> = (2u8..=6).map(|i| (make_key(i), vec![i;32])).collect();
        let old = tree.root_hash();
        let (items, proof) = batch_insert_with_proof_with::<H>(&mut tree, &batch).unwrap();
        let new = tree.root_hash();
        assert!(verify_consistency_with::<H>(&proof, old, new, &items));
        let bytes = consistency_proof_to_bytes(&proof);
        assert!(!bytes.is_empty());

        // empty batch
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<H>(make_key(1), vec![1;32]).unwrap();
        let old = tree.root_hash();
        let (items, proof) = batch_insert_with_proof_with::<H>(&mut tree, &[]).unwrap();
        assert!(items.is_empty());
        let new = tree.root_hash();
        assert_eq!(old, new);
        assert!(verify_consistency_with::<H>(&proof, old, new, &items));

        // insert into empty tree
        let mut tree = SparseMerkleTree::new();
        let old = tree.root_hash();
        let batch: Vec<_> = (1u8..=3).map(|i| (make_key(i), vec![i;32])).collect();
        let (items, proof) = batch_insert_with_proof_with::<H>(&mut tree, &batch).unwrap();
        let new = tree.root_hash();
        assert!(verify_consistency_with::<H>(&proof, old, new, &items));
    }

    /// A single existing leaf, split by one new leaf, must emit `OL` (opened),
    /// never opaque `S`, for the preserved leaf.
    #[test]
    fn border_leaf_emits_ol_not_s() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<Sha256Hasher>(make_key(1), vec![1; 32]).unwrap();
        let old = tree.root_hash();
        let (items, proof) = batch_insert_with_proof_with::<Sha256Hasher>(
            &mut tree,
            &[(make_key(3), vec![3; 32])],
        ).unwrap();
        let new = tree.root_hash();
        assert!(verify_consistency_with::<Sha256Hasher>(&proof, old, new, &items));
        assert!(
            proof.iter().any(|op| matches!(op, ProofOp::OL { .. })),
            "expected an OL opcode for the preserved leaf under the new split junction: {proof:?}"
        );
        assert!(
            !proof.iter().any(|op| matches!(op, ProofOp::S(_))),
            "no opaque S should appear when the only preserved subtree sits under a new edge: {proof:?}"
        );
    }

    /// Round 1 builds an internal NodeBranch (two leaves diverging at bit 4,
    /// sharing prefix bits 0..3 = "0000"). Round 2 inserts a key that
    /// diverges from that shared prefix at bit 2 — *before* the existing
    /// node's own depth — forcing a new junction above it and requiring the
    /// preserved NodeBranch to be presented opened via `O`.
    #[test]
    fn deep_split_emits_o_opcode() {
        let mut tree = SparseMerkleTree::new();
        let mut key_a = [0u8; 32];
        key_a[0] = 0b0000_0000; // bits 0..3 = 0000, bit 4 = 0
        let mut key_b = [0u8; 32];
        key_b[0] = 0b0000_1000; // bits 0..3 = 0000, bit 4 = 1
        batch_insert_with::<Sha256Hasher>(
            &mut tree,
            &[(key_a, vec![1; 4]), (key_b, vec![2; 4])],
        ).unwrap();

        let old = tree.root_hash();
        let mut key_c = [0u8; 32];
        key_c[0] = 0b0010_0000; // bits 0..1 = 00, bit 2 = 1: diverges before depth 4
        let batch = vec![(key_c, vec![0xEE; 4])];
        let (items, proof) = batch_insert_with_proof_with::<Sha256Hasher>(&mut tree, &batch).unwrap();
        let new = tree.root_hash();
        assert!(verify_consistency_with::<Sha256Hasher>(&proof, old, new, &items));
        assert!(
            proof.iter().any(|op| matches!(op, ProofOp::O { .. })),
            "expected an O opcode opening the preserved subtree under the new split junction: {proof:?}"
        );
    }

    /// Parse an `aggregator_rsmt_v1` envelope back into (leaves, proof) and
    /// run it through `verify_consistency`. This is the Rust-side mirror of
    /// the Go `rsmt.Verify` path and locks the wire format in place.
    fn decode_envelope_v1(
        bytes: &[u8],
    ) -> (Vec<(SmtKey, Vec<u8>)>, ConsistencyProof) {
        rsmt_verify::decode_aggregator_envelope_v1(bytes).expect("valid envelope")
    }

    #[test]
    fn envelope_v1_roundtrip() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf_with::<Sha256Hasher>(make_key(1), vec![1; 32]).unwrap();
        let old = tree.root_hash();
        let batch: Vec<_> = (2u8..=10).map(|i| (make_key(i), vec![i; 16])).collect();
        let (items, proof) = batch_insert_with_proof_with::<Sha256Hasher>(&mut tree, &batch).unwrap();
        let new = tree.root_hash();

        let envelope = encode_aggregator_envelope_v1(&items, &proof);
        let (re_leaves, re_proof) = decode_envelope_v1(&envelope);
        assert_eq!(re_leaves.len(), items.len());
        for (a, b) in re_leaves.iter().zip(items.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1, b.1);
        }
        assert!(
            verify_consistency_with::<Sha256Hasher>(&re_proof, old, new, &re_leaves),
            "envelope round-trip failed verification"
        );
    }

    #[test]
    fn envelope_v1_empty_batch() {
        // No leaves, no proof → 4 bytes of zeros.
        let env = encode_aggregator_envelope_v1(&[], &vec![]);
        assert_eq!(env, vec![0, 0, 0, 0]);
    }

    #[test]
    fn envelope_v1_leaves_pre_sorted() {
        // Encoder accepts sorted leaves from batch_insert_with_proof.
        let mut tree = SparseMerkleTree::new();
        let batch: Vec<_> = (1u8..=8).map(|i| (make_key(i ^ 0xA5), vec![i])).collect();
        let (items, proof) = batch_insert_with_proof_with::<Sha256Hasher>(&mut tree, &batch).unwrap();
        // items is guaranteed sorted by consistency.rs; encoder's debug_assert!
        // verifies this — if it trips, we have a regression.
        let _ = encode_aggregator_envelope_v1(&items, &proof);
    }

    #[test]
    fn sha256_suite() { run_suite::<Sha256Hasher>(); }

    #[test]
    fn blake2s_suite() { run_suite::<Blake2sHasher>(); }

    #[test]
    fn blake2b_suite() { run_suite::<Blake2bHasher>(); }

    fn lcg_key(seed: &mut u64) -> SmtKey {
        let mut key = [0u8; 32];
        for chunk in key.chunks_exact_mut(8) {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            chunk.copy_from_slice(&seed.to_le_bytes());
        }
        key
    }

    #[test]
    fn large_random_multi_round_no_panic() {
        let mut tree = SparseMerkleTree::new();
        let mut seed: u64 = 0xdeadbeef_cafebabe;
        for _round in 0..20 {
            let batch: Vec<(SmtKey, Vec<u8>)> = (0..500)
                .map(|_| (lcg_key(&mut seed), vec![42u8; 32]))
                .collect();
            batch_insert(&mut tree, &batch).unwrap();
        }
    }
}
