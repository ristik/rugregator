//! Consistency proofs for the Sparse Merkle Tree.
//!
//! Two public entry-points:
//!
//! - [`batch_insert`]            — fast insert, no proof overhead.
//! - [`batch_insert_with_proof`] — insert + generate post-order consistency proof.
//!
//! Both default to SHA-256; use the `_with::<H>` variants to select a hasher.
//!
//! ## Proof format (post-order, 3 opcodes)
//!
//! The proof is a flat stream from LSB-first post-order traversal:
//!
//! | Opcode | Stream encoding | Meaning |
//! |--------|----------------|---------|
//! | `S`    | `['S', hash?]` | Unchanged subtree (hash or None for empty). |
//! | `L`    |  `['L']`       | New leaf — consumer pops from sorted batch. |
//! | `N`    | `['N', depth]` | Node at depth. Two children precede (left, right). |
//!
//! ## Verification (stack machine)
//!
//! 1. Sort batch B by LSB-first traversal order (`get_sort_key`).
//! 2. Scan tokens:
//!    - `S(h)`: push `(h, h)`.
//!    - `L`: pop `(k,v)` from sorted batch, push `(None, hash_leaf(k,v))`.
//!    - `N(depth)`: pop right `(rh0,rh1)`, pop left `(lh0,lh1)`.
//!      `h0 = resolve_pre_state(lh0, rh0, depth)`,
//!      `h1 = hash_node(lh1, rh1, depth)`. Push `(h0, h1)`.
//! 3. Accept iff streams exhausted, stack has one element = `(old_root, new_root)`.
//!
//! ## Wire format (binary)
//!
//! [`consistency_proof_to_bytes`] encodes the proof as a flat byte slice:
//!
//! | Opcode | Bytes            | Size |
//! |--------|------------------|------|
//! | `S(h)` | `0x00` + `h[32]` | 33   |
//! | `L`    | `0x01`           | 1    |
//! | `N(d)` | `0x02` + `d`     | 2    |

use std::collections::HashMap;
use std::sync::Arc;

use crate::hash::{SmtHasher, Sha256Hasher};
use rayon;
use crate::path::{get_sort_key, key_bit_at, CompressedPath, SmtKey, KEY_BITS};
use crate::tree::{SmtError, SparseMerkleTree};
use crate::types::{branch_hash, make_leaf, make_node, Branch, NodeBranch};

/// Minimum batch slice size to spawn a rayon parallel task.
/// Below this threshold sequential execution is faster (rayon overhead ~1 µs).
const PAR_THRESHOLD: usize = 64;

// ─── Proof opcodes ────────────────────────────────────────────────────────────

/// One element of the flat post-order consistency-proof stream.
#[derive(Debug, Clone)]
pub enum ProofOp {
    /// Unchanged subtree — carries its hash.
    ///
    /// `S(None)` (empty unchanged subtree) is provably unreachable for any
    /// valid tree operation and is not part of the format.
    S([u8; 32]),
    /// New leaf (key/value consumed from sorted batch).
    L,
    /// Node at the given depth. Two children precede on the stack.
    N(u8),
}

/// Ordered flat consistency proof.
pub type ConsistencyProof = Vec<ProofOp>;

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

/// Verify a consistency proof using SHA-256 (default).
pub fn verify_consistency(
    proof: &ConsistencyProof,
    old_root: Option<[u8; 32]>,
    new_root: Option<[u8; 32]>,
    batch: &[(SmtKey, Vec<u8>)],
) -> bool {
    verify_consistency_with::<Sha256Hasher>(proof, old_root, new_root, batch)
}

/// Verify a consistency proof using the given hasher.
pub fn verify_consistency_with<H: SmtHasher>(
    proof: &ConsistencyProof,
    old_root: Option<[u8; 32]>,
    new_root: Option<[u8; 32]>,
    batch: &[(SmtKey, Vec<u8>)],
) -> bool {
    if batch.is_empty() {
        return old_root == new_root;
    }

    // Precompute sort keys exactly once; sort (sort_key, original_index) pairs.
    let mut sort_idx: Vec<(SmtKey, usize)> = batch
        .iter()
        .enumerate()
        .map(|(i, (k, _))| (get_sort_key(k), i))
        .collect();
    sort_idx.sort_unstable_by_key(|&(sk, _)| sk);

    let mut stack: Vec<(Option<[u8; 32]>, Option<[u8; 32]>)> = Vec::new();
    let mut pi = 0usize; // proof index
    let mut bi = 0usize; // batch index (into sort_idx)

    while pi < proof.len() {
        match &proof[pi] {
            ProofOp::S(h) => {
                pi += 1;
                stack.push((Some(*h), Some(*h)));
            }
            ProofOp::L => {
                pi += 1;
                if bi >= sort_idx.len() {
                    return false;
                }
                let (k, v) = &batch[sort_idx[bi].1];
                bi += 1;
                stack.push((None, Some(H::hash_leaf(k, v))));
            }
            ProofOp::N(depth) => {
                pi += 1;
                let depth = *depth;
                if stack.len() < 2 {
                    return false;
                }
                let (rh0, rh1) = stack.pop().unwrap();
                let (lh0, lh1) = stack.pop().unwrap();

                let h0 = match (lh0, rh0) {
                    (None, None) => None,
                    (None, rh) => rh,
                    (lh, None) => lh,
                    (Some(l), Some(r)) => Some(H::hash_node(&l, &r, depth)),
                };

                let h1 = match (lh1, rh1) {
                    (Some(l), Some(r)) => Some(H::hash_node(&l, &r, depth)),
                    _ => return false,
                };

                stack.push((h0, h1));
            }
        }
    }

    pi == proof.len()
        && bi == sort_idx.len()
        && stack.len() == 1
        && stack[0].0 == old_root
        && stack[0].1 == new_root
}

// ─── Wire encoding ───────────────────────────────────────────────────────────

/// Encode a `ConsistencyProof` as a flat binary byte slice.
///
/// Wire format per opcode:
/// - `S(h)`: `[0x00, h[0..32]]` — 33 bytes
/// - `L`:    `[0x01]`           —  1 byte
/// - `N(d)`: `[0x02, d]`        —  2 bytes
pub fn consistency_proof_to_bytes(proof: &ConsistencyProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(proof.len() * 4);
    for op in proof {
        match op {
            ProofOp::S(h) => { out.push(0x00); out.extend_from_slice(h); }
            ProofOp::L    => { out.push(0x01); }
            ProofOp::N(d) => { out.push(0x02); out.push(*d); }
        }
    }
    out
}

/// Legacy CBOR encoding — kept for callers that have not yet migrated.
///
/// Prefer [`consistency_proof_to_bytes`] for new deployments.
pub fn consistency_proof_to_cbor(proof: &ConsistencyProof) -> Vec<u8> {
    let mut out = cbor_array(proof.len());
    for op in proof {
        match op {
            ProofOp::S(h) => {
                out.extend_from_slice(&cbor_array(2));
                out.push(0x00);
                out.push(0x58);
                out.push(32);
                out.extend_from_slice(h);
            }
            ProofOp::L => {
                out.extend_from_slice(&cbor_array(1));
                out.push(0x01);
            }
            ProofOp::N(depth) => {
                out.extend_from_slice(&cbor_array(2));
                out.push(0x02);
                out.push(0x18);
                out.push(*depth);
            }
        }
    }
    out
}

fn cbor_array(len: usize) -> Vec<u8> {
    if len < 24 {
        vec![0x80 | len as u8]
    } else if len < 256 {
        vec![0x98, len as u8]
    } else {
        let n = len as u16;
        vec![0x99, (n >> 8) as u8, n as u8]
    }
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

    new_items.sort_by(|a, b| get_sort_key(&a.0).cmp(&get_sort_key(&b.0)));

    let mut proof = Vec::new();
    let old_root = tree.root.take();
    let proof_out = if with_proof { Some(&mut proof) } else { None };
    let new_root = insert_proof::<H>(old_root, &new_items, 0, new_items.len(), 0, proof_out);
    tree.root = new_root;

    Ok((new_items, proof))
}

// ─── insert_proof ─────────────────────────────────────────────────────────────

fn insert_proof<H: SmtHasher>(
    node_opt: Option<Arc<Branch>>,
    batch: &[(SmtKey, Vec<u8>)],
    start: usize,
    end: usize,
    start_bit: usize,
    proof_out: Option<&mut Vec<ProofOp>>,
) -> Option<Arc<Branch>> {
    if start == end {
        if let Some(p) = proof_out {
            // node_opt is always Some here: internal nodes always have two
            // non-None children, and node_split_proof guarantees the
            // batch-only side is non-empty.
            let h = branch_hash(node_opt.as_deref().expect("S(None) unreachable"));
            p.push(ProofOp::S(h));
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
            mixed.sort_by(|a, b| get_sort_key(&a.0).cmp(&get_sort_key(&b.0)));
            Some(build_subtree::<H>(&mixed, 0, mixed.len(), start_bit, proof_out, &frozen))
        }

        Branch::Node(node) => {
            let n_path = node.path.path_len();
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
                            || insert_proof::<H>(Some(left_arc),  batch, start, mid, split + 1, None),
                            || insert_proof::<H>(Some(right_arc), batch, mid,   end, split + 1, None),
                        )
                    } else {
                        let l = insert_proof::<H>(Some(node.left),  batch, start, mid, split + 1, None);
                        let r = insert_proof::<H>(Some(node.right), batch, mid,   end, split + 1, None);
                        (l, r)
                    };
                    Some(make_node::<H>(
                        node.path,
                        new_left.expect("left child"),
                        new_right.expect("right child"),
                        split as u8,
                    ))
                }
                Some(p) => {
                    let (new_left, new_right, lp, rp) = if end - start >= PAR_THRESHOLD {
                        let left_arc  = node.left.clone();
                        let right_arc = node.right.clone();
                        let ((nl, lp), (nr, rp)) = rayon::join(
                            || {
                                let mut lp = Vec::new();
                                let nl = insert_proof::<H>(Some(left_arc),  batch, start, mid, split + 1, Some(&mut lp));
                                (nl, lp)
                            },
                            || {
                                let mut rp = Vec::new();
                                let nr = insert_proof::<H>(Some(right_arc), batch, mid,   end, split + 1, Some(&mut rp));
                                (nr, rp)
                            },
                        );
                        (nl, nr, lp, rp)
                    } else {
                        let mut lp = Vec::new();
                        let mut rp = Vec::new();
                        let nl = insert_proof::<H>(Some(node.left),  batch, start, mid, split + 1, Some(&mut lp));
                        let nr = insert_proof::<H>(Some(node.right), batch, mid,   end, split + 1, Some(&mut rp));
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
            if let Some(old_hash) = frozen.get(k) {
                p.push(ProofOp::S(*old_hash));
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
            make_node::<H>(cp, ln, rn, split as u8)
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
            make_node::<H>(cp, ln, rn, split as u8)
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
    node.hash = Some(H::hash_node(&lh, &rh, node.depth));

    let new_cp = CompressedPath::from_key_range(&batch[start].0, start_bit, n_common);
    let mid = partition_point(batch, start, end, new_split);
    let old_node: Option<Arc<Branch>> = Some(Arc::new(Branch::Node(node)));

    match proof_out {
        None => {
            let (new_left, new_right) = if end - start >= PAR_THRESHOLD {
                if old_dir == 0 {
                    let old_node_r = old_node;
                    rayon::join(
                        || insert_proof::<H>(old_node_r, batch, start, mid, new_split + 1, None),
                        || insert_proof::<H>(None,       batch, mid,   end, new_split + 1, None),
                    )
                } else {
                    let old_node_r = old_node;
                    rayon::join(
                        || insert_proof::<H>(None,       batch, start, mid, new_split + 1, None),
                        || insert_proof::<H>(old_node_r, batch, mid,   end, new_split + 1, None),
                    )
                }
            } else if old_dir == 0 {
                let nl = insert_proof::<H>(old_node, batch, start, mid, new_split + 1, None);
                let nr = insert_proof::<H>(None,     batch, mid,   end, new_split + 1, None);
                (nl, nr)
            } else {
                let nl = insert_proof::<H>(None,     batch, start, mid, new_split + 1, None);
                let nr = insert_proof::<H>(old_node, batch, mid,   end, new_split + 1, None);
                (nl, nr)
            };
            make_node::<H>(
                new_cp,
                new_left.expect("left child"),
                new_right.expect("right child"),
                new_split as u8,
            )
        }
        Some(p) => {
            let (new_left, new_right, lp, rp) = if end - start >= PAR_THRESHOLD {
                let ((nl, lp), (nr, rp)) = if old_dir == 0 {
                    let old_node_r = old_node;
                    rayon::join(
                        || {
                            let mut lp = Vec::new();
                            let nl = insert_proof::<H>(old_node_r, batch, start, mid, new_split + 1, Some(&mut lp));
                            (nl, lp)
                        },
                        || {
                            let mut rp = Vec::new();
                            let nr = insert_proof::<H>(None, batch, mid, end, new_split + 1, Some(&mut rp));
                            (nr, rp)
                        },
                    )
                } else {
                    let old_node_r = old_node;
                    rayon::join(
                        || {
                            let mut lp = Vec::new();
                            let nl = insert_proof::<H>(None, batch, start, mid, new_split + 1, Some(&mut lp));
                            (nl, lp)
                        },
                        || {
                            let mut rp = Vec::new();
                            let nr = insert_proof::<H>(old_node_r, batch, mid, end, new_split + 1, Some(&mut rp));
                            (nr, rp)
                        },
                    )
                };
                (nl, nr, lp, rp)
            } else {
                let mut lp = Vec::new();
                let mut rp = Vec::new();
                let (nl, nr) = if old_dir == 0 {
                    let nl = insert_proof::<H>(old_node, batch, start, mid, new_split + 1, Some(&mut lp));
                    let nr = insert_proof::<H>(None,     batch, mid,   end, new_split + 1, Some(&mut rp));
                    (nl, nr)
                } else {
                    let nl = insert_proof::<H>(None,     batch, start, mid, new_split + 1, Some(&mut lp));
                    let nr = insert_proof::<H>(old_node, batch, mid,   end, new_split + 1, Some(&mut rp));
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

fn first_set_bit_from(key: &SmtKey, start_bit: usize) -> usize {
    let byte_idx = start_bit / 8;
    let bit_off  = start_bit % 8;
    if byte_idx < 32 {
        let masked = key[byte_idx] >> bit_off;
        if masked != 0 {
            return start_bit + masked.trailing_zeros() as usize;
        }
    }
    for i in (byte_idx + 1)..32 {
        if key[i] != 0 {
            return i * 8 + key[i].trailing_zeros() as usize;
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
    use crate::hash::{Blake3Hasher, Sha256Hasher};

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

        // border leaf
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

    #[test]
    fn sha256_suite() { run_suite::<Sha256Hasher>(); }

    #[test]
    fn blake3_suite() { run_suite::<Blake3Hasher>(); }

    #[test]
    fn sha256_and_blake3_roots_differ() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let pairs: Vec<_> = (1u8..=4).map(|i| (make_key(i), vec![i;32])).collect();
        batch_insert_with::<Sha256Hasher>(&mut t1, &pairs).unwrap();
        batch_insert_with::<Blake3Hasher>(&mut t2, &pairs).unwrap();
        assert_ne!(t1.root_hash(), t2.root_hash());
    }

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
