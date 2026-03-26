//! Consistency proofs for the Sparse Merkle Tree.
//!
//! Two public entry-points:
//!
//! - [`batch_insert`]            — fast insert, no proof overhead.
//! - [`batch_insert_with_proof`] — insert + generate post-order consistency proof.
//!
//! ## Proof format (post-order, 3 opcodes)
//!
//! The proof is a flat stream from LSB-first post-order traversal:
//!
//! | Opcode | Stream encoding | Meaning |
//! |--------|----------------|---------|
//! | `S`    | `['S', hash]`  | Unchanged subtree (hash or None for empty). |
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

use std::collections::HashMap;
use std::sync::Arc;

use crate::hash::{hash_leaf, hash_node};
use crate::path::{get_sort_key, key_bit_at, CompressedPath, SmtKey, KEY_BITS};
use crate::tree::{SmtError, SparseMerkleTree};
use crate::types::{branch_hash, make_leaf, make_node, Branch, NodeBranch};

// ─── Proof opcodes ────────────────────────────────────────────────────────────

/// One element of the flat post-order consistency-proof stream.
#[derive(Debug, Clone)]
pub enum ProofOp {
    /// Unchanged subtree hash (`None` = empty subtree).
    S(Option<[u8; 32]>),
    /// New leaf (key/value consumed from sorted batch).
    L,
    /// Node at the given depth. Two children precede on the stack.
    N(u8),
}

/// Ordered flat consistency proof.
pub type ConsistencyProof = Vec<ProofOp>;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Insert a batch without generating a proof (fast path).
///
/// Returns the actually-inserted `(key, value)` pairs (duplicates excluded).
pub fn batch_insert(
    tree: &mut SparseMerkleTree,
    batch: &[(SmtKey, Vec<u8>)],
) -> Result<Vec<(SmtKey, Vec<u8>)>, SmtError> {
    let (items, _) = run_batch(tree, batch, false)?;
    Ok(items)
}

/// Insert a batch and generate a consistency proof.
///
/// Returns `(inserted_items, proof)`.
pub fn batch_insert_with_proof(
    tree: &mut SparseMerkleTree,
    batch: &[(SmtKey, Vec<u8>)],
) -> Result<(Vec<(SmtKey, Vec<u8>)>, ConsistencyProof), SmtError> {
    run_batch(tree, batch, true)
}

// ─── Core algorithm ───────────────────────────────────────────────────────────

fn run_batch(
    tree: &mut SparseMerkleTree,
    batch: &[(SmtKey, Vec<u8>)],
    with_proof: bool,
) -> Result<(Vec<(SmtKey, Vec<u8>)>, ConsistencyProof), SmtError> {
    // Deduplicate and filter already-existing keys.
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
        let proof = if with_proof {
            let h = tree.root_hash();
            vec![ProofOp::S(h)]
        } else {
            vec![]
        };
        return Ok((vec![], proof));
    }

    // Sort by LSB-first traversal order.
    new_items.sort_by(|a, b| get_sort_key(&a.0).cmp(&get_sort_key(&b.0)));

    let mut proof = Vec::new();

    // Swap out root, run recursive algorithm, swap back.
    let old_root = tree.root.take();
    let proof_out = if with_proof {
        Some(&mut proof)
    } else {
        None
    };
    let new_root = insert_proof(old_root, &new_items, 0, new_items.len(), 0, proof_out);
    tree.root = new_root;

    Ok((new_items, proof))
}

// ─── insert_proof ─────────────────────────────────────────────────────────────

/// Recursive insertion with optional proof generation.
///
/// Operates on the slice `batch[start..end]` which is sorted by `get_sort_key`.
/// `start_bit` is the current bit position in the key.
fn insert_proof(
    node_opt: Option<Arc<Branch>>,
    batch: &[(SmtKey, Vec<u8>)],
    start: usize,
    end: usize,
    start_bit: usize,
    proof_out: Option<&mut Vec<ProofOp>>,
) -> Option<Arc<Branch>> {
    // No new items for this subtree — emit S and return unchanged.
    if start == end {
        if let Some(p) = proof_out {
            let h = node_opt.as_deref().map(|b| branch_hash(b));
            p.push(ProofOp::S(h));
        }
        return node_opt;
    }

    let Some(arc) = node_opt else {
        // Empty subtree — build a new subtree from the batch items.
        return Some(build_subtree(
            batch,
            start,
            end,
            start_bit,
            proof_out,
            &HashMap::new(),
        ));
    };

    // CoW: take ownership if sole Arc owner, else clone.
    let b = match Arc::try_unwrap(arc) {
        Ok(b) => b,
        Err(a) => (*a).clone(),
    };

    match b {
        Branch::Leaf(leaf) => {
            // Merge existing leaf into the batch and rebuild.
            let frozen: HashMap<SmtKey, [u8; 32]> =
                [(leaf.key, leaf.hash)].into_iter().collect();

            // Merge: batch items + existing leaf, sorted.
            let mut mixed: Vec<(SmtKey, Vec<u8>)> = batch[start..end].to_vec();
            mixed.push((leaf.key, leaf.value));
            mixed.sort_by(|a, b| get_sort_key(&a.0).cmp(&get_sort_key(&b.0)));

            Some(build_subtree(
                &mixed,
                0,
                mixed.len(),
                start_bit,
                proof_out,
                &frozen,
            ))
        }

        Branch::Node(node) => {
            let n_path = node.path.path_len();
            let node_prefix_matches = |key: &SmtKey| -> usize {
                first_divergence_in_prefix(&node.path, key, start_bit)
            };

            // O(1) divergence check from batch extremes.
            let mut first_div = n_path;
            let d_start = node_prefix_matches(&batch[start].0);
            if d_start < first_div {
                first_div = d_start;
            }
            let d_end = node_prefix_matches(&batch[end - 1].0);
            if d_end < first_div {
                first_div = d_end;
            }

            if first_div < n_path {
                return Some(node_split_proof(
                    node, batch, start, end, start_bit, first_div, proof_out,
                ));
            }

            // Full prefix match — descend into children.
            let split = start_bit + n_path;

            // Binary search for the partition point.
            let mid = partition_point(batch, start, end, split);

            match proof_out {
                None => {
                    let new_left =
                        insert_proof(Some(node.left), batch, start, mid, split + 1, None);
                    let new_right =
                        insert_proof(Some(node.right), batch, mid, end, split + 1, None);
                    Some(make_node(
                        node.path,
                        new_left.expect("left child"),
                        new_right.expect("right child"),
                        split as u8,
                    ))
                }
                Some(p) => {
                    let mut left_proof = Vec::new();
                    let mut right_proof = Vec::new();
                    let new_left = insert_proof(
                        Some(node.left),
                        batch,
                        start,
                        mid,
                        split + 1,
                        Some(&mut left_proof),
                    );
                    let new_right = insert_proof(
                        Some(node.right),
                        batch,
                        mid,
                        end,
                        split + 1,
                        Some(&mut right_proof),
                    );
                    p.extend(left_proof);
                    p.extend(right_proof);
                    p.push(ProofOp::N(split as u8));
                    Some(make_node(
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

/// Build a fresh subtree from sorted batch items.
///
/// `frozen` maps keys of pre-existing leaves to their old hashes (for S opcodes).
fn build_subtree(
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
                p.push(ProofOp::S(Some(*old_hash)));
            } else {
                p.push(ProofOp::L);
            }
        }
        return make_leaf(*k, v.clone());
    }

    // Find split point: first diverging bit among the batch items.
    let xor = xor_keys(&batch[start].0, &batch[end - 1].0);
    let split = first_set_bit_from(&xor, start_bit);

    // Binary search for partition.
    let mid = partition_point(batch, start, end, split);

    debug_assert!(mid > start && mid < end, "trivial partition at split={split} start={start} mid={mid} end={end}");

    let n_common = split - start_bit;
    let cp = CompressedPath::from_key_range(&batch[start].0, start_bit, n_common);

    match proof_out {
        None => {
            let ln = build_subtree(batch, start, mid, split + 1, None, frozen);
            let rn = build_subtree(batch, mid, end, split + 1, None, frozen);
            make_node(cp, ln, rn, split as u8)
        }
        Some(p) => {
            let mut lp = Vec::new();
            let mut rp = Vec::new();
            let ln = build_subtree(batch, start, mid, split + 1, Some(&mut lp), frozen);
            let rn = build_subtree(batch, mid, end, split + 1, Some(&mut rp), frozen);
            p.extend(lp);
            p.extend(rp);
            p.push(ProofOp::N(split as u8));
            make_node(cp, ln, rn, split as u8)
        }
    }
}

// ─── node_split_proof ────────────────────────────────────────────────────────

/// Split a node when batch items diverge within its common prefix.
fn node_split_proof(
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
    let old_dir = node.path.bit_at(n_common); // which side old node goes

    // Shorten the old node's path.
    let remaining = n_path - n_common - 1;
    node.path =
        CompressedPath::from_key_range_with_path_bits(&node.path, n_common + 1, remaining);
    node.hash = None;
    // Recompute hash for shortened node.
    let lh = branch_hash(&node.left);
    let rh = branch_hash(&node.right);
    node.hash = Some(hash_node(&lh, &rh, node.depth));

    let new_cp = CompressedPath::from_key_range(&batch[start].0, start_bit, n_common);

    // Binary search for partition at new_split.
    let mid = partition_point(batch, start, end, new_split);

    let old_node: Option<Arc<Branch>> = Some(Arc::new(Branch::Node(node)));

    match proof_out {
        None => {
            let (new_left, new_right) = if old_dir == 0 {
                let nl = insert_proof(old_node, batch, start, mid, new_split + 1, None);
                let nr = insert_proof(None, batch, mid, end, new_split + 1, None);
                (nl, nr)
            } else {
                let nl = insert_proof(None, batch, start, mid, new_split + 1, None);
                let nr = insert_proof(old_node, batch, mid, end, new_split + 1, None);
                (nl, nr)
            };
            make_node(
                new_cp,
                new_left.expect("left child"),
                new_right.expect("right child"),
                new_split as u8,
            )
        }
        Some(p) => {
            let mut lp = Vec::new();
            let mut rp = Vec::new();
            let (new_left, new_right) = if old_dir == 0 {
                let nl = insert_proof(old_node, batch, start, mid, new_split + 1, Some(&mut lp));
                let nr = insert_proof(None, batch, mid, end, new_split + 1, Some(&mut rp));
                (nl, nr)
            } else {
                let nl = insert_proof(None, batch, start, mid, new_split + 1, Some(&mut lp));
                let nr = insert_proof(old_node, batch, mid, end, new_split + 1, Some(&mut rp));
                (nl, nr)
            };
            p.extend(lp);
            p.extend(rp);
            p.push(ProofOp::N(new_split as u8));
            make_node(
                new_cp,
                new_left.expect("left child"),
                new_right.expect("right child"),
                new_split as u8,
            )
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// XOR two 32-byte keys.
#[inline]
fn xor_keys(a: &SmtKey, b: &SmtKey) -> SmtKey {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Find the first set bit >= `start_bit` in a 256-bit key (LSB-first).
fn first_set_bit_from(key: &SmtKey, start_bit: usize) -> usize {
    let byte_idx = start_bit / 8;
    let bit_off = start_bit % 8;

    // Check the partial first byte.
    if byte_idx < 32 {
        let masked = key[byte_idx] >> bit_off;
        if masked != 0 {
            return start_bit + masked.trailing_zeros() as usize;
        }
    }

    // Check remaining bytes.
    for i in (byte_idx + 1)..32 {
        if key[i] != 0 {
            return i * 8 + key[i].trailing_zeros() as usize;
        }
    }

    KEY_BITS // should not happen for distinct keys
}

/// Binary search for the partition point: first index in `batch[start..end]`
/// where the key has bit 1 at position `split`.
fn partition_point(batch: &[(SmtKey, Vec<u8>)], start: usize, end: usize, split: usize) -> usize {
    let mut lo = start;
    let mut hi = end;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if key_bit_at(&batch[mid].0, split) == 1 {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

/// Check how many bits of a `CompressedPath` match the key starting at
/// `start_bit`. Returns the number of matching bits (0..=path.path_len()).
fn first_divergence_in_prefix(
    path: &CompressedPath,
    key: &SmtKey,
    start_bit: usize,
) -> usize {
    let n = path.path_len();
    for i in 0..n {
        if path.bit_at(i) != key_bit_at(key, start_bit + i) {
            return i;
        }
    }
    n
}

// ─── verify_consistency ──────────────────────────────────────────────────────

/// Stack-machine verifier for post-order consistency proofs.
///
/// Verifies that `proof` witnesses insertion of `batch` into a tree with
/// root hash `old_root`, yielding root hash `new_root`.
pub fn verify_consistency(
    proof: &ConsistencyProof,
    old_root: Option<[u8; 32]>,
    new_root: Option<[u8; 32]>,
    batch: &[(SmtKey, Vec<u8>)],
) -> bool {
    if batch.is_empty() {
        return old_root == new_root;
    }

    // Sort batch by LSB-first traversal order.
    let mut sorted_batch: Vec<(SmtKey, Vec<u8>)> = batch.to_vec();
    sorted_batch.sort_by(|a, b| get_sort_key(&a.0).cmp(&get_sort_key(&b.0)));

    let mut stack: Vec<(Option<[u8; 32]>, Option<[u8; 32]>)> = Vec::new();
    let mut pi = 0usize; // proof index
    let mut bi = 0usize; // batch index

    while pi < proof.len() {
        match &proof[pi] {
            ProofOp::S(h) => {
                pi += 1;
                stack.push((*h, *h));
            }
            ProofOp::L => {
                pi += 1;
                if bi >= sorted_batch.len() {
                    return false;
                }
                let (k, v) = &sorted_batch[bi];
                bi += 1;
                stack.push((None, Some(hash_leaf(k, v))));
            }
            ProofOp::N(depth) => {
                pi += 1;
                let depth = *depth;
                if stack.len() < 2 {
                    return false;
                }
                let (rh0, rh1) = stack.pop().unwrap();
                let (lh0, lh1) = stack.pop().unwrap();

                // Resolve pre-state hash.
                let h0 = match (lh0, rh0) {
                    (None, None) => None,
                    (None, rh) => rh,
                    (lh, None) => lh,
                    (Some(l), Some(r)) => Some(hash_node(&l, &r, depth)),
                };

                // Compute post-state hash.
                let h1 = match (lh1, rh1) {
                    (Some(l), Some(r)) => Some(hash_node(&l, &r, depth)),
                    _ => return false, // post-state must have both children
                };

                stack.push((h0, h1));
            }
        }
    }

    pi == proof.len()
        && bi == sorted_batch.len()
        && stack.len() == 1
        && stack[0].0 == old_root
        && stack[0].1 == new_root
}

// ─── CBOR encoding ───────────────────────────────────────────────────────────

/// Encode a `ConsistencyProof` as CBOR bytes for the BFT Core `zk_proof` field.
///
/// Wire format: CBOR array of opcodes, each opcode is a small array:
/// - `S(h)`: `[0, h_bytes | null]`
/// - `L`:    `[1]`
/// - `N(d)`: `[2, d]`
pub fn consistency_proof_to_cbor(proof: &ConsistencyProof) -> Vec<u8> {
    let mut out = cbor_array(proof.len());
    for op in proof {
        match op {
            ProofOp::S(h) => {
                out.extend_from_slice(&cbor_array(2));
                out.push(0x00); // tag 0
                match h {
                    Some(hash) => {
                        out.push(0x58); // bytes, 1-byte length
                        out.push(32);
                        out.extend_from_slice(hash);
                    }
                    None => {
                        out.push(0xf6); // null
                    }
                }
            }
            ProofOp::L => {
                out.extend_from_slice(&cbor_array(1));
                out.push(0x01); // tag 1
            }
            ProofOp::N(depth) => {
                out.extend_from_slice(&cbor_array(2));
                out.push(0x02); // tag 2
                out.push(0x18); // uint8
                out.push(*depth);
            }
        }
    }
    out
}

/// Hand-assembled CBOR array header.
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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::SparseMerkleTree;

    fn make_key(byte: u8) -> SmtKey {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    fn check(tree: &mut SparseMerkleTree, batch: Vec<(SmtKey, Vec<u8>)>, label: &str) {
        let old = tree.root_hash();
        let (items, proof) = batch_insert_with_proof(tree, &batch).unwrap();
        let new = tree.root_hash();
        assert!(
            verify_consistency(&proof, old, new, &items),
            "{label}: consistency verification failed"
        );
    }

    #[test]
    fn root_matches_sequential_add_leaf() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let pairs: Vec<_> = (1u8..=8)
            .map(|i| (make_key(i), vec![i; 32]))
            .collect();
        for (k, v) in &pairs {
            t1.add_leaf(*k, v.clone()).unwrap();
        }
        batch_insert(&mut t2, &pairs).unwrap();
        assert_eq!(
            t1.root_hash(),
            t2.root_hash(),
            "batch_insert must produce same root as sequential add_leaf"
        );
    }

    #[test]
    fn single_leaf_consistency() {
        let mut tree = SparseMerkleTree::new();
        check(
            &mut tree,
            vec![(make_key(1), vec![0xab; 32])],
            "single",
        );
    }

    #[test]
    fn two_leaf_consistency() {
        let mut tree = SparseMerkleTree::new();
        check(
            &mut tree,
            vec![
                (make_key(1), vec![1; 32]),
                (make_key(2), vec![2; 32]),
            ],
            "two",
        );
    }

    #[test]
    fn border_leaf_consistency() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(1), vec![1; 32]).unwrap();
        check(&mut tree, vec![(make_key(3), vec![3; 32])], "border_leaf");
    }

    #[test]
    fn duplicate_skipped() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(5), vec![5; 32]).unwrap();
        let old = tree.root_hash();
        let (items, proof) = batch_insert_with_proof(
            &mut tree,
            &[(make_key(5), vec![99; 32]), (make_key(7), vec![7; 32])],
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        let new = tree.root_hash();
        assert!(verify_consistency(&proof, old, new, &items));
    }

    #[test]
    fn multi_round_consistency() {
        let mut tree = SparseMerkleTree::new();
        for r in 0u8..5 {
            let b: Vec<_> = (0u8..10)
                .map(|i| (make_key(r * 10 + i), vec![r * 10 + i; 32]))
                .collect();
            check(&mut tree, b, &format!("round {r}"));
        }
    }

    #[test]
    fn fast_batch_insert_matches_with_proof() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let pairs: Vec<_> = (1u8..=16)
            .map(|i| (make_key(i), vec![i; 32]))
            .collect();
        batch_insert(&mut t1, &pairs).unwrap();
        batch_insert_with_proof(&mut t2, &pairs).unwrap();
        assert_eq!(t1.root_hash(), t2.root_hash());
    }

    #[test]
    fn proof_cbor_non_empty() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(1), vec![1; 32]).unwrap();
        let batch: Vec<_> = (2u8..=6)
            .map(|i| (make_key(i), vec![i; 32]))
            .collect();
        let old = tree.root_hash();
        let (items, proof) = batch_insert_with_proof(&mut tree, &batch).unwrap();
        let new = tree.root_hash();

        assert!(verify_consistency(&proof, old, new, &items));

        let cbor = consistency_proof_to_cbor(&proof);
        assert!(!cbor.is_empty());
        assert_eq!(cbor[0] & 0xe0, 0x80, "expected CBOR array header");
    }

    #[test]
    fn empty_batch_returns_unchanged() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(1), vec![1; 32]).unwrap();
        let old = tree.root_hash();
        let (items, proof) = batch_insert_with_proof(&mut tree, &[]).unwrap();
        assert!(items.is_empty());
        let new = tree.root_hash();
        assert_eq!(old, new);
        assert!(verify_consistency(&proof, old, new, &items));
    }

    #[test]
    fn insert_into_empty_tree() {
        let mut tree = SparseMerkleTree::new();
        let old = tree.root_hash();
        assert!(old.is_none());
        let batch: Vec<_> = (1u8..=3)
            .map(|i| (make_key(i), vec![i; 32]))
            .collect();
        let (items, proof) = batch_insert_with_proof(&mut tree, &batch).unwrap();
        let new = tree.root_hash();
        assert!(verify_consistency(&proof, old, new, &items));
    }

    /// Simple LCG to generate pseudo-random keys without external deps.
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
