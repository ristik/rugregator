//! Consistency proofs for the Sparse Merkle Tree.
//!
//! Two public entry-points share a single tree-traversal algorithm:
//!
//! - [`batch_insert`]            — fast insert, no proof overhead.
//! - [`batch_insert_with_proof`] — insert + generate consistency proof.
//!
//! ## Path-encoding note (Go compatibility)
//!
//! The Go aggregator stores every node's path as the *full remaining prefix*
//! including the routing bit that directed keys into this subtree.  Concretely,
//! after a parent node consumes `n_common` data bits at depth `start_bit`, its
//! children start at `start_bit_child = start_bit + n_common` — the routing bit
//! at that position is **not** pre-consumed; it becomes the first visible bit
//! of the child subtree.  This differs from the Python reference (`ndsmt3.py`)
//! which advances past the routing bit (`start_bit_child = split + 1`).
//!
//! ## Proof opcodes
//!
//! The proof is a flat pre-order sequence of [`ProofOp`] values:
//!
//! | Opcode | Meaning |
//! |--------|---------|
//! | `S(hash)` | Unchanged subtree carrying its raw hash (None = empty). |
//! | `N(cp)` | New junction node with common-prefix path `cp`. |
//! | `L(key)` | New leaf inserted from the batch. |
//! | `Bl{old_path,key,value}` | Border leaf: existing leaf repositioned. |
//! | `Bns{old_path,new_path,lh,rh}` | Border node shortened. |
//!
//! Verification replays the proof computing both the pre- and post-insertion
//! root hashes and checks them against the known values.

use std::collections::HashMap;

use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::hash::{hash_leaf, hash_node};
use crate::path::{bit_at, path_len, rsh, SmtPath};
use crate::tree::{calc_branch_hash, calc_node_hash, SmtError};
use crate::types::{leaf, Branch, NodeBranch};

// ─── Proof opcodes ────────────────────────────────────────────────────────────

/// One element of the flat consistency-proof stream.
#[derive(Debug, Clone)]
pub enum ProofOp {
    /// Unchanged subtree; raw 32-byte SHA-256 hash (None = empty subtree).
    S(Option<[u8; 32]>),
    /// **New** junction node created by this batch (didn't exist before).
    /// Pre-insertion hash uses the path-compression pass-through rule.
    N(SmtPath),
    /// **Existing** node being traversed (was already in the tree).
    /// Pre-insertion hash always uses `hash_node(cp, lh0, rh0)`.
    Nx(SmtPath),
    /// New leaf; full sentinel-encoded original key.
    L(SmtPath),
    /// Border leaf — existing leaf repositioned by the batch.
    Bl {
        old_path: SmtPath,
        key:      SmtPath,
        value:    Vec<u8>,
    },
    /// Border node shortened — existing node whose common prefix was truncated.
    Bns {
        old_path: SmtPath,
        new_path: SmtPath,
        lh: Option<[u8; 32]>,
        rh: Option<[u8; 32]>,
    },
}

/// Ordered flat consistency proof — a sequence of [`ProofOp`] values.
pub type ConsistencyProof = Vec<ProofOp>;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Insert a batch without generating a proof (fast path).
///
/// Duplicates within the batch and keys already present in the tree are
/// silently skipped.  Returns the sorted list of actually inserted pairs.
pub fn batch_insert(
    tree:  &mut super::tree::SparseMerkleTree,
    batch: &[(SmtPath, Vec<u8>)],
) -> Result<Vec<(SmtPath, Vec<u8>)>, SmtError> {
    let (items, _) = run_batch(tree, batch, false)?;
    Ok(items)
}

/// Insert a batch and generate a consistency proof.
///
/// Returns `(inserted_items, proof)`.
pub fn batch_insert_with_proof(
    tree:  &mut super::tree::SparseMerkleTree,
    batch: &[(SmtPath, Vec<u8>)],
) -> Result<(Vec<(SmtPath, Vec<u8>)>, ConsistencyProof), SmtError> {
    run_batch(tree, batch, true)
}

// ─── Core algorithm ───────────────────────────────────────────────────────────

fn run_batch(
    tree:         &mut super::tree::SparseMerkleTree,
    batch:        &[(SmtPath, Vec<u8>)],
    with_proof:   bool,
) -> Result<(Vec<(SmtPath, Vec<u8>)>, ConsistencyProof), SmtError> {
    let _depth = tree.key_length;

    // Deduplicate batch and filter out keys already in the tree.
    let mut seen: HashMap<SmtPath, ()> = HashMap::new();
    let mut new_items: Vec<(SmtPath, Vec<u8>)> = Vec::new();
    for (k, v) in batch {
        if seen.contains_key(k) { continue; }
        seen.insert(k.clone(), ());
        match tree.get_leaf(k) {
            Ok(_)                     => continue,
            Err(SmtError::LeafNotFound) => {}
            Err(_)                    => {}
        }
        new_items.push((k.clone(), v.clone()));
    }

    if new_items.is_empty() {
        let proof = if with_proof {
            let h = calc_node_hash(&mut tree.root);
            vec![ProofOp::S(Some(h))]
        } else {
            vec![]
        };
        return Ok((vec![], proof));
    }

    // Sort by key (BigUint numeric order; sentinel at position key_length is
    // identical for all keys, so this equals sorting by raw key bits).
    new_items.sort_by(|a, b| a.0.cmp(&b.0));

    let mut proof = Vec::new();

    // Swap out the root, run the recursive algorithm, swap back.
    let old_root = std::mem::replace(
        &mut tree.root,
        NodeBranch::new_root(BigUint::one(), None, None),
    );
    let root_branch = Box::new(Branch::Node(old_root));
    let proof_out = if with_proof { Some(&mut proof) } else { None };
    let new_root_branch = insert_node(
        Some(root_branch), &new_items, 0, proof_out,
    );

    match *new_root_branch.expect("root must not disappear") {
        Branch::Node(n) => tree.root = n,
        Branch::Leaf(_) => panic!("tree root became a leaf — logic error"),
    }

    Ok((new_items, proof))
}

// ─── insert_node ─────────────────────────────────────────────────────────────

/// Recursive proof-generating insertion.
///
/// `proof_out = None` → fast path (no opcodes emitted).
fn insert_node(
    node:      Option<Box<Branch>>,
    batch:     &[(SmtPath, Vec<u8>)],
    start_bit: usize,
    proof_out: Option<&mut Vec<ProofOp>>,
) -> Option<Box<Branch>> {
    if batch.is_empty() {
        if let Some(p) = proof_out {
            let h = node.as_deref().map(|b| branch_hash_immut(b));
            p.push(ProofOp::S(h));
        }
        return node;
    }

    let Some(b) = node else {
        return build_subtree(batch, start_bit, proof_out, None);
    };

    match *b {
        // ── Existing leaf ─────────────────────────────────────────────────────
        Branch::Leaf(l) => {
            let filtered: Vec<_> = batch
                .iter()
                .filter(|(k, _)| k != &l.original_path)
                .cloned()
                .collect();

            if filtered.is_empty() {
                // All batch keys were duplicates of this leaf.
                if let Some(p) = proof_out {
                    let h = hash_leaf(&l.path, &l.value);
                    p.push(ProofOp::S(Some(h)));
                }
                return Some(Box::new(Branch::Leaf(l)));
            }

            let old_path = l.path.clone();
            let border: Option<HashMap<SmtPath, SmtPath>> =
                proof_out.as_ref().map(|_| {
                    [(l.original_path.clone(), old_path)].into_iter().collect()
                });

            let mut all_items: Vec<(SmtPath, Vec<u8>)> =
                std::iter::once((l.original_path.clone(), l.value.clone()))
                    .chain(filtered)
                    .collect();
            all_items.sort_by(|a, b| a.0.cmp(&b.0));

            build_subtree(&all_items, start_bit, proof_out, border.as_ref())
        }

        // ── Existing node ─────────────────────────────────────────────────────
        Branch::Node(mut n) => {
            let n_path       = path_len(&n.path);
            let node_prefix: BigUint =
                &n.path & ((BigUint::one() << n_path) - BigUint::one());

            // First bit where any batch key diverges from the node's prefix.
            let mut first_div = n_path;
            for (k, _) in batch {
                let item_pfx: BigUint =
                    (k >> start_bit) & ((BigUint::one() << n_path) - BigUint::one());
                let xor = &item_pfx ^ &node_prefix;
                if !xor.is_zero() {
                    let low = xor.trailing_zeros().unwrap() as usize;
                    if low < first_div { first_div = low; }
                }
            }

            if first_div < n_path {
                return Some(node_split(n, batch, start_bit, first_div, proof_out));
            }

            // No split — recurse into existing children.
            // Go convention: children start at `split` (routing bit not pre-consumed).
            let split       = start_bit + n_path;
            let batch_left:  Vec<_> = batch.iter().filter(|(k,_)| bit_at(k, split) == 0).cloned().collect();
            let batch_right: Vec<_> = batch.iter().filter(|(k,_)| bit_at(k, split) == 1).cloned().collect();

            n.hash_cache = None;

            match proof_out {
                None => {
                    let old_left  = n.left.take();
                    n.left  = insert_node(old_left,  &batch_left,  split, None);
                    let old_right = n.right.take();
                    n.right = insert_node(old_right, &batch_right, split, None);
                }
                Some(p) => {
                    // Nx = existing node; verifier uses hash_node (no pass-through).
                    p.push(ProofOp::Nx(n.path.clone()));
                    let mut left_proof  = Vec::new();
                    let mut right_proof = Vec::new();
                    let old_left  = n.left.take();
                    let old_right = n.right.take();
                    n.left  = insert_node(old_left,  &batch_left,  split, Some(&mut left_proof));
                    n.right = insert_node(old_right, &batch_right, split, Some(&mut right_proof));
                    p.extend(left_proof);
                    p.extend(right_proof);
                }
            }

            Some(Box::new(Branch::Node(n)))
        }
    }
}

// ─── build_subtree ────────────────────────────────────────────────────────────

/// Build a fresh subtree from an all-new batch, emitting proof opcodes.
/// `border_old_paths`: for border leaves, maps original_key → old_remaining_path.
fn build_subtree(
    batch:            &[(SmtPath, Vec<u8>)],
    start_bit:        usize,
    proof_out:        Option<&mut Vec<ProofOp>>,
    border_old_paths: Option<&HashMap<SmtPath, SmtPath>>,
) -> Option<Box<Branch>> {
    if batch.is_empty() {
        if let Some(p) = proof_out { p.push(ProofOp::S(None)); }
        return None;
    }

    if batch.len() == 1 {
        let (k, v) = &batch[0];
        let new_path = rsh(k, start_bit);
        let new_leaf = leaf(new_path, v.clone(), k.clone());
        if let Some(p) = proof_out {
            match border_old_paths.and_then(|m| m.get(k)) {
                None           => p.push(ProofOp::L(k.clone())),
                Some(old_path) => p.push(ProofOp::Bl {
                    old_path: old_path.clone(),
                    key:      k.clone(),
                    value:    v.clone(),
                }),
            }
        }
        return Some(new_leaf);
    }

    let keys: Vec<_> = batch.iter().map(|(k, _)| k.clone()).collect();
    let split = first_split(&keys, start_bit)
        .expect("multiple distinct keys must diverge somewhere");

    let n_common = split - start_bit;
    let cbits: BigUint = (&keys[0] >> start_bit)
        & ((BigUint::one() << n_common) - BigUint::one());
    let cp = (BigUint::one() << n_common) | cbits;

    let batch_left:  Vec<_> = batch.iter().filter(|(k,_)| bit_at(k, split) == 0).cloned().collect();
    let batch_right: Vec<_> = batch.iter().filter(|(k,_)| bit_at(k, split) == 1).cloned().collect();

    // Go convention: children start at `split` (not `split + 1`).
    match proof_out {
        None => {
            let ln = build_subtree(&batch_left,  split, None, border_old_paths);
            let rn = build_subtree(&batch_right, split, None, border_old_paths);
            Some(Box::new(Branch::Node(NodeBranch::new(cp, ln, rn))))
        }
        Some(p) => {
            p.push(ProofOp::N(cp.clone()));
            let mut lp = Vec::new();
            let mut rp = Vec::new();
            let ln = build_subtree(&batch_left,  split, Some(&mut lp), border_old_paths);
            let rn = build_subtree(&batch_right, split, Some(&mut rp), border_old_paths);
            p.extend(lp);
            p.extend(rp);
            Some(Box::new(Branch::Node(NodeBranch::new(cp, ln, rn))))
        }
    }
}

// ─── node_split ───────────────────────────────────────────────────────────────

/// Handle BNS: a batch key diverges inside a node's common prefix.
fn node_split(
    mut node:  NodeBranch,
    batch:     &[(SmtPath, Vec<u8>)],
    start_bit: usize,
    first_div: usize,
    proof_out: Option<&mut Vec<ProofOp>>,
) -> Box<Branch> {
    let n_path       = path_len(&node.path);
    let node_prefix: BigUint =
        &node.path & ((BigUint::one() << n_path) - BigUint::one());

    let n_common    = first_div;
    let common_bits: BigUint =
        &node_prefix & ((BigUint::one() << n_common) - BigUint::one());
    let new_cp      = (BigUint::one() << n_common) | common_bits;
    let new_split   = start_bit + n_common;

    // Routing direction of the old node at the split.
    let old_dir = ((node_prefix.clone() >> n_common) & BigUint::one()) == BigUint::one();

    let old_path = node.path.clone();
    let lh: Option<[u8; 32]> = node.left.as_deref_mut().map(calc_branch_hash);
    let rh: Option<[u8; 32]> = node.right.as_deref_mut().map(calc_branch_hash);

    let new_path: SmtPath = {
        let s = node.path.clone() >> n_common;
        if s.is_zero() { BigUint::one() } else { s }
    };
    node.path      = new_path.clone();
    node.hash_cache = None;

    let batch_left:  Vec<_> = batch.iter().filter(|(k,_)| bit_at(k, new_split) == 0).cloned().collect();
    let batch_right: Vec<_> = batch.iter().filter(|(k,_)| bit_at(k, new_split) == 1).cloned().collect();

    match proof_out {
        None => {
            let (new_left, new_right) = if !old_dir {
                let nl = insert_node(Some(Box::new(Branch::Node(node))), &batch_left,  new_split, None);
                let nr = insert_node(None,                                &batch_right, new_split, None);
                (nl, nr)
            } else {
                let nl = insert_node(None,                                &batch_left,  new_split, None);
                let nr = insert_node(Some(Box::new(Branch::Node(node))), &batch_right, new_split, None);
                (nl, nr)
            };
            Box::new(Branch::Node(NodeBranch::new(new_cp, new_left, new_right)))
        }
        Some(p) => {
            p.push(ProofOp::N(new_cp.clone()));
            let bns = ProofOp::Bns { old_path, new_path, lh, rh };

            let mut lp = Vec::new();
            let mut rp = Vec::new();

            let (new_left, new_right) = if !old_dir {
                lp.push(bns);
                let nl = insert_node(Some(Box::new(Branch::Node(node))), &batch_left,  new_split, Some(&mut lp));
                let nr = insert_node(None,                                &batch_right, new_split, Some(&mut rp));
                (nl, nr)
            } else {
                rp.push(bns);
                let nl = insert_node(None,                                &batch_left,  new_split, Some(&mut lp));
                let nr = insert_node(Some(Box::new(Branch::Node(node))), &batch_right, new_split, Some(&mut rp));
                (nl, nr)
            };
            p.extend(lp);
            p.extend(rp);
            Box::new(Branch::Node(NodeBranch::new(new_cp, new_left, new_right)))
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn branch_hash_immut(b: &Branch) -> [u8; 32] {
    let mut c = b.clone();
    calc_branch_hash(&mut c)
}

/// First bit position ≥ `start_bit` where adjacent sorted keys diverge.
fn first_split(keys: &[SmtPath], start_bit: usize) -> Option<usize> {
    let mut result: Option<usize> = None;
    for i in 0..keys.len().saturating_sub(1) {
        let xor = &keys[i] ^ &keys[i + 1];
        if !xor.is_zero() {
            let shifted = &xor >> start_bit;
            if !shifted.is_zero() {
                let pos = start_bit + shifted.trailing_zeros().unwrap() as usize;
                result = Some(result.map_or(pos, |r| r.min(pos)));
            }
        }
    }
    result
}

// ─── synchronized_proof_eval ─────────────────────────────────────────────────

/// One-pass proof replay computing `(r0, r1)` — pre- and post-insertion hashes.
///
/// `batch_dict` is consumed as leaves are matched; it must be empty after
/// a valid proof is fully consumed.
pub fn synchronized_proof_eval(
    proof:      &[ProofOp],
    depth:      usize,
    batch_dict: &mut HashMap<SmtPath, Vec<u8>>,
    pos:        &mut usize,
    start_bit:  usize,
) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
    let _ = depth; // kept in signature for API clarity
    if *pos >= proof.len() { return (None, None); }

    match proof[*pos].clone() {
        ProofOp::S(h) => {
            *pos += 1;
            (h, h)
        }

        ProofOp::N(cp) => {
            // New junction created by this batch.
            // Pre-insertion: path-compression pass-through rule — the junction
            // didn't exist before, so the old "hash" is the surviving child's hash.
            *pos += 1;
            let n_common = path_len(&cp);
            let split = start_bit + n_common;
            let (lh0, lh1) = synchronized_proof_eval(proof, depth, batch_dict, pos, split);
            let (rh0, rh1) = synchronized_proof_eval(proof, depth, batch_dict, pos, split);

            let h0 = match (lh0, rh0) {
                (None, None)         => None,
                (None, rh)           => rh,
                (lh,   None)         => lh,
                (Some(lh), Some(rh)) => Some(hash_node(&cp, Some(&lh), Some(&rh))),
            };
            let h1 = hash_node(&cp, lh1.as_ref(), rh1.as_ref());
            (h0, Some(h1))
        }

        ProofOp::Nx(cp) => {
            // Existing node traversed by the batch.
            // Pre-insertion hash always uses hash_node (no pass-through), because
            // the Go tree never omits hash_node even for single-child or empty nodes.
            *pos += 1;
            let n_common = path_len(&cp);
            let split = start_bit + n_common;
            let (lh0, lh1) = synchronized_proof_eval(proof, depth, batch_dict, pos, split);
            let (rh0, rh1) = synchronized_proof_eval(proof, depth, batch_dict, pos, split);

            let h0 = Some(hash_node(&cp, lh0.as_ref(), rh0.as_ref()));
            let h1 = hash_node(&cp, lh1.as_ref(), rh1.as_ref());
            (h0, Some(h1))
        }

        ProofOp::L(k) => {
            *pos += 1;
            let v = batch_dict.remove(&k)
                .expect("proof references key not in batch");
            let new_path = rsh(&k, start_bit);
            (None, Some(hash_leaf(&new_path, &v)))
        }

        ProofOp::Bl { old_path, key, value } => {
            *pos += 1;
            let new_path = rsh(&key, start_bit);
            let h0 = hash_leaf(&old_path, &value);
            let h1 = hash_leaf(&new_path, &value);
            (Some(h0), Some(h1))
        }

        ProofOp::Bns { old_path, new_path, lh, rh } => {
            *pos += 1;
            let (inner0, inner1) =
                synchronized_proof_eval(proof, depth, batch_dict, pos, start_bit);
            let expected = hash_node(&new_path, lh.as_ref(), rh.as_ref());
            assert_eq!(inner0, Some(expected), "BNS: inner0 mismatch — forgery?");
            let h0 = hash_node(&old_path, lh.as_ref(), rh.as_ref());
            (Some(h0), inner1)
        }
    }
}

// ─── verify_consistency ──────────────────────────────────────────────────────

/// Verify that `proof` witnesses insertion of `batch` into a tree with raw
/// root hash `old_root`, yielding a tree with raw root hash `new_root`.
///
/// Both root hashes are raw 32-byte SHA-256 digests (not 34-byte imprints).
/// `batch` must be the sorted, deduplicated list returned by
/// [`batch_insert_with_proof`].
pub fn verify_consistency(
    proof:    &ConsistencyProof,
    old_root: Option<[u8; 32]>,
    new_root: [u8; 32],
    batch:    &[(SmtPath, Vec<u8>)],
    depth:    usize,
) -> bool {
    if batch.is_empty() {
        return old_root == Some(new_root);
    }
    let mut dict: HashMap<SmtPath, Vec<u8>> = batch.iter().cloned().collect();
    let mut pos = 0usize;
    let (r0, r1) = synchronized_proof_eval(proof, depth, &mut dict, &mut pos, 0);
    pos == proof.len() && dict.is_empty() && r0 == old_root && r1 == Some(new_root)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::*;
    use crate::path::state_id_to_smt_path;
    use crate::tree::{calc_node_hash, SparseMerkleTree, KEY_LENGTH};

    fn pid(byte: u8) -> SmtPath {
        let mut id = [0u8; 32];
        id[31] = byte;
        state_id_to_smt_path(&id)
    }

    fn raw_root(tree: &mut SparseMerkleTree) -> [u8; 32] {
        calc_node_hash(&mut tree.root)
    }

    fn check(tree: &mut SparseMerkleTree, batch: Vec<(SmtPath, Vec<u8>)>, label: &str) {
        let old = raw_root(tree);
        let (items, proof) = batch_insert_with_proof(tree, &batch).unwrap();
        let new = raw_root(tree);
        assert!(
            verify_consistency(&proof, Some(old), new, &items, KEY_LENGTH),
            "{label}: consistency verification failed"
        );
    }

    #[test]
    fn root_matches_sequential_add_leaf() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let pairs: Vec<_> = (1u8..=8).map(|i| (pid(i), vec![i; 34])).collect();
        for (k, v) in &pairs { t1.add_leaf(k.clone(), v.clone()).unwrap(); }
        batch_insert_with_proof(&mut t2, &pairs).unwrap();
        assert_eq!(
            t1.root_hash_imprint(), t2.root_hash_imprint(),
            "batch_insert must produce same root as sequential add_leaf"
        );
    }

    #[test]
    fn single_leaf_consistency() {
        let mut tree = SparseMerkleTree::new();
        check(&mut tree, vec![(pid(1), vec![0xab; 34])], "single");
    }

    #[test]
    fn two_leaf_consistency() {
        let mut tree = SparseMerkleTree::new();
        check(&mut tree, vec![(pid(1), vec![1;34]), (pid(2), vec![2;34])], "two");
    }

    #[test]
    fn border_leaf_consistency() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(pid(1), vec![1;34]).unwrap();
        check(&mut tree, vec![(pid(3), vec![3;34])], "border_leaf");
    }

    #[test]
    fn duplicate_skipped() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(pid(5), vec![5;34]).unwrap();
        let (items, proof) = batch_insert_with_proof(
            &mut tree, &[(pid(5), vec![99;34]), (pid(7), vec![7;34])],
        ).unwrap();
        assert_eq!(items.len(), 1);
        let new = raw_root(&mut tree);
        let old_tree_before = {
            let mut t = SparseMerkleTree::new();
            t.add_leaf(pid(5), vec![5;34]).unwrap();
            raw_root(&mut t)
        };
        assert!(verify_consistency(&proof, Some(old_tree_before), new, &items, KEY_LENGTH));
    }

    #[test]
    fn multi_round_consistency() {
        let mut tree = SparseMerkleTree::new();
        for r in 0u8..5 {
            let b: Vec<_> = (0u8..10).map(|i| (pid(r*10+i), vec![r*10+i;34])).collect();
            check(&mut tree, b, &format!("round {r}"));
        }
    }

    #[test]
    fn fast_batch_insert_matches_with_proof() {
        let mut t1 = SparseMerkleTree::new();
        let mut t2 = SparseMerkleTree::new();
        let pairs: Vec<_> = (1u8..=16).map(|i| (pid(i), vec![i;34])).collect();
        batch_insert(&mut t1, &pairs).unwrap();
        batch_insert_with_proof(&mut t2, &pairs).unwrap();
        assert_eq!(t1.root_hash_imprint(), t2.root_hash_imprint());
    }
}
