//! Inclusion and non-inclusion proofs for the radix sparse Merkle tree.
//!
//! Both proof generators use the same key-directed walk.  An inclusion proof
//! omits the terminal because its `(key, value)` is supplied by the verifier.
//! A non-inclusion proof authenticates the terminal leaf reached by the walk;
//! a different terminal key proves that the target key is absent.
//!
//! Bitmap bit `d` is the `d`-th most-significant bit of the 32-byte bitmap.
//! Siblings are stored root-to-leaf (ascending depth), and verification consumes
//! them in reverse while folding a leaf hash back to the root.

use crate::hash::{hash_leaf, hash_node};
use crate::path::{key_bit_at, prefix_region, SmtKey};
use crate::tree::{SmtError, SparseMerkleTree};
use crate::types::{branch_hash, Branch};

const BITMAP_SIZE: usize = 32;
const HASH_SIZE: usize = 32;
const KEY_BITS: usize = 256;

// ─── Proof types ─────────────────────────────────────────────────────────────

/// An inclusion proof for a single leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Bitmap: set bits indicate junction depths on the proof path.
    pub bitmap: [u8; BITMAP_SIZE],
    /// Sibling hashes, ordered root-to-leaf (ascending junction depth).
    pub siblings: Vec<[u8; HASH_SIZE]>,
}

impl InclusionProof {
    /// Number of siblings (= population count of the bitmap).
    pub fn sibling_count(&self) -> usize {
        self.siblings.len()
    }

    /// Serialize the established inclusion-proof wire format:
    /// `bitmap[32] || sibling_0[32] || ...`.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_path(&self.bitmap, &self.siblings)
    }

    /// Deserialize the established inclusion-proof wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let (bitmap, siblings, consumed) = decode_path(data)?;
        if consumed != data.len() {
            return Err("unexpected data after inclusion siblings");
        }
        Ok(Self { bitmap, siblings })
    }
}

/// A proof that a target key is absent from a certified tree.
///
/// A non-empty proof authenticates the different terminal leaf reached by
/// key-directed descent.  The empty byte string is the distinguished proof for
/// an empty tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonInclusionProof {
    body: Option<NonInclusionBody>,
}

/// Result of asking the tree for a non-inclusion proof.
///
/// Presence is a normal, authenticated lookup outcome rather than an SMT
/// mutation error.  Keeping it explicit prevents callers from translating an
/// unrelated insertion error through several API layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonInclusionProofOutcome {
    /// The target key is present, so no non-inclusion proof exists.
    StateIncluded,
    /// The target key is absent and this proof authenticates that relation.
    Proof(NonInclusionProof),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NonInclusionBody {
    bitmap: [u8; BITMAP_SIZE],
    siblings: Vec<[u8; HASH_SIZE]>,
    terminal_key: SmtKey,
    terminal_value: Vec<u8>,
}

impl NonInclusionProof {
    fn empty() -> Self {
        Self { body: None }
    }

    fn new(path: GeneratedPath) -> Self {
        Self {
            body: Some(NonInclusionBody {
                bitmap: path.bitmap,
                siblings: path.siblings,
                terminal_key: path.terminal_key,
                terminal_value: path.terminal_value,
            }),
        }
    }

    /// Whether this is the distinguished proof for an empty tree.
    pub fn is_empty(&self) -> bool {
        self.body.is_none()
    }

    /// The authenticated terminal key, or `None` for an empty-tree proof.
    pub fn terminal_key(&self) -> Option<&SmtKey> {
        self.body.as_ref().map(|body| &body.terminal_key)
    }

    /// The authenticated terminal value, or `None` for an empty-tree proof.
    pub fn terminal_value(&self) -> Option<&[u8]> {
        self.body
            .as_ref()
            .map(|body| body.terminal_value.as_slice())
    }

    /// Number of authenticated junctions on the path.
    pub fn sibling_count(&self) -> usize {
        self.body.as_ref().map_or(0, |body| body.siblings.len())
    }

    /// Serialize as the canonical certificate bytes:
    ///
    /// `bitmap[32] || siblings[n][32] || terminal_key[32] || terminal_value`.
    ///
    /// The empty-tree proof is the empty byte string.
    pub fn to_bytes(&self) -> Vec<u8> {
        let Some(body) = &self.body else {
            return Vec::new();
        };
        let mut out = encode_path(&body.bitmap, &body.siblings);
        out.reserve(HASH_SIZE + body.terminal_value.len());
        out.extend_from_slice(&body.terminal_key);
        out.extend_from_slice(&body.terminal_value);
        out
    }

    /// Decode canonical non-inclusion certificate bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Ok(Self::empty());
        }
        let (bitmap, siblings, consumed) = decode_path(data)?;
        if data.len() < consumed + HASH_SIZE {
            return Err("too short for terminal key");
        }
        let mut terminal_key = [0u8; HASH_SIZE];
        terminal_key.copy_from_slice(&data[consumed..consumed + HASH_SIZE]);
        let terminal_value = data[consumed + HASH_SIZE..].to_vec();
        Ok(Self {
            body: Some(NonInclusionBody {
                bitmap,
                siblings,
                terminal_key,
                terminal_value,
            }),
        })
    }
}

fn encode_path(bitmap: &[u8; BITMAP_SIZE], siblings: &[[u8; HASH_SIZE]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BITMAP_SIZE + siblings.len() * HASH_SIZE);
    out.extend_from_slice(bitmap);
    for sibling in siblings {
        out.extend_from_slice(sibling);
    }
    out
}

/// Decode the bitmap and exactly the sibling count determined by its popcount.
/// Returns the number of bytes consumed, allowing a relation-specific terminal
/// to follow the shared path.
fn decode_path(
    data: &[u8],
) -> Result<([u8; BITMAP_SIZE], Vec<[u8; HASH_SIZE]>, usize), &'static str> {
    if data.len() < BITMAP_SIZE {
        return Err("too short for bitmap");
    }
    let mut bitmap = [0u8; BITMAP_SIZE];
    bitmap.copy_from_slice(&data[..BITMAP_SIZE]);
    let count = bitmap.iter().map(|b| b.count_ones()).sum::<u32>() as usize;
    let sibling_bytes = count
        .checked_mul(HASH_SIZE)
        .ok_or("sibling byte length overflow")?;
    let consumed = BITMAP_SIZE
        .checked_add(sibling_bytes)
        .ok_or("proof byte length overflow")?;
    if data.len() < consumed {
        return Err("fewer siblings than bitmap popcount");
    }
    let siblings = data[BITMAP_SIZE..consumed]
        .chunks_exact(HASH_SIZE)
        .map(|chunk| {
            let mut hash = [0u8; HASH_SIZE];
            hash.copy_from_slice(chunk);
            hash
        })
        .collect();
    Ok((bitmap, siblings, consumed))
}

#[inline]
fn bitmap_has_depth(bitmap: &[u8; BITMAP_SIZE], depth: usize) -> bool {
    bitmap[depth / 8] & (0x80 >> (depth % 8)) != 0
}

// ─── Proof generation ───────────────────────────────────────────────────────

struct GeneratedPath {
    bitmap: [u8; BITMAP_SIZE],
    siblings: Vec<[u8; HASH_SIZE]>,
    terminal_key: SmtKey,
    terminal_value: Vec<u8>,
}

impl SparseMerkleTree {
    /// Generate an inclusion proof for the leaf at `key`.
    ///
    /// Returns `Err(LeafNotFound)` if no leaf exists at that key.
    pub fn get_inclusion_proof(&self, key: &SmtKey) -> Result<InclusionProof, SmtError> {
        let path = self.generate_path(key)?.ok_or(SmtError::LeafNotFound)?;
        if path.terminal_key != *key {
            return Err(SmtError::LeafNotFound);
        }
        Ok(InclusionProof {
            bitmap: path.bitmap,
            siblings: path.siblings,
        })
    }

    /// Generate a non-inclusion proof for `key`.
    ///
    /// The empty tree returns the distinguished empty proof.  Presence is an
    /// explicit lookup outcome and never produces a non-inclusion proof.
    pub fn get_non_inclusion_proof(
        &self,
        key: &SmtKey,
    ) -> Result<NonInclusionProofOutcome, SmtError> {
        let Some(path) = self.generate_path(key)? else {
            return Ok(NonInclusionProofOutcome::Proof(NonInclusionProof::empty()));
        };
        if path.terminal_key == *key {
            return Ok(NonInclusionProofOutcome::StateIncluded);
        }
        Ok(NonInclusionProofOutcome::Proof(NonInclusionProof::new(
            path,
        )))
    }

    /// Follow the target's branch bit at every actual junction, even when the
    /// target diverges inside a compressed edge.  Stopping at a prefix mismatch
    /// would not authenticate the terminal and is insufficient for absence.
    fn generate_path(&self, target: &SmtKey) -> Result<Option<GeneratedPath>, SmtError> {
        let Some(root) = self.root.as_deref() else {
            return Ok(None);
        };
        let mut bitmap = [0u8; BITMAP_SIZE];
        let mut siblings = Vec::new();
        let (terminal_key, terminal_value) =
            walk_to_terminal(root, target, 0, &mut bitmap, &mut siblings)?;
        Ok(Some(GeneratedPath {
            bitmap,
            siblings,
            terminal_key,
            terminal_value,
        }))
    }
}

fn walk_to_terminal(
    node: &Branch,
    target: &SmtKey,
    start_bit: usize,
    bitmap: &mut [u8; BITMAP_SIZE],
    siblings: &mut Vec<[u8; HASH_SIZE]>,
) -> Result<(SmtKey, Vec<u8>), SmtError> {
    match node {
        Branch::Leaf(leaf) => Ok((leaf.key, leaf.value.clone())),
        Branch::Node(node) => {
            let depth = node.depth as usize;
            debug_assert_eq!(depth, start_bit + node.path.path_len());
            bitmap[depth / 8] |= 0x80 >> (depth % 8);

            if key_bit_at(target, depth) == 1 {
                siblings.push(branch_hash(&node.left));
                walk_to_terminal(&node.right, target, depth + 1, bitmap, siblings)
            } else {
                siblings.push(branch_hash(&node.right));
                walk_to_terminal(&node.left, target, depth + 1, bitmap, siblings)
            }
        }
        Branch::Stub(_) => Err(SmtError::UnmaterializedBranch),
    }
}

// ─── Proof verification ─────────────────────────────────────────────────────

/// Verify that `(key, value)` is included under `root`.
pub fn verify_inclusion(
    proof: &InclusionProof,
    root: &[u8; HASH_SIZE],
    key: &SmtKey,
    value: &[u8],
) -> bool {
    fold_path(&proof.bitmap, &proof.siblings, key, key, value)
        .is_some_and(|calculated| calculated == *root)
}

/// Verify that `target` is absent under `root`.
///
/// Besides authenticating the terminal leaf, this checks at every junction
/// that the target and terminal choose the same branch.  This is the condition
/// that turns an authenticated *different* leaf into a sound absence proof.
pub fn verify_non_inclusion(
    proof: &NonInclusionProof,
    root: Option<&[u8; HASH_SIZE]>,
    target: &SmtKey,
) -> bool {
    let Some(body) = &proof.body else {
        return root.is_none();
    };
    let Some(root) = root else {
        return false;
    };
    if body.terminal_key == *target {
        return false;
    }
    fold_path(
        &body.bitmap,
        &body.siblings,
        target,
        &body.terminal_key,
        &body.terminal_value,
    )
    .is_some_and(|calculated| calculated == *root)
}

fn fold_path(
    bitmap: &[u8; BITMAP_SIZE],
    siblings: &[[u8; HASH_SIZE]],
    target_key: &SmtKey,
    terminal_key: &SmtKey,
    terminal_value: &[u8],
) -> Option<[u8; HASH_SIZE]> {
    let mut hash = hash_leaf(terminal_key, terminal_value);
    let mut sibling_idx = siblings.len();

    for depth in (0..KEY_BITS).rev() {
        if !bitmap_has_depth(bitmap, depth) {
            continue;
        }
        if sibling_idx == 0 || key_bit_at(target_key, depth) != key_bit_at(terminal_key, depth) {
            return None;
        }
        sibling_idx -= 1;
        let sibling = &siblings[sibling_idx];
        let region = prefix_region(terminal_key, depth);

        hash = if key_bit_at(terminal_key, depth) == 1 {
            hash_node(sibling, &hash, depth as u8, &region)
        } else {
            hash_node(&hash, sibling, depth as u8, &region)
        };
    }

    (sibling_idx == 0).then_some(hash)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(byte: u8) -> SmtKey {
        let mut key = [0u8; 32];
        key[0] = byte;
        key
    }

    #[test]
    fn inclusion_proofs_still_verify() {
        let mut tree = SparseMerkleTree::new();
        for i in 0u8..=64 {
            tree.add_leaf(make_key(i), vec![i; 32]).unwrap();
        }
        let root = tree.root_hash().unwrap();

        for i in 0u8..=64 {
            let key = make_key(i);
            let value = vec![i; 32];
            let proof = tree.get_inclusion_proof(&key).unwrap();
            assert!(verify_inclusion(&proof, &root, &key, &value));
        }
    }

    #[test]
    fn inclusion_bitmap_uses_msb_first_depth_bits() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(0x00), vec![1; 32]).unwrap();
        tree.add_leaf(make_key(0x80), vec![2; 32]).unwrap();
        let proof = tree.get_inclusion_proof(&make_key(0x00)).unwrap();
        assert_eq!(proof.bitmap[0], 0x80, "depth zero is the bitmap MSB");
    }

    #[test]
    fn inclusion_missing_and_empty_return_errors() {
        let mut tree = SparseMerkleTree::new();
        assert_eq!(
            tree.get_inclusion_proof(&make_key(1)),
            Err(SmtError::LeafNotFound)
        );
        tree.add_leaf(make_key(1), vec![1; 32]).unwrap();
        assert_eq!(
            tree.get_inclusion_proof(&make_key(2)),
            Err(SmtError::LeafNotFound)
        );
    }

    #[test]
    fn inclusion_wrong_value_and_root_fail() {
        let mut tree = SparseMerkleTree::new();
        let key = make_key(42);
        let value = vec![42; 32];
        tree.add_leaf(key, value.clone()).unwrap();
        let root = tree.root_hash().unwrap();
        let proof = tree.get_inclusion_proof(&key).unwrap();
        assert!(!verify_inclusion(&proof, &root, &key, &[99; 32]));
        assert!(!verify_inclusion(&proof, &[0xff; 32], &key, &value));
    }

    #[test]
    fn inclusion_serialization_roundtrip() {
        let mut tree = SparseMerkleTree::new();
        for i in 1u8..=8 {
            tree.add_leaf(make_key(i), vec![i; 32]).unwrap();
        }
        let root = tree.root_hash().unwrap();
        let key = make_key(5);
        let value = vec![5; 32];
        let proof = tree.get_inclusion_proof(&key).unwrap();
        let decoded = InclusionProof::from_bytes(&proof.to_bytes()).unwrap();
        assert_eq!(decoded, proof);
        assert!(verify_inclusion(&decoded, &root, &key, &value));
    }

    #[test]
    fn empty_tree_has_distinguished_non_inclusion_proof() {
        let tree = SparseMerkleTree::new();
        let target = make_key(7);
        let NonInclusionProofOutcome::Proof(proof) = tree.get_non_inclusion_proof(&target).unwrap()
        else {
            panic!("absent key must produce a proof");
        };
        assert!(proof.is_empty());
        assert!(proof.to_bytes().is_empty());
        assert!(verify_non_inclusion(&proof, None, &target));
        assert!(!verify_non_inclusion(&proof, Some(&[0u8; 32]), &target));
        assert_eq!(NonInclusionProof::from_bytes(&[]).unwrap(), proof);
    }

    #[test]
    fn singleton_non_inclusion_authenticates_terminal() {
        let mut tree = SparseMerkleTree::new();
        let stored = make_key(1);
        let target = make_key(2);
        tree.add_leaf(stored, vec![0xabu8; 32]).unwrap();
        let root = tree.root_hash().unwrap();
        let NonInclusionProofOutcome::Proof(proof) = tree.get_non_inclusion_proof(&target).unwrap()
        else {
            panic!("absent key must produce a proof");
        };

        assert_eq!(proof.terminal_key(), Some(&stored));
        assert!(verify_non_inclusion(&proof, Some(&root), &target));
        assert_eq!(
            NonInclusionProof::from_bytes(&proof.to_bytes()).unwrap(),
            proof
        );
    }

    #[test]
    fn present_key_never_produces_non_inclusion_proof() {
        let mut tree = SparseMerkleTree::new();
        let key = make_key(1);
        tree.add_leaf(key, vec![1; 32]).unwrap();
        assert_eq!(
            tree.get_non_inclusion_proof(&key),
            Ok(NonInclusionProofOutcome::StateIncluded)
        );
    }

    #[test]
    fn unmaterialized_client_selected_branch_returns_error() {
        use std::sync::Arc;

        use crate::path::CompressedPath;
        use crate::types::{make_leaf_sha256, make_node_sha256};

        // Model a partially materialized disk tree. The untrusted target selects
        // the left stub; the right sibling is sufficiently represented by its
        // hash. This must fail the request, never unwind the round manager.
        let left = Arc::new(Branch::Stub([0xabu8; HASH_SIZE]));
        let right = make_leaf_sha256(make_key(0x80), vec![2; 32]);
        let root = make_node_sha256(CompressedPath::empty(), left, right, 0, [0u8; HASH_SIZE]);
        let tree = SparseMerkleTree { root: Some(root) };
        let target = make_key(0x00);

        assert_eq!(
            tree.get_inclusion_proof(&target),
            Err(SmtError::UnmaterializedBranch)
        );
        assert_eq!(
            tree.get_non_inclusion_proof(&target),
            Err(SmtError::UnmaterializedBranch)
        );
    }

    #[test]
    fn compressed_edge_divergence_is_a_valid_absence_proof() {
        // Stored keys share depths 0..6 and bifurcate at depth 7.  The target
        // differs from both at depth 0, inside the compressed edge above that
        // junction, but chooses the same actual depth-7 branch as `left`.
        let mut tree = SparseMerkleTree::new();
        let left = make_key(0x40);
        let right = make_key(0x41);
        let target = make_key(0xc0);
        tree.add_leaf(left, vec![1; 32]).unwrap();
        tree.add_leaf(right, vec![2; 32]).unwrap();
        let root = tree.root_hash().unwrap();

        let NonInclusionProofOutcome::Proof(proof) = tree.get_non_inclusion_proof(&target).unwrap()
        else {
            panic!("absent key must produce a proof");
        };
        assert_eq!(proof.terminal_key(), Some(&left));
        assert!(verify_non_inclusion(&proof, Some(&root), &target));
    }

    #[test]
    fn replay_for_a_target_taking_another_branch_fails() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(0x00), vec![1; 32]).unwrap();
        tree.add_leaf(make_key(0x80), vec![2; 32]).unwrap();
        let root = tree.root_hash().unwrap();

        let left_absent = make_key(0x01);
        let NonInclusionProofOutcome::Proof(proof) =
            tree.get_non_inclusion_proof(&left_absent).unwrap()
        else {
            panic!("absent key must produce a proof");
        };
        let mut expected_certificate = vec![0u8; 32];
        expected_certificate[0] = 0x80;
        expected_certificate.extend_from_slice(&[
            0xd7, 0x9a, 0xe1, 0x16, 0xbb, 0x8c, 0x86, 0x04, 0x81, 0x9a, 0xdc, 0x35, 0xc2, 0xa7,
            0x1b, 0x7c, 0x3a, 0xcf, 0x89, 0xcd, 0x1b, 0xe8, 0xa3, 0x82, 0xfb, 0xed, 0xbd, 0x69,
            0x05, 0xac, 0x20, 0xe7,
        ]);
        expected_certificate.extend_from_slice(&[0u8; 32]);
        expected_certificate.extend_from_slice(&[1u8; 32]);
        assert_eq!(proof.to_bytes(), expected_certificate);
        assert_eq!(
            root,
            [
                0x51, 0x58, 0xa5, 0xf4, 0x02, 0x95, 0x11, 0xf5, 0x31, 0x2b, 0x7a, 0x14, 0x7c, 0x9d,
                0xa4, 0x8b, 0x92, 0x81, 0x32, 0x2d, 0x1b, 0x89, 0x3a, 0x10, 0xa2, 0x5b, 0x2c, 0x17,
                0xe2, 0x19, 0x7a, 0x53,
            ]
        );
        assert!(verify_non_inclusion(&proof, Some(&root), &left_absent));

        let right_absent = make_key(0x81);
        assert!(!verify_non_inclusion(&proof, Some(&root), &right_absent));
    }

    #[test]
    fn tampered_terminal_or_root_fails() {
        let mut tree = SparseMerkleTree::new();
        tree.add_leaf(make_key(0x00), vec![1; 32]).unwrap();
        tree.add_leaf(make_key(0x80), vec![2; 32]).unwrap();
        let root = tree.root_hash().unwrap();
        let target = make_key(0x01);
        let NonInclusionProofOutcome::Proof(proof) = tree.get_non_inclusion_proof(&target).unwrap()
        else {
            panic!("absent key must produce a proof");
        };

        let mut encoded = proof.to_bytes();
        *encoded.last_mut().unwrap() ^= 1;
        let tampered = NonInclusionProof::from_bytes(&encoded).unwrap();
        assert!(!verify_non_inclusion(&tampered, Some(&root), &target));
        assert!(!verify_non_inclusion(&proof, Some(&[0xff; 32]), &target));
    }

    #[test]
    fn decoder_rejects_truncated_siblings_and_terminal() {
        let mut bitmap = [0u8; BITMAP_SIZE];
        bitmap[0] = 0x80;
        assert!(NonInclusionProof::from_bytes(&bitmap).is_err());

        let mut no_terminal = bitmap.to_vec();
        no_terminal.extend_from_slice(&[0u8; HASH_SIZE]);
        assert!(NonInclusionProof::from_bytes(&no_terminal).is_err());
    }
}
