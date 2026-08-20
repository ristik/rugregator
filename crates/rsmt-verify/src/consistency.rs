//! Consistency proof types, verification, and wire encoding/decoding.
//!
//! This module is `no_std`-compatible (requires `alloc`).
//!
//! ## Proof format (post-order, RSMT v6a — 5 opcodes)
//!
//! | Opcode        | Wire bytes                              | Meaning                                                                     |
//! |---------------|------------------------------------------|------------------------------------------------------------------------------|
//! | `S(h)`        | `0x00` + `h[32]`                         | Opaque preserved subtree — only valid where the parent junction pre-existed. |
//! | `L`           | `0x01`                                   | New leaf — verifier pops from sorted batch.                                  |
//! | `N(d)`        | `0x02` + `d`                             | Junction at depth `d` (two children precede on the stack).                   |
//! | `O(d,p,hL,hR)`| `0x03` + `d` + `p[32]` + `hL[32]` + `hR[32]` | Preserved junction, opened one level — required when a preserved subtree becomes the child of a junction created this round. |
//! | `O_L(k,v)`    | `0x04` + `k[32]` + `len(v) (u16 BE)` + `v` | Preserved leaf, opened (same "new parent" trigger as `O`). The length prefix is a wire-format necessity of this crate (the value is not otherwise self-delimiting mid-stream); the Yellowpaper's abstract format assumes out-of-band framing. |
//!
//! An opaque `S` is admissible only where the parent junction already exists in
//! the pre-state tree. Where a preserved subtree becomes the child of a
//! junction created this round (an edge split, including the leaf-merge
//! case), it must be presented opened, as `O` or `O_L`, so the verifier can
//! check the new edge against the child's authenticated depth and region.
//!
//! ## Wire envelope (`aggregator_rsmt_v1`)
//!
//! ```text
//! offset  size  field
//! 0       4     leaf_count                         (u32 big-endian)
//! 4       ...   leaves:   leaf_count ×
//!                         { key[32] || value_len (u16 BE) || value[value_len] }
//! ...     ...   opcode stream (see above)
//! ```

use alloc::vec::Vec;

use crate::hash::SmtHasher;
use crate::path::{key_bit_at, prefix_region, SmtKey, KEY_BITS};

// ─── Proof opcodes ────────────────────────────────────────────────────────────

/// One element of the flat post-order consistency-proof stream.
#[derive(Debug, Clone, PartialEq)]
pub enum ProofOp {
    /// Opaque preserved subtree — carries its hash. Only admissible where the
    /// parent junction already existed in the pre-state.
    S([u8; 32]),
    /// New leaf (key/value consumed from sorted batch).
    L,
    /// Junction at the given depth. Two children precede on the stack.
    N(u8),
    /// Preserved junction, opened one level (required when it becomes the
    /// child of a junction created this round).
    O {
        depth: u8,
        region: [u8; 32],
        left: [u8; 32],
        right: [u8; 32],
    },
    /// Preserved leaf, opened (required when it becomes the child of a
    /// junction created this round).
    OL { key: SmtKey, value: Vec<u8> },
}

/// Ordered flat consistency proof.
pub type ConsistencyProof = Vec<ProofOp>;

// ─── Verification ────────────────────────────────────────────────────────────

/// Verify a consistency proof using SHA-256 (default).
pub fn verify_consistency(
    proof: &ConsistencyProof,
    old_root: Option<[u8; 32]>,
    new_root: Option<[u8; 32]>,
    batch: &[(SmtKey, Vec<u8>)],
    reference_time: u64,
) -> bool {
    verify_consistency_with::<crate::hash::Sha256Hasher>(
        proof,
        old_root,
        new_root,
        batch,
        reference_time,
    )
}

/// Advice tuple carried by a stack entry: the depth and region of the
/// subtree's top node. `256` is used as the depth for leaves. `None` for
/// opaque `S` subtrees, whose top node is not disclosed.
type Advice = Option<(u16, [u8; 32])>;

/// A region is well-formed for depth `d` iff its bits `d..256` are zero
/// (the packing that [`prefix_region`] produces).
#[inline]
fn region_well_formed(region: &[u8; 32], depth: usize) -> bool {
    &prefix_region(region, depth) == region
}

/// Verify a consistency proof using the given hasher.
///
/// `batch` **must** already be sorted by plain key order (RSMT v6a:
/// `rsmt_sort_key(k) = k`, i.e. ordinary unsigned lexicographic byte order)
/// — this is the responsibility of the proof producer.
/// [`decode_aggregator_envelope_v1`] preserves the sort order encoded by the
/// prover, and `batch_insert_with_proof` returns leaves in sorted order, so
/// callers that use these functions satisfy the precondition automatically.
pub fn verify_consistency_with<H: SmtHasher>(
    proof: &ConsistencyProof,
    old_root: Option<[u8; 32]>,
    new_root: Option<[u8; 32]>,
    batch: &[(SmtKey, Vec<u8>)],
    reference_time: u64,
) -> bool {
    if batch.is_empty() {
        return old_root == new_root && proof.is_empty();
    }

    let mut stack: Vec<(Option<[u8; 32]>, Option<[u8; 32]>, Advice)> = Vec::new();
    let mut bi = 0usize; // batch index

    for op in proof {
        match op {
            ProofOp::S(h) => {
                stack.push((Some(*h), Some(*h), None));
            }
            ProofOp::O {
                depth,
                region,
                left,
                right,
            } => {
                let d = *depth;
                if !region_well_formed(region, d as usize) {
                    return false;
                }
                let h = H::hash_node(left, right, d, region);
                stack.push((Some(h), Some(h), Some((d as u16, *region))));
            }
            ProofOp::OL { key, value } => {
                let h = H::hash_leaf(key, value);
                stack.push((Some(h), Some(h), Some((KEY_BITS as u16, *key))));
            }
            ProofOp::L => {
                if bi >= batch.len() {
                    return false;
                }
                // The batch declares transaction hashes; the tree stores leaf
                // values that bind the round's reference time. Deriving them
                // here rather than accepting a supplied leaf value is what
                // makes a wrong reference time unrepresentable.
                let (k, v) = &batch[bi];
                bi += 1;
                let leaf = crate::leaf_value::leaf_value(v, reference_time);
                stack.push((
                    None,
                    Some(H::hash_leaf(k, &leaf)),
                    Some((KEY_BITS as u16, *k)),
                ));
            }
            ProofOp::N(depth) => {
                let d = *depth;
                if stack.len() < 2 {
                    return false;
                }
                let (rh0, rh1, r_adv) = stack.pop().unwrap();
                let (lh0, lh1, l_adv) = stack.pop().unwrap();

                // Derive the junction region from every advised child; all
                // advised children must agree, and at least one is required.
                let mut p: Option<[u8; 32]> = None;
                for (adv, side) in [(l_adv, 0u8), (r_adv, 1u8)] {
                    if let Some((delta, rho)) = adv {
                        if delta as usize <= d as usize {
                            return false;
                        }
                        if key_bit_at(&rho, d as usize) != side {
                            return false;
                        }
                        let candidate = prefix_region(&rho, d as usize);
                        match p {
                            None => p = Some(candidate),
                            Some(existing) if existing != candidate => return false,
                            Some(_) => {}
                        }
                    }
                }
                let Some(p) = p else {
                    return false;
                };

                // Junction absent from the pre-state ⇒ neither child may be
                // an opaque S (no opaque child may attach to a new edge).
                let is_new = lh0.is_none() || rh0.is_none();
                if is_new && (l_adv.is_none() || r_adv.is_none()) {
                    return false;
                }

                let h0 = match (lh0, rh0) {
                    (None, None) => None,
                    (None, Some(r)) => Some(r),
                    (Some(l), None) => Some(l),
                    (Some(l), Some(r)) => Some(H::hash_node(&l, &r, d, &p)),
                };
                let (l1, r1) = match (lh1, rh1) {
                    (Some(l), Some(r)) => (l, r),
                    _ => return false,
                };
                let h1 = H::hash_node(&l1, &r1, d, &p);

                stack.push((h0, Some(h1), Some((d as u16, p))));
            }
        }
    }

    if bi != batch.len() || stack.len() != 1 {
        return false;
    }
    let (h0, h1, _) = stack[0];
    h0 == old_root && h1 == new_root
}

// ─── Wire encoding ───────────────────────────────────────────────────────────

/// Byte length of a single encoded opcode.
#[inline]
fn op_byte_len(op: &ProofOp) -> usize {
    match op {
        ProofOp::S(_) => 33,
        ProofOp::L => 1,
        ProofOp::N(_) => 2,
        ProofOp::O { .. } => 98,
        ProofOp::OL { value, .. } => 33 + 2 + value.len(),
    }
}

fn write_op(out: &mut Vec<u8>, op: &ProofOp) {
    match op {
        ProofOp::S(h) => {
            out.push(0x00);
            out.extend_from_slice(h);
        }
        ProofOp::L => {
            out.push(0x01);
        }
        ProofOp::N(d) => {
            out.push(0x02);
            out.push(*d);
        }
        ProofOp::O {
            depth,
            region,
            left,
            right,
        } => {
            out.push(0x03);
            out.push(*depth);
            out.extend_from_slice(region);
            out.extend_from_slice(left);
            out.extend_from_slice(right);
        }
        ProofOp::OL { key, value } => {
            out.push(0x04);
            out.extend_from_slice(key);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
    }
}

/// Encode a `ConsistencyProof` as a flat binary byte slice.
///
/// See the module-level table for the per-opcode wire layout.
pub fn consistency_proof_to_bytes(proof: &ConsistencyProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(proof.iter().map(op_byte_len).sum());
    for op in proof {
        write_op(&mut out, op);
    }
    out
}

/// Encode an `aggregator_rsmt_v1` envelope: the batch of newly-inserted
/// leaves followed by the flat opcode stream.
///
/// `leaves_sorted` **must** already be sorted by plain key order.
pub fn encode_aggregator_envelope_v1(
    leaves_sorted: &[(SmtKey, Vec<u8>)],
    proof: &ConsistencyProof,
) -> Vec<u8> {
    debug_assert!(
        leaves_sorted.windows(2).all(|w| w[0].0 < w[1].0),
        "encode_aggregator_envelope_v1: leaves not sorted by key"
    );
    debug_assert!(
        leaves_sorted.len() <= u32::MAX as usize,
        "encode_aggregator_envelope_v1: too many leaves"
    );
    let proof_bytes_len: usize = proof.iter().map(op_byte_len).sum();
    let leaves_bytes_len: usize = leaves_sorted.iter().map(|(_, v)| 32 + 2 + v.len()).sum();
    let mut out = Vec::with_capacity(4 + leaves_bytes_len + proof_bytes_len);

    out.extend_from_slice(&(leaves_sorted.len() as u32).to_be_bytes());
    for (k, v) in leaves_sorted {
        debug_assert!(
            v.len() <= u16::MAX as usize,
            "encode_aggregator_envelope_v1: value length {} exceeds u16::MAX",
            v.len()
        );
        out.extend_from_slice(k);
        out.extend_from_slice(&(v.len() as u16).to_be_bytes());
        out.extend_from_slice(v);
    }
    for op in proof {
        write_op(&mut out, op);
    }
    out
}

// ─── Wire decoding ───────────────────────────────────────────────────────────

/// Maximum number of leaves accepted by [`decode_aggregator_envelope_v1`].
///
/// Matches the Go verifier's limit.
const MAX_LEAF_COUNT: usize = 1 << 20; // 1 048 576

/// Error returned by [`decode_aggregator_envelope_v1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The byte slice is shorter than the 4-byte leaf-count header.
    TooShort,
    /// The leaf count exceeds [`MAX_LEAF_COUNT`].
    TooManyLeaves,
    /// A leaf's value-length field would read past the end of the buffer.
    UnexpectedEnd,
    /// An opcode byte is not one of `0x00`..=`0x04`.
    BadOpcode(u8),
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EnvelopeError::TooShort => f.write_str("envelope too short"),
            EnvelopeError::TooManyLeaves => f.write_str("leaf count exceeds limit"),
            EnvelopeError::UnexpectedEnd => f.write_str("unexpected end of envelope"),
            EnvelopeError::BadOpcode(b) => write!(f, "bad opcode 0x{b:02x}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EnvelopeError {}

/// Decode an `aggregator_rsmt_v1` envelope into `(leaves, proof)`.
///
/// This is the Rust mirror of the Go `rsmt.DecodeEnvelope` function
/// (`bft-core/rootchain/consensus/zkverifier/rsmt/envelope.go`).
pub fn decode_aggregator_envelope_v1(
    bytes: &[u8],
) -> Result<(Vec<(SmtKey, Vec<u8>)>, ConsistencyProof), EnvelopeError> {
    if bytes.len() < 4 {
        return Err(EnvelopeError::TooShort);
    }
    let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if count > MAX_LEAF_COUNT {
        return Err(EnvelopeError::TooManyLeaves);
    }

    let mut pos = 4usize;
    let mut leaves = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 34 > bytes.len() {
            return Err(EnvelopeError::UnexpectedEnd);
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let vlen = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if pos + vlen > bytes.len() {
            return Err(EnvelopeError::UnexpectedEnd);
        }
        let v = bytes[pos..pos + vlen].to_vec();
        pos += vlen;
        leaves.push((k, v));
    }

    let mut proof = Vec::new();
    while pos < bytes.len() {
        match bytes[pos] {
            0x00 => {
                if pos + 33 > bytes.len() {
                    return Err(EnvelopeError::UnexpectedEnd);
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes[pos + 1..pos + 33]);
                proof.push(ProofOp::S(h));
                pos += 33;
            }
            0x01 => {
                proof.push(ProofOp::L);
                pos += 1;
            }
            0x02 => {
                if pos + 2 > bytes.len() {
                    return Err(EnvelopeError::UnexpectedEnd);
                }
                proof.push(ProofOp::N(bytes[pos + 1]));
                pos += 2;
            }
            0x03 => {
                if pos + 98 > bytes.len() {
                    return Err(EnvelopeError::UnexpectedEnd);
                }
                let depth = bytes[pos + 1];
                let mut region = [0u8; 32];
                region.copy_from_slice(&bytes[pos + 2..pos + 34]);
                let mut left = [0u8; 32];
                left.copy_from_slice(&bytes[pos + 34..pos + 66]);
                let mut right = [0u8; 32];
                right.copy_from_slice(&bytes[pos + 66..pos + 98]);
                proof.push(ProofOp::O {
                    depth,
                    region,
                    left,
                    right,
                });
                pos += 98;
            }
            0x04 => {
                if pos + 35 > bytes.len() {
                    return Err(EnvelopeError::UnexpectedEnd);
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes[pos + 1..pos + 33]);
                let vlen = u16::from_be_bytes([bytes[pos + 33], bytes[pos + 34]]) as usize;
                let value_start = pos + 35;
                if value_start + vlen > bytes.len() {
                    return Err(EnvelopeError::UnexpectedEnd);
                }
                let value = bytes[value_start..value_start + vlen].to_vec();
                proof.push(ProofOp::OL { key, value });
                pos = value_start + vlen;
            }
            b => return Err(EnvelopeError::BadOpcode(b)),
        }
    }

    Ok((leaves, proof))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference time every fixture in this module builds its leaves under.
    const TEST_REFERENCE_TIME: u64 = 1_755_000_000;

    fn make_key(byte: u8) -> SmtKey {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    // Build a minimal envelope manually: 1 leaf, 1 L opcode.
    fn hand_build_envelope(key: SmtKey, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&key);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out.push(0x01); // L opcode
        out
    }

    #[test]
    fn decode_single_leaf_l_opcode() {
        let k = make_key(7);
        let v = vec![0xAB; 16];
        let env = hand_build_envelope(k, &v);
        let (leaves, proof) = decode_aggregator_envelope_v1(&env).unwrap();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].0, k);
        assert_eq!(leaves[0].1, v);
        assert_eq!(proof.len(), 1);
        assert!(matches!(proof[0], ProofOp::L));
    }

    #[test]
    fn decode_empty_envelope() {
        // 4 bytes of zero leaf_count, no proof bytes.
        let env = vec![0u8; 4];
        let (leaves, proof) = decode_aggregator_envelope_v1(&env).unwrap();
        assert!(leaves.is_empty());
        assert!(proof.is_empty());
    }

    #[test]
    fn decode_s_opcode() {
        let mut env = vec![0u8; 4]; // 0 leaves
        env.push(0x00); // S opcode
        env.extend_from_slice(&[0xBB; 32]);
        let (_, proof) = decode_aggregator_envelope_v1(&env).unwrap();
        assert_eq!(proof.len(), 1);
        assert!(matches!(proof[0], ProofOp::S(h) if h == [0xBB; 32]));
    }

    #[test]
    fn decode_n_opcode() {
        let mut env = vec![0u8; 4]; // 0 leaves
        env.push(0x02); // N opcode
        env.push(42); // depth
        let (_, proof) = decode_aggregator_envelope_v1(&env).unwrap();
        assert!(matches!(proof[0], ProofOp::N(42)));
    }

    #[test]
    fn decode_o_opcode() {
        let mut env = vec![0u8; 4]; // 0 leaves
        env.push(0x03); // O opcode
        env.push(5); // depth
        env.extend_from_slice(&[0x11; 32]); // region
        env.extend_from_slice(&[0x22; 32]); // left
        env.extend_from_slice(&[0x33; 32]); // right
        let (_, proof) = decode_aggregator_envelope_v1(&env).unwrap();
        assert_eq!(proof.len(), 1);
        assert!(matches!(
            &proof[0],
            ProofOp::O { depth: 5, region, left, right }
                if *region == [0x11; 32] && *left == [0x22; 32] && *right == [0x33; 32]
        ));
    }

    #[test]
    fn decode_ol_opcode() {
        let k = make_key(9);
        let v = vec![0xCD; 5];
        let mut env = vec![0u8; 4]; // 0 leaves
        env.push(0x04); // O_L opcode
        env.extend_from_slice(&k);
        env.extend_from_slice(&(v.len() as u16).to_be_bytes());
        env.extend_from_slice(&v);
        let (_, proof) = decode_aggregator_envelope_v1(&env).unwrap();
        assert_eq!(proof.len(), 1);
        assert!(matches!(&proof[0], ProofOp::OL { key, value } if *key == k && *value == v));
    }

    #[test]
    fn decode_bad_opcode() {
        let mut env = vec![0u8; 4];
        env.push(0xFF);
        assert_eq!(
            decode_aggregator_envelope_v1(&env),
            Err(EnvelopeError::BadOpcode(0xFF))
        );
    }

    #[test]
    fn decode_too_short() {
        assert_eq!(
            decode_aggregator_envelope_v1(&[0, 0, 0]),
            Err(EnvelopeError::TooShort)
        );
    }

    #[test]
    fn decode_unexpected_end_s() {
        let mut env = vec![0u8; 4]; // 0 leaves
        env.push(0x00); // S opcode — needs 32 more bytes
        env.extend_from_slice(&[0u8; 16]); // only 16, not 32
        assert_eq!(
            decode_aggregator_envelope_v1(&env),
            Err(EnvelopeError::UnexpectedEnd)
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut leaves: Vec<(SmtKey, Vec<u8>)> = (1u8..=4)
            .map(|i| {
                let mut k = [0u8; 32];
                k[0] = i;
                (k, vec![i; 8])
            })
            .collect();
        leaves.sort_by_key(|(k, _)| *k);

        let proof = alloc::vec![ProofOp::L, ProofOp::L, ProofOp::L, ProofOp::L];
        let env = encode_aggregator_envelope_v1(&leaves, &proof);
        let (dec_leaves, dec_proof) = decode_aggregator_envelope_v1(&env).unwrap();

        assert_eq!(dec_leaves.len(), 4);
        for (a, b) in dec_leaves.iter().zip(leaves.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1, b.1);
        }
        assert_eq!(dec_proof.len(), 4);
    }

    #[test]
    fn encode_decode_roundtrip_with_o_and_ol() {
        let leaves: Vec<(SmtKey, Vec<u8>)> = vec![(make_key(9), vec![1, 2, 3])];
        let proof = alloc::vec![
            ProofOp::OL {
                key: make_key(1),
                value: vec![0xAA; 3],
            },
            ProofOp::L,
            ProofOp::N(4),
            ProofOp::O {
                depth: 2,
                region: [0x55; 32],
                left: [0x66; 32],
                right: [0x77; 32],
            },
            ProofOp::N(1),
        ];
        let env = encode_aggregator_envelope_v1(&leaves, &proof);
        let (dec_leaves, dec_proof) = decode_aggregator_envelope_v1(&env).unwrap();
        assert_eq!(dec_leaves, leaves);
        assert_eq!(dec_proof, proof);
    }

    /// Verify that the verifier agrees with a manually-constructed single-leaf
    /// tree.  Also confirms SP1 sha256 precompile path works.
    #[test]
    fn verify_single_leaf() {
        use crate::hash::Sha256Hasher;
        let k = make_key(1);
        let v = vec![0xAB; 32];
        let leaf_hash = Sha256Hasher::hash_leaf(&k, &crate::leaf_value(&v, TEST_REFERENCE_TIME));
        let proof = alloc::vec![ProofOp::L];
        let batch = alloc::vec![(k, v)];
        assert!(verify_consistency(
            &proof,
            None,
            Some(leaf_hash),
            &batch,
            TEST_REFERENCE_TIME
        ));
    }

    #[test]
    fn verify_empty_batch() {
        let root = [0x42u8; 32];
        assert!(verify_consistency(
            &alloc::vec![],
            Some(root),
            Some(root),
            &[],
            TEST_REFERENCE_TIME
        ));
        assert!(!verify_consistency(
            &alloc::vec![],
            Some(root),
            None,
            &[],
            TEST_REFERENCE_TIME
        ));
    }

    /// Two new leaves under an empty tree: root = N(bifurcation depth) over
    /// two L leaves. Exercises the plain new-junction path (no S/O/OL).
    #[test]
    fn verify_two_new_leaves() {
        use crate::hash::Sha256Hasher;
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x80; // diverges from k0 at bit 0 (MSB-first)
        let v0 = vec![1u8; 4];
        let v1 = vec![2u8; 4];
        let h0 = Sha256Hasher::hash_leaf(&k0, &crate::leaf_value(&v0, TEST_REFERENCE_TIME));
        let h1 = Sha256Hasher::hash_leaf(&k1, &crate::leaf_value(&v1, TEST_REFERENCE_TIME));
        let region = prefix_region(&k0, 0);
        let root = Sha256Hasher::hash_node(&h0, &h1, 0, &region);

        let proof = alloc::vec![ProofOp::L, ProofOp::L, ProofOp::N(0)];
        let batch = alloc::vec![(k0, v0), (k1, v1)];
        assert!(verify_consistency(
            &proof,
            None,
            Some(root),
            &batch,
            TEST_REFERENCE_TIME
        ));
    }

    /// An edge split: a pre-existing leaf, opened via `OL`, becomes the
    /// sibling of a newly-inserted leaf under a brand-new junction.
    #[test]
    fn verify_edge_split_with_ol() {
        use crate::hash::Sha256Hasher;
        let mut old_key = [0u8; 32];
        old_key[0] = 0x00; // bit 0 = 0
        let old_value = vec![9u8; 4];
        let old_root = Sha256Hasher::hash_leaf(&old_key, &old_value);

        let mut new_key = [0u8; 32];
        new_key[0] = 0x80; // bit 0 = 1: diverges from old_key at depth 0
        let new_value = vec![7u8; 4];
        let new_leaf_hash = Sha256Hasher::hash_leaf(
            &new_key,
            &crate::leaf_value(&new_value, TEST_REFERENCE_TIME),
        );

        let region = prefix_region(&old_key, 0);
        let new_root = Sha256Hasher::hash_node(&old_root, &new_leaf_hash, 0, &region);

        let proof = alloc::vec![
            ProofOp::OL {
                key: old_key,
                value: old_value,
            },
            ProofOp::L,
            ProofOp::N(0),
        ];
        let batch = alloc::vec![(new_key, new_value)];
        assert!(verify_consistency(
            &proof,
            Some(old_root),
            Some(new_root),
            &batch,
            TEST_REFERENCE_TIME
        ));

        // The same subtree presented opaquely (as S) instead of opened (as
        // OL) must be REJECTED: an opaque S may not attach to a new edge.
        let bad_proof = alloc::vec![ProofOp::S(old_root), ProofOp::L, ProofOp::N(0)];
        assert!(!verify_consistency(
            &bad_proof,
            Some(old_root),
            Some(new_root),
            &batch,
            TEST_REFERENCE_TIME
        ));
    }
}
