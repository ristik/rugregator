//! Consistency proof types, verification, and wire encoding/decoding.
//!
//! This module is `no_std`-compatible (requires `alloc`).
//!
//! ## Proof format (post-order, 3 opcodes)
//!
//! | Opcode | Wire bytes       | Meaning                                         |
//! |--------|------------------|-------------------------------------------------|
//! | `S(h)` | `0x00` + `h[32]` | Unchanged subtree carrying its hash (33 bytes). |
//! | `L`    | `0x01`           | New leaf — verifier pops from sorted batch.     |
//! | `N(d)` | `0x02` + `d`     | Node at depth `d` (two children precede).       |
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
use crate::path::{get_sort_key, SmtKey};

// ─── Proof opcodes ────────────────────────────────────────────────────────────

/// One element of the flat post-order consistency-proof stream.
#[derive(Debug, Clone, PartialEq)]
pub enum ProofOp {
    /// Unchanged subtree — carries its hash.
    S([u8; 32]),
    /// New leaf (key/value consumed from sorted batch).
    L,
    /// Node at the given depth.  Two children precede on the stack.
    N(u8),
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
) -> bool {
    verify_consistency_with::<crate::hash::Sha256Hasher>(proof, old_root, new_root, batch)
}

/// Verify a consistency proof using the given hasher.
///
/// `batch` **must** already be sorted by [`get_sort_key`] — this is the
/// responsibility of the proof producer.  [`decode_aggregator_envelope_v1`]
/// preserves the sort order encoded by the prover, and
/// `batch_insert_with_proof` returns leaves in sorted order, so callers
/// that use these functions satisfy the precondition automatically.
pub fn verify_consistency_with<H: SmtHasher>(
    proof: &ConsistencyProof,
    old_root: Option<[u8; 32]>,
    new_root: Option<[u8; 32]>,
    batch: &[(SmtKey, Vec<u8>)],
) -> bool {
    if batch.is_empty() {
        return old_root == new_root;
    }

    let mut stack: Vec<(Option<[u8; 32]>, Option<[u8; 32]>)> = Vec::new();
    let mut pi = 0usize; // proof index
    let mut bi = 0usize; // batch index

    while pi < proof.len() {
        match &proof[pi] {
            ProofOp::S(h) => {
                pi += 1;
                stack.push((Some(*h), Some(*h)));
            }
            ProofOp::L => {
                pi += 1;
                if bi >= batch.len() {
                    return false;
                }
                let (k, v) = &batch[bi];
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
        && bi == batch.len()
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
        }
    }
    out
}

/// Encode an `aggregator_rsmt_v1` envelope: the batch of newly-inserted
/// leaves followed by the flat opcode stream.
///
/// `leaves_sorted` **must** already be sorted by [`get_sort_key`].
pub fn encode_aggregator_envelope_v1(
    leaves_sorted: &[(SmtKey, Vec<u8>)],
    proof: &ConsistencyProof,
) -> Vec<u8> {
    debug_assert!(
        leaves_sorted
            .windows(2)
            .all(|w| get_sort_key(&w[0].0) < get_sort_key(&w[1].0)),
        "encode_aggregator_envelope_v1: leaves not sorted by get_sort_key"
    );
    debug_assert!(
        leaves_sorted.len() <= u32::MAX as usize,
        "encode_aggregator_envelope_v1: too many leaves"
    );
    let proof_bytes_len: usize = proof
        .iter()
        .map(|op| match op {
            ProofOp::S(_) => 33,
            ProofOp::L => 1,
            ProofOp::N(_) => 2,
        })
        .sum();
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
        }
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
    /// An opcode byte is not `0x00`, `0x01`, or `0x02`.
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
            b => return Err(EnvelopeError::BadOpcode(b)),
        }
    }

    Ok((leaves, proof))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        let leaves: Vec<(SmtKey, Vec<u8>)> = (1u8..=4)
            .map(|i| {
                let mut k = [0u8; 32];
                k[0] = i;
                (k, vec![i; 8])
            })
            .collect();
        // Sort by sort_key before encoding (normally done by batch_insert_with_proof).
        let mut sorted = leaves.clone();
        sorted.sort_by_key(|(k, _)| get_sort_key(k));

        let proof = alloc::vec![ProofOp::L, ProofOp::L, ProofOp::L, ProofOp::L];
        let env = encode_aggregator_envelope_v1(&sorted, &proof);
        let (dec_leaves, dec_proof) = decode_aggregator_envelope_v1(&env).unwrap();

        assert_eq!(dec_leaves.len(), 4);
        for (a, b) in dec_leaves.iter().zip(sorted.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1, b.1);
        }
        assert_eq!(dec_proof.len(), 4);
    }

    /// Verify that the verifier agrees with a manually-constructed single-leaf
    /// tree.  Also confirms SP1 sha256 precompile path works.
    #[test]
    fn verify_single_leaf() {
        use crate::hash::Sha256Hasher;
        let k = make_key(1);
        let v = vec![0xAB; 32];
        let leaf_hash = Sha256Hasher::hash_leaf(&k, &v);
        let proof = alloc::vec![ProofOp::L];
        let batch = alloc::vec![(k, v)];
        assert!(verify_consistency(&proof, None, Some(leaf_hash), &batch));
    }

    #[test]
    fn verify_empty_batch() {
        let root = [0x42u8; 32];
        assert!(verify_consistency(
            &alloc::vec![],
            Some(root),
            Some(root),
            &[]
        ));
        assert!(!verify_consistency(&alloc::vec![], Some(root), None, &[]));
    }
}
