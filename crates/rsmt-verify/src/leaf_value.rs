//! The Unicity aggregation profile's leaf-value derivation.
//!
//! The batch a round declares carries transaction hashes; the tree stores leaf
//! values that bind the round's reference time. BFT Core derives
//!
//! ```text
//! B* = < (sid_i, H(h_tx,i, tau)) >,  tau = CR.IR.t
//! ```
//!
//! from the batch it receives and verifies the consistency proof against `B*`
//! rather than against `B`. Deriving rather than accepting a supplied leaf
//! value is what makes a wrong reference time unrepresentable: a shard that
//! built its tree under any other reference time produces a root the Core does
//! not reproduce, so the round is rejected rather than merely attributable
//! afterwards.
//!
//! The ZK-compressed instantiation exposes no batch, so the circuit performs
//! the same derivation internally and exposes the reference time as a public
//! input.

use crate::hash::sha256_parts;

/// Derive the stored leaf value from a declared transaction hash and the
/// round's reference time: `SHA-256(CBOR([transactionHash, referenceTime]))`.
///
/// `transaction_hash` is the raw 32-byte digest. The encoding is a two-element
/// deterministic CBOR array: a byte string of the digest followed by the
/// reference time as an unsigned integer.
pub fn leaf_value(transaction_hash: &[u8], reference_time: u64) -> [u8; 32] {
    let mut header = [0u8; 3];
    header[0] = 0x82; // array(2)
    header[1] = 0x58; // byte string, 1-byte length
    header[2] = transaction_hash.len() as u8;

    let mut time = [0u8; 9];
    let time_len = encode_uint(reference_time, &mut time);

    sha256_parts(&[&header, transaction_hash, &time[..time_len]])
}

/// Encode `value` as a deterministic (shortest-form) CBOR unsigned integer.
fn encode_uint(value: u64, out: &mut [u8; 9]) -> usize {
    if value <= 23 {
        out[0] = value as u8;
        1
    } else if value <= u8::MAX as u64 {
        out[0] = 0x18;
        out[1] = value as u8;
        2
    } else if value <= u16::MAX as u64 {
        out[0] = 0x19;
        out[1..3].copy_from_slice(&(value as u16).to_be_bytes());
        3
    } else if value <= u32::MAX as u64 {
        out[0] = 0x1a;
        out[1..5].copy_from_slice(&(value as u32).to_be_bytes());
        5
    } else {
        out[0] = 0x1b;
        out[1..9].copy_from_slice(&value.to_be_bytes());
        9
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared across the Go, Java and TypeScript implementations.
    #[test]
    fn matches_the_shared_test_vector() {
        let mut transaction_hash = [0u8; 32];
        for (i, b) in transaction_hash.iter_mut().enumerate() {
            *b = i as u8;
        }
        let expected: [u8; 32] = [
            0x02, 0x35, 0xbd, 0x52, 0xcf, 0xa1, 0x0c, 0x97, 0x85, 0xdf, 0xa0, 0x19, 0x42, 0xbc,
            0x39, 0x6f, 0x20, 0x1f, 0xe7, 0x15, 0xdb, 0xc3, 0x89, 0x6e, 0xe1, 0x17, 0xa9, 0x7e,
            0x89, 0x5e, 0x1e, 0x36,
        ];

        assert_eq!(leaf_value(&transaction_hash, 1_755_000_000), expected);
    }

    #[test]
    fn changes_with_the_reference_time() {
        let transaction_hash = [0x11u8; 32];

        assert_ne!(
            leaf_value(&transaction_hash, 1_755_000_000),
            leaf_value(&transaction_hash, 1_755_000_001)
        );
    }

    fn encoded(value: u64) -> alloc::vec::Vec<u8> {
        let mut out = [0u8; 9];
        let len = encode_uint(value, &mut out);
        out[..len].to_vec()
    }

    #[test]
    fn encodes_unsigned_integers_in_shortest_form() {
        assert_eq!(encoded(0), [0x00]);
        assert_eq!(encoded(23), [0x17]);
        assert_eq!(encoded(24), [0x18, 0x18]);
        assert_eq!(encoded(256), [0x19, 0x01, 0x00]);
        assert_eq!(encoded(1_755_000_000), [0x1a, 0x68, 0x9b, 0x2c, 0xc0]);
        assert_eq!(
            encoded(u64::MAX),
            [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }
}
