//! Re-exports from the `rsmt` crate plus aggregator-local helpers.
pub use rsmt::*;

/// Leaf-value width in the Unicity aggregation profile.
///
/// The generic RSMT wire format permits arbitrary byte-string values. Unicity
/// restricts them to one raw SHA-256 transaction hash.
pub const AGGREGATION_TREE_VALUE_SIZE: usize = 32;

/// Convert a 32-byte StateID to an SMT key.
///
/// In the new tree format the key is simply the raw 32-byte StateID.
pub fn state_id_to_smt_key(state_id: &[u8]) -> SmtKey {
    let mut key = [0u8; 32];
    let len = state_id.len().min(32);
    key[..len].copy_from_slice(&state_id[..len]);
    key
}

// ─── Local CBOR helpers ───────────────────────────────────────────────────────
//
// These used to live in rsmt::hash but were removed when Go-compatibility was
// dropped. They remain here for StateID and signature preimage computation.

pub mod hash {
    /// CBOR array header for `n` items.
    pub fn cbor_array(n: usize) -> Vec<u8> {
        if n < 24 {
            vec![0x80 | n as u8]
        } else if n < 0x100 {
            vec![0x98, n as u8]
        } else {
            vec![0x99, (n >> 8) as u8, n as u8]
        }
    }

    /// CBOR byte-string header + data.
    pub fn cbor_bytes(data: &[u8]) -> Vec<u8> {
        let n = data.len();
        let mut hdr = if n < 24 {
            vec![0x40 | n as u8]
        } else if n < 0x100 {
            vec![0x58, n as u8]
        } else if n < 0x10000 {
            vec![0x59, (n >> 8) as u8, n as u8]
        } else {
            vec![
                0x5A,
                (n >> 24) as u8,
                (n >> 16) as u8,
                (n >> 8) as u8,
                n as u8,
            ]
        };
        hdr.extend_from_slice(data);
        hdr
    }
}
