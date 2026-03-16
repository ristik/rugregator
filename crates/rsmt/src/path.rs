//! SMT path operations – sentinel-encoded BigUint paths.
//!
//! Sentinel-bit encoding (identical to Go/Python): `path = (1 << k) | bits`
//! where k is the number of data bits.  Bit 0 is the LSB.
//!
//! Root path = BigUint(1): sentinel at bit 0, zero data bits.

use num_bigint::BigUint;
use num_traits::{One, Zero};

/// An SMT path with a sentinel high bit.
pub type SmtPath = BigUint;

// ─── Basic path accessors ────────────────────────────────────────────────────

/// Number of data bits in the path (bit-length minus the sentinel).
/// Matches Go `path.BitLen() - 1`.
#[inline]
pub fn path_len(p: &SmtPath) -> usize {
    p.bits() as usize - 1
}

/// Big-endian byte encoding of the path (matches Go `BigintEncode`).
/// Zero produces an empty slice.
pub fn path_as_bytes(p: &SmtPath) -> Vec<u8> {
    if p.is_zero() {
        return vec![];
    }
    p.to_bytes_be()
}

/// Decimal string of the path (used in proof steps and JSON).
pub fn path_to_decimal(p: &SmtPath) -> String {
    p.to_str_radix(10)
}

// ─── Bit access ──────────────────────────────────────────────────────────────

/// Get the bit at `pos` (LSB = 0).  Returns 0 or 1.
#[inline]
pub fn bit_at(n: &BigUint, pos: usize) -> u8 {
    // to_bytes_le gives the little-endian bytes, so byte 0 has the LSB.
    let bytes = n.to_bytes_le();
    let byte_idx = pos / 8;
    if byte_idx >= bytes.len() {
        return 0;
    }
    (bytes[byte_idx] >> (pos % 8)) & 1
}

// ─── Path derivation ─────────────────────────────────────────────────────────

/// Convert a 32-byte StateID (V2 imprint) to an SMT path.
///
/// Matches Go `ImprintV2.GetPath()`:
///   1. Pad 32-byte input with two leading zero bytes → 34 bytes.
///   2. Prepend 0x01 sentinel byte → 35 bytes.
///   3. Interpret big-endian → BigUint.
///
/// The resulting BigUint has `bits() == 273`, `path_len == 272`.
pub fn state_id_to_smt_path(state_id: &[u8]) -> SmtPath {
    let padded: Vec<u8> = if state_id.len() == 32 {
        let mut buf = vec![0u8; 34];
        buf[2..].copy_from_slice(state_id);
        buf
    } else {
        state_id.to_vec()
    };
    // 0x01 sentinel preserves leading zero bits in the hash.
    let mut key_bytes = vec![0x01u8];
    key_bytes.extend_from_slice(&padded);
    BigUint::from_bytes_be(&key_bytes)
}

/// The root path: BigUint(1) — sentinel at bit 0, no data bits.
#[inline]
pub fn root_path() -> SmtPath {
    BigUint::one()
}

// ─── calculateCommonPath ─────────────────────────────────────────────────────

/// Longest common LSB-first prefix of two paths.
///
/// Matches Go `calculateCommonPath(path1, path2 *big.Int) *big.Int`:
///   - Iterates bits 0..min_len-1 from LSB until they diverge.
///   - Returns a BigUint with sentinel at the first diverging bit.
///
/// # Panics
/// Panics if either path is zero (identical to the Go panic).
pub fn calculate_common_path(path1: &SmtPath, path2: &SmtPath) -> SmtPath {
    debug_assert!(!path1.is_zero() && !path2.is_zero(), "non-positive path value");

    let max_pos = (std::cmp::min(path1.bits(), path2.bits()) as usize).saturating_sub(1);
    let mut pos = 0usize;

    while pos < max_pos && bit_at(path1, pos) == bit_at(path2, pos) {
        pos += 1;
    }

    // mask = 1 << pos
    let mask = BigUint::one() << pos;
    // res = ((mask - 1) & path1) | mask
    (&mask - BigUint::one() & path1) | &mask
}

// ─── Shift helper ────────────────────────────────────────────────────────────

/// Right-shift by `shift` bits (like Go `new(big.Int).Rsh(n, shift)`).
#[inline]
pub fn rsh(n: &SmtPath, shift: usize) -> SmtPath {
    if shift == 0 {
        return n.clone();
    }
    n >> shift
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::*;
    use num_traits::{One, Zero};

    #[test]
    fn state_id_all_zeros_gives_272_bit_path() {
        let state_id = [0u8; 32];
        let path = state_id_to_smt_path(&state_id);
        // 0x01 || [0u8;34] → BigUint with 273 bits (MSB is the 0x01 sentinel)
        assert_eq!(path.bits(), 273);
        assert_eq!(path_len(&path), 272);
    }

    #[test]
    fn state_id_non_zero_sentinel_preserved() {
        let mut state_id = [0u8; 32];
        state_id[31] = 0xff; // LSB of the hash
        let path = state_id_to_smt_path(&state_id);
        assert_eq!(path.bits(), 273); // sentinel always at bit 272
    }

    #[test]
    fn common_path_identical() {
        let p = BigUint::from(0b101u32);
        assert_eq!(calculate_common_path(&p, &p), p);
    }

    #[test]
    fn common_path_diverge_at_bit0() {
        // 0b10 (bit0=0) vs 0b11 (bit0=1) → diverge immediately
        let p1 = BigUint::from(0b10u32);
        let p2 = BigUint::from(0b11u32);
        // mask = 1, lower = 0, res = 0 & p1 | 1 = 1
        assert_eq!(calculate_common_path(&p1, &p2), BigUint::one());
    }

    #[test]
    fn common_path_diverge_at_bit1() {
        // 0b100 (bit0=0,bit1=0) vs 0b110 (bit0=0,bit1=1) → diverge at pos=1
        let p1 = BigUint::from(0b100u32);
        let p2 = BigUint::from(0b110u32);
        // pos=1: mask=2, lower=1, res = (1 & p1) | 2 = 0|2 = 2
        assert_eq!(calculate_common_path(&p1, &p2), BigUint::from(0b10u32));
    }

    #[test]
    fn path_as_bytes_zero() {
        assert!(path_as_bytes(&BigUint::zero()).is_empty());
    }

    #[test]
    fn path_as_bytes_one() {
        assert_eq!(path_as_bytes(&BigUint::one()), vec![0x01]);
    }
}
