//! SMT key primitives needed by the consistency proof verifier.
//!
//! Keys are plain 256-bit (32-byte) arrays.  Bit addressing is LSB-first:
//! byte 0, bit 0 is position 0; byte 0, bit 7 is position 7; byte 1, bit 0
//! is position 8; and so on.

/// A 256-bit SMT key.
pub type SmtKey = [u8; 32];

/// Number of bits in an SMT key.
pub const KEY_BITS: usize = 256;

// Pre-computed table to reverse bits in a byte (for get_sort_key).
pub(crate) const BIT_REVERSE_TABLE: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut reversed = 0u8;
        let mut bit = 0;
        while bit < 8 {
            if (i >> bit) & 1 != 0 {
                reversed |= 1 << (7 - bit);
            }
            bit += 1;
        }
        table[i] = reversed;
        i += 1;
    }
    table
};

// ─── Bit access ──────────────────────────────────────────────────────────────

/// Get the bit at `pos` from a 256-bit key (LSB-first).
///
/// `pos = 0` is bit 0 of byte 0.  `pos = 255` is bit 7 of byte 31.
#[inline]
pub fn key_bit_at(key: &SmtKey, pos: usize) -> u8 {
    debug_assert!(pos < KEY_BITS);
    (key[pos / 8] >> (pos % 8)) & 1
}

// ─── Sort key ────────────────────────────────────────────────────────────────

/// Convert a key to LSB-first lexicographic sort order.
///
/// Bit-reverse each byte in place (no byte-order reversal).  This makes
/// bit 0 the most-significant bit in sort_key[0], producing true LSB-first
/// ordering: items differing at bit 0 are separated first, then bit 1, etc.
#[inline]
pub fn get_sort_key(key: &SmtKey) -> SmtKey {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = BIT_REVERSE_TABLE[key[i] as usize];
        i += 1;
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_key_bit0() {
        let mut key = [0u8; 32];
        key[0] = 0b0000_0001;
        let sk = get_sort_key(&key);
        assert_eq!(sk[0], 0b1000_0000);
        assert_eq!(sk[31], 0);
    }

    #[test]
    fn sort_key_ordering() {
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x01;
        assert!(get_sort_key(&k0) < get_sort_key(&k1));
    }

    #[test]
    fn key_bit_at_byte0() {
        let mut key = [0u8; 32];
        key[0] = 0b1010_0101;
        assert_eq!(key_bit_at(&key, 0), 1);
        assert_eq!(key_bit_at(&key, 1), 0);
        assert_eq!(key_bit_at(&key, 2), 1);
        assert_eq!(key_bit_at(&key, 7), 1);
    }
}
