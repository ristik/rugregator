//! SMT key primitives needed by the consistency proof verifier.
//!
//! Keys are plain 256-bit (32-byte) arrays, read as big-endian bit strings
//! (RSMT v6a): bit 0 is the most-significant bit of byte 0, bit 7 is the
//! least-significant bit of byte 0, bit 8 is the most-significant bit of
//! byte 1, and so on. Byte order itself (byte 0 first) is unchanged.

/// A 256-bit SMT key.
pub type SmtKey = [u8; 32];

/// Number of bits in an SMT key.
pub const KEY_BITS: usize = 256;

// ─── Bit access ──────────────────────────────────────────────────────────────

/// Get the bit at `pos` from a 256-bit key (MSB-first / big-endian).
///
/// `pos = 0` is the MSB of byte 0.  `pos = 255` is the LSB of byte 31.
#[inline]
pub fn key_bit_at(key: &SmtKey, pos: usize) -> u8 {
    debug_assert!(pos < KEY_BITS);
    (key[pos / 8] >> (7 - pos % 8)) & 1
}

/// Pack the `depth`-bit region (key prefix `[0..depth)`) into a 32-byte
/// big-endian bit string: the prefix occupies the first `depth` bits and
/// the remaining suffix bits are zero. Together with `depth`, this packing
/// is injective (RSMT v6a node-hash region commitment).
#[inline]
pub fn prefix_region(key: &SmtKey, depth: usize) -> SmtKey {
    debug_assert!(depth <= KEY_BITS);
    let mut region = [0u8; 32];
    let full_bytes = depth / 8;
    let partial_bits = depth % 8;
    region[..full_bytes].copy_from_slice(&key[..full_bytes]);
    if partial_bits != 0 {
        let mask = 0xffu8 << (8 - partial_bits);
        region[full_bytes] = key[full_bytes] & mask;
    }
    region
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_bit_at_byte0_msb_first() {
        let mut key = [0u8; 32];
        key[0] = 0b1100_0010; // MSB-first bits: 1,1,0,0,0,0,1,0
        assert_eq!(key_bit_at(&key, 0), 1);
        assert_eq!(key_bit_at(&key, 1), 1);
        assert_eq!(key_bit_at(&key, 2), 0);
        assert_eq!(key_bit_at(&key, 6), 1);
        assert_eq!(key_bit_at(&key, 7), 0);
    }

    #[test]
    fn key_bit_at_byte1() {
        let mut key = [0u8; 32];
        key[1] = 0b1000_0000; // MSB of byte 1 = bit position 8
        assert_eq!(key_bit_at(&key, 7), 0);
        assert_eq!(key_bit_at(&key, 8), 1);
        assert_eq!(key_bit_at(&key, 9), 0);
    }

    #[test]
    fn prefix_region_zero_depth_is_empty() {
        let key = [0xFFu8; 32];
        assert_eq!(prefix_region(&key, 0), [0u8; 32]);
    }

    #[test]
    fn prefix_region_byte_aligned() {
        let mut key = [0u8; 32];
        key[0] = 0xAB;
        key[1] = 0xCD;
        let region = prefix_region(&key, 8);
        let mut expected = [0u8; 32];
        expected[0] = 0xAB;
        assert_eq!(region, expected);
    }

    #[test]
    fn prefix_region_partial_byte() {
        let mut key = [0u8; 32];
        key[0] = 0b1111_1111;
        // depth = 3: keep the top 3 bits, clear the rest.
        let region = prefix_region(&key, 3);
        let mut expected = [0u8; 32];
        expected[0] = 0b1110_0000;
        assert_eq!(region, expected);
    }

    #[test]
    fn prefix_region_full_depth_is_key() {
        let key = [0xA5u8; 32];
        assert_eq!(prefix_region(&key, KEY_BITS), key);
    }
}
