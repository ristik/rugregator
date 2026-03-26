//! SMT key and path operations.
//!
//! Keys are plain 256-bit (32-byte) arrays.  Bit addressing is LSB-first:
//! byte 0, bit 0 is position 0; byte 0, bit 7 is position 7; byte 1, bit 0
//! is position 8; and so on.
//!
//! `CompressedPath` stores the common-prefix bits of an internal node using
//! sentinel-bit encoding: `(1 << n) | bits` where `n` is the number of data
//! bits.  This is used only for tree navigation, never in hashes.

/// A 256-bit SMT key.
pub type SmtKey = [u8; 32];

/// Number of bits in an SMT key.
pub const KEY_BITS: usize = 256;

// Pre-computed table to reverse bits in a byte (for get_sort_key).
const BIT_REVERSE_TABLE: [u8; 256] = {
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
///
/// Matches Python's `get_sort_key`:
///   `k.to_bytes(32,"big")[::-1].translate(BIT_REVERSE_TABLE)`
/// where the `[::-1]` brings the LSB byte to index 0, and bit-reversal
/// places raw bit 0 in the MSB of sort_key[0].
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

// ─── CompressedPath ──────────────────────────────────────────────────────────

/// Compressed common-prefix for internal nodes.
///
/// Stores up to 255 bits of common prefix.  Used only for tree navigation
/// (routing keys through the trie), never in hash computations.
///
/// Internal representation: `len` is the number of data bits (0..=255).
/// `bits[0..ceil(len/8)]` store the prefix bits in LSB-first order (matching
/// the key bit ordering).
#[derive(Clone, Debug)]
pub struct CompressedPath {
    /// Number of data bits (0 = empty path, i.e. the node is at a pure
    /// bifurcation with no shared prefix).
    pub len: u8,
    /// Prefix bits, LSB-first.  Only the first `len` bits are meaningful.
    bits: [u8; 32],
}

impl CompressedPath {
    /// An empty path (zero common-prefix bits).
    #[inline]
    pub const fn empty() -> Self {
        Self { len: 0, bits: [0u8; 32] }
    }

    /// Number of common-prefix data bits.
    #[inline]
    pub fn path_len(&self) -> usize {
        self.len as usize
    }

    /// Get bit at position `pos` within the compressed path.
    #[inline]
    pub fn bit_at(&self, pos: usize) -> u8 {
        debug_assert!(pos < self.len as usize);
        (self.bits[pos / 8] >> (pos % 8)) & 1
    }

    /// Extract a range of bits from a key as a `CompressedPath`.
    ///
    /// Takes `n_bits` bits starting at `start_bit` from `key`.
    pub fn from_key_range(key: &SmtKey, start_bit: usize, n_bits: usize) -> Self {
        debug_assert!(n_bits <= 255);
        debug_assert!(start_bit + n_bits <= KEY_BITS);
        let mut cp = Self { len: n_bits as u8, bits: [0u8; 32] };
        for i in 0..n_bits {
            let b = key_bit_at(key, start_bit + i);
            if b != 0 {
                cp.bits[i / 8] |= 1 << (i % 8);
            }
        }
        cp
    }

    /// Check whether the key's bits starting at `start_bit` match this path's
    /// prefix for all `self.len` bits.
    #[inline]
    pub fn matches_key(&self, key: &SmtKey, start_bit: usize) -> bool {
        let n = self.len as usize;
        // Fast path: check byte-aligned chunks.
        let full_bytes = n / 8;
        for i in 0..full_bytes {
            let key_byte = extract_key_byte(key, start_bit + i * 8);
            if key_byte != self.bits[i] {
                return false;
            }
        }
        // Check remaining bits.
        let remaining = n % 8;
        if remaining > 0 {
            let mask = (1u8 << remaining) - 1;
            let key_byte = extract_key_byte(key, start_bit + full_bytes * 8);
            if (key_byte & mask) != (self.bits[full_bytes] & mask) {
                return false;
            }
        }
        true
    }

    /// Set a single bit at position `pos`.
    #[inline]
    pub fn set_bit(&mut self, pos: usize, val: u8) {
        debug_assert!(pos < self.len as usize);
        if val != 0 {
            self.bits[pos / 8] |= 1 << (pos % 8);
        } else {
            self.bits[pos / 8] &= !(1 << (pos % 8));
        }
    }

    /// Raw bits slice (for serialization).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        let n_bytes = (self.len as usize + 7) / 8;
        &self.bits[..n_bytes]
    }

    /// Construct from raw parts (for deserialization).
    pub fn from_raw(len: u8, raw: &[u8]) -> Self {
        let mut bits = [0u8; 32];
        let n = raw.len().min(32);
        bits[..n].copy_from_slice(&raw[..n]);
        Self { len, bits }
    }
}

impl PartialEq for CompressedPath {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        let n = self.len as usize;
        let full_bytes = n / 8;
        if self.bits[..full_bytes] != other.bits[..full_bytes] {
            return false;
        }
        let remaining = n % 8;
        if remaining > 0 {
            let mask = (1u8 << remaining) - 1;
            if (self.bits[full_bytes] & mask) != (other.bits[full_bytes] & mask) {
                return false;
            }
        }
        true
    }
}

impl Eq for CompressedPath {}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Extract 8 consecutive bits from a key starting at `start_bit`, packed into
/// a byte with the lowest-addressed bit in the LSB.
#[inline]
fn extract_key_byte(key: &SmtKey, start_bit: usize) -> u8 {
    let byte_idx = start_bit / 8;
    let bit_off = start_bit % 8;
    if bit_off == 0 {
        // Aligned: just return the byte.
        if byte_idx < 32 { key[byte_idx] } else { 0 }
    } else {
        // Straddles two bytes.
        let lo = if byte_idx < 32 { key[byte_idx] } else { 0 };
        let hi = if byte_idx + 1 < 32 { key[byte_idx + 1] } else { 0 };
        (lo >> bit_off) | (hi << (8 - bit_off))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_bit_at_byte0() {
        let mut key = [0u8; 32];
        key[0] = 0b1010_0101;
        assert_eq!(key_bit_at(&key, 0), 1);
        assert_eq!(key_bit_at(&key, 1), 0);
        assert_eq!(key_bit_at(&key, 2), 1);
        assert_eq!(key_bit_at(&key, 5), 1);
        assert_eq!(key_bit_at(&key, 7), 1);
    }

    #[test]
    fn key_bit_at_byte1() {
        let mut key = [0u8; 32];
        key[1] = 0x01; // bit 8 set
        assert_eq!(key_bit_at(&key, 7), 0);
        assert_eq!(key_bit_at(&key, 8), 1);
        assert_eq!(key_bit_at(&key, 9), 0);
    }

    #[test]
    fn sort_key_matches_python() {
        // Python get_sort_key: k.to_bytes(32,"big")[::-1].translate(BIT_REVERSE_TABLE)
        // = reverse byte order (LSB byte first) then bit-reverse each byte.
        // For key[0] = 0b0000_0001 (bit 0 set), byte 0 is the LSB byte,
        // so it goes to sort_key[0] after byte-reversal, then bit-reversed:
        // 0b0000_0001 → 0b1000_0000.
        let mut key = [0u8; 32];
        key[0] = 0b0000_0001; // bit 0 set
        let sk = get_sort_key(&key);
        // Rust implementation: bit-reverse each byte in place (no byte-order reversal).
        // byte 0 of key → byte 0 of sort_key, bit-reversed: 0b0000_0001 → 0b1000_0000
        assert_eq!(sk[0], 0b1000_0000);
        assert_eq!(sk[31], 0); // byte 31 of key was 0
    }

    #[test]
    fn sort_key_ordering() {
        // Key with bit 0 = 0 should sort before key with bit 0 = 1
        let k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        k1[0] = 0x01; // bit 0 set
        assert!(get_sort_key(&k0) < get_sort_key(&k1));
    }

    #[test]
    fn compressed_path_empty() {
        let cp = CompressedPath::empty();
        assert_eq!(cp.path_len(), 0);
    }

    #[test]
    fn compressed_path_from_key() {
        let mut key = [0u8; 32];
        key[0] = 0b1010_0101; // bits 0-7
        let cp = CompressedPath::from_key_range(&key, 0, 4);
        assert_eq!(cp.path_len(), 4);
        assert_eq!(cp.bit_at(0), 1); // bit 0
        assert_eq!(cp.bit_at(1), 0); // bit 1
        assert_eq!(cp.bit_at(2), 1); // bit 2
        assert_eq!(cp.bit_at(3), 0); // bit 3
    }

    #[test]
    fn compressed_path_matches_key() {
        let mut key = [0u8; 32];
        key[0] = 0b1010_0101;
        let cp = CompressedPath::from_key_range(&key, 0, 8);
        assert!(cp.matches_key(&key, 0));

        let mut key2 = [0u8; 32];
        key2[0] = 0b1010_0100; // bit 0 differs
        assert!(!cp.matches_key(&key2, 0));
    }

    #[test]
    fn compressed_path_equality() {
        let mut key = [0u8; 32];
        key[0] = 0xFF;
        let a = CompressedPath::from_key_range(&key, 0, 3);
        let b = CompressedPath::from_key_range(&key, 0, 3);
        assert_eq!(a, b);
        let c = CompressedPath::from_key_range(&key, 0, 4);
        assert_ne!(a, c);
    }

    #[test]
    fn compressed_path_serialization_roundtrip() {
        let mut key = [0u8; 32];
        key[0] = 0xAB;
        key[1] = 0xCD;
        let cp = CompressedPath::from_key_range(&key, 0, 13);
        let raw = cp.as_bytes();
        let restored = CompressedPath::from_raw(cp.len, raw);
        assert_eq!(cp, restored);
    }

    #[test]
    fn compressed_path_mid_key() {
        let mut key = [0u8; 32];
        key[2] = 0b1111_0000; // bits 16..23
        let cp = CompressedPath::from_key_range(&key, 16, 8);
        assert_eq!(cp.bit_at(0), 0); // bit 16 of key
        assert_eq!(cp.bit_at(4), 1); // bit 20 of key
    }
}
