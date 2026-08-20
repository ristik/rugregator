//! SMT hash functions — domain-separated SHA-256 (RSMT v6a).
//!
//! **Leaf:**  `H(0x00 || key_32B || value)`
//! **Node:**  `H(0x01 || depth_1B || region_32B || left_hash_32B || right_hash_32B)`
//!
//! ## SP1 zkVM acceleration
//!
//! On `riscv64im-succinct-zkvm-elf` (SP1 6.x) the SHA-256 syscall precompile
//! is called directly via `extern "C"` declarations that resolve to the
//! `no_mangle` symbols exported by `sp1-zkvm`.  This avoids the  riscv32
//! sha2 patch (which checks if `target_arch = "riscv32"` and therefore never
//! activates on SP1 6.x's riscv64 target).
//!
//! On all other targets the standard `sha2` crate is used.

use crate::path::SmtKey;

// ─── Trait ───────────────────────────────────────────────────────────────────

/// A zero-sized type that provides the two SMT hash functions.
pub trait SmtHasher: Copy + Send + Sync + 'static {
    /// Hash a leaf: `H(0x00 || key || value)`.
    fn hash_leaf(key: &SmtKey, value: &[u8]) -> [u8; 32];
    /// Hash an internal node: `H(0x01 || depth || region || left_hash || right_hash)`.
    fn hash_node(left: &[u8; 32], right: &[u8; 32], depth: u8, region: &[u8; 32]) -> [u8; 32];
}

// ─── SHA-256 (default) ────────────────────────────────────────────────────────

/// Domain-separated SHA-256 hasher.  This is the default.
///
/// On SP1 6.x (riscv64 zkVM target) SHA-256 blocks are computed via the
/// `SHA_COMPRESS` / `SHA_EXTEND` precompile syscalls for full acceleration.
/// On all other targets the `sha2` crate is used.
#[derive(Copy, Clone, Debug, Default)]
pub struct Sha256Hasher;

impl SmtHasher for Sha256Hasher {
    #[inline]
    fn hash_leaf(key: &SmtKey, value: &[u8]) -> [u8; 32] {
        sha256_parts(&[&[0x00], key.as_slice(), value])
    }

    #[inline]
    fn hash_node(left: &[u8; 32], right: &[u8; 32], depth: u8, region: &[u8; 32]) -> [u8; 32] {
        sha256_parts(&[
            &[0x01, depth],
            region.as_slice(),
            left.as_slice(),
            right.as_slice(),
        ])
    }
}

// ─── Platform dispatch ────────────────────────────────────────────────────────

/// Hash the concatenation of the given slices with SHA-256, using the SP1
/// precompile where available.
#[inline]
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(all(
        target_os = "zkvm",
        target_vendor = "succinct",
        target_arch = "riscv64"
    ))]
    {
        zkvm::sha256_parts(parts)
    }
    #[cfg(not(all(
        target_os = "zkvm",
        target_vendor = "succinct",
        target_arch = "riscv64"
    )))]
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }
}

// ─── SP1 zkVM path ───────────────────────────────────────────────────────────

#[cfg(all(
    target_os = "zkvm",
    target_vendor = "succinct",
    target_arch = "riscv64"
))]
mod zkvm {
    //! Minimal SHA-256 implementation that calls SP1 6.x syscall precompiles.
    //!
    //! Memory layout (as observed from sp1-core-executor 6.0.2 source):
    //! - State:            `[u64; 8]`  — one SHA-256 u32 word per u64 slot
    //! - Message schedule: `[u64; 64]` — one SHA-256 u32 word per u64 slot
    //!
    //! `syscall_sha256_extend` fills W[16..64] from W[0..16].
    //! `syscall_sha256_compress` runs the 64 compression rounds and writes
    //! the updated state back into the state array in place.

    extern "C" {
        /// Expand message schedule W[0..16] to W[0..64] in place.
        fn syscall_sha256_extend(w: *mut [u64; 64]);
        /// Compress 64-word message schedule into state, updating state in place.
        fn syscall_sha256_compress(w: *mut [u64; 64], state: *mut [u64; 8]);
    }

    /// SHA-256 initial hash values (first 32 bits of fractional parts of √primes).
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// Incremental SHA-256 context (stack-only, no alloc).
    struct Ctx {
        /// SHA-256 working state; u32 words stored in lower 32 bits of each u64.
        state: [u64; 8],
        /// Partial block buffer (not yet compressed).
        buf: [u8; 64],
        /// Total message bytes fed so far (used for length padding).
        len: u64,
        /// Number of valid bytes in `buf`.
        pos: usize,
    }

    impl Ctx {
        fn new() -> Self {
            let mut state = [0u64; 8];
            for i in 0..8 {
                state[i] = IV[i] as u64;
            }
            Self {
                state,
                buf: [0u8; 64],
                len: 0,
                pos: 0,
            }
        }

        fn update(&mut self, data: &[u8]) {
            let mut offset = 0;
            while offset < data.len() {
                let take = (64 - self.pos).min(data.len() - offset);
                self.buf[self.pos..self.pos + take].copy_from_slice(&data[offset..offset + take]);
                self.pos += take;
                self.len += take as u64;
                offset += take;
                if self.pos == 64 {
                    self.compress_block();
                }
            }
        }

        /// Compress `self.buf` as a 64-byte block; reset buf and pos afterwards.
        fn compress_block(&mut self) {
            let mut w = [0u64; 64];
            for i in 0..16 {
                let b = &self.buf[i * 4..(i + 1) * 4];
                w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
            }
            // SAFETY: w and self.state are valid, non-overlapping, aligned buffers.
            unsafe {
                syscall_sha256_extend(&mut w as *mut [u64; 64]);
                syscall_sha256_compress(&mut w as *mut [u64; 64], &mut self.state as *mut [u64; 8]);
            }
            self.pos = 0;
            self.buf = [0u8; 64];
        }

        fn finalize(mut self) -> [u8; 32] {
            // Record original bit length before any padding.
            let bit_len = self.len * 8;

            // Append 0x80 padding byte.
            self.buf[self.pos] = 0x80;
            self.pos += 1;

            // If the current block has no room for the 8-byte length field
            // (positions 56..64), flush and start a fresh (all-zero) block.
            if self.pos > 56 {
                // buf[pos..64] are already zero (buf is zeroed after each compress).
                self.compress_block(); // resets pos=0, buf=zeroed
            }

            // buf[pos..56] are already zero; write big-endian bit length at 56..64.
            let len_bytes = bit_len.to_be_bytes();
            self.buf[56..64].copy_from_slice(&len_bytes);
            self.compress_block();

            // Serialise state as big-endian u32 words.
            let mut digest = [0u8; 32];
            for i in 0..8 {
                let word = self.state[i] as u32;
                digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
            }
            digest
        }
    }

    /// Hash the concatenation of `parts` with SHA-256 using SP1 syscall precompiles.
    pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
        let mut ctx = Ctx::new();
        for p in parts {
            ctx.update(p);
        }
        ctx.finalize()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let key = [1u8; 32];
        assert_eq!(
            Sha256Hasher::hash_leaf(&key, b"hello"),
            Sha256Hasher::hash_leaf(&key, b"hello")
        );
        assert_ne!(
            Sha256Hasher::hash_leaf(&key, b"hello"),
            Sha256Hasher::hash_leaf(&key, b"world")
        );
    }

    #[test]
    fn domain_separation() {
        let lh = Sha256Hasher::hash_leaf(&[0u8; 32], &[0u8; 64]);
        let nh = Sha256Hasher::hash_node(&[0u8; 32], &[0u8; 32], 0, &[0u8; 32]);
        assert_ne!(lh, nh);
    }

    #[test]
    fn depth_matters() {
        let l = [1u8; 32];
        let r = [2u8; 32];
        let region = [0u8; 32];
        assert_ne!(
            Sha256Hasher::hash_node(&l, &r, 0, &region),
            Sha256Hasher::hash_node(&l, &r, 1, &region)
        );
    }

    #[test]
    fn region_matters() {
        let l = [1u8; 32];
        let r = [2u8; 32];
        let region_a = [0u8; 32];
        let mut region_b = [0u8; 32];
        region_b[0] = 0x80;
        assert_ne!(
            Sha256Hasher::hash_node(&l, &r, 1, &region_a),
            Sha256Hasher::hash_node(&l, &r, 1, &region_b)
        );
    }

    /// Cross-check Sha256Hasher output against a raw sha2::Sha256 reference.
    /// Also confirms SP1 sha256 precompile path works when running in zkVM.
    #[test]
    fn hash_matches_reference() {
        use sha2::{Digest, Sha256};
        let key = [0xabu8; 32];
        let val = b"test value";
        let got = Sha256Hasher::hash_leaf(&key, val);
        let expected: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([0x00u8]);
            h.update(key);
            h.update(val);
            h.finalize().into()
        };
        assert_eq!(
            got, expected,
            "Sha256Hasher must produce standard SHA-256 output"
        );
    }
}
