//! secp256k1 signature verification.
//!
//! Unicity signature format: `[R(32) || S(32) || V(1)]` (65 bytes).
//! This is the inverse of btcec's `[V || R || S]` compact format.
//!
//! Verification is done by recovering the public key from the signature and
//! comparing it to the expected key (matches Go `VerifyHashWithPublicKey`).

use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("signature must be exactly 65 bytes, got {0}")]
    InvalidLength(usize),
    #[error("invalid recovery id {0}")]
    InvalidRecoveryId(u8),
    #[error("secp256k1 error: {0}")]
    Secp(#[from] secp256k1::Error),
    #[error("signature r and s must each be in [1, n-1]")]
    ScalarOutOfRange,
    #[error("non-canonical high-s signature (s > n/2)")]
    HighS,
    #[error("signature verification failed: recovered key does not match")]
    Mismatch,
}

/// Verify a Unicity-format secp256k1 signature.
///
/// `hash` is the raw 32-byte SHA-256 digest (NOT the imprint).
/// `sig` is the 65-byte `[R || S || V]` witness.
/// `pubkey` is the 33-byte compressed public key from the predicate.
///
/// Matches Go `VerifyHashWithPublicKey`. A signature is valid only if
/// `1 <= r < n`, `1 <= s <= n/2` (low-S, as the SDKs require), the recovery id is
/// in 0..=3, and the recovered key equals `pubkey`. Admission only: the high-S twin
/// of an owner's signature recovers to the same key, so it must be refused here or
/// it can pre-empt the owner's request and leave a proof the SDKs reject.
pub fn verify_signature(hash: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> Result<(), SignatureError> {
    if sig.len() != 65 {
        return Err(SignatureError::InvalidLength(sig.len()));
    }

    // Unicity: [R(32) | S(32) | V(1)]  →  btcec/secp256k1: [V | R(32) | S(32)]
    // V in Unicity is 0 or 1 (recovery bit); btcec uses 31/32 for compressed keys.
    // secp256k1 crate uses RecoveryId::from_i32(0|1) directly.
    let rs = &sig[..64];
    let v = sig[64];

    let recovery_id =
        RecoveryId::from_i32(v as i32).map_err(|_| SignatureError::InvalidRecoveryId(v))?;

    if rs[..32].iter().all(|b| *b == 0) || rs[32..].iter().all(|b| *b == 0) {
        return Err(SignatureError::ScalarOutOfRange);
    }
    // from_compact rejects r or s >= n.
    let recoverable = RecoverableSignature::from_compact(rs, recovery_id)?;

    let mut standard = recoverable.to_standard();
    standard.normalize_s();
    if standard.serialize_compact()[..] != rs[..] {
        return Err(SignatureError::HighS);
    }

    let msg = Message::from_digest(*hash);
    let secp = Secp256k1::verification_only();

    let recovered = secp.recover_ecdsa(&msg, &recoverable)?;
    let expected = PublicKey::from_slice(pubkey)?;

    if recovered != expected {
        return Err(SignatureError::Mismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    fn sign_unicity(hash: &[u8; 32], sk: &SecretKey) -> Vec<u8> {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(*hash);
        let (recovery_id, compact) = secp.sign_ecdsa_recoverable(&msg, sk).serialize_compact();
        // Convert [R||S] + recovery_id → [R||S||V] (Unicity format)
        let mut sig = vec![0u8; 65];
        sig[..64].copy_from_slice(&compact);
        sig[64] = recovery_id.to_i32() as u8;
        sig
    }

    #[test]
    fn valid_signature_accepted() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk)
            .serialize()
            .to_vec();

        let hash = Sha256::digest(b"test message").into();
        let sig = sign_unicity(&hash, &sk);

        assert!(verify_signature(&hash, &sig, &pk).is_ok());
    }

    #[test]
    fn wrong_key_rejected() {
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let pk2 = secp256k1::PublicKey::from_secret_key(&secp, &sk2)
            .serialize()
            .to_vec();

        let hash = Sha256::digest(b"test message").into();
        let sig = sign_unicity(&hash, &sk1);

        assert!(matches!(
            verify_signature(&hash, &sig, &pk2),
            Err(SignatureError::Mismatch)
        ));
    }

    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    /// n - s for a 32-byte big-endian s < n.
    fn n_minus(s: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = N[i] as i16 - s[i] as i16 - borrow;
            borrow = if d < 0 {
                d += 256;
                1
            } else {
                0
            };
            out[i] = d as u8;
        }
        out
    }

    fn fixture() -> ([u8; 32], Vec<u8>, Vec<u8>) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk)
            .serialize()
            .to_vec();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();
        let sig = sign_unicity(&hash, &sk);
        (hash, sig, pk)
    }

    fn twin(sig: &[u8], flip_v: bool) -> Vec<u8> {
        let mut t = sig.to_vec();
        t[32..64].copy_from_slice(&n_minus(&sig[32..64]));
        if flip_v {
            t[64] ^= 1;
        }
        t
    }

    #[test]
    fn signer_output_is_low_s_and_accepted() {
        let (hash, sig, pk) = fixture();
        assert!(verify_signature(&hash, &sig, &pk).is_ok());
    }

    #[test]
    fn high_s_twin_with_flipped_v_rejected() {
        let (hash, sig, pk) = fixture();
        assert!(matches!(
            verify_signature(&hash, &twin(&sig, true), &pk),
            Err(SignatureError::HighS)
        ));
    }

    #[test]
    fn high_s_twin_with_original_v_rejected() {
        let (hash, sig, pk) = fixture();
        assert!(matches!(
            verify_signature(&hash, &twin(&sig, false), &pk),
            Err(SignatureError::HighS)
        ));
    }

    #[test]
    fn out_of_range_scalars_rejected() {
        let (hash, sig, pk) = fixture();
        let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut s = sig.clone();
            f(&mut s);
            verify_signature(&hash, &s, &pk)
        };
        assert!(mutate(&|s| s[32..64].fill(0)).is_err(), "s = 0");
        assert!(mutate(&|s| s[..32].fill(0)).is_err(), "r = 0");
        assert!(mutate(&|s| s[32..64].copy_from_slice(&N)).is_err(), "s = n");
        assert!(mutate(&|s| s[32..64].fill(0xFF)).is_err(), "s > n");
        assert!(mutate(&|s| s[..32].copy_from_slice(&N)).is_err(), "r = n");
        assert!(mutate(&|s| s[64] = 4).is_err(), "v = 4");
    }

    #[test]
    fn bad_length_rejected() {
        let hash = [0u8; 32];
        let sig = vec![0u8; 64]; // wrong length
        assert!(matches!(
            verify_signature(&hash, &sig, &[0u8; 33]),
            Err(SignatureError::InvalidLength(64))
        ));
    }
}
