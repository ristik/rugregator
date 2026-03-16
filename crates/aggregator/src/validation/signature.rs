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
    #[error("signature verification failed: recovered key does not match")]
    Mismatch,
}

/// Verify a Unicity-format secp256k1 signature.
///
/// `hash` is the raw 32-byte SHA-256 digest (NOT the imprint).
/// `sig` is the 65-byte `[R || S || V]` witness.
/// `pubkey` is the 33-byte compressed public key from the predicate.
///
/// Matches Go `VerifyHashWithPublicKey`.
pub fn verify_signature(
    hash: &[u8; 32],
    sig: &[u8],
    pubkey: &[u8],
) -> Result<(), SignatureError> {
    if sig.len() != 65 {
        return Err(SignatureError::InvalidLength(sig.len()));
    }

    // Unicity: [R(32) | S(32) | V(1)]  →  btcec/secp256k1: [V | R(32) | S(32)]
    // V in Unicity is 0 or 1 (recovery bit); btcec uses 31/32 for compressed keys.
    // secp256k1 crate uses RecoveryId::from_i32(0|1) directly.
    let rs = &sig[..64];
    let v = sig[64];

    let recovery_id = RecoveryId::from_i32(v as i32)
        .map_err(|_| SignatureError::InvalidRecoveryId(v))?;

    let recoverable = RecoverableSignature::from_compact(rs, recovery_id)?;

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
        let (recovery_id, compact) = secp
            .sign_ecdsa_recoverable(&msg, sk)
            .serialize_compact();
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
