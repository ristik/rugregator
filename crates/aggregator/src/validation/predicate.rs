//! PayToPublicKey predicate validation.
//!
//! A valid predicate must satisfy (from the Go validator):
//!   - engine  = 1
//!   - code    = [0x01]  (1 byte)
//!   - params  = compressed secp256k1 public key (33 bytes, starts with 02 or 03)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PredicateError {
    #[error("invalid engine type: expected 1, got {0}")]
    InvalidEngine(u64),
    #[error("invalid predicate code: expected [0x01], got {0:?}")]
    InvalidCode(Vec<u8>),
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
}

/// Parsed and validated PayToPublicKey predicate.
#[derive(Debug, Clone)]
pub struct PayToPublicKeyPredicate {
    /// Raw 33-byte compressed secp256k1 public key.
    pub public_key: Vec<u8>,
}

/// Validate a predicate and return the extracted public key bytes.
///
/// Matches Go `verifyPayToPublicKeyPredicate` + `ValidatePublicKey`.
pub fn validate_pay_to_public_key(
    engine: u64,
    code: &[u8],
    params: &[u8],
) -> Result<PayToPublicKeyPredicate, PredicateError> {
    if engine != 1 {
        return Err(PredicateError::InvalidEngine(engine));
    }
    if code != [0x01] {
        return Err(PredicateError::InvalidCode(code.to_vec()));
    }
    validate_public_key(params)?;
    Ok(PayToPublicKeyPredicate { public_key: params.to_vec() })
}

/// Verify that `key_bytes` is a valid compressed secp256k1 public key.
pub fn validate_public_key(key_bytes: &[u8]) -> Result<(), PredicateError> {
    if key_bytes.len() != 33 {
        return Err(PredicateError::InvalidPublicKey(format!(
            "expected 33 bytes, got {}",
            key_bytes.len()
        )));
    }
    secp256k1::PublicKey::from_slice(key_bytes)
        .map_err(|e| PredicateError::InvalidPublicKey(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_predicate_accepted() {
        // Create a real secp256k1 public key.
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk)
            .serialize()
            .to_vec();
        assert!(validate_pay_to_public_key(1, &[0x01], &pk).is_ok());
    }

    #[test]
    fn wrong_engine_rejected() {
        assert!(matches!(
            validate_pay_to_public_key(0, &[0x01], &[0u8; 33]),
            Err(PredicateError::InvalidEngine(0))
        ));
    }

    #[test]
    fn wrong_code_rejected() {
        assert!(matches!(
            validate_pay_to_public_key(1, &[0x02], &[0u8; 33]),
            Err(PredicateError::InvalidCode(_))
        ));
    }
}
