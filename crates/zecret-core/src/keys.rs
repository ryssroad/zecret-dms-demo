//! Ed25519 key and signature profile (envelope-v0, «Профиль Ed25519»).

use ed25519_dalek::{Signature, VerifyingKey};

pub type PublicKey = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("not a curve point")]
    NotAPoint,
    #[error("non-canonical point encoding")]
    NonCanonical,
    #[error("point of small order")]
    SmallOrder,
    #[error("keys of the set are not pairwise distinct")]
    NotDistinct,
}

/// Accepts a public key only if it decodes, is canonically encoded and is not of
/// small order.
pub fn validate_public_key(bytes: &PublicKey) -> Result<VerifyingKey, KeyError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| KeyError::NotAPoint)?;
    // `to_bytes()` returns the stored input; canonicity needs the point re-encoded.
    if key.to_edwards().compress().to_bytes() != *bytes {
        return Err(KeyError::NonCanonical);
    }
    if key.is_weak() {
        return Err(KeyError::SmallOrder);
    }
    Ok(key)
}

/// Validates every key and checks that they are pairwise distinct.
pub fn validate_key_set(keys: &[PublicKey]) -> Result<Vec<VerifyingKey>, KeyError> {
    let parsed = keys
        .iter()
        .map(validate_public_key)
        .collect::<Result<Vec<_>, _>>()?;
    for (i, a) in keys.iter().enumerate() {
        if keys[i + 1..].contains(a) {
            return Err(KeyError::NotDistinct);
        }
    }
    Ok(parsed)
}

/// Strict Ed25519 verification: canonical R not of small order, S < ℓ, and the
/// cofactorless equation [S]B = R + [k]A (ed25519-dalek `verify_strict`).
pub fn verify(key: &VerifyingKey, message: &[u8], sig: &[u8; 64]) -> bool {
    key.verify_strict(message, &Signature::from_bytes(sig))
        .is_ok()
}

/// Which key of a set a signature verifies under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    None,
    One(usize),
    /// More than one key verified: rejected as ambiguous.
    Ambiguous,
}

pub fn classify(keys: &[VerifyingKey], message: &[u8], sig: &[u8; 64]) -> Match {
    let mut found = Match::None;
    for (i, key) in keys.iter().enumerate() {
        if verify(key, message, sig) {
            found = match found {
                Match::None => Match::One(i),
                _ => return Match::Ambiguous,
            };
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    #[test]
    fn accepts_ordinary_keys() {
        assert!(validate_public_key(&key(1).verifying_key().to_bytes()).is_ok());
    }

    #[test]
    fn rejects_small_order_points() {
        // Identity (0, 1) and the order-2 point (0, -1).
        let identity = {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        };
        assert_eq!(validate_public_key(&identity), Err(KeyError::SmallOrder));
        let mut minus_one = [0xffu8; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        assert_eq!(validate_public_key(&minus_one), Err(KeyError::SmallOrder));
    }

    #[test]
    fn rejects_non_canonical_encoding() {
        // y = p + 1 encodes the same point as y = 1 (identity) but non-canonically.
        let mut y = [0xffu8; 32];
        y[0] = 0xee;
        y[31] = 0x7f;
        assert!(matches!(
            validate_public_key(&y),
            Err(KeyError::NonCanonical | KeyError::NotAPoint)
        ));
        // A canonical key with the sign bit flipped for x = 0 is non-canonical.
        let mut identity_neg = [0u8; 32];
        identity_neg[0] = 1;
        identity_neg[31] = 0x80;
        assert!(validate_public_key(&identity_neg).is_err());
    }

    #[test]
    fn key_sets_must_be_distinct() {
        let a = key(1).verifying_key().to_bytes();
        let b = key(2).verifying_key().to_bytes();
        assert!(validate_key_set(&[a, b]).is_ok());
        assert_eq!(
            validate_key_set(&[a, b, a]).unwrap_err(),
            KeyError::NotDistinct
        );
    }

    #[test]
    fn strict_verification_rejects_high_s() {
        let sk = key(3);
        let msg = b"zecret";
        let mut sig = sk.sign(msg).to_bytes();
        assert!(verify(&sk.verifying_key(), msg, &sig));
        // S + ℓ is the same scalar mod ℓ but not canonical.
        let l: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = sig[32 + i] as u16 + l[i] as u16 + carry;
            sig[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert!(!verify(&sk.verifying_key(), msg, &sig));
    }

    #[test]
    fn classify_finds_the_signing_key() {
        let keys: Vec<_> = (1..=3).map(|n| key(n).verifying_key()).collect();
        let sig = key(2).sign(b"m").to_bytes();
        assert_eq!(classify(&keys, b"m", &sig), Match::One(1));
        assert_eq!(classify(&keys, b"other", &sig), Match::None);
    }
}
