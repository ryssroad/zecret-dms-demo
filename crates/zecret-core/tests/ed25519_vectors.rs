//! Negative Ed25519 vectors for the strict profile (envelope-v0, «Профиль Ed25519»).
//!
//! Each case says why it is rejected. The small-order R case has a satisfied
//! cofactorless equation, so it is rejected because of R alone: non-strict
//! verification accepts it. Vectors: docs/test-vectors/ed25519-strict.json; regenerate
//! with ZECRET_WRITE_VECTORS=1 cargo test -p zecret-core --test ed25519_vectors.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use zecret_core::keys;

const MESSAGE: &[u8] = b"zecret/v1\0strict profile vector";

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// S = k·a with k = H(R ‖ A ‖ M): the equation [S]B = R + [k]A holds exactly when R is
/// the identity, whatever bytes encode it.
fn identity_r_signature(r_bytes: [u8; 32]) -> [u8; 64] {
    let sk = signer();
    let a = sk.verifying_key().to_bytes();
    let k = Scalar::from_hash(
        Sha512::new()
            .chain_update(r_bytes)
            .chain_update(a)
            .chain_update(MESSAGE),
    );
    let s = k * sk.to_scalar();
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

fn add_order(sig: &mut [u8; 64]) {
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = sig[32 + i] as u16 + l[i] as u16 + carry;
        sig[32 + i] = v as u8;
        carry = v >> 8;
    }
}

struct Case {
    name: &'static str,
    public_key: [u8; 32],
    message: Vec<u8>,
    signature: [u8; 64],
    accept: bool,
    reason: &'static str,
}

fn cases() -> Vec<Case> {
    let sk = signer();
    let a = sk.verifying_key().to_bytes();
    let good = sk.sign(MESSAGE).to_bytes();

    let mut high_s = good;
    add_order(&mut high_s);

    let mut identity = [0u8; 32];
    identity[0] = 1;
    // x = 0 with the sign bit set: a non-canonical encoding of the identity.
    let mut identity_neg = identity;
    identity_neg[31] = 0x80;

    vec![
        Case {
            name: "valid",
            public_key: a,
            message: MESSAGE.to_vec(),
            signature: good,
            accept: true,
            reason: "canonical R and S, equation holds",
        },
        Case {
            name: "wrong_equation",
            public_key: a,
            message: b"another message".to_vec(),
            signature: good,
            accept: false,
            reason: "signature of a different message: [S]B != R + [k]A",
        },
        Case {
            name: "s_not_reduced",
            public_key: a,
            message: MESSAGE.to_vec(),
            signature: high_s,
            accept: false,
            reason: "S + l: same scalar mod l, but S >= l",
        },
        Case {
            name: "r_small_order_equation_holds",
            public_key: a,
            message: MESSAGE.to_vec(),
            signature: identity_r_signature(identity),
            accept: false,
            reason: "R is the identity (small order); S = k*a so the cofactorless equation holds",
        },
        Case {
            name: "r_non_canonical_equation_holds",
            public_key: a,
            message: MESSAGE.to_vec(),
            signature: identity_r_signature(identity_neg),
            accept: false,
            reason: "R encodes the identity non-canonically (x = 0 with sign bit); equation holds",
        },
        Case {
            name: "a_small_order",
            public_key: identity,
            message: MESSAGE.to_vec(),
            signature: good,
            accept: false,
            reason: "public key is the identity: rejected by the key profile",
        },
    ]
}

fn strict_accepts(c: &Case) -> bool {
    match keys::validate_public_key(&c.public_key) {
        Ok(key) => keys::verify(&key, &c.message, &c.signature),
        Err(_) => false,
    }
}

#[test]
fn strict_profile_verdicts() {
    for c in cases() {
        assert_eq!(strict_accepts(&c), c.accept, "{}", c.name);
    }
}

#[test]
fn small_order_r_is_rejected_because_of_r() {
    let c = cases()
        .into_iter()
        .find(|c| c.name == "r_small_order_equation_holds")
        .unwrap();
    let key = VerifyingKey::from_bytes(&c.public_key).unwrap();
    let sig = Signature::from_bytes(&c.signature);
    assert!(key.verify_strict(&c.message, &sig).is_err());
    // The non-strict check accepts it: the equation itself holds.
    assert!(ed25519_dalek::Verifier::verify(&key, &c.message, &sig).is_ok());
}

#[test]
fn golden_vectors() {
    let doc = serde_json::json!({
        "spec": "docs/envelope-v0.md, «Профиль Ed25519»",
        "note": "accept = verdict of the full strict profile: key profile, canonical R not of small order, S < l, cofactorless equation",
        "cases": cases().iter().map(|c| serde_json::json!({
            "name": c.name,
            "public_key": hex::encode(c.public_key),
            "message": hex::encode(&c.message),
            "signature": hex::encode(c.signature),
            "accept": c.accept,
            "reason": c.reason,
        })).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/test-vectors/ed25519-strict.json"
    );
    if std::env::var_os("ZECRET_WRITE_VECTORS").is_some() {
        std::fs::write(path, &text).unwrap();
    }
    let committed = std::fs::read_to_string(path)
        .expect("vectors file; regenerate with ZECRET_WRITE_VECTORS=1");
    assert_eq!(committed, text);
}
