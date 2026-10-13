//! Sealing records into memos and parsing memos back (envelope-v0, «Шифрование»,
//! «Представление в memo», «Разбор (шаг 1)»).
//!
//! Every record is padded to 344 bytes and sealed into exactly 384 bytes
//! (nonce ‖ ciphertext ‖ tag). A binary memo is `0xFF ‖ sealed ‖ zeros`; a text memo is
//! the 512-character Base64 of `sealed`. Parsing never panics on arbitrary input: a
//! rejection means "not a record of ours", never "stop scanning".

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, RngCore};

use crate::hash::Hash32;
use crate::record::{PLAINTEXT_LEN, ParseError, Record};

pub const MEMO_LEN: usize = 512;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const SEALED_LEN: usize = NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;
pub const BINARY_MARKER: u8 = 0xFF;

pub type EnvelopeKey = [u8; 32];
pub type Sealed = [u8; SEALED_LEN];
pub type Memo = [u8; MEMO_LEN];

/// `ASCII("zecret/v1") ‖ u8(network)`, from the guardian's trusted configuration.
pub fn aad(network: u8) -> [u8; 10] {
    let mut a = [0u8; 10];
    a[..9].copy_from_slice(b"zecret/v1");
    a[9] = network;
    a
}

pub fn seal<R: RngCore + CryptoRng>(record: &Record, key: &EnvelopeKey, rng: &mut R) -> Sealed {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    seal_with_nonce(record, key, &nonce)
}

/// Sealing with a caller-chosen nonce, for test vectors. Production code uses [`seal`].
pub fn seal_with_nonce(record: &Record, key: &EnvelopeKey, nonce: &[u8; NONCE_LEN]) -> Sealed {
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad = aad(record.header().network);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &record.to_plaintext(),
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption of 344 bytes cannot fail");
    let mut sealed = [0u8; SEALED_LEN];
    sealed[..NONCE_LEN].copy_from_slice(nonce);
    sealed[NONCE_LEN..].copy_from_slice(&ct);
    sealed
}

pub fn open(sealed: &Sealed, key: &EnvelopeKey, network: u8) -> Option<[u8; PLAINTEXT_LEN]> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let pt = cipher
        .decrypt(
            XNonce::from_slice(&sealed[..NONCE_LEN]),
            Payload {
                msg: &sealed[NONCE_LEN..],
                aad: &aad(network),
            },
        )
        .ok()?;
    pt.try_into().ok()
}

pub fn memo_binary(sealed: &Sealed) -> Memo {
    let mut m = [0u8; MEMO_LEN];
    m[0] = BINARY_MARKER;
    m[1..1 + SEALED_LEN].copy_from_slice(sealed);
    m
}

pub fn memo_text(sealed: &Sealed) -> Memo {
    let s = STANDARD_NO_PAD.encode(sealed);
    s.as_bytes()
        .try_into()
        .expect("Base64 of 384 bytes is 512 characters")
}

fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// Step 1: the sealed envelope inside a memo, in either representation.
pub fn extract_sealed(memo: &Memo) -> Option<Sealed> {
    if memo[0] == BINARY_MARKER {
        return memo[1..1 + SEALED_LEN].try_into().ok();
    }
    if memo.iter().all(|&b| is_base64_char(b)) {
        let bytes = STANDARD_NO_PAD.decode(memo).ok()?;
        return bytes.try_into().ok();
    }
    None
}

/// What the guardian knows about one session it serves.
#[derive(Clone)]
pub struct SessionContext {
    pub session: Hash32,
    pub envelope_key: EnvelopeKey,
    /// `H_pol` of the session's policy.
    pub policy: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// Index into the sessions passed to [`parse_memo`].
    pub session_index: usize,
    pub record: Record,
    pub rid: Hash32,
}

/// Why a memo is not a record of ours. Any of these means: skip the memo silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    #[error("not an envelope")]
    NotEnvelope,
    #[error("no session key opens it")]
    NoSession,
    #[error("record: {0}")]
    Record(ParseError),
    #[error("session field does not match the key that opened it")]
    SessionMismatch,
    #[error("policy does not match the session")]
    PolicyMismatch,
}

/// Steps 1–4 of parsing: envelope, decryption, structure, session. The signature is
/// not checked here; that needs the session's key history.
pub fn parse_memo(memo: &Memo, network: u8, sessions: &[SessionContext]) -> Result<Parsed, Reject> {
    let sealed = extract_sealed(memo).ok_or(Reject::NotEnvelope)?;
    let (session_index, plaintext) = sessions
        .iter()
        .enumerate()
        .find_map(|(i, s)| open(&sealed, &s.envelope_key, network).map(|p| (i, p)))
        .ok_or(Reject::NoSession)?;
    let record = Record::parse(&plaintext, network).map_err(Reject::Record)?;
    let ctx = &sessions[session_index];
    if record.header().session != ctx.session {
        return Err(Reject::SessionMismatch);
    }
    if record.header().policy != ctx.policy {
        return Err(Reject::PolicyMismatch);
    }
    let rid = record.rid();
    Ok(Parsed {
        session_index,
        record,
        rid,
    })
}
