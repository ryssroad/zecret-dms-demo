//! Envelope codec tests against docs/envelope-v0.md.

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use zecret_core::envelope::{
    self, MEMO_LEN, Memo, Reject, SEALED_LEN, SessionContext, extract_sealed, memo_binary,
    memo_text, open, parse_memo, seal_with_nonce,
};
use zecret_core::hash;
use zecret_core::keys;
use zecret_core::record::{
    BuildError, Command, Header, NewKeys, PLAINTEXT_LEN, ParseError, Record, RecordType,
    UnsignedRecord,
};

const REGTEST: u8 = 0x02;
const TESTNET: u8 = 0x01;
const ENVELOPE_KEY: [u8; 32] = [0x42; 32];
const NONCE: [u8; 24] = [0x24; 24];

fn signer(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn session() -> [u8; 32] {
    hash::session_id(b"vector session secret")
}

fn policy() -> [u8; 32] {
    hash::h(
        hash::POLICY,
        b"placeholder policy bytes: PolicyV1 codec comes later",
    )
}

fn ctx() -> SessionContext {
    SessionContext {
        session: session(),
        envelope_key: ENVELOPE_KEY,
        policy: policy(),
    }
}

fn new_keys() -> NewKeys {
    NewKeys {
        main: signer(10).verifying_key().to_bytes(),
        duress: signer(11).verifying_key().to_bytes(),
    }
}

fn command(t: RecordType) -> Command {
    match t {
        RecordType::Heartbeat => Command::Heartbeat,
        RecordType::Panic => Command::Panic,
        RecordType::Rotate => Command::Rotate(new_keys()),
        RecordType::Cancel => Command::Cancel,
        RecordType::Recover => Command::Recover(new_keys()),
    }
}

fn header(t: RecordType) -> Header {
    Header {
        network: REGTEST,
        session: session(),
        generation: if t == RecordType::Cancel { 0 } else { 1 },
        epoch: 7,
        issued_height: 4_407_458,
        prev: hash::h(hash::RECORD, b"previous record"),
        policy: policy(),
    }
}

fn unsigned(t: RecordType) -> UnsignedRecord {
    UnsignedRecord::new(header(t), command(t)).unwrap()
}

const ALL: [RecordType; 5] = [
    RecordType::Heartbeat,
    RecordType::Panic,
    RecordType::Rotate,
    RecordType::Cancel,
    RecordType::Recover,
];

fn record(t: RecordType) -> Record {
    unsigned(t).sign(&signer(1))
}

fn parse(memo: &Memo) -> Result<envelope::Parsed, Reject> {
    parse_memo(memo, REGTEST, &[ctx()])
}

/// Seals arbitrary plaintext bytes, to test structural checks past the AEAD.
fn seal_plaintext(pt: &[u8; PLAINTEXT_LEN], network: u8) -> Memo {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let cipher = chacha20poly1305::XChaCha20Poly1305::new((&ENVELOPE_KEY).into());
    let ct = cipher
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&NONCE),
            Payload {
                msg: pt,
                aad: &envelope::aad(network),
            },
        )
        .unwrap();
    let mut sealed = [0u8; SEALED_LEN];
    sealed[..24].copy_from_slice(&NONCE);
    sealed[24..].copy_from_slice(&ct);
    memo_binary(&sealed)
}

#[test]
fn sizes_match_the_budget() {
    assert_eq!(SEALED_LEN, 384);
    for t in ALL {
        let r = record(t);
        let expected = if t.has_keys() { 275 } else { 211 };
        assert_eq!(r.to_bytes().len(), expected, "{t:?}");
        assert!(r.to_bytes().len() <= PLAINTEXT_LEN);
        let sealed = seal_with_nonce(&r, &ENVELOPE_KEY, &NONCE);
        let text = memo_text(&sealed);
        assert_eq!(text.len(), MEMO_LEN);
        assert!(text.iter().all(|b| b.is_ascii() && *b != b'='));
        assert!(text[0] <= 0xF4, "text memo per ZIP 302");
    }
}

#[test]
fn every_type_round_trips_in_both_representations() {
    for t in ALL {
        let r = record(t);
        let sealed = seal_with_nonce(&r, &ENVELOPE_KEY, &NONCE);
        let binary = parse(&memo_binary(&sealed)).unwrap();
        let text = parse(&memo_text(&sealed)).unwrap();
        assert_eq!(binary.record, r, "{t:?}");
        assert_eq!(binary.rid, r.rid());
        assert_eq!(text.rid, binary.rid, "{t:?}: one rid in both modes");
        let key = signer(1).verifying_key();
        assert!(keys::verify(
            &key,
            &binary.record.signed_message(),
            binary.record.sig()
        ));
    }
}

#[test]
fn resealing_with_a_new_nonce_keeps_the_rid() {
    let r = record(RecordType::Heartbeat);
    let a = seal_with_nonce(&r, &ENVELOPE_KEY, &[1; 24]);
    let b = envelope::seal(&r, &ENVELOPE_KEY, &mut rand_core::OsRng);
    assert_ne!(a, b);
    assert_eq!(
        parse(&memo_binary(&a)).unwrap().rid,
        parse(&memo_binary(&b)).unwrap().rid
    );
}

#[test]
fn binary_tail_is_ignored() {
    let mut m = memo_binary(&seal_with_nonce(
        &record(RecordType::Panic),
        &ENVELOPE_KEY,
        &NONCE,
    ));
    m[400] = 0xAB;
    assert!(parse(&m).is_ok());
}

#[test]
fn wrong_key_network_session_or_policy_is_rejected() {
    let m = memo_binary(&seal_with_nonce(
        &record(RecordType::Heartbeat),
        &ENVELOPE_KEY,
        &NONCE,
    ));
    let other_key = SessionContext {
        envelope_key: [0x43; 32],
        ..ctx()
    };
    assert_eq!(
        parse_memo(&m, REGTEST, &[other_key]),
        Err(Reject::NoSession)
    );
    assert_eq!(
        parse_memo(&m, TESTNET, &[ctx()]),
        Err(Reject::NoSession),
        "AAD binds network"
    );
    let other_session = SessionContext {
        session: [9; 32],
        ..ctx()
    };
    assert_eq!(
        parse_memo(&m, REGTEST, &[other_session]),
        Err(Reject::SessionMismatch)
    );
    let other_policy = SessionContext {
        policy: [9; 32],
        ..ctx()
    };
    assert_eq!(
        parse_memo(&m, REGTEST, &[other_policy]),
        Err(Reject::PolicyMismatch)
    );
}

#[test]
fn second_session_key_is_found() {
    let m = memo_binary(&seal_with_nonce(
        &record(RecordType::Heartbeat),
        &ENVELOPE_KEY,
        &NONCE,
    ));
    let decoy = SessionContext {
        envelope_key: [0x43; 32],
        ..ctx()
    };
    assert_eq!(
        parse_memo(&m, REGTEST, &[decoy, ctx()])
            .unwrap()
            .session_index,
        1
    );
}

#[test]
fn structural_rejections() {
    let base = record(RecordType::Heartbeat).to_plaintext();
    let reject = |pt: &[u8; PLAINTEXT_LEN]| parse(&seal_plaintext(pt, REGTEST)).unwrap_err();

    let mut p = base;
    p[0] = 0x02;
    assert_eq!(reject(&p), Reject::Record(ParseError::Version(0x02)));

    let mut p = base;
    p[1] = TESTNET;
    assert_eq!(reject(&p), Reject::Record(ParseError::Network(TESTNET)));

    let mut p = base;
    p[2] = 0x06;
    assert_eq!(reject(&p), Reject::Record(ParseError::Reserved), "EXTEND");
    p[2] = 0x07;
    assert_eq!(reject(&p), Reject::Record(ParseError::UnknownType(0x07)));

    let mut p = base;
    p[39..47].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(reject(&p), Reject::Record(ParseError::EpochMax));

    let mut p = base;
    p[130] = 1;
    assert_eq!(reject(&p), Reject::Record(ParseError::Head));

    let mut p = base;
    p[300] = 1;
    assert_eq!(reject(&p), Reject::Record(ParseError::Padding));

    let mut p = record(RecordType::Cancel).to_plaintext();
    p[38] = 1;
    assert_eq!(reject(&p), Reject::Record(ParseError::CancelGeneration));
}

fn with_keys(t: RecordType, keys: NewKeys) -> Command {
    if t == RecordType::Rotate {
        Command::Rotate(keys)
    } else {
        Command::Recover(keys)
    }
}

fn identity_point() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
}

#[test]
fn rotate_and_recover_keys_are_validated_when_parsing() {
    for t in [RecordType::Rotate, RecordType::Recover] {
        let small = NewKeys {
            main: identity_point(),
            ..new_keys()
        };
        let r = UnsignedRecord::new_unchecked_for_negative_tests(header(t), with_keys(t, small))
            .sign(&signer(1));
        let m = memo_binary(&seal_with_nonce(&r, &ENVELOPE_KEY, &NONCE));
        assert_eq!(
            parse(&m),
            Err(Reject::Record(ParseError::BodyKey(
                keys::KeyError::SmallOrder
            )))
        );

        let k = new_keys().main;
        let same = NewKeys { main: k, duress: k };
        let r = UnsignedRecord::new_unchecked_for_negative_tests(header(t), with_keys(t, same))
            .sign(&signer(1));
        let m = memo_binary(&seal_with_nonce(&r, &ENVELOPE_KEY, &NONCE));
        assert_eq!(
            parse(&m),
            Err(Reject::Record(ParseError::BodyKey(
                keys::KeyError::NotDistinct
            )))
        );
    }
}

// PR1-R1: a record that the guardian would parse differently, or reject, must fail
// before it is signed and sent.
#[test]
fn invalid_records_cannot_be_built() {
    for t in [RecordType::Rotate, RecordType::Recover] {
        let bad = [
            (
                NewKeys {
                    main: identity_point(),
                    ..new_keys()
                },
                keys::KeyError::SmallOrder,
            ),
            (
                NewKeys {
                    duress: identity_point(),
                    ..new_keys()
                },
                keys::KeyError::SmallOrder,
            ),
            (
                NewKeys {
                    main: new_keys().main,
                    duress: new_keys().main,
                },
                keys::KeyError::NotDistinct,
            ),
        ];
        for (k, err) in bad {
            assert_eq!(
                UnsignedRecord::new(header(t), with_keys(t, k)),
                Err(BuildError::NewKey(err)),
                "{t:?}"
            );
        }
    }
    for t in ALL {
        let mut h = header(t);
        h.epoch = u64::MAX;
        assert_eq!(
            UnsignedRecord::new(h, command(t)),
            Err(BuildError::EpochMax),
            "{t:?}"
        );
    }
    let mut h = header(RecordType::Cancel);
    h.generation = 1;
    assert_eq!(
        UnsignedRecord::new(h, Command::Cancel),
        Err(BuildError::CancelGeneration)
    );
}

// PR1-R1: type and body are one value, so the serialized length always matches what
// the parser expects for the type, and a valid record survives the full round trip.
#[test]
fn body_always_matches_type() {
    for t in ALL {
        let u = unsigned(t);
        assert_eq!(u.record_type(), t);
        assert_eq!(u.command().new_keys().is_some(), t.has_keys(), "{t:?}");
        let r = u.sign(&signer(1));
        assert_eq!(r.to_bytes().len(), t.record_len(), "{t:?}");
        let parsed = parse(&memo_binary(&seal_with_nonce(&r, &ENVELOPE_KEY, &NONCE))).unwrap();
        assert_eq!(parsed.record, r);
        assert_eq!(parsed.rid, r.rid());
        assert!(keys::verify(
            &signer(1).verifying_key(),
            &parsed.record.signed_message(),
            parsed.record.sig()
        ));
    }
}

#[test]
fn non_envelope_memos() {
    let mut empty = [0u8; MEMO_LEN];
    empty[0] = 0xF6;
    assert_eq!(parse(&empty), Err(Reject::NotEnvelope));
    let mut text = [b' '; MEMO_LEN];
    text[..5].copy_from_slice(b"hello");
    assert_eq!(parse(&text), Err(Reject::NotEnvelope));
    let mut padded = memo_text(&seal_with_nonce(
        &record(RecordType::Panic),
        &ENVELOPE_KEY,
        &NONCE,
    ));
    padded[511] = b'=';
    assert_eq!(parse(&padded), Err(Reject::NotEnvelope));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn arbitrary_memo_never_panics(bytes in proptest::collection::vec(any::<u8>(), MEMO_LEN)) {
        let memo: Memo = bytes.try_into().unwrap();
        prop_assert!(parse(&memo).is_err());
    }

    #[test]
    fn arbitrary_binary_memo_never_panics(bytes in proptest::collection::vec(any::<u8>(), MEMO_LEN)) {
        let mut memo: Memo = bytes.try_into().unwrap();
        memo[0] = 0xFF;
        prop_assert!(parse(&memo).is_err());
    }

    #[test]
    fn arbitrary_base64_memo_never_panics(idx in proptest::collection::vec(0usize..64, MEMO_LEN)) {
        const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let memo: Memo = idx.iter().map(|&i| ALPHABET[i]).collect::<Vec<_>>().try_into().unwrap();
        prop_assert!(parse(&memo).is_err());
    }

    #[test]
    fn arbitrary_plaintext_under_a_valid_key_never_panics(bytes in proptest::collection::vec(any::<u8>(), PLAINTEXT_LEN)) {
        let pt: [u8; PLAINTEXT_LEN] = bytes.try_into().unwrap();
        let _ = parse(&seal_plaintext(&pt, REGTEST));
    }

    #[test]
    fn flipped_ciphertext_bit_is_rejected(pos in 0usize..SEALED_LEN, bit in 0u8..8) {
        let sealed = seal_with_nonce(&record(RecordType::Heartbeat), &ENVELOPE_KEY, &NONCE);
        let mut bad = sealed;
        bad[pos] ^= 1 << bit;
        prop_assert!(open(&bad, &ENVELOPE_KEY, REGTEST).is_none());
        prop_assert_eq!(extract_sealed(&memo_binary(&bad)), Some(bad));
    }
}

// Golden vectors: docs/test-vectors/envelope-v0.json. Regenerate with
// ZECRET_WRITE_VECTORS=1 cargo test -p zecret-core --test envelope golden_vectors
#[test]
fn golden_vectors() {
    let mut cases = Vec::new();
    for t in ALL {
        let r = record(t);
        let sealed = seal_with_nonce(&r, &ENVELOPE_KEY, &NONCE);
        cases.push(serde_json::json!({
            "type": format!("{t:?}"),
            "record": hex::encode(r.to_bytes()),
            "signed_message": hex::encode(r.signed_message()),
            "rid": hex::encode(r.rid()),
            "sealed": hex::encode(sealed),
            "memo_text": String::from_utf8(memo_text(&sealed).to_vec()).unwrap(),
        }));
    }
    let doc = serde_json::json!({
        "spec": "docs/envelope-v0.md, revision 3.1",
        "network": REGTEST,
        "session_secret_utf8": "vector session secret",
        "session_id": hex::encode(session()),
        "policy_hash": hex::encode(policy()),
        "policy_note": "H_pol over the placeholder bytes 'placeholder policy bytes: PolicyV1 codec comes later'",
        "signing_key_seed": hex::encode([1u8; 32]),
        "signing_public_key": hex::encode(signer(1).verifying_key().to_bytes()),
        "new_main_public_key": hex::encode(signer(10).verifying_key().to_bytes()),
        "new_duress_public_key": hex::encode(signer(11).verifying_key().to_bytes()),
        "envelope_key": hex::encode(ENVELOPE_KEY),
        "nonce": hex::encode(NONCE),
        "cases": cases,
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/test-vectors/envelope-v0.json"
    );
    if std::env::var_os("ZECRET_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
        std::fs::write(path, &text).unwrap();
    }
    let committed = std::fs::read_to_string(path)
        .expect("vectors file; regenerate with ZECRET_WRITE_VECTORS=1");
    assert_eq!(
        committed, text,
        "codec output differs from committed vectors"
    );
}
