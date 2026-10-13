//! PolicyV1 / SetupV1 codec tests against docs/policy-v1.md.

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use zecret_core::hash;
use zecret_core::keys::KeyError;
use zecret_core::policy::{
    AcceptError, Policy, PolicyError, PolicyParams, RecipientKey, SetupError, SetupV1, X25519Error,
    validate_recipient_key,
};

const REGTEST: u8 = 0x02;

fn ed(n: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes()
}

fn x(n: u8) -> RecipientKey {
    // Any u below p with bit 255 clear and not of small order passes the profile.
    let mut u = [n; 32];
    u[31] = 0x10;
    u
}

fn params(n: u8, m: u8) -> PolicyParams {
    PolicyParams {
        network: REGTEST,
        threshold: n.div_ceil(2).max(1),
        guardians: (0..n).map(|i| ed(100 + i)).collect(),
        timeout_blocks: 72,
        warning_blocks: 12,
        grace_blocks: 12,
        max_delay_blocks: 18,
        confirmations: 3,
        hard_end_height: 4_500_000,
        recipients: (0..m).map(|i| x(1 + i)).collect(),
        payload_hash: hash::h(hash::CIPHER, b"C"),
    }
}

fn policy() -> Policy {
    Policy::new(params(3, 2)).unwrap()
}

fn setup() -> SetupV1 {
    SetupV1::new(hash::session_id(b"s"), policy(), ed(1), ed(2), ed(3)).unwrap()
}

#[test]
fn sizes_at_the_range_limits() {
    let small = Policy::new(params(1, 1)).unwrap();
    let large = Policy::new(params(16, 16)).unwrap();
    assert_eq!(small.to_bytes().len(), 122);
    assert_eq!(large.to_bytes().len(), 1082);
    let s = |p: Policy| {
        SetupV1::new([0; 32], p, ed(1), ed(2), ed(3))
            .unwrap()
            .to_bytes()
            .len()
    };
    assert_eq!(s(small), 251);
    assert_eq!(s(large), 1211);
}

#[test]
fn round_trips() {
    let p = policy();
    assert_eq!(Policy::parse(&p.to_bytes()).unwrap(), p);
    let s = setup();
    let parsed = SetupV1::parse(&s.to_bytes()).unwrap();
    assert_eq!(parsed, s);
    assert_eq!(parsed.id(), s.id());
    assert_eq!(parsed.policy().hash(), p.hash());
}

#[test]
fn new_sorts_but_parse_rejects_unsorted_or_repeated() {
    let mut reversed = params(3, 2);
    reversed.guardians.reverse();
    reversed.recipients.reverse();
    assert_eq!(
        Policy::new(reversed).unwrap(),
        policy(),
        "same policy whatever the input order"
    );

    let bytes = policy().to_bytes();
    let mut swapped = bytes.clone();
    // guardians start at offset 4; swap the first two keys
    let (a, b) = (swapped[4..36].to_vec(), swapped[36..68].to_vec());
    swapped[4..36].copy_from_slice(&b);
    swapped[36..68].copy_from_slice(&a);
    assert_eq!(Policy::parse(&swapped), Err(PolicyError::Unsorted));

    let mut dup = params(3, 2);
    dup.guardians[1] = dup.guardians[0];
    assert_eq!(Policy::new(dup), Err(PolicyError::Unsorted));
    let mut dup = params(3, 2);
    dup.recipients[1] = dup.recipients[0];
    assert_eq!(Policy::new(dup), Err(PolicyError::Unsorted));
}

#[test]
fn counts_and_threshold() {
    assert_eq!(
        Policy::new(params(0, 1)),
        Err(PolicyError::GuardianCount(0))
    );
    assert_eq!(
        Policy::new(params(17, 1)),
        Err(PolicyError::GuardianCount(17))
    );
    assert_eq!(
        Policy::new(params(3, 0)),
        Err(PolicyError::RecipientCount(0))
    );
    assert_eq!(
        Policy::new(params(3, 17)),
        Err(PolicyError::RecipientCount(17))
    );
    for t in [0u8, 4] {
        let mut p = params(3, 1);
        p.threshold = t;
        assert_eq!(
            Policy::new(p),
            Err(PolicyError::Threshold { threshold: t, n: 3 })
        );
    }
    let mut p = params(3, 1);
    p.threshold = 3;
    assert!(Policy::new(p).is_ok(), "t = n is allowed");
}

#[test]
fn timing_rules() {
    type Zero = (&'static str, fn(&mut PolicyParams));
    let zeroed: [Zero; 4] = [
        ("timeout_blocks", |p| p.timeout_blocks = 0),
        ("warning_blocks", |p| p.warning_blocks = 0),
        ("grace_blocks", |p| p.grace_blocks = 0),
        ("max_delay_blocks", |p| p.max_delay_blocks = 0),
    ];
    for (name, zero) in zeroed {
        let mut p = params(3, 1);
        zero(&mut p);
        assert_eq!(Policy::new(p), Err(PolicyError::Zero(name)));
    }
    let mut p = params(3, 1);
    p.max_delay_blocks = p.timeout_blocks;
    assert_eq!(Policy::new(p), Err(PolicyError::MaxDelay));
    let mut p = params(3, 1);
    p.confirmations = 0;
    assert_eq!(Policy::new(p), Err(PolicyError::Confirmations));
    let mut p = params(3, 1);
    p.hard_end_height = p.grace_blocks + p.warning_blocks - 1;
    assert_eq!(Policy::new(p), Err(PolicyError::HardEndUnderflow));
    let mut p = params(3, 1);
    p.hard_end_height = p.grace_blocks + p.warning_blocks;
    let ok = Policy::new(p).unwrap();
    assert_eq!(ok.w_hard(), Some(0));
    assert_eq!(policy().w_hard(), Some(4_500_000 - 24));
    assert_eq!(policy().g_hard(), 4_500_000 - 12);
}

#[test]
fn guardian_keys_follow_the_ed25519_profile() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut p = params(3, 1);
    p.guardians[0] = identity;
    assert_eq!(
        Policy::new(p),
        Err(PolicyError::GuardianKey(KeyError::SmallOrder))
    );
}

#[test]
fn recipient_keys_follow_the_x25519_profile() {
    let small = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    for h in small {
        let u: RecipientKey = hex::decode(h).unwrap().try_into().unwrap();
        assert_eq!(
            validate_recipient_key(&u),
            Err(X25519Error::SmallOrder),
            "{h}"
        );
    }
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f; // u = p
    assert_eq!(validate_recipient_key(&p), Err(X25519Error::NotReduced));
    p[0] = 0xee; // u = p + 1, encodes the order-1 point non-canonically
    assert_eq!(validate_recipient_key(&p), Err(X25519Error::NotReduced));
    let mut high = x(1);
    high[31] |= 0x80;
    assert_eq!(validate_recipient_key(&high), Err(X25519Error::HighBit));
    let mut base = [0u8; 32];
    base[0] = 9; // the X25519 base point
    assert_eq!(validate_recipient_key(&base), Ok(()));
    p[0] = 0xeb; // u = p - 2; p - 1 is small order and listed above
    assert_eq!(validate_recipient_key(&p), Ok(()));

    let mut bad = params(3, 2);
    bad.recipients[0] = [0; 32];
    assert_eq!(
        Policy::new(bad),
        Err(PolicyError::RecipientKey(X25519Error::SmallOrder))
    );
}

#[test]
fn header_version_network_truncation_trailing() {
    let bytes = policy().to_bytes();
    let mut v = bytes.clone();
    v[0] = 2;
    assert_eq!(Policy::parse(&v), Err(PolicyError::Version(2)));
    let mut v = bytes.clone();
    v[1] = 3;
    assert_eq!(Policy::parse(&v), Err(PolicyError::Network(3)));
    for len in 0..bytes.len() {
        assert_eq!(
            Policy::parse(&bytes[..len]),
            Err(PolicyError::Truncated),
            "len {len}"
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(Policy::parse(&long), Err(PolicyError::Trailing(1)));

    let s = setup().to_bytes();
    for len in 0..s.len() {
        assert!(SetupV1::parse(&s[..len]).is_err(), "len {len}");
    }
    let mut long = s.clone();
    long.push(0);
    assert_eq!(SetupV1::parse(&long), Err(SetupError::Trailing(1)));
}

#[test]
fn setup_keys_are_checked() {
    let p = policy();
    assert_eq!(
        SetupV1::new([0; 32], p.clone(), ed(1), ed(2), ed(1)),
        Err(SetupError::Keys(KeyError::NotDistinct))
    );
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(
        SetupV1::new([0; 32], p, ed(1), identity, ed(3)),
        Err(SetupError::Keys(KeyError::SmallOrder))
    );
}

#[test]
fn guardian_acceptance() {
    let s = setup();
    let w_hard = s.policy().w_hard().unwrap();
    let me = s.policy().guardians()[1];
    assert_eq!(s.accept(&me, REGTEST, w_hard - 1), Ok(()));
    assert_eq!(
        s.accept(&me, REGTEST, w_hard),
        Err(AcceptError::TooLate {
            w_hard,
            height: w_hard
        })
    );
    assert_eq!(
        s.accept(&ed(99), REGTEST, 0),
        Err(AcceptError::NotAGuardian)
    );
    assert_eq!(s.accept(&me, 0x01, 0), Err(AcceptError::Network(REGTEST)));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1300)) {
        let _ = Policy::parse(&bytes);
        let _ = SetupV1::parse(&bytes);
    }

    #[test]
    fn mutated_policy_never_panics(pos in 0usize..190, val in any::<u8>()) {
        let mut b = policy().to_bytes();
        let i = pos % b.len();
        b[i] = val;
        if let Ok(p) = Policy::parse(&b) {
            prop_assert_eq!(p.to_bytes(), b, "parse is canonical");
        }
    }
}

// Golden vectors: docs/test-vectors/policy-v1.json. Regenerate with
// ZECRET_WRITE_VECTORS=1 cargo test -p zecret-core --test policy golden_vectors
#[test]
fn golden_vectors() {
    let p = policy();
    let s = setup();
    let doc = serde_json::json!({
        "spec": "docs/policy-v1.md, revision 3",
        "policy": hex::encode(p.to_bytes()),
        "policy_hash": hex::encode(p.hash()),
        "w_hard": p.w_hard(),
        "g_hard": p.g_hard(),
        "setup": hex::encode(s.to_bytes()),
        "setup_id": hex::encode(s.id()),
        "session_secret_utf8": "s",
        "owner_key_seeds": [hex::encode([1u8; 32]), hex::encode([2u8; 32]), hex::encode([3u8; 32])],
        "guardian_key_seeds": (100u8..103).map(|n| hex::encode([n; 32])).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/test-vectors/policy-v1.json"
    );
    if std::env::var_os("ZECRET_WRITE_VECTORS").is_some() {
        std::fs::write(path, &text).unwrap();
    }
    let committed = std::fs::read_to_string(path)
        .expect("vectors file; regenerate with ZECRET_WRITE_VECTORS=1");
    assert_eq!(committed, text);
}
