//! Personalised BLAKE2b-256 hashes (envelope-v0, «Обозначения»).
//!
//! `hash_length = 32` is a BLAKE2b parameter, not a truncation of BLAKE2b-512; no key,
//! no salt, fanout 1, depth 1.

pub type Hash32 = [u8; 32];

pub const SESSION: &[u8; 16] = b"zecret-v1-sessid";
pub const RECORD: &[u8; 16] = b"zecret-v1-record";
pub const POLICY: &[u8; 16] = b"zecret-v1-policy";
pub const CIPHER: &[u8; 16] = b"zecret-v1-cipher";
pub const SETUP: &[u8; 16] = b"zecret-v1-setup_";

pub fn h(personal: &[u8; 16], data: &[u8]) -> Hash32 {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .fanout(1)
        .max_depth(1)
        .personal(personal)
        .hash(data);
    hash.as_bytes().try_into().expect("hash_length is 32")
}

/// `H_sess(session_secret)`: the session id carried in every record.
pub fn session_id(session_secret: &[u8]) -> Hash32 {
    h(SESSION, session_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personalisations_are_16_bytes_and_distinct() {
        let all = [SESSION, RECORD, POLICY, CIPHER, SETUP];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_ne!(h(SESSION, b"x"), h(RECORD, b"x"));
    }

    #[test]
    fn is_not_truncated_blake2b_512() {
        let full = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(RECORD)
            .hash(b"x");
        assert_ne!(&h(RECORD, b"x")[..], &full.as_bytes()[..32]);
    }
}
