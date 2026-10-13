//! Record layout, canonical bytes, signing and structural parsing (envelope-v0,
//! «Запись», «Подпись и идентичность», «Разбор», шаг 3).
//!
//! Parsing checks structure only. Which key must have signed a record depends on the
//! session history and is decided by the session state machine (session-v0).

use ed25519_dalek::{Signer, SigningKey};

use crate::hash::{self, Hash32};
use crate::keys::{self, KeyError, PublicKey};
use crate::net::Net;

pub const VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 147;
pub const SIG_LEN: usize = 64;
/// Record plus zero padding: the AEAD plaintext is always this long.
pub const PLAINTEXT_LEN: usize = 344;
/// Domain prefix of the signed message.
pub const SIGNING_DOMAIN: &[u8; 10] = b"zecret/v1\0";

/// Network byte of records and of the AEAD associated data.
pub fn network_code(net: &Net) -> u8 {
    match net {
        Net::Main => 0x00,
        Net::Test => 0x01,
        Net::Regtest(_) => 0x02,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    Heartbeat,
    Panic,
    Rotate,
    Cancel,
    Recover,
}

impl RecordType {
    pub const EXTEND_CODE: u8 = 0x06;

    pub fn code(self) -> u8 {
        match self {
            RecordType::Heartbeat => 0x01,
            RecordType::Panic => 0x02,
            RecordType::Rotate => 0x03,
            RecordType::Cancel => 0x04,
            RecordType::Recover => 0x05,
        }
    }

    pub fn from_code(code: u8) -> Result<Self, ParseError> {
        Ok(match code {
            0x01 => RecordType::Heartbeat,
            0x02 => RecordType::Panic,
            0x03 => RecordType::Rotate,
            0x04 => RecordType::Cancel,
            0x05 => RecordType::Recover,
            Self::EXTEND_CODE => return Err(ParseError::Reserved),
            other => return Err(ParseError::UnknownType(other)),
        })
    }

    /// Whether the body carries a new main and duress key.
    pub fn has_keys(self) -> bool {
        matches!(self, RecordType::Rotate | RecordType::Recover)
    }

    /// CANCEL and RECOVER belong to the administrative line (recovery key).
    pub fn is_admin(self) -> bool {
        matches!(self, RecordType::Cancel | RecordType::Recover)
    }

    pub fn body_len(self) -> usize {
        if self.has_keys() { 64 } else { 0 }
    }

    pub fn record_len(self) -> usize {
        HEADER_LEN + self.body_len() + SIG_LEN
    }
}

/// New main and duress keys carried by ROTATE and RECOVER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewKeys {
    pub main: PublicKey,
    pub duress: PublicKey,
}

/// A record's type together with its body: a ROTATE or RECOVER without keys, or any
/// other type with keys, cannot be expressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Heartbeat,
    Panic,
    Rotate(NewKeys),
    Cancel,
    Recover(NewKeys),
}

impl Command {
    pub fn record_type(&self) -> RecordType {
        match self {
            Command::Heartbeat => RecordType::Heartbeat,
            Command::Panic => RecordType::Panic,
            Command::Rotate(_) => RecordType::Rotate,
            Command::Cancel => RecordType::Cancel,
            Command::Recover(_) => RecordType::Recover,
        }
    }

    pub fn new_keys(&self) -> Option<&NewKeys> {
        match self {
            Command::Rotate(k) | Command::Recover(k) => Some(k),
            _ => None,
        }
    }
}

/// Header fields of a record. `head` is always zero in v0.1 and not represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub network: u8,
    pub session: Hash32,
    pub generation: u32,
    pub epoch: u64,
    pub issued_height: u32,
    pub prev: Hash32,
    pub policy: Hash32,
}

/// Why a record cannot be built. These are the structural rules the codec knows
/// locally; authority and key history belong to the session layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    #[error("epoch u64::MAX is not allowed")]
    EpochMax,
    #[error("CANCEL must have generation 0")]
    CancelGeneration,
    #[error("new key: {0}")]
    NewKey(KeyError),
}

/// Every field of a record except the signature. Built only through [`Self::new`],
/// which enforces the local structural rules, or by parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedRecord {
    header: Header,
    command: Command,
}

impl UnsignedRecord {
    pub fn new(header: Header, command: Command) -> Result<Self, BuildError> {
        if header.epoch == u64::MAX {
            return Err(BuildError::EpochMax);
        }
        if command == Command::Cancel && header.generation != 0 {
            return Err(BuildError::CancelGeneration);
        }
        if let Some(k) = command.new_keys() {
            keys::validate_key_set(&[k.main, k.duress]).map_err(BuildError::NewKey)?;
        }
        Ok(Self { header, command })
    }

    /// Skips the checks of [`Self::new`]. Only for building invalid records in
    /// negative tests; never use it to produce records for sending.
    #[doc(hidden)]
    pub fn new_unchecked_for_negative_tests(header: Header, command: Command) -> Self {
        Self { header, command }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn command(&self) -> &Command {
        &self.command
    }

    pub fn record_type(&self) -> RecordType {
        self.command.record_type()
    }

    /// Canonical bytes of every field but `sig`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let h = &self.header;
        let mut b = Vec::with_capacity(HEADER_LEN + 64);
        b.push(VERSION);
        b.push(h.network);
        b.push(self.record_type().code());
        b.extend_from_slice(&h.session);
        b.extend_from_slice(&h.generation.to_be_bytes());
        b.extend_from_slice(&h.epoch.to_be_bytes());
        b.extend_from_slice(&h.issued_height.to_be_bytes());
        b.extend_from_slice(&h.prev);
        b.extend_from_slice(&h.policy);
        b.extend_from_slice(&[0u8; 32]); // head, reserved for v0.2
        if let Some(k) = self.command.new_keys() {
            b.extend_from_slice(&k.main);
            b.extend_from_slice(&k.duress);
        }
        debug_assert_eq!(b.len() + SIG_LEN, self.record_type().record_len());
        b
    }

    /// `"zecret/v1" ‖ 0x00 ‖ record[0 .. 147+N]`.
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = SIGNING_DOMAIN.to_vec();
        m.extend_from_slice(&self.to_bytes());
        m
    }

    pub fn sign(self, key: &SigningKey) -> Record {
        let sig = key.sign(&self.signed_message()).to_bytes();
        Record {
            unsigned: self,
            sig,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    unsigned: UnsignedRecord,
    sig: [u8; SIG_LEN],
}

impl Record {
    pub fn unsigned(&self) -> &UnsignedRecord {
        &self.unsigned
    }

    pub fn header(&self) -> &Header {
        &self.unsigned.header
    }

    pub fn command(&self) -> &Command {
        &self.unsigned.command
    }

    pub fn sig(&self) -> &[u8; SIG_LEN] {
        &self.sig
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.unsigned.to_bytes();
        b.extend_from_slice(&self.sig);
        b
    }

    /// `rid = H_rec(record)`, over the signed bytes, without padding.
    pub fn rid(&self) -> Hash32 {
        hash::h(hash::RECORD, &self.to_bytes())
    }

    pub fn signed_message(&self) -> Vec<u8> {
        self.unsigned.signed_message()
    }

    /// The zero-padded AEAD plaintext.
    pub fn to_plaintext(&self) -> [u8; PLAINTEXT_LEN] {
        let bytes = self.to_bytes();
        let mut p = [0u8; PLAINTEXT_LEN];
        p[..bytes.len()].copy_from_slice(&bytes);
        p
    }

    /// Parses a decrypted plaintext and checks its structure (step 3 of parsing).
    pub fn parse(plaintext: &[u8; PLAINTEXT_LEN], network: u8) -> Result<Self, ParseError> {
        let p = plaintext;
        if p[0] != VERSION {
            return Err(ParseError::Version(p[0]));
        }
        if p[1] != network {
            return Err(ParseError::Network(p[1]));
        }
        let record_type = RecordType::from_code(p[2])?;
        let len = record_type.record_len();
        if p[len..].iter().any(|&b| b != 0) {
            return Err(ParseError::Padding);
        }
        let generation = u32::from_be_bytes(p[35..39].try_into().expect("4 bytes"));
        let epoch = u64::from_be_bytes(p[39..47].try_into().expect("8 bytes"));
        if epoch == u64::MAX {
            return Err(ParseError::EpochMax);
        }
        if p[115..147].iter().any(|&b| b != 0) {
            return Err(ParseError::Head);
        }
        if record_type == RecordType::Cancel && generation != 0 {
            return Err(ParseError::CancelGeneration);
        }
        let command = match record_type {
            RecordType::Heartbeat => Command::Heartbeat,
            RecordType::Panic => Command::Panic,
            RecordType::Cancel => Command::Cancel,
            RecordType::Rotate | RecordType::Recover => {
                let main: PublicKey = p[147..179].try_into().expect("32 bytes");
                let duress: PublicKey = p[179..211].try_into().expect("32 bytes");
                keys::validate_key_set(&[main, duress]).map_err(ParseError::BodyKey)?;
                let k = NewKeys { main, duress };
                if record_type == RecordType::Rotate {
                    Command::Rotate(k)
                } else {
                    Command::Recover(k)
                }
            }
        };
        let sig_at = len - SIG_LEN;
        Ok(Record {
            unsigned: UnsignedRecord {
                header: Header {
                    network: p[1],
                    session: p[3..35].try_into().expect("32 bytes"),
                    generation,
                    epoch,
                    issued_height: u32::from_be_bytes(p[47..51].try_into().expect("4 bytes")),
                    prev: p[51..83].try_into().expect("32 bytes"),
                    policy: p[83..115].try_into().expect("32 bytes"),
                },
                command,
            },
            sig: p[sig_at..len].try_into().expect("64 bytes"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("unsupported version {0:#04x}")]
    Version(u8),
    #[error("record for network {0:#04x}")]
    Network(u8),
    #[error("unknown record type {0:#04x}")]
    UnknownType(u8),
    #[error("EXTEND is reserved in v0.1")]
    Reserved,
    #[error("epoch u64::MAX is not allowed")]
    EpochMax,
    #[error("head must be zero in v0.1")]
    Head,
    #[error("non-zero padding after the record")]
    Padding,
    #[error("CANCEL must have generation 0")]
    CancelGeneration,
    #[error("key in body: {0}")]
    BodyKey(KeyError),
}
