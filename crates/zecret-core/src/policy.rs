//! PolicyV1 and SetupV1 (docs/policy-v1.md).
//!
//! Both are built only through checked constructors or parsing, so a value of these
//! types always satisfies the structural rules. The rule that depends on the setup
//! height (`W_hard` in the future) and the guardian-local checks (own membership,
//! network) are separate: [`SetupV1::accept`].

use crate::hash::{self, Hash32};
use crate::keys::{self, KeyError, PublicKey};

pub const VERSION: u8 = 0x01;
pub const MAX_GUARDIANS: usize = 16;
pub const MAX_RECIPIENTS: usize = 16;

/// X25519 public key of a recipient, in the single representation PolicyV1 allows.
pub type RecipientKey = [u8; 32];

/// Canonical u-coordinates of small order on Curve25519 and its twist (policy-v1,
/// «Профиль X25519»).
const X25519_SMALL_ORDER: [[u8; 32]; 5] = [
    [0; 32],
    {
        let mut u = [0u8; 32];
        u[0] = 1;
        u
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// `p = 2^255 − 19`, little-endian.
const P25519: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

fn le_less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum X25519Error {
    #[error("bit 255 is set")]
    HighBit,
    #[error("u is not reduced below p")]
    NotReduced,
    #[error("u of small order")]
    SmallOrder,
}

/// PolicyV1 X25519 profile: bit 255 clear, `u < p`, not one of the small-order `u`.
pub fn validate_recipient_key(u: &RecipientKey) -> Result<(), X25519Error> {
    if u[31] & 0x80 != 0 {
        return Err(X25519Error::HighBit);
    }
    if !le_less_than(u, &P25519) {
        return Err(X25519Error::NotReduced);
    }
    if X25519_SMALL_ORDER.contains(u) {
        return Err(X25519Error::SmallOrder);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("unsupported version {0:#04x}")]
    Version(u8),
    #[error("unknown network {0:#04x}")]
    Network(u8),
    #[error("input ends early")]
    Truncated,
    #[error("{0} trailing bytes")]
    Trailing(usize),
    #[error("guardian count {0} outside 1..=16")]
    GuardianCount(usize),
    #[error("threshold {threshold} outside 1..={n}")]
    Threshold { threshold: u8, n: usize },
    #[error("recipient count {0} outside 1..=16")]
    RecipientCount(usize),
    #[error("key list is not strictly ascending (unsorted or repeated)")]
    Unsorted,
    #[error("guardian key: {0}")]
    GuardianKey(KeyError),
    #[error("recipient key: {0}")]
    RecipientKey(X25519Error),
    #[error("{0} must be greater than zero")]
    Zero(&'static str),
    #[error("max_delay_blocks must be below timeout_blocks")]
    MaxDelay,
    #[error("confirmations must be at least 1")]
    Confirmations,
    #[error("hard_end_height is below grace + warning")]
    HardEndUnderflow,
}

/// Policy parameters. Build with [`Policy::new`] (checked) or [`Policy::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    network: u8,
    threshold: u8,
    guardians: Vec<PublicKey>,
    timeout_blocks: u32,
    warning_blocks: u32,
    grace_blocks: u32,
    max_delay_blocks: u32,
    confirmations: u8,
    hard_end_height: u32,
    recipients: Vec<RecipientKey>,
    payload_hash: Hash32,
}

/// Plain input for [`Policy::new`]. Key lists may be in any order; they are sorted.
#[derive(Debug, Clone)]
pub struct PolicyParams {
    pub network: u8,
    pub threshold: u8,
    pub guardians: Vec<PublicKey>,
    pub timeout_blocks: u32,
    pub warning_blocks: u32,
    pub grace_blocks: u32,
    pub max_delay_blocks: u32,
    pub confirmations: u8,
    pub hard_end_height: u32,
    pub recipients: Vec<RecipientKey>,
    pub payload_hash: Hash32,
}

fn strictly_ascending(keys: &[[u8; 32]]) -> bool {
    keys.windows(2).all(|w| w[0] < w[1])
}

impl Policy {
    pub fn new(mut p: PolicyParams) -> Result<Self, PolicyError> {
        p.guardians.sort();
        p.recipients.sort();
        let policy = Policy {
            network: p.network,
            threshold: p.threshold,
            guardians: p.guardians,
            timeout_blocks: p.timeout_blocks,
            warning_blocks: p.warning_blocks,
            grace_blocks: p.grace_blocks,
            max_delay_blocks: p.max_delay_blocks,
            confirmations: p.confirmations,
            hard_end_height: p.hard_end_height,
            recipients: p.recipients,
            payload_hash: p.payload_hash,
        };
        policy.check()?;
        Ok(policy)
    }

    fn check(&self) -> Result<(), PolicyError> {
        if self.network > 0x02 {
            return Err(PolicyError::Network(self.network));
        }
        let n = self.guardians.len();
        if !(1..=MAX_GUARDIANS).contains(&n) {
            return Err(PolicyError::GuardianCount(n));
        }
        if self.threshold == 0 || usize::from(self.threshold) > n {
            return Err(PolicyError::Threshold {
                threshold: self.threshold,
                n,
            });
        }
        if !strictly_ascending(&self.guardians) {
            return Err(PolicyError::Unsorted);
        }
        for g in &self.guardians {
            keys::validate_public_key(g).map_err(PolicyError::GuardianKey)?;
        }
        let m = self.recipients.len();
        if !(1..=MAX_RECIPIENTS).contains(&m) {
            return Err(PolicyError::RecipientCount(m));
        }
        if !strictly_ascending(&self.recipients) {
            return Err(PolicyError::Unsorted);
        }
        for r in &self.recipients {
            validate_recipient_key(r).map_err(PolicyError::RecipientKey)?;
        }
        for (name, v) in [
            ("timeout_blocks", self.timeout_blocks),
            ("warning_blocks", self.warning_blocks),
            ("grace_blocks", self.grace_blocks),
            ("max_delay_blocks", self.max_delay_blocks),
        ] {
            if v == 0 {
                return Err(PolicyError::Zero(name));
            }
        }
        if self.max_delay_blocks >= self.timeout_blocks {
            return Err(PolicyError::MaxDelay);
        }
        if self.confirmations == 0 {
            return Err(PolicyError::Confirmations);
        }
        self.w_hard().ok_or(PolicyError::HardEndUnderflow)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(122 + 32 * (self.guardians.len() + self.recipients.len()));
        b.push(VERSION);
        b.push(self.network);
        b.push(self.threshold);
        b.push(self.guardians.len() as u8);
        for g in &self.guardians {
            b.extend_from_slice(g);
        }
        for v in [
            self.timeout_blocks,
            self.warning_blocks,
            self.grace_blocks,
            self.max_delay_blocks,
        ] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.push(self.confirmations);
        b.extend_from_slice(&self.hard_end_height.to_be_bytes());
        b.push(self.recipients.len() as u8);
        for r in &self.recipients {
            b.extend_from_slice(r);
        }
        b.extend_from_slice(&self.payload_hash);
        b
    }

    /// Parses exactly one policy; trailing bytes are an error.
    pub fn parse(bytes: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader(bytes);
        let policy = Self::read(&mut r)?;
        if !r.0.is_empty() {
            return Err(PolicyError::Trailing(r.0.len()));
        }
        Ok(policy)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, PolicyError> {
        let version = r.u8()?;
        if version != VERSION {
            return Err(PolicyError::Version(version));
        }
        let network = r.u8()?;
        let threshold = r.u8()?;
        let n = usize::from(r.u8()?);
        let guardians = (0..n).map(|_| r.key()).collect::<Result<Vec<_>, _>>()?;
        let timeout_blocks = r.u32()?;
        let warning_blocks = r.u32()?;
        let grace_blocks = r.u32()?;
        let max_delay_blocks = r.u32()?;
        let confirmations = r.u8()?;
        let hard_end_height = r.u32()?;
        let m = usize::from(r.u8()?);
        let recipients = (0..m).map(|_| r.key()).collect::<Result<Vec<_>, _>>()?;
        let payload_hash = r.key()?;
        let policy = Policy {
            network,
            threshold,
            guardians,
            timeout_blocks,
            warning_blocks,
            grace_blocks,
            max_delay_blocks,
            confirmations,
            hard_end_height,
            recipients,
            payload_hash,
        };
        // Unlike `new`, parsing never sorts: an unsorted list is an error.
        policy.check()?;
        Ok(policy)
    }

    /// `H_pol(policy_bytes)`: the `policy` field of every record of the session.
    pub fn hash(&self) -> Hash32 {
        hash::h(hash::POLICY, &self.to_bytes())
    }

    /// `W_hard = hard_end_height − grace_blocks − warning_blocks`, or None on underflow.
    pub fn w_hard(&self) -> Option<u32> {
        self.hard_end_height
            .checked_sub(self.grace_blocks)?
            .checked_sub(self.warning_blocks)
    }

    /// `G_hard = hard_end_height − grace_blocks`.
    pub fn g_hard(&self) -> u32 {
        self.hard_end_height - self.grace_blocks
    }

    pub fn network(&self) -> u8 {
        self.network
    }
    pub fn threshold(&self) -> u8 {
        self.threshold
    }
    pub fn guardians(&self) -> &[PublicKey] {
        &self.guardians
    }
    pub fn timeout_blocks(&self) -> u32 {
        self.timeout_blocks
    }
    pub fn warning_blocks(&self) -> u32 {
        self.warning_blocks
    }
    pub fn grace_blocks(&self) -> u32 {
        self.grace_blocks
    }
    pub fn max_delay_blocks(&self) -> u32 {
        self.max_delay_blocks
    }
    pub fn confirmations(&self) -> u8 {
        self.confirmations
    }
    pub fn hard_end_height(&self) -> u32 {
        self.hard_end_height
    }
    pub fn recipients(&self) -> &[RecipientKey] {
        &self.recipients
    }
    pub fn payload_hash(&self) -> &Hash32 {
        &self.payload_hash
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], PolicyError> {
        if self.0.len() < n {
            return Err(PolicyError::Truncated);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, PolicyError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, PolicyError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn key(&mut self) -> Result<[u8; 32], PolicyError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    #[error("unsupported version {0:#04x}")]
    Version(u8),
    #[error("input ends early")]
    Truncated,
    #[error("{0} trailing bytes")]
    Trailing(usize),
    #[error("policy: {0}")]
    Policy(PolicyError),
    #[error("owner keys: {0}")]
    Keys(KeyError),
}

/// What a guardian receives at setup: session, policy and the owner's three keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupV1 {
    session: Hash32,
    policy: Policy,
    main_key: PublicKey,
    duress_key: PublicKey,
    recovery_key: PublicKey,
}

/// Why a guardian refuses a structurally valid setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AcceptError {
    #[error("this guardian's key is not in the policy")]
    NotAGuardian,
    #[error("setup is for network {0:#04x}")]
    Network(u8),
    #[error("W_hard {w_hard} is not after the setup height {height}")]
    TooLate { w_hard: u32, height: u32 },
}

impl SetupV1 {
    pub fn new(
        session: Hash32,
        policy: Policy,
        main_key: PublicKey,
        duress_key: PublicKey,
        recovery_key: PublicKey,
    ) -> Result<Self, SetupError> {
        keys::validate_key_set(&[main_key, duress_key, recovery_key]).map_err(SetupError::Keys)?;
        Ok(Self {
            session,
            policy,
            main_key,
            duress_key,
            recovery_key,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![VERSION];
        b.extend_from_slice(&self.session);
        b.extend_from_slice(&self.policy.to_bytes());
        b.extend_from_slice(&self.main_key);
        b.extend_from_slice(&self.duress_key);
        b.extend_from_slice(&self.recovery_key);
        b
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, SetupError> {
        let mut r = Reader(bytes);
        let version = r.u8().map_err(|_| SetupError::Truncated)?;
        if version != VERSION {
            return Err(SetupError::Version(version));
        }
        let session = r.key().map_err(|_| SetupError::Truncated)?;
        let policy = Policy::read(&mut r).map_err(|e| match e {
            PolicyError::Truncated => SetupError::Truncated,
            e => SetupError::Policy(e),
        })?;
        let mut key = || r.key().map_err(|_| SetupError::Truncated);
        let (main_key, duress_key, recovery_key) = (key()?, key()?, key()?);
        if !r.0.is_empty() {
            return Err(SetupError::Trailing(r.0.len()));
        }
        Self::new(session, policy, main_key, duress_key, recovery_key)
    }

    /// `setup_id = H_setup(setup_bytes)`.
    pub fn id(&self) -> Hash32 {
        hash::h(hash::SETUP, &self.to_bytes())
    }

    /// Guardian-side acceptance (session-v0, «Setup»): the guardian's own key is in the
    /// policy, the network matches its trusted configuration, and the whole hard-end
    /// schedule is after `height`, the confirmed height at which the setup is accepted.
    pub fn accept(&self, own_key: &PublicKey, network: u8, height: u32) -> Result<(), AcceptError> {
        if !self.policy.guardians.contains(own_key) {
            return Err(AcceptError::NotAGuardian);
        }
        if self.policy.network != network {
            return Err(AcceptError::Network(self.policy.network));
        }
        let w_hard = self
            .policy
            .w_hard()
            .expect("checked when the policy was built");
        if w_hard <= height {
            return Err(AcceptError::TooLate { w_hard, height });
        }
        Ok(())
    }

    pub fn session(&self) -> &Hash32 {
        &self.session
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn main_key(&self) -> &PublicKey {
        &self.main_key
    }
    pub fn duress_key(&self) -> &PublicKey {
        &self.duress_key
    }
    pub fn recovery_key(&self) -> &PublicKey {
        &self.recovery_key
    }
}
