//! Session state machine (docs/session-v0.md, revision 2).
//!
//! A pure, deterministic function of the confirmed prefix: [`Session::apply_block`]
//! takes the records included in one block (already parsed by the envelope codec, in
//! canonical order: transaction position, then Ironwood action index) and applies
//! them, then the time transitions for that height. Blocks must come strictly one by
//! one. There is no clock and no I/O; the same blocks always give the same state.
//!
//! Reorgs are handled by the caller: `Session` is `Clone`, the scanner keeps a snapshot
//! per processed block and restores the snapshot of the last common block. Facts that
//! cannot be undone (a share handed to a recipient) are not part of this state.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;

use crate::hash::Hash32;
use crate::keys::{self, PublicKey};
use crate::policy::{Policy, SetupV1};
use crate::record::{Command, NewKeys, Record, RecordType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Setup,
    Armed,
    Warning,
    Grace,
    Closed,
    Released,
}

impl Stage {
    pub fn is_terminal(self) -> bool {
        matches!(self, Stage::Closed | Stage::Released)
    }
}

/// What happened to one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The record changed the session.
    Applied(Effect),
    /// First equivocation evidence of the current generation.
    Equivocation,
    /// Another evidence after the first one: logged, no effect.
    RepeatedEvidence,
    /// A second, different administrative record for an occupied administrative epoch.
    AdminConflict,
    /// Valid but not applicable here; no effect.
    Ignored(Ignore),
    /// Invalid for this session; no effect.
    Rejected(Reject),
    /// Time transition at the end of a block (no record).
    Timer(Stage),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Armed,
    Heartbeat,
    Rotated,
    Recovered { generation: u32 },
    Cancelled,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ignore {
    /// Same rid already applied or recorded as evidence.
    Duplicate,
    /// The session is closed or released.
    Terminal,
    /// PANIC, duress, CANCEL or RECOVER before the session is armed.
    NotArmed,
    /// Operational record of an earlier generation: kept for audit, no effect.
    StaleGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Included outside `[issued_height, issued_height + max_delay_blocks]`.
    OutsideDeliveryWindow,
    /// Signature does not match the key this record needs.
    BadSignature,
    /// Wrong epoch or prev for its line.
    OutOfOrder,
    /// Operational record of a generation that does not exist yet.
    FutureGeneration,
    /// First HEARTBEAT outside `ready_height < h < W_hard`.
    NotReady,
    /// Main key may only PANIC after equivocation.
    MainKeyAfterEquivocation,
    /// ROTATE outside the armed stage.
    RotateNotArmed,
    /// ROTATE or RECOVER reusing a key already used in this session, or the recovery key.
    KeyReuse,
    /// RECOVER whose generation is not current + 1, or overflow.
    WrongGeneration,
    /// Network, session or policy hash of another session. The envelope parser
    /// already filters these; the state machine does not rely on it.
    WrongSession,
}

/// One entry of the block log: the record's rid (None for time transitions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub height: u32,
    pub rid: Option<Hash32>,
    pub outcome: Outcome,
    /// Stage after this entry.
    pub stage: Stage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("expected block {expected}, got {got}")]
    NotNext { expected: u32, got: u32 },
}

/// Stage deadlines; `None` while no liveness has been recorded (stage Setup).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadlines {
    pub warning: u64,
    pub grace: u64,
    pub release: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperationalLine {
    /// Highest applied epoch of the current generation, None before the first record.
    last_epoch: Option<u64>,
    last_rid: Hash32,
    /// prev of epoch 0: zero for generation 0, rid of the opening RECOVER otherwise.
    anchor: Hash32,
    /// Applied epochs of the current generation: rid and the main key that signed it.
    applied: BTreeMap<u64, (Hash32, PublicKey)>,
}

impl OperationalLine {
    fn new(anchor: Hash32) -> Self {
        Self {
            last_epoch: None,
            last_rid: anchor,
            anchor,
            applied: BTreeMap::new(),
        }
    }

    fn next_epoch(&self) -> Option<u64> {
        match self.last_epoch {
            None => Some(0),
            Some(e) => e.checked_add(1),
        }
    }

    fn expected_prev(&self) -> Hash32 {
        if self.last_epoch.is_none() {
            self.anchor
        } else {
            self.last_rid
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    session: Hash32,
    policy: Policy,
    network: u8,
    recovery: PublicKey,
    ready_height: u32,
    /// Last processed block.
    height: u32,

    stage: Stage,
    generation: u32,
    main: PublicKey,
    duress: PublicKey,
    op: OperationalLine,
    admin_last: Option<u64>,
    admin_last_rid: Hash32,
    admin_applied: BTreeMap<u64, Hash32>,

    /// issued_height of the last record that confirmed liveness.
    liveness: Option<u32>,
    /// Height at which the first evidence of the current generation was applied.
    equivocation: Option<u32>,
    admin_conflict: bool,

    used_keys: BTreeSet<PublicKey>,
    seen: BTreeSet<Hash32>,
}

const ZERO: Hash32 = [0; 32];

impl Session {
    /// A session accepted at `ready_height`: setup accepted and the guardian ready
    /// (session-v0, «Первое взведение»). The first block processed is `ready_height + 1`.
    pub fn new(setup: &SetupV1, ready_height: u32) -> Self {
        let policy = setup.policy().clone();
        let used_keys = [
            *setup.main_key(),
            *setup.duress_key(),
            *setup.recovery_key(),
        ]
        .into_iter()
        .collect();
        Self {
            session: *setup.session(),
            network: policy.network(),
            policy,
            recovery: *setup.recovery_key(),
            ready_height,
            height: ready_height,
            stage: Stage::Setup,
            generation: 0,
            main: *setup.main_key(),
            duress: *setup.duress_key(),
            op: OperationalLine::new(ZERO),
            admin_last: None,
            admin_last_rid: ZERO,
            admin_applied: BTreeMap::new(),
            liveness: None,
            equivocation: None,
            admin_conflict: false,
            used_keys,
            seen: BTreeSet::new(),
        }
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    pub fn equivocated(&self) -> bool {
        self.equivocation.is_some()
    }
    /// Persistent alarm: two different administrative records for one epoch.
    pub fn admin_conflict(&self) -> bool {
        self.admin_conflict
    }
    pub fn height(&self) -> u32 {
        self.height
    }
    pub fn session_id(&self) -> &Hash32 {
        &self.session
    }
    pub fn main_key(&self) -> &PublicKey {
        &self.main
    }
    pub fn duress_key(&self) -> &PublicKey {
        &self.duress
    }

    /// `W*`, `G*`, `X*`: the earliest of the liveness, equivocation and hard-end
    /// schedules (session-v0, «Время»).
    pub fn deadlines(&self) -> Option<Deadlines> {
        let p = &self.policy;
        let (t, w, g) = (
            u64::from(p.timeout_blocks()),
            u64::from(p.warning_blocks()),
            u64::from(p.grace_blocks()),
        );
        let l = u64::from(self.liveness?);
        let hard_end = u64::from(p.hard_end_height());
        let w_hard = u64::from(p.w_hard().expect("policy invariant"));
        let g_hard = u64::from(p.g_hard());
        let mut d = Deadlines {
            warning: (l + t).min(w_hard),
            grace: (l + t + w).min(g_hard),
            release: (l + t + w + g).min(hard_end),
        };
        if let Some(e) = self.equivocation.map(u64::from) {
            d.warning = d.warning.min(e);
            d.grace = d.grace.min(e + w);
            d.release = d.release.min(e + w + g);
        }
        Some(d)
    }

    fn w_hard(&self) -> u32 {
        self.policy.w_hard().expect("policy invariant")
    }

    /// Applies the records of block `height`, then its time transitions.
    pub fn apply_block(
        &mut self,
        height: u32,
        records: &[Record],
    ) -> Result<Vec<LogEntry>, BlockError> {
        let expected = self.height.checked_add(1).expect("height below u32::MAX");
        if height != expected {
            return Err(BlockError::NotNext {
                expected,
                got: height,
            });
        }
        self.height = height;
        let mut log = Vec::new();
        for r in records {
            let rid = r.rid();
            let outcome = self.apply_record(height, r, rid);
            // Repeats are judged against records that were applied or recorded as
            // evidence or conflict; ignored and rejected records stay re-deliverable.
            if matches!(
                outcome,
                Outcome::Applied(_)
                    | Outcome::Equivocation
                    | Outcome::RepeatedEvidence
                    | Outcome::AdminConflict
            ) {
                self.seen.insert(rid);
            }
            log.push(LogEntry {
                height,
                rid: Some(rid),
                outcome,
                stage: self.stage,
            });
        }
        self.apply_timers(height, &mut log);
        Ok(log)
    }

    fn apply_timers(&mut self, h: u32, log: &mut Vec<LogEntry>) {
        let Some(d) = self.deadlines() else { return };
        let h = u64::from(h);
        loop {
            let next = match self.stage {
                Stage::Armed if h >= d.warning => Stage::Warning,
                Stage::Warning if h >= d.grace => Stage::Grace,
                Stage::Grace if h >= d.release => Stage::Released,
                _ => break,
            };
            self.stage = next;
            log.push(LogEntry {
                height: h as u32,
                rid: None,
                outcome: Outcome::Timer(next),
                stage: next,
            });
        }
    }

    fn in_window(&self, h: u32, r: &Record) -> bool {
        let issued = u64::from(r.header().issued_height);
        let h = u64::from(h);
        issued <= h && h <= issued + u64::from(self.policy.max_delay_blocks())
    }

    fn apply_record(&mut self, h: u32, r: &Record, rid: Hash32) -> Outcome {
        let hdr = r.header();
        if hdr.network != self.network
            || hdr.session != self.session
            || hdr.policy != self.policy.hash()
        {
            return Outcome::Rejected(Reject::WrongSession);
        }
        if self.seen.contains(&rid) {
            return Outcome::Ignored(Ignore::Duplicate);
        }
        let admin = r.unsigned().record_type().is_admin();
        if self.stage.is_terminal() {
            // An administrative conflict is recorded even after a terminal stage
            // (session-v0, «Административный конфликт»); nothing else is.
            if admin && self.in_window(h, r) && self.is_admin_conflict(r) {
                self.admin_conflict = true;
                return Outcome::AdminConflict;
            }
            return Outcome::Ignored(Ignore::Terminal);
        }
        if !self.in_window(h, r) {
            return Outcome::Rejected(Reject::OutsideDeliveryWindow);
        }
        if admin {
            self.apply_admin(h, r, rid)
        } else {
            self.apply_operational(h, r, rid)
        }
    }

    fn verifies(key: &PublicKey, r: &Record) -> bool {
        VerifyingKey::from_bytes(key)
            .map(|k| keys::verify(&k, &r.signed_message(), r.sig()))
            .unwrap_or(false)
    }

    fn apply_operational(&mut self, h: u32, r: &Record, rid: Hash32) -> Outcome {
        let hdr = r.header();
        if hdr.generation < self.generation {
            return Outcome::Ignored(Ignore::StaleGeneration);
        }
        if hdr.generation > self.generation {
            return Outcome::Rejected(Reject::FutureGeneration);
        }
        let rtype = r.unsigned().record_type();

        if self.stage == Stage::Setup {
            if rtype != RecordType::Heartbeat || !Self::verifies(&self.main, r) {
                return Outcome::Ignored(Ignore::NotArmed);
            }
            if hdr.epoch != 0 || hdr.prev != ZERO {
                return Outcome::Rejected(Reject::OutOfOrder);
            }
            if !(self.ready_height < h && h < self.w_hard()) {
                return Outcome::Rejected(Reject::NotReady);
            }
            self.accept_epoch(0, rid);
            self.liveness = Some(hdr.issued_height);
            self.stage = Stage::Armed;
            return Outcome::Applied(Effect::Armed);
        }

        // Armed, Warning or Grace. Duress with the current pair: release, no order check.
        if Self::verifies(&self.duress, r) {
            self.stage = Stage::Released;
            return Outcome::Applied(Effect::Released);
        }

        // A record for an epoch already taken in this generation can only be evidence,
        // checked against the main key that held that epoch.
        if let Some(&(applied_rid, epoch_main)) = self.op.applied.get(&hdr.epoch) {
            debug_assert_ne!(applied_rid, rid, "duplicates are filtered earlier");
            let main_type = matches!(rtype, RecordType::Heartbeat | RecordType::Rotate);
            if main_type && Self::verifies(&epoch_main, r) {
                if self.equivocation.is_none() {
                    self.equivocation = Some(h);
                    return Outcome::Equivocation;
                }
                return Outcome::RepeatedEvidence;
            }
            if rtype == RecordType::Panic && Self::verifies(&self.main, r) {
                self.stage = Stage::Released;
                return Outcome::Applied(Effect::Released);
            }
            return Outcome::Rejected(Reject::BadSignature);
        }

        if !Self::verifies(&self.main, r) {
            return Outcome::Rejected(Reject::BadSignature);
        }
        if rtype == RecordType::Panic {
            self.stage = Stage::Released;
            return Outcome::Applied(Effect::Released);
        }
        if self.equivocated() {
            return Outcome::Rejected(Reject::MainKeyAfterEquivocation);
        }
        if Some(hdr.epoch) != self.op.next_epoch() || hdr.prev != self.op.expected_prev() {
            return Outcome::Rejected(Reject::OutOfOrder);
        }
        match r.command() {
            Command::Heartbeat => {
                self.accept_epoch(hdr.epoch, rid);
                self.liveness = Some(hdr.issued_height);
                if matches!(self.stage, Stage::Warning | Stage::Grace) && h < self.w_hard() {
                    self.stage = Stage::Armed;
                }
                Outcome::Applied(Effect::Heartbeat)
            }
            Command::Rotate(k) => {
                if self.stage != Stage::Armed {
                    return Outcome::Rejected(Reject::RotateNotArmed);
                }
                if !self.fresh(k) {
                    return Outcome::Rejected(Reject::KeyReuse);
                }
                self.accept_epoch(hdr.epoch, rid);
                self.install(k);
                self.liveness = Some(hdr.issued_height);
                Outcome::Applied(Effect::Rotated)
            }
            _ => unreachable!("operational line"),
        }
    }

    /// A recovery-signed record for an administrative epoch already taken by another
    /// record (different rids: duplicates are filtered before).
    fn is_admin_conflict(&self, r: &Record) -> bool {
        self.admin_applied.contains_key(&r.header().epoch) && Self::verifies(&self.recovery, r)
    }

    fn apply_admin(&mut self, h: u32, r: &Record, rid: Hash32) -> Outcome {
        if !Self::verifies(&self.recovery, r) {
            return Outcome::Rejected(Reject::BadSignature);
        }
        let hdr = r.header();
        if self.is_admin_conflict(r) {
            self.admin_conflict = true;
            return Outcome::AdminConflict;
        }
        if self.stage == Stage::Setup {
            return Outcome::Ignored(Ignore::NotArmed);
        }
        let next = match self.admin_last {
            None => Some(0),
            Some(a) => a.checked_add(1),
        };
        if Some(hdr.epoch) != next || hdr.prev != self.admin_last_rid {
            return Outcome::Rejected(Reject::OutOfOrder);
        }
        match r.command() {
            Command::Cancel => {
                self.accept_admin(hdr.epoch, rid);
                self.stage = Stage::Closed;
                Outcome::Applied(Effect::Cancelled)
            }
            Command::Recover(k) => {
                if Some(hdr.generation) != self.generation.checked_add(1) {
                    return Outcome::Rejected(Reject::WrongGeneration);
                }
                if !self.fresh(k) {
                    return Outcome::Rejected(Reject::KeyReuse);
                }
                self.accept_admin(hdr.epoch, rid);
                self.generation = hdr.generation;
                self.install(k);
                self.op = OperationalLine::new(rid);
                self.equivocation = None;
                self.liveness = Some(hdr.issued_height);
                if matches!(self.stage, Stage::Warning | Stage::Grace) && h < self.w_hard() {
                    self.stage = Stage::Armed;
                }
                Outcome::Applied(Effect::Recovered {
                    generation: self.generation,
                })
            }
            _ => unreachable!("administrative line"),
        }
    }

    fn accept_epoch(&mut self, epoch: u64, rid: Hash32) {
        self.op.applied.insert(epoch, (rid, self.main));
        self.op.last_epoch = Some(epoch);
        self.op.last_rid = rid;
    }

    fn accept_admin(&mut self, epoch: u64, rid: Hash32) {
        self.admin_applied.insert(epoch, rid);
        self.admin_last = Some(epoch);
        self.admin_last_rid = rid;
    }

    /// New keys must never have been used in this session in any role.
    fn fresh(&self, k: &NewKeys) -> bool {
        !self.used_keys.contains(&k.main) && !self.used_keys.contains(&k.duress)
    }

    fn install(&mut self, k: &NewKeys) {
        self.main = k.main;
        self.duress = k.duress;
        self.used_keys.insert(k.main);
        self.used_keys.insert(k.duress);
    }
}

/// Decision height for a processed tip: the last block with `confirmations`
/// confirmations, the block itself included. None while there is no confirmed prefix.
pub fn decision_height(processed_tip: u32, confirmations: u8) -> Option<u32> {
    processed_tip.checked_sub(u32::from(confirmations).checked_sub(1)?)
}
