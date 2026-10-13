//! Session state machine tests against docs/session-v0.md (revision 2).
//!
//! `Owner` keeps both of its lines (operational epochs per generation, administrative
//! sequence) and produces correctly signed records; tests bend them where needed.

use ed25519_dalek::SigningKey;
use zecret_core::hash::{self, Hash32};
use zecret_core::policy::{Policy, PolicyParams, SetupV1};
use zecret_core::record::{Command, Header, NewKeys, Record, UnsignedRecord};
use zecret_core::session::{
    BlockError, Effect, Ignore, LogEntry, Outcome, Reject, Session, Stage, decision_height,
};

const REGTEST: u8 = 0x02;
const ZERO: Hash32 = [0; 32];

fn sk(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn pk(n: u8) -> [u8; 32] {
    sk(n).verifying_key().to_bytes()
}

struct Params {
    timeout: u32,
    warning: u32,
    grace: u32,
    max_delay: u32,
    hard_end: u32,
}

const DEFAULT: Params = Params {
    timeout: 10,
    warning: 5,
    grace: 5,
    max_delay: 4,
    hard_end: 300, // W_hard 290, G_hard 295
};

fn policy(p: &Params) -> Policy {
    let mut recipient = [7u8; 32];
    recipient[31] = 0x10;
    Policy::new(PolicyParams {
        network: REGTEST,
        threshold: 1,
        guardians: vec![pk(100)],
        timeout_blocks: p.timeout,
        warning_blocks: p.warning,
        grace_blocks: p.grace,
        max_delay_blocks: p.max_delay,
        confirmations: 1,
        hard_end_height: p.hard_end,
        recipients: vec![recipient],
        payload_hash: hash::h(hash::CIPHER, b"C"),
    })
    .unwrap()
}

#[derive(Clone)]
struct Owner {
    session: Hash32,
    policy: Hash32,
    main: u8,
    duress: u8,
    recovery: u8,
    generation: u32,
    epoch: Option<u64>,
    prev: Hash32,
    admin: Option<u64>,
    admin_prev: Hash32,
}

impl Owner {
    fn header(&self, generation: u32, epoch: u64, prev: Hash32, issued: u32) -> Header {
        Header {
            network: REGTEST,
            session: self.session,
            generation,
            epoch,
            issued_height: issued,
            prev,
            policy: self.policy,
        }
    }

    fn next_epoch(&self) -> u64 {
        self.epoch.map_or(0, |e| e + 1)
    }

    /// Any operational record at an explicit position, signed by key `signer`.
    fn op_at(&self, cmd: Command, epoch: u64, prev: Hash32, issued: u32, signer: u8) -> Record {
        UnsignedRecord::new(self.header(self.generation, epoch, prev, issued), cmd)
            .unwrap()
            .sign(&sk(signer))
    }

    /// The next operational record, signed by the current main key; advances the chain.
    fn next_op(&mut self, cmd: Command, issued: u32) -> Record {
        let r = self.op_at(cmd, self.next_epoch(), self.prev, issued, self.main);
        self.epoch = Some(self.next_epoch());
        self.prev = r.rid();
        r
    }

    fn heartbeat(&mut self, issued: u32) -> Record {
        self.next_op(Command::Heartbeat, issued)
    }

    fn rotate(&mut self, issued: u32, main: u8, duress: u8) -> Record {
        let r = self.next_op(
            Command::Rotate(NewKeys {
                main: pk(main),
                duress: pk(duress),
            }),
            issued,
        );
        self.main = main;
        self.duress = duress;
        r
    }

    /// PANIC with the current main key; does not advance (no order check).
    fn panic(&self, issued: u32) -> Record {
        self.op_at(
            Command::Panic,
            self.next_epoch(),
            self.prev,
            issued,
            self.main,
        )
    }

    /// A heartbeat signed with the duress key; does not advance.
    fn duress_heartbeat(&self, issued: u32) -> Record {
        self.op_at(
            Command::Heartbeat,
            self.next_epoch(),
            self.prev,
            issued,
            self.duress,
        )
    }

    fn admin_at(
        &self,
        cmd: Command,
        generation: u32,
        epoch: u64,
        prev: Hash32,
        issued: u32,
    ) -> Record {
        UnsignedRecord::new(self.header(generation, epoch, prev, issued), cmd)
            .unwrap()
            .sign(&sk(self.recovery))
    }

    fn next_admin_epoch(&self) -> u64 {
        self.admin.map_or(0, |a| a + 1)
    }

    fn cancel(&mut self, issued: u32) -> Record {
        let r = self.admin_at(
            Command::Cancel,
            0,
            self.next_admin_epoch(),
            self.admin_prev,
            issued,
        );
        self.admin = Some(self.next_admin_epoch());
        self.admin_prev = r.rid();
        r
    }

    fn recover(&mut self, issued: u32, main: u8, duress: u8) -> Record {
        let cmd = Command::Recover(NewKeys {
            main: pk(main),
            duress: pk(duress),
        });
        let r = self.admin_at(
            cmd,
            self.generation + 1,
            self.next_admin_epoch(),
            self.admin_prev,
            issued,
        );
        self.admin = Some(self.next_admin_epoch());
        self.admin_prev = r.rid();
        self.generation += 1;
        self.epoch = None;
        self.prev = r.rid();
        self.main = main;
        self.duress = duress;
        r
    }
}

struct Chain {
    s: Session,
}

impl Chain {
    fn next(&self) -> u32 {
        self.s.height() + 1
    }
    fn block(&mut self, records: Vec<Record>) -> Vec<LogEntry> {
        let h = self.next();
        self.s.apply_block(h, &records).unwrap()
    }
    /// Applies empty blocks so that the next block is `h`.
    fn skip_to(&mut self, h: u32) {
        while self.next() < h {
            self.block(vec![]);
        }
    }
    fn stage(&self) -> Stage {
        self.s.stage()
    }
}

fn outcomes(log: &[LogEntry]) -> Vec<Outcome> {
    log.iter().map(|e| e.outcome.clone()).collect()
}

fn start(p: &Params, ready: u32) -> (Chain, Owner) {
    let pol = policy(p);
    let owner = Owner {
        session: hash::session_id(b"session"),
        policy: pol.hash(),
        main: 1,
        duress: 2,
        recovery: 3,
        generation: 0,
        epoch: None,
        prev: ZERO,
        admin: None,
        admin_prev: ZERO,
    };
    let setup = SetupV1::new(owner.session, pol, pk(1), pk(2), pk(3)).unwrap();
    (
        Chain {
            s: Session::new(&setup, ready),
        },
        owner,
    )
}

/// Armed at block 101 with liveness 101.
fn armed() -> (Chain, Owner) {
    let (mut c, mut o) = start(&DEFAULT, 100);
    let hb = o.heartbeat(101);
    assert_eq!(
        outcomes(&c.block(vec![hb])),
        vec![Outcome::Applied(Effect::Armed)]
    );
    (c, o)
}

// --- arming ---------------------------------------------------------------------------

#[test]
fn blocks_must_be_consecutive() {
    let (mut c, _) = start(&DEFAULT, 100);
    assert_eq!(
        c.s.apply_block(102, &[]),
        Err(BlockError::NotNext {
            expected: 101,
            got: 102
        })
    );
    assert!(c.s.apply_block(101, &[]).is_ok());
}

#[test]
fn setup_ignores_everything_but_the_first_heartbeat() {
    let (mut c, mut o) = start(&DEFAULT, 100);
    let log = c.block(vec![
        o.panic(101),
        o.duress_heartbeat(101),
        o.clone().cancel(101),
    ]);
    assert_eq!(
        outcomes(&log),
        vec![
            Outcome::Ignored(Ignore::NotArmed),
            Outcome::Ignored(Ignore::NotArmed),
            Outcome::Ignored(Ignore::NotArmed)
        ]
    );
    assert_eq!(c.stage(), Stage::Setup);
    let hb = o.heartbeat(102);
    assert_eq!(
        outcomes(&c.block(vec![hb])),
        vec![Outcome::Applied(Effect::Armed)]
    );
}

#[test]
fn first_heartbeat_only_strictly_before_w_hard() {
    // hard_end 130: W_hard 120, G_hard 125.
    let p = Params {
        hard_end: 130,
        ..DEFAULT
    };
    for (at, armed) in [(119, true), (120, false), (130, false), (135, false)] {
        let (mut c, mut o) = start(&p, 100);
        c.skip_to(at);
        let log = c.block(vec![o.heartbeat(at)]);
        let expected = if armed {
            Outcome::Applied(Effect::Armed)
        } else {
            Outcome::Rejected(Reject::NotReady)
        };
        assert_eq!(log[0].outcome, expected, "first heartbeat at {at}");
    }
}

#[test]
fn ready_height_is_the_lower_bound() {
    // The session processes blocks only after ready_height; a heartbeat issued before
    // readiness but still inside the delivery window is accepted at the first block.
    let (mut c, mut o) = start(&DEFAULT, 100);
    let hb = o.heartbeat(98);
    assert_eq!(
        outcomes(&c.block(vec![hb])),
        vec![Outcome::Applied(Effect::Armed)]
    );
    let (mut c, mut o) = start(&DEFAULT, 100);
    let hb = o.heartbeat(95); // 101 > 95 + 4
    assert_eq!(
        outcomes(&c.block(vec![hb])),
        vec![Outcome::Rejected(Reject::OutsideDeliveryWindow)]
    );
}

// --- liveness, stages and time ----------------------------------------------------------

#[test]
fn silence_walks_through_warning_and_grace_to_release() {
    let (mut c, _) = armed(); // L = 101: W* 111, G* 116, X* 121
    c.skip_to(111);
    assert_eq!(c.stage(), Stage::Armed);
    assert_eq!(
        outcomes(&c.block(vec![])),
        vec![Outcome::Timer(Stage::Warning)]
    );
    c.skip_to(116);
    assert_eq!(
        outcomes(&c.block(vec![])),
        vec![Outcome::Timer(Stage::Grace)]
    );
    c.skip_to(121);
    assert_eq!(
        outcomes(&c.block(vec![])),
        vec![Outcome::Timer(Stage::Released)]
    );
}

#[test]
fn heartbeat_in_the_deadline_block_counts() {
    let (mut c, mut o) = armed();
    c.skip_to(111); // W* = 111
    let log = c.block(vec![o.heartbeat(111)]);
    assert_eq!(outcomes(&log), vec![Outcome::Applied(Effect::Heartbeat)]);
    assert_eq!(c.stage(), Stage::Armed, "events before timers");
}

#[test]
fn heartbeat_returns_from_warning_and_grace() {
    for stage_at in [(112, Stage::Warning), (117, Stage::Grace)] {
        let (mut c, mut o) = armed();
        c.skip_to(stage_at.0);
        assert_eq!(c.stage(), stage_at.1);
        let hb = o.heartbeat(stage_at.0);
        c.block(vec![hb]);
        assert_eq!(c.stage(), Stage::Armed);
    }
}

#[test]
fn stage_does_not_step_back_inside_the_final_window() {
    // Codex review #3 trace: timeout 10, warning 5, grace 5, hard_end 110, L = 85.
    let p = Params {
        hard_end: 110,
        ..DEFAULT
    };
    let (mut c, mut o) = start(&p, 80);
    c.skip_to(85);
    c.block(vec![o.heartbeat(85)]);
    c.skip_to(96);
    assert_eq!(c.stage(), Stage::Warning, "W* = 95");
    c.skip_to(101);
    assert_eq!(c.stage(), Stage::Grace, "G* = 100");
    let log = c.block(vec![o.heartbeat(101)]);
    assert_eq!(outcomes(&log), vec![Outcome::Applied(Effect::Heartbeat)]);
    assert_eq!(
        c.stage(),
        Stage::Grace,
        "h >= W_hard: no return, no step back"
    );
    let d = c.s.deadlines().unwrap();
    assert_eq!((d.warning, d.grace, d.release), (100, 105, 110));
    c.skip_to(110);
    assert_eq!(
        outcomes(&c.block(vec![])),
        vec![Outcome::Timer(Stage::Released)]
    );
}

#[test]
fn nothing_moves_release_past_hard_end() {
    // Heartbeats every block, a rotation and a recovery: release still at hard_end.
    let p = Params {
        hard_end: 160,
        ..DEFAULT
    }; // W_hard 150, G_hard 155
    let (mut c, mut o) = start(&p, 100);
    let mut released_at = None;
    let mut next_key = 20;
    for h in 101..=170 {
        let mut recs = vec![o.heartbeat(h)];
        if h == 130 {
            recs.push(o.rotate(h, next_key, next_key + 1));
            next_key += 2;
        }
        if h == 151 {
            recs = vec![o.recover(h, next_key, next_key + 1)];
            next_key += 2;
        }
        let log = c.block(recs);
        if c.stage() == Stage::Released && released_at.is_none() {
            released_at = Some(h);
            assert!(
                log.iter()
                    .any(|e| e.outcome == Outcome::Timer(Stage::Released))
            );
        }
        if c.stage().is_terminal() {
            break;
        }
    }
    assert_eq!(released_at, Some(160));
}

#[test]
fn hard_end_schedule_with_a_live_owner() {
    let p = Params {
        hard_end: 160,
        ..DEFAULT
    };
    let (mut c, mut o) = start(&p, 100);
    for h in 101..150 {
        c.block(vec![o.heartbeat(h)]);
    }
    assert_eq!(c.stage(), Stage::Armed);
    c.block(vec![o.heartbeat(150)]); // W_hard: heartbeat applies, then timer
    assert_eq!(c.stage(), Stage::Warning);
    for h in 151..155 {
        c.block(vec![o.heartbeat(h)]);
        assert_eq!(c.stage(), Stage::Warning, "no return to armed after W_hard");
    }
    c.block(vec![o.heartbeat(155)]);
    assert_eq!(c.stage(), Stage::Grace, "G_hard");
}

#[test]
fn liveness_release_comes_before_hard_end_when_owner_is_silent() {
    let p = Params {
        hard_end: 300,
        ..DEFAULT
    };
    let (mut c, _) = {
        let (mut c, mut o) = start(&p, 100);
        c.block(vec![o.heartbeat(101)]);
        (c, o)
    };
    c.skip_to(121);
    c.block(vec![]);
    assert_eq!(c.stage(), Stage::Released);
    assert!(c.s.height() < 300);
}

#[test]
fn rotate_on_w_hard_block_passes_but_not_after() {
    let p = Params {
        hard_end: 160,
        ..DEFAULT
    }; // W_hard 150
    let (mut c, mut o) = start(&p, 100);
    for h in 101..150 {
        c.block(vec![o.heartbeat(h)]);
    }
    let log = c.block(vec![o.rotate(150, 20, 21)]);
    assert_eq!(log[0].outcome, Outcome::Applied(Effect::Rotated));
    assert_eq!(c.stage(), Stage::Warning);
    let log = c.block(vec![o.clone().rotate(151, 22, 23)]);
    assert_eq!(log[0].outcome, Outcome::Rejected(Reject::RotateNotArmed));
}

#[test]
fn cancel_and_heartbeat_in_the_hard_end_block() {
    let p = Params {
        hard_end: 160,
        ..DEFAULT
    };
    let setup = |o: &mut Owner, c: &mut Chain| {
        for h in 101..160 {
            c.block(vec![o.heartbeat(h)]);
        }
    };
    let (mut c, mut o) = start(&p, 100);
    setup(&mut o, &mut c);
    let cancel = o.cancel(160);
    let log = c.block(vec![cancel, o.heartbeat(160)]);
    assert_eq!(log[0].outcome, Outcome::Applied(Effect::Cancelled));
    assert_eq!(log[1].outcome, Outcome::Ignored(Ignore::Terminal));
    assert_eq!(c.stage(), Stage::Closed);

    let (mut c, mut o) = start(&p, 100);
    setup(&mut o, &mut c);
    let log = c.block(vec![o.heartbeat(160)]);
    assert_eq!(log[0].outcome, Outcome::Applied(Effect::Heartbeat));
    assert_eq!(
        c.stage(),
        Stage::Released,
        "heartbeat does not cancel release at hard_end"
    );
}

#[test]
fn panic_and_cancel_in_one_block_first_wins() {
    let (mut c, mut o) = armed();
    let (panic, cancel) = (o.panic(102), o.cancel(102));
    let log = c.block(vec![panic.clone(), cancel.clone()]);
    assert_eq!(
        outcomes(&log),
        vec![
            Outcome::Applied(Effect::Released),
            Outcome::Ignored(Ignore::Terminal)
        ]
    );

    let (mut c, mut o) = armed();
    let (panic, cancel) = (o.panic(102), o.cancel(102));
    let log = c.block(vec![cancel, panic]);
    assert_eq!(
        outcomes(&log),
        vec![
            Outcome::Applied(Effect::Cancelled),
            Outcome::Ignored(Ignore::Terminal)
        ]
    );
}

#[test]
fn ignored_records_stay_re_deliverable() {
    // A PANIC ignored in Setup is not "seen": delivered again after arming (still
    // inside its delivery window) it applies instead of being dropped as a repeat.
    let (mut c, mut o) = start(&DEFAULT, 100);
    let panic = o.op_at(Command::Panic, 1, ZERO, 101, 1);
    assert_eq!(
        c.block(vec![panic.clone()])[0].outcome,
        Outcome::Ignored(Ignore::NotArmed)
    );
    c.block(vec![o.heartbeat(102)]);
    assert_eq!(
        c.block(vec![panic])[0].outcome,
        Outcome::Applied(Effect::Released)
    );
}

#[test]
fn records_of_another_session_are_rejected() {
    let (mut c, o) = armed();
    let mut other = o.clone();
    other.session = hash::session_id(b"another");
    assert_eq!(
        c.block(vec![other.panic(102)])[0].outcome,
        Outcome::Rejected(Reject::WrongSession)
    );
    let mut other = o.clone();
    other.policy = [9; 32];
    assert_eq!(
        c.block(vec![other.panic(103)])[0].outcome,
        Outcome::Rejected(Reject::WrongSession)
    );
    assert_eq!(c.stage(), Stage::Armed);
}

// --- authority and lines -----------------------------------------------------------------

#[test]
fn main_key_records_before_cancel_do_not_void_it() {
    // V2-R1: the administrative line does not depend on the operational one.
    let (mut c, mut o) = armed();
    let cancel = o.cancel(102); // prepared before the heartbeats below
    c.block(vec![o.heartbeat(102), o.rotate(102, 20, 21)]);
    c.block(vec![o.heartbeat(103)]);
    let log = c.block(vec![cancel]);
    assert_eq!(log[0].outcome, Outcome::Applied(Effect::Cancelled));
}

#[test]
fn admin_records_need_the_recovery_key_and_order() {
    let (mut c, o) = armed();
    let forged = UnsignedRecord::new(o.header(0, 0, ZERO, 102), Command::Cancel)
        .unwrap()
        .sign(&sk(1)); // main key
    assert_eq!(
        c.block(vec![forged])[0].outcome,
        Outcome::Rejected(Reject::BadSignature)
    );
    let skipped = o.admin_at(Command::Cancel, 0, 1, ZERO, 103);
    assert_eq!(
        c.block(vec![skipped])[0].outcome,
        Outcome::Rejected(Reject::OutOfOrder)
    );
    assert_eq!(c.stage(), Stage::Armed);
}

#[test]
fn panic_and_duress_release_with_current_keys_only() {
    let (mut c, o) = armed();
    assert_eq!(
        c.block(vec![o.panic(102)])[0].outcome,
        Outcome::Applied(Effect::Released)
    );

    let (mut c, o) = armed();
    assert_eq!(
        c.block(vec![o.duress_heartbeat(102)])[0].outcome,
        Outcome::Applied(Effect::Released)
    );

    // After a rotation the old duress key no longer releases.
    let (mut c, mut o) = armed();
    let old = o.clone();
    c.block(vec![o.rotate(102, 20, 21)]);
    let log = c.block(vec![old.duress_heartbeat(103)]);
    assert_eq!(log[0].outcome, Outcome::Rejected(Reject::BadSignature));
    assert_eq!(c.stage(), Stage::Armed);
}

#[test]
fn operational_order_is_checked() {
    let (mut c, o) = armed();
    let gap = o.op_at(Command::Heartbeat, 2, o.prev, 102, o.main);
    assert_eq!(
        c.block(vec![gap])[0].outcome,
        Outcome::Rejected(Reject::OutOfOrder)
    );
    let wrong_prev = o.op_at(Command::Heartbeat, 1, [9; 32], 103, o.main);
    assert_eq!(
        c.block(vec![wrong_prev])[0].outcome,
        Outcome::Rejected(Reject::OutOfOrder)
    );
    let future = UnsignedRecord::new(o.header(1, 0, ZERO, 104), Command::Heartbeat)
        .unwrap()
        .sign(&sk(1));
    assert_eq!(
        c.block(vec![future])[0].outcome,
        Outcome::Rejected(Reject::FutureGeneration)
    );
}

#[test]
fn delivery_window_and_duplicates() {
    let (mut c, mut o) = armed();
    c.skip_to(110);
    let late = o.clone().heartbeat(105); // 110 > 105 + 4
    assert_eq!(
        c.block(vec![late])[0].outcome,
        Outcome::Rejected(Reject::OutsideDeliveryWindow)
    );
    let early = o.clone().heartbeat(112); // issued after inclusion
    assert_eq!(
        c.block(vec![early])[0].outcome,
        Outcome::Rejected(Reject::OutsideDeliveryWindow)
    );
    let hb = o.heartbeat(110);
    assert_eq!(
        c.block(vec![hb.clone()])[0].outcome,
        Outcome::Applied(Effect::Heartbeat)
    );
    assert_eq!(
        c.block(vec![hb])[0].outcome,
        Outcome::Ignored(Ignore::Duplicate)
    );
}

#[test]
fn keys_are_never_reused() {
    let (mut c, mut o) = armed();
    let reuse_recovery = o.clone().rotate(102, 3, 30);
    assert_eq!(
        c.block(vec![reuse_recovery])[0].outcome,
        Outcome::Rejected(Reject::KeyReuse)
    );
    c.block(vec![o.rotate(103, 20, 21)]);
    let back_to_old = o.clone().rotate(104, 1, 22);
    assert_eq!(
        c.block(vec![back_to_old])[0].outcome,
        Outcome::Rejected(Reject::KeyReuse)
    );
    let recover_old = o.clone().recover(105, 2, 23);
    assert_eq!(
        c.block(vec![recover_old])[0].outcome,
        Outcome::Rejected(Reject::KeyReuse)
    );
    assert_eq!(c.s.generation(), 0);
}

// --- equivocation and recovery -------------------------------------------------------------

#[test]
fn equivocation_moves_to_warning_and_locks_the_main_key() {
    let (mut c, mut o) = armed();
    let fork = o.clone();
    let a = o.heartbeat(102);
    let b = fork.clone().heartbeat(103); // same epoch 1, different issued_height
    c.block(vec![a]);
    let log = c.block(vec![b]);
    assert_eq!(
        outcomes(&log),
        vec![Outcome::Equivocation, Outcome::Timer(Stage::Warning)]
    );
    assert!(c.s.equivocated());
    let before = c.s.deadlines();
    let c2 = fork.op_at(Command::Heartbeat, 1, fork.prev, 104, fork.main);
    assert_eq!(c.block(vec![c2])[0].outcome, Outcome::RepeatedEvidence);
    assert_eq!(
        c.s.deadlines(),
        before,
        "repeated evidence does not move deadlines"
    );
    assert_eq!(
        c.block(vec![o.clone().heartbeat(105)])[0].outcome,
        Outcome::Rejected(Reject::MainKeyAfterEquivocation)
    );
    assert_eq!(
        c.block(vec![o.panic(106)])[0].outcome,
        Outcome::Applied(Effect::Released)
    );
}

#[test]
fn equivocation_graph_releases_without_recovery() {
    let (mut c, mut o) = armed();
    let fork = o.clone();
    c.block(vec![o.heartbeat(102)]);
    c.block(vec![fork.clone().heartbeat(103)]); // E = 103
    c.skip_to(113);
    assert_eq!(
        c.block(vec![])[0].outcome,
        Outcome::Timer(Stage::Released),
        "E + 5 + 5"
    );
}

#[test]
fn late_conflict_then_recover_opens_a_new_generation() {
    // V2-R2: conflict on epoch 1 found after epochs 2 and 3 are accepted.
    let (mut c, mut o) = armed();
    let fork = o.clone();
    c.block(vec![o.heartbeat(102)]); // epoch 1
    c.block(vec![o.heartbeat(103)]); // epoch 2
    c.block(vec![o.heartbeat(104)]); // epoch 3
    let conflicting = fork.clone().heartbeat(103); // epoch 1, different issued: another rid, delivered at 105
    assert_eq!(c.block(vec![conflicting])[0].outcome, Outcome::Equivocation);

    let rec = o.recover(106, 20, 21);
    let log = c.block(vec![rec]);
    assert_eq!(
        log[0].outcome,
        Outcome::Applied(Effect::Recovered { generation: 1 })
    );
    assert_eq!(c.stage(), Stage::Armed);
    assert!(!c.s.equivocated());
    assert_eq!(
        c.block(vec![o.heartbeat(107)])[0].outcome,
        Outcome::Applied(Effect::Heartbeat)
    );

    // Anything of generation 0 is now stale, whatever key signs it.
    let stale = fork.clone().heartbeat(108);
    assert_eq!(
        c.block(vec![stale])[0].outcome,
        Outcome::Ignored(Ignore::StaleGeneration)
    );
}

#[test]
fn old_key_cannot_reopen_equivocation_after_recover() {
    // V2-R3.
    let (mut c, mut o) = armed();
    let old = o.clone();
    c.block(vec![o.heartbeat(102)]);
    c.block(vec![old.clone().heartbeat(103)]); // evidence in generation 0
    c.block(vec![o.recover(104, 20, 21)]);
    assert!(!c.s.equivocated());
    let again = old.op_at(Command::Heartbeat, 1, old.prev, 105, old.main);
    assert_eq!(
        c.block(vec![again])[0].outcome,
        Outcome::Ignored(Ignore::StaleGeneration)
    );
    assert!(!c.s.equivocated());
    assert_eq!(c.stage(), Stage::Armed);

    // Equivocation with the current key of generation 1 is still detected.
    let fork = o.clone();
    c.block(vec![o.heartbeat(106)]);
    assert_eq!(
        c.block(vec![fork.clone().heartbeat(107)])[0].outcome,
        Outcome::Equivocation
    );
}

#[test]
fn recover_without_equivocation_after_losing_the_phone() {
    let (mut c, mut o) = armed();
    c.skip_to(112); // warning
    assert_eq!(c.stage(), Stage::Warning);
    c.block(vec![o.recover(112, 20, 21)]);
    assert_eq!(c.stage(), Stage::Armed);
    assert_eq!(c.s.generation(), 1);
    assert_eq!(c.s.main_key(), &pk(20));
}

#[test]
fn recover_must_open_exactly_the_next_generation() {
    let (mut c, o) = armed();
    let cmd = Command::Recover(NewKeys {
        main: pk(20),
        duress: pk(21),
    });
    let skip = o.admin_at(cmd, 2, 0, ZERO, 102);
    assert_eq!(
        c.block(vec![skip])[0].outcome,
        Outcome::Rejected(Reject::WrongGeneration)
    );
}

#[test]
fn admin_conflicts_are_recorded_even_after_a_terminal_stage() {
    let (mut c, mut o) = armed();
    let other = o.clone();
    c.block(vec![o.recover(102, 20, 21)]); // admin epoch 0
    let conflicting = other.clone().cancel(103); // admin epoch 0 too
    assert_eq!(
        c.block(vec![conflicting])[0].outcome,
        Outcome::AdminConflict
    );
    assert!(c.s.admin_conflict());
    assert_eq!(c.stage(), Stage::Armed);

    let (mut c, mut o) = armed();
    let other = o.clone();
    c.block(vec![o.cancel(102)]);
    assert_eq!(c.stage(), Stage::Closed);
    let conflicting = other.clone().recover(103, 20, 21);
    assert_eq!(
        c.block(vec![conflicting])[0].outcome,
        Outcome::AdminConflict
    );
    assert!(c.s.admin_conflict());
    assert_eq!(
        c.stage(),
        Stage::Closed,
        "a late conflict never turns CANCEL into release"
    );
}

// --- determinism, prefix and reorgs -----------------------------------------------------------

fn scripted_chain() -> (Vec<Vec<Record>>, Owner) {
    let (_, mut o) = start(&DEFAULT, 100);
    let fork = o.clone();
    let mut blocks = vec![vec![o.heartbeat(101)], vec![], vec![o.heartbeat(103)]];
    blocks.push(vec![o.rotate(104, 20, 21), fork.clone().heartbeat(104)]);
    blocks.extend((0..6).map(|_| vec![]));
    blocks.push(vec![o.recover(111, 30, 31)]);
    blocks.push(vec![o.heartbeat(112)]);
    blocks.extend((0..25).map(|_| vec![]));
    (blocks, o)
}

fn run(blocks: &[Vec<Record>]) -> (Session, Vec<LogEntry>) {
    let (mut c, _) = start(&DEFAULT, 100);
    let mut log = Vec::new();
    for b in blocks {
        log.extend(c.block(b.clone()));
    }
    (c.s, log)
}

#[test]
fn replay_and_restart_give_the_same_state() {
    let (blocks, _) = scripted_chain();
    let (a, log_a) = run(&blocks);
    let (b, log_b) = run(&blocks);
    assert_eq!(a, b);
    assert_eq!(log_a, log_b);
    // Restart midway from a snapshot.
    let (mut c, _) = start(&DEFAULT, 100);
    for b in &blocks[..12] {
        c.block(b.clone());
    }
    let snapshot = c.s.clone();
    let mut resumed = Chain { s: snapshot };
    for b in &blocks[12..] {
        resumed.block(b.clone());
    }
    assert_eq!(resumed.s, a);
    assert_eq!(a.stage(), Stage::Released);
}

#[test]
fn reorg_by_snapshot_equals_a_fresh_run_on_the_new_chain() {
    let (old_blocks, _) = scripted_chain();
    for depth in [1usize, 2, 3, 4] {
        let fork_at = 12 - depth; // blocks[fork_at..12] are replaced
        let (mut c, _) = start(&DEFAULT, 100);
        let mut snapshots = vec![c.s.clone()];
        for b in &old_blocks[..12] {
            c.block(b.clone());
            snapshots.push(c.s.clone());
        }
        // New branch: the same blocks without records (the recovery never happened).
        let mut new_blocks = old_blocks[..fork_at].to_vec();
        new_blocks.extend((fork_at..30).map(|_| vec![]));
        let mut c = Chain {
            s: snapshots[fork_at].clone(),
        };
        for b in &new_blocks[fork_at..] {
            c.block(b.clone());
        }
        let (fresh, _) = run(&new_blocks);
        assert_eq!(c.s, fresh, "depth {depth}");
    }
}

#[test]
fn decision_height_counts_the_block_itself() {
    assert_eq!(decision_height(110, 1), Some(110));
    assert_eq!(decision_height(110, 3), Some(108));
    assert_eq!(decision_height(1, 3), None);
    assert_eq!(decision_height(2, 3), Some(0));
    assert_eq!(decision_height(5, 0), None);
}

#[test]
fn panic_in_the_unconfirmed_tail_is_not_applied() {
    // confirmations = 3: a guardian applies blocks only up to decision_height(tip).
    let (mut c, o) = armed();
    let panic_block = 105u32;
    let mut chain: Vec<Vec<Record>> = (102..=107).map(|_| vec![]).collect();
    chain[(panic_block - 102) as usize] = vec![o.panic(panic_block)];
    let mut tip = 104;
    while tip <= 107 {
        let target = decision_height(tip, 3).unwrap();
        while c.s.height() < target {
            let b = chain[(c.s.height() + 1 - 102) as usize].clone();
            c.block(b);
        }
        let expect_released = target >= panic_block;
        assert_eq!(c.stage() == Stage::Released, expect_released, "tip {tip}");
        tip += 1;
    }
}
