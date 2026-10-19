//! The command executor: an ordered, bounded, idempotent queue that runs
//! validated commands in the game on the game thread, one guarded call at a
//! time.
//!
//! Where the Python bridge stopped the server thread in a debugger, rewrote its
//! registers and retried the queue write, the native core calls the game
//! function directly from inside the WRITE detour (game lock held, server
//! thread). The consequences this module handles:
//!
//! * **no nesting**: a game function may write a batch itself and re-enter the
//!   detour; `pump` refuses to run while a call is in progress;
//! * **live-state guards**: every command names the phases it is valid in; when
//!   the game is elsewhere it waits (bounded age) instead of being forced;
//! * **ordering**: commands carry `(stream, seq)`; a stream runs strictly in
//!   order, a hole is waited for (bounded) and then skipped and counted;
//! * **idempotency**: a repeated `(stream, seq)` returns the stored outcome and
//!   never calls the game twice; a seq older than the stream's progress that was
//!   never run is `Stale`;
//! * **bounded**: queue length, calls per pump and the finished-outcome memory
//!   have hard limits;
//! * **fail-stop**: a call whose verification fails halts the executor, so one
//!   inconsistency cannot snowball into more game calls.

use crate::command::{validate, Command, Image};
use crate::Result;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const MAX_QUEUE: usize = 4096;
/// Game calls per pump (one WRITE).
pub const CALLS_PER_PUMP: usize = 24;
/// Pumps a command may wait for its game state before it expires.
pub const MAX_DEFER_PUMPS: u32 = 3000;
/// Pumps a hole in a stream is waited for before it is skipped.
pub const GAP_PUMPS: u32 = 600;
/// Finished outcomes remembered for duplicate detection.
pub const MEMORY: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The game function ran and its verification passed.
    Done,
    /// Refused before running: the arguments are out of bounds.
    Rejected,
    /// Waited too long for the right game state.
    Expired,
    /// The call ran but the game did not reach the expected state; the executor halted.
    Failed,
    /// The same `(stream, seq)` had already finished; this is its stored outcome.
    Duplicate(OutcomeKind),
    /// Older than the stream's progress and never run.
    Stale,
}

/// The outcome kinds a duplicate can repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    Done,
    Rejected,
    Expired,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Completion {
    pub stream: u8,
    pub seq: u64,
    pub outcome: Outcome,
    pub reason: Option<String>,
}

/// The phases of the game's run state machine that matter for guards.
pub mod phase {
    pub const MENU: u8 = 0;
    pub const PLAYING: u8 = 1;
    pub const CHOOSING: u8 = 2;
    pub const PAUSED: u8 = 3;
    pub const DOWNED: u8 = 4;
    pub const RESULT: u8 = 5;
}

/// What the executor needs from the game.
pub trait Env {
    /// Current run phase (`Game+0x8BF`).
    fn phase(&self) -> u8;
    /// The shared (co-op) pause is on.
    fn paused(&self) -> bool;
    /// Called before a command runs; captures state `verify` compares against.
    fn before(&mut self, command: &Command) -> Result<()>;
    /// Calls the game function. Only ever invoked with a validated, guarded command.
    fn call(&mut self, command: &Command) -> Result<()>;
    /// Checks that the call had its effect (spawn count, phase, pending counters).
    fn verify(&mut self, command: &Command) -> Result<()>;
}

/// Phases a command may run in; `None` means any phase.
pub fn allowed_phases(command: &Command) -> Option<&'static [u8]> {
    use phase::*;
    Some(match command {
        Command::Start => &[MENU],
        Command::UiCommand { .. } => &[RESULT],
        Command::Pause { ui_only: false } => &[PLAYING],
        Command::Pause { ui_only: true } | Command::Resume { ui_only: true } => &[DOWNED],
        Command::Resume { ui_only: false } => &[PAUSED],
        Command::AwardXp { amount: 0 } => &[PLAYING],
        Command::AwardXp { .. } => &[PLAYING, CHOOSING, PAUSED, DOWNED],
        Command::Damage { .. } | Command::Hurt { .. } => &[PLAYING],
        Command::Spawn { .. } | Command::SpawnLoot { .. } | Command::SpawnBoss { .. } => &[PLAYING],
        Command::OfferChoices { .. } | Command::RemoveLoot { .. } => &[PLAYING],
        Command::ApplyEffect { .. } | Command::ApplyDot { .. } => &[PLAYING],
    })
}

/// Commands that must not run while the shared pause is on.
fn needs_unpaused(command: &Command) -> bool {
    matches!(command, Command::Damage { .. } | Command::Hurt { .. } | Command::Spawn { .. } | Command::ApplyEffect { .. } | Command::ApplyDot { .. })
}

struct Entry {
    stream: u8,
    seq: u64,
    command: Command,
    age: u32,
}

struct Stream {
    /// The next seq to release into the ready queue (seqs start at 1).
    next: u64,
    /// Entries that arrived ahead of a hole: seq -> entry.
    ahead: BTreeMap<u64, Entry>,
    /// Seqs already settled (rejected on submit) that are ahead of `next`.
    consumed: BTreeSet<u64>,
    /// Pumps the current hole has been waited for.
    gap_age: u32,
}

impl Default for Stream {
    fn default() -> Stream {
        Stream { next: 1, ahead: BTreeMap::new(), consumed: BTreeSet::new(), gap_age: 0 }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub submitted: u64,
    pub done: u64,
    pub rejected: u64,
    pub expired: u64,
    pub failed: u64,
    pub duplicates: u64,
    pub stale: u64,
    pub skipped_gaps: u64,
    pub deferred_pumps: u64,
}

pub struct Executor {
    image: Image,
    streams: BTreeMap<u8, Stream>,
    /// In-order entries ready to run, across streams, in arrival order.
    ready: VecDeque<Entry>,
    memory: VecDeque<((u8, u64), OutcomeKind)>,
    in_call: bool,
    halted: bool,
    pub stats: Stats,
}

impl Executor {
    pub fn new(image: Image) -> Executor {
        Executor { image, streams: BTreeMap::new(), ready: VecDeque::new(), memory: VecDeque::new(), in_call: false, halted: false, stats: Stats::default() }
    }

    pub fn halted(&self) -> bool {
        self.halted
    }

    /// Re-arms the executor after a reviewed halt (a new run, or the user's decision).
    pub fn reset(&mut self) {
        self.halted = false;
        self.ready.clear();
        self.streams.clear();
    }

    pub fn pending(&self) -> usize {
        self.ready.len() + self.streams.values().map(|s| s.ahead.len()).sum::<usize>()
    }

    fn remembered(&self, key: (u8, u64)) -> Option<OutcomeKind> {
        self.memory.iter().find(|(k, _)| *k == key).map(|(_, o)| *o)
    }

    fn remember(&mut self, key: (u8, u64), kind: OutcomeKind) {
        if self.memory.len() >= MEMORY {
            self.memory.pop_front();
        }
        self.memory.push_back((key, kind));
    }

    /// Queues a command. Returns an immediate completion for duplicates, stale
    /// and malformed commands; `Ok(None)` means it is queued.
    pub fn submit(&mut self, stream: u8, seq: u64, command: Command) -> Result<Option<Completion>> {
        self.stats.submitted += 1;
        if seq == 0 {
            return Err("Command sequence numbers start at 1".into());
        }
        if let Some(kind) = self.remembered((stream, seq)) {
            self.stats.duplicates += 1;
            return Ok(Some(Completion { stream, seq, outcome: Outcome::Duplicate(kind), reason: None }));
        }
        let queued = self.ready.iter().any(|e| e.stream == stream && e.seq == seq)
            || self.streams.get(&stream).is_some_and(|s| s.ahead.contains_key(&seq) || s.consumed.contains(&seq));
        if queued {
            self.stats.duplicates += 1;
            return Ok(Some(Completion { stream, seq, outcome: Outcome::Duplicate(OutcomeKind::Skipped), reason: Some("already queued".into()) }));
        }
        let next = self.streams.entry(stream).or_default().next;
        if seq < next {
            self.stats.stale += 1;
            return Ok(Some(Completion { stream, seq, outcome: Outcome::Stale, reason: None }));
        }
        if let Err(reason) = validate(&command, self.image) {
            // A malformed command still takes its place in the order.
            self.stats.rejected += 1;
            self.remember((stream, seq), OutcomeKind::Rejected);
            self.streams.get_mut(&stream).unwrap().consumed.insert(seq);
            self.promote(stream);
            return Ok(Some(Completion { stream, seq, outcome: Outcome::Rejected, reason: Some(reason) }));
        }
        if self.pending() >= MAX_QUEUE {
            return Err("Executor queue is full".into());
        }
        self.streams.get_mut(&stream).unwrap().ahead.insert(seq, Entry { stream, seq, command, age: 0 });
        self.promote(stream);
        Ok(None)
    }

    /// Releases entries that are next in their stream to the ready queue.
    fn promote(&mut self, stream: u8) {
        let s = self.streams.get_mut(&stream).unwrap();
        loop {
            if s.consumed.remove(&s.next) {
                s.next += 1;
            } else if let Some(entry) = s.ahead.remove(&s.next) {
                self.ready.push_back(entry);
                s.next += 1;
                s.gap_age = 0;
            } else {
                break;
            }
        }
    }

    /// Runs queued commands (at most `CALLS_PER_PUMP`) and returns their completions.
    /// Returns nothing while a call is already in progress (re-entry from the game).
    pub fn pump(&mut self, env: &mut dyn Env) -> Vec<Completion> {
        let mut out = Vec::new();
        if self.in_call || self.halted {
            return out;
        }
        self.age_gaps(&mut out);
        let mut calls = 0;
        let mut kept: VecDeque<Entry> = VecDeque::new();
        let mut blocked_streams: Vec<u8> = Vec::new();
        while let Some(mut entry) = self.ready.pop_front() {
            if calls >= CALLS_PER_PUMP || self.halted || blocked_streams.contains(&entry.stream) {
                kept.push_back(entry);
                continue;
            }
            // Guard: right phase, and not paused where that matters.
            let phase_ok = allowed_phases(&entry.command).map_or(true, |p| p.contains(&env.phase()));
            let pause_ok = !needs_unpaused(&entry.command) || !env.paused();
            if !(phase_ok && pause_ok) {
                entry.age += 1;
                self.stats.deferred_pumps += 1;
                if entry.age > MAX_DEFER_PUMPS {
                    out.push(self.finish(&entry, Outcome::Expired, OutcomeKind::Expired, Some("game never reached the required state".into())));
                } else {
                    // Order inside a stream: nothing behind it may overtake.
                    blocked_streams.push(entry.stream);
                    kept.push_back(entry);
                }
                continue;
            }
            calls += 1;
            self.in_call = true;
            let result = env.before(&entry.command).and_then(|_| env.call(&entry.command)).and_then(|_| env.verify(&entry.command));
            self.in_call = false;
            match result {
                Ok(()) => out.push(self.finish(&entry, Outcome::Done, OutcomeKind::Done, None)),
                Err(reason) => {
                    self.halted = true;
                    out.push(self.finish(&entry, Outcome::Failed, OutcomeKind::Failed, Some(reason)));
                }
            }
        }
        self.ready = kept;
        let streams: Vec<u8> = self.streams.keys().copied().collect();
        for stream in streams {
            self.promote(stream);
        }
        out
    }

    fn finish(&mut self, entry: &Entry, outcome: Outcome, kind: OutcomeKind, reason: Option<String>) -> Completion {
        match outcome {
            Outcome::Done => self.stats.done += 1,
            Outcome::Expired => self.stats.expired += 1,
            Outcome::Failed => self.stats.failed += 1,
            _ => {}
        }
        self.remember((entry.stream, entry.seq), kind);
        Completion { stream: entry.stream, seq: entry.seq, outcome, reason }
    }

    /// A hole in a stream is waited for `GAP_PUMPS` pumps, then skipped.
    fn age_gaps(&mut self, out: &mut Vec<Completion>) {
        let streams: Vec<u8> = self.streams.keys().copied().collect();
        for stream in streams {
            let s = self.streams.get_mut(&stream).unwrap();
            let waiting = s.ahead.keys().next().copied();
            let Some(first) = waiting else {
                s.gap_age = 0;
                continue;
            };
            s.gap_age += 1;
            if s.gap_age <= GAP_PUMPS {
                continue;
            }
            let from = s.next;
            s.next = first.min(s.consumed.iter().next().copied().unwrap_or(first));
            s.gap_age = 0;
            let skipped: Vec<u64> = (from..s.next).collect();
            self.stats.skipped_gaps += skipped.len() as u64;
            for seq in skipped {
                out.push(Completion { stream, seq, outcome: Outcome::Stale, reason: Some("never arrived".into()) });
                self.remember((stream, seq), OutcomeKind::Skipped);
            }
            self.promote(stream);
        }
    }
}
