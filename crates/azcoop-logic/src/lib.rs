//! The decision logic of the co-op bridge as pure state machines.
//!
//! Each module ports one piece of `visibility_bridge.py` / `native_guest_combat.py`. The logic
//! never touches the game: everything it reads or changes there goes through the [`Io`] trait
//! (game fields are named by the legacy offsets of `game_field`, like the Python), so the same
//! code runs against the real game, a fake game in tests, and a recording stub that is compared
//! with the verbatim Python.

pub mod apply_hit;
pub mod chests;
pub mod economy;
pub mod flow;
pub mod hits;
pub mod mirrors;
pub mod results;
pub mod revival;
pub mod surrender;

pub type Result<T> = std::result::Result<T, String>;
pub type Packet = (u16, Vec<u8>);

/// A value in a logged event.
#[derive(Debug, Clone, PartialEq)]
pub enum Detail {
    Num(f64),
    Text(String),
    List(Vec<f64>),
    /// A list of numbers and texts (`finite_text`: NaN and infinities as text).
    Items(Vec<Detail>),
}

/// `finite_text(values)`: floats for the JSON log, NaN/inf as text.
pub fn finite_text(values: &[f64]) -> Detail {
    Detail::Items(values.iter().map(|v| finite_item(*v)).collect())
}

/// One element of `finite_text`.
pub fn finite_item(v: f64) -> Detail {
    if v.is_finite() {
        Detail::Num(v)
    } else {
        Detail::Text(if v.is_nan() { "nan" } else if v > 0.0 { "inf" } else { "-inf" }.into())
    }
}

/// `note_native_skip` of visibility_bridge.py: a skipped native entry is logged once per
/// (event, key) and minute. Like the Python it is process-wide state with its own clock
/// (`time.monotonic()`), which the bridge sets before each event.
pub mod skips {
    use super::{Detail, Event};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    struct State {
        now: f64,
        last: BTreeMap<(String, u64), f64>,
    }

    static STATE: Mutex<State> = Mutex::new(State { now: 0.0, last: BTreeMap::new() });

    pub fn set_clock(now: f64) {
        STATE.lock().unwrap().now = now;
    }

    pub fn reset() {
        STATE.lock().unwrap().last.clear();
    }

    /// Reports through `io.record` unless the same (event, key) was reported within a minute.
    pub fn note(report: &mut dyn FnMut(Event), event: &str, key: u64, details: Vec<(&str, Detail)>) {
        {
            let mut state = STATE.lock().unwrap();
            let now = state.now;
            if state.last.get(&(event.to_string(), key)).is_some_and(|t| now - *t < 60.0) {
                return;
            }
            if state.last.len() >= 4096 {
                state.last.retain(|_, t| now - *t < 60.0);
            }
            state.last.insert((event.to_string(), key), now);
        }
        let mut e = Event::new(event).num("key", key as f64);
        for (k, v) in details {
            e.details.push((k.to_string(), v));
        }
        report(e);
    }
}

/// `record(event=..., **details)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub name: String,
    pub details: Vec<(String, Detail)>,
}

impl Event {
    pub fn new(name: &str) -> Event {
        Event { name: name.into(), details: Vec::new() }
    }
    pub fn num(mut self, key: &str, value: f64) -> Event {
        self.details.push((key.into(), Detail::Num(value)));
        self
    }
    pub fn text(mut self, key: &str, value: &str) -> Event {
        self.details.push((key.into(), Detail::Text(value.into())));
        self
    }
    pub fn list(mut self, key: &str, value: Vec<f64>) -> Event {
        self.details.push((key.into(), Detail::List(value)));
        self
    }
}

/// Native functions the logic may ask the executor to run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Call {
    DefeatUi,
    Resume,
    /// HURT(game, attacker, damage, melee) on this player's own game.
    Hurt { attacker: u64, damage: f64, melee: bool },
    /// AWARD_XP(game, amount); 0 opens the talent chooser without a point.
    AwardXp { amount: u64 },
    Pause,
    /// REMOVE_LOOT(game, index)
    RemoveLoot { index: u64 },
    /// OFFER_CHOICES(game, kind)
    OfferChoices { kind: u64 },
    /// The native surrender function on this player's game.
    Surrender,
    /// PAUSE / RESUME that only switch the UI (a downed player has no simulation to pause).
    PauseUi,
    ResumeUi,
    /// The native enemy spawn that creates a guest's mirror record: a boss definition address
    /// (absolute) or an ordinary enemy, at a position.
    SpawnMirror { boss: Option<u64>, position: [f64; 3] },
    /// DAMAGE(game, enemy, damage): a melee hit on the enemy record `enemy` (a GUID here).
    Damage { enemy: u64, amount: f64 },
}

/// A temporary instruction patch: (rva, original bytes, replacement bytes).
pub type CodePatch = (u64, Vec<u8>, Vec<u8>);

/// The game-facing side of the logic. Fields are legacy `game_field` offsets.
pub trait Io {
    /// The game image's base address (`client.base`).
    fn base(&self) -> u64 {
        0
    }
    fn read_f32(&mut self, field: u64) -> Result<f32>;
    fn read_u8(&mut self, field: u64) -> Result<u8>;
    fn read_u32x2(&mut self, field: u64) -> Result<[u32; 2]>;
    fn put_f32(&mut self, field: u64, value: f32);
    fn put_u32x2(&mut self, field: u64, value: [u32; 2]);
    fn put_u8(&mut self, field: u64, value: u8);
    /// Raw bytes of a game field (the shared clock is restored byte for byte).
    fn read_bytes(&mut self, field: u64, len: usize) -> Result<Vec<u8>>;
    fn put_bytes(&mut self, field: u64, value: &[u8]);
    /// Bytes at a raw Game offset (fields that are not `game_field` entries).
    fn read_raw(&mut self, offset: u64, len: usize) -> Result<Vec<u8>>;
    /// The loot vector's records (`count * 0x48` bytes behind the pointer at `Game+0x5C8`).
    fn read_loot(&mut self, len: u64) -> Result<Vec<u8>>;
    /// Bytes at an offset from the server object (the run evaluation's lock, phase, account).
    fn read_server(&mut self, offset: u64, len: usize) -> Result<Vec<u8>>;
    fn put_server(&mut self, offset: u64, value: &[u8]);
    /// Writes to an absolute address (a class XP entry of the account table).
    fn put_abs(&mut self, address: u64, value: &[u8]);
    /// Bytes at an absolute address the bridge owns (e.g. its gold counter).
    fn read_abs(&mut self, address: u64, len: usize) -> Result<Vec<u8>>;
    /// Runs the native call; it has returned when this does.
    fn call(&mut self, call: Call) -> Result<()>;
    /// `rearm_result(client, reason)`.
    fn rearm_result(&mut self, reason: &str) -> Result<()>;
    /// Bytes of the game's code at `base + rva` (a patch precondition).
    fn code_read(&mut self, _rva: u64, _len: usize) -> Result<Vec<u8>> {
        Err("code access is not available".into())
    }
    /// Overwrites the game's code at `base + rva`.
    fn code_patch(&mut self, _rva: u64, _bytes: &[u8]) -> Result<()> {
        Err("code access is not available".into())
    }
    fn record(&mut self, event: Event);
}
