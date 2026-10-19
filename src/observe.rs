//! Observation hooks (M3): count how often the game calls each reviewed
//! function and remember the last call's arguments. Nothing is changed in the
//! game: every stub saves the volatile state, counts, restores it bit for bit
//! and continues in the original code.
//!
//! Opt-in (`AZCOOP_OBSERVE=1`). Only function entries are hooked: a 5-byte
//! MinHook jump in the middle of a function may overwrite a branch target, so
//! the mid-function sites (BOSS_DEATH, ENEMY_AOE, ENEMY_TARGET, GROUND_AOE,
//! HUD_DELIVER) stay with the debugger until they get a breakpoint-style hook.
//! WRITE and TICK have their own detours and counters.

use crate::stub::Context;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};

/// Reviewed hooks observed here, in id order (all but WRITE and TICK).
pub const NAMES: [&str; 25] = [
    "APPLY_DOT", "APPLY_EFFECT", "AWARD_XP", "BOSS_DEATH", "CHOOSE", "DAMAGE", "DEFEAT_UI", "ENEMY_AOE", "ENEMY_TARGET",
    "FIND_SPAWN", "GROUND_AOE", "HUD_DELIVER", "HURT", "MAP_SELECT", "MOVE", "OFFER_CHOICES", "PAUSE", "REMOVE_LOOT",
    "RESUME", "SERIALIZE", "SPAWN", "SPAWN_BOSS", "SPAWN_LOOT", "START", "UI_COMMAND",
];

pub const COUNT: usize = NAMES.len();

/// Calls seen per hook.
pub static COUNTS: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
/// Last call per hook: rcx, rdx, r8, r9, return address.
pub static LAST: [[AtomicU64; 5]; COUNT] = [const { [const { AtomicU64::new(0) }; 5] }; COUNT];

/// Thread bookkeeping per hook (the observed ones, then WRITE and TICK): the first thread that
/// called it and how many calls came from any other thread. Tells whether the game runs a hook
/// on one thread only, which decides how the in-process core may share state.
pub const THREAD_SLOTS: usize = COUNT + 2;
pub const SLOT_WRITE: usize = COUNT;
pub const SLOT_TICK: usize = COUNT + 1;
static THREAD_FIRST: [AtomicU32; THREAD_SLOTS] = [const { AtomicU32::new(0) }; THREAD_SLOTS];
static THREAD_OTHER: [AtomicU64; THREAD_SLOTS] = [const { AtomicU64::new(0) }; THREAD_SLOTS];
static THREAD_LAST_OTHER: [AtomicU32; THREAD_SLOTS] = [const { AtomicU32::new(0) }; THREAD_SLOTS];

/// Records the calling thread for hook slot `slot`.
pub fn note_thread(slot: usize) {
    let tid = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() };
    let first = &THREAD_FIRST[slot];
    if first.compare_exchange(0, tid, Relaxed, Relaxed).is_ok() || first.load(Relaxed) == tid {
        return;
    }
    THREAD_OTHER[slot].fetch_add(1, Relaxed);
    THREAD_LAST_OTHER[slot].store(tid, Relaxed);
}

/// e.g. `WRITE t18232 only, TICK t18232 only, MOVE t18232 (+3 other, last t4411)`.
pub fn thread_summary() -> String {
    let name = |slot: usize| match slot {
        SLOT_WRITE => "WRITE",
        SLOT_TICK => "TICK",
        i => NAMES[i],
    };
    let parts: Vec<String> = (0..THREAD_SLOTS)
        .filter_map(|slot| {
            let first = THREAD_FIRST[slot].load(Relaxed);
            if first == 0 {
                return None;
            }
            let other = THREAD_OTHER[slot].load(Relaxed);
            Some(if other == 0 {
                format!("{} t{first} only", name(slot))
            } else {
                format!("{} t{first} (+{other} other, last t{})", name(slot), THREAD_LAST_OTHER[slot].load(Relaxed))
            })
        })
        .collect();
    if parts.is_empty() {
        "no hook called yet".into()
    } else {
        parts.join(", ")
    }
}

/// Counts one call and keeps its arguments (shared by the generic stub and the specialised ones).
pub fn note(ctx: &Context) {
    let id = ctx.id as usize;
    if id >= COUNT {
        return;
    }
    COUNTS[id].fetch_add(1, Relaxed);
    note_thread(id);
    let last = &LAST[id];
    last[0].store(ctx.rcx, Relaxed);
    last[1].store(ctx.rdx, Relaxed);
    last[2].store(ctx.r8, Relaxed);
    last[3].store(ctx.r9, Relaxed);
    last[4].store(ctx.return_address(), Relaxed);
}

extern "C" fn handler(ctx: &Context) {
    note(ctx);
}

macro_rules! observed {
    ($($id:literal $name:ident),* $(,)?) => {
        $(
            #[allow(non_snake_case)]
            mod $name {
                use std::sync::atomic::AtomicUsize;
                pub static TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
                crate::context_stub!(stub, $id, super::handler, TRAMPOLINE);
            }
        )*
        /// (trampoline slot, stub address) of observed hook `id`.
        pub fn slot(id: usize) -> (&'static AtomicUsize, usize) {
            match id {
                $( $id => (&$name::TRAMPOLINE, $name::stub as *const () as usize), )*
                _ => unreachable!("observe id out of range"),
            }
        }
    };
}

observed! {
    0 APPLY_DOT, 1 APPLY_EFFECT, 2 AWARD_XP, 3 BOSS_DEATH, 4 CHOOSE, 5 DAMAGE, 6 DEFEAT_UI, 7 ENEMY_AOE, 8 ENEMY_TARGET,
    9 FIND_SPAWN, 10 GROUND_AOE, 11 HUD_DELIVER, 12 HURT, 13 MAP_SELECT, 14 MOVE, 15 OFFER_CHOICES, 16 PAUSE,
    17 REMOVE_LOOT, 18 RESUME, 19 SERIALIZE, 20 SPAWN, 21 SPAWN_BOSS, 22 SPAWN_LOOT, 23 START, 24 UI_COMMAND,
}

/// True if the bytes start like a function entry (stack-frame prologue), the
/// only place a MinHook jump is known to be safe.
pub fn is_function_entry(code: &[u8]) -> bool {
    match code {
        [0x55 | 0x56 | 0x57 | 0x53, ..] => true,
        [0x40 | 0x41, 0x50..=0x57, ..] => true,
        [0x48, 0x83 | 0x81, 0xEC, ..] => true,
        _ => false,
    }
}

/// The golden bytes (first 24 of every hook in every supported build), pinned
/// by the game crate's static check.
const GOLDEN: &str = include_str!("../crates/azcoop-game/tests/golden/hook-bytes.txt");

/// Golden bytes of `name` at `rva` for game version `version` ("0.93.1"), if pinned.
pub fn golden_bytes(version: &str, name: &str, rva: u64) -> Option<Vec<u8>> {
    let prefix = format!("{version} {name} {rva:#x} ");
    let line = GOLDEN.lines().find(|l| l.starts_with(&prefix))?;
    let hex = line[prefix.len()..].trim();
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect()
}

/// One line with every hook that was called, e.g. `HURT 12034, SPAWN 311`.
pub fn summary() -> String {
    let parts: Vec<String> = (0..COUNT)
        .filter_map(|i| {
            let n = COUNTS[i].load(Relaxed);
            (n > 0).then(|| format!("{} {n}", NAMES[i]))
        })
        .collect();
    if parts.is_empty() {
        "none called yet".into()
    } else {
        parts.join(", ")
    }
}
