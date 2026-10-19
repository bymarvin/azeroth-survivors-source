//! The real call shapes into the game (Windows x64 ABI), one per command.
//!
//! The Python bridge placed these arguments by writing the thread's CONTEXT
//! (`Native.call_before`): rcx = first argument, rdx = second, r8/r9, xmm1..3
//! for float arguments in those positions, further arguments at `[rsp+0x28]`
//! upwards (after the return address and 32 bytes of shadow space). A direct
//! Rust call with `extern "system"` signatures puts the same values in the same
//! places; `tests/native_abi.rs` proves it with a stand-in that records the raw
//! registers and stack slots.
//!
//! Safety: `Native::call` jumps into game code. It must only be called with a
//! validated, guarded command, on the game thread inside the WRITE detour, and
//! only for entries that were verified against the executable.

#![cfg(all(windows, target_arch = "x86_64"))]

use crate::command::Command;
use crate::executor::Env;
use crate::Result;
use std::ffi::c_void;

type Game = *mut c_void;

type FnGame = unsafe extern "system" fn(Game);
type FnGameU64 = unsafe extern "system" fn(Game, u64);
type FnDamage = unsafe extern "system" fn(Game, u64, f32, u64, u64, u64, u64);
type FnHurt = unsafe extern "system" fn(Game, f32, u64, u64);
type FnSpawn = unsafe extern "system" fn(Game, u64, *const [u32; 4]);
type FnSpawnLoot = unsafe extern "system" fn(Game, u64, u64, *const [f32; 3]);
type FnOffer = unsafe extern "system" fn(Game, u64, u64);
type FnEffect = unsafe extern "system" fn(Game, u64, *const [u8; 12], u64, u64);
type FnDot = unsafe extern "system" fn(Game, u64, u64, f32, f32, u64, f32, u64, u64, u64, f32);

/// Absolute addresses of the verified entries (base + rva), 0 = not available.
#[derive(Debug, Clone, Copy, Default)]
pub struct Entries {
    pub start: usize,
    pub pause: usize,
    pub resume: usize,
    /// The pause/resume entries that only change the menu (generated, see [`ui_only_entry`]).
    pub pause_ui: usize,
    pub resume_ui: usize,
    pub award_xp: usize,
    pub damage: usize,
    pub hurt: usize,
    pub spawn: usize,
    pub spawn_loot: usize,
    pub offer_choices: usize,
    pub remove_loot: usize,
    pub apply_effect: usize,
    pub apply_dot: usize,
    pub spawn_boss: usize,
    pub ui_command: usize,
}

/// Machine code of a UI-only entry: the original prologue, `mov rsi, rcx`, and an absolute jump
/// to `target` (the pause/resume body after its own prologue). Byte-for-byte what the Python builds.
pub fn ui_only_entry(target: u64) -> Vec<u8> {
    let mut code = crate::UI_PROLOGUE.to_vec();
    code.extend_from_slice(&[0x48, 0x89, 0xCE]); // mov rsi, rcx
    code.extend_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]); // jmp [rip+0]
    code.extend_from_slice(&target.to_le_bytes());
    code
}

/// Calls into one game. `buffer` is the UI command scratch (0xE8 bytes) the game reads.
pub struct Native {
    pub entries: Entries,
    pub game: usize,
    pub server: usize,
    command_buffer: Box<[u8; 0xE8]>,
}

impl Native {
    pub fn new(entries: Entries, game: usize, server: usize) -> Native {
        Native { entries, game, server, command_buffer: Box::new([0; 0xE8]) }
    }

    fn entry(&self, address: usize, name: &str) -> Result<usize> {
        if address == 0 {
            Err(format!("{name} entry is not available in this build"))
        } else {
            Ok(address)
        }
    }

    /// Runs `command` in the game.
    ///
    /// # Safety
    /// Game thread, game lock held, `command` validated and guarded, entries verified.
    pub unsafe fn call(&mut self, command: &Command) -> Result<()> {
        let game = self.game as Game;
        unsafe {
            match command {
                Command::Start => std::mem::transmute::<usize, FnGame>(self.entry(self.entries.start, "START")?)(game),
                Command::Pause { ui_only: false } => std::mem::transmute::<usize, FnGame>(self.entry(self.entries.pause, "PAUSE")?)(game),
                Command::Resume { ui_only: false } => std::mem::transmute::<usize, FnGame>(self.entry(self.entries.resume, "RESUME")?)(game),
                Command::Pause { ui_only: true } => std::mem::transmute::<usize, FnGame>(self.entry(self.entries.pause_ui, "PAUSE (menu only)")?)(game),
                Command::Resume { ui_only: true } => std::mem::transmute::<usize, FnGame>(self.entry(self.entries.resume_ui, "RESUME (menu only)")?)(game),
                Command::AwardXp { amount } => std::mem::transmute::<usize, FnGameU64>(self.entry(self.entries.award_xp, "AWARD_XP")?)(game, *amount as u64),
                Command::Damage { enemy, amount } => {
                    // Basic melee: no spell id, then the three trailing arguments the Python pushed (0, 0, 1).
                    std::mem::transmute::<usize, FnDamage>(self.entry(self.entries.damage, "DAMAGE")?)(game, *enemy, *amount, 0, 0, 0, 1)
                }
                Command::Hurt { amount, second, melee } => {
                    std::mem::transmute::<usize, FnHurt>(self.entry(self.entries.hurt, "HURT")?)(game, *amount, *second, *melee as u64)
                }
                Command::Spawn { kind, position } => {
                    let record = [1u32, position[0].to_bits(), position[1].to_bits(), position[2].to_bits()];
                    std::mem::transmute::<usize, FnSpawn>(self.entry(self.entries.spawn, "SPAWN")?)(game, *kind, &record)
                }
                Command::SpawnLoot { kind, amount, position } => {
                    std::mem::transmute::<usize, FnSpawnLoot>(self.entry(self.entries.spawn_loot, "SPAWN_LOOT")?)(game, *kind, *amount, position)
                }
                Command::OfferChoices { kind } => std::mem::transmute::<usize, FnOffer>(self.entry(self.entries.offer_choices, "OFFER_CHOICES")?)(game, *kind, 1),
                Command::RemoveLoot { index } => std::mem::transmute::<usize, FnGameU64>(self.entry(self.entries.remove_loot, "REMOVE_LOOT")?)(game, *index),
                Command::ApplyEffect { target, kind, value, duration, spell } => {
                    let mut effect = [0u8; 12];
                    effect[..4].copy_from_slice(&kind.to_le_bytes());
                    effect[4..8].copy_from_slice(&value.to_le_bytes());
                    effect[8..].copy_from_slice(&duration.to_le_bytes());
                    std::mem::transmute::<usize, FnEffect>(self.entry(self.entries.apply_effect, "APPLY_EFFECT")?)(game, *target, &effect, 0, *spell)
                }
                Command::ApplyDot { target, total, duration, ticks, clock } => {
                    // Physical school (0); the tagged-source tail: 0, 0, 0, 1 then the clock.
                    std::mem::transmute::<usize, FnDot>(self.entry(self.entries.apply_dot, "APPLY_DOT")?)(game, *target, 0, *total, *duration, *ticks, 0.0, 0, 0, 1, *clock)
                }
                Command::SpawnBoss { definition } => std::mem::transmute::<usize, FnGameU64>(self.entry(self.entries.spawn_boss, "SPAWN_BOSS")?)(game, *definition),
                Command::UiCommand { command } => {
                    self.command_buffer.fill(0);
                    self.command_buffer[..4].copy_from_slice(&command.to_le_bytes());
                    let f = std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void, *const u8)>(self.entry(self.entries.ui_command, "UI_COMMAND")?);
                    f(self.server as *mut c_void, self.command_buffer.as_ptr())
                }
            }
        }
        Ok(())
    }
}

/// An [`Env`] that calls the real game and leaves state reading to a closure set.
pub struct GameEnv<'a> {
    pub native: &'a mut Native,
    pub phase: &'a dyn Fn() -> u8,
    pub paused: &'a dyn Fn() -> bool,
    pub before: &'a mut dyn FnMut(&Command) -> Result<()>,
    pub verify: &'a mut dyn FnMut(&Command) -> Result<()>,
}

impl Env for GameEnv<'_> {
    fn phase(&self) -> u8 {
        (self.phase)()
    }
    fn paused(&self) -> bool {
        (self.paused)()
    }
    fn before(&mut self, command: &Command) -> Result<()> {
        (self.before)(command)
    }
    fn call(&mut self, command: &Command) -> Result<()> {
        unsafe { self.native.call(command) }
    }
    fn verify(&mut self, command: &Command) -> Result<()> {
        (self.verify)(command)
    }
}
