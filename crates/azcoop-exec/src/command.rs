//! Commands the executor can run in the game, and their argument validation:
//! a port of the checks at the top of `Native.call_before` (native_probe.py).
//! Nothing here touches the game; a command that passes `validate` is
//! well-formed, whether the game is in the right state is the executor's guard.

use crate::Result;

pub const MAX_ENEMY_DAMAGE: f64 = 1e12;
pub const MAX_HIT_DAMAGE: f64 = 1e12;
pub const MAX_COUNTER: u64 = 0xFFFF_FFFF;

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// START(game): begin the run.
    Start,
    /// PAUSE(game); `ui_only` only changes the menu (a downed player).
    Pause { ui_only: bool },
    Resume { ui_only: bool },
    /// AWARD_XP(game, amount); 0 opens the native talent chooser without a point.
    AwardXp { amount: u32 },
    /// DAMAGE(game, enemy, damage, ...): a melee hit on the enemy record at `enemy`.
    Damage { enemy: u64, amount: f32 },
    /// HURT(game, damage, second, melee).
    Hurt { amount: f32, second: u64, melee: bool },
    /// SPAWN(game, kind, &{1, x, y, z}).
    Spawn { kind: u64, position: [f32; 3] },
    /// SPAWN_LOOT(game, kind, amount, &position).
    SpawnLoot { kind: u64, amount: u64, position: [f32; 3] },
    /// OFFER_CHOICES(game, kind, 1).
    OfferChoices { kind: u64 },
    /// REMOVE_LOOT(game, index).
    RemoveLoot { index: u64 },
    /// APPLY_EFFECT(game, target, &{kind, value, duration}, spell).
    ApplyEffect { target: u64, kind: u32, value: f32, duration: f32, spell: u64 },
    /// APPLY_DOT(game, target, school 0, total, duration, ticks, ..., clock).
    ApplyDot { target: u64, total: f32, duration: f32, ticks: u64, clock: f32 },
    /// SPAWN_BOSS(game, definition): `definition` is an absolute address inside the image.
    SpawnBoss { definition: u64 },
    /// UI_COMMAND(server, &{command, 0...}): a result-screen choice.
    UiCommand { command: u32 },
}

/// Names for logs and the differential test.
impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::Start => "START",
            Command::Pause { .. } => "PAUSE",
            Command::Resume { .. } => "RESUME",
            Command::AwardXp { .. } => "AWARD_XP",
            Command::Damage { .. } => "DAMAGE",
            Command::Hurt { .. } => "HURT",
            Command::Spawn { .. } => "SPAWN",
            Command::SpawnLoot { .. } => "SPAWN_LOOT",
            Command::OfferChoices { .. } => "OFFER_CHOICES",
            Command::RemoveLoot { .. } => "REMOVE_LOOT",
            Command::ApplyEffect { .. } => "APPLY_EFFECT",
            Command::ApplyDot { .. } => "APPLY_DOT",
            Command::SpawnBoss { .. } => "SPAWN_BOSS",
            Command::UiCommand { .. } => "UI_COMMAND",
        }
    }
}

/// What validation needs to know about the running image.
#[derive(Debug, Clone, Copy)]
pub struct Image {
    pub base: u64,
    pub size: u64,
}

fn finite3(p: &[f32; 3]) -> bool {
    p.iter().all(|v| v.is_finite())
}

/// The argument checks of `call_before`.
pub fn validate(command: &Command, image: Image) -> Result<()> {
    match command {
        Command::Start | Command::AwardXp { .. } | Command::RemoveLoot { .. } | Command::UiCommand { .. } => {}
        Command::Pause { .. } | Command::Resume { .. } => {}
        Command::SpawnBoss { definition } => {
            if !(image.base <= *definition && *definition < image.base + image.size - 0x58) {
                return Err("Unverified boss definition".into());
            }
        }
        Command::Damage { amount, .. } => {
            let a = *amount as f64;
            if !(a.is_finite() && 0.0 < a && a <= MAX_ENEMY_DAMAGE) {
                return Err("Invalid native damage".into());
            }
        }
        Command::Hurt { amount, .. } => {
            let a = *amount as f64;
            if !(a.is_finite() && 0.0 < a && a <= MAX_HIT_DAMAGE) {
                return Err("Invalid native damage".into());
            }
        }
        Command::ApplyDot { target, total, duration, ticks, clock } => {
            // The Python's `damage` is the periodic total and goes through the HURT-sized bound.
            let a = *total as f64;
            if !(a.is_finite() && 0.0 < a && a <= MAX_HIT_DAMAGE) {
                return Err("Invalid native damage".into());
            }
            if !(1..=0xFFFF_FFFF).contains(target) {
                return Err("Invalid periodic effect".into());
            }
            let (d, c) = (*duration as f64, *clock as f64);
            if !(d.is_finite() && 0.0 < d && d <= 3600.0 && (1..=1000).contains(ticks) && c.is_finite() && c >= 0.0) {
                return Err("Invalid periodic timing".into());
            }
        }
        Command::Spawn { kind, position } => {
            if !finite3(position) || *kind > 11 {
                return Err("Invalid native mirror spawn".into());
            }
        }
        Command::SpawnLoot { kind, amount, position } => {
            if !finite3(position) || *kind > 2 || !(1..=MAX_COUNTER).contains(amount) {
                return Err("Invalid native loot spawn".into());
            }
        }
        Command::OfferChoices { kind } => {
            if *kind > 2 {
                return Err("Invalid native choice kind".into());
            }
        }
        Command::ApplyEffect { kind, value, duration, spell, .. } => {
            let (v, d) = (*value as f64, *duration as f64);
            let timed = matches!(kind, 1 | 10);
            if *spell > MAX_COUNTER
                || !matches!(kind, 1 | 2 | 3 | 4 | 10)
                || !v.is_finite()
                || !(0.0 <= v && v <= if timed { 1.0 } else { 3600.0 })
                || (timed && !(d.is_finite() && 0.0 <= d && d <= 3600.0))
            {
                return Err("Unsupported native enemy effect".into());
            }
        }
    }
    Ok(())
}
