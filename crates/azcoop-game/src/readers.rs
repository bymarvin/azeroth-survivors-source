//! Typed readers over a memory view: ports of the game-state readers of the
//! Python bridge (`native_progress_state`, `native_enemy_array` /
//! `parse_native_enemies`, `native_melee_stats`, the loot vector of
//! `sync_chests`). They only read; a failed or inconsistent read is an error,
//! never a guess.

use crate::builds::{reviewed, Variant, GAME_FIELDS};
use crate::profile::Profile;
use crate::Result;
use std::collections::BTreeMap;

/// A view of the game's memory. The game is stopped while a reader runs.
pub trait Mem {
    fn read(&self, address: u64, len: usize) -> Result<Vec<u8>>;
}

pub const MAX_ENEMIES: u64 = 32_768;
pub const MAX_NATIVE_OBJECTS: u64 = 1_000_000;
/// Loot record size and the loot kinds the updated builds know.
pub const LOOT_STRIDE: u64 = 0x48;

fn u32_at(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap())
}
fn u64_at(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn f32_at(d: &[u8], at: usize) -> f32 {
    f32::from_le_bytes(d[at..at + 4].try_into().unwrap())
}

/// `game_field(legacy)` of every reviewed legacy offset, resolved for one build.
#[derive(Debug, Clone)]
pub struct GameFields {
    fields: BTreeMap<u64, u64>,
}

impl GameFields {
    pub fn resolve(profile: &Profile) -> Result<GameFields> {
        let mut fields = BTreeMap::new();
        for legacy in GAME_FIELDS {
            let offset = profile.field("game", legacy as i64 + 0x10)?;
            fields.insert(legacy, u64::try_from(offset).map_err(|_| format!("game+{legacy:#x} resolves negative"))?);
        }
        Ok(GameFields { fields })
    }

    pub fn get(&self, legacy: u64) -> Result<u64> {
        self.fields.get(&legacy).copied().ok_or_else(|| "Updated game field has not been reviewed".to_string())
    }
}

/// Everything a reader needs to know about the running build.
pub struct Reader<'a> {
    pub mem: &'a dyn Mem,
    pub variant: Variant,
    pub profile: &'a Profile,
    pub fields: &'a GameFields,
    /// Image base of the running executable.
    pub base: u64,
    /// The Game object (`server + 0x10`).
    pub game: u64,
}

/// `native_progress_state`: (phase, level, xp, talents pending).
pub fn progress_state(r: &Reader, initialized: bool) -> Result<(u8, u32, u32, u32)> {
    if !initialized {
        return Ok((0, 1, 0, 0));
    }
    let lx = r.mem.read(r.game + r.fields.get(0x498)?, 8)?;
    let phase = r.mem.read(r.game + r.fields.get(0x8BF)?, 1)?[0];
    let pending = u32_at(&r.mem.read(r.game + r.fields.get(0x860)?, 4)?, 0);
    Ok((phase, u32_at(&lx, 0), u32_at(&lx, 4), pending))
}

/// The game clock in seconds (`Game+0x85C`).
pub fn clock(r: &Reader) -> Result<f32> {
    Ok(f32_at(&r.mem.read(r.game + r.fields.get(0x85C)?, 4)?, 0))
}

/// `native_enemy_array`: the raw enemy records and the game clock.
pub fn enemy_array(r: &Reader) -> Result<(Vec<u8>, f32)> {
    let head = r.mem.read(r.game + r.fields.get(0x568)?, 16)?;
    let (pointer, count) = (u64_at(&head, 0), u64_at(&head, 8));
    if count > MAX_ENEMIES {
        return Err("Native enemy vector exceeds diagnostic bound".into());
    }
    let data = if count > 0 { r.mem.read(pointer, (count * r.variant.enemy_layout().stride) as usize)? } else { Vec::new() };
    Ok((data, f32_at(&r.mem.read(r.game + r.fields.get(0x85C)?, 4)?, 0)))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Enemy {
    pub guid: u64,
    pub hp: f32,
    /// Position interpolated along the current movement leg at `now`.
    pub position: [f32; 3],
}

/// `parse_native_enemies`: living enemies of a record array at game time `now`.
/// The interpolation runs in f64 on f32 inputs like the Python's floats; the
/// result is stored as f64 bit-exactly (`Enemy::position64`).
pub fn parse_enemies(data: &[u8], now: f32, variant: Variant) -> Result<(Vec<EnemyExact>, Vec<SkippedEnemy>)> {
    let layout = variant.enemy_layout();
    let record = 4 + layout.guid_gap as usize + 8 + 96 + 4 + 24 + 12 + 12 + 4 + 4;
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut offset = 0x68usize;
    while offset < data.len() {
        let end = offset + record;
        if end > data.len() {
            return Err("unpack requires a buffer of enough bytes".into());
        }
        let r = &data[offset..end];
        if u32_at(r, 0) != 1 {
            let guid_at = 4 + layout.guid_gap as usize;
            let guid = u64_at(r, guid_at);
            let mut at = guid_at + 8 + 96;
            let hp = f32_at(r, at) as f64;
            at += 4 + 24;
            let mut v = [0f64; 8];
            for (i, slot) in v.iter_mut().enumerate() {
                *slot = f32_at(r, at + 4 * i) as f64;
            }
            let (x0, y0, z0, x1, y1, z1, began, duration) = (v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
            let now = now as f64;
            if ![now, hp, x0, y0, z0, x1, y1, z1, began, duration].iter().all(|v| v.is_finite()) {
                // A record with NaN/inf (dying, or its slot reused) is treated as not there.
                skipped.push(SkippedEnemy { guid, now, fields: [hp, x0, y0, z0, x1, y1, z1, began, duration] });
                offset += layout.stride as usize;
                continue;
            }
            let t = if duration > 0.0 { ((now - began) / duration).clamp(0.0, 1.0) } else { 1.0 };
            out.push(EnemyExact { guid, hp, position: [x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, z0 + (z1 - z0) * t] });
        }
        offset += layout.stride as usize;
    }
    Ok((out, skipped))
}

/// A living record skipped because of a non-finite value (`enemy_pose` returned `None`).
#[derive(Debug, Clone, PartialEq)]
pub struct SkippedEnemy {
    pub guid: u64,
    pub now: f64,
    /// hp, x0, y0, z0, x1, y1, z1, began, duration
    pub fields: [f64; 9],
}

/// An enemy with Python-identical (f64) arithmetic.
#[derive(Debug, Clone, PartialEq)]
pub struct EnemyExact {
    pub guid: u64,
    pub hp: f64,
    pub position: [f64; 3],
}

/// `native_melee_stats`: (phase, damage, interval, radius) of the melee class, or `None` for ranged/spell classes.
pub fn melee_stats(r: &Reader, phase: u8) -> Result<Option<(u8, f64, f64, f64)>> {
    let class = r.mem.read(r.game + r.fields.get(0x33C)?, 1)?[0];
    let relocated = |legacy: u64| -> Result<u64> {
        r.profile.addresses.get(&reviewed(legacy)?).copied().ok_or_else(|| format!("profile has no address for {legacy:#x}"))
    };
    let profile_address = if (2..=11).contains(&class) {
        u64_at(&r.mem.read(r.base + relocated(0x6623E50)? + (class as u64 - 2) * 8, 8)?, 0)
    } else {
        r.base + relocated(0x65F6848)?
    };
    let head = r.mem.read(profile_address, 16)?;
    let (enabled, damage, interval, radius) = (u32_at(&head, 0), f32_at(&head, 4) as f64, f32_at(&head, 8) as f64, f32_at(&head, 12) as f64);
    if enabled & 1 == 0 {
        return Ok(None);
    }
    let ms = r.mem.read(r.game + r.fields.get(0x4FC)?, 8)?;
    let (multiplier, speed) = (f32_at(&ms, 0) as f64, f32_at(&ms, 4) as f64);
    let list = r.mem.read(r.game + r.fields.get(0x730)?, 16)?;
    let (pointer, count) = (u64_at(&list, 0), u64_at(&list, 8));
    if count > 256 {
        return Err("Unexpected guest modifier count".into());
    }
    let modifiers = if count > 0 { r.mem.read(pointer, (count * 8) as usize)? } else { Vec::new() };
    let mut bonus = 0f64;
    for i in (0..modifiers.len()).step_by(8) {
        if modifiers[i] == 0x10 {
            bonus += f32_at(&modifiers, i + 4) as f64;
        }
    }
    let ok = |v: f64| v.is_finite() && 0.0 < v && v <= 1000.0;
    if ![damage, interval, radius, multiplier, speed, 1.0 + bonus].iter().all(|v| ok(*v)) {
        return Err("Invalid native guest melee profile".into());
    }
    Ok(Some((phase, damage * 1.5 * multiplier * (1.0 + bonus), interval * 1.2 * speed.sqrt(), radius)))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Loot {
    pub index: u64,
    pub guid: u64,
    pub position: [f32; 3],
    pub kind: u32,
    pub value: u32,
}

/// The loot vector (`sync_chests`): records of the kinds 0..=6 keyed by GUID.
pub fn loot(r: &Reader) -> Result<BTreeMap<u64, Loot>> {
    let head = r.mem.read(r.game + r.fields.get(0x5C8)?, 16)?;
    let (pointer, count) = (u64_at(&head, 0), u64_at(&head, 8));
    if count > MAX_NATIVE_OBJECTS {
        return Err("Native loot count exceeds bound".into());
    }
    let data = if count > 0 { r.mem.read(pointer, (count * LOOT_STRIDE) as usize)? } else { Vec::new() };
    let mut out = BTreeMap::new();
    for i in (0..data.len()).step_by(LOOT_STRIDE as usize) {
        let kind = u32_at(&data, i + 0x20);
        if kind > 6 {
            continue;
        }
        let pos = [f32_at(&data, i + 0x34), f32_at(&data, i + 0x38), f32_at(&data, i + 0x3C)];
        out.insert(
            u64_at(&data, i + 0x28),
            Loot { index: i as u64 / LOOT_STRIDE, guid: u64_at(&data, i + 0x28), position: pos, kind, value: u32_at(&data, i + 0x24) },
        );
    }
    Ok(out)
}
