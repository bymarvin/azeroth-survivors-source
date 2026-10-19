//! Applying a waiting hit to a guest's own game: ports of `apply_incoming_hit`, `chained_hit`
//! and `hit_batch_written` (visibility_bridge.py).
//!
//! The guest's own game takes the damage through the native HURT call, with the host's clock
//! installed for the call so cooldown/timer logic sees the moment the hit happened. The result
//! (health before and after) goes to every client as a melee packet and a health update.

use crate::hits::{HitQueues, Kind};
use crate::revival::Room;
use crate::{Call, Event, Io, Result};
use azcoop_world::builders::melee_packet;
use azcoop_world::{values_packet, SELF, UPDATE};
use std::collections::BTreeMap;

pub const HITS_PER_BATCH: u32 = 24;
pub const HIT_CHAIN_SECONDS: f64 = 0.008;
const FIELD_HEALTH: u64 = 0x4A0;
const FIELD_CLOCK: u64 = 0x85C;
const FIELD_PHASE: u64 = 0x8BF;

/// The two clocks the Python reads: `time.perf_counter()` and `time.monotonic()`.
#[derive(Debug, Clone, Copy)]
pub struct Clocks {
    pub perf: f64,
    pub mono: f64,
}

#[derive(Default)]
pub struct HitApplier {
    /// Per player: (hits applied in this queue write, perf time of the first).
    chain: BTreeMap<u32, (u32, Option<f64>)>,
    /// writes, hits, max per write, last record time
    batch_stats: BTreeMap<u32, [f64; 4]>,
}

fn round(x: f64, digits: i32) -> f64 {
    let p = 10f64.powi(digits);
    format!("{:.*}", digits as usize, x).parse().unwrap_or((x * p).round() / p)
}

static TEST_LETHAL_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `AZCOOP_TEST_GUEST_LETHAL_AT` (host game seconds), read once; None without it (the normal case).
/// Only with the `test-hooks` feature (never in a shipped build): the name is not even in the binary without it.
#[cfg(feature = "test-hooks")]
fn test_lethal_at() -> Option<f64> {
    static AT: std::sync::OnceLock<Option<f64>> = std::sync::OnceLock::new();
    *AT.get_or_init(|| std::env::var("AZCOOP_TEST_GUEST_LETHAL_AT").ok().and_then(|v| v.parse::<f64>().ok()).filter(|v| v.is_finite() && *v >= 0.0))
}

#[cfg(not(feature = "test-hooks"))]
fn test_lethal_at() -> Option<f64> {
    None
}

impl HitApplier {
    /// `chained_hit(client, context)`: apply the next waiting hit if this write still has room.
    pub fn chained_hit(&mut self, io: &mut dyn Io, room: &mut Room, queues: &mut HitQueues, number: u32, clocks: Clocks) -> Result<bool> {
        let (count, started) = self.chain.get(&number).copied().unwrap_or((0, None));
        if count >= HITS_PER_BATCH || started.is_some_and(|s| clocks.perf - s >= HIT_CHAIN_SECONDS) {
            return Ok(false); // the rest waits for the next write; nothing is dropped
        }
        if !self.apply_incoming_hit(io, room, queues, number, clocks)? {
            return Ok(false);
        }
        self.chain.insert(number, (count + 1, Some(started.unwrap_or(clocks.perf))));
        Ok(true)
    }

    /// `hit_batch_written(number)`: the native queue write proceeds; close this write's chain.
    pub fn hit_batch_written(&mut self, io: &mut dyn Io, number: u32, clocks: Clocks) {
        let (count, _) = self.chain.remove(&number).unwrap_or((0, None));
        if count == 0 {
            return;
        }
        let stats = self.batch_stats.entry(number).or_insert([0.0, 0.0, 0.0, clocks.mono]);
        stats[0] += 1.0;
        stats[1] += count as f64;
        stats[2] = stats[2].max(count as f64);
        if clocks.mono - stats[3] >= 10.0 {
            io.record(
                Event::new("hits_applied_per_batch")
                    .num("player", number as f64)
                    .num("writes", stats[0])
                    .num("hits", stats[1])
                    .num("max", stats[2])
                    .num("mean", round(stats[1] / stats[0], 2))
                    .num("limit", HITS_PER_BATCH as f64),
            );
            self.batch_stats.insert(number, [0.0, 0.0, 0.0, clocks.mono]);
        }
    }

    /// `apply_incoming_hit(client, context)`.
    pub fn apply_incoming_hit(&mut self, io: &mut dyn Io, room: &mut Room, queues: &mut HitQueues, number: u32, clocks: Clocks) -> Result<bool> {
        if number == 1 || room.native_states.get(&number).ok_or("Unknown player state")?[0] != 1 || room.paused {
            return Ok(false);
        }
        let mut waiting: Vec<(u64, Kind)> = Vec::new();
        for kind in [Kind::Hits, Kind::Areas] {
            if !queues.queues.entry((number, kind)).or_default().is_empty() {
                let first = queues.queued_hit_metadata(number, kind, clocks.mono).front().ok_or("empty metadata")?.0;
                waiting.push((first, kind));
            }
        }
        // min() over (sequence, kind name): sequences are unique.
        let Some(&(_, kind)) = waiting.iter().min_by_key(|(s, k)| (*s, k.name())) else {
            return Ok(false);
        };
        let (_, arrived, clock) = queues.queued_hit_metadata(number, kind, clocks.mono).pop_front().ok_or("empty metadata")?;
        let hit = queues.queues.get_mut(&(number, kind)).unwrap().remove(0);
        let (attacker, mut damage) = (hit.attacker, hit.damage);
        let before = f32::from_le_bytes(io.read_bytes(FIELD_HEALTH, 4)?[..4].try_into().unwrap());
        // Live test only (AZCOOP_TEST_GUEST_LETHAL_AT=<host game seconds>): from that time on every hit deals 4x the guest's health
        // until the guest is down once (the game ignores absurd damage and hits in its cooldown), so a two-window run can prove the
        // revival of a downed guest by a living host. Inert without the variable.
        let lethal = test_lethal_at().is_some_and(|at| room.host_clock >= at) && !TEST_LETHAL_DONE.load(std::sync::atomic::Ordering::SeqCst);
        if lethal && before.is_finite() && before > 0.0 {
            damage = before as f64 * 4.0 + 100.0;
            io.record(Event::new("test_lethal_hit").num("player", number as f64).num("host_clock", room.host_clock).num("damage", damage));
        }
        let current_clock = io.read_bytes(FIELD_CLOCK, 4)?;
        io.put_bytes(FIELD_CLOCK, &(clock as f32).to_le_bytes());
        let attacker_u64 = u64::try_from(attacker).map_err(|_| "Invalid attacker".to_string())?;
        io.call(Call::Hurt { attacker: attacker_u64, damage, melee: kind == Kind::Hits })?;
        // completed_hit
        let after = f32::from_le_bytes(io.read_bytes(FIELD_HEALTH, 4)?[..4].try_into().unwrap());
        let phase = io.read_u8(FIELD_PHASE)?;
        if lethal && (after <= 0.0 || phase != 1) {
            TEST_LETHAL_DONE.store(true, std::sync::atomic::Ordering::SeqCst); // down once: from now on the normal damage
        }
        io.put_bytes(FIELD_CLOCK, &current_clock);
        if !after.is_finite() {
            crate::skips::note(&mut |e| io.record(e), "guest_health_nonfinite", number as u64, vec![("before", crate::finite_item(before as f64))]);
            return Ok(true);
        }
        let metrics = queues.metrics.entry((number, kind)).or_default();
        metrics.applied += 1.0;
        metrics.max_wait = Some(metrics.max_wait.unwrap_or(0.0).max(clocks.mono - arrived));
        let dealt = (before as f64 - after as f64).max(0.0);
        if kind == Kind::Hits && dealt.is_infinite() {
            return Err("OverflowError: cannot convert float infinity to integer".into()); // int(dealt)
        }
        for recipient in room.members.clone() {
            let victim = if recipient == number { SELF } else { 0xFF0100 + number as u64 };
            if kind == Kind::Hits {
                room.hurt.entry(recipient).or_default().push((0x14A, melee_packet(attacker_u64, victim, dealt as u64)?));
            }
            let health = (after as f64).max(0.0) as i64;
            room.hurt.entry(recipient).or_default().push((UPDATE, values_packet(victim, &BTreeMap::from([(22u32, health as u32)]))?));
        }
        io.record(
            Event::new(if kind == Kind::Hits { "guest_hurt" } else { "guest_area_hurt" })
                .num("player", number as f64)
                .num("attacker", attacker as f64)
                .num("before", before as f64)
                .num("after", after as f64)
                .num("phase", phase as f64)
                .num("requested", damage)
                .num("queued_seconds", round(clocks.mono - arrived, 3)),
        );
        Ok(true)
    }
}

impl HitApplier {
    /// Per player: (hits applied in the current write, perf time of the first), for tests and logs.
    pub fn chain_state(&self) -> &BTreeMap<u32, (u32, Option<f64>)> {
        &self.chain
    }
    /// Per player: writes, hits, max per write, last record time.
    pub fn batch_stats_state(&self) -> &BTreeMap<u32, [f64; 4]> {
        &self.batch_stats
    }
}
