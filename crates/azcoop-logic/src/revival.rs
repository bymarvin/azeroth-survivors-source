//! `Bridge.sync_revival`: a downed player is revived by a living teammate standing within
//! 5 yards for 3 seconds of shared game time; when everybody is down the team-defeat screen
//! is shown instead. Time spent paused or in menus never counts and never erases progress.

use crate::{Call, Event, Io, Packet, Result};
use azcoop_world::builders::system_message;
use azcoop_world::{values_packet, SELF, UPDATE};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ENEMY_HP: f64 = 1e15;
const FIELD_MAX_HEALTH: u64 = 0x4F8;
const FIELD_HEALTH: u64 = 0x4A0;
const FIELD_REVIVE_FLAGS: u64 = 0x7F8;
const FIELD_PHASE: u64 = 0x8BF;
const FIELD_PROGRESS: u64 = 0x498;

/// What the revival logic reads and keeps of the room.
#[derive(Default, Debug, Clone)]
pub struct Room {
    pub members: Vec<u32>,
    /// `native_states[n]`: (phase, level, xp, talents due).
    pub native_states: BTreeMap<u32, [u64; 4]>,
    /// Router poses (x, y, z) by player number.
    pub poses: BTreeMap<u32, [f64; 3]>,
    pub host_clock: f64,
    pub draining: bool,
    pub paused: bool,
    pub surrendered: BTreeSet<u32>,
    pub surrender_applied: BTreeSet<u32>,
    pub party_surrender: bool,
    pub self_surrendered: bool,
    pub stop_requested: bool,
    /// The local player's number (a network guest); `None` on a host process.
    pub own_number: Option<u32>,
    pub release_7264: bool,
    /// Game offset of the native surrender flag (byte) of this build (`RawGameFields::surrender_flag`).
    pub surrender_flag: u64,
    pub guests: BTreeSet<u32>,
    pub ready: BTreeSet<u32>,
    /// Players whose game still has to mirror the shared pause (true) or resume (false).
    pub pause_pending: BTreeMap<u32, bool>,
    /// (sequence, command) of the host's victory choice.
    pub end_action: Option<(u64, u32)>,
    pub end_pending: BTreeMap<u32, u32>,
    pub completed_players: BTreeSet<u32>,
    /// Incoming combat hits to retire: (player, reason). Applied by the hit queues' owner.
    pub clear_requests: Vec<(u32, String)>,
    pub victory_requested: bool,
    pub victory_guests: BTreeSet<u32>,
    pub team_defeat: BTreeSet<u32>,
    pub downed: BTreeSet<u32>,
    /// (seconds of progress, game time at the last update)
    pub revive_progress: BTreeMap<u32, (f64, f64)>,
    pub revive_status: BTreeMap<u32, String>,
    pub notice: BTreeMap<u32, Vec<Packet>>,
    pub hurt: BTreeMap<u32, Vec<Packet>>,
}

fn state_phase(room: &Room, n: u32) -> u64 {
    room.native_states.get(&n).map_or(0, |s| s[0])
}

fn squared(a: [f64; 3], b: [f64; 3]) -> f64 {
    let mut sum = 0.0;
    for i in 0..3 {
        sum += (a[i] - b[i]).powi(2);
    }
    sum
}

impl Room {
    /// `sync_revival(client, context)`: true when it called into the game (the caller retries
    /// the queue write afterwards).
    pub fn sync_revival(&mut self, io: &mut dyn Io, number: u32) -> Result<bool> {
        let teammates: Vec<u32> = self.members.iter().copied().filter(|n| *n != number).collect();
        let living: Vec<u32> = teammates.iter().copied().filter(|n| state_phase(self, *n) == 1).collect();
        let fallen_pose = self.poses.get(&number).copied();
        let other = match (living.is_empty(), fallen_pose) {
            (false, Some(fallen)) => {
                let mut best: Option<(u32, f64)> = None;
                for n in &living {
                    let pose = *self.poses.get(n).ok_or("Unknown teammate pose")?;
                    let d = squared(fallen, pose);
                    if best.map_or(true, |(_, bd)| d < bd) {
                        best = Some((*n, d));
                    }
                }
                best.unwrap().0
            }
            _ => teammates.first().copied().unwrap_or(number),
        };
        let phase = self.native_states.get(&number).ok_or("Unknown player state")?[0];
        if phase != 4 {
            self.revive_progress.remove(&number);
            self.revive_status.remove(&number);
            return Ok(false);
        }
        if teammates.iter().all(|n| state_phase(self, *n) == 4) && !self.team_defeat.contains(&number) {
            self.team_defeat.insert(number);
            io.call(Call::DefeatUi)?;
            io.record(Event::new("team_defeat_shown").num("player", number as f64));
            return Ok(true);
        }
        if self.surrendered.contains(&number) {
            return Ok(false); // a player who gave up is never revived
        }
        if !self.downed.contains(&number) {
            self.downed.insert(number);
            io.record(Event::new("player_downed").num("player", number as f64));
            let notice = system_message(&format!("Player {number} is down. Stand within 5 yards for 3 seconds to revive."))?;
            for packets in self.notice.values_mut() {
                packets.push(notice.clone());
            }
        }
        let now = self.host_clock;
        let (mut elapsed, previous) = self.revive_progress.get(&number).copied().unwrap_or((0.0, now));
        let suspended = self.draining || self.paused || self.native_states.values().any(|s| matches!(s[0], 2 | 3));
        if suspended {
            self.revive_progress.insert(number, (elapsed, now));
            self.status(io, number, "suspended", |e| e.num("elapsed", elapsed));
            return Ok(false);
        }
        if state_phase(self, other) != 1 {
            self.revive_progress.remove(&number);
            self.status(io, number, "no_survivor", |e| e);
            return Ok(false);
        }
        let fallen = *self.poses.get(&number).ok_or("Unknown player pose")?;
        let survivor = *self.poses.get(&other).ok_or("Unknown teammate pose")?;
        let distance = squared(fallen, survivor);
        if distance > 25.0 {
            self.revive_progress.remove(&number);
            self.status(io, number, "outside_radius", |e| e.num("distance", distance.sqrt()).num("elapsed", elapsed));
            return Ok(false);
        }
        if self.revive_status.get(&number).map(String::as_str) == Some("in_range") {
            elapsed += (now - previous).max(0.0);
        }
        self.revive_progress.insert(number, (elapsed, now));
        self.status(io, number, "in_range", |e| e.num("by", other as f64).num("elapsed", elapsed).num("distance", distance.sqrt()));
        if elapsed < 3.0 {
            return Ok(false);
        }
        let maximum = io.read_f32(FIELD_MAX_HEALTH)? as f64;
        if !maximum.is_finite() || !(1.0..=MAX_ENEMY_HP).contains(&maximum) {
            crate::skips::note(&mut |e| io.record(e), "revival_health_invalid", number as u64, vec![("maximum", crate::finite_item(maximum))]);
            return Ok(false); // tried again next batch
        }
        let health = (maximum * 0.5).max(1.0);
        let before = self.native_states[&number][1..].to_vec();
        io.put_f32(FIELD_HEALTH, health as f32);
        io.put_u32x2(FIELD_REVIVE_FLAGS, [0, 0]);
        io.rearm_result("revival")?; // the fall already ran the once-per-run evaluation
        // Native resume sends unroot + resume UI without resetting world/build/XP.
        io.put_u8(FIELD_PHASE, 3);
        io.call(Call::Resume)?;
        // The completion check of the Python's `after` callback.
        let restored = io.read_u8(FIELD_PHASE)?;
        if restored != 1 {
            return Err("Native revival resume failed".into());
        }
        self.downed.remove(&number);
        self.revive_progress.remove(&number);
        self.status(io, number, "completed", |e| e.num("by", other as f64).num("elapsed", elapsed));
        let notice = system_message(&format!("Player {number} revived with 50% health."))?;
        for packets in self.notice.values_mut() {
            packets.push(notice.clone());
        }
        for recipient in self.members.clone() {
            let guid = if recipient == number { SELF } else { 0xFF0100 + number as u64 };
            let packet = values_packet(guid, &BTreeMap::from([(22u32, health as i64 as u32)]))?;
            self.hurt.entry(recipient).or_default().push((UPDATE, packet));
        }
        let after = io.read_u32x2(FIELD_PROGRESS)?;
        io.record(
            Event::new("player_revived")
                .num("player", number as f64)
                .num("by", other as f64)
                .num("health", health)
                .list("progress_before", before.iter().map(|v| *v as f64).collect())
                .list("progress_after", vec![after[0] as f64, after[1] as f64]),
        );
        Ok(true)
    }

    /// `status(reason, **details)`: log a change of the revival state once.
    fn status(&mut self, io: &mut dyn Io, number: u32, reason: &str, details: impl FnOnce(Event) -> Event) {
        if self.revive_status.get(&number).map(String::as_str) != Some(reason) {
            self.revive_status.insert(number, reason.to_string());
            io.record(details(Event::new("revival_progress").num("player", number as f64).text("reason", reason)));
        }
    }
}
