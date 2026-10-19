//! Enemy-sync figure: one `enemy_sync` log line per second on both sides, read-only (nothing is written to the game
//! and no message changes, so the Python-compatible wire and the differential tests are untouched).
//!
//! Host line (`role=1`, one per guest): the enemies the host's game has now against the last snapshot it sent that
//! guest. The position difference is what the guest's picture is off by, plus the snapshot's age and the acknowledgement lag.
//! Guest line (`role=2`): the host snapshot the guest holds against the enemies its own game has (the mirror writes
//! the snapshot into the game each batch, so the difference shows whether the writes arrive), the snapshot's age and
//! the enemies that exist on one side only. Host difference and guest difference together bound the picture seen by the guest.

use crate::bridge::Bridge;
use crate::client::{Client, Result};
use crate::io::GameIo;
use crate::regs::Regs;
use azcoop_logic::Event;
use std::collections::{BTreeMap, HashMap};

/// Seconds between two figures.
pub const INTERVAL: f64 = 1.0;

/// Positions of the living enemies of one side: guid, x, y, z.
pub type Poses = Vec<(u64, [f64; 3])>;

/// Bookkeeping of the figure (lives in the send-side bookkeeping, per bridge).
#[derive(Default)]
pub struct SyncState {
    due: f64,
    /// Guest: the bridge clock when the last enemy update arrived (0 = none yet).
    last_rx: f64,
    /// Host: per guest, the last snapshot sent: sequence, time sent, positions.
    pub sent: BTreeMap<u32, (u64, f64, Poses)>,
    /// Lines written (tests and the report).
    pub lines: u64,
    /// Host: the claim whose refusal was logged last (one line per refused claim).
    refusal_logged: Option<i128>,
    /// The bridge clock of the previous call (0 = none yet): paused time is taken out of the snapshot age with it.
    last_call: f64,
    /// Host: loot guid -> bridge clock when it was last in the host's loot table (to tell 'removed by the host a while ago' from 'never known').
    seen_loot: HashMap<u64, f64>,
    /// Guest, `COOP_STEP_METRIC=1`: the enemy positions of the previous tick and the steps measured since the last `enemy_step` line.
    step_prev: HashMap<u64, [f64; 3]>,
    steps: Vec<f64>,
    step_samples: u64,
}

/// `COOP_STEP_METRIC=1`: measure, at every tick, how far the enemies of the guest's game moved since the tick before (the visual step).
fn step_metric_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("COOP_STEP_METRIC").is_ok_and(|v| v == "1"))
}

/// Steps from one tick to the next of the enemies present in both; jumps (spawn, teleport) are no steps.
fn collect_steps(prev: &HashMap<u64, [f64; 3]>, now: &Poses, out: &mut Vec<f64>) {
    for (guid, pose) in now {
        if let Some(before) = prev.get(guid) {
            let d = ((pose[0] - before[0]).powi(2) + (pose[1] - before[1]).powi(2) + (pose[2] - before[2]).powi(2)).sqrt();
            if d < 10.0 {
                out.push(d);
            }
        }
    }
}

fn step_event(steps: &mut Vec<f64>, samples: u64, seconds: f64) -> Event {
    let total = steps.len();
    let mut moving: Vec<f64> = steps.iter().copied().filter(|d| *d > 1e-4).collect();
    moving.sort_by(|a, b| a.total_cmp(b));
    steps.clear();
    let zero_share = if total == 0 { 0.0 } else { 1.0 - moving.len() as f64 / total as f64 };
    Event::new("enemy_step")
        .num("steps", total as f64)
        .num("moving", moving.len() as f64)
        .num("p50", (percentile(&moving, 0.5) * 1000.0).round() / 1000.0)
        .num("p95", (percentile(&moving, 0.95) * 1000.0).round() / 1000.0)
        .num("max", (moving.last().copied().unwrap_or(0.0) * 1000.0).round() / 1000.0)
        .num("zero_share", (zero_share * 1000.0).round() / 1000.0)
        .num("ticks_per_s", (samples as f64 / seconds.max(1e-3) * 10.0).round() / 10.0)
}

/// The two sets compared by guid.
#[derive(Debug, Clone, PartialEq)]
pub struct Comparison {
    pub reference: usize,
    pub local: usize,
    pub common: usize,
    pub only_reference: usize,
    pub only_local: usize,
    /// Distance between the positions of the common guids: median, 95th percentile (nearest rank), maximum.
    pub median: f64,
    pub p95: f64,
    pub max: f64,
}

/// Nearest-rank percentile of an ascending list (`p` in 0..=1).
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (p * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

/// `reference` against `local`: counts of guids on one side only and the spread of the position difference of the shared ones.
pub fn compare(reference: &[(u64, [f64; 3])], local: &[(u64, [f64; 3])]) -> Comparison {
    let by_guid: HashMap<u64, [f64; 3]> = local.iter().copied().collect();
    let mut distances: Vec<f64> = Vec::with_capacity(reference.len());
    for (guid, a) in reference {
        if let Some(b) = by_guid.get(guid) {
            distances.push(((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2)).sqrt());
        }
    }
    distances.sort_by(|x, y| x.total_cmp(y));
    let common = distances.len();
    Comparison {
        reference: reference.len(),
        local: by_guid.len(),
        common,
        only_reference: reference.len() - common,
        only_local: by_guid.len() - common,
        median: percentile(&distances, 0.5),
        p95: percentile(&distances, 0.95),
        max: distances.last().copied().unwrap_or(0.0),
    }
}

fn comparison_event(role: u32, player: u32, c: &Comparison, age: f64, seq: u64) -> Event {
    Event::new("enemy_sync")
        .num("role", role as f64)
        .num("player", player as f64)
        .num("reference", c.reference as f64)
        .num("local", c.local as f64)
        .num("common", c.common as f64)
        .num("only_reference", c.only_reference as f64)
        .num("only_local", c.only_local as f64)
        .num("dev_median", (c.median * 1000.0).round() / 1000.0)
        .num("dev_p95", (c.p95 * 1000.0).round() / 1000.0)
        .num("dev_max", (c.max * 1000.0).round() / 1000.0)
        .num("age_ms", (age * 1000.0).round())
        .num("seq", seq as f64)
}

/// Why the host refunds a guest's loot claim: (the loot object is in the host's table, distance to the guest, the claim's range).
pub fn refusal_reason(chest_known: bool, distance: Option<f64>, range: f64) -> &'static str {
    match (chest_known, distance) {
        (false, _) => "loot_gone",
        (true, Some(d)) if d > range => "out_of_range",
        (true, _) => "other",
    }
}

impl SyncState {
    /// Host: a guest's link came back; what was sent over the old link no longer describes its picture.
    pub fn forget(&mut self, peer: u32) {
        self.sent.remove(&peer);
    }

    /// Guest: an enemy update of the host arrived now.
    pub fn note_snapshot(&mut self, now: f64) {
        self.last_rx = now;
    }
}

impl Bridge {
    /// Host: a line for every guest claim the host refuses (the logic layer is silent there, which hid that the guest's
    /// claims were all refused). Read-only; called after every hook of the host process.
    pub fn claim_notes(&mut self, client: &mut dyn Client) {
        let Some(online) = self.online.as_mut() else { return };
        if online.number != 1 {
            return;
        }
        let state = &mut online.outgoing.sync;
        let Some(claim) = self.economy.chest_claim.as_ref().filter(|c| c.status == "refund") else {
            state.refusal_logged = None;
            return;
        };
        if state.refusal_logged == Some(claim.guid) {
            return;
        }
        state.refusal_logged = Some(claim.guid);
        let chest = u64::try_from(claim.guid).ok().and_then(|g| self.economy.chests.get(&g));
        let distance = chest.and_then(|c| self.economy.poses.get(&claim.player()).map(|p| (0..3).map(|i| (c.position[i] - p[i]).powi(2)).sum::<f64>().sqrt()));
        let reason = refusal_reason(chest.is_some(), distance, claim.range);
        let seen_ago = u64::try_from(claim.guid).ok().and_then(|g| state.seen_loot.get(&g)).map(|at| (self.now - at).max(0.0));
        let mut event = Event::new("guest_claim_refused").num("player", claim.player() as f64).num("guid", claim.guid as f64).num("negative_guid", (claim.guid < 0) as u8 as f64).num("range", claim.range).text("reason", reason);
        if let Some(c) = chest {
            event = event.num("kind", c.kind as f64);
        }
        if let Some(d) = distance {
            event = event.num("distance", (d * 100.0).round() / 100.0);
        }
        if chest.is_none() {
            // seen_ago: seconds since the host's loot table last held this guid (-1: never sampled, so it came and went within a second or was never the host's)
            event = event.num("seen_ago", seen_ago.map_or(-1.0, |s| (s * 10.0).round() / 10.0));
        }
        client.record(event);
    }

    /// The figure, once per [`INTERVAL`]: called by the game process after a TICK, where the native enemy array is read anyway.
    pub fn sync_stats(&mut self, client: &mut dyn Client) -> Result<()> {
        let now = self.now;
        let Some(mut online) = self.online.take() else { return Ok(()) };
        // A shared pause (talent choice) stops the game's ticks and with them the enemy updates: that time is not a stall.
        let elapsed = (now - online.outgoing.sync.last_call).max(0.0);
        if online.outgoing.sync.last_call > 0.0 && self.room.paused {
            let sync = &mut online.outgoing.sync;
            sync.last_rx += if sync.last_rx > 0.0 { elapsed } else { 0.0 };
            for (_, at, _) in sync.sent.values_mut() {
                *at += elapsed;
            }
        }
        online.outgoing.sync.last_call = now;
        let result = (|| -> Result<()> {
            let metric = online.number != 1 && step_metric_enabled();
            let due = now >= online.outgoing.sync.due;
            if !due && !metric {
                return Ok(());
            }
            // After the run the player is back in the native menu (a new world): the enemy array of the old world is gone.
            if self.menu_players.contains(&online.number) {
                return Ok(());
            }
            let mut io_regs = Regs::default();
            let native: Poses = {
                let mut io = GameIo::new(client, &mut io_regs, &self.build.fields, &mut self.results);
                self.mirrors.native_poses(&mut io)?.into_iter().map(|(guid, _, pose)| (guid, pose)).collect()
            };
            if metric && !self.room.paused {
                let sync = &mut online.outgoing.sync;
                collect_steps(&sync.step_prev, &native, &mut sync.steps);
                sync.step_prev = native.iter().copied().collect();
                sync.step_samples += 1;
            }
            if !due {
                return Ok(());
            }
            online.outgoing.sync.due = (online.outgoing.sync.due + INTERVAL).max(now);
            if online.number == 1 {
                let sync = &mut online.outgoing.sync;
                for guid in self.economy.chests.keys() {
                    sync.seen_loot.insert(*guid, now);
                }
                if sync.seen_loot.len() > 4096 {
                    sync.seen_loot.retain(|_, at| now - *at < 120.0);
                }
                let mut lines = Vec::new();
                for (peer, (seq, at, sent)) in &online.outgoing.sync.sent {
                    let c = compare(&native, sent);
                    let acked = online.group.enemy_acked.get(peer).copied().unwrap_or(0);
                    lines.push(comparison_event(1, *peer, &c, (now - at).max(0.0), *seq).num("acked", acked as f64).num("lag", seq.saturating_sub(acked) as f64));
                }
                for line in lines {
                    client.record(line);
                }
            } else {
                // the mirror draws the enemies a little behind the newest snapshot (smoothing): compare with where it should draw them now
                let snapshot: Poses = self.mirrors.snapshot_entries().into_iter().map(|(guid, s)| (guid, self.mirrors.display_pose(guid, now).unwrap_or(s.pose))).collect();
                let seq = online.group.peers.get(&1).map_or(0, |p| p.enemy_mirror.seq);
                let age = (now - online.outgoing.sync.last_rx).max(0.0);
                let c = compare(&snapshot, &native);
                client.record(comparison_event(2, online.number, &c, age, seq));
                if metric {
                    let sync = &mut online.outgoing.sync;
                    let samples = std::mem::take(&mut sync.step_samples);
                    client.record(step_event(&mut sync.steps, samples, INTERVAL));
                }
            }
            online.outgoing.sync.lines += 1;
            Ok(())
        })();
        self.online = Some(online);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pose(x: f64) -> [f64; 3] {
        [x, 0.0, 0.0]
    }

    #[test]
    fn refusal_reasons() {
        assert_eq!(refusal_reason(false, None, 9.0), "loot_gone");
        assert_eq!(refusal_reason(true, Some(12.0), 9.0), "out_of_range");
        assert_eq!(refusal_reason(true, Some(4.0), 9.0), "other");
        assert_eq!(refusal_reason(true, None, 9.0), "other");
    }

    #[test]
    fn empty_sides_give_zeros() {
        let c = compare(&[], &[]);
        assert_eq!((c.reference, c.local, c.common, c.only_reference, c.only_local), (0, 0, 0, 0, 0));
        assert_eq!((c.median, c.p95, c.max), (0.0, 0.0, 0.0));
    }

    #[test]
    fn counts_split_by_side_and_distances_use_the_shared_guids_only() {
        let reference = vec![(1, pose(0.0)), (2, pose(0.0)), (3, pose(0.0)), (4, pose(0.0))];
        let local = vec![(2, pose(3.0)), (3, pose(4.0)), (4, pose(10.0)), (9, pose(1.0))];
        let c = compare(&reference, &local);
        assert_eq!((c.reference, c.local, c.common, c.only_reference, c.only_local), (4, 4, 3, 1, 1));
        assert_eq!(c.median, 4.0);
        assert_eq!(c.p95, 10.0);
        assert_eq!(c.max, 10.0);
    }

    #[test]
    fn distance_is_euclidean_in_three_dimensions() {
        let c = compare(&[(1, [0.0, 0.0, 0.0])], &[(1, [2.0, 3.0, 6.0])]);
        assert_eq!((c.median, c.max), (7.0, 7.0));
    }

    #[test]
    fn percentile_is_nearest_rank() {
        let v: Vec<f64> = (1..=20).map(|i| i as f64).collect();
        assert_eq!(percentile(&v, 0.5), 10.0);
        assert_eq!(percentile(&v, 0.95), 19.0);
        assert_eq!(percentile(&v, 1.0), 20.0);
        assert_eq!(percentile(&[7.0], 0.95), 7.0);
        assert_eq!(percentile(&[], 0.5), 0.0);
    }

    #[test]
    fn duplicate_guids_do_not_inflate_the_local_count() {
        let c = compare(&[(1, pose(0.0))], &[(1, pose(1.0)), (1, pose(2.0))]);
        assert_eq!((c.local, c.common, c.only_local), (1, 1, 0));
    }
}
