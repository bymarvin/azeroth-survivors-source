//! The bounded queues of accepted incoming hits (`queue_incoming_hit`, `merge_waiting_hit`,
//! `clear_incoming_hits`, `queued_hit_metadata`): ports of `visibility_bridge.py`.
//!
//! Hits arrive from the peers as `(attacker, damage[, clock])`. A queue never grows past
//! `QUEUE_LIMIT`: when full, the two oldest waiting hits of one attacker are folded into one
//! (their damage summed, bounded by the native HURT maximum); only when no pair exists is the
//! oldest dropped (decision 15.10.2026: a stopped game is worse than a lost hit).

use crate::{Event, Io};
use std::collections::{BTreeMap, VecDeque};

pub const QUEUE_LIMIT: usize = 128;
pub const MAX_HIT_DAMAGE: f64 = 1e12;

#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub attacker: i128,
    pub damage: f64,
    /// Present on "hits" (3 fields), absent on "areas" (2 fields).
    pub clock: Option<f64>,
}

/// (sequence, wall time it was queued, game clock it belongs to)
pub type Meta = (u64, f64, f64);

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    pub incoming: f64,
    pub applied: f64,
    pub obsolete: f64,
    pub high_water: f64,
    pub merged: Option<f64>,
    pub merged_damage: Option<f64>,
    pub max_wait: Option<f64>,
}

#[derive(Default)]
pub struct HitQueues {
    pub queues: BTreeMap<(u32, Kind), Vec<Hit>>,
    pub metadata: BTreeMap<(u32, Kind), VecDeque<Meta>>,
    pub metrics: BTreeMap<(u32, Kind), Metrics>,
    /// (count, damage, last record time) of merges not yet logged.
    pub merge_pending: BTreeMap<(u32, Kind), (f64, f64, f64)>,
    pub sequence: u64,
    pub host_clock: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Hits,
    Areas,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Hits => "hits",
            Kind::Areas => "areas",
        }
    }
}

fn round3(x: f64) -> f64 {
    format!("{x:.3}").parse().unwrap_or(x)
}

impl HitQueues {
    /// `queued_hit_metadata(number, kind)`: metadata is kept in step with the queue.
    pub fn queued_hit_metadata(&mut self, number: u32, kind: Kind, now: f64) -> &mut VecDeque<Meta> {
        let key = (number, kind);
        let queue_len = self.queues.entry(key).or_default().len();
        let mut metadata = self.metadata.remove(&key).unwrap_or_default();
        while metadata.len() < queue_len {
            self.sequence += 1;
            let hit = &self.queues[&key][metadata.len()];
            metadata.push_back((self.sequence, now, if kind == Kind::Hits { hit.clock.unwrap_or(0.0) } else { self.host_clock }));
        }
        self.metadata.entry(key).or_insert(metadata)
    }

    /// `merge_waiting_hit(number, kind, queue, metadata, metrics)`: fold the oldest mergeable pair.
    fn merge_waiting_hit(&mut self, io: &mut dyn Io, number: u32, kind: Kind, now: f64) -> bool {
        let key = (number, kind);
        let mut first: BTreeMap<i128, usize> = BTreeMap::new();
        let len = self.queues[&key].len();
        for index in 0..len {
            let (attacker, damage) = {
                let hit = &self.queues[&key][index];
                (hit.attacker, hit.damage)
            };
            if let Some(older) = first.get(&attacker).copied() {
                let total = self.queues[&key][older].damage + damage;
                if total <= MAX_HIT_DAMAGE {
                    self.queues.get_mut(&key).unwrap()[older].damage = total;
                    self.queues.get_mut(&key).unwrap().remove(index);
                    self.metadata.get_mut(&key).unwrap().remove(index);
                    let metrics = self.metrics.entry(key).or_default();
                    metrics.merged = Some(metrics.merged.unwrap_or(0.0) + 1.0);
                    metrics.merged_damage = Some(metrics.merged_damage.unwrap_or(0.0) + damage);
                    let pending = self.merge_pending.entry(key).or_insert((0.0, 0.0, 0.0));
                    pending.0 += 1.0;
                    pending.1 += damage;
                    if now - pending.2 >= 1.0 {
                        // Aggregated: at most one record per second.
                        let length = self.queues[&key].len();
                        io.record(
                            Event::new("hit_queue_merged")
                                .num("player", number as f64)
                                .text("queue", kind.name())
                                .num("merged", pending.0)
                                .num("damage", round3(pending.1))
                                .num("length", length as f64),
                        );
                        self.merge_pending.insert(key, (0.0, 0.0, now));
                    }
                    return true;
                }
                if damage < MAX_HIT_DAMAGE {
                    first.insert(attacker, index); // the older one is too big: try the newer one
                }
            } else if damage < MAX_HIT_DAMAGE {
                first.insert(attacker, index);
            }
        }
        false
    }

    /// `queue_incoming_hit(number, kind, hit, clock)`.
    pub fn queue_incoming_hit(&mut self, io: &mut dyn Io, number: u32, kind: Kind, hit: Hit, clock: Option<f64>, now: f64) {
        let key = (number, kind);
        self.queued_hit_metadata(number, kind, now);
        self.metrics.entry(key).or_insert_with(|| Metrics { incoming: 0.0, applied: 0.0, obsolete: 0.0, high_water: 0.0, ..Default::default() });
        if self.queues[&key].len() >= QUEUE_LIMIT && !self.merge_waiting_hit(io, number, kind, now) {
            // Last resort only when no two waiting hits share an attacker.
            io.record(
                Event::new("hit_queue_overflow")
                    .num("player", number as f64)
                    .text("queue", kind.name())
                    .num("dropped", 1.0)
                    .num("attempted_length", (self.queues[&key].len() + 1) as f64),
            );
            self.queues.get_mut(&key).unwrap().remove(0);
            self.metadata.get_mut(&key).unwrap().pop_front();
            self.metrics.get_mut(&key).unwrap().obsolete += 1.0;
        }
        self.sequence += 1;
        let meta_clock = clock.unwrap_or(if kind == Kind::Hits { hit.clock.unwrap_or(0.0) } else { self.host_clock });
        self.metadata.get_mut(&key).unwrap().push_back((self.sequence, now, meta_clock));
        self.queues.get_mut(&key).unwrap().push(hit);
        let length = self.queues[&key].len() as f64;
        let metrics = self.metrics.get_mut(&key).unwrap();
        metrics.incoming += 1.0;
        metrics.high_water = metrics.high_water.max(length);
    }

    /// `clear_incoming_hits(number, reason)`.
    pub fn clear_incoming_hits(&mut self, io: &mut dyn Io, number: u32, reason: &str, now: f64) {
        for kind in [Kind::Hits, Kind::Areas] {
            let key = (number, kind);
            let queue_len = self.queues.entry(key).or_default().len();
            if queue_len > 0 {
                let metrics = self.metrics.entry(key).or_insert_with(|| Metrics { incoming: 0.0, applied: 0.0, obsolete: 0.0, high_water: 0.0, ..Default::default() });
                let _ = metrics;
                let oldest = self.queued_hit_metadata(number, kind, now).front().copied();
                let metrics = self.metrics.get_mut(&key).unwrap();
                if let Some((_, queued_at, _)) = oldest {
                    metrics.max_wait = Some(metrics.max_wait.unwrap_or(0.0).max(now - queued_at));
                }
                metrics.obsolete += queue_len as f64;
                io.record(
                    Event::new("incoming_hits_obsolete")
                        .num("player", number as f64)
                        .text("queue", kind.name())
                        .num("count", queue_len as f64)
                        .text("reason", reason),
                );
            }
            self.queues.get_mut(&key).unwrap().clear();
            self.metadata.remove(&key);
        }
    }
}
