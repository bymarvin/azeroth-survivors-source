//! Guest enemy mirrors: ports of `snapshot_enemies`, `_parse_enemy_raw` and `sync_mirrors`
//! (native_guest_combat.py).
//!
//! A guest has no simulation of the host's enemies. Its game keeps one native record per
//! host enemy: the host snapshot is written into those records (position, health, host
//! debuffs) before every batch, slots of enemies that left are retired, missing ones are
//! created with the native spawn. Damage the guest's own attacks do to a mirror shows as a
//! health drop against what was provided; that difference is queued for the host.

use crate::{Call, CodePatch, Event, Io, Result};
use azcoop_game::builds::Variant;
use crate::{finite_item, finite_text, skips};
use azcoop_game::readers::{parse_enemies, SkippedEnemy};

/// The log line of each skipped record (`enemy_pose` -> `note_native_skip('enemy_state_nonfinite', guid, ...)`).
pub fn note_enemy_skips(io: &mut dyn Io, skipped: &[SkippedEnemy]) {
    for s in skipped {
        skips::note(&mut |e| io.record(e), "enemy_state_nonfinite", s.guid, vec![("clock", finite_item(s.now)), ("fields", finite_text(&s.fields))]);
    }
}
use azcoop_world::auras::Ordered;
use std::collections::{BTreeMap, HashMap, VecDeque};

pub const MAX_ENEMIES: usize = 32768;
pub const MAX_ENEMY_DAMAGE: f64 = 1e12;
const DEAD_MARK: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// One host enemy as the mirror writes it: the record bytes from +0x68 (definition pointer
/// stored image-relative), its health and its pose.
#[derive(Debug, Clone, PartialEq)]
pub struct Snap {
    pub flat: Vec<u8>,
    pub hp: f64,
    pub pose: [f64; 3],
}

/// Smoothing of the mirrored enemy positions (guest). The host sends the enemies every 100 ms; writing each snapshot as it arrives
/// moves the enemies in 10 Hz steps while the game draws 60+ frames. The mirror therefore keeps the last arrivals of every enemy and
/// writes, at every batch, the position at `now - delay` between them (a short history, linear), extrapolating with the last
/// velocity (capped) when a snapshot is late, and snapping when an enemy appears or jumps. Combat stays host-authoritative: only the
/// displayed position is delayed. See `docs/ENEMY-SMOOTHING.md`.
pub mod smoothing {
    use std::collections::VecDeque;

    /// Arrivals kept per enemy.
    pub const HISTORY: usize = 8;
    /// Distance between two snapshots of one enemy that counts as a jump (spawn, teleport, charge): shown at once.
    pub const SNAP_DISTANCE: f64 = 10.0;
    /// Longest stretch an enemy is moved on past its newest snapshot, in seconds.
    pub const MAX_EXTRAPOLATION: f64 = 0.15;
    pub const MIN_DELAY: f64 = 0.10;
    pub const MAX_DELAY: f64 = 0.25;

    pub type Point = (f64, [f64; 3]);

    /// Arrival rhythm of the snapshots: mean gap and its mean deviation (both smoothed).
    #[derive(Debug, Clone, Default)]
    pub struct Clock {
        last: f64,
        pub interval: f64,
        pub jitter: f64,
    }

    impl Clock {
        pub fn arrival(&mut self, now: f64) {
            if self.last > 0.0 {
                let gap = now - self.last;
                if gap > 0.0 && gap < 1.0 {
                    if self.interval == 0.0 {
                        self.interval = gap;
                    } else {
                        self.jitter += 0.1 * ((gap - self.interval).abs() - self.jitter);
                        self.interval += 0.1 * (gap - self.interval);
                    }
                }
            }
            self.last = now;
        }

        /// How far behind the newest data the picture is drawn: the usual gap plus room for its irregularity.
        pub fn delay(&self) -> f64 {
            if self.interval == 0.0 {
                return MIN_DELAY.max(0.12);
            }
            (self.interval + 2.5 * self.jitter + 0.02).clamp(MIN_DELAY, MAX_DELAY)
        }
    }

    fn lerp(a: [f64; 3], b: [f64; 3], t: f64) -> [f64; 3] {
        [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]
    }

    fn distance(a: [f64; 3], b: [f64; 3]) -> f64 {
        ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2)).sqrt()
    }

    /// A new arrival for one enemy; a jump (or a dead enemy) starts the history again so that it is shown at once.
    pub fn push(track: &mut VecDeque<Point>, now: f64, pose: [f64; 3], dead: bool) {
        if dead || track.back().is_some_and(|(_, last)| distance(*last, pose) > SNAP_DISTANCE) {
            track.clear();
        }
        track.push_back((now, pose));
        while track.len() > HISTORY {
            track.pop_front();
        }
    }

    /// Where the enemy is drawn at `now`.
    pub fn display(track: &VecDeque<Point>, now: f64, delay: f64) -> Option<[f64; 3]> {
        let (first, last) = (track.front()?, track.back()?);
        let at = now - delay;
        if track.len() == 1 || at <= first.0 {
            return Some(first.1);
        }
        if at >= last.0 {
            // late snapshot: go on with the last velocity for a short while
            let before = track[track.len() - 2];
            let span = last.0 - before.0;
            if span < 1e-3 {
                return Some(last.1);
            }
            let ahead = (at - last.0).min(MAX_EXTRAPOLATION);
            let t = 1.0 + ahead / span;
            return Some(lerp(before.1, last.1, t));
        }
        let i = track.iter().position(|p| p.0 > at)?;
        let (a, b) = (track[i - 1], track[i]);
        let span = b.0 - a.0;
        Some(if span < 1e-9 { b.1 } else { lerp(a.1, b.1, (at - a.0) / span) })
    }
}

pub struct Mirrors {
    pub variant: Variant,
    pub image_size: u64,
    pub max_enemies: usize,
    /// `COOP_MIRROR_WRITE=all`: write every record and retired flag each batch.
    pub write_all: bool,
    /// Draw the mirrored enemies between the last snapshots instead of on the newest one (guest; `COOP_MIRROR_SMOOTH=0` turns it off).
    pub smoothing: bool,
    tracks: HashMap<u64, VecDeque<smoothing::Point>>,
    clock: smoothing::Clock,
    raw: Option<(Vec<u8>, f32, u64)>,
    snapshot: Ordered<Snap>,
    pub boss_definitions: HashMap<u64, u64>,
    pub ranged_enemies: Ordered<Snap>,
    /// Health this guest's mirrors were given at the previous batch, per player.
    pub provided: BTreeMap<u32, Ordered<f64>>,
    pub damage_pending: Ordered<f64>,
    /// Guids whose debuffs are still queued from the host: their conditions are not overwritten.
    pub effects_pending: Vec<(u64, Vec<u8>, u32)>,
    /// (target guid, requested damage) of every `guest_damage_target_already_dead` / `native_guest_damage_applied`,
    /// for the host's damage receipts; the bridge drains it after each event.
    pub damage_applied: Vec<(u64, f64)>,
    pub notes: VecDeque<(String, Vec<i128>)>,
    pub bound_dropped: BTreeMap<String, i128>,
    pub bound_logged: BTreeMap<String, f64>,
}

fn q(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

/// `struct.pack('<f', v)`: finite values beyond the float range raise.
fn pack_f32(v: f64) -> Result<[u8; 4]> {
    if v.is_finite() && v.abs() > f32::MAX as f64 && (v as f32).is_infinite() {
        return Err("float too large to pack with f format".into());
    }
    Ok((v as f32).to_le_bytes())
}

impl Mirrors {
    pub fn new(variant: Variant, image_size: u64) -> Mirrors {
        Mirrors {
            variant,
            image_size,
            max_enemies: MAX_ENEMIES,
            write_all: false,
            smoothing: true,
            tracks: HashMap::new(),
            clock: smoothing::Clock::default(),
            raw: None,
            snapshot: Ordered::default(),
            boss_definitions: HashMap::new(),
            ranged_enemies: Ordered::default(),
            provided: BTreeMap::new(),
            damage_pending: Ordered::default(),
            effects_pending: Vec::new(),
            damage_applied: Vec::new(),
            notes: VecDeque::new(),
            bound_dropped: BTreeMap::new(),
            bound_logged: BTreeMap::new(),
        }
    }

    fn note(&mut self, kind: &str, values: Vec<i128>) {
        if self.notes.len() == 64 {
            self.notes.pop_front();
        }
        self.notes.push_back((kind.to_string(), values));
    }

    fn note_bound(&mut self, io: &mut dyn Io, state: &str, amount: i128, now: f64, details: Vec<(&str, f64)>) {
        *self.bound_dropped.entry(state.into()).or_insert(0) += amount;
        if now >= self.bound_logged.get(state).copied().unwrap_or(0.0) {
            self.bound_logged.insert(state.into(), now + 60.0);
            let mut event = Event::new("bounded_state_dropped").text("state", state).num("dropped", self.bound_dropped[state] as f64);
            for (k, v) in details {
                event = event.num(k, v);
            }
            io.record(event);
        }
    }

    /// The parsed snapshot (host enemies as last captured), in capture order.
    pub fn snapshot_guids(&self) -> Vec<u64> {
        self.snapshot.keys()
    }

    /// `enemy_snapshot.get(guid) or ranged_enemies.get(guid)`: parses a pending capture first.
    pub fn lookup(&mut self, io: &mut dyn Io, guid: u64, monotonic: f64) -> Result<Option<Snap>> {
        self.ensure_parsed(io, monotonic)?;
        Ok(self.snapshot.get(guid).cloned().or_else(|| self.ranged_enemies.get(guid).cloned()))
    }

    /// `guid in enemy_snapshot`: parses a pending capture first.
    pub fn snapshot_contains(&mut self, io: &mut dyn Io, guid: u64, monotonic: f64) -> Result<bool> {
        self.ensure_parsed(io, monotonic)?;
        Ok(self.snapshot.contains(guid))
    }

    /// Run end on the host: `enemy_snapshot.clear(); boss_definitions.clear(); damage_pending.clear(); effects_pending.clear()`.
    pub fn clear_host_run(&mut self, io: &mut dyn Io, monotonic: f64) -> Result<()> {
        self.ensure_parsed(io, monotonic)?;
        self.snapshot = Ordered::default();
        self.boss_definitions.clear();
        self.damage_pending = Ordered::default();
        self.effects_pending.clear();
        Ok(())
    }

    /// A capture is waiting to be parsed.
    pub fn raw_pending(&self) -> bool {
        self.raw.is_some()
    }

    pub fn snapshot_get(&self, guid: u64) -> Option<&Snap> {
        self.snapshot.get(guid)
    }

    /// The parsed snapshot in insertion order, parsing a pending capture first (`enemy_snapshot`).
    pub fn snapshot_view(&mut self, io: &mut dyn Io, monotonic: f64) -> Result<Vec<(u64, Snap)>> {
        self.ensure_parsed(io, monotonic)?;
        Ok(self.snapshot_entries())
    }

    /// A snapshot received from the host (guest side): replaces `enemy_snapshot` and `boss_definitions`.
    pub fn set_host_snapshot(&mut self, entries: Vec<(u64, Snap)>, bosses: HashMap<u64, u64>) {
        self.raw = None;
        let mut snapshot = Ordered::default();
        for (guid, snap) in entries {
            snapshot.set(guid, snap);
        }
        self.snapshot = snapshot;
        self.boss_definitions = bosses;
    }

    /// `set_host_snapshot` for a snapshot that arrived at `now` (seconds, the bridge clock): also feeds the smoothing history.
    pub fn set_host_snapshot_at(&mut self, entries: Vec<(u64, Snap)>, bosses: HashMap<u64, u64>, now: f64) {
        self.clock.arrival(now);
        let mut tracks = std::mem::take(&mut self.tracks);
        tracks.retain(|guid, _| entries.iter().any(|(g, _)| g == guid));
        for (guid, snap) in &entries {
            smoothing::push(tracks.entry(*guid).or_default(), now, snap.pose, snap.hp <= 0.0);
        }
        self.tracks = tracks;
        self.set_host_snapshot(entries, bosses);
    }

    /// Where the mirror of `guid` is drawn at `now` (None: no history, the snapshot pose is used).
    pub fn display_pose(&self, guid: u64, now: f64) -> Option<[f64; 3]> {
        if !self.smoothing {
            return None;
        }
        smoothing::display(self.tracks.get(&guid)?, now, self.clock.delay())
    }

    /// The parsed snapshot in insertion order (tests and logs).
    pub fn snapshot_entries(&self) -> Vec<(u64, Snap)> {
        self.snapshot.keys().into_iter().map(|g| (g, self.snapshot.get(g).cloned().unwrap())).collect()
    }

    /// `snapshot_enemies(client)`: capture the native enemy array; parsed when first needed.
    pub fn snapshot_enemies(&mut self, io: &mut dyn Io) -> Result<()> {
        let head = io.read_bytes(0x568, 16)?;
        let (pointer, count) = (q(&head, 0), q(&head, 8));
        if count > self.max_enemies as u64 {
            return Err("Native enemy vector exceeds diagnostic bound".into());
        }
        let stride = self.variant.enemy_layout().stride;
        let data = if count > 0 { io.read_abs(pointer, (count * stride) as usize)? } else { Vec::new() };
        let now = f32::from_le_bytes(io.read_bytes(0x85C, 4)?[..4].try_into().unwrap());
        self.raw = Some((data, now, io.base()));
        Ok(())
    }

    /// Reading `enemy_snapshot` / `boss_definitions` parses a pending capture first.
    fn ensure_parsed(&mut self, io: &mut dyn Io, monotonic: f64) -> Result<()> {
        let Some((data, now, base)) = self.raw.take() else { return Ok(()) };
        let poses = {
            let mut poses = Ordered::default();
            let (enemies, skipped) = parse_enemies(&data, now, self.variant)?;
            note_enemy_skips(io, &skipped);
            for e in enemies {
                poses.set(e.guid, (e.hp, e.position));
            }
            poses
        };
        let mut snapshot = Ordered::default();
        let mut bosses = HashMap::new();
        let layout = self.variant.enemy_layout();
        let (stride, guid_offset) = (layout.stride as usize, layout.guid_offset as usize);
        let definition_offset = (self.variant.enemy_offset(0x80) - 0x68) as usize;
        let mut ranged_new = Vec::new();
        let mut bad = 0usize;
        let result = (|| -> Result<()> {
            for offset in (0..data.len()).step_by(stride) {
                let guid = q(&data, offset + guid_offset);
                let Some(&(hp, pose)) = poses.get(guid) else { continue };
                let mut flat = data[offset + 0x68..offset + stride].to_vec();
                let mut definition = q(&flat, definition_offset) as i128;
                if definition != 0 {
                    definition -= base as i128;
                    if !(0..self.image_size as i128).contains(&definition) {
                        // One record mid-teardown: skipped like an absent enemy.
                        bad += 1;
                        skips::note(&mut |e| io.record(e), "enemy_definition_invalid", guid, vec![]);
                        continue;
                    }
                } else {
                    let boss = q(&data, offset + 0x30) as i128 - base as i128;
                    if q(&data, offset + 0x18) == DEAD_MARK || !(0..self.image_size as i128 - 0x58).contains(&boss) {
                        bad += 1;
                        skips::note(&mut |e| io.record(e), "boss_definition_invalid", guid, vec![]);
                        continue;
                    }
                    bosses.insert(guid, boss as u64);
                }
                flat[definition_offset..definition_offset + 8].copy_from_slice(&(definition as u64).to_le_bytes());
                snapshot.set(guid, Snap { flat, hp, pose });
                if definition != 0 {
                    // A queued GO can precede a death caused by injected guest damage:
                    // cast metadata is retired in packet order at DESTROY.
                    ranged_new.push(guid);
                }
            }
            Ok(())
        })();
        // The Python assigns the half-built dicts before the loop and keeps them on an error.
        let result = result.and_then(|()| {
            if bad > 0 && bad == poses.len() && poses.len() >= 5 {
                // Every living enemy points outside the executable: a wrong layout, not a single broken entry.
                Err("Enemy definition is not in the verified executable".to_string())
            } else {
                Ok(())
            }
        });
        for guid in ranged_new {
            let snap = snapshot.get(guid).cloned().unwrap();
            self.ranged_enemies.set(guid, snap);
        }
        self.snapshot = snapshot;
        self.boss_definitions = bosses;
        result?;
        if self.ranged_enemies.len() > 2 * self.max_enemies {
            // Enemies that left without a DESTROY (run end): keep the current ones, drop the oldest others.
            let excess = self.ranged_enemies.len() - 3 * self.max_enemies / 2;
            let stale: Vec<u64> = self.ranged_enemies.keys().into_iter().filter(|g| !self.snapshot.contains(*g)).take(excess).collect();
            for guid in &stale {
                self.ranged_enemies.remove(*guid);
            }
            let kept = self.ranged_enemies.len() as f64;
            self.note_bound(io, "ordinary_enemy_metadata", stale.len() as i128, monotonic, vec![("kept", kept)]);
        }
        Ok(())
    }

    /// `sync_mirrors(client, context, capture_only)`: true when it called into the game (the
    /// caller retries the queue write afterwards).
    pub fn sync_mirrors(&mut self, io: &mut dyn Io, number: u32, capture_only: bool, monotonic: f64) -> Result<bool> {
        let layout = self.variant.enemy_layout();
        let s = layout.stride as usize;
        let e = |o: u64| self.variant.enemy_offset(o) as usize;
        let base = io.base();
        let head = io.read_bytes(0x568, 16)?;
        let (pointer, count) = (q(&head, 0), q(&head, 8) as usize);
        if count > self.max_enemies {
            return Err("Enemy mirror count exceeds bound".into());
        }
        let mut data = if count > 0 { io.read_abs(pointer, count * s)? } else { Vec::new() };
        let mut by_guid: Ordered<usize> = Ordered::default();
        for i in 0..count {
            by_guid.set(q(&data, i * s + e(0x78)), i);
        }
        let mut provided = self.provided.remove(&number).unwrap_or_default();
        let outcome = self.mirror_pass(io, number, capture_only, monotonic, base, pointer, count, &mut data, &mut by_guid, &mut provided);
        self.provided.insert(number, provided);
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn mirror_pass(
        &mut self,
        io: &mut dyn Io,
        _number: u32,
        capture_only: bool,
        monotonic: f64,
        base: u64,
        pointer: u64,
        count: usize,
        data: &mut Vec<u8>,
        by_guid: &mut Ordered<usize>,
        provided: &mut Ordered<f64>,
    ) -> Result<bool> {
        let s = self.variant.enemy_layout().stride as usize;
        let variant = self.variant;
        let e = |o: u64| variant.enemy_offset(o) as usize;
        for guid in provided.keys() {
            let previous = *provided.get(guid).unwrap();
            if let Some(&i) = by_guid.get(guid) {
                let health = f32::from_le_bytes(data[i * s + e(0xE0)..i * s + e(0xE0) + 4].try_into().unwrap()) as f64;
                if !health.is_finite() {
                    skips::note(&mut |e| io.record(e), "mirror_health_nonfinite", guid, vec![("health", finite_item(health))]);
                    continue;
                }
                let dealt = previous - if health > 0.0 { health } else { 0.0 };
                if dealt > 0.0 {
                    self.ensure_parsed(io, monotonic)?;
                    if self.snapshot.contains(guid) {
                        let sum = self.damage_pending.get(guid).copied().unwrap_or(0.0) + dealt;
                        self.damage_pending.set(guid, sum);
                        io.record(Event::new("native_guest_damage_computed").num("target", guid as f64).num("damage", dealt));
                    }
                }
            }
        }
        *provided = Ordered::default();
        let too_many = self.damage_pending.len() > self.max_enemies;
        if too_many || self.damage_pending.keys().iter().any(|g| *self.damage_pending.get(*g).unwrap() > MAX_ENEMY_DAMAGE) {
            return Err("Guest damage queue exceeds bound".into());
        }
        if capture_only {
            return Ok(false); // Final accepted native hits, without starting another mirror tick.
        }
        self.ensure_parsed(io, monotonic)?;
        let mut retired: Vec<usize> = by_guid.keys().into_iter().filter(|g| !self.snapshot.contains(*g)).map(|g| *by_guid.get(g).unwrap()).collect();
        let missing: Vec<u64> = self.snapshot.keys().into_iter().filter(|g| !by_guid.contains(*g)).collect();
        // START's hidden local enemies are reusable owned allocations too.
        for guid in missing {
            let boss = self.boss_definitions.get(&guid).copied();
            let reusable = retired
                .iter()
                .copied()
                .find(|&index| (q(data, index * s + 0x18) != DEAD_MARK) == boss.is_some() && boss.map_or(true, |b| q(data, index * s + 0x30) == base.wrapping_add(b)));
            let Some(index) = reusable else {
                let pose = self.snapshot.get(guid).unwrap().pose;
                let before = count as u64;
                self.note("mirror_spawn", vec![1]);
                io.call(Call::SpawnMirror { boss: boss.map(|b| base + b), position: pose })?;
                let after = q(&io.read_bytes(0x570, 8)?, 0);
                if after != before + 1 {
                    return Err("Native enemy mirror spawn was refused".into());
                }
                // Native local GUID counters can collide with an existing host GUID:
                // retire by slot before the next GUID lookup.
                let fresh = q(&io.read_bytes(0x568, 8)?, 0);
                io.put_abs(fresh + before * s as u64 + e(0x78) as u64, &[0; 8]);
                io.put_abs(fresh + before * s as u64 + 0x68, &1u32.to_le_bytes());
                return Ok(true);
            };
            let at = retired.iter().position(|i| *i == index).unwrap();
            retired.remove(at);
            let mut flat = self.snapshot.get(guid).unwrap().flat.clone();
            let definition_offset = e(0x80) - 0x68;
            let definition = q(&flat, definition_offset);
            if definition != 0 {
                let relocated = definition.checked_add(base).ok_or("argument out of range")?;
                flat[definition_offset..definition_offset + 8].copy_from_slice(&relocated.to_le_bytes());
            }
            let address = pointer + (index * s) as u64;
            // Preserve native-owned vectors, retiring plain periodic-effect entries.
            io.put_abs(address + 0x10, &[0; 8]);
            io.put_abs(address + 0x68, &flat);
            data[index * s + 0x68..(index + 1) * s].copy_from_slice(&flat);
            by_guid.set(guid, index);
        }
        let (mut retired_writes, mut written) = (0i128, 0i128);
        for index in retired {
            // Retired slots keep their dead flag; rewriting it every batch made native
            // writes grow with every enemy that ever died (v11).
            if self.write_all || u32::from_le_bytes(data[index * s + 0x68..index * s + 0x6C].try_into().unwrap()) != 1 {
                io.put_abs(pointer + (index * s) as u64 + 0x68, &1u32.to_le_bytes());
                retired_writes += 1;
            }
        }
        for guid in self.snapshot.keys() {
            let Snap { flat, hp, pose } = self.snapshot.get(guid).unwrap().clone();
            let index = *by_guid.get(guid).ok_or("KeyError")?;
            let address = pointer + (index * s) as u64;
            let remaining = hp - self.damage_pending.get(guid).copied().unwrap_or(0.0);
            let health = if remaining > 0.0 { remaining } else { 0.0 };
            let pose = if health > 0.0 { self.display_pose(guid, monotonic).unwrap_or(pose) } else { pose };
            // All game threads are suspended at this debugger event. Preserve native-owned
            // fields from this exact read and update one contiguous span.
            let start = index * s + 0x68;
            let original = data[start..start + s - 0x68].to_vec();
            let mut updated = original.clone();
            updated[0..4].copy_from_slice(&((health == 0.0) as u32).to_le_bytes());
            let at = e(0xE0) - 0x68;
            updated[at..at + 4].copy_from_slice(&pack_f32(health)?);
            let at = e(0xFC) - 0x68;
            for (k, v) in pose.iter().chain(pose.iter()).enumerate() {
                updated[at + 4 * k..at + 4 * k + 4].copy_from_slice(&pack_f32(*v)?);
            }
            updated[e(0x114) - 0x68..e(0x11C) - 0x68].fill(0);
            if !self.effects_pending.iter().any(|e| e.0 == guid) {
                // Host debuffs also inform guest native conditional abilities.
                for (from, to) in [(0x88u64, 0x98u64), (0x124, 0x128), (0x130, 0x140)] {
                    let range = e(from) - 0x68..e(to) - 0x68;
                    updated[range.clone()].copy_from_slice(&flat[range]);
                }
            }
            if self.write_all || updated != original {
                io.put_abs(address + 0x68, &updated);
                written += 1;
            }
            provided.set(guid, health);
        }
        if written != 0 || retired_writes != 0 {
            self.note("mirror_writes", vec![written, retired_writes]);
        }
        Ok(false)
    }
}

impl Mirrors {
    /// Read-only: (guid, hp, pose) of every living record of the native enemy array, in array order (the enemy-sync figure).
    /// Unlike `snapshot_enemies` it leaves the captured snapshot alone and does not log skipped records.
    pub fn native_poses(&self, io: &mut dyn Io) -> Result<Vec<(u64, f64, [f64; 3])>> {
        let stride = self.variant.enemy_layout().stride;
        let head = io.read_bytes(0x568, 16)?;
        let (pointer, count) = (q(&head, 0), q(&head, 8));
        if count > self.max_enemies as u64 {
            return Err("Native enemy vector exceeds diagnostic bound".into());
        }
        let data = if count > 0 { io.read_abs(pointer, (count * stride) as usize)? } else { Vec::new() };
        let now = f32::from_le_bytes(io.read_bytes(0x85C, 4)?[..4].try_into().unwrap());
        let (enemies, _skipped) = parse_enemies(&data, now, self.variant)?;
        Ok(enemies.into_iter().map(|e| (e.guid, e.hp, e.position)).collect())
    }

    /// `native_enemy(client, game, guid)`: (hp, pose) of the first living record with this guid.
    pub fn native_enemy(&self, io: &mut dyn Io, guid: u64) -> Result<Option<(f64, [f64; 3])>> {
        let layout = self.variant.enemy_layout();
        let (stride, guid_offset) = (layout.stride as usize, layout.guid_offset as usize);
        let head = io.read_bytes(0x568, 16)?;
        let (pointer, count) = (q(&head, 0), q(&head, 8));
        if count > self.max_enemies as u64 {
            return Err("Native enemy vector exceeds diagnostic bound".into());
        }
        let data = if count > 0 { io.read_abs(pointer, count as usize * stride)? } else { Vec::new() };
        let now = f32::from_le_bytes(io.read_bytes(0x85C, 4)?[..4].try_into().unwrap()) as f64;
        let record = 4 + layout.guid_gap as usize + 8 + 96 + 4 + 24 + 12 + 12 + 4 + 4;
        for entry in 0..count as usize {
            let offset = entry * stride;
            if q(&data, offset + guid_offset) != guid {
                continue;
            }
            let at = offset + 0x68;
            let r = data.get(at..at + record).ok_or("unpack_from requires a buffer of enough bytes")?;
            if u32::from_le_bytes(r[0..4].try_into().unwrap()) == 1 {
                continue;
            }
            let f = |k: usize| f32::from_le_bytes(r[k..k + 4].try_into().unwrap()) as f64;
            let mut at = 4 + layout.guid_gap as usize + 8 + 96;
            let hp = f(at);
            at += 4 + 24;
            let v: Vec<f64> = (0..8).map(|i| f(at + 4 * i)).collect();
            let (x0, y0, z0, x1, y1, z1, began, duration) = (v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
            if ![now, hp, x0, y0, z0, x1, y1, z1, began, duration].iter().all(|x| x.is_finite()) {
                note_enemy_skips(io, &[SkippedEnemy { guid, now, fields: [hp, x0, y0, z0, x1, y1, z1, began, duration] }]);
                return Ok(None); // as if not there
            }
            let t = if duration > 0.0 { ((now - began) / duration).clamp(0.0, 1.0) } else { 1.0 };
            return Ok(Some((hp, [x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, z0 + (z1 - z0) * t])));
        }
        Ok(None)
    }

    /// `apply_guest_damage(client, context)`: inject the oldest queued guest damage into the host's
    /// game through the native DAMAGE call, with the host's private modifiers patched out for the
    /// duration of the call. `base_patches` is `guest_damage_patches()`, `downed_gate` the extra
    /// phase-gate patch used while the host is down. True when the call was made.
    pub fn apply_guest_damage(&mut self, io: &mut dyn Io, host_phase: u64, base_patches: &[CodePatch], downed_gate: &CodePatch, monotonic: f64) -> Result<bool> {
        let target = self.damage_pending.first_key().ok_or("StopIteration")?;
        let damage = *self.damage_pending.get(target).unwrap();
        let before = self.native_enemy(io, target)?.map_or(0.0, |e| e.0);
        if before <= 0.0 {
            self.damage_pending.remove(target);
            self.damage_applied.push((target, damage));
            io.record(Event::new("guest_damage_target_already_dead").num("target", target as f64).num("requested", damage));
            return Ok(false);
        }
        let mut patches: Vec<CodePatch> = base_patches.to_vec();
        if host_phase == 4 {
            patches.push(downed_gate.clone());
        }
        for (rva, original, _) in &patches {
            if io.code_read(*rva, original.len())? != *original {
                return Err("Native raw damage instructions changed".into());
            }
        }
        for (rva, _, replacement) in &patches {
            io.code_patch(*rva, replacement)?;
        }
        let called = io.call(Call::Damage { enemy: target, amount: damage });
        // The Python leaves the patches in place when the call itself fails; restore them either way.
        for (rva, original, _) in &patches {
            io.code_patch(*rva, original)?;
        }
        called?;
        let after = self.native_enemy(io, target)?.map_or(0.0, |e| e.0);
        let left = self.damage_pending.get(target).copied().unwrap_or(0.0) - damage;
        self.damage_pending.set(target, left);
        if left <= 0.0 {
            self.damage_pending.remove(target);
        }
        self.snapshot_enemies(io)?;
        let _ = monotonic;
        self.damage_applied.push((target, damage));
        io.record(
            Event::new("native_guest_damage_applied")
                .num("target", target as f64)
                .num("before", before)
                .num("after", after)
                .num("requested", damage)
                .num("host_downed", (host_phase == 4) as u8 as f64),
        );
        Ok(true)
    }
}
