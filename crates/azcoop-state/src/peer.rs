//! `OnlineBridge.receive_state`: strict validation of the peer's state message
//! and the per-peer state it updates.
//!
//! Fail closed: the Python accepts a few shapes this port rejects (float or
//! bool where an int is meant, guest combat/summon/chat packets, which the
//! native host does not take yet). Whatever it accepts, the Python accepts
//! too, with the same effect. `receive` is transactional: on error the state
//! is unchanged.

use crate::limits::*;
use crate::{as_big, as_int, finite, is_int, unbinary, Result};
use azcoop_world::builders::clone_player;
use azcoop_world::filter::set_name_response;
use crate::auras::validate_auras;
use crate::enemies::{Codec, Enemy, EnemyMirror, MAX_ENEMY_HP};
use azcoop_world::auras::AuraOverlay;
use azcoop_world::builders::reject_remote_marker_packet;
use azcoop_world::guest_input::GuestInput;
use azcoop_world::session::{decode_ground_movement, is_movement_opcode, validate_movement_packet};
use azcoop_world::is_world;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub type Packet = (u16, Vec<u8>);

#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub kind: &'static str,
    pub guid: i128,
    pub damage: f64,
    pub clock: f64,
    /// The remaining value of a "hits" entry is its clock, an "areas" entry has none.
    pub order_clock: f64,
}

/// State shared by all peers of one session: the checks a guest's packets pass on the host.
pub struct Session {
    pub members: Vec<u32>,
    pub input: GuestInput,
    /// Guest debuffs placed on the shared enemies (host side).
    pub overlay: AuraOverlay,
}

impl Session {
    pub fn new(members: Vec<u32>) -> Session {
        Session { input: GuestInput::new(&members), overlay: AuraOverlay::new(azcoop_world::auras::MAX_ENEMIES), members }
    }
}

/// What this side knows about one remote peer, and what it has queued from it.
#[derive(Debug, Clone, Default)]
pub struct Peer {
    /// This side's player number (1 = host) and the peer's.
    pub number: u32,
    pub other: u32,
    pub members: Vec<u32>,
    /// A local shutdown drain: pause controls are ignored.
    pub draining: bool,
    /// The host's current boss reward sequence (host side only).
    pub boss_reward_sequence: u64,
    /// World packets the host has handed out / captured so far (host side only).
    pub world_delivered: u64,
    pub world_captured: u64,

    // --- state kept per peer
    pub template: Option<Vec<u8>>,
    pub template_pose: Option<[f64; 4]>,
    pub name_response: Option<Vec<u8>>,
    pub created: Option<BTreeSet<u32>>,
    pub ready: bool,
    pub loaded: bool,
    pub native_state: Option<[u64; 4]>,
    pub latest_movement: Option<Packet>,
    pub xp_multiplier: f64,
    /// State messages accepted so far.
    pub states_received: u64,
    pub boss_reward_applied: u64,
    pub boss_reward_seen: u64,
    pub boss_reward_pending: Vec<(u64, u64, i64)>,
    pub paused: Option<bool>,
    pub restart_requested: bool,
    pub stop_requested: bool,
    pub peer_finished: bool,
    pub chest_claim: Option<Value>,
    pub powerups_pending: Vec<u8>,
    /// Raid icons the host assigned (guests).
    pub raid_assignments: BTreeMap<u32, u8>,
    /// Packets from the peer to show in the local game (`notice_packets`).
    pub notice_packets: Vec<Packet>,

    // --- host side
    pub damage_pending: BTreeMap<i128, f64>,
    pub effects_pending: Vec<(i128, Vec<u8>, i64)>,
    /// Group layer: the enemy sequence last sent to this guest (set by the caller), the last acknowledged
    /// one and whether the guest asked for a full snapshot.
    pub enemy_sequence_sent: u64,
    /// Set by the group while this guest's link just came back: its enemy acknowledgements name the old link's numbers.
    pub resync: bool,
    pub enemy_acked: u64,
    pub enemy_full_requested: bool,
    pub surrendered: bool,

    // --- guest side
    pub host_clock: f64,
    pub host_boss_hud: Value,
    pub xp_pending: f64,
    pub gold_pending: f64,
    pub party_surrender: bool,
    pub incoming: Vec<Hit>,
    pub damage_sent: BTreeMap<i128, f64>,
    pub damage_acked: BTreeMap<i128, f64>,
    pub world_pending: Vec<Packet>,
    pub world_bytes: usize,
    pub world_captured_count: u64,
    pub chests: BTreeMap<i128, Vec<Value>>,
    /// The enemy record layout of this build; without it enemy snapshots are bounded and ignored.
    pub codec: Option<Codec>,
    /// The host's enemy snapshot as received (needs `codec`).
    pub enemy_mirror: EnemyMirror,
    pub transitions: u32,
    /// `guest_display_rejected` events raised by this message: (player, avatar, display).
    pub display_rejections: Vec<(u32, i64, u32)>,
}

impl Peer {
    /// `number` is this side, `other` the peer, `members` all players.
    pub fn new(number: u32, other: u32, members: Vec<u32>) -> Peer {
        Peer { number, other, members, xp_multiplier: 1.0, host_boss_hud: Value::Null, ..Default::default() }
    }

    /// `receive_state(message)`. Returns false when the peer said goodbye.
    pub fn receive(&mut self, message: &Value, session: &mut Session) -> Result<bool> {
        let mut next = self.clone();
        let more = next.receive_inner(message, session)?;
        next.states_received += more as u64;
        *self = next;
        Ok(more)
    }

    fn receive_inner(&mut self, message: &Value, session: &mut Session) -> Result<bool> {
        let obj = message.as_object().ok_or("Unknown co-op message")?;
        match obj.get("kind").and_then(Value::as_str) {
            Some("goodbye") => {
                self.peer_finished = true;
                self.stop_requested = true;
                return Ok(false);
            }
            Some("state") => {}
            _ => return Err("Unknown co-op message".into()),
        }
        let get = |key: &str| obj.get(key);
        let truthy = |key: &str| match obj.get(key) {
            None | Some(Value::Null) | Some(Value::Bool(false)) => false,
            Some(Value::Number(n)) => n.as_f64() != Some(0.0),
            Some(Value::String(s)) => !s.is_empty(),
            Some(Value::Array(a)) => !a.is_empty(),
            Some(Value::Object(o)) => !o.is_empty(),
            Some(Value::Bool(true)) => true,
        };
        if let Some(value) = get("raid_assignments") {
            if self.number == 1 {
                return Err("Only the host can assign raid icons".into());
            }
            let object = value.as_object().filter(|o| o.len() <= 4).ok_or("Invalid raid assignments")?;
            let mut assignments = BTreeMap::new();
            for (player, icon) in object {
                let number: u32 = player.parse().ok().filter(|n| self.members.contains(n) && n.to_string() == *player).ok_or("Invalid raid assignment")?;
                let icon = as_int(icon).filter(|i| (0..8).contains(i)).ok_or("Invalid raid assignment")? as u8;
                assignments.insert(number, icon);
            }
            let icons: BTreeSet<u8> = assignments.values().copied().collect();
            if icons.len() != assignments.len() {
                return Err("Duplicate raid icons".into());
            }
            if self.raid_assignments.iter().any(|(n, icon)| assignments.get(n).map_or(false, |new| new != icon)) {
                return Err("Raid assignment changed during a run".into());
            }
            self.raid_assignments = assignments;
        }
        self.xp_multiplier = finite(get("xp_multiplier").unwrap_or(&Value::from(1)), 0.0, MAX_MULTIPLIER)?;
        if self.number != 1 {
            let powerups = match get("powerups") {
                None => &Vec::new(),
                Some(Value::Array(a)) => a,
                Some(_) => return Err("Invalid shared powerup events".into()),
            };
            if powerups.len() + self.powerups_pending.len() > MAX_QUEUE {
                return Err("Invalid shared powerup events".into());
            }
            let mut kinds = Vec::new();
            for kind in powerups {
                match as_int(kind) {
                    Some(k @ 3..=6) => kinds.push(k as u8),
                    _ => return Err("Invalid shared powerup events".into()),
                }
            }
            self.powerups_pending.extend(kinds);
        } else if get("powerups").is_some() {
            return Err("Only the host can publish powerups".into());
        }
        if self.number == 1 {
            let ack = match get("boss_reward_ack") {
                None => 0,
                Some(v) => as_int(v).filter(|a| *a >= 0).ok_or("Invalid boss reward acknowledgement")? as u64,
            };
            if !(self.boss_reward_applied <= ack && ack <= self.boss_reward_sequence) {
                return Err("Invalid boss reward acknowledgement".into());
            }
            self.boss_reward_applied = ack;
        } else {
            self.receive_boss_rewards(get("boss_rewards"))?;
        }
        if truthy("closing") {
            self.stop_requested = true;
        }
        if let Some(name) = get("name_response") {
            let body = unbinary(name, 128)?;
            if let Some(registered) = set_name_response(&self.members, self.other, self.name_response.as_deref(), &body)? {
                self.name_response = Some(registered);
            }
        }
        if let Some(template) = get("template") {
            if self.template.is_some() {
                return Err("Repeated co-op character template".into());
            }
            let body = unbinary(template, 1_048_576)?;
            if body.len() < 36 {
                return Err("Short co-op character template".into());
            }
            let pose: [f64; 4] = std::array::from_fn(|i| {
                f32::from_le_bytes(body[20 + 4 * i..24 + 4 * i].try_into().unwrap()) as f64
            });
            clone_player(&body, 0xFF0100 + self.other as u64, pose)?;
            session.input.templates.insert(self.other, body.clone());
            self.template = Some(body);
            self.template_pose = Some(pose);
            self.created = Some(BTreeSet::new());
        }
        for key in ["ready", "loaded"] {
            match get(key) {
                Some(Value::Bool(set)) => {
                    if *set {
                        if key == "ready" {
                            self.ready = true;
                        } else {
                            self.loaded = true;
                        }
                    }
                }
                _ => return Err("Invalid co-op readiness".into()),
            }
        }
        if let Some(state) = get("state") {
            if !state.is_null() {
                let list = state.as_array().filter(|s| s.len() == 4).ok_or("Invalid co-op player state")?;
                let mut values = [0u64; 4];
                for (slot, value) in values.iter_mut().zip(list) {
                    let v = as_int(value).filter(|v| (0..=MAX_COUNTER as i64).contains(v)).ok_or("Invalid co-op player state")?;
                    *slot = v as u64;
                }
                if values[0] > 5 {
                    return Err("Invalid co-op player state".into());
                }
                self.native_state = Some(values);
            }
        }
        let created = match get("created") {
            None => Vec::new(),
            Some(Value::Array(list)) => list.iter().map(|v| as_int(v)).collect::<Option<Vec<_>>>().unwrap_or_default(),
            Some(_) => return Err("Invalid remote creation acknowledgement".into()),
        };
        if let Some(Value::Array(list)) = get("created") {
            if created.len() != list.len()
                || created.iter().any(|v| !self.members.iter().any(|m| *m as i64 == *v) || *v == self.other as i64)
            {
                return Err("Invalid remote creation acknowledgement".into());
            }
        }
        if let Some(set) = &mut self.created {
            *set = created.iter().map(|v| *v as u32).collect();
        }
        if let (Some(movement), Some(_)) = (get("movement"), &self.template) {
            let [opcode, encoded] = movement.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 2]>::try_from(s).ok()).ok_or("Invalid movement")?;
            let opcode = as_int(opcode).filter(|o| (0..=0xFFFF).contains(o)).ok_or("Invalid movement opcode")? as u16;
            let body = unbinary(encoded, 44)?;
            decode_ground_movement(&body)?;
            if !is_movement_opcode(opcode as u32) {
                return Err("Not a movement opcode".into());
            }
            self.latest_movement = Some((opcode, body));
        }
        let controls = match get("controls") {
            None => &Vec::new(),
            Some(Value::Array(a)) => a,
            Some(_) => return Err("Invalid co-op controls".into()),
        };
        if controls.len() > 32 {
            return Err("Too many co-op controls".into());
        }
        for control in controls {
            let paused = control.get("paused").and_then(Value::as_bool).ok_or("Invalid co-op pause state")?;
            if !self.draining {
                self.paused = Some(paused);
            }
        }
        if truthy("restart") {
            self.restart_requested = true;
        }
        let packets = match get("packets") {
            None => &Vec::new(),
            Some(Value::Array(a)) => a,
            Some(_) => return Err("Invalid co-op packets".into()),
        };
        if packets.len() > MAX_QUEUE {
            return Err("Too many co-op packets".into());
        }
        for entry in packets {
            let [opcode, encoded] = entry.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 2]>::try_from(s).ok()).ok_or("Invalid co-op packet")?;
            let opcode = as_int(opcode).filter(|o| (0..=0xFFFF).contains(o)).ok_or("Unsupported peer combat packet")? as u16;
            if !(is_world(opcode) || is_movement_opcode(opcode as u32) || opcode == 0x96) {
                return Err("Unsupported peer combat packet".into());
            }
            let payload = unbinary(encoded, 1_048_576)?;
            reject_remote_marker_packet(opcode, &payload)?;
            let owner = if self.number == 1 { Some(self.other) } else { None };
            if is_movement_opcode(opcode as u32) {
                let members: Vec<u64> = self.members.iter().map(|m| *m as u64).collect();
                validate_movement_packet(&payload, &members, owner.map(|o| o as u64))?;
            }
            session.input.receive_summon_packet(opcode, &payload, owner)?;
            let payload = if self.number == 1 {
                // The host checks guest avatars before anyone renders them.
                let (kept, first) = session.input.sanitize_player_values(self.other, opcode, &payload)?;
                if first {
                    // logged once per peer: the avatar and the display it tried to set
                    let blocks = azcoop_world::objects(&payload, false, None)?;
                    let block = &blocks[0];
                    self.display_rejections.push((self.other, block.guid as i64 - 0xFF0100, block.fields.get(&azcoop_world::DISPLAY_ID).copied().unwrap_or(0)));
                }
                kept
            } else {
                Some(payload)
            };
            if let Some(payload) = payload {
                self.notice_packets.push((opcode, payload));
            }
        }
        if let Some(claim) = get("claim") {
            if !claim.is_null() {
                let expected: &[&str] = if self.number == 1 { &["reserved"] } else { &["removed", "refund", "collected"] };
                let status = claim.get("status").and_then(Value::as_str);
                if !status.map_or(false, |s| expected.contains(&s)) || !claim.get("guid").map_or(false, is_int) {
                    return Err("Invalid co-op loot claim".into());
                }
                for (key, maximum) in [("cost", MAX_COUNTER), ("range", 1000.0), ("multiplier", MAX_MULTIPLIER), ("xp_multiplier", MAX_MULTIPLIER)] {
                    finite(claim.get(key).ok_or("Invalid co-op loot claim")?, 0.0, maximum)?;
                }
            }
            let replace = !claim.is_null()
                || self.number == 1
                || self.chest_claim.as_ref().map_or(true, |c| c.get("status").and_then(Value::as_str) != Some("reserved"));
            if replace {
                self.chest_claim = if claim.is_null() { None } else { Some(claim.clone()) };
            }
        }
        if self.number == 1 {
            self.receive_for_host(message, session)?;
        } else {
            self.receive_for_guest(message)?;
        }
        if truthy("restart") {
            self.transitions += 1;
        }
        Ok(true)
    }

    /// `receive_boss_rewards(number, events)` for this guest.
    fn receive_boss_rewards(&mut self, events: Option<&Value>) -> Result<()> {
        let empty = Vec::new();
        let events = match events {
            None => &empty,
            Some(Value::Array(a)) => a,
            Some(_) => return Err("Invalid boss reward recipient or event count".into()),
        };
        if events.len() > MAX_QUEUE {
            return Err("Invalid boss reward recipient or event count".into());
        }
        for event in events {
            let object = event.as_object().ok_or("Invalid boss reward event")?;
            let ok_keys = object.len() == 3 && ["sequence", "map", "boss"].iter().all(|k| object.contains_key(*k));
            let (sequence, map, boss) = (as_int(&event["sequence"]), as_int(&event["map"]), as_int(&event["boss"]));
            // boss_rewards.GUARDIAN = -1: -1 <= boss < 5.
            let (Some(sequence), Some(map), Some(boss)) = (sequence, map, boss) else {
                return Err("Invalid boss reward event".into());
            };
            if !ok_keys || !(1..=0xFFFF_FFFF).contains(&sequence) || !(0..9).contains(&map) || !(-1..5).contains(&boss) {
                return Err("Invalid boss reward event".into());
            }
            let sequence = sequence as u64;
            if sequence <= self.boss_reward_seen {
                continue;
            }
            if sequence != self.boss_reward_seen + 1 {
                return Err("Out-of-order boss reward event".into());
            }
            if self.boss_reward_pending.len() >= MAX_QUEUE {
                return Err("Boss reward queue exceeds bound".into());
            }
            self.boss_reward_pending.push((sequence, map as u64, boss));
            self.boss_reward_seen = sequence;
        }
        Ok(())
    }

    fn receive_for_host(&mut self, message: &Value, session: &mut Session) -> Result<()> {
        let ack = match message.get("enemy_ack") {
            None => 0,
            Some(v) => as_int(v).filter(|a| *a >= 0).ok_or("Invalid enemy snapshot acknowledgement")? as u64,
        };
        let full = match message.get("enemy_full") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err("Invalid enemy snapshot acknowledgement".into()),
        };
        let ack = if self.resync { 0 } else { ack };
        if ack > self.enemy_sequence_sent {
            return Err("Invalid enemy snapshot acknowledgement".into());
        }
        self.enemy_acked = ack;
        if full {
            self.enemy_full_requested = true;
        }
        let received = message.get("world_received").and_then(as_int).filter(|r| *r >= 0).ok_or("Invalid co-op world acknowledgement")? as u64;
        if !(self.world_delivered <= received && received <= self.world_captured) {
            return Err("Invalid co-op world acknowledgement".into());
        }
        self.world_delivered = received;
        if let Some(auras) = message.get("auras") {
            let truthy = match auras {
                Value::Null | Value::Bool(false) => false,
                Value::Array(a) => !a.is_empty(),
                Value::Object(o) => !o.is_empty(),
                Value::String(t) => !t.is_empty(),
                Value::Number(n) => n.as_f64() != Some(0.0),
                Value::Bool(true) => true,
            };
            if !session.members.iter().filter(|m| **m != 1).any(|m| *m == self.other) {
                return Err("Guest auras from a non-guest".into());
            }
            if truthy {
                session.overlay.guest_auras(self.other, &validate_auras(auras)?);
            }
        }
        // Surrender broadcasts are accepted and ignored by this peer.
        if message.get("surrendered") == Some(&Value::Bool(true)) {
            self.surrendered = true;
        }
        let damage_list = match message.get("damage") {
            None => &[][..],
            Some(Value::Array(a)) => a.as_slice(),
            Some(_) => return Err("Invalid enemy damage".into()),
        };
        for entry in damage_list {
            let [guid, damage] = entry.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 2]>::try_from(s).ok()).ok_or("Invalid enemy damage")?;
            let guid = as_big(guid).ok_or("Invalid enemy identity")?;
            let damage = finite(damage, 0.0, MAX_ENEMY_DAMAGE)?;
            let total = self.damage_pending.get(&guid).copied().unwrap_or(0.0) + damage;
            if total > MAX_ENEMY_DAMAGE {
                return Err("Pending damage exceeds bound".into());
            }
            self.damage_pending.insert(guid, total);
        }
        let effects = match message.get("effects") {
            None => &[][..],
            Some(Value::Array(a)) => a.as_slice(),
            Some(_) => return Err("Invalid co-op effects".into()),
        };
        if effects.len() + self.effects_pending.len() > MAX_QUEUE {
            return Err("Too many co-op effects".into());
        }
        for entry in effects {
            let [guid, effect, spell] = entry.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 3]>::try_from(s).ok()).ok_or("Invalid co-op effect")?;
            let (guid, spell) = (as_big(guid).ok_or("Invalid co-op effect")?, as_int(spell).ok_or("Invalid co-op effect")?);
            self.effects_pending.push((guid, unbinary(effect, 12)?, spell));
        }
        Ok(())
    }

    fn receive_for_guest(&mut self, message: &Value) -> Result<()> {
        let need = |key: &str| message.get(key).ok_or_else(|| format!("Missing co-op field {key}"));
        self.host_clock = finite(need("clock")?, 0.0, MAX_CLOCK)?;
        if let Some(surrender) = message.get("surrender") {
            if surrender != &Value::Bool(true) {
                return Err("Invalid party surrender".into());
            }
            if !self.party_surrender {
                self.party_surrender = true;
                self.surrendered = true; // the host (the only possible sender) gave up for the party
            }
        }
        self.host_boss_hud = need("boss")?.clone();
        self.xp_pending += finite(need("xp")?, 0.0, MAX_COUNTER)?.trunc();
        self.gold_pending += finite(need("gold")?, 0.0, MAX_COUNTER)?.trunc();
        let mut lists: [&Vec<Value>; 2] = [&Vec::new(), &Vec::new()];
        for (i, (key, length)) in [("hits", 3usize), ("areas", 2)].into_iter().enumerate() {
            let list = need(key)?.as_array().filter(|l| l.len() <= MAX_QUEUE).ok_or("Invalid incoming hit batch")?;
            for hit in list {
                let fields = hit.as_array().filter(|h| h.len() == length).ok_or("Invalid co-op incoming hit")?;
                if !is_int(&fields[0]) {
                    return Err("Invalid co-op incoming hit".into());
                }
                finite(&fields[1], 0.0, MAX_HIT_DAMAGE)?;
                if key == "hits" {
                    finite(&fields[2], 0.0, MAX_CLOCK)?;
                }
            }
            lists[i] = list;
        }
        let (hits, areas) = (lists[0], lists[1]);
        let order: Vec<(String, f64)> = match message.get("hit_order") {
            None => areas
                .iter()
                .map(|_| ("areas".to_string(), self.host_clock))
                .chain(hits.iter().map(|h| ("hits".to_string(), h[2].as_f64().unwrap())))
                .collect(),
            Some(Value::Array(list)) => {
                let mut out = Vec::new();
                for entry in list {
                    let pair = entry.as_array().filter(|e| e.len() == 2).ok_or("Invalid incoming hit order")?;
                    let kind = pair[0].as_str().filter(|k| *k == "hits" || *k == "areas").ok_or("Invalid incoming hit order")?;
                    out.push((kind.to_string(), 0.0));
                    // The clock is validated below, after the index checks, like the Python.
                }
                if list.len() != hits.len() + areas.len() {
                    return Err("Invalid incoming hit order".into());
                }
                let mut at = (0usize, 0usize);
                for (entry, slot) in list.iter().zip(out.iter_mut()) {
                    let index = if slot.0 == "hits" { &mut at.0 } else { &mut at.1 };
                    if *index >= if slot.0 == "hits" { hits.len() } else { areas.len() } {
                        return Err("Repeated incoming hit index".into());
                    }
                    *index += 1;
                    slot.1 = finite(&entry[1], 0.0, MAX_CLOCK)?;
                }
                out
            }
            Some(_) => return Err("Invalid incoming hit order".into()),
        };
        if order.len() != hits.len() + areas.len() {
            return Err("Invalid incoming hit order".into());
        }
        let mut at = (0usize, 0usize);
        for (kind, clock) in order {
            let (list, index) = if kind == "hits" { (hits, &mut at.0) } else { (areas, &mut at.1) };
            let entry = list.get(*index).ok_or("Repeated incoming hit index")?;
            *index += 1;
            self.incoming.push(Hit {
                kind: if kind == "hits" { "hits" } else { "areas" },
                guid: as_big(&entry[0]).ok_or("Invalid co-op incoming hit")?,
                damage: entry[1].as_f64().unwrap(),
                clock: entry.get(2).and_then(Value::as_f64).unwrap_or(0.0),
                order_clock: clock,
            });
        }
        let mut full_list: Option<BTreeMap<u64, Enemy>> = None;
        if let Some(enemies) = message.get("enemies") {
            let list = enemies.as_array().filter(|e| e.len() <= MAX_ENEMIES).ok_or("Too many co-op enemies")?;
            if let Some(codec) = &self.codec {
                let mut snapshot = BTreeMap::new();
                for entry in list {
                    let [guid, encoded, hp, pose, boss] = entry.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 5]>::try_from(s).ok()).ok_or("Invalid co-op enemy snapshot")?;
                    let guid = as_big(guid).and_then(|g| u64::try_from(g).ok()).ok_or("Invalid enemy identity")?;
                    let flat = unbinary(encoded, codec.flat)?;
                    let boss = match boss {
                        Value::Null => None,
                        v => Some(as_big(v).and_then(|b| u64::try_from(b).ok()).ok_or("Invalid co-op boss definition")?),
                    };
                    codec.check(guid, &flat, boss)?;
                    let pose = pose.as_array().filter(|p| p.len() == 3).ok_or("Invalid co-op enemy snapshot")?;
                    let hp = finite(hp, 0.0, MAX_ENEMY_HP)?;
                    let pose = [finite(&pose[0], -100000.0, 100000.0)?, finite(&pose[1], -100000.0, 100000.0)?, finite(&pose[2], -100000.0, 100000.0)?];
                    snapshot.insert(guid, Enemy { flat, hp, pose, boss });
                }
                full_list = Some(snapshot);
            }
        }
        if let (Some(update), Some(codec)) = (message.get("enemy_update"), self.codec.clone()) {
            self.enemy_mirror.apply(&codec, update)?;
        }
        for entry in need("damage_done")?.as_array().ok_or("Invalid damage receipts")? {
            let [guid, done] = entry.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 2]>::try_from(s).ok()).ok_or("Invalid damage receipt")?;
            let guid = as_big(guid).ok_or("Invalid damage receipt")?;
            if is_int(done) && done.as_i64() == Some(0) || done.as_f64() == Some(0.0) && matches!(done, Value::Number(_)) {
                self.damage_acked.remove(&guid);
                if self.damage_sent.get(&guid).copied().unwrap_or(0.0) == 0.0 && !self.damage_pending.contains_key(&guid) {
                    self.damage_sent.remove(&guid);
                }
                continue;
            }
            let previous = self.damage_acked.get(&guid).copied().unwrap_or(0.0);
            let total = finite(done, previous, MAX_DAMAGE_TOTAL)?;
            if is_int(done) && total.abs() > 9_007_199_254_740_992.0 {
                return Err("Damage receipt is not exactly representable".into()); // fail closed: the receipt is an f64 here
            }
            let delta = total - previous;
            if delta != 0.0 {
                let pending = (self.damage_pending.get(&guid).copied().unwrap_or(0.0) - delta).max(0.0);
                let sent = (self.damage_sent.get(&guid).copied().unwrap_or(0.0) - delta).max(0.0);
                if pending == 0.0 {
                    self.damage_pending.remove(&guid);
                    if sent == 0.0 {
                        self.damage_sent.remove(&guid);
                    } else {
                        self.damage_sent.insert(guid, sent);
                    }
                } else {
                    self.damage_pending.insert(guid, pending);
                    self.damage_sent.insert(guid, sent);
                }
                self.damage_acked.insert(guid, total);
            }
        }
        if let Some(snapshot) = full_list {
            self.enemy_mirror.snapshot = snapshot;
        }
        if let Some(chests) = message.get("chests") {
            let list = chests.as_array().filter(|c| c.len() <= MAX_NATIVE_OBJECTS).ok_or("Too many co-op loot objects")?;
            let mut map = BTreeMap::new();
            for entry in list {
                let [guid, value] = entry.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 2]>::try_from(s).ok()).ok_or("Invalid co-op loot object")?;
                let value = value.as_array().ok_or("Invalid co-op loot object")?;
                map.insert(as_big(guid).ok_or("Invalid co-op loot object")?, value.clone());
            }
            self.chests = map;
        }
        if let Some(update) = message.get("chest_update") {
            let entries = update.get("set").and_then(Value::as_array);
            let no_drop = Vec::new();
            let drop = update.get("drop").map_or(Some(&no_drop), Value::as_array);
            let (Some(Value::Bool(full)), Some(entries), Some(drop)) = (update.get("full"), entries, drop) else {
                return Err("Invalid co-op loot update".into());
            };
            if entries.len() + drop.len() > 2 * MAX_NATIVE_OBJECTS {
                return Err("Invalid co-op loot update".into());
            }
            let mut chests = if *full { BTreeMap::new() } else { self.chests.clone() };
            for guid in drop {
                chests.remove(&as_big(guid).ok_or("Invalid co-op loot object")?);
            }
            for entry in entries {
                let [guid, value] = entry.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 2]>::try_from(s).ok()).ok_or("Invalid co-op loot object")?;
                let value = value.as_array().ok_or("Invalid co-op loot object")?;
                chests.insert(as_big(guid).ok_or("Invalid co-op loot object")?, value.clone());
            }
            if chests.len() > MAX_NATIVE_OBJECTS {
                return Err("Too many co-op loot objects".into());
            }
            self.chests = chests;
        }
        for entry in need("world")?.as_array().ok_or("Invalid co-op world")? {
            let [opcode, encoded] = entry.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 2]>::try_from(s).ok()).ok_or("Invalid co-op world packet")?;
            let opcode = as_int(opcode).filter(|o| (0..=0xFFFF).contains(o) && is_world(*o as u16)).ok_or("Unsupported co-op world packet")? as u16;
            let body = unbinary(encoded, 1_048_576)?;
            self.world_bytes += body.len() + 4;
            self.world_pending.push((opcode, body));
            self.world_captured_count += 1;
        }
        if self.world_bytes > MAX_RENDER_BACKLOG {
            return Err("Co-op renderer fell behind".into());
        }
        Ok(())
    }
}
