//! The peer layer of the bridge: `OnlineBridge.receive_state` and `GroupOnlineBridge.receive_peer`
//! applied to the bridge's own state.
//!
//! `azcoop_state::{peer::Peer, group::Group}` validate a message and keep what it says in a
//! self-contained model (differentially tested on a stub bridge). Here that model is bound to the real
//! bridge: the fields the Python mutated in place are loaded into the model before a message, the model
//! receives, and what changed is stored back, together with the effects the Python had on the router, the
//! hit queues, the player lists and the log. A message that fails validation changes nothing (the model is
//! transactional); the Python had changed state up to the failing field and ended the session.

use crate::bridge::Bridge;
use crate::client::{Client, Result};
use crate::io::GameIo;
use crate::regs::Regs;
use azcoop_logic::chests::Claim;
use azcoop_logic::hits::{Hit, Kind};
use azcoop_logic::Event;
use azcoop_state::group::Group;
use azcoop_world::session::decode_ground_movement;
use azcoop_world::DESTROY;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// What `GroupOnlineBridge` adds to the bridge: the group model with one peer per remote player.
pub struct Online {
    /// This side's player number (1 = host).
    pub number: u32,
    pub group: Group,
    /// The claim last published to / received from each peer (`claims_sent`).
    pub claims_sent: BTreeMap<u32, Option<Claim>>,
    /// Pause decisions made here that the peers have not heard of yet (`controls`).
    pub controls: Vec<Value>,
    /// Messages produced while receiving (a refund answer), to be sent with the next round.
    pub outbox: Vec<(u32, Value)>,
    /// `last_network`: the bridge clock of the last send round.
    pub last_network: f64,
    /// Send-side bookkeeping per peer (receipts, enemy encoders, loot baselines, cadence).
    pub outgoing: crate::online_send::Outgoing,
    /// Peers whose link is down inside the grace window (Step 3), with the bridge clock when it went down.
    pub away: BTreeMap<u32, f64>,
}

impl Online {
    pub fn new(number: u32, members: Vec<u32>) -> Online {
        Online { number, group: Group::new(number, members), claims_sent: BTreeMap::new(), controls: Vec::new(), outbox: Vec::new(), last_network: 0.0, outgoing: Default::default(), away: BTreeMap::new() }
    }
}

/// Python truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => false,
        Value::Bool(true) => true,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// A claim as the Python dict (numbers only; `player` absent = player 2).
pub fn claim_from_value(value: &Value) -> Option<Claim> {
    let f = |key: &str| value.get(key).and_then(Value::as_f64);
    Some(Claim {
        guid: value.get("guid").and_then(|g| g.as_i64().map(i128::from).or_else(|| g.as_u64().map(i128::from)))?,
        player: value.get("player").and_then(Value::as_u64).map(|p| p as u32),
        cost: f("cost")?,
        status: value.get("status")?.as_str()?.to_string(),
        range: f("range")?,
        multiplier: f("multiplier")?,
        xp_multiplier: f("xp_multiplier")?,
    })
}

pub fn claim_to_value(claim: &Claim) -> Value {
    let mut map = serde_json::Map::new();
    // GUIDs are u64 and mostly above i64::MAX: an `as i64` cast wrapped them negative, the host then found no loot object
    // for the claim (`u64::try_from` failed) and refunded every claim of the guest.
    let guid = match u64::try_from(claim.guid) {
        Ok(guid) => json!(guid),
        Err(_) => json!(claim.guid as i64),
    };
    map.insert("guid".into(), guid);
    if let Some(p) = claim.player {
        map.insert("player".into(), json!(p));
    }
    map.insert("cost".into(), json!(claim.cost));
    map.insert("status".into(), json!(claim.status));
    map.insert("range".into(), json!(claim.range));
    map.insert("multiplier".into(), json!(claim.multiplier));
    map.insert("xp_multiplier".into(), json!(claim.xp_multiplier));
    Value::Object(map)
}

impl Bridge {
    /// Turns this bridge into one end of a peer group: `number` is the player this process runs.
    pub fn go_online(&mut self, number: u32, image_size: u64) {
        let mut online = Online::new(number, self.room.members.clone());
        for peer in online.group.peers.values_mut() {
            peer.codec = Some(azcoop_state::enemies::Codec::new(self.build.variant, image_size));
        }
        if number != 1 {
            self.raid_assignments.clear(); // a guest receives the icons from the host
        }
        self.online = Some(online);
    }

    /// `GroupOnlineBridge.receive_peer(peer, message)`.
    pub fn receive_peer(&mut self, client: &mut dyn Client, peer: u32, message: &Value) -> Result<()> {
        let mut online = self.online.take().ok_or("the bridge is not online")?;
        let result = self.receive_with(client, peer, message, &mut online);
        self.online = Some(online);
        result
    }

    /// `connection_ended` for a peer that said goodbye or whose link broke.
    pub fn connection_ended(&mut self, client: &mut dyn Client, online: &mut Online, peer: u32, reason: &str) -> Result<()> {
        if online.number == 1 {
            self.remove_guest(client, online, peer, reason)
        } else {
            online.group.peer_finished = true;
            self.room.stop_requested = true;
            self.stop_requested = true;
            let after_run = self.run_finished_here(online.number);
            client.record(Event::new("host_departed").text("reason", reason).num("after_run", after_run as u8 as f64));
            Ok(())
        }
    }

    /// `run_finished_here()`: this player's run is over.
    pub fn run_finished_here(&self, number: u32) -> bool {
        self.room.native_states.get(&number).map_or(0, |s| s[0]) == 5
            || self.room.completed_players.contains(&number)
            || self.room.team_defeat.contains(&number)
            || self.room.party_surrender
    }

    fn receive_with(&mut self, client: &mut dyn Client, peer_number: u32, message: &Value, online: &mut Online) -> Result<()> {
        let number = online.number;
        if message.get("kind").and_then(Value::as_str) == Some("goodbye") {
            if online.group.departed.contains(&peer_number) {
                return Err("Message from a departed player".into());
            }
            return self.connection_ended(client, online, peer_number, "left");
        }
        // ---- load: the bridge state the message is validated against and added to
        let group = &mut online.group;
        group.draining = self.room.draining;
        group.damage_pending = self.mirrors.damage_pending.keys().into_iter().map(|g| (g as i128, *self.mirrors.damage_pending.get(g).unwrap())).collect();
        group.effects_pending = self.mirrors.effects_pending.iter().map(|(g, e, s)| (*g as i128, e.clone(), *s as i64)).collect();
        group.chest_claim = self.economy.chest_claim.as_ref().map(claim_to_value);
        group.end_action = self.room.end_action.map(|(sequence, command)| json!({"sequence": sequence, "command": command}));
        if let Some(command) = self.room.end_pending.get(&number) {
            group.end_pending.insert(number, *command as i64);
        } else {
            group.end_pending.remove(&number);
        }
        group.notice.clear();
        group.completed.clear();
        group.outbox.clear();
        group.removed.clear();
        group.world_delivered_total = self.counts.get("world_delivered").copied().unwrap_or(0);
        let claim_before = self.economy.chest_claim.clone();
        let members = group.members.clone();
        // what the bridge already knows of the other guests (the model checks the party against it)
        if number != 1 {
            for guest in group.guests.clone() {
                if guest == number {
                    continue;
                }
                let member = group.party.entry(guest).or_default();
                member.template = self.wire.templates.iter().find(|(n, _)| *n == guest).map(|(_, t)| t.clone());
                member.name_response = self.wire.name_responses.get(&guest).cloned();
            }
        }
        if let Some(peer) = group.peers.get_mut(&peer_number) {
            peer.members = members;
            peer.draining = self.room.draining;
            peer.boss_reward_sequence = self.boss_reward_sequence;
            peer.boss_reward_applied = self.boss_reward_applied.get(&peer_number).copied().unwrap_or(0);
            peer.boss_reward_seen = self.boss_reward_seen.get(&number).copied().unwrap_or(0);
            peer.boss_reward_pending = self.boss_reward_pending.get(&number).map(|v| v.iter().map(|e| (e.sequence, e.map as u64, e.boss)).collect()).unwrap_or_default();
            if number != 1 {
                // the guest's own damage in flight (the group lends the room-wide maps only to the host's peers)
                peer.damage_pending = self.mirrors.damage_pending.keys().into_iter().map(|g| (g as i128, *self.mirrors.damage_pending.get(g).unwrap())).collect();
                peer.world_delivered = self.counts.get("world_delivered").copied().unwrap_or(0);
                peer.world_captured = self.counts.get("world_captured").copied().unwrap_or(0);
            }
            peer.powerups_pending = self.powerups_pending.get(&number).map(|v| v.iter().map(|k| *k as u8).collect()).unwrap_or_default();
            peer.xp_pending = (if number == 2 { self.economy.xp_pending } else { self.economy.xp_queues.get(&number).copied().unwrap_or(0) }) as f64;
            peer.gold_pending = (if number == 2 { self.economy.gold_pending } else { self.economy.gold_by_guest.get(&number).copied().unwrap_or(0) }) as f64;
            peer.host_clock = self.room.host_clock;
            peer.party_surrender = self.room.party_surrender;
            peer.raid_assignments = self.raid_assignments.iter().map(|(n, i)| (*n, *i)).collect();
            // the host world packets not yet rendered wait in this player's feed, where the batch rebuild takes them
            peer.world_pending = self.wire.feeds.get(&number).map(|f| f.world_pending.clone()).unwrap_or_default();
            peer.world_bytes = self.world.world_bytes;
            peer.world_captured_count = peer.world_captured;
            peer.display_rejections.clear();
            peer.incoming.clear();
            peer.notice_packets.clear();
            peer.paused = None;
            peer.transitions = 0;
            peer.template = self.wire.templates.iter().find(|(n, _)| *n == peer_number).map(|(_, t)| t.clone());
            peer.name_response = self.wire.name_responses.get(&peer_number).cloned();
            peer.created = self.registered.contains(&peer_number).then(|| self.wire.feeds.get(&peer_number).map(|f| f.created.clone()).unwrap_or_default());
        }
        let before_party = self.room.party_surrender;
        let before_template = group.peers.get(&peer_number).is_some_and(|p| p.template.is_some());
        let runs_before = group.next_runs.len();
        let acks_before = group.next_run_acks.contains(&peer_number);
        group.controls.clear();
        let before_party_templates: Vec<u32> = group.party.iter().filter(|(_, m)| m.template.is_some()).map(|(n, _)| *n).collect();

        // the room's checks (movement owners, summons, displays, guest auras) run on the bridge's own state
        self.sync_guest_input();
        std::mem::swap(&mut self.input, &mut online.group.session.input);
        std::mem::swap(&mut self.overlay, &mut online.group.session.overlay);
        let received = online.group.receive(peer_number, message);
        std::mem::swap(&mut self.input, &mut online.group.session.input);
        std::mem::swap(&mut self.overlay, &mut online.group.session.overlay);
        received?;

        // ---- store: what the message changed
        let group = &mut online.group;
        if number != 1 {
            self.host_map = group.host_map.clone(); // the zone the host confirmed
        }
        if number != 1 && message.get("next_run").is_some() && peer_number != 1 {
            client.record(Event::new("next_run_rejected").num("player", number as f64).num("sender", peer_number as f64));
        }
        for offer in group.next_runs[runs_before..].to_vec() {
            client.record(Event::new("next_run_invited").num("player", number as f64).text("room", offer["room"].as_str().unwrap_or("")));
        }
        if number == 1 && !acks_before && group.next_run_acks.contains(&peer_number) {
            let room = group.next_run_offer.as_ref().and_then(|o| o["room"].as_str()).unwrap_or("").to_string();
            client.record(Event::new("next_run_confirmed").num("player", peer_number as f64).text("room", &room));
        }
        online.controls.extend(std::mem::take(&mut group.controls));
        let removed = std::mem::take(&mut group.removed);
        // a closing host starts this guest's drain (the Python sets `draining` with `host_closing`, in this message only)
        if group.number != 1 && message.get("closing") == Some(&Value::Bool(true)) {
            self.room.draining = true;
        }
        for (recipient, packets) in std::mem::take(&mut group.notice) {
            if !packets.is_empty() {
                self.wire.feeds.entry(recipient).or_default().notice_packets.extend(packets);
            }
        }
        online.outbox.extend(std::mem::take(&mut group.outbox));
        self.room.end_action = group.end_action.as_ref().and_then(|a| Some((a.get("sequence")?.as_u64()?, a.get("command")?.as_u64()? as u32)));
        match group.end_pending.get(&number) {
            Some(command) => {
                self.room.end_pending.insert(number, *command as u32);
            }
            None => {
                self.room.end_pending.remove(&number);
            }
        }
        self.economy.chest_claim = group.chest_claim.as_ref().and_then(claim_from_value);
        let completed = std::mem::take(&mut group.completed);

        if let Some(peer) = group.peers.get(&peer_number) {
            self.room.stop_requested |= peer.stop_requested;
            self.stop_requested |= peer.stop_requested;
            let sanitized: Vec<_> = peer.display_rejections.clone();
            if let Some(name) = &peer.name_response {
                if self.wire.name_responses.get(&peer_number) != Some(name) {
                    let text = azcoop_world::builders::character_name(name)?;
                    client.record(Event::new("character_name_registered").num("player", peer_number as f64).text("name", &text).text("body", &name.iter().map(|b| format!("{b:02x}")).collect::<String>()));
                }
                self.wire.name_responses.insert(peer_number, name.clone());
            }
            self.economy.xp_multipliers.insert(peer_number, peer.xp_multiplier);
            if let (Some(template), Some(pose)) = (&peer.template, peer.template_pose) {
                if !before_template {
                    if self.wire.poses.contains_key(&peer_number) {
                        return Err("Player ID must be unique and owned by an account".into());
                    }
                    self.wire.templates.push((peer_number, template.clone()));
                    self.registered.insert(peer_number);
                    self.wire.feeds.entry(peer_number).or_default().created.clear();
                    self.wire.poses.insert(peer_number, pose);
                }
            }
            for (player, avatar, display) in &sanitized {
                client.record(Event::new("guest_display_rejected").num("player", *player as f64).num("avatar", *avatar as f64).num("display", *display as f64));
            }
            // the model keeps what earlier messages said; the bridge applies only what this one says
            if message.get("ready") == Some(&Value::Bool(true)) {
                self.room.ready.insert(peer_number);
            }
            if message.get("loaded") == Some(&Value::Bool(true)) {
                self.loaded.insert(peer_number);
            }
            if let (Some(state), true) = (peer.native_state, message.get("state").is_some_and(|s| !s.is_null())) {
                self.room.native_states.insert(peer_number, state);
            }
            if let (Some(created), true) = (&peer.created, self.registered.contains(&peer_number)) {
                self.wire.feeds.entry(peer_number).or_default().created = created.clone();
            }
            if let Some((opcode, body)) = &peer.latest_movement {
                if message.get("movement").is_some() && self.wire.templates.iter().any(|(n, _)| *n == peer_number) {
                    let pose = decode_ground_movement(body)?;
                    self.wire.poses.insert(peer_number, [pose.x as f64, pose.y as f64, pose.z as f64, pose.facing as f64]);
                    self.latest_movement.insert(peer_number, (*opcode as u32, body.clone()));
                }
            }
            if let Some(paused) = peer.paused {
                self.room.paused = paused;
                self.room.pause_pending.insert(number, paused);
            }
            if message.get("restart").is_some_and(truthy) {
                self.restart_requested = true;
                // a guest does not echo a restart it received from the host back to it
                self.remote_restart = number != 1;
            }
            // the raid icons the host assigned (`raid_assignments = assignments`; a changed icon was rejected by the model)
            if number != 1 && message.get("raid_assignments").is_some() {
                self.raid_assignments = peer.raid_assignments.iter().map(|(n, i)| (*n, *i)).collect();
            }
            self.powerups_pending.insert(number, peer.powerups_pending.iter().map(|k| *k as u64).collect());
            if number != 1 {
                self.boss_reward_seen.insert(number, peer.boss_reward_seen);
                self.boss_reward_pending.insert(
                    number,
                    peer.boss_reward_pending.iter().map(|(sequence, map, boss)| crate::before_batch::RewardEvent { sequence: *sequence, map: *map as u32, boss: *boss }).collect(),
                );
            }
            if number == 1 {
                self.boss_reward_applied.insert(peer_number, peer.boss_reward_applied);
                let acknowledged = self.boss_reward_applied.values().copied().min().unwrap_or(0);
                self.boss_reward_events.retain(|e| e.sequence > acknowledged);
                // the Python adds in message order; the model's map is sorted
                for entry in message.get("damage").and_then(Value::as_array).into_iter().flatten() {
                    let guid = entry[0].as_u64().unwrap_or(0);
                    let total = self.mirrors.damage_pending.get(guid).copied().unwrap_or(0.0) + entry[1].as_f64().unwrap_or(0.0);
                    self.mirrors.damage_pending.set(guid, total);
                }
                if group.effects_pending.iter().any(|(g, _, s)| *g < 0 || *s < 0) {
                    return Err("Invalid co-op effect".into());
                }
                self.mirrors.effects_pending = group.effects_pending.iter().map(|(g, e, s)| (*g as u64, e.clone(), *s as u32)).collect();
                if message.get("surrender").is_some() && self.surrender_rejected.insert(peer_number) {
                    client.record(Event::new("surrender_broadcast_rejected").num("player", peer_number as f64));
                }
                if message.get("surrendered") == Some(&Value::Bool(true)) && self.room.surrendered.insert(peer_number) {
                    client.record(Event::new("guest_surrendered").num("player", peer_number as f64));
                }
                self.counts.insert("world_delivered", group.world_delivered_total);
            } else {
                self.room.host_clock = peer.host_clock;
                if peer.party_surrender && !before_party {
                    self.room.party_surrender = true;
                    self.room.surrendered.insert(1);
                    client.record(Event::new("party_surrender_received").num("player", number as f64));
                }
                self.host_boss_hud = match &peer.host_boss_hud {
                    Value::Null => None,
                    other => Some(other.clone()),
                };
                if number == 2 {
                    self.economy.xp_pending = peer.xp_pending as i128;
                    self.economy.gold_pending = peer.gold_pending as i128;
                } else {
                    self.economy.xp_queues.insert(number, peer.xp_pending as i128);
                    self.economy.gold_by_guest.insert(number, peer.gold_pending as i128);
                }
                for guid in self.mirrors.damage_pending.keys() {
                    match peer.damage_pending.get(&(guid as i128)) {
                        None => {
                            self.mirrors.damage_pending.remove(guid);
                        }
                        Some(value) if self.mirrors.damage_pending.get(guid) != Some(value) => self.mirrors.damage_pending.set(guid, *value),
                        Some(_) => {}
                    }
                }
                self.wire.feeds.entry(number).or_default().world_pending = peer.world_pending.clone();
                self.world.world_bytes = peer.world_bytes;
                self.counts.insert("world_captured", peer.world_captured_count);
                self.economy.chests = peer
                    .chests
                    .iter()
                    .filter_map(|(guid, value)| {
                        // [slot, [x, y, z], kind, value]
                        let position = value.get(1)?.as_array().filter(|p| p.len() == 3)?;
                        Some((*guid as u64, azcoop_logic::chests::Chest {
                            index: value.first()?.as_u64()?,
                            position: [position[0].as_f64()?, position[1].as_f64()?, position[2].as_f64()?],
                            kind: value.get(2)?.as_u64()? as u32,
                            value: value.get(3)?.as_u64()? as u32,
                        }))
                    })
                    .collect();
                if message.get("enemies").is_some() || message.get("enemy_update").is_some() {
                    online.outgoing.sync.note_snapshot(self.now);
                    let entries = peer.enemy_mirror.snapshot.iter().map(|(guid, e)| (*guid, azcoop_logic::mirrors::Snap { flat: e.flat.clone(), hp: e.hp, pose: e.pose })).collect();
                    let bosses = peer.enemy_mirror.snapshot.iter().filter_map(|(guid, e)| e.boss.map(|b| (*guid, b))).collect();
                    self.mirrors.set_host_snapshot_at(entries, bosses, self.now);
                }
            }
        }
        // hits queued for the local game
        let hits = group.peers.get_mut(&peer_number).map(|p| std::mem::take(&mut p.incoming)).unwrap_or_default();
        if !hits.is_empty() {
            self.refresh();
            for hit in hits {
                let kind = if hit.kind == "hits" { Kind::Hits } else { Kind::Areas };
                let queued = Hit { attacker: hit.guid, damage: hit.damage, clock: (kind == Kind::Hits).then_some(hit.clock) };
                let mut io_regs = Regs::default();
                let mut io = GameIo::new(client, &mut io_regs, &self.build.fields, &mut self.results);
                self.hits.queue_incoming_hit(&mut io, number, kind, queued, Some(hit.order_clock), self.now);
            }
        }
        // the claim history per peer (the room-wide claim itself was stored above)
        match message.get("kind").and_then(Value::as_str) {
            Some("claim_refund") => {
                online.claims_sent.insert(peer_number, self.economy.chest_claim.clone());
            }
            _ => {
                if let Some(claim) = message.get("claim") {
                    let kept = !(number == 1 && claim_before.as_ref().is_some_and(|c| c.player() != peer_number));
                    let replaced = kept && (!claim.is_null() || number == 1 || claim_before.as_ref().map_or(true, |c| c.status != "reserved"));
                    if replaced {
                        online.claims_sent.insert(peer_number, claim_from_value(claim));
                    }
                }
            }
        }
        // the other guests the host publishes (guest side)
        if number != 1 {
            // only the members this message names (the model keeps what earlier messages said)
            let named: Vec<u32> = message.get("party").and_then(Value::as_object).map(|p| p.keys().filter_map(|k| k.parse().ok()).collect()).unwrap_or_default();
            let party: Vec<(u32, azcoop_state::group::PartyMember)> = online.group.party.iter().filter(|(n, _)| named.contains(n)).map(|(n, m)| (*n, m.clone())).collect();
            for (member, entry) in party {
                // the model keeps what earlier messages said; only what THIS message says is applied
                let said = message.get("party").and_then(|p| p.get(member.to_string())).cloned().unwrap_or(Value::Null);
                let says = |key: &str| said.get(key).is_some_and(|v| !v.is_null());
                if let Some(name) = entry.name_response.as_ref().filter(|_| says("name_response")) {
                    if self.wire.name_responses.get(&member) != Some(name) {
                        let text = azcoop_world::builders::character_name(name)?;
                        client.record(Event::new("character_name_registered").num("player", member as f64).text("name", &text).text("body", &name.iter().map(|b| format!("{b:02x}")).collect::<String>()));
                    }
                    self.wire.name_responses.insert(member, name.clone());
                }
                if let Some(template) = &entry.template {
                    if !before_party_templates.contains(&member) && !self.wire.templates.iter().any(|(n, _)| *n == member) {
                        if self.wire.poses.contains_key(&member) {
                            return Err("Player ID must be unique and owned by an account".into());
                        }
                        let pose: [f64; 4] = std::array::from_fn(|i| f32::from_le_bytes(template[20 + 4 * i..24 + 4 * i].try_into().unwrap()) as f64);
                        self.wire.templates.push((member, template.clone()));
                        self.registered.insert(member);
                        self.wire.feeds.entry(member).or_default().created.clear();
                        self.wire.poses.insert(member, pose);
                    }
                }
                if let Some(state) = entry.state.filter(|_| says("state")) {
                    self.room.native_states.insert(member, state);
                }
                if entry.ready && said.get("ready").is_some_and(truthy) {
                    self.room.ready.insert(member);
                }
                if entry.loaded && said.get("loaded").is_some_and(truthy) {
                    self.loaded.insert(member);
                }
                if let Some((opcode, body)) = entry.movement.as_ref().filter(|_| said.get("movement").is_some_and(truthy)) {
                    let pose = decode_ground_movement(body)?;
                    self.wire.poses.insert(member, [pose.x as f64, pose.y as f64, pose.z as f64, pose.facing as f64]);
                    self.latest_movement.insert(member, (*opcode as u32, body.clone()));
                }
            }
        }
        // transitions the message requested (play again)
        for (who, command) in completed {
            self.refresh();
            let mut io_regs = Regs::default();
            self.completed_transition(client, &mut io_regs, who, command, None);
        }
        for member in removed {
            self.remove_guest(client, online, member, "left")?;
        }
        Ok(())
    }

    /// `GroupOnlineBridge.remove_guest(number, reason)`: the player leaves the room.
    pub fn remove_guest(&mut self, client: &mut dyn Client, online: &mut Online, number: u32, reason: &str) -> Result<()> {
        if self.departed.contains(&number) {
            return Ok(());
        }
        if !self.room.guests.contains(&number) || number == online.number {
            return Err("Invalid departing guest".into());
        }
        {
            self.refresh();
            let mut io_regs = Regs::default();
            let mut io = GameIo::new(client, &mut io_regs, &self.build.fields, &mut self.results);
            self.hits.clear_incoming_hits(&mut io, number, "player_departed", self.now);
        }
        let pending_world = self.wire.feeds.get(&number).map_or(0, |f| f.world_pending.len()) as u64;
        self.departed.insert(number);
        online.group.quiesced_peers.remove(&number);
        online.group.departed.insert(number);
        self.wire.name_responses.remove(&number);
        for feed in self.wire.feeds.values_mut() {
            feed.name_queries.remove(&number);
        }
        online.group.enemy_acked.remove(&number);
        online.group.enemy_sequences.remove(&number);
        online.group.enemy_full_requested.remove(&number);
        online.group.party.remove(&number);
        self.room.members.retain(|n| *n != number);
        self.room.guests.remove(&number);
        self.raid_assignments.remove(&number);
        online.group.members.retain(|n| *n != number);
        online.group.guests.retain(|n| *n != number);
        for peer in online.group.peers.values_mut() {
            peer.members.retain(|n| *n != number);
        }
        // everyone who had created the departed player removes it
        let recipients: Vec<u32> = self.room.members.clone();
        for recipient in &recipients {
            let had = self.wire.feeds.get(recipient).is_some_and(|f| f.created.contains(&number));
            if had {
                self.wire.feeds.entry(*recipient).or_default().notice_packets.push((DESTROY, (0xFF0100 + number as u64).to_le_bytes().to_vec()));
            }
        }
        for feed in self.wire.feeds.values_mut() {
            feed.created.remove(&number);
        }
        let mut summons: Vec<u64> = self.input.summons.remove(&number).map(|s| s.into_iter().collect()).unwrap_or_default();
        summons.sort();
        for guid in summons {
            for recipient in &recipients {
                self.wire.feeds.entry(*recipient).or_default().notice_packets.push((DESTROY, guid.to_le_bytes().to_vec()));
            }
        }
        self.guest.maps.remove(&number);
        self.overlay.drop_player(number);
        self.wire.poses.remove(&number);
        self.wire.templates.retain(|(n, _)| *n != number);
        self.registered.remove(&number);
        self.room.native_states.remove(&number);
        self.latest_movement.remove(&number);
        if let Some(feed) = self.wire.feeds.get_mut(&number) {
            feed.world_pending.clear();
            feed.attack_packets.clear();
            feed.hurt_packets.clear();
            feed.notice_packets.clear();
            feed.created.clear();
        }
        self.room.revive_progress.remove(&number);
        self.room.revive_status.remove(&number);
        self.room.pause_pending.remove(&number);
        self.room.end_pending.remove(&number);
        self.hit_work_turn.remove(&number);
        self.boss_reward_applied.remove(&number);
        self.economy.gold_by_guest.remove(&number);
        for set in [&mut self.room.ready, &mut self.loaded, &mut self.room.downed, &mut self.economy.talent_paused, &mut self.room.team_defeat, &mut self.menu_players] {
            set.remove(&number);
        }
        for kind in [Kind::Hits, Kind::Areas] {
            if let Some(queue) = self.hits.queues.get_mut(&(number, kind)) {
                queue.clear();
            }
            self.hits.metadata.remove(&(number, kind));
        }
        self.economy.xp_queues.insert(number, 0);
        if number == 2 {
            self.economy.xp_pending = 0;
            self.economy.gold_pending = 0;
        }
        if self.economy.chest_claim.as_ref().is_some_and(|c| c.player() == number) {
            self.economy.chest_claim = None;
        }
        if online.number == 1 {
            // unacknowledged work for a departed recipient cannot be delivered
            let sent = online.group.world_sent.get(&number).copied().unwrap_or(0);
            let acked = online.group.world_acked.get(&number).copied().unwrap_or(0);
            *self.counts.entry("world_abandoned").or_insert(0) += sent.saturating_sub(acked) + pending_world;
            let acknowledged = self.boss_reward_applied.values().copied().min().unwrap_or(self.boss_reward_sequence);
            self.boss_reward_events.retain(|e| e.sequence > acknowledged);
        }
        self.room.paused = self.room.draining;
        let draining = self.room.draining;
        for member in self.room.members.clone() {
            self.room.pause_pending.insert(member, draining);
        }
        online.controls = if draining { Vec::new() } else { vec![json!({"paused": false})] };
        online.last_network = 0.0;
        client.record(Event::new("guest_departed").num("player", number as f64).text("reason", reason));
        Ok(())
    }
}

#[cfg(test)]
mod claim_tests {
    use super::*;

    fn claim(guid: i128) -> Claim {
        Claim { guid, player: Some(2), cost: 0.0, status: "reserved".into(), range: 9.0, multiplier: 1.2, xp_multiplier: 1.1 }
    }

    #[test]
    fn a_guid_above_i64_max_survives_the_wire() {
        for guid in [17379391113034467000i128, u64::MAX as i128, i64::MAX as i128 + 1, 0, 1, 5000] {
            let wire = serde_json::to_string(&claim_to_value(&claim(guid))).unwrap();
            let back = claim_from_value(&serde_json::from_str(&wire).unwrap()).unwrap();
            assert_eq!(back.guid, guid, "{wire}");
        }
    }

    #[test]
    fn a_negative_guid_still_round_trips() {
        let wire = serde_json::to_string(&claim_to_value(&claim(-5))).unwrap();
        assert_eq!(claim_from_value(&serde_json::from_str(&wire).unwrap()).unwrap().guid, -5);
    }
}
