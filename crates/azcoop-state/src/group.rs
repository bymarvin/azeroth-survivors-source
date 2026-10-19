//! The group layer of real rooms: `GroupOnlineBridge.receive_peer` (both roles) on top of
//! [`Peer`]. Hosts and guests of a room exchange the base state message plus these fields:
//! `next_run` / `next_run_seen`, `quiesced`, `enemy_ack` / `enemy_full`, `forwarded`
//! (guest-to-guest packets relayed by the host), `departed`, `host_map`, `host_action`,
//! `party` (the other guests' identities), `claim_refund`.
//!
//! A [`Group`] owns the session-wide state the Python keeps on the bridge (shared queues,
//! the single chest claim, pending damage, who has left) and one [`Peer`] per remote player.
//! State that is global in the Python (pending damage and effects, the loot claim, the pause
//! request) is lent to the peer for each message and taken back afterwards.

use crate::peer::{Peer, Session};
use crate::{as_big, as_int, unbinary, Result};
use azcoop_world::builders::{clone_player, reject_remote_marker_packet};
use azcoop_world::filter::set_name_response;
use azcoop_world::is_world;
use azcoop_world::session::{is_movement_opcode, validate_movement_packet};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Packet = (u16, Vec<u8>);

pub const ZONES: [&str; 12] = ["elwynn", "duskwood", "wsg", "ungoro", "ab", "feralas", "arena", "sm", "av", "brm", "aq", "naxx"];

/// What the guest learns about another guest from the host's `party` field.
#[derive(Debug, Clone, Default)]
pub struct PartyMember {
    pub template: Option<Vec<u8>>,
    pub name_response: Option<Vec<u8>>,
    pub state: Option<[u64; 4]>,
    pub ready: bool,
    pub loaded: bool,
    pub movement: Option<Packet>,
}

pub struct Group {
    /// This side's number (1 = host).
    pub number: u32,
    pub members: Vec<u32>,
    pub guests: Vec<u32>,
    pub departed: BTreeSet<u32>,
    pub peers: BTreeMap<u32, Peer>,
    pub session: Session,
    pub draining: bool,
    /// Packets to show in each player's local game, in arrival order.
    pub notice: BTreeMap<u32, Vec<Packet>>,
    // --- host
    pub enemy_sequences: BTreeMap<u32, u64>,
    pub enemy_acked: BTreeMap<u32, u64>,
    pub enemy_full_requested: BTreeSet<u32>,
    /// Host: guests whose link came back and have not asked for a full enemy snapshot yet: their acknowledgements still
    /// refer to the old link's sequence numbers and are ignored (not an error) until the guest's `enemy_full` arrives.
    pub resync: BTreeSet<u32>,
    pub quiesced_peers: BTreeSet<u32>,
    pub world_sent: BTreeMap<u32, u64>,
    pub world_acked: BTreeMap<u32, u64>,
    /// `counts['world_delivered']` of the host: the sum of what every guest acknowledged.
    pub world_delivered_total: u64,
    /// Templates of other guests already sent to each guest (`party_templates_sent`).
    pub party_templates_sent: BTreeMap<u32, BTreeSet<u32>>,
    pub controls: Vec<Value>,
    pub chest_claim: Option<Value>,
    pub damage_pending: BTreeMap<i128, f64>,
    pub effects_pending: Vec<(i128, Vec<u8>, i64)>,
    pub damage_owners: BTreeMap<i128, BTreeMap<u32, f64>>,
    pub next_run_offer: Option<Value>,
    pub next_run_acks: BTreeSet<u32>,
    pub removed: Vec<u32>,
    /// Messages queued for a peer by the receive path (a refund reply to a claim).
    pub outbox: Vec<(u32, Value)>,
    // --- guest
    pub next_run_received: Option<Value>,
    pub next_runs: Vec<Value>,
    pub host_closing: bool,
    pub host_map: Option<String>,
    pub end_action: Option<Value>,
    pub end_pending: BTreeMap<u32, i64>,
    pub party: BTreeMap<u32, PartyMember>,
    /// `completed_transition(number, command)` calls, in order.
    pub completed: Vec<(u32, u32)>,
    pub peer_finished: bool,
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

fn next_room_ok(room: &str) -> bool {
    (1..=64).contains(&room.len()) && room.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn next_invite_ok(invite: &str) -> bool {
    (1..=128).contains(&invite.len()) && invite.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'~' | b'-'))
}

impl Group {
    pub fn new(number: u32, members: Vec<u32>) -> Group {
        let guests: Vec<u32> = members.iter().copied().filter(|m| *m != 1).collect();
        let others: Vec<u32> = if number == 1 { guests.clone() } else { vec![1] };
        let peers = others.iter().map(|o| (*o, Peer::new(number, *o, members.clone()))).collect();
        Group {
            number,
            session: Session::new(members.clone()),
            members,
            guests,
            departed: BTreeSet::new(),
            peers,
            draining: false,
            notice: BTreeMap::new(),
            enemy_sequences: BTreeMap::new(),
            enemy_acked: BTreeMap::new(),
            enemy_full_requested: BTreeSet::new(),
            resync: BTreeSet::new(),
            quiesced_peers: BTreeSet::new(),
            world_sent: BTreeMap::new(),
            world_acked: BTreeMap::new(),
            world_delivered_total: 0,
            party_templates_sent: BTreeMap::new(),
            controls: Vec::new(),
            chest_claim: None,
            damage_pending: BTreeMap::new(),
            effects_pending: Vec::new(),
            damage_owners: BTreeMap::new(),
            next_run_offer: None,
            next_run_acks: BTreeSet::new(),
            removed: Vec::new(),
            outbox: Vec::new(),
            next_run_received: None,
            next_runs: Vec::new(),
            host_closing: false,
            host_map: None,
            end_action: None,
            end_pending: BTreeMap::new(),
            party: BTreeMap::new(),
            completed: Vec::new(),
            peer_finished: false,
        }
    }

    /// `remove_guest(number)`: the player leaves the room (idempotent).
    pub fn remove_guest(&mut self, number: u32) -> Result<()> {
        self.removed.push(number);
        if self.departed.contains(&number) {
            return Ok(());
        }
        if !self.guests.contains(&number) || number == self.number {
            return Err("Invalid departing guest".into());
        }
        self.departed.insert(number);
        self.quiesced_peers.remove(&number);
        // The peer record stays for inspection; `receive` refuses anything from a departed player.
        self.members.retain(|n| *n != number);
        self.guests.retain(|n| *n != number);
        for peer in self.peers.values_mut() {
            peer.members.retain(|n| *n != number);
        }
        self.session.members.retain(|n| *n != number);
        self.session.input.guests.retain(|n| *n != number);
        Ok(())
    }

    /// `receive_next_run(peer, message)`.
    fn receive_next_run(&mut self, peer: u32, message: &Map<String, Value>) -> Result<()> {
        if self.number != 1 && message.contains_key("next_run") {
            if peer != 1 {
                return Ok(()); // only the host invites
            }
            let offer = &message["next_run"];
            let valid = offer.as_object().is_some_and(|o| {
                o.len() == 2 && o.get("room").and_then(Value::as_str).is_some_and(next_room_ok) && o.get("invite").and_then(Value::as_str).is_some_and(next_invite_ok)
            });
            if !valid {
                return Err("Invalid next-run invitation".into());
            }
            if self.next_run_received.as_ref() != Some(offer) {
                self.next_run_received = Some(offer.clone());
                self.next_runs.push(offer.clone());
            }
        } else if self.number == 1 && message.contains_key("next_run_seen") {
            if let Some(offer) = &self.next_run_offer {
                if message["next_run_seen"] == offer["room"] && !self.next_run_acks.contains(&peer) {
                    self.next_run_acks.insert(peer);
                }
            }
        }
        Ok(())
    }

    /// `receive_peer(peer, message)`.
    pub fn receive(&mut self, peer: u32, message: &Value) -> Result<()> {
        if self.departed.contains(&peer) {
            return Err("Message from a departed player".into());
        }
        let object = message.as_object().ok_or("Unknown co-op message")?;
        if object.get("kind").and_then(Value::as_str) == Some("goodbye") {
            if self.number == 1 {
                return self.remove_guest(peer);
            }
            self.peer_finished = true;
            if let Some(p) = self.peers.get_mut(&peer) {
                p.peer_finished = true;
                p.stop_requested = true;
            }
            return Ok(());
        }
        self.receive_next_run(peer, object)?;
        if let Some(closing) = object.get("closing") {
            if !closing.is_boolean() {
                return Err("Invalid closing state".into());
            }
        }
        let closing = object.get("closing") == Some(&Value::Bool(true));
        let quiesced = match object.get("quiesced") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err("Invalid drain quiescence acknowledgement".into()),
        };
        if quiesced && !closing {
            return Err("Invalid drain quiescence acknowledgement".into());
        }
        let leaving = self.number == 1 && closing && !self.draining;
        let mut message = object.clone();
        if closing {
            if self.number != 1 {
                self.host_closing = true;
                self.draining = true;
            }
            message.insert("closing".into(), json!(false));
        }
        if self.number == 1 {
            if let Some(Value::Array(created)) = message.get("created").cloned() {
                let kept: Vec<Value> = created.into_iter().filter(|n| !as_int(n).is_some_and(|n| self.departed.contains(&(n as u32)))).collect();
                message.insert("created".into(), Value::Array(kept));
            }
        }
        let mut departed_now: Vec<u32> = Vec::new();
        let outcome = self.receive_body(peer, &mut message, quiesced, &mut departed_now);
        // `finally`: the host's delivered counter is the sum over all guests again.
        if self.number == 1 {
            self.world_delivered_total = self.world_acked.values().sum();
        }
        outcome?;
        if leaving {
            self.remove_guest(peer)?;
        }
        for number in departed_now {
            self.remove_guest(number)?;
        }
        Ok(())
    }

    fn receive_body(&mut self, peer: u32, message: &mut Map<String, Value>, quiesced: bool, departed_now: &mut Vec<u32>) -> Result<()> {
        if self.number == 1 {
            if message.contains_key("party") {
                return Err("Only the host can publish the party".into());
            }
            let ack = match message.get("enemy_ack") {
                None => 0,
                Some(v) => as_int(v).filter(|a| *a >= 0).ok_or("Invalid enemy snapshot acknowledgement")? as u64,
            };
            let full = match message.get("enemy_full") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return Err("Invalid enemy snapshot acknowledgement".into()),
            };
            let ack = if self.resync.contains(&peer) { 0 } else { ack };
            if ack > self.enemy_sequences.get(&peer).copied().unwrap_or(0) {
                return Err("Invalid enemy snapshot acknowledgement".into());
            }
            self.enemy_acked.insert(peer, ack);
            if full {
                self.enemy_full_requested.insert(peer);
                self.resync.remove(&peer);
            }
            let claim = message.get("claim").cloned().unwrap_or(Value::Null);
            if !claim.is_null() {
                let player = claim.as_object().ok_or("Invalid co-op loot claim")?.get("player").map_or(Some(2), |p| as_int(p));
                if player != Some(peer as i64) {
                    return Err("Loot claim belongs to another player".into());
                }
            }
            if let Some(held) = &self.chest_claim {
                let holder = held.get("player").map_or(Some(2), as_int);
                if holder != Some(peer as i64) {
                    if truthy(message.get("claim")) {
                        let mut refund = message["claim"].clone();
                        refund["status"] = json!("refund");
                        self.outbox.push((peer, json!({"kind": "claim_refund", "claim": refund})));
                    }
                    message.remove("claim");
                }
            }
            let known = self.peers.contains_key(&peer);
            if !known {
                return Err("Unknown peer".into());
            }
            // Lend the room-wide state to the peer for this message.
            let world_sent = self.world_sent.get(&peer).copied().unwrap_or(0);
            let world_acked = self.world_acked.get(&peer).copied().unwrap_or(0);
            let before = self.damage_pending.clone();
            let (outcome, notices, paused, restart, controls) = {
                let p = self.peers.get_mut(&peer).unwrap();
                p.draining = self.draining;
                p.world_captured = world_sent;
                p.world_delivered = world_acked;
                p.enemy_sequence_sent = self.enemy_sequences.get(&peer).copied().unwrap_or(0);
                p.resync = self.resync.contains(&peer) && !message.get("enemy_full").is_some_and(|f| f == &Value::Bool(true));
                p.damage_pending = std::mem::take(&mut self.damage_pending);
                p.effects_pending = std::mem::take(&mut self.effects_pending);
                p.chest_claim = self.chest_claim.take();
                p.notice_packets.clear();
                let value = Value::Object(message.clone());
                let outcome = p.receive(&value, &mut self.session);
                self.damage_pending = std::mem::take(&mut p.damage_pending);
                self.effects_pending = std::mem::take(&mut p.effects_pending);
                self.chest_claim = p.chest_claim.take();
                (outcome, std::mem::take(&mut p.notice_packets), p.paused, p.restart_requested, message.get("controls").cloned())
            };
            let _ = (paused, restart);
            outcome?;
            self.notice.entry(1).or_default().extend(notices);
            if quiesced {
                self.quiesced_peers.insert(peer);
            } else {
                self.quiesced_peers.remove(&peer);
            }
            self.world_acked.insert(peer, self.peers[&peer].world_delivered);
            for (guid, amount) in &self.damage_pending {
                let delta = amount - before.get(guid).copied().unwrap_or(0.0);
                if delta > 0.0 {
                    *self.damage_owners.entry(*guid).or_default().entry(peer).or_insert(0.0) += delta;
                }
            }
            if !self.draining {
                if let Some(Value::Array(c)) = controls {
                    self.controls.extend(c);
                }
            }
            if let Some(forwarded) = message.get("forwarded") {
                let map = forwarded.as_object().ok_or("Invalid peer packet recipient")?;
                for (recipient, packets) in map {
                    let recipient: u32 = recipient.parse().map_err(|_| "Invalid peer packet recipient".to_string())?;
                    if self.departed.contains(&recipient) {
                        continue; // an already in-flight packet may name a departed peer
                    }
                    let list = packets.as_array().ok_or("Invalid peer packet recipient")?;
                    if !self.guests.contains(&recipient) || recipient == peer || list.len() > crate::limits::MAX_QUEUE {
                        return Err("Invalid peer packet recipient".into());
                    }
                    for entry in list {
                        let [opcode, encoded] = entry.as_array().map(Vec::as_slice).and_then(|s| <&[Value; 2]>::try_from(s).ok()).ok_or("Unsupported peer packet")?;
                        let opcode = as_int(opcode).filter(|o| (0..=0xFFFF).contains(o)).ok_or("Unsupported peer packet")? as u16;
                        if !(is_world(opcode) || is_movement_opcode(opcode as u32) || opcode == 0x96) {
                            return Err("Unsupported peer packet".into());
                        }
                        let payload = unbinary(encoded, 1_048_576)?;
                        reject_remote_marker_packet(opcode, &payload)?;
                        if is_movement_opcode(opcode as u32) {
                            let members: Vec<u64> = self.members.iter().map(|m| *m as u64).collect();
                            validate_movement_packet(&payload, &members, Some(peer as u64))?;
                        }
                        self.session.input.receive_summon_packet(opcode, &payload, Some(peer))?;
                        if let Some(payload) = self.session.input.sanitize_player_values(peer, opcode, &payload)?.0 {
                            self.notice.entry(recipient).or_default().push((opcode, payload));
                        }
                    }
                }
            }
            return Ok(());
        }

        // ---- guest
        if message.get("kind").and_then(Value::as_str) == Some("claim_refund") {
            let claim = message.get("claim").ok_or("Invalid claim refund")?;
            let held = self.chest_claim.as_ref().ok_or("Unexpected chest refund")?;
            if claim.get("guid") != held.get("guid") {
                return Err("Unexpected chest refund".into());
            }
            self.chest_claim.as_mut().unwrap()["status"] = json!("refund");
            return Ok(());
        }
        let outcome = {
            let p = self.peers.get_mut(&peer).ok_or("Unknown peer")?;
            p.draining = self.draining;
            p.chest_claim = self.chest_claim.take();
            p.notice_packets.clear();
            let value = Value::Object(message.clone());
            let outcome = p.receive(&value, &mut self.session);
            self.chest_claim = p.chest_claim.take();
            (outcome, std::mem::take(&mut p.notice_packets))
        };
        outcome.0?;
        self.notice.entry(self.number).or_default().extend(outcome.1);
        // departed
        let departed = match message.get("departed") {
            None => Vec::new(),
            Some(Value::Array(a)) => a.clone(),
            Some(_) => return Err("Invalid departed party members".into()),
        };
        if departed.len() > 3 {
            return Err("Invalid departed party members".into());
        }
        let mut numbers = Vec::new();
        for n in &departed {
            let n = as_int(n).filter(|n| (self.guests.contains(&(*n as u32)) || self.departed.contains(&(*n as u32))) && *n != self.number as i64).ok_or("Invalid departed party members")?;
            numbers.push(n as u32);
        }
        departed_now.extend(numbers);
        if let Some(zone) = message.get("host_map") {
            if !zone.is_null() {
                let name = zone.as_str().filter(|z| ZONES.contains(z)).ok_or("Invalid or changed host map")?;
                if self.host_map.as_deref().is_some_and(|m| m != name) {
                    return Err("Invalid or changed host map".into());
                }
                self.host_map = Some(name.to_string());
            }
        }
        if let Some(action) = message.get("host_action") {
            if !action.is_null() {
                let sequence = action.get("sequence").and_then(as_int);
                let command = action.get("command").and_then(as_int);
                if !sequence.is_some_and(|s| (1..=1i64 << 53).contains(&s)) || !matches!(command, Some(8) | Some(9)) {
                    return Err("Invalid host victory action".into());
                }
                let newer = self.end_action.as_ref().map_or(true, |a| sequence.unwrap() > a["sequence"].as_i64().unwrap_or(0));
                if newer {
                    self.end_action = Some(action.clone());
                    self.end_pending.insert(self.number, command.unwrap());
                }
            }
        }
        if let Some(party) = message.get("party") {
            let entries = party.as_object().ok_or("Invalid party member")?;
            for (raw, entry) in entries {
                let number: u32 = raw.parse().map_err(|_| "Invalid party member".to_string())?;
                if !self.guests.contains(&number) || number == self.number {
                    return Err("Invalid party member".into());
                }
                let entry = entry.as_object().ok_or("Invalid party member")?;
                let member = self.party.entry(number).or_default();
                if let Some(name) = entry.get("name_response").filter(|v| !v.is_null()) {
                    let body = unbinary(name, 128)?;
                    if let Some(registered) = set_name_response(&self.members, number, member.name_response.as_deref(), &body)? {
                        member.name_response = Some(registered);
                    }
                }
                if member.template.is_none() {
                    let template = entry.get("template").filter(|v| !v.is_null()).ok_or("Party member template missing")?;
                    let body = unbinary(template, 1_048_576)?;
                    if body.len() < 36 {
                        return Err("Short co-op character template".into());
                    }
                    let pose: [f64; 4] = std::array::from_fn(|i| f32::from_le_bytes(body[20 + 4 * i..24 + 4 * i].try_into().unwrap()) as f64);
                    clone_player(&body, 0xFF0100 + number as u64, pose)?;
                    member.template = Some(body);
                }
                if let Some(state) = entry.get("state").filter(|v| !v.is_null()) {
                    let list = state.as_array().filter(|s| s.len() == 4).ok_or("Invalid party state")?;
                    let mut values = [0u64; 4];
                    for (slot, value) in values.iter_mut().zip(list) {
                        *slot = as_big(value).filter(|v| (0..=crate::limits::MAX_COUNTER as i128).contains(v)).ok_or("Invalid party state")? as u64;
                    }
                    if values[0] > 5 {
                        return Err("Invalid party state".into());
                    }
                    member.state = Some(values);
                }
                for key in ["ready", "loaded"] {
                    match entry.get(key) {
                        Some(Value::Bool(set)) => {
                            if *set {
                                if key == "ready" { member.ready = true } else { member.loaded = true }
                            }
                        }
                        _ => return Err("Invalid party readiness".into()),
                    }
                }
                if truthy(entry.get("movement")) {
                    let pair = entry["movement"].as_array().filter(|m| m.len() == 2).ok_or("Invalid party movement")?;
                    let opcode = as_int(&pair[0]).filter(|o| (0..=0xFFFF).contains(o)).ok_or("Invalid party movement")? as u16;
                    let body = unbinary(&pair[1], 44)?;
                    if !is_movement_opcode(opcode as u32) {
                        return Err("Not a movement opcode".into());
                    }
                    azcoop_world::session::decode_ground_movement(&body)?;
                    member.movement = Some((opcode, body));
                }
            }
        }
        if truthy(message.get("restart")) {
            self.completed.push((self.number, 6));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sending: `GroupOnlineBridge.decorate`

impl Group {
    /// Host: the group fields added to the base state message for `peer`.
    /// `world_len` is the number of world packets in that message.
    pub fn decorate_host(&mut self, peer: u32, message: &mut Map<String, Value>, world_len: u64) {
        message.insert("departed".into(), json!(self.departed.iter().copied().collect::<Vec<_>>()));
        if let Some(offer) = &self.next_run_offer {
            message.insert("next_run".into(), offer.clone());
        }
        message.insert("host_action".into(), self.end_action.clone().unwrap_or(Value::Null));
        message.insert("host_map".into(), self.host_map.as_ref().map_or(Value::Null, |m| json!(m)));
        *self.world_sent.entry(peer).or_insert(0) += world_len;
        let mut party = Map::new();
        let numbers: Vec<u32> = self.members.iter().copied().filter(|n| *n != 1 && *n != peer).collect();
        let sent = self.party_templates_sent.entry(peer).or_default();
        for n in numbers {
            let Some(p) = self.peers.get(&n) else { continue };
            let Some(template) = &p.template else { continue };
            let mut entry = Map::new();
            entry.insert("name_response".into(), p.name_response.as_ref().map_or(Value::Null, |b| crate::binary(b)));
            entry.insert("state".into(), p.native_state.map_or(Value::Null, |s| json!(s)));
            entry.insert("ready".into(), json!(p.ready));
            entry.insert("loaded".into(), json!(p.loaded));
            entry.insert("movement".into(), p.latest_movement.as_ref().map_or(Value::Null, |(op, body)| json!([op, crate::binary(body)])));
            // Templates never change; the ordered channel delivers each once.
            if !sent.contains(&n) {
                entry.insert("template".into(), crate::binary(template));
                sent.insert(n);
            }
            party.insert(n.to_string(), Value::Object(entry));
        }
        message.insert("party".into(), Value::Object(party));
        if let Some(claim) = &self.chest_claim {
            if claim.get("player").map_or(Some(2), as_int) != Some(peer as i64) {
                message.remove("claim");
            }
        }
    }

    /// Guest: the group fields added to the base state message. `forward` holds the attack, hurt
    /// and notice packets queued for the other guests (they are taken); `quiesced` is the drain
    /// acknowledgement computed from the game state; `enemy_ack` / `enemy_full` come from the enemy mirror.
    pub fn decorate_guest(&mut self, message: &mut Map<String, Value>, quiesced: bool, forward: &mut BTreeMap<u32, Vec<Packet>>, enemy_ack: u64, enemy_full: bool) {
        if let Some(offer) = &self.next_run_received {
            message.insert("next_run_seen".into(), offer["room"].clone());
        }
        message.insert("quiesced".into(), json!(self.draining && quiesced));
        let mut forwarded = Map::new();
        for recipient in self.guests.clone() {
            if recipient == self.number {
                continue;
            }
            let packets = forward.remove(&recipient).unwrap_or_default();
            forwarded.insert(recipient.to_string(), Value::Array(packets.iter().map(|(op, body)| json!([op, crate::binary(body)])).collect()));
        }
        message.insert("forwarded".into(), Value::Object(forwarded));
        message.insert("enemy_ack".into(), json!(enemy_ack));
        if enemy_full {
            message.insert("enemy_full".into(), json!(true));
        }
    }
}
