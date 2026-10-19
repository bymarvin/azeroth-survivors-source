//! The send side of the peer layer: `GroupOnlineBridge.poll_network` (the send round),
//! `OnlineBridge.send_state`, `decorate` and `thin_snapshot`.
//!
//! The pieces that encode (state message, group fields, enemy deltas, receipts, loot deltas) are the
//! differentially tested ones of `azcoop-state`; this module collects their inputs from the bridge,
//! in the order the Python does, and performs the side effects of sending (queues cleared, claim and
//! template bookkeeping).

use crate::bridge::Bridge;
use crate::client::{Client, Result};
use crate::io::GameIo;
use crate::online::{claim_to_value, Online};
use crate::regs::Regs;
use azcoop_logic::hits::Kind;
use azcoop_logic::Event;
use azcoop_state::build::{state_message, Common, GuestPart, HostPart, Role};
use azcoop_state::enemies::{Enemy, EnemyEncoder};
use azcoop_state::producers::{ChestSync, ReceiptBook};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// `poll_network`: a send round every 40 ms (or at once for a restart request).
pub const SEND_INTERVAL: f64 = 0.04;
/// `ENEMY_SNAPSHOT_INTERVAL`: seconds between enemy updates per guest (10 Hz).
pub const ENEMY_INTERVAL: f64 = 0.1;
/// `RECEIPT_PRUNE_SECONDS`
pub const RECEIPT_PRUNE_SECONDS: f64 = 10.0;

/// Host-side bookkeeping per guest that the send round owns.
#[derive(Default)]
pub struct Outgoing {
    pub receipts: BTreeMap<u32, ReceiptBook>,
    pub encoders: BTreeMap<u32, EnemyEncoder>,
    pub chest_sync: BTreeMap<u32, ChestSync>,
    pub snapshot_due: BTreeMap<u32, f64>,
    pub size_report_due: BTreeMap<u32, f64>,
    pub template_sent: BTreeSet<u32>,
    pub receipts_prune_due: f64,
    /// The enemy-sync figure (read-only, see `sync_stats`).
    pub sync: crate::sync_stats::SyncState,
}

/// A GUID as a JSON integer (the u64 range included).
fn guid_value(guid: i128) -> Value {
    if let Ok(v) = u64::try_from(guid) {
        json!(v)
    } else {
        json!(i64::try_from(guid).unwrap_or(0))
    }
}

fn number_value(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9.0e15 {
        json!(value as i64)
    } else {
        json!(value)
    }
}

/// What the peer links brought since the last round, in arrival order.
#[derive(Clone, Debug, PartialEq)]
pub enum NetEvent {
    /// A message of player `.0`.
    Message(u32, Value),
    /// The link to player `.0` ended (`ConnectionError`/`TimeoutError` in the Python's words).
    Lost(u32, String),
    /// The link to player `.0` went down but its slot stays open for a grace window (Step 3).
    Down(u32),
    /// The link to player `.0` is back: generation `.1` (Step 3).
    Up(u32, u64),
}

impl Bridge {
    /// `OnlineBridge.__call__`: the network is served before and after the hook.
    pub fn on_hook_online(&mut self, client: &mut dyn Client, hook: crate::client::Hook, regs: &mut Regs, inbox: &[(u32, Value)]) -> Result<Vec<(u32, Value)>> {
        let events: Vec<NetEvent> = inbox.iter().map(|(p, m)| NetEvent::Message(*p, m.clone())).collect();
        self.on_hook_events(client, hook, regs, &events)
    }

    /// [`Bridge::on_hook_online`] with link losses among the events.
    pub fn on_hook_events(&mut self, client: &mut dyn Client, hook: crate::client::Hook, regs: &mut Regs, events: &[NetEvent]) -> Result<Vec<(u32, Value)>> {
        // `Channel.drain` returns the queued messages and raises only once the queue is empty, so a loss that arrives
        // together with messages of that player is noticed by the poll after the hook.
        let mut now: Vec<NetEvent> = Vec::new();
        let mut later: Vec<NetEvent> = Vec::new();
        for event in events {
            match event {
                NetEvent::Lost(peer, _) | NetEvent::Down(peer) if now.iter().any(|e| matches!(e, NetEvent::Message(p, _) if p == peer)) => later.push(event.clone()),
                _ => now.push(event.clone()),
            }
        }
        let mut out = self.poll_events(client, &now)?;
        self.on_hook(client, hook, regs)?;
        out.extend(self.poll_events(client, &later)?);
        Ok(out)
    }

    /// `poll_network`: the messages `inbox` brought are applied, then the send round runs when due.
    /// Returns what goes out, per peer.
    pub fn poll_network(&mut self, client: &mut dyn Client, inbox: &[(u32, Value)]) -> Result<Vec<(u32, Value)>> {
        let events: Vec<NetEvent> = inbox.iter().map(|(p, m)| NetEvent::Message(*p, m.clone())).collect();
        self.poll_events(client, &events)
    }

    /// The host (or, on the host, every guest) is gone: the network is finished (`peer_finished`).
    pub fn peer_finished(&self) -> bool {
        self.online.as_ref().is_some_and(|o| o.group.peer_finished)
    }

    /// `connection_ended(peer, error)` for a link that broke (no-op for a player that already left).
    pub fn peer_lost(&mut self, client: &mut dyn Client, peer: u32, reason: &str) -> Result<()> {
        let mut online = self.online.take().ok_or("the bridge is not online")?;
        let known = online.group.peers.contains_key(&peer) && !online.group.departed.contains(&peer);
        let result = if known { self.connection_ended(client, &mut online, peer, reason) } else { Ok(()) };
        self.online = Some(online);
        result
    }

    /// `poll_network` over arrival-ordered events.
    pub fn poll_events(&mut self, client: &mut dyn Client, inbox: &[NetEvent]) -> Result<Vec<(u32, Value)>> {
        let mut online = self.online.take().ok_or("the bridge is not online")?;
        let mut out = Vec::new();
        let result = (|| -> Result<()> {
            if online.group.peer_finished {
                return Ok(());
            }
            self.online = Some(std::mem::replace(&mut online, Online::new(0, vec![])));
            for event in inbox {
                let before = self.online.as_ref().unwrap().group.peer_finished;
                match event {
                    NetEvent::Message(peer, message) => self.receive_peer(client, *peer, message)?,
                    NetEvent::Lost(peer, reason) => self.peer_lost(client, *peer, reason)?,
                    NetEvent::Down(peer) => self.peer_down(client, *peer)?,
                    NetEvent::Up(peer, epoch) => self.peer_up(client, *peer, *epoch)?,
                }
                let after = self.online.as_ref().unwrap().group.peer_finished;
                if after && !before {
                    break;
                }
            }
            online = self.online.take().unwrap();
            if online.group.peer_finished {
                return Ok(());
            }
            out = self.send_round(client, &mut online)?;
            Ok(())
        })();
        if self.online.is_none() {
            self.online = Some(online);
        }
        result.map(|()| out)
    }

    fn send_round(&mut self, client: &mut dyn Client, online: &mut Online) -> Result<Vec<(u32, Value)>> {
        let now = self.now;
        let mut out: Vec<(u32, Value)> = std::mem::take(&mut online.outbox);
        if online.number == 1 {
            online.group.host_map = self.host_map.clone(); // `PartyMenu.host_map`, published in every host message
        }
        if !(now - online.last_network >= SEND_INTERVAL || self.restart_requested) {
            return Ok(out);
        }
        let controls = online.controls.clone();
        let peers: Vec<u32> = online.group.peers.keys().copied().filter(|p| !online.group.departed.contains(p)).collect();
        for peer in peers {
            if online.away.contains_key(&peer) {
                self.drop_queued_for(peer); // nobody reads it: the queues must not grow while the link is down
                continue;
            }
            online.controls = controls.clone();
            let message = self.send_state(client, online, peer)?;
            out.push((peer, message));
        }
        online.controls = Vec::new();
        online.last_network = now;
        Ok(out)
    }

    /// `OnlineBridge.send_state` plus the group's `decorate` and, on the host, `thin_snapshot`, for one peer.
    fn send_state(&mut self, client: &mut dyn Client, online: &mut Online, peer: u32) -> Result<Value> {
        let n = online.number;
        let now = self.now;
        // the guest whose queues this message serves (`_select_guest`)
        let served = if n == 1 { peer } else { n };
        self.refresh();
        let draining = self.room.draining;
        online.group.draining = draining;
        let claim_sent = online.claims_sent.get(&peer).cloned().flatten();
        let mut common = Common {
            ready: self.room.ready.contains(&n),
            loaded: self.loaded.contains(&n),
            state: self.room.native_states.get(&n).copied(),
            created: self.wire.feeds.get(&n).map(|f| f.created.iter().copied().collect()).unwrap_or_default(),
            controls: Vec::new(),
            restart: self.restart_requested && !self.remote_restart,
            xp_multiplier: self.economy.xp_multipliers.get(&n).copied().unwrap_or(1.0),
            closing: draining,
            name_response: self.wire.name_responses.get(&n).cloned(),
            template: None,
            movement: None,
            packets: Vec::new(),
            claim: None,
            world_received: if n != 1 { self.counts.get("world_delivered").copied().unwrap_or(0) } else { 0 },
        };
        let control_values: Vec<Value> = if draining { Vec::new() } else { online.controls.clone() };
        common.controls = control_values.iter().map(|c| c.get("paused").and_then(Value::as_bool).unwrap_or(false)).collect();
        if let Some((_, template)) = self.wire.templates.iter().find(|(m, _)| *m == n) {
            if !online.outgoing.template_sent.contains(&peer) {
                common.template = Some(template.clone());
            }
        }
        if let Some((opcode, body)) = self.latest_movement.get(&n) {
            common.movement = Some((*opcode as u16, body.clone()));
        }
        {
            let feed = self.wire.feeds.entry(peer).or_default();
            common.packets.extend(feed.attack_packets.drain(..));
            common.packets.extend(feed.hurt_packets.drain(..));
            common.packets.extend(feed.notice_packets.drain(..));
        }
        // Guests publish only requests (reserved) and completion (none); a local shutdown refund is not a host answer.
        let claim = self.economy.chest_claim.clone();
        let publish_claim = if n != 1 {
            claim.as_ref().map_or(true, |c| c.status == "reserved")
        } else {
            claim.as_ref().map_or(true, |c| c.player() == peer && c.status != "reserved")
        };
        let mut claim_after = claim_sent.clone();
        if publish_claim && claim != claim_sent {
            common.claim = Some(claim.as_ref().map(claim_to_value));
            claim_after = claim.clone();
        }
        let role;
        let mut enemy_view: Vec<(u64, Enemy)> = Vec::new();
        let mut chests_now: Vec<(i128, Value)> = Vec::new();
        let mut guest_auras: Option<Value> = None;
        if n == 1 {
            let mut order: Vec<(u64, &str, f64)> = Vec::new();
            for (kind, name) in [(Kind::Hits, "hits"), (Kind::Areas, "areas")] {
                for meta in self.hits.queued_hit_metadata(peer, kind, now).iter() {
                    order.push((meta.0, name, meta.2));
                }
            }
            order.sort_by(|a, b| a.0.cmp(&b.0));
            let powerups: Vec<u8> = self.powerups_pending.get(&peer).map(|v| v.iter().map(|k| *k as u8).collect()).unwrap_or_default();
            self.powerups_pending.insert(peer, Vec::new());
            let events: Vec<Value> = self.boss_reward_events.iter().map(|e| json!({"sequence": e.sequence, "map": e.map, "boss": e.boss})).collect();
            let queue = |kind: Kind| self.hits.queues.get(&(peer, kind)).cloned().unwrap_or_default();
            let hits: Vec<(i128, f64, f64)> = queue(Kind::Hits).iter().map(|h| (h.attacker, h.damage, h.clock.unwrap_or(0.0))).collect();
            let areas: Vec<(i128, f64)> = queue(Kind::Areas).iter().map(|h| (h.attacker, h.damage)).collect();
            let (xp, gold) = if peer == 2 {
                (self.economy.xp_pending, self.economy.gold_pending)
            } else {
                (self.economy.xp_queues.get(&peer).copied().unwrap_or(0), self.economy.gold_by_guest.get(&peer).copied().unwrap_or(0))
            };
            let world = self.wire.feeds.get(&peer).map(|f| f.world_pending.clone()).unwrap_or_default();
            // loot objects as the guests receive them: slot, position, kind, value
            chests_now = self
                .economy
                .chests
                .iter()
                .map(|(guid, c)| (*guid as i128, json!([c.index, [c.position[0], c.position[1], c.position[2]], c.kind, c.value])))
                .collect();
            if self.mirrors.snapshot_view(&mut GameIo::new(client, &mut Regs::default(), &self.build.fields, &mut self.results), now).is_ok() {
                enemy_view = self
                    .mirrors
                    .snapshot_entries()
                    .into_iter()
                    .map(|(guid, s)| (guid, Enemy { flat: s.flat, hp: s.hp, pose: s.pose, boss: self.mirrors.boss_definitions.get(&guid).copied() }))
                    .collect();
            }
            role = Role::Host(HostPart {
                hit_order: order.iter().map(|(_, kind, clock)| (kind.to_string(), *clock)).collect(),
                powerups,
                surrender: self.room.party_surrender,
                raid_assignments: self.raid_assignments.iter().map(|(k, v)| (*k, *v)).collect(),
                boss_rewards: events,
                clock: self.room.host_clock,
                boss: self.host_boss_hud.clone().unwrap_or(Value::Null),
                xp: xp.max(0) as u64,
                gold: gold.max(0) as u64,
                hits,
                areas,
                world,
                damage_done: Vec::new(),
                chests: Vec::new(),
                deltas: true,
                enemy_update: None,
                chest_update: None,
            });
        } else {
            let applied = self.boss_reward_applied.get(&n).copied().unwrap_or(0);
            let peer_state = online.group.peers.get(&peer);
            let sent = peer_state.map(|p| p.damage_sent.clone()).unwrap_or_default();
            let mut damage = Vec::new();
            let mut new_sent = sent.clone();
            for guid in self.mirrors.damage_pending.keys() {
                let pending = *self.mirrors.damage_pending.get(guid).unwrap();
                let delta = pending - sent.get(&(guid as i128)).copied().unwrap_or(0.0);
                if delta > 0.0 {
                    damage.push((guid as i128, delta));
                    new_sent.insert(guid as i128, pending);
                }
            }
            if let Some(p) = online.group.peers.get_mut(&peer) {
                p.damage_sent = new_sent;
            }
            let effects: Vec<(i128, Vec<u8>, i64)> = self.mirrors.effects_pending.iter().map(|(g, e, s)| (*g as i128, e.clone(), *s as i64)).collect();
            self.mirrors.effects_pending = Vec::new();
            if let Some(own) = self.own_auras.get_mut(&n) {
                let changes = own.take_changes(crate::bridge::MAX_ENEMIES);
                if !changes.is_empty() {
                    guest_auras = Some(Value::Array(
                        changes
                            .iter()
                            .map(|(guid, debuffs)| json!([guid, debuffs.iter().map(|a| json!([a[0], a[1], a[2], a[3]])).collect::<Vec<_>>()]))
                            .collect(),
                    ));
                }
            }
            self.note_aura_drops_public(client);
            role = Role::Guest(GuestPart {
                boss_reward_ack: applied,
                damage,
                effects,
                surrendered: self.room.self_surrendered,
                enemy_ack: None,
                enemy_full: false,
            });
        }
        let mut message = state_message(&common, &role);
        let map = message.as_object_mut().unwrap();
        // the controls travel as the Python's dicts
        map.insert("controls".into(), Value::Array(control_values));
        if let Some(auras) = guest_auras {
            map.insert("auras".into(), auras);
        }
        // ---- the group's decorate
        if n == 1 {
            let world_len = map.get("world").and_then(Value::as_array).map_or(0, Vec::len) as u64;
            online.group.chest_claim = self.economy.chest_claim.as_ref().map(claim_to_value);
            online.group.end_action = self.room.end_action.map(|(sequence, command)| json!({"sequence": sequence, "command": command}));
            // party entries come from the members the host knows
            sync_party_state(self, online);
            online.group.decorate_host(peer, map, world_len);
        } else {
            let quiesced = self.drain_quiesced(online, n) && !self.client_saved;
            let mut forward: BTreeMap<u32, Vec<(u16, Vec<u8>)>> = BTreeMap::new();
            for recipient in online.group.guests.clone() {
                if recipient == n {
                    continue;
                }
                let feed = self.wire.feeds.entry(recipient).or_default();
                let mut packets: Vec<(u16, Vec<u8>)> = Vec::new();
                packets.extend(feed.attack_packets.drain(..));
                packets.extend(feed.hurt_packets.drain(..));
                packets.extend(feed.notice_packets.drain(..));
                forward.insert(recipient, packets);
            }
            let (ack, full) = online.group.peers.get(&peer).map_or((0, false), |p| (p.enemy_mirror.seq, p.enemy_mirror.full_needed));
            online.group.decorate_guest(map, quiesced, &mut forward, ack, full);
        }
        // ---- thin_snapshot (host)
        if n == 1 {
            self.prune_receipts(online, now);
            let receipts = online.outgoing.receipts.entry(peer).or_default();
            let changes = receipts.take_changes();
            map.insert("damage_done".into(), Value::Array(changes.iter().map(|(g, v)| json!([guid_value(*g), number_value(*v)])).collect()));
            let due = online.outgoing.snapshot_due.get(&peer).copied().unwrap_or(0.0);
            if now >= due - 0.005 {
                online.outgoing.snapshot_due.insert(peer, (due + ENEMY_INTERVAL).max(now));
                let image_size = self.mirrors.image_size;
                let variant = self.build.variant;
                let encoder = online.outgoing.encoders.entry(peer).or_insert_with(|| EnemyEncoder::new(azcoop_state::enemies::Codec::new(variant, image_size)));
                encoder.full_requested |= online.group.enemy_full_requested.remove(&peer);
                let was_full = encoder.full_requested;
                if let Some(update) = encoder.update(&enemy_view, false)? {
                    let sequence = update["seq"].as_u64().unwrap_or(0);
                    online.group.enemy_sequences.insert(peer, sequence);
                    if update["base"].is_null() {
                        client.record(Event::new("enemy_full_snapshot").num("player", peer as f64).num("enemies", enemy_view.len() as f64).num("bytes", update["blob"].as_str().map_or(0, |b| b.len()) as f64));
                    }
                    let _ = was_full;
                    online.outgoing.sync.sent.insert(peer, (sequence, now, enemy_view.iter().map(|(guid, e)| (*guid, e.pose)).collect()));
                    map.insert("enemy_update".into(), update);
                }
            }
            let sync = online.outgoing.chest_sync.entry(peer).or_default();
            if let Some(update) = sync.update(&chests_now, false) {
                map.insert("chest_update".into(), update);
            }
            // sent: the queues the message served are emptied
            self.economy_clear_sent(peer);
        } else {
            map.remove("enemies");
        }
        online.claims_sent.insert(peer, claim_after);
        if self.wire.templates.iter().any(|(m, _)| *m == n) && map.contains_key("template") {
            online.outgoing.template_sent.insert(peer);
        }
        let _ = served;
        Ok(message)
    }

    /// The host's queues for `peer` after a message carried them (`send_state` host branch tail).
    fn economy_clear_sent(&mut self, peer: u32) {
        if peer == 2 {
            self.economy.xp_pending = 0;
            self.economy.gold_pending = 0;
        } else {
            self.economy.xp_queues.insert(peer, 0);
            self.economy.gold_by_guest.insert(peer, 0);
        }
        for kind in [Kind::Hits, Kind::Areas] {
            if let Some(q) = self.hits.queues.get_mut(&(peer, kind)) {
                q.clear();
            }
            self.hits.metadata.remove(&(peer, kind));
        }
        if let Some(feed) = self.wire.feeds.get_mut(&peer) {
            feed.world_pending.clear();
        }
        self.world.world_bytes = 0;
    }

    /// `prune_receipts`: every 10 s, forget the receipts of gone enemies with nothing in flight.
    fn prune_receipts(&mut self, online: &mut Online, now: f64) {
        if now < online.outgoing.receipts_prune_due {
            return;
        }
        online.outgoing.receipts_prune_due = now + RECEIPT_PRUNE_SECONDS;
        let alive: HashSet<u64> = self.mirrors.snapshot_entries().iter().map(|(g, _)| *g).collect();
        let pending: HashSet<i128> = self.mirrors.damage_pending.keys().iter().map(|g| *g as i128).collect();
        let owned: HashSet<i128> = online.group.damage_owners.iter().filter(|(_, o)| !o.is_empty()).map(|(g, _)| *g).collect();
        for book in online.outgoing.receipts.values_mut() {
            book.prune(&alive, &pending, &owned);
        }
    }

    /// `message['quiesced']` of a guest (`decorate`): the drain is acknowledged once nothing is left to apply.
    fn drain_quiesced(&mut self, online: &Online, n: u32) -> bool {
        let _ = online;
        let nothing_queued = self.hits.queues.values().all(|q| q.is_empty());
        self.room.draining
            && (self.drain_capture_complete || self.room.native_states.get(&n).map_or(0, |s| s[0]) == 5 || self.menu_players.contains(&n))
            && self.room.native_states.get(&n).map_or(1, |s| s[0]) != 1
            && !self.room.pause_pending.get(&n).copied().unwrap_or(false)
            && nothing_queued
            && !self.powerups_pending.get(&n).is_some_and(|p| !p.is_empty())
    }

    pub fn note_aura_drops_public(&mut self, client: &mut dyn Client) {
        self.note_aura_drops_pub(client);
    }
}

/// The host's view of the other guests (name, state, ready, loaded, movement) lives in the bridge; the group
/// model that builds `party` reads its peers, so they are refreshed from the bridge first.
fn sync_party_state(bridge: &Bridge, online: &mut Online) {
    for (number, peer) in online.group.peers.iter_mut() {
        peer.template = bridge.wire.templates.iter().find(|(m, _)| m == number).map(|(_, t)| t.clone());
        peer.name_response = bridge.wire.name_responses.get(number).cloned();
        peer.native_state = bridge.room.native_states.get(number).copied();
        peer.ready = bridge.room.ready.contains(number);
        peer.loaded = bridge.loaded.contains(number);
        peer.latest_movement = bridge.latest_movement.get(number).map(|(op, body)| (*op as u16, body.clone()));
    }
}

/// Wraps the client for one hook event of an online bridge: the events whose side effects belong to the
/// peer layer (`OnlineBridge.record`) are noted on the way through.
pub struct Tap<'a> {
    pub inner: &'a mut dyn Client,
    /// `shared_pause_requested` decisions made during the event, oldest first.
    pub pauses: Vec<bool>,
}

impl Client for Tap<'_> {
    fn number(&self) -> u32 {
        self.inner.number()
    }
    fn base(&self) -> u64 {
        self.inner.base()
    }
    fn server(&self) -> u64 {
        self.inner.server()
    }
    fn set_server(&mut self, server: u64) {
        self.inner.set_server(server)
    }
    fn memory(&mut self, address: u64, len: usize) -> Result<Vec<u8>> {
        self.inner.memory(address, len)
    }
    fn put(&mut self, address: u64, data: &[u8]) -> Result<()> {
        self.inner.put(address, data)
    }
    fn patch(&mut self, address: u64, data: &[u8]) -> Result<()> {
        self.inner.patch(address, data)
    }
    fn allocate(&mut self, size: usize) -> Result<u64> {
        self.inner.allocate(size)
    }
    fn executable_buffer(&mut self, code: &[u8], near: Option<u64>) -> Result<u64> {
        self.inner.executable_buffer(code, near)
    }
    fn image(&self) -> std::rc::Rc<dyn azcoop_patch::Image> {
        self.inner.image()
    }
    fn loading_cleared(&mut self, number: u32) -> bool {
        self.inner.loading_cleared(number)
    }
    fn saved_context(&self) -> bool {
        self.inner.saved_context()
    }
    fn call_is_request(&self) -> bool {
        self.inner.call_is_request()
    }
    fn call_return(&self) -> u64 {
        self.inner.call_return()
    }
    fn disable_hook(&mut self, hook: crate::client::Hook) {
        self.inner.disable_hook(hook)
    }
    fn call_before(&mut self, regs: &mut Regs, call: crate::client::CallSpec) -> Result<()> {
        self.inner.call_before(regs, call)
    }
    fn record(&mut self, event: Event) {
        if event.name == "shared_pause_requested" {
            if let Some((_, azcoop_logic::Detail::Num(paused))) = event.details.iter().find(|(k, _)| k == "paused") {
                self.pauses.push(*paused != 0.0);
            }
        }
        self.inner.record(event)
    }
}

impl Bridge {
    /// What the peer layer does with the events of one hook: pause decisions become `controls`, and the host's
    /// damage that reached the game is credited to the guests whose damage it was (`GroupOnlineBridge.record`).
    pub(crate) fn absorb_events(&mut self, pauses: Vec<bool>) -> Result<()> {
        let applied = std::mem::take(&mut self.mirrors.damage_applied);
        let Some(online) = self.online.as_mut() else { return Ok(()) };
        for paused in pauses {
            online.controls.push(json!({"paused": paused}));
        }
        if online.number != 1 {
            return Ok(());
        }
        for (target, requested) in applied {
            let mut remaining = requested;
            let guid = target as i128;
            let owners: Vec<u32> = online.group.damage_owners.get(&guid).map(|o| o.keys().copied().collect()).unwrap_or_default();
            for owner in owners {
                let have = online.group.damage_owners[&guid][&owner];
                let credited = remaining.min(have);
                let book = online.outgoing.receipts.entry(owner).or_default();
                let total = book.get(guid).unwrap_or(0.0) + credited;
                book.set(guid, total);
                remaining -= credited;
                let left = have - credited;
                let owners_map = online.group.damage_owners.get_mut(&guid).unwrap();
                if left <= 0.0 {
                    owners_map.remove(&owner);
                } else {
                    owners_map.insert(owner, left);
                }
            }
            if online.group.damage_owners.get(&guid).is_some_and(|o| o.is_empty()) {
                online.group.damage_owners.remove(&guid); // nothing in flight for this enemy
            }
            if remaining > 0.001 {
                return Err("Damage acknowledgement has no authenticated owner".into());
            }
        }
        Ok(())
    }
}
