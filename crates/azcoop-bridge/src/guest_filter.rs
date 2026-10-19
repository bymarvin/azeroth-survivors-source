//! `NativeCombatBridge.filter_packet` and its helpers: what a packet of the game's own outgoing
//! batch does beyond the base filter. The host routes ordinary ranged casts to the nearer player;
//! a guest's downed avatar is kept down, its vitals are relayed to the others, its summons,
//! totems and ground spells are mapped into the reserved GUID namespace and relayed, and its
//! combat packets reach the other players' attack queues.

use crate::bridge::Bridge;
use crate::client::{Client, Result};
use crate::io::GameIo;
use crate::regs::Regs;
use azcoop_logic::Event;
use azcoop_world::auras::Ordered;
use azcoop_world::builders::character_name;
use azcoop_world::{
    downed_player_values, dynamic_caster, dynamic_object, object_packet, objects, remap_combat, values_packet, ObjectBlock, Reader, COMBAT, DESTROY, DISPLAY_ID,
    MONSTER, PROGRESSION, SELF, UPDATE,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const SUMMON_PREFIXES: [u64; 2] = [0xF130, 0xF140];
pub const MAX_LIVE_SUMMONS: usize = 4096;
pub const SUMMON_HISTORY: usize = 100_000;

/// Per-guest summon identities and the other state `filter_summons` keeps.
pub struct GuestState {
    /// `summon_maps[n]`: native GUID -> network GUID, oldest first.
    pub maps: BTreeMap<u32, Ordered<u64>>,
    /// `dynamic_guids[n]`: native ground-spell GUIDs per owner.
    pub dynamic_guids: BTreeMap<u32, BTreeSet<u64>>,
    /// Logged once each; bounded.
    pub unmapped_companions: BTreeSet<u64>,
    pub max_live_summons: usize,
    pub summon_history: usize,
}

impl GuestState {
    pub fn new(members: &[u32]) -> GuestState {
        GuestState {
            maps: members.iter().map(|m| (*m, Ordered::default())).collect(),
            dynamic_guids: members.iter().map(|m| (*m, BTreeSet::new())).collect(),
            unmapped_companions: BTreeSet::new(),
            max_live_summons: MAX_LIVE_SUMMONS,
            summon_history: SUMMON_HISTORY,
        }
    }
}

/// A native unit this player summoned or created (pets, water elemental, spirit wolves, treants).
pub fn owned_companion(block: &ObjectBlock) -> bool {
    [12u32, 14].iter().any(|k| {
        block.fields.contains_key(k)
            && (block.fields[k] as u64 | ((block.fields.get(&(k + 1)).copied().unwrap_or(0) as u64) << 32)) == SELF
    })
}

fn q(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

fn hash_map(map: &Ordered<u64>) -> HashMap<u64, u64> {
    map.keys().into_iter().map(|k| (k, *map.get(k).unwrap())).collect()
}

impl Bridge {
    /// `native_totem_guids(number)`: GUIDs of the player's live native totems.
    fn native_totem_guids(&mut self, client: &mut dyn Client) -> Result<BTreeSet<u64>> {
        let address = client.server() + 0x10 + self.build.totem_vector;
        let head = client.memory(address, 16)?;
        let (pointer, count) = (q(&head, 0), q(&head, 8) as usize);
        if count > self.guest.max_live_summons || (count > 0 && pointer == 0) {
            return Err("Native totem vector exceeds bound".into());
        }
        // The verified totem update region owns 0x70-byte entries (47e4: 0x78, GUID +0x58).
        let (stride, guid) = if self.build.variant.is_47e4() { (0x78u64, 0x58u64) } else { (0x70, 0x50) };
        let mut out = BTreeSet::new();
        for i in 0..count as u64 {
            out.insert(q(&client.memory(pointer + i * stride + guid, 8)?, 0));
        }
        Ok(out)
    }

    /// `make_summon_room(number, limit)`: keep one guest's summon identities bounded: drop the oldest
    /// destroyed ones, never live ones.
    fn make_summon_room(&mut self, client: &mut dyn Client, number: u32) {
        let limit = self.guest.summon_history;
        let mapping = self.guest.maps.get_mut(&number).unwrap();
        if mapping.len() < limit {
            return;
        }
        let live = self.input.summons.entry(number).or_default().clone();
        let mut drop = Vec::new();
        for native in mapping.keys() {
            let network = *mapping.get(native).unwrap();
            if !live.contains(&network) {
                drop.push(native);
                if ((mapping.len() - drop.len()) as i64) < (limit * 3 / 4) as i64 {
                    break;
                }
            }
        }
        for native in &drop {
            mapping.remove(*native);
            self.guest.dynamic_guids.get_mut(&number).unwrap().remove(native);
        }
        let kept = self.guest.maps[&number].len() as f64;
        self.note_bound_event(client, "summon_identities", drop.len() as i128, vec![("player", number as f64), ("kept", kept)]);
    }

    /// `note_bound(state, amount, **details)` with the bridge's clock.
    pub fn note_bound_event(&mut self, client: &mut dyn Client, state: &str, amount: i128, details: Vec<(&str, f64)>) {
        let now = self.now;
        let mut regs = Regs::default();
        let mut io = GameIo::new(client, &mut regs, &self.build.fields, &mut self.results);
        self.economy.note_bound(&mut io, state, amount, now, details);
    }

    /// `publish_local_auras(number)`: a process that also runs the host game overlays the guest's
    /// changes directly; a network guest sends them in its state message.
    fn publish_local_auras(&mut self, client: &mut dyn Client, number: u32) -> Result<()> {
        if self.room.own_number.unwrap_or(1) == 1 {
            let changes = self.own_auras.get_mut(&number).map(|o| o.take_changes(crate::bridge::MAX_ENEMIES)).unwrap_or_default();
            self.receive_guest_auras(number, changes)?;
        }
        self.note_aura_drops(client);
        Ok(())
    }

    /// `receive_guest_auras(player, auras)`: state only; the overlay is written with the next captured host world block.
    pub fn receive_guest_auras(&mut self, player: u32, auras: Vec<(u64, Vec<azcoop_world::auras::Aura>)>) -> Result<()> {
        if !self.room.guests.contains(&player) {
            return Err("Guest auras from a non-guest".into());
        }
        if !auras.is_empty() {
            self.overlay.guest_auras(player, &auras);
        }
        Ok(())
    }

    /// `note_aura_drops()`
    pub(crate) fn note_aura_drops_pub(&mut self, client: &mut dyn Client) {
        self.note_aura_drops(client)
    }

    fn note_aura_drops(&mut self, client: &mut dyn Client) {
        let dropped = self.own_auras.values().map(|o| o.dropped).sum::<u64>() + self.overlay.dropped;
        if dropped > self.aura_drops_seen {
            let guest_entries: usize = self.own_auras.values().map(|o| o.state().0.len()).sum();
            let host_entries = self.overlay.state().guests.len();
            let amount = (dropped - self.aura_drops_seen) as i128;
            self.note_bound_event(client, "guest_auras", amount, vec![("guest_entries", guest_entries as f64), ("host_entries", host_entries as f64)]);
            self.aura_drops_seen = dropped;
        }
    }

    /// `filter_packet(number, opcode, body)` of NativeCombatBridge.
    pub fn filter_packet_native(&mut self, client: &mut dyn Client, number: u32, opcode: u16, body: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut body = body.to_vec();
        if number == 1 {
            body = self.route_projectile(client, opcode, &body)?;
            if opcode == DESTROY && body.len() == 8 {
                let retired = q(&body, 0);
                self.mirrors.ranged_enemies.remove(retired);
                self.ranged_targets.retain(|(attacker, _), _| *attacker != retired);
            }
        }
        if opcode == UPDATE && self.room.native_states.get(&number).map_or(0, |s| s[0]) == 4 {
            body = downed_player_values(&body)?;
        }
        if number != 1 && opcode == UPDATE {
            for block in objects(&body, false, None)? {
                if block.guid == SELF {
                    // These fields update this guest's remote avatar only. Native XP awards still come
                    // exclusively from the host. The display model carries druid forms.
                    let vitals: BTreeMap<u32, u32> = block
                        .fields
                        .iter()
                        .filter(|(f, _)| (22..=33).contains(*f) || PROGRESSION.contains(f) || **f == DISPLAY_ID)
                        .map(|(f, v)| (*f, *v))
                        .collect();
                    if !vitals.is_empty() {
                        self.sync_guest_input();
                        let candidate = values_packet(0xFF0100 + number as u64, &vitals)?;
                        let (packet, first) = self.input.sanitize_player_values(number, UPDATE, &candidate)?;
                        if first {
                            let avatar = number as f64;
                            let display = vitals.get(&DISPLAY_ID).copied().unwrap_or(0) as f64;
                            client.record(Event::new("guest_display_rejected").num("player", number as f64).num("avatar", avatar).num("display", display));
                        }
                        if let Some(packet) = packet {
                            for recipient in self.room.members.clone() {
                                if recipient != number {
                                    self.wire.feeds.entry(recipient).or_default().notice_packets.push((UPDATE, packet.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }
        if number != 1 && matches!(opcode, UPDATE | DESTROY | MONSTER) {
            if let Some(translated) = self.filter_summons(client, number, opcode, &body)? {
                return Ok(Some(translated));
            }
        }
        if number != 1 && COMBAT.contains(&opcode) {
            let map = hash_map(&self.guest.maps[&number]);
            for recipient in self.room.members.clone() {
                if recipient != number {
                    let relayed = remap_combat(opcode, &body, 0xFF0100 + number as u64, Some(0xFF0100 + recipient as u64), Some(&map))?;
                    self.wire.feeds.entry(recipient).or_default().attack_packets.push((opcode, relayed));
                }
            }
            self.native_combat_packets += 1;
            let hex: String = body.iter().map(|b| format!("{b:02x}")).collect();
            client.record(Event::new("native_guest_combat").num("player", number as f64).num("opcode", opcode as f64).text("body", &hex));
            return Ok(Some(remap_combat(opcode, &body, SELF, None, Some(&map))?));
        }
        self.filter_base(client, number, opcode, &body)
    }

    /// `filter_summons(number, opcode, body)`
    fn filter_summons(&mut self, client: &mut dyn Client, number: u32, opcode: u16, body: &[u8]) -> Result<Option<Vec<u8>>> {
        if opcode == UPDATE {
            let blocks = objects(body, false, None)?;
            if self.own_auras.contains_key(&number) {
                for block in &blocks {
                    if !self.guest.maps[&number].contains(block.guid) && !owned_companion(block) {
                        self.own_auras.get_mut(&number).unwrap().observe(block); // Mirror enemies only (native creature GUIDs).
                    }
                }
                self.publish_local_auras(client, number)?;
            }
            let candidates: Vec<&ObjectBlock> = blocks.iter().filter(|b| matches!(b.kind, 2 | 3) && b.object_type == Some(3)).collect();
            let owned = if candidates.is_empty() { BTreeSet::new() } else { self.native_totem_guids(client)? };
            for block in candidates {
                let in_map = self.guest.maps[&number].contains(block.guid);
                let companion = !owned.contains(&block.guid) && !in_map && owned_companion(block);
                if companion && (!SUMMON_PREFIXES.contains(&(block.guid >> 48)) || block.guid & 0xC00000 != 0) {
                    // Not representable in the reserved namespace: logged, stays hidden as before instead of ending the session.
                    if !self.guest.unmapped_companions.contains(&block.guid) {
                        if self.guest.unmapped_companions.len() < 128 {
                            self.guest.unmapped_companions.insert(block.guid);
                            client.record(Event::new("guest_companion_unmapped").num("player", number as f64).num("native_guid", block.guid as f64));
                        } else {
                            self.note_bound_event(client, "unmapped_companions", 1, vec![("player", number as f64), ("native_guid", block.guid as f64)]);
                        }
                    }
                    continue;
                }
                if companion {
                    if !self.guest.maps[&number].contains(block.guid) {
                        self.make_summon_room(client, number);
                    }
                    let network = block.guid | ((number as u64 - 1) << 22);
                    self.guest.maps.get_mut(&number).unwrap().set(block.guid, network);
                    self.input.summons.entry(number).or_default().insert(network);
                    let entry = block.fields.get(&3).copied().unwrap_or(0) as f64;
                    client.record(
                        Event::new("guest_companion_created").num("player", number as f64).num("native_guid", block.guid as f64).num("network_guid", network as f64).num("entry", entry),
                    );
                    continue;
                }
                if owned.contains(&block.guid) {
                    if block.guid >> 48 != 0xF130 || block.guid & 0xC00000 != 0 {
                        // Above four million native objects in one run the reserved owner bits are taken: like a
                        // companion, the totem stays hidden for the others (it still works for its owner).
                        if !self.guest.unmapped_companions.contains(&block.guid) && self.guest.unmapped_companions.len() < 128 {
                            self.guest.unmapped_companions.insert(block.guid);
                            client.record(Event::new("guest_totem_unmapped").num("player", number as f64).num("native_guid", block.guid as f64));
                        } else {
                            self.note_bound_event(client, "unmapped_totems", 1, vec![("player", number as f64), ("native_guid", block.guid as f64)]);
                        }
                        continue;
                    }
                    if !self.guest.maps[&number].contains(block.guid) {
                        self.make_summon_room(client, number);
                    }
                    let network = block.guid | ((number as u64 - 1) << 22);
                    self.guest.maps.get_mut(&number).unwrap().set(block.guid, network);
                    self.input.summons.entry(number).or_default().insert(network);
                    let entry = block.fields.get(&3).copied().unwrap_or(0) as f64;
                    client.record(Event::new("guest_totem_created").num("player", number as f64).num("native_guid", block.guid as f64).num("network_guid", network as f64).num("entry", entry));
                }
            }
            for block in &blocks {
                // Own ground spells (Rain of Fire). Mirror-enemy casts stay hidden.
                if dynamic_object(block, true)? && dynamic_caster(block)? == SELF && !self.guest.maps[&number].contains(block.guid) {
                    self.make_summon_room(client, number);
                    let network = block.guid | ((number as u64 - 1) << 22);
                    self.guest.maps.get_mut(&number).unwrap().set(block.guid, network);
                    self.input.summons.entry(number).or_default().insert(network);
                    self.guest.dynamic_guids.get_mut(&number).unwrap().insert(block.guid);
                }
            }
            let mapping = hash_map(&self.guest.maps[&number]);
            let selected: Vec<ObjectBlock> = blocks.iter().filter(|b| mapping.contains_key(&b.guid)).cloned().collect();
            if selected.is_empty() {
                return Ok(None);
            }
            for recipient in self.room.members.clone() {
                if recipient != number {
                    let mut translated = mapping.clone();
                    translated.insert(SELF, 0xFF0100 + number as u64);
                    translated.insert(0xFF0100 + recipient as u64, SELF);
                    let relayed = object_packet(&objects(&object_packet(&selected), true, Some(&translated))?);
                    self.wire.feeds.entry(recipient).or_default().attack_packets.push((UPDATE, relayed));
                }
            }
            // Keep local player/inventory output as well as the owner's totems.
            let allowed: Vec<ObjectBlock> = blocks.iter().filter(|b| mapping.contains_key(&b.guid) || b.guid == SELF || b.guid >> 48 == 0x4000).cloned().collect();
            if allowed.iter().any(|b| b.guid == SELF && PROGRESSION.iter().any(|k| b.fields.contains_key(k))) {
                self.wire.feeds.entry(number).or_default().progress_sent = None;
            }
            let mut local = mapping.clone();
            local.insert(SELF, SELF);
            return Ok(Some(object_packet(&objects(&object_packet(&allowed), true, Some(&local))?)));
        }
        if matches!(opcode, DESTROY | MONSTER) {
            let mut reader = Reader::configured(body, false, azcoop_world::HOST, None, None);
            let guid = reader.guid(opcode != DESTROY, false)?;
            if !self.guest.maps[&number].contains(guid) {
                if opcode == DESTROY && self.own_auras.contains_key(&number) {
                    self.own_auras.get_mut(&number).unwrap().destroy(guid);
                    self.publish_local_auras(client, number)?;
                }
                return Ok(None);
            }
            let map = hash_map(&self.guest.maps[&number]);
            for recipient in self.room.members.clone() {
                if recipient != number {
                    let relayed = remap_combat(opcode, body, 0xFF0100 + number as u64, Some(0xFF0100 + recipient as u64), Some(&map))?;
                    self.wire.feeds.entry(recipient).or_default().attack_packets.push((opcode, relayed));
                }
            }
            if opcode == DESTROY {
                let network = *self.guest.maps[&number].get(guid).unwrap();
                self.input.summons.entry(number).or_default().remove(&network);
                if self.guest.dynamic_guids[&number].contains(&guid) {
                    // Ground spells never reuse a GUID within one Game; keep the history bounded.
                    let local = remap_combat(opcode, body, SELF, None, Some(&map))?;
                    self.guest.dynamic_guids.get_mut(&number).unwrap().remove(&guid);
                    self.guest.maps.get_mut(&number).unwrap().remove(guid);
                    return Ok(Some(local));
                }
                client.record(Event::new("guest_totem_destroyed").num("player", number as f64).num("network_guid", network as f64));
            }
            return Ok(Some(remap_combat(opcode, body, SELF, None, Some(&map))?));
        }
        Ok(None)
    }

    /// Keeps the guest-input view of the login templates in step with the wire state.
    pub(crate) fn sync_guest_input(&mut self) {
        self.input.templates = self.wire.templates.iter().map(|(n, t)| (*n, t.clone())).collect();
        let _ = character_name; // (names are validated by the base filter)
    }
}
