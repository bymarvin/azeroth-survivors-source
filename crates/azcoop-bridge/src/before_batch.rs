//! `before_batch`: what a player's game is asked to do before its next native queue write is let
//! through. Three layers in the Python (BossRewards, NativeCombatBridge, Bridge); each either calls
//! into the game (the caller then retries the write) or hands over to the next layer.

use crate::bridge::Bridge;
use crate::client::{CallSpec, Client, Hook, Result};
use crate::io::GameIo;
use crate::regs::Regs;
use azcoop_logic::apply_hit::Clocks;
use azcoop_logic::hits::Kind;
use azcoop_logic::{Detail, Event};
use azcoop_patch::ui::reward_code;
use azcoop_patch::Ctx;

pub const GUARDIAN: i64 = -1;
const MAX_COUNTER: u64 = 0xFFFF_FFFF;
const MAX_NATIVE_OBJECTS: u64 = 1_000_000;
const MAX_MULTIPLIER: f64 = 1e6;
const MAP_TABLE: u64 = 0x6636F60;
const REWARD_VECTOR: i64 = 0x648;
const MAX_QUEUE: usize = 65_536;

/// One authoritative boss notification: the guest rolls its own gear for it.
#[derive(Debug, Clone, PartialEq)]
pub struct RewardEvent {
    pub sequence: u64,
    pub map: u32,
    pub boss: i64,
}

/// Runs a Mirrors method with the bridge-wide bound counters in step with the economy's.
macro_rules! mirrors {
    ($self:ident, $m:ident, $e:expr) => {{
        $self.mirrors.bound_dropped = $self.economy.bound_dropped.clone();
        $self.mirrors.bound_logged = $self.economy.bound_logged.clone();
        let result = {
            let $m = &mut $self.mirrors;
            $e
        };
        $self.economy.bound_dropped = $self.mirrors.bound_dropped.clone();
        $self.economy.bound_logged = $self.mirrors.bound_logged.clone();
        result
    }};
}
pub(crate) use mirrors;

fn q(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

fn u32le(data: &[u8]) -> u32 {
    u32::from_le_bytes(data[..4].try_into().unwrap())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Bridge {
    /// `guardian_counters()`: raw Game offsets of the guardian kill count and pending reward choices.
    fn guardian_counters(&self) -> (u64, u64) {
        (self.build.raw.guardian_kills, self.build.raw.guardian_choices)
    }

    /// `native_map(client, game)`: the native map index and its boss-array pointer.
    pub(crate) fn native_map(&self, client: &mut dyn Client, game: u64) -> Result<(u32, u64)> {
        let profile = &self.build.profile;
        let selected = client.memory(game + profile.field("game", 0x2D8)? as u64, 16)?;
        let size = q(&selected, 8) as usize;
        if !(1..=32).contains(&size) {
            return Err("Invalid native boss map name".into());
        }
        let name = client.memory(q(&selected, 0), size)?;
        let stride = profile.field("map", 0xA0)? as u64;
        let (name_pointer, name_length, boss_pointer) = (profile.field("map", 0)? as usize, profile.field("map", 8)? as usize, profile.field("map", 0x40)? as usize);
        let table = client.base() + self.reviewed_rva(MAP_TABLE)?;
        for map_index in 0..crate::menu::zones_of(profile.menu.as_ref()).len() as u64 {
            let row = client.memory(table + map_index * stride, boss_pointer + 8)?;
            if q(&row, name_length) as usize == size && client.memory(q(&row, name_pointer), size)? == name {
                return Ok((map_index as u32, q(&row, boss_pointer)));
            }
        }
        Err("Unknown native boss map".into())
    }

    pub(crate) fn reviewed_rva(&self, reviewed: u64) -> Result<u64> {
        self.build.profile.addresses.get(&reviewed).copied().ok_or_else(|| format!("profile has no address for {reviewed:#x}"))
    }

    /// `reward_items(client)`: the gear rewards already rolled.
    fn reward_items(&self, client: &mut dyn Client) -> Result<Vec<u32>> {
        let game = client.server() + 0x10;
        let head = client.memory(game + self.build.profile.field("game", REWARD_VECTOR)? as u64, 24)?;
        let (capacity, pointer, count) = (q(&head, 0), q(&head, 8), q(&head, 16));
        if !(count <= capacity && capacity <= MAX_NATIVE_OBJECTS) {
            return Err("Invalid native gear reward vector".into());
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        let data = client.memory(pointer, count as usize * 4)?;
        Ok(data.chunks(4).map(u32le).collect())
    }

    /// `publish_reward(map_index, boss)`
    pub(crate) fn publish_reward(&mut self, client: &mut dyn Client, map_index: u32, boss: i64) -> Result<()> {
        let sequence = self.boss_reward_sequence + 1;
        let event = RewardEvent { sequence, map: map_index, boss };
        if self.boss_reward_events.len() >= MAX_QUEUE {
            return Err("Unacknowledged encounter reward history exceeds bound".into());
        }
        self.boss_reward_events.push(event.clone());
        self.boss_reward_sequence = sequence;
        for number in self.room.guests.clone() {
            if self.clients.contains(&number) {
                self.receive_boss_rewards(number, std::slice::from_ref(&event))?;
            }
        }
        let name = if boss == GUARDIAN { "authoritative_guardian_reward" } else { "authoritative_boss_reward" };
        client.record(Event::new(name).num("sequence", sequence as f64).num("map", map_index as f64).num("boss", boss as f64));
        Ok(())
    }

    /// `receive_boss_rewards(number, events)`
    pub fn receive_boss_rewards(&mut self, number: u32, events: &[RewardEvent]) -> Result<()> {
        if !self.room.guests.contains(&number) || events.len() > MAX_QUEUE {
            return Err("Invalid boss reward recipient or event count".into());
        }
        for event in events {
            if !(1..=0xFFFF_FFFF).contains(&event.sequence) || event.map >= 9 || !(GUARDIAN..5).contains(&event.boss) {
                return Err("Invalid boss reward event".into());
            }
            let seen = self.boss_reward_seen.entry(number).or_insert(0);
            if event.sequence <= *seen {
                continue;
            }
            if event.sequence != *seen + 1 {
                return Err("Out-of-order boss reward event".into());
            }
            let pending = self.boss_reward_pending.entry(number).or_default();
            if pending.len() >= MAX_QUEUE {
                return Err("Boss reward queue exceeds bound".into());
            }
            pending.push(event.clone());
            *self.boss_reward_seen.get_mut(&number).unwrap() = event.sequence;
        }
        Ok(())
    }

    /// `before_batch(client, context)` of the outermost layer (BossRewards).
    pub(crate) fn before_batch(&mut self, client: &mut dyn Client, regs: &mut Regs) -> Result<bool> {
        let number = client.number();
        let game = client.server() + 0x10;
        #[cfg(feature = "test-hooks")]
        if number == 1 && !self.stress_clock_done && self.room.native_states.get(&1).map_or(0, |s| s[0]) == 1 {
            if let Some(seconds) = self.stress.as_ref().and_then(|s| s.clock_seconds) {
                // stress test: minute 25 (the clock and the next-wave time move together)
                client.put(game + self.build.fields.get(0x85C)?, &seconds.to_le_bytes())?;
                if let Some(next_wave) = self.stress.as_ref().and_then(|s| s.next_wave) {
                    client.put(game + next_wave, &seconds.to_le_bytes())?;
                }
                client.record(Event::new("test_stress_clock").num("seconds", seconds as f64));
            }
            self.stress_clock_done = true;
            if let Some(amount) = self.stress.as_ref().and_then(|s| s.xp_boost) {
                client.record(Event::new("test_stress_xp").num("amount", amount as f64));
                client.call_before(regs, CallSpec::new(Hook::AwardXp, game, amount))?;
                return Ok(true);
            }
        }
        #[cfg(feature = "test-hooks")]
        if number == 1 && self.room.native_states.get(&1).map_or(0, |s| s[0]) == 5 && self.room.end_pending.is_empty() && self.room.end_action.is_none() {
            if let Some(command) = self.stress.as_ref().and_then(|s| s.victory_command) {
                // stress test: the run is won; after 3 s on the victory screen the host "clicks" the choice: the native UI command as
                // a player request (request = 1), so the bridge's own ui_command path takes it like a real click
                let since = *self.stress_victory_since.get_or_insert(self.now);
                if self.now - since >= 3.0 && !self.stress_clicked {
                    self.stress_clicked = true; // one click per test, as a player clicks once (Again sets no end_action)
                    if self.stress_click_buffer == 0 {
                        self.stress_click_buffer = client.allocate(0xE8)?;
                    }
                    let mut payload = command.to_le_bytes().to_vec();
                    payload.extend_from_slice(&[0u8; 0xE4]);
                    client.put(self.stress_click_buffer, &payload)?;
                    client.record(Event::new("test_stress_victory_click").num("command", command as f64));
                    let server = client.server();
                    client.call_before(regs, CallSpec::new(Hook::UiCommand, server, self.stress_click_buffer).with("request", Detail::Num(1.0)))?;
                    return Ok(true);
                }
            }
        }
        if self.auto_talent && self.room.native_states.get(&number).map_or(0, |s| s[0]) == 2 {
            // the choice menu is open: take slot (number - 1) % count, then this write is retried
            let count = u64::from_le_bytes(client.memory(game + self.build.fields.get(0x618)?, 8)?[..8].try_into().unwrap());
            if !(1..=16).contains(&count) {
                return Err("Invalid native choices".into());
            }
            #[allow(unused_mut)]
            let mut slot = (number as u64 - 1) % count;
            #[cfg(feature = "test-hooks")]
            if let Some(picks) = self.stress.as_ref().and_then(|s| s.picks.clone()) {
                // stress test: the wanted ability by its key (the choices Vec of the config)
                let wanted: Vec<String> = picks.wanted.iter().find(|(n, _)| *n == number).map(|(_, k)| k.clone()).unwrap_or_default();
                let head = client.memory(game + picks.vector, 16)?;
                let (pointer, len) = (u64::from_le_bytes(head[..8].try_into().unwrap()), u64::from_le_bytes(head[8..16].try_into().unwrap()));
                for index in 0..len.min(16) {
                    let tag = u64::from_le_bytes(client.memory(pointer + index * picks.stride + picks.tag, 8)?[..8].try_into().unwrap());
                    if tag != picks.ability_tag {
                        continue; // not an ability choice
                    }
                    let entry = client.memory(pointer + index * picks.stride + picks.key, 16)?;
                    let (kp, kl) = (u64::from_le_bytes(entry[..8].try_into().unwrap()), u64::from_le_bytes(entry[8..16].try_into().unwrap()));
                    if kl == 0 || kl > 64 {
                        continue;
                    }
                    let key = String::from_utf8_lossy(&client.memory(kp, kl as usize)?).to_string();
                    if wanted.iter().any(|w| *w == key) {
                        slot = index;
                        client.record(Event::new("test_stress_pick").num("player", number as f64).text("key", &key).num("slot", index as f64));
                        break;
                    }
                }
            }
            client.call_before(regs, CallSpec::new(Hook::Choose, game, slot))?;
            return Ok(true);
        }
        let (kills, choices) = self.guardian_counters();
        if number == 1 && self.room.ready.contains(&1) {
            // DAMAGE increments this native statistic only on a real guardian death, even if a level-up
            // defers the host's jewelry menu.
            let count = u32le(&client.memory(game + kills, 4)?) as u64;
            if !(self.guardian_count_seen <= count && count <= self.guardian_count_seen + 128) {
                return Err("Native guardian count changed unexpectedly".into());
            }
            if count > self.guardian_count_seen {
                let map_index = self.native_map(client, game)?.0;
                for _ in 0..count - self.guardian_count_seen {
                    self.publish_reward(client, map_index, GUARDIAN)?;
                }
                self.guardian_count_seen = count;
            }
        }
        let pending_first = self.boss_reward_pending.get(&number).and_then(|p| p.first()).cloned();
        if self.room.ready.contains(&number) {
            if let Some(event) = pending_first {
                if self.native_map(client, game)?.0 != event.map {
                    return Err("Guest map differs from the authoritative boss reward map".into());
                }
                if event.boss == GUARDIAN {
                    for offset in [kills, choices] {
                        let value = u32le(&client.memory(game + offset, 4)?) as u64;
                        if value >= MAX_COUNTER {
                            return Err("Native guardian reward counter exceeds bound".into());
                        }
                        client.put(game + offset, &((value + 1) as u32).to_le_bytes())?;
                    }
                    self.boss_reward_pending.get_mut(&number).unwrap().remove(0);
                    self.boss_reward_applied.insert(number, event.sequence);
                    let phase = self.room.native_states.get(&number).ok_or("KeyError: native state")?[0];
                    client.record(Event::new("independent_guardian_reward").num("player", number as f64).num("sequence", event.sequence as f64).num("phase", phase as f64));
                    return Ok(false); // Entitlement persists in the native pending-choice counter.
                }
                let before = self.reward_items(client)?;
                let code = {
                    let image = client.image();
                    let ctx = Ctx { variant: self.build.variant, profile: &self.build.profile, image: &*image };
                    reward_code(&ctx, client.base())?
                };
                let spec = CallSpec { hook: None, argument: game, second: ((event.map as u64) << 8) | (event.boss as u64 & 0xFF), details: vec![("entry_code", Detail::Text(hex(&code)))] };
                client.call_before(regs, spec)?;
                let after = self.reward_items(client)?;
                if after[..before.len().min(after.len())] != before[..] || after.len() < before.len() {
                    return Err("Native boss roll replaced existing rewards".into());
                }
                self.boss_reward_pending.get_mut(&number).unwrap().remove(0);
                self.boss_reward_applied.insert(number, event.sequence);
                client.record(
                    Event::new("independent_boss_reward")
                        .num("player", number as f64)
                        .num("sequence", event.sequence as f64)
                        .num("map", event.map as f64)
                        .num("boss", event.boss as f64)
                        .list("items", after[before.len()..].iter().map(|x| *x as f64).collect()),
                );
                return Ok(true);
            }
        }
        if self.room.guests.contains(&number)
            && self.room.ready.contains(&number)
            && !self.room.draining
            && !self.room.paused
            && self.room.native_states.get(&number).ok_or("KeyError: native state")?[0] == 1
        {
            // Phase 1 only: OFFER_CHOICES sets phase 2 without checking, and over a paused player's open menu
            // RESUME (phase 3 only) can never close it again.
            if u32le(&client.memory(game + choices, 4)?) != 0 {
                client.call_before(regs, CallSpec::new(Hook::OfferChoices, game, 2))?;
                client.record(Event::new("guardian_choice_offered").num("player", number as f64));
                return Ok(true);
            }
        }
        self.native_before_batch(client, regs)
    }

    /// `spawn_bonus()`: 0 to 0.5 extra spawns by the distance between the living players.
    pub(crate) fn spawn_bonus(&self) -> f64 {
        #[cfg(feature = "test-hooks")]
        if let Some(bonus) = self.stress.as_ref().and_then(|s| s.spawn_bonus) {
            return bonus; // stress test: population cap and spawn debt (4.0 = 5x)
        }
        let living: Vec<u32> = self.room.members.iter().copied().filter(|n| matches!(self.room.native_states.get(n).map_or(0, |s| s[0]), 1..=3)).collect();
        let poses: Vec<[f64; 4]> = living.iter().filter_map(|n| self.wire.poses.get(n).copied()).collect();
        let mut distance = 0f64;
        for a in &poses {
            for b in &poses {
                distance = distance.max((a[0] - b[0]).hypot(a[1] - b[1]));
            }
        }
        0.5 * (distance / self.spawn_bonus_distance).min(1.0)
    }

    /// `before_batch` of NativeCombatBridge.
    fn native_before_batch(&mut self, client: &mut dyn Client, regs: &mut Regs) -> Result<bool> {
        let number = client.number();
        let clocks = Clocks { perf: self.perf, mono: self.now };
        self.next_guest_attack = f64::INFINITY;
        if !self.room.ready.contains(&number) {
            return self.base_before_batch(client, regs);
        }
        self.refresh();
        macro_rules! io {
            () => {
                GameIo::new(client, regs, &self.build.fields, &mut self.results)
            };
        }
        let surrendered = {
            let mut io = io!();
            self.room.apply_party_surrender(&mut io, number)?
        };
        self.flush_outputs();
        if surrendered {
            return Ok(true);
        }
        if number == 1 {
            // A boss death can collect coins and enter native victory in the same tick: publish those final
            // credits before publishing phase 5.
            let mut io = io!();
            self.economy.capture_pickup_gold(&mut io)?;
        }
        let phase = self.room.native_states.get(&number).ok_or("KeyError: native state")?[0];
        if phase == 5 {
            if number != 1 && self.economy.chest_claim.as_ref().is_some_and(|c| c.status == "refund") {
                let mut io = io!();
                self.economy.sync_chests(&mut io, number, self.now)?;
                self.flush_outputs();
            }
            let expired = self.powerups_pending.get(&number).map_or(0, |p| p.len());
            if expired > 0 {
                client.record(Event::new("shared_powerups_expired").num("player", number as f64).text("reason", "run_finished").num("count", expired as f64));
                self.powerups_pending.get_mut(&number).unwrap().clear();
            }
            // Native victory tears down combat-owned storage. A stale peer snapshot must never reconstruct
            // mirrors into that completed run.
            if number == 1 {
                let mut io = io!();
                mirrors!(self, m, m.clear_host_run(&mut io, self.now))?;
                self.bonus_spawns.clear();
                self.front_spawns.clear();
            } else {
                self.mirrors.provided.remove(&number);
                self.mirrors.damage_pending = azcoop_world::auras::Ordered::default();
                {
                    let mut io = io!();
                    self.hits.clear_incoming_hits(&mut io, number, "run_finished", self.now);
                }
                let mut io = io!();
                self.economy.apply_shared_gold(&mut io, number, self.now)?;
                self.flush_outputs();
            }
            return Ok(false);
        }
        let game = client.server() + 0x10;
        if self.room.guests.contains(&number) {
            if phase == 4 {
                // Native HURT ignores dead recipients; these hits cannot become new attacks against the player's later revived life.
                let mut io = io!();
                self.hits.clear_incoming_hits(&mut io, number, "recipient_dead", self.now);
            }
            // Hits and other per-write work (mirrors, chests, rewards) alternate; chained_hit bounds the hits per native queue write.
            let due = self.hit_work_turn.get(&number).copied().unwrap_or(true);
            self.hit_work_turn.insert(number, !due);
            if due {
                let mut io = io!();
                if self.applier.chained_hit(&mut io, &mut self.room, &mut self.hits, number, clocks)? {
                    self.flush_outputs();
                    return Ok(true);
                }
            }
        }
        let multiplier = f32::from_le_bytes(client.memory(game + self.build.fields.get(0x514)?, 4)?[..4].try_into().unwrap()) as f64;
        let multiplier = if !multiplier.is_finite() || !(0.0..=MAX_MULTIPLIER).contains(&multiplier) {
            azcoop_logic::skips::note(&mut |e| client.record(e), "xp_multiplier_invalid", number as u64, vec![("value", azcoop_logic::finite_item(multiplier))]);
            self.economy.xp_multipliers.get(&number).copied().unwrap_or(1.0) // keeps the last valid value
        } else {
            multiplier
        };
        self.economy.xp_multipliers.insert(number, multiplier);
        if number == 1 {
            let value = self.economy.party_xp_multiplier() as f32;
            client.put(self.party_xp_buffer, &value.to_le_bytes())?;
        }
        if self.powerups_pending.get(&number).is_some_and(|p| !p.is_empty()) {
            let kind = self.powerups_pending.get_mut(&number).unwrap().remove(0);
            if kind == 6 {
                // Magnet acts on the single authoritative loot world. Its XP and gold credits are already shared.
                if number == 1 {
                    let head = client.memory(game + self.build.fields.get(0x5C8)?, 16)?;
                    let (pointer, count) = (q(&head, 0), q(&head, 8));
                    if count > MAX_NATIVE_OBJECTS {
                        return Err("Magnet loot count exceeds bound".into());
                    }
                    for i in 0..count {
                        let address = pointer + i * 0x48;
                        let loot_kind = u32le(&client.memory(address + 0x20, 4)?);
                        let moving = u32le(&client.memory(address + 0x18, 4)?);
                        if loot_kind == 1 && moving == 0 {
                            let xy = client.memory(address + 0x34, 8)?;
                            let (x, y) = (f32::from_le_bytes(xy[..4].try_into().unwrap()) as f64, f32::from_le_bytes(xy[4..8].try_into().unwrap()) as f64);
                            let hxy = client.memory(game + self.build.fields.get(0x488)?, 8)?;
                            let (hx, hy) = (f32::from_le_bytes(hxy[..4].try_into().unwrap()) as f64, f32::from_le_bytes(hxy[4..8].try_into().unwrap()) as f64);
                            let arrival = self.room.host_clock + ((x - hx).hypot(y - hy) / 40.0).max(0.15000000596046448);
                            let mut value = 1u32.to_le_bytes().to_vec();
                            value.extend_from_slice(&(arrival as f32).to_le_bytes());
                            client.put(address + 0x18, &value)?;
                        }
                    }
                    let code = {
                        let mut c = vec![0x48, 0xB8];
                        c.extend_from_slice(&(client.base() + self.reviewed_rva(0x5412470)?).to_le_bytes());
                        c.extend([0xFF, 0xE0]);
                        c
                    };
                    client.call_before(regs, CallSpec { hook: None, argument: game, second: 0, details: vec![("entry_code", Detail::Text(hex(&code)))] })?;
                    client.record(Event::new("shared_powerup_applied").num("player", 1.0).num("kind", 6.0));
                    return Ok(true);
                }
                client.record(Event::new("shared_powerup_applied").num("player", number as f64).num("kind", kind as f64));
            } else {
                // Native Speed/Berserking/Restoration owns timers, buff stacking, recalculated stats, healing cap and the player's UI packets.
                let mut code = vec![0x48, 0xB8];
                code.extend_from_slice(&(client.base() + self.reviewed_rva(0x54135A0)?).to_le_bytes());
                code.extend([0xFF, 0xE0]);
                client.call_before(regs, CallSpec { hook: None, argument: game, second: kind, details: vec![("entry_code", Detail::Text(hex(&code)))] })?;
                client.record(Event::new("shared_powerup_applied").num("player", number as f64).num("kind", kind as f64));
                return Ok(true);
            }
        }
        if number == 1 {
            let scale = (self.spawn_bonus() * 65536.0) as u64;
            client.put(self.spawn_scale, &scale.to_le_bytes())?;
            {
                let mut io = io!();
                if self.economy.sync_chests(&mut io, number, self.now)? {
                    self.flush_outputs();
                    return Ok(true);
                }
            }
            self.flush_outputs();
            if self.economy.pickup_xp_pending != 0 {
                let amount = self.economy.pickup_xp_pending.min(MAX_COUNTER as i128); // One native u32 award; the rest next batch.
                self.economy.pickup_xp_pending -= amount;
                client.call_before(regs, CallSpec::new(Hook::AwardXp, client.server() + 0x10, amount as u64))?;
                return Ok(true);
            }
            {
                let mut io = io!();
                mirrors!(self, m, m.snapshot_enemies(&mut io))?;
            }
            let host_phase = self.room.native_states.get(&1).map_or(0, |s| s[0]);
            if !self.mirrors.effects_pending.is_empty() && !self.room.paused && matches!(host_phase, 1 | 4) {
                let (target, effect, spell) = self.mirrors.effects_pending.remove(0);
                let known = {
                    let mut io = io!();
                    mirrors!(self, m, m.snapshot_contains(&mut io, target, self.now))?
                };
                if known {
                    let server_game = client.server() + 0x10;
                    let spec = CallSpec::new(Hook::ApplyEffect, server_game, target)
                        .with("effect", Detail::Text(hex(&effect)))
                        .with("spell", Detail::Num(spell as f64));
                    client.call_before(regs, spec)?;
                    {
                        let mut io = io!();
                        mirrors!(self, m, m.snapshot_enemies(&mut io))?;
                    }
                    let kind = u32le(&effect);
                    client.record(Event::new("guest_effect_applied").num("target", target as f64).num("kind", kind as f64).num("spell", spell as f64));
                    return Ok(true);
                }
            }
            if !self.mirrors.damage_pending.is_empty() && !self.room.paused && matches!(host_phase, 1 | 4) {
                let (patches, gate) = self.guest_damage_patches(client)?;
                let mut io = io!();
                let called = mirrors!(self, m, m.apply_guest_damage(&mut io, host_phase, &patches, &gate, self.now))?;
                self.flush_outputs();
                return Ok(called);
            }
            while let Some(&(kind, owner)) = self.front_spawns.front() {
                if self.room.draining || self.room.paused || !matches!(host_phase, 1 | 4) {
                    break;
                }
                self.front_spawns.pop_front();
                if !matches!(self.room.native_states.get(&owner).map_or(0, |s| s[0]), 1..=3) {
                    continue; // that player is no longer playing
                }
                self.spawning_bonus = true;
                self.spawn_owner_override = Some(owner);
                let spec = CallSpec::new(Hook::Spawn, client.server() + 0x10, kind).with("position", Detail::List(vec![0.0, 0.0, 0.0]));
                let outcome = client.call_before(regs, spec);
                self.spawning_bonus = false;
                self.spawn_owner_override = None;
                outcome?;
                return Ok(true);
            }
            if !self.bonus_spawns.is_empty() && !self.room.draining && !self.room.paused && matches!(host_phase, 1 | 4) {
                let kind = self.bonus_spawns.remove(0);
                self.spawning_bonus = true;
                let spec = CallSpec::new(Hook::Spawn, client.server() + 0x10, kind).with("position", Detail::List(vec![0.0, 0.0, 0.0]));
                client.call_before(regs, spec)?;
                self.spawning_bonus = false;
                return Ok(true);
            }
        } else {
            // the host has won: its victory screen (phase 5) or its victory choice (end_action, sent with every host message) reaches this
            // guest; the choice alone suffices, a host that leaves phase 5 within one network send must not cost the guest its victory
            // (stress run 19.10.2026: phase 5 for 31 ms, the guest never got the victory, its evaluation or the zone unlock)
            let host_won = self.room.native_states.get(&1).map_or(0, |s| s[0]) == 5 || self.room.end_action.is_some();
            if host_won && !self.room.victory_guests.contains(&number) {
                let mut io = io!();
                self.room.shared_victory(&mut io, number)?;
            }
            {
                let mut io = io!();
                self.economy.apply_shared_gold(&mut io, number, self.now)?;
            }
            self.flush_outputs();
            let chests = {
                let mut io = io!();
                self.economy.sync_chests(&mut io, number, self.now)?
            };
            self.flush_outputs();
            if chests {
                return Ok(true);
            }
            if self.room.draining {
                {
                    let mut io = io!();
                    mirrors!(self, m, m.sync_mirrors(&mut io, number, true, self.now))?;
                }
                self.drain_capture_complete = self.room.native_states.get(&number).ok_or("KeyError: native state")?[0] != 1;
                return self.base_before_batch(client, regs);
            }
            let called = {
                let mut io = io!();
                mirrors!(self, m, m.sync_mirrors(&mut io, number, false, self.now))?
            };
            if called {
                return Ok(true);
            }
        }
        self.base_before_batch(client, regs)
    }

    /// `before_batch` of the base bridge: the next waiting hit, if this write still has room. (The host-side
    /// simulation of a guest's melee needs `guest_stats`, which only a process running guest 2's own game
    /// ever sets, and it applies to the host's client only: it never runs.)
    fn base_before_batch(&mut self, client: &mut dyn Client, regs: &mut Regs) -> Result<bool> {
        let number = client.number();
        let clocks = Clocks { perf: self.perf, mono: self.now };
        self.refresh();
        let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
        let applied = self.applier.chained_hit(&mut io, &mut self.room, &mut self.hits, number, clocks)?;
        self.flush_outputs();
        Ok(applied)
    }

    /// `guest_damage_patches()` and the extra gate patch for a downed host.
    fn guest_damage_patches(&self, client: &mut dyn Client) -> Result<(Vec<azcoop_logic::CodePatch>, azcoop_logic::CodePatch)> {
        let image = client.image();
        let ctx = Ctx { variant: self.build.variant, profile: &self.build.profile, image: &*image };
        let patches = azcoop_patch::damage::guest_damage_patches(&ctx)?;
        let gate_rva = ctx.rva(0x53FF52B)?;
        let original = azcoop_patch::install::native_branch(&ctx, 0x53FF52B, 0x5402BF3, &[0x0F, 0x85], 6)?;
        Ok((patches, (gate_rva, original, vec![0x90; 6])))
    }
}
