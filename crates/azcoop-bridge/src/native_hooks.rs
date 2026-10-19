//! The hook branches of NativeCombatBridge (and BossRewards) that run before the base handler:
//! loot pickups, the boss HUD, enemy ability targeting and area attacks, guest effects, spawns,
//! enemy hits aimed at a guest, and boss deaths.

use crate::bridge::{Bridge, MAX_ENEMIES};
use crate::client::{Client, Result};
use crate::regs::{self, Regs};
use azcoop_game::readers::{enemy_array, parse_enemies, Reader};
use azcoop_logic::hits::{Hit, Kind};
use azcoop_logic::Event;
use azcoop_world::{pack_guid, Reader as WireReader, SELF};

const MAX_NATIVE_OBJECTS: u64 = 1_000_000;
const MAX_QUEUE: usize = 65_536;
const MAX_ENEMY_DAMAGE: f64 = 1e12;
const MAX_HIT_DAMAGE: f64 = 1e12;

fn q(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

fn f32le(data: &[u8], at: usize) -> f32 {
    f32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

impl Bridge {
    /// `validate_live_game(client, context, register_offset, enemy_offset=..., enemy_frame=...)`
    fn validate_live_game(&self, client: &mut dyn Client, regs: &Regs, register: usize, enemy_offset: Option<usize>, enemy_frame: bool) -> Result<u64> {
        let game = client.server() + 0x10;
        let frame = regs.q(regs::RBP);
        let profile = &self.build.profile;
        let slot = if enemy_frame && self.build.variant.is_47e4() { profile.field("enemy_frame", 0x3E0)? } else { profile.field("game_update_frame", 0x3E0)? } as u64;
        if regs.q(register) != game || q(&client.memory(frame + slot, 8)?, 0) != game {
            return Err("Interior native Game ownership changed".into());
        }
        if let Some(offset) = enemy_offset {
            let head = client.memory(game + self.build.fields.get(0x568)?, 16)?;
            let (pointer, count) = (q(&head, 0), q(&head, 8));
            let enemy = regs.q(offset);
            let stride = self.build.variant.enemy_layout().stride;
            if !(0 < count && count <= MAX_ENEMIES as u64) || !(pointer <= enemy && enemy < pointer + count * stride) || (enemy - pointer) % stride != 0 {
                return Err("Interior native Enemy ownership changed".into());
            }
        }
        Ok(game)
    }

    /// The hooks of NativeCombatBridge/BossRewards that act before the base handler. `Some(())`: handled
    /// (the Python returns); `None`: continue with the rest of the dispatch.
    pub(crate) fn native_hook_branches(&mut self, client: &mut dyn Client, hook: crate::client::Hook, regs: &mut Regs, number: u32) -> Result<Option<()>> {
        use crate::client::Hook;
        match hook {
            Hook::BossDeath => {
                self.boss_death(client, regs, number)?;
                Ok(Some(()))
            }
            Hook::RemoveLoot if number == 1 => {
                self.remove_loot(client, regs)?;
                Ok(Some(()))
            }
            Hook::HudDeliver => {
                self.hud_deliver(client, regs, number)?;
                Ok(Some(()))
            }
            Hook::EnemyTarget => {
                self.enemy_target(client, regs, number)?;
                Ok(Some(()))
            }
            Hook::EnemyAoe | Hook::GroundAoe => {
                self.area_attack(client, regs, number, hook == Hook::EnemyAoe)?;
                Ok(Some(()))
            }
            Hook::ApplyEffect => {
                if number != 1 {
                    let effect = client.memory(regs.q(regs::R8), 12)?;
                    let kind = u32::from_le_bytes(effect[..4].try_into().unwrap());
                    if matches!(kind, 1 | 2 | 3 | 4 | 10) {
                        if self.mirrors.effects_pending.len() >= MAX_QUEUE {
                            return Err("Guest effect queue exceeds bound".into());
                        }
                        let spell = u32::from_le_bytes(client.memory(regs.q(regs::RSP) + 0x28, 4)?[..4].try_into().unwrap());
                        self.mirrors.effects_pending.push((regs.q(regs::RDX), effect, spell));
                    }
                }
                Ok(Some(()))
            }
            Hook::Spawn if number == 1 && self.room.ready.contains(&1) && self.wire.poses.len() == self.room.members.len() => {
                self.spawn_kind = regs.q(regs::RDX);
                if self.spawn_kind > 11 {
                    return Err("Unknown native enemy kind".into());
                }
                // Both centers use the original annulus and native terrain validation.
                regs.set_q(regs::R8, self.spawn_option);
                Ok(None)
            }
            Hook::FindSpawn if number == 1 && self.room.ready.contains(&1) => {
                let top = q(&client.memory(regs.q(regs::RSP), 8)?, 0);
                if top == client.base() + self.relocated(0x53FE9EC)? && self.wire.poses.len() == self.room.members.len() {
                    self.find_spawn(client, regs)?;
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// REMOVE_LOOT: a power-up pickup is shared with the party.
    fn remove_loot(&mut self, client: &mut dyn Client, regs: &Regs) -> Result<()> {
        let (game, index) = (regs.q(regs::RCX), regs.q(regs::RDX));
        if game != client.server() + 0x10 {
            return Err("Loot removal has no owned game".into());
        }
        let head = client.memory(game + self.build.fields.get(0x5C8)?, 16)?;
        let (pointer, count) = (q(&head, 0), q(&head, 8));
        if !(index < count && count <= MAX_NATIVE_OBJECTS) {
            return Err("Loot removal index exceeds owned array".into());
        }
        let kind = u32::from_le_bytes(client.memory(pointer + index * 0x48 + 0x20, 4)?[..4].try_into().unwrap());
        if matches!(kind, 3..=6) {
            let injected = client.saved_context() && q(&client.memory(regs.q(regs::RSP), 8)?, 0) == client.call_return();
            let recipients: Vec<u32> = if injected { self.room.members.clone() } else { self.room.guests.iter().copied().collect() };
            for n in &recipients {
                if self.powerups_pending.entry(*n).or_default().len() >= MAX_QUEUE {
                    return Err("Shared powerup queue exceeds bound".into());
                }
                self.powerups_pending.get_mut(n).unwrap().push(kind as u64);
            }
            client.record(Event::new("shared_powerup_collected").num("kind", kind as f64).list("recipients", recipients.iter().map(|r| *r as f64).collect()));
        }
        Ok(())
    }

    /// HUD_DELIVER: the host's boss bar replaces the guests' own, delivered through a borrowed string.
    fn hud_deliver(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        let raw = client.memory(regs.q(regs::RDX), regs.q(regs::R8) as usize)?;
        let mut payload: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| format!("JSONDecodeError: {e}"))?;
        if number == 1 {
            let object = payload.as_object().ok_or("AttributeError: not a JSON object")?;
            self.host_boss_hud = object.get("boss").cloned();
        } else {
            // HUD receives a borrowed string; the caller still frees its original native allocation.
            let object = payload.as_object_mut().ok_or("TypeError: not a JSON object")?;
            object.insert("boss".into(), self.host_boss_hud.clone().unwrap_or(serde_json::Value::Null));
            let body = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
            if body.len() > 1_048_576 {
                return Err("Native HUD exceeds scratch buffer".into());
            }
            let existing = if number == 2 { self.hud_buffer } else { self.hud_buffers.get(&number).copied().unwrap_or(0) };
            let buffer = if existing == 0 {
                let buffer = client.allocate(1_048_576)?;
                if number == 2 {
                    self.hud_buffer = buffer;
                } else {
                    self.hud_buffers.insert(number, buffer);
                }
                buffer
            } else {
                existing
            };
            client.put(buffer, &body)?;
            regs.set_q(regs::RDX, buffer);
            regs.set_q(regs::R8, body.len() as u64);
        }
        // Emulate the exact indirect CALL [RAX+20], preserving its return.
        let stack = regs.q(regs::RSP) - 8;
        let hud_rva = self.build.profile.hooks.get("HUD_DELIVER").ok_or("profile has no HUD_DELIVER hook")?.rva;
        client.put(stack, &(client.base() + hud_rva + 3).to_le_bytes())?;
        regs.set_q(regs::RSP, stack);
        let target = q(&client.memory(regs.q(regs::RAX) + 0x20, 8)?, 0);
        regs.set_q(regs::RIP, target);
        Ok(())
    }

    /// ENEMY_TARGET: an enemy ability aims at the nearest living player's position.
    fn enemy_target(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        let v47 = self.build.variant.is_47e4();
        let v7264 = self.build.variant.is_7264_family();
        // 0.95.0 family (0.97.1, 0.99.0 checked): the attack event is loaded at this site, edx = kind, r15d = ability id,
        // r14d = count (REA chat); read only, each combination once
        if v7264 && self.attack_kinds_seen.len() < 256 {
            let key = (regs.q(regs::RDX) as u32, regs.q(regs::R15) as u32, regs.q(regs::R14) as u32);
            if self.attack_kinds_seen.insert(key) {
                client.record(Event::new("enemy_attack_kind").num("player", number as f64).num("kind", key.0 as f64)
                    .num("ability", key.1 as f64).num("count", key.2 as f64));
            }
        }
        let game_register = if v47 { regs::RSI } else { regs::R8 };
        let enemy_xmm = if v7264 { 6 } else if v47 { 14 } else { 12 };
        self.validate_live_game(client, regs, game_register, Some(regs::RCX), true)?;
        let enemy_xy = [regs.xmm_f32(enemy_xmm), f32le(&regs.xmm[enemy_xmm], 4)];
        let mut xy = client.memory(regs.q(game_register) + self.build.fields.get(0x488)?, 8)?;
        let player_xy = [f32le(&xy, 0), f32le(&xy, 4)];
        // NaN/inf (an enemy record being torn down): no guest choice, the native target (the host) stays.
        let broken = !enemy_xy.iter().chain(player_xy.iter()).all(|v| v.is_finite());
        if broken {
            let both = |v: [f32; 2]| azcoop_logic::finite_text(&[v[0] as f64, v[1] as f64]);
            azcoop_logic::skips::note(&mut |e| client.record(e), "enemy_target_nonfinite", regs.q(regs::RDX), vec![("enemy", both(enemy_xy)), ("player", both(player_xy))]);
        }
        let mut owner = 1u32;
        // Radial attacks are centered on the enemy. Their native distance check must retain the host position;
        // the guest is checked separately.
        if number == 1 && regs.q(regs::RDX) != 3 && !broken {
            let (x, y) = (enemy_xy[0] as f64, enemy_xy[1] as f64);
            let (hx, hy) = (f32le(&xy, 0) as f64, f32le(&xy, 4) as f64);
            let mut closest = if matches!(self.room.native_states.get(&1).map_or(0, |s| s[0]), 1..=3) { (x - hx).hypot(y - hy) } else { f64::INFINITY };
            for guest in self.room.guests.clone() {
                if !matches!(self.room.native_states.get(&guest).map_or(0, |s| s[0]), 1..=3) {
                    continue;
                }
                let pose = self.wire.poses.get(&guest).ok_or("KeyError: player pose")?;
                let distance = (x - pose[0]).hypot(y - pose[1]);
                if distance < closest {
                    closest = distance;
                    xy = (pose[0] as f32).to_le_bytes().iter().chain((pose[1] as f32).to_le_bytes().iter()).copied().collect();
                    owner = guest;
                }
            }
        }
        regs.xmm[1] = [0u8; 16];
        regs.xmm[1][..8].copy_from_slice(&xy);
        regs.set_q(regs::RIP, client.base() + self.relocated(0x53E5580)?);
        if number == 1 {
            client.record(Event::new("native_enemy_ability_target").num("player", owner as f64).num("owner_verified", 1.0));
        }
        Ok(())
    }

    /// ENEMY_AOE / GROUND_AOE: an area attack; the displaced branch is emulated and the host's attack is
    /// mirrored onto the guests it reaches.
    fn area_attack(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32, radial: bool) -> Result<()> {
        let v47 = self.build.variant.is_47e4();
        let v7264 = self.build.variant.is_7264_family();
        let is_0843 = !v47;
        if v47 {
            self.validate_live_game(client, regs, if radial { if v7264 { regs::RCX } else { regs::RBX } } else { regs::R14 }, None, radial)?;
        } else {
            self.validate_live_game(client, regs, if radial { regs::RDX } else { regs::R15 }, None, false)?;
        }
        let ground_xmm = if v47 { 11 } else { 10 };
        let ground = [regs.xmm_f32(ground_xmm), f32le(&regs.xmm[ground_xmm], 4)];
        // Emulate the displaced unsigned-below branch without changing flags.
        let below = regs.eflags() & 1 != 0;
        let destinations = if radial { (0x53E5430u64, 0x53E6069u64) } else { (0x53E1898, 0x53E1883) };
        let destination = self.relocated(if below { destinations.0 } else { destinations.1 })?;
        regs.set_q(regs::RIP, client.base() + destination);
        if number == 1 {
            let radius_xmm = if v47 { if radial { if v7264 { 9 } else { 6 } } else { 10 } } else { 9 };
            let radius = regs.xmm_f32(radius_xmm) as f64;
            let mut damage = regs.xmm_f32(if v7264 && radial { 8 } else { 7 }) as f64;
            let (attacker, enemy): (u64, Option<[f64; 2]>);
            if radial {
                damage *= regs.xmm_f32(if v7264 { 7 } else if v47 { 12 } else { 8 }) as f64;
                attacker = regs.q(if v7264 { regs::R13 } else { regs::R12 });
                let game = client.server() + 0x10;
                let _ = game;
                let found = {
                    let mut io_regs = Regs::default();
                    let mut io = crate::io::GameIo::new(client, &mut io_regs, &self.build.fields, &mut self.results);
                    crate::before_batch::mirrors!(self, m, m.native_enemy(&mut io, attacker))?
                };
                enemy = found.map(|f| [f.1[0], f.1[1]]);
            } else {
                let frame = regs.q(regs::RBP);
                let slot = self.build.profile.field("game_update_frame", 0x3D0)? as u64;
                attacker = q(&client.memory(frame + slot, 8)?, 0);
                if ground.iter().all(|v| v.is_finite()) {
                    enemy = Some([ground[0] as f64, ground[1] as f64]);
                } else {
                    azcoop_logic::skips::note(&mut |e| client.record(e), "area_attack_nonfinite", attacker, vec![("position", azcoop_logic::finite_text(&[ground[0] as f64, ground[1] as f64]))]);
                    enemy = None; // the native branch still runs; only the guest check is skipped
                }
            }
            let _ = is_0843;
            if !(radius.is_finite() && (0.0..=1000.0).contains(&radius) && damage.is_finite() && (0.0..=MAX_ENEMY_DAMAGE).contains(&damage)) {
                azcoop_logic::skips::note(
                    &mut |e| client.record(e),
                    "area_attack_invalid",
                    attacker,
                    vec![("radius", azcoop_logic::finite_item(radius)), ("damage", azcoop_logic::finite_item(damage))],
                );
                return Ok(());
            }
            let mut guest_hit = false;
            if let (Some(enemy), false, false) = (enemy, self.room.draining, self.room.paused) {
                for guest in self.room.guests.clone() {
                    if self.room.native_states.get(&guest).map_or(0, |s| s[0]) != 1 {
                        continue;
                    }
                    let pose = self.wire.poses.get(&guest).ok_or("KeyError: player pose")?;
                    let hit = (pose[0] - enemy[0]).hypot(pose[1] - enemy[1]) <= radius;
                    guest_hit |= hit;
                    if hit && damage > 0.0 {
                        let clock_address = client.server() + 0x10 + self.build.fields.get(0x85C)?;
                        let clock = f32le(&client.memory(clock_address, 4)?, 0) as f64;
                        self.refresh();
                        let mut io_regs = Regs::default();
                        let mut io = crate::io::GameIo::new(client, &mut io_regs, &self.build.fields, &mut self.results);
                        self.hits.queue_incoming_hit(&mut io, guest, Kind::Areas, Hit { attacker: attacker as i128, damage, clock: None }, Some(clock), self.now);
                    }
                }
            }
            client.record(
                Event::new("native_enemy_area")
                    .num("attacker", attacker as f64)
                    .num("radius", radius)
                    .num("damage", damage)
                    .num("host_hit", (!below) as u8 as f64)
                    .num("guest_hit", guest_hit as u8 as f64)
                    .text("kind", if radial { "radial" } else { "ground" })
                    .num("owner_verified", 1.0),
            );
        }
        Ok(())
    }

    /// FIND_SPAWN: the host's spawn search runs from the position of the player whose turn it is.
    fn find_spawn(&mut self, client: &mut dyn Client, regs: &mut Regs) -> Result<()> {
        let living: Vec<u32> = self.room.members.iter().copied().filter(|n| matches!(self.room.native_states.get(n).map_or(0, |s| s[0]), 1..=3)).collect();
        if living.is_empty() {
            return Ok(());
        }
        let owner = match self.spawn_owner_override.filter(|o| living.contains(o)) {
            Some(owner) => owner, // a front-loaded spawn: the round robin stays where it is
            None => {
                let owner = living[(self.spawn_turn % living.len() as u64) as usize];
                if living.len() > 1 {
                    self.spawn_turn += 1;
                }
                owner
            }
        };
        if self.front_load && !self.front_loaded && !self.spawning_bonus && living.len() > 1 {
            self.front_loaded = true;
            let n = living.len() as u32;
            let per_player = front_per_player(n, self.front_count);
            for _ in 0..per_player {
                for player in &living {
                    self.front_spawns.push_back((self.spawn_kind, *player));
                }
            }
            client.record(Event::new("front_load_queued").num("players", n as f64).num("per_player", per_player as f64).num("kind", self.spawn_kind as f64));
        }
        *self.spawn_counts.entry(owner).or_insert(0) += 1;
        let game = regs.q(regs::RDX);
        let extent = self.build.profile.field("game_extent", 0x8D0)? as usize;
        let mut clone = client.memory(game, extent)?;
        if self.spawn_rng {
            let rng = self.build.fields.get(0x808)? as usize;
            let rng_state = client.memory(self.spawn_clone + rng as u64, 32)?;
            clone[rng..rng + 32].copy_from_slice(&rng_state);
        }
        self.spawn_rng = true;
        let pose = self.wire.poses.get(&owner).copied().ok_or("KeyError: player pose")?;
        let at = self.build.fields.get(0x488)? as usize;
        for (k, v) in pose[..3].iter().enumerate() {
            if v.is_finite() && v.abs() > f32::MAX as f64 {
                return Err("float too large to pack with f format".into());
            }
            clone[at + 4 * k..at + 4 * k + 4].copy_from_slice(&(*v as f32).to_le_bytes());
        }
        client.put(self.spawn_clone, &clone)?;
        regs.set_q(regs::RDX, self.spawn_clone);
        let bonus = self.spawn_bonus();
        if !self.spawning_bonus {
            self.spawn_debt += bonus;
            if self.spawn_debt >= 1.0 {
                if self.bonus_spawns.len() >= MAX_QUEUE {
                    return Err("Spawn bonus queue exceeds bound".into());
                }
                self.bonus_spawns.push(self.spawn_kind);
                self.spawn_debt -= 1.0;
            }
        }
        let mut counts = Vec::new();
        for (n, c) in &self.spawn_counts {
            counts.push(*n as f64);
            counts.push(*c as f64);
        }
        let mut event = Event::new("spawn_allocated").num("player", owner as f64).num("bonus", self.spawning_bonus as u8 as f64).num("multiplier", 1.0 + bonus).list("counts", counts);
        if self.spawn_owner_override.is_some() {
            event = event.num("front", 1.0);
        }
        client.record(event);
        Ok(())
    }

    /// HURT: an enemy hit that lands on the host may be aimed at a guest instead.
    pub(crate) fn hurt(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        #[cfg(feature = "test-hooks")]
        if self.stress.as_ref().is_some_and(|s| s.godmode) {
            return Bridge::skip_function(client, regs); // stress test: every hero is immortal
        }
        if number == 1 && !client.saved_context() {
            self.route_enemy_hit(client, regs)?;
        }
        Ok(())
    }

    fn route_enemy_hit(&mut self, client: &mut dyn Client, regs: &mut Regs) -> Result<()> {
        // NativeCombatBridge: an ordinary projectile's impact record names its victim.
        let stack = regs.q(regs::RSP);
        let (impact_return, victim_slot) = if self.build.variant.is_47e4() {
            let family = self.build.variant.family().ok_or("no family constants")?;
            (family.impact_return, family.impact_victim_slot as u64)
        } else {
            (0x5458E5E, 0x180)
        };
        if regs.q(regs::R9) & 255 == 0 && q(&client.memory(stack, 8)?, 0) == client.base() + impact_return {
            let victim = q(&client.memory(regs.q(regs::RBP) + victim_slot, 8)?, 0);
            if victim != SELF {
                let number = victim as i64 - 0xFF0100;
                let damage = regs.xmm_f32(1) as f64;
                if !damage.is_finite() || !(0.0..=MAX_ENEMY_DAMAGE).contains(&damage) {
                    azcoop_logic::skips::note(&mut |e| client.record(e), "projectile_damage_invalid", regs.q(regs::R8), vec![("damage", azcoop_logic::finite_item(damage))]);
                } else if number > 0 && self.room.guests.contains(&(number as u32)) && self.room.native_states.get(&(number as u32)).map_or(0, |s| s[0]) == 1 {
                    let clock_address = client.server() + 0x10 + self.build.fields.get(0x85C)?;
                    let clock = f32le(&client.memory(clock_address, 4)?, 0) as f64;
                    self.refresh();
                    let mut io_regs = Regs::default();
                    let mut io = crate::io::GameIo::new(client, &mut io_regs, &self.build.fields, &mut self.results);
                    self.hits.queue_incoming_hit(&mut io, number as u32, Kind::Areas, Hit { attacker: regs.q(regs::R8) as i128, damage, clock: None }, Some(clock), self.now);
                }
                let top = q(&client.memory(stack, 8)?, 0);
                regs.set_q(regs::RIP, top);
                regs.set_q(regs::RSP, stack + 8);
                client.record(Event::new("ordinary_projectile_impact").num("player", number as f64).num("attacker", regs.q(regs::R8) as f64).num("damage", damage));
                return Ok(());
            }
        }
        self.base_route_enemy_hit(client, regs)
    }

    /// `Bridge.route_enemy_hit`: redirect an existing melee hit to the nearer participating player.
    fn base_route_enemy_hit(&mut self, client: &mut dyn Client, regs: &mut Regs) -> Result<()> {
        if self.room.draining || self.room.paused || regs.q(regs::R9) & 255 != 1 {
            return Ok(());
        }
        let (game, attacker) = (regs.q(regs::RCX), regs.q(regs::R8));
        let enemies = {
            let mem = crate::write::ClientMem(std::cell::RefCell::new(&mut *client));
            let reader = Reader { mem: &mem, variant: self.build.variant, profile: &self.build.profile, fields: &self.build.fields, base: 0, game };
            let (data, now) = enemy_array(&reader)?;
            let (enemies, skipped) = parse_enemies(&data, now, self.build.variant)?;
            for s in &skipped {
                azcoop_logic::skips::note(&mut |e| client.record(e), "enemy_state_nonfinite", s.guid, vec![("clock", azcoop_logic::finite_item(s.now)), ("fields", azcoop_logic::finite_text(&s.fields))]);
            }
            enemies
        };
        let Some(enemy) = enemies.iter().find(|e| e.guid == attacker && e.hp > 0.0).map(|e| e.position) else { return Ok(()) };
        let living: Vec<u32> = self
            .room
            .members
            .iter()
            .copied()
            .filter(|n| self.room.native_states.get(n).map_or(if *n == 1 { 1 } else { 0 }, |s| s[0]) == 1 && self.wire.poses.contains_key(n))
            .collect();
        if living.is_empty() {
            return Ok(());
        }
        let mut distances = std::collections::BTreeMap::new();
        for number in &living {
            let pose = self.wire.poses[number];
            distances.insert(*number, (0..3).map(|k| (enemy[k] - pose[k]).powi(2)).sum::<f64>());
        }
        let nearest = distances.values().copied().fold(f64::INFINITY, f64::min);
        let tied: Vec<u32> = living.iter().copied().filter(|n| (distances[n] - nearest).abs() < 0.01).collect();
        self.hit_turn += 1;
        let target = tied[(self.hit_turn % tied.len() as u64) as usize];
        let created = |this: &Bridge, who: u32| this.wire.feeds.get(&who).map(|f| f.created.clone()).unwrap_or_default();
        if target == 1 || !created(self, 1).contains(&target) || !created(self, target).contains(&1) {
            return Ok(());
        }
        let head = client.memory(game + self.build.fields.get(0x5E0)?, 16)?;
        let (pointer, count) = (q(&head, 0), q(&head, 8));
        if !(1..=MAX_NATIVE_OBJECTS).contains(&count) {
            return Ok(());
        }
        let packet = client.memory(pointer + (count - 1) * 32, 32)?;
        if u16::from_le_bytes([packet[24], packet[25]]) != 0x14A {
            return Ok(());
        }
        let body = client.memory(q(&packet, 8), q(&packet, 16) as usize)?;
        let mut reader = WireReader::new(&body);
        reader.take(4)?;
        if reader.guid(true, true)? != attacker {
            return Ok(());
        }
        let start = reader.pos;
        if reader.guid(true, true)? != SELF || reader.pos - start != 4 {
            return Ok(());
        }
        let damage = regs.xmm_f32(1) as f64;
        if !damage.is_finite() || !(0.0 < damage && damage <= MAX_HIT_DAMAGE) {
            return Err("Invalid native enemy hit".into());
        }
        // Mark only the victim GUID; batch filtering removes this old host hit.
        client.put(q(&packet, 8) + start as u64, &pack_guid(0xFF0100 + target as u64))?;
        let clock_address = game + self.build.fields.get(0x85C)?;
        let clock = f32le(&client.memory(clock_address, 4)?, 0) as f64;
        self.refresh();
        {
            let mut io_regs = Regs::default();
            let mut io = crate::io::GameIo::new(client, &mut io_regs, &self.build.fields, &mut self.results);
            self.hits.queue_incoming_hit(&mut io, target, Kind::Hits, Hit { attacker: attacker as i128, damage, clock: Some(clock) }, None, self.now);
        }
        let stack = regs.q(regs::RSP);
        let top = q(&client.memory(stack, 8)?, 0);
        regs.set_q(regs::RIP, top);
        regs.set_q(regs::RSP, stack + 8);
        client.record(Event::new("enemy_hit_redirected").num("attacker", attacker as f64).num("damage", damage));
        Ok(())
    }

    /// BOSS_DEATH: the host's boss kill is published as an authoritative notification; a guest's own
    /// prediction never rolls gear.
    fn boss_death(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        let hook_rva = self.build.profile.hooks.get("BOSS_DEATH").ok_or("profile has no BOSS_DEATH hook")?.rva;
        if number == 1 && self.build.variant.is_47e4() {
            // 47e4 hook is INC DWORD [RSI+BOSS_COUNT] (Game in RSI, boss definition in RCX).
            let game = regs.q(regs::RSI);
            if game != client.server() + 0x10 {
                return Err("Boss death hook has no owned game".into());
            }
            let definition = regs.q(regs::RCX);
            let (map_index, boss) = self.boss_identity(client, definition, game)?;
            self.publish_reward(client, map_index, boss)?;
            let counter = game + self.build.profile.field("game", 0x6DC)? as u64;
            let value = u32::from_le_bytes(client.memory(counter, 4)?[..4].try_into().unwrap());
            client.put(counter, &(value.checked_add(1).ok_or("'I' format requires 0 <= number <= 4294967295")?).to_le_bytes())?;
            regs.set_q(regs::RIP, client.base() + hook_rva + 6);
        } else if number == 1 {
            let rbp = regs.q(regs::RBP);
            let slot = self.build.profile.field("damage_frame", 0x178)? as u64;
            let game = q(&client.memory(rbp + slot, 8)?, 0);
            let definition = regs.q(if self.build.variant == azcoop_game::builds::Variant::V0843 { regs::R12 } else { regs::R15 });
            let (map_index, boss) = self.boss_identity(client, definition, game)?;
            self.publish_reward(client, map_index, boss)?;
            regs.set_q(regs::RAX, game);
            regs.set_q(regs::RIP, client.base() + hook_rva + 7);
        } else {
            // Prediction may kill/revive mirrors repeatedly before host death: it must never roll gear or unlock a map speculatively.
            regs.set_q(regs::RIP, client.base() + self.reviewed_rva(0x540CF75)?);
        }
        Ok(())
    }

    /// `boss_identity(client, definition, game)`
    fn boss_identity(&self, client: &mut dyn Client, definition: u64, game: u64) -> Result<(u32, i64)> {
        let (map_index, bosses) = self.native_map(client, game)?;
        let delta = definition as i128 - bosses as i128;
        if (0..5 * 0x58).contains(&delta) && delta % 0x58 == 0 {
            return Ok((map_index, (delta / 0x58) as i64));
        }
        Err("Boss definition does not belong to the selected map".into())
    }
}


/// Front-loaded spawns per living player at the start of a run: the native start brings about 4 enemies in the first 10 s, shared by
/// the `n` players; `ceil(4 (n-1) / n)` more each gives every player about the solo first contact (2 -> 2, 3 -> 3, 4 -> 3).
pub fn front_per_player(n: u32, count: Option<u32>) -> u32 {
    if n <= 1 {
        return 0;
    }
    count.unwrap_or((4 * (n - 1)).div_ceil(n))
}

#[cfg(test)]
mod front_load_tests {
    use super::front_per_player;

    #[test]
    fn every_player_gets_about_the_solo_first_contact() {
        assert_eq!([1, 2, 3, 4].map(|n| front_per_player(n, None)), [0, 2, 3, 3]);
        // native ~4 shared by n plus the front load: at least ~4 per player
        for n in 2..=4u32 {
            let per_player = 4.0 / n as f64 + front_per_player(n, None) as f64;
            assert!((4.0..=5.0).contains(&per_player), "{n} players: {per_player}");
        }
        assert_eq!(front_per_player(2, Some(5)), 5, "the override");
        assert_eq!(front_per_player(1, Some(5)), 0, "solo never front-loads");
    }
}
