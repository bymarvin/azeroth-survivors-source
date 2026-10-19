//! The server-direction queue write: the batch the game sends its own client. Before it is let
//! through the bridge applies what is owed to this game (shared pause, revival, talents, hits,
//! rewards: `before_batch`), then filters the batch, appends what this player must see and
//! re-encrypts it into a scratch buffer the write is redirected to.

use crate::bridge::Bridge;
use crate::client::{CallSpec, Client, Hook, Result};
use crate::io::GameIo;
use crate::regs::{self, Regs};
use crate::write::ClientMem;
use azcoop_game::readers::{melee_stats, progress_state, Reader};
use azcoop_logic::apply_hit::Clocks;
use azcoop_logic::Event;
use azcoop_world::builders::{character_name, minimap_packet, raid_packet};
use azcoop_world::rebuild::{decode_native, rebuild_append, Event as WireEvent, RetargetInfo};
use azcoop_world::MAX_QUEUE;
use std::collections::BTreeMap;

fn q(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Bridge {
    /// `relocated(legacy)`: this build's RVA of a legacy address.
    pub(crate) fn relocated(&self, legacy: u64) -> Result<u64> {
        self.reviewed_rva(azcoop_game::builds::reviewed(legacy)?)
    }

    /// `replace_downed_ui(client, pointer, count, replacement)`: the game's own UI strings of this batch.
    fn replace_downed_ui(client: &mut dyn Client, pointer: u64, count: u64, replacement: Option<&[u8]>) -> Result<u64> {
        if count > MAX_QUEUE as u64 {
            return Err("Native UI batch exceeds bound".into());
        }
        let mut replaced = 0;
        for i in 0..count {
            let entry = client.memory(pointer + i * 24, 24)?;
            let (capacity, address, length) = (q(&entry, 0), q(&entry, 8), q(&entry, 16));
            if length > capacity || length > 1_048_576 {
                return Err("Invalid native UI string".into());
            }
            let body = client.memory(address, length as usize)?;
            if body.windows(6).any(|w| w == b"defeat") {
                let parsed: serde_json::Value = serde_json::from_slice(&body).map_err(|e| format!("JSONDecodeError: {e}"))?;
                let object = parsed.as_object().ok_or("AttributeError: not a JSON object")?;
                if object.get("type").and_then(|t| t.as_str()) == Some("defeat") {
                    if let Some(replacement) = replacement {
                        if replacement.len() as u64 > capacity {
                            return Err("Native UI allocation too small".into());
                        }
                        client.put(address, replacement)?;
                        client.put(pointer + i * 24 + 16, &(replacement.len() as u64).to_le_bytes())?;
                    }
                    replaced += 1;
                }
            }
        }
        Ok(replaced)
    }

    /// The part of `Bridge.__call__` after the client-direction branch (`queue == server queue`).
    pub(crate) fn server_direction(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32, pointer: u64, connection: &[u8]) -> Result<()> {
        let ui_return = |this: &Bridge, client: &mut dyn Client, regs: &Regs| -> Result<bool> {
            let top = q(&client.memory(regs.q(regs::RSP), 8)?, 0);
            Ok(top == client.base() + this.relocated(0x539FC26)?)
        };
        if self.leave_requested && ui_return(self, client, regs)? {
            // Leaving the run properly (the host left): the native "back to character select" command runs the run evaluation and the
            // save, from any phase. Same way in as the victory choice below.
            self.leave_requested = false;
            let phase = self.room.native_states.get(&number).map_or(0, |s| s[0]);
            if !self.command_buffers.contains_key(&number) {
                let buffer = client.allocate(0xE8)?;
                self.command_buffers.insert(number, buffer);
            }
            let buffer = self.command_buffers[&number];
            let mut payload = 9u32.to_le_bytes().to_vec();
            payload.extend_from_slice(&[0u8; 0xE4]);
            client.put(buffer, &payload)?;
            self.room.end_pending.remove(&number);
            self.menu_players.insert(number);
            let server = client.server();
            client.call_before(regs, CallSpec::new(Hook::UiCommand, server, buffer))?;
            client.record(Event::new("leave_applied").num("player", number as f64).num("phase", phase as f64));
            return Ok(());
        }
        if self.room.end_pending.contains_key(&number) && ui_return(self, client, regs)? {
            let command = self.room.end_pending[&number];
            let boss_pending = self.boss_reward_pending.get(&number).is_some_and(|p| !p.is_empty());
            if self.room.native_states.get(&number).map_or(0, |s| s[0]) == 5 && !boss_pending {
                self.completed_transition(client, regs, number, command, None);
                if !self.command_buffers.contains_key(&number) {
                    let buffer = client.allocate(0xE8)?;
                    self.command_buffers.insert(number, buffer);
                }
                let buffer = self.command_buffers[&number];
                let mut payload = command.to_le_bytes().to_vec();
                payload.extend_from_slice(&[0u8; 0xE4]);
                client.put(buffer, &payload)?;
                self.room.end_pending.remove(&number);
                if command == 9 {
                    self.menu_players.insert(number);
                }
                let server = client.server();
                client.call_before(regs, CallSpec::new(Hook::UiCommand, server, buffer))?;
                client.record(Event::new("victory_action_applied").num("player", number as f64).num("command", command as f64));
                return Ok(());
            }
        }
        if self.shared_world && ui_return(self, client, regs)? {
            // This native batch owns a separate UI-string vector, not chat packets.
            let frame = regs.q(regs::RBP);
            let profile = &self.build.profile;
            let ui_pointer = q(&client.memory(frame + profile.field("batch_frame", 0x998)? as u64, 8)?, 0);
            let ui_count = q(&client.memory(frame + profile.field("batch_frame", 0x9A0)? as u64, 8)?, 0);
            let others_alive = self.room.members.iter().any(|n| *n != number && self.room.native_states.get(n).map_or(4, |s| s[0]) != 4);
            if others_alive && Bridge::replace_downed_ui(client, ui_pointer, ui_count, Some(b"{\"type\":\"unpaused\"}"))? > 0 {
                client.record(Event::new("downed_ui_replaced").num("player", number as f64));
            } else if self.room.team_defeat.contains(&number) && Bridge::replace_downed_ui(client, ui_pointer, ui_count, None)? > 0 {
                if self.defeat_delivered_logged.insert(number) {
                    client.record(Event::new("team_defeat_delivered").num("player", number as f64));
                }
            } else if self.trace_defeat_ui && Bridge::replace_downed_ui(client, ui_pointer, ui_count, None)? > 0 {
                // the game shows its own defeat screen and neither branch above claimed it: say why (phases of every member, -1 = unknown)
                let phase = |n: u32| self.room.native_states.get(&n).map_or(-1.0, |s| s[0] as f64);
                let mut event = Event::new("defeat_ui_passed").num("player", number as f64).num("others_alive", others_alive as u8 as f64).num("team_defeat", self.room.team_defeat.contains(&number) as u8 as f64);
                for member in &self.room.members {
                    event = event.num(&format!("phase{member}"), phase(*member));
                }
                client.record(event);
            }
        }
        let mut phase = 0u64;
        if self.shared_world {
            let game = client.server() + 0x10;
            self.check_loading(client);
            let state = {
                let mem = ClientMem(std::cell::RefCell::new(&mut *client));
                let reader = Reader { mem: &mem, variant: self.build.variant, profile: &self.build.profile, fields: &self.build.fields, base: 0, game };
                progress_state(&reader, self.room.ready.contains(&number))?
            };
            let (p, level, xp, pending) = state;
            phase = p as u64;
            if self.room.draining && self.results.result_open.contains_key(&number) {
                let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
                let mut results = std::mem::take(io.results);
                let outcome = results.keep_open_result(&mut io, number);
                *io.results = results;
                outcome?; // The run ends here without another evaluation of it.
            }
            let clock_address = game + self.build.fields.get(0x85C)?;
            if number == 1 && self.room.ready.contains(&1) {
                self.room.host_clock = f32::from_le_bytes(client.memory(clock_address, 4)?[..4].try_into().unwrap()) as f64;
            } else if self.room.ready.contains(&number) {
                client.put(clock_address, &(self.room.host_clock as f32).to_le_bytes())?;
            }
            if number == 2 && self.room.ready.contains(&2) {
                let base = client.base();
                let mem = ClientMem(std::cell::RefCell::new(&mut *client));
                let reader = Reader { mem: &mem, variant: self.build.variant, profile: &self.build.profile, fields: &self.build.fields, base, game };
                self.guest_stats = melee_stats(&reader, p)?;
            }
            if number == 1 {
                let any_guest_playing = self.room.guests.iter().any(|n| self.room.native_states.get(n).map_or(0, |s| s[0]) == 1);
                let enabled = !self.room.draining && !self.room.paused && any_guest_playing;
                client.put(self.world_enable, &[enabled as u8])?;
                // Choosing/paused players remain alive targets; do not trigger enemy leashing.
                for (index, guest) in self.pursuit_guests.clone().into_iter().enumerate() {
                    let slot = self.guest_target + index as u64 * 16;
                    if let Some(pose) = self.wire.poses.get(&guest).copied() {
                        let mut value = Vec::new();
                        for v in [pose[0], pose[1], pose[2]] {
                            value.extend_from_slice(&(v as f32).to_le_bytes());
                        }
                        let alive = matches!(self.room.native_states.get(&guest).map_or(0, |s| s[0]), 1..=3);
                        value.extend_from_slice(&(alive as u32).to_le_bytes());
                        client.put(slot, &value)?;
                    } else {
                        client.put(slot, &[0u8; 16])?;
                    }
                }
            }
            let state_now = [p as u64, level as u64, xp as u64, pending as u64];
            if self.room.native_states.get(&number) != Some(&state_now) {
                let previous = self.room.native_states.get(&number).copied();
                if let Some(prev) = previous {
                    if prev[3] > state_now[3] {
                        client.record(
                            Event::new("native_talent_spent")
                                .num("player", number as f64)
                                .num("count", (prev[3] - state_now[3]) as f64)
                                .num("remaining", pending as f64)
                                .num("level", level as f64),
                        );
                    }
                }
                self.room.native_states.insert(number, state_now);
                if matches!(p, 1..=3) && previous.map_or(true, |prev| matches!(prev[0], 0 | 5)) {
                    let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
                    let mut results = std::mem::take(io.results);
                    let outcome = results.remember_result_xp(&mut io, number);
                    *io.results = results;
                    outcome?; // Run start, or playing on after a victory.
                }
                client.record(Event::new("native_state").num("player", number as f64).num("phase", p as f64).num("level", level as f64).num("xp", xp as f64).num("talents_due", pending as f64));
                self.refresh();
                let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
                self.room.native_phase_changed(&mut io, number, previous, state_now)?;
                self.flush_outputs();
            }
            if self.loaded.len() == self.room.members.len() && self.room.ready.contains(&number) && p == 0 {
                client.call_before(regs, CallSpec::new(Hook::Start, game, 0))?;
                return Ok(());
            }
            self.refresh();
            let mirrored = {
                let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
                self.economy.mirror_xp(&mut io, number, phase)?
            };
            self.flush_outputs();
            if mirrored {
                return Ok(());
            }
        }
        if self.room.pause_pending.contains_key(&number) && self.room.ready.contains(&number) {
            self.refresh();
            let called = {
                let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
                self.room.apply_pause_pending(&mut io, number)?
            };
            self.flush_outputs();
            if called {
                return Ok(());
            }
        }
        if self.shared_world && self.room.ready.contains(&number) {
            self.refresh();
            let revived = {
                let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
                self.room.sync_revival(&mut io, number)?
            };
            self.flush_outputs();
            if revived {
                return Ok(());
            }
            let talents = {
                let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
                self.economy.sync_talents(&mut io, number)?
            };
            self.flush_outputs();
            if talents {
                return Ok(());
            }
            if self.before_batch(client, regs)? {
                return Ok(());
            }
        }
        {
            // This write now proceeds: its hit chain ends here.
            self.refresh();
            let clocks = Clocks { perf: self.perf, mono: self.now };
            let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
            self.applier.hit_batch_written(&mut io, number, clocks);
        }
        self.rebuild_server_batch(client, regs, number, pointer, connection, phase as u32)
    }

    /// `check_loading()`
    fn check_loading(&mut self, client: &mut dyn Client) {
        if self.loaded.len() == self.room.members.len() || self.now < self.loading_check {
            return;
        }
        self.loading_check = self.now + self.loading_poll;
        for number in self.clients.clone() {
            if self.loaded.contains(&number) {
                continue;
            }
            if client.loading_cleared(number) {
                self.loaded.insert(number);
                client.record(Event::new("client_loaded").num("player", number as f64));
            }
        }
    }

    /// The tail of the handler: filter, extend and re-encrypt the game's batch.
    fn rebuild_server_batch(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32, pointer: u64, connection: &[u8], host_phase: u32) -> Result<()> {
        let original = client.memory(regs.q(regs::RDX), regs.q(regs::R8) as usize)?;
        let batch_start = self.server_states.get(&number).copied();
        let key = &connection[0x31..0x59];
        let end = (connection[0x59] as usize, connection[0x5A]);
        if batch_start.is_some() {
            *self.counts.entry("batch_reads").or_insert(0) += 1;
        }
        self.refresh();
        let retarget = RetargetInfo::of(&self.wire);
        let native = {
            let mut filter = |opcode: u16, body: Vec<u8>| -> Result<Option<Vec<u8>>> { self.filter_packet_native(client, number, opcode, &body) };
            decode_native(number, &original, key, batch_start, end, host_phase, &retarget, &mut filter)?
        };
        self.refresh();
        let now = self.now;
        let rebuilt = {
            let Bridge { wire, room, raid_assignments, raid_sent, minimap_sent, menu_players, restart_requested, registered, .. } = self;
            let own = room.own_number.unwrap_or(1);
            let mut marker_events: Vec<Event> = Vec::new();
            let mut markers = |wire: &azcoop_world::rebuild::Bridge, packets: &mut Vec<(u16, Vec<u8>)>| -> Result<()> {
                // party_markers.append_markers: the raid board and the minimap snapshot.
                let active = !room.draining && !*restart_requested && menu_players.is_empty() && room.native_states.get(&1).map_or(0, |s| s[0]) != 5;
                if own == 1 && !active {
                    raid_assignments.clear();
                }
                let assignments: BTreeMap<u32, u8> = if active { raid_assignments.clone() } else { BTreeMap::new() };
                if !registered.contains(&number) {
                    return Err("KeyError: created".into());
                }
                let visible: Vec<u32> = wire.feeds.get(&number).map(|f| f.created.iter().copied().collect()).unwrap_or_default();
                let board = raid_packet(&assignments, number, &visible);
                if raid_sent.get(&number) != Some(&board) {
                    packets.push(board.clone());
                    raid_sent.insert(number, board.clone());
                    let mut flat = Vec::new();
                    for (player, icon) in &assignments {
                        flat.push(*player as f64);
                        flat.push(*icon as f64);
                    }
                    marker_events.push(Event::new("raid_markers_written").num("recipient", number as f64).list("assignments", flat).text("body", &hex(&board.1)));
                }
                if now - minimap_sent.get(&number).copied().unwrap_or(0.0) < 0.1 {
                    return Ok(());
                }
                minimap_sent.insert(number, now);
                let mut rows = Vec::new();
                if active && room.ready.contains(&number) {
                    let origin = wire.poses.get(&number).ok_or("KeyError: pose")?;
                    for player in &room.members {
                        if *player == number || !wire.feeds.get(&number).is_some_and(|f| f.created.contains(player)) {
                            continue;
                        }
                        let pose = wire.poses.get(player).ok_or("KeyError: pose")?;
                        let name = match wire.name_responses.get(player) {
                            Some(body) => character_name(body)?,
                            None => format!("Player {player}"),
                        };
                        rows.push((*player, pose[0] - origin[0], pose[1] - origin[1], room.native_states.get(player).map_or(0, |s| s[0]) == 4, name));
                    }
                }
                let downed = active && room.native_states.get(&number).map_or(0, |s| s[0]) == 4;
                packets.push(minimap_packet(&rows, downed));
                Ok(())
            };
            let rebuilt = rebuild_append(wire, number, native, &original, key, batch_start, end, &mut markers)?;
            (rebuilt, marker_events)
        };
        let (rebuilt, marker_events) = rebuilt;
        if rebuilt.world_bytes_reset {
            self.world.world_bytes = 0;
        }
        *self.counts.entry("created").or_insert(0) += rebuilt.created;
        *self.counts.entry("relayed").or_insert(0) += rebuilt.relayed;
        *self.counts.entry("world_delivered").or_insert(0) += rebuilt.world_delivered;
        let mut marker_events = Some(marker_events);
        for event in &rebuilt.events {
            match event {
                WireEvent::Display { guid, display } => {
                    self.wire.remote_display.insert(*guid, *display);
                    if self.remote_display_seen.get(&(number, *guid)) != Some(display) {
                        self.remote_display_seen.insert((number, *guid), *display);
                        client.record(Event::new("remote_display_delivered").num("recipient", number as f64).num("player", (*guid as i64 - 0xFF0100) as f64).num("display", *display as f64));
                    }
                }
                WireEvent::RemoteCreate { player, guid } => {
                    client.record(Event::new("remote_create").num("recipient", number as f64).num("player", *player as f64).num("guid", *guid as f64));
                }
                WireEvent::SharedProgress { progress } => {
                    client.record(Event::new("shared_progress").num("recipient", number as f64).list("progress", progress.iter().map(|x| *x as f64).collect()));
                }
                WireEvent::AttackDelivered { opcode, body } => {
                    client.record(Event::new("guest_attack_delivered").num("recipient", number as f64).num("opcode", *opcode as f64).text("body", &hex(body)));
                }
                WireEvent::HurtDelivered { opcode, body } => {
                    client.record(Event::new("guest_hurt_delivered").num("recipient", number as f64).num("opcode", *opcode as f64).text("body", &hex(body)));
                }
                WireEvent::RemotePose { player, pose, opcode, body } => {
                    client.record(
                        Event::new("remote_pose")
                            .num("recipient", number as f64)
                            .num("player", *player as f64)
                            .list("pose", pose.to_vec())
                            .num("synthetic", 0.0)
                            .num("opcode", *opcode as f64)
                            .text("body", &hex(body)),
                    );
                }
                WireEvent::Markers => {
                    for e in marker_events.take().unwrap_or_default() {
                        client.record(e);
                    }
                }
                WireEvent::Created { .. } | WireEvent::Named { .. } => {}
            }
        }
        if self.shared_world {
            self.server_states.insert(number, rebuilt.end);
        }
        let Some(data) = rebuilt.data else { return Ok(()) };
        if data.len() > 1_048_576 {
            return Err(format!("Rebuilt server batch of {} bytes exceeds the 1 MiB buffer", data.len()));
        }
        if !self.buffers.contains_key(&number) {
            let buffer = client.allocate(1_048_576)?;
            self.buffers.insert(number, buffer);
        }
        let address = self.buffers[&number];
        client.put(address, &data)?;
        client.put(pointer + 0x59, &[rebuilt.end.0 as u8, rebuilt.end.1])?;
        regs.set_q(regs::RDX, address);
        regs.set_q(regs::R8, data.len() as u64);
        for event in &rebuilt.events {
            match event {
                WireEvent::Created { player, body } => {
                    client.record(Event::new("remote_player_create_written").num("recipient", number as f64).num("player", *player as f64).text("body", &hex(body)));
                }
                WireEvent::Named { player, body } => {
                    let name = character_name(body)?;
                    client.record(Event::new("remote_character_name_written").num("recipient", number as f64).num("player", *player as f64).text("name", &name).text("body", &hex(body)));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
