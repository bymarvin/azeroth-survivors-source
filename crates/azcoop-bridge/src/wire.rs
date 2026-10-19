//! The wire side of the bridge state: derived copies shared by the logic modules, the packet filter
//! with its effects, host-world capture with the aura overlay, and the per-recipient output queues.

use crate::bridge::Bridge;
use crate::client::Result;
use azcoop_world::filter::{filter_packet, Action, FilterCtx};
use azcoop_world::{values_packet, UPDATE};

impl Bridge {
    /// Brings the derived copies in line with the canonical state: the logic modules keep their own
    /// views of members, phases, poses and flags, the wire state keeps poses with facing.
    pub fn refresh(&mut self) {
        let members = self.room.members.clone();
        let guests: Vec<u32> = members.iter().copied().filter(|m| self.room.guests.contains(m)).collect();
        self.wire.members = members.clone();
        self.wire.guests = guests.clone();
        self.wire.shared_world = self.shared_world;
        self.wire.all_present = self.wire.poses.len() == members.len();
        self.wire.phases = self.room.native_states.iter().map(|(k, v)| (*k, v[0] as u32)).collect();
        self.room.poses = self.wire.poses.iter().map(|(k, p)| (*k, [p[0], p[1], p[2]])).collect();
        let e = &mut self.economy;
        e.members = members;
        e.guests = guests;
        e.native_states = self.room.native_states.clone();
        e.ready = self.room.ready.clone();
        e.draining = self.room.draining;
        e.paused = self.room.paused;
        e.poses = self.room.poses.clone();
    }

    /// Moves what a logic module queued for the players into the per-recipient output queues, in order.
    pub fn flush_outputs(&mut self) {
        // The maps keep one (possibly empty) queue per member: the logic appends to every queue.
        for (n, packets) in self.room.notice.iter_mut() {
            self.wire.feeds.entry(*n).or_default().notice_packets.append(packets);
        }
        for (n, packets) in self.room.hurt.iter_mut() {
            self.wire.feeds.entry(*n).or_default().hurt_packets.append(packets);
        }
        for (n, packets) in self.economy.notice.iter_mut() {
            self.wire.feeds.entry(*n).or_default().notice_packets.append(packets);
        }
    }

    /// `Bridge.filter_packet(number, opcode, body)` of the base class: `None` drops the packet.
    pub fn filter_base(&mut self, client: &mut dyn crate::client::Client, number: u32, opcode: u16, body: &[u8]) -> Result<Option<Vec<u8>>> {
        self.refresh();
        let (action, effects) = {
            let ctx = FilterCtx {
                number,
                members: &self.wire.members,
                guests: &self.wire.guests,
                own_name_response: self.wire.name_responses.get(&number).map(Vec::as_slice),
            };
            filter_packet(&ctx, opcode, body)?
        };
        if let Some(registered) = effects.register_name_response {
            let name = azcoop_world::builders::character_name(&registered)?;
            let hex: String = registered.iter().map(|b| format!("{b:02x}")).collect();
            self.wire.name_responses.insert(number, registered);
            client.record(azcoop_logic::Event::new("character_name_registered").num("player", number as f64).text("name", &name).text("body", &hex));
        }
        if let Some(other) = effects.name_query {
            self.wire.feeds.entry(number).or_default().name_queries.insert(other);
        }
        if effects.capture_world {
            self.capture_world(opcode, body)?;
        }
        if effects.progress_resend {
            self.wire.feeds.entry(number).or_default().progress_sent = None;
        }
        if effects.suppressed {
            *self.counts.entry("guest_suppressed").or_insert(0) += 1;
        }
        Ok(match action {
            Action::Keep(filtered) => Some(filtered),
            Action::Drop => None,
        })
    }

    /// `capture_world(opcode, body)` of NativeCombatBridge: replicate the host's world packet to the
    /// guests, observe it for the aura overlay, and emit overlay updates that became due.
    pub fn capture_world(&mut self, opcode: u16, body: &[u8]) -> Result<()> {
        let guests = self.wire.guests.clone();
        let deliveries = {
            let feeds = &self.wire.feeds;
            let queued = |recipient: u32| feeds.get(&recipient).map_or(0, |f| f.world_pending.iter().map(|(_, d)| d.len() + 4).sum());
            let overlay = &mut self.overlay;
            self.world.capture(opcode, body, &guests, &queued, &mut |blocks, destroyed| {
                for block in blocks {
                    overlay.host_block(block);
                }
                if let Some(guid) = destroyed {
                    overlay.destroy(guid);
                }
            })?
        };
        self.wire.progress = self.world.host_progress;
        for delivery in deliveries {
            self.wire.feeds.entry(delivery.recipient).or_default().world_pending.push((delivery.opcode, delivery.body));
            *self.counts.entry("world_captured").or_insert(0) += 1;
        }
        if !self.overlay.dirty.is_empty() {
            self.emit_aura_overlay()?;
        }
        Ok(())
    }

    /// Only after this host block is queued: a host write to a shared packed aura field must reach every
    /// client before our composed value.
    fn emit_aura_overlay(&mut self) -> Result<()> {
        for (guid, fields) in self.overlay.updates(&self.world.world_guids) {
            let packet = values_packet(guid, &fields)?;
            for recipient in self.wire.guests.clone() {
                self.wire.feeds.entry(recipient).or_default().world_pending.push((UPDATE, packet.clone()));
                *self.counts.entry("world_captured").or_insert(0) += 1;
            }
            self.wire.feeds.entry(1).or_default().notice_packets.push((UPDATE, packet));
        }
        Ok(())
    }
}
