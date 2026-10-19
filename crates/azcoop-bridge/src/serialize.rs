//! The SERIALIZE hook: the bootstrap packets of the local player's login. The login template is
//! registered once (it becomes the avatar every other player sees), and in a shared world every
//! bootstrap world packet goes through the same filter as later batches.

use crate::bridge::Bridge;
use crate::client::{Client, Hook, Result};
use crate::regs::{self, Regs};
use azcoop_logic::Event;
use azcoop_world::builders::clone_player;
use azcoop_world::is_world;

/// `01 00 00 00 00 03 07 fe ff ff 04 71`: the verified shape of the local player's create packet.
pub const TEMPLATE_PREFIX: [u8; 12] = [0x01, 0, 0, 0, 0, 0x03, 0x07, 0xFE, 0xFF, 0xFF, 0x04, 0x71];

fn q(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

impl Bridge {
    pub(crate) fn serialize(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        *self.counts.entry("serializer_stops").or_insert(0) += 1;
        if self.server_states.contains_key(&number) {
            // Once bootstrap is delivered, whole queue batches are inspected instead.
            client.disable_hook(Hook::Serialize);
            return Ok(());
        }
        let packet = client.memory(regs.q(regs::RDX), 32)?;
        let size = q(&packet, 16) as usize;
        let opcode = u16::from_le_bytes([packet[24], packet[25]]);
        let registered = self.wire.templates.iter().any(|(n, _)| *n == number);
        if opcode == 0xA9 && !registered {
            let body = client.memory(q(&packet, 8), size)?;
            if body.len() >= 12 && body[..12] == TEMPLATE_PREFIX {
                if body.len() < 36 {
                    return Err("unpack_from requires a buffer of at least 36 bytes".into());
                }
                let f = |at: usize| f32::from_le_bytes(body[at..at + 4].try_into().unwrap()) as f64;
                let pose = [f(20), f(24), f(28), f(32)];
                let guid = 0xFF0100 + number as u64;
                clone_player(&body, guid, pose)?; // Validate before registering.
                self.wire.templates.push((number, body.clone()));
                if !self.shared_world {
                    client.disable_hook(Hook::Serialize);
                }
                self.wire.feeds.entry(number).or_default().created.clear();
                self.registered.insert(number);
                if self.wire.poses.contains_key(&number) {
                    return Err("Player ID must be unique and owned by an account".into());
                }
                if !pose.iter().all(|v| v.is_finite()) {
                    return Err("Invalid initial pose".into());
                }
                self.wire.poses.insert(number, pose);
                client.record(Event::new("player_registered").num("player", number as f64).num("guid", guid as f64));
                let hex: String = body.iter().map(|b| format!("{b:02x}")).collect();
                client.record(Event::new("native_player_create").num("player", number as f64).text("body", &hex));
            }
        }
        if self.shared_world && (is_world(opcode) || opcode == 0x51) {
            let body = client.memory(q(&packet, 8), size)?;
            match self.filter_packet_native(client, number, opcode, &body)? {
                None => {
                    let stack = regs.q(regs::RSP);
                    let return_address = q(&client.memory(stack, 8)?, 0);
                    regs.skip_with(return_address);
                }
                Some(filtered) if filtered != body => {
                    if filtered.len() as u64 > q(&packet, 0) {
                        return Err("Filtered bootstrap exceeds native allocation".into());
                    }
                    client.put(q(&packet, 8), &filtered)?;
                    client.put(regs.q(regs::RDX) + 16, &(filtered.len() as u64).to_le_bytes())?;
                }
                Some(_) => {}
            }
        }
        self.flush_outputs();
        Ok(())
    }
}
