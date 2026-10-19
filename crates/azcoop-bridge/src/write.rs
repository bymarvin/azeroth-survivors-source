//! The WRITE hook: the game's native queue writes. The client-direction queue carries the local
//! player's own packets (movement is relayed to the other players); the server-direction queue is
//! the batch the game sends its own client, which the bridge filters, extends and re-encrypts.

use crate::bridge::Bridge;
use crate::client::{Client, Result};
use crate::regs::{self, Regs};
use azcoop_logic::Event;
use azcoop_world::session::{decode_ground_movement, is_movement_opcode, ClientFrames, HeaderCipher};
use azcoop_world::{pack_guid, MAX_QUEUE};

fn q(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

impl Bridge {
    /// `Bridge.__call__` for `rva == WRITE` (visibility_bridge.py) with the NativeCombat/BossRewards wrappers.
    pub(crate) fn write(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        if number == 1 && self.pursuit_guard != 0 {
            let guard = client.memory(self.pursuit_guard, 16)?;
            let (failed, checks) = (q(&guard, 0), q(&guard, 8));
            if failed != 0 {
                return Err("Native pursuit owner/vector/SIMD guard failed".into());
            }
            if checks != 0 && !self.pursuit_guard_observed {
                self.pursuit_guard_observed = true;
                client.record(Event::new("native_pursuit_guard").num("checks", checks as f64));
            }
        }
        self.clients.insert(number);
        self.client_saved = client.saved_context();
        if self.menu_players.contains(&number) {
            return Ok(()); // Native character-selection lifecycle owns this server again.
        }
        if client.server() == 0 {
            return Ok(());
        }
        let head = client.memory(client.server() + self.build.connections, 16)?;
        let (pointer, count) = (q(&head, 0), q(&head, 8));
        if count != 1 {
            return Ok(());
        }
        let connection = client.memory(pointer, 0xB0)?;
        if connection[0x30] != 1 {
            return Ok(());
        }
        if self.native_connection_replaced(client, number, &connection) {
            return Ok(());
        }
        let queue = regs.q(regs::RCX);
        if queue == q(&connection, 0x88) + 0x10 {
            return self.client_direction(client, regs, number, &connection);
        }
        if queue != q(&connection, 0x90) + 0x10 || !self.wire.templates.iter().any(|(n, _)| *n == number) {
            return Ok(());
        }
        self.server_direction(client, regs, number, pointer, &connection)
    }

    /// `native_connection_replaced(number, connection)`: a new native world/connection for a player this
    /// session already mirrors. Its cipher keys no longer match the parsers and batch states of this run:
    /// stop mirroring that client and end the session cleanly.
    fn native_connection_replaced(&mut self, client: &mut dyn Client, number: u32, connection: &[u8]) -> bool {
        let mut keys = connection[0x31..0x59].to_vec();
        keys.extend_from_slice(&connection[0x5B..0x83]);
        let known = self.connection_keys.entry(number).or_insert_with(|| keys.clone());
        if *known == keys {
            return false;
        }
        self.menu_players.insert(number);
        self.stop_requested = true;
        client.record(Event::new("native_world_restarted").num("player", number as f64));
        client.record(Event::new("party_restart_requires_lobby").num("player", number as f64));
        true
    }

    /// The local player's own input stream: movement is validated, stored and relayed to the others.
    fn client_direction(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32, connection: &[u8]) -> Result<()> {
        if !self.parsers.contains_key(&number) {
            let mut cipher = HeaderCipher::new(&connection[0x5B..0x83])?;
            cipher.index = connection[0x83] as usize;
            cipher.previous = connection[0x84];
            self.parsers.insert(number, ClientFrames::new(Some(cipher)));
        }
        let data = client.memory(regs.q(regs::RDX), regs.q(regs::R8) as usize)?;
        let frames = self.parsers.get_mut(&number).unwrap().feed(&data)?;
        for (opcode, body) in frames {
            if is_movement_opcode(opcode) && self.wire.templates.iter().any(|(n, _)| *n == number) {
                // Reject unsupported modes before touching the session parser.
                let pose = match decode_ground_movement(&body) {
                    Ok(pose) => pose,
                    Err(_) => {
                        *self.counts.entry("unsupported_moves").or_insert(0) += 1;
                        if self.counts["unsupported_moves"] <= 5 {
                            let flags: String = body.iter().take(4).map(|b| format!("{b:02x}")).collect();
                            client.record(
                                Event::new("unsupported_movement")
                                    .num("player", number as f64)
                                    .num("opcode", opcode as f64)
                                    .num("length", body.len() as f64)
                                    .text("flags", &flags),
                            );
                        }
                        continue;
                    }
                };
                // `router.receive(...)`: the selected character's pose.
                if !self.wire.poses.contains_key(&number) {
                    return Err("Movement before player login".into());
                }
                self.wire.poses.insert(number, [pose.x as f64, pose.y as f64, pose.z as f64, pose.facing as f64]);
                self.latest_movement.insert(number, (opcode, body.clone()));
                // Preserve every transition: a later heartbeat must not overwrite jump/landing before the next network batch.
                for recipient in self.room.members.clone() {
                    if recipient != number {
                        let feed = self.wire.feeds.entry(recipient).or_default();
                        if feed.notice_packets.len() >= MAX_QUEUE {
                            return Err("Movement notice queue exceeds bound".into());
                        }
                        let mut payload = pack_guid(0xFF0100 + number as u64);
                        payload.extend_from_slice(&body);
                        feed.notice_packets.push((opcode as u16, payload));
                    }
                }
                *self.counts.entry("native_moves").or_insert(0) += 1;
                let hex: String = body.iter().map(|b| format!("{b:02x}")).collect();
                client.record(Event::new("native_movement").num("player", number as f64).num("opcode", opcode as f64).text("body", &hex));
            }
        }
        Ok(())
    }
}

/// A client as the readers' memory view.
pub struct ClientMem<'a>(pub std::cell::RefCell<&'a mut dyn Client>);

impl azcoop_game::readers::Mem for ClientMem<'_> {
    fn read(&self, address: u64, len: usize) -> Result<Vec<u8>> {
        self.0.borrow_mut().memory(address, len)
    }
}
