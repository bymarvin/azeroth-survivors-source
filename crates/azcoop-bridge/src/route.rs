//! `route_projectile`: an ordinary ranged enemy's cast is aimed at the nearest living player. The
//! native projectile record is re-addressed and its flight time recomputed for a guest target.

use crate::bridge::{Bridge, MAX_ENEMIES};
use crate::client::{Client, Result};
use crate::regs::Regs;
use azcoop_logic::Event;
use azcoop_world::{remap_combat, Reader, SELF};
use std::collections::HashMap;

const MAX_NATIVE_OBJECTS: u64 = 1_000_000;

fn q(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

/// All ordinary ranged spells in the nine 0.84.3 maps; values verified against native speed helper 5497C50.
fn projectile_speed(spell: u32) -> Option<f64> {
    Some(match spell {
        116 => 28.0,
        133 => 24.0,
        403 => 20.0,
        589 => 0.0,
        686 => 20.0,
        8092 => 0.0,
        11366 => 24.0,
        _ => return None,
    })
}

impl Bridge {
    pub(crate) fn route_projectile(&mut self, client: &mut dyn Client, opcode: u16, body: &[u8]) -> Result<Vec<u8>> {
        if opcode != 0x131 && opcode != 0x132 {
            return Ok(body.to_vec());
        }
        let mut reader = Reader::configured(body, false, 0xFF0101, None, None);
        let attacker = reader.guid(true, false)?;
        reader.guid(true, false)?;
        let spell = reader.integer(4)? as u32;
        let now_clock = self.now;
        let enemy = {
            let mut regs = Regs::default();
            let mut io = crate::io::GameIo::new(client, &mut regs, &self.build.fields, &mut self.results);
            let economy = &mut self.economy;
            self.mirrors.bound_dropped = economy.bound_dropped.clone();
            self.mirrors.bound_logged = economy.bound_logged.clone();
            let found = self.mirrors.lookup(&mut io, attacker, now_clock);
            economy.bound_dropped = self.mirrors.bound_dropped.clone();
            economy.bound_logged = self.mirrors.bound_logged.clone();
            found?
        };
        let Some(enemy) = enemy else { return Ok(body.to_vec()) };
        let definition_offset = (self.build.variant.enemy_offset(0x80) - 0x68) as usize;
        let definition = q(&enemy.flat, definition_offset);
        // `self.clients[1]`: the host's client.
        if !self.clients.contains(&1) {
            return Err("KeyError: 1".into());
        }
        if definition == 0 {
            return Ok(body.to_vec());
        }
        let head = client.memory(client.base() + definition, 8)?;
        if (u32::from_le_bytes(head[..4].try_into().unwrap()), u32::from_le_bytes(head[4..8].try_into().unwrap())) != (1, spell) {
            return Ok(body.to_vec()); // Ordinary ranged definitions only; bosses are separate.
        }
        let key = (attacker, spell);
        let living: Vec<u32> = self.room.members.iter().copied().filter(|n| matches!(self.room.native_states.get(n).map_or(0, |s| s[0]), 1..=3)).collect();
        if opcode == 0x131 || !self.ranged_targets.contains(&key) {
            if !self.ranged_targets.contains(&key) && self.ranged_targets.len() >= MAX_ENEMIES {
                // Casts whose enemy vanished without a DESTROY (run end): drop the oldest.
                let first = self.ranged_targets.first_key().unwrap();
                self.ranged_targets.remove(&first);
                self.note_bound_event(client, "ordinary_cast_targets", 1, vec![]);
            }
            let target = if living.is_empty() {
                1
            } else {
                let mut best: Option<(u32, f64)> = None;
                for n in &living {
                    let p = self.wire.poses.get(n).ok_or("KeyError: player pose")?;
                    let d: f64 = enemy.pose.iter().zip([p[0], p[1], p[2]]).map(|(a, b)| (a - b) * (a - b)).sum();
                    if best.map_or(true, |(_, bd)| d < bd) {
                        best = Some((*n, d));
                    }
                }
                best.unwrap().0
            };
            self.ranged_targets.set(key, target);
        }
        let target = *self.ranged_targets.get(&key).unwrap();
        if opcode == 0x132 {
            self.ranged_targets.remove(&key);
            let game = client.server() + 0x10;
            // Pending ordinary impacts Vec (ptr,len), the build's own field (RawGameFields).
            let head = client.memory(game + self.build.raw.impacts, 16)?;
            let (pointer, count) = (q(&head, 0), q(&head, 8));
            if count > MAX_NATIVE_OBJECTS {
                return Err("Native pending impact count exceeds bound".into());
            }
            // Match the newly appended ordinary impact, leaving earlier flights alone.
            let mut matched = false;
            for index in (0..count).rev() {
                let address = pointer + index * 0x50;
                let row = client.memory(address, 0x50)?;
                if q(&row, 0x28) == attacker && q(&row, 0x20) == SELF && u32::from_le_bytes(row[0x40..0x44].try_into().unwrap()) == spell && row[0x49] == 1 {
                    let owner = if target == 1 { SELF } else { 0xFF0100 + target as u64 };
                    client.put(address + 0x20, &owner.to_le_bytes())?;
                    if self.room.guests.contains(&target) {
                        let pose = self.wire.poses.get(&target).ok_or("KeyError: player pose")?;
                        let speed = projectile_speed(spell).ok_or("KeyError: spell")?;
                        let clock_address = game + self.build.fields.get(0x85C)?;
                        let now = f32::from_le_bytes(client.memory(clock_address, 4)?[..4].try_into().unwrap()) as f64;
                        let distance = ((enemy.pose[0] - pose[0]).hypot(enemy.pose[1] - pose[1])) as f64;
                        let arrival = (now + if speed != 0.0 { distance / speed } else { 0.0 }) as f32;
                        client.put(address + 0x3C, &arrival.to_le_bytes())?;
                    }
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err("Ordinary cast has no matching native projectile".into());
            }
        }
        client.record(
            Event::new("ordinary_projectile_target").num("attacker", attacker as f64).num("spell", spell as f64).num("player", target as f64).num("opcode", opcode as f64),
        );
        let map: HashMap<u64, u64> = HashMap::from([(SELF, if target == 1 { SELF } else { 0xFF0100 + target as u64 })]);
        remap_combat(opcode, body, SELF, None, Some(&map))
    }
}
