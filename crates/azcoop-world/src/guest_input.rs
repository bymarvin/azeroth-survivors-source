//! Validation of what a peer sends into the host's world: ports of
//! `receive_summon_packet` (native_guest_combat.py) and
//! `Bridge.sanitize_player_values` / `display_allowed` (visibility_bridge.py), 0.0.15.
//!
//! A guest may only create summons and ground spells under its own identity and
//! only show a model its login template or a druid form allows. Everything else
//! is an error (the session ends) or is stripped.

use crate::{dynamic_caster, dynamic_object, objects, values_packet, Result, DESTROY, DISPLAY_ID, FORM_DISPLAYS, UPDATE};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub const MAX_LIVE_SUMMONS: usize = 4096;
/// Player-owned units: native creature GUIDs (totems, companions) and pet GUIDs.
pub const SUMMON_PREFIXES: [u64; 2] = [0xF130, 0xF140];

/// Session-wide state these checks read and extend.
#[derive(Default)]
pub struct GuestInput {
    /// The co-op guests (players 2..).
    pub guests: Vec<u32>,
    /// Live summon identities per player (`self.summons`, one entry per member).
    pub summons: BTreeMap<u32, HashSet<u64>>,
    /// Login character templates per player.
    pub templates: BTreeMap<u32, Vec<u8>>,
    /// The login model of each player, learned from its template on first use.
    pub template_displays: BTreeMap<u32, Option<u32>>,
    /// Peers whose rejected model was already logged.
    pub displays_rejected: BTreeSet<u32>,
}

impl GuestInput {
    pub fn new(members: &[u32]) -> GuestInput {
        GuestInput {
            guests: members.iter().copied().filter(|m| *m != 1).collect(),
            summons: members.iter().map(|m| (*m, HashSet::new())).collect(),
            ..Default::default()
        }
    }

    /// `receive_summon_packet(opcode, body, owner)`.
    pub fn receive_summon_packet(&mut self, opcode: u16, body: &[u8], owner: Option<u32>) -> Result<()> {
        if opcode == UPDATE {
            for block in objects(body, false, None)? {
                let number = (((block.guid & 0xFFFFFF) >> 22) + 1) as u32;
                if matches!(block.kind, 2 | 3) && block.object_type == Some(3) {
                    // Totems name their owner in SUMMONEDBY and CREATEDBY; companions in at least one.
                    let owners: Vec<u64> = [12u32, 14]
                        .iter()
                        .filter(|k| block.fields.contains_key(k))
                        .map(|k| block.fields.get(k).copied().unwrap_or(0) as u64 | ((block.fields.get(&(k + 1)).copied().unwrap_or(0) as u64) << 32))
                        .collect();
                    let identity = block.fields.get(&0).copied().unwrap_or(0) as u64 | ((block.fields.get(&1).copied().unwrap_or(0) as u64) << 32);
                    if !SUMMON_PREFIXES.contains(&(block.guid >> 48))
                        || !self.guests.contains(&number)
                        || owner.is_some_and(|o| number != o)
                        || identity != block.guid
                        || owners.is_empty()
                        || owners.iter().any(|o| *o != 0xFF0100 + number as u64)
                    {
                        return Err("Guest summon has an invalid owner or identity".into());
                    }
                    self.add_summon(number, block.guid, "Too many remote summons")?;
                } else if dynamic_object(&block, false)? {
                    if !self.guests.contains(&number) || owner.is_some_and(|o| number != o) || dynamic_caster(&block)? != 0xFF0100 + number as u64 {
                        return Err("Guest ground spell has an invalid owner or identity".into());
                    }
                    self.add_summon(number, block.guid, "Too many remote summons")?;
                }
            }
        } else if opcode == DESTROY && body.len() == 8 {
            let guid = u64::from_le_bytes(body.try_into().unwrap());
            let number = (((guid & 0xFFFFFF) >> 22) + 1) as u32;
            if let Some(set) = self.summons.get_mut(&number) {
                if owner.is_some_and(|o| number != o) {
                    return Err("Guest destroyed another owner summon".into());
                }
                set.remove(&guid);
            }
        }
        Ok(())
    }

    fn add_summon(&mut self, number: u32, guid: u64, error: &str) -> Result<()> {
        let set = self.summons.get_mut(&number).ok_or("No summon table for this player")?;
        if set.len() >= MAX_LIVE_SUMMONS && !set.contains(&guid) {
            return Err(error.into());
        }
        set.insert(guid);
        Ok(())
    }

    /// `display_allowed(number, display)`: a login model or a native druid form model.
    fn display_allowed(&mut self, number: i64, display: u32) -> Result<bool> {
        if FORM_DISPLAYS.contains(&display) {
            return Ok(true);
        }
        let key = u32::try_from(number).ok();
        if let Some(n) = key {
            if !self.template_displays.contains_key(&n) {
                if let Some(template) = self.templates.get(&n) {
                    let blocks = objects(template, false, None)?;
                    let [block] = blocks.as_slice() else { return Err("Expected exactly one object block".into()) };
                    self.template_displays.insert(n, block.fields.get(&DISPLAY_ID).copied());
                }
            }
            return Ok(self.template_displays.get(&n).copied().flatten() == Some(display));
        }
        Ok(false)
    }

    /// `sanitize_player_values(peer, opcode, payload)`: drops an unexpected display model from a
    /// peer's avatar update. Returns the packet to keep (or none) and whether the rejection is new.
    pub fn sanitize_player_values(&mut self, peer: u32, opcode: u16, payload: &[u8]) -> Result<(Option<Vec<u8>>, bool)> {
        if opcode != UPDATE || payload.get(..6) != Some(&[1, 0, 0, 0, 0, 0][..]) || payload.get(6) != Some(&0x07) || payload.get(8..10) != Some(&[1, 0xff][..]) {
            return Ok((Some(payload.to_vec()), false));
        }
        let blocks = objects(payload, false, None)?;
        let [block] = blocks.as_slice() else { return Err("Expected exactly one object block".into()) };
        let Some(display) = block.fields.get(&DISPLAY_ID).copied() else { return Ok((Some(payload.to_vec()), false)) };
        if self.display_allowed(block.guid as i64 - 0xFF0100, display)? {
            return Ok((Some(payload.to_vec()), false));
        }
        let first = self.displays_rejected.insert(peer);
        let fields: BTreeMap<u32, u32> = block.fields.iter().filter(|(k, _)| **k != DISPLAY_ID).map(|(k, v)| (*k, *v)).collect();
        if fields.is_empty() {
            Ok((None, first))
        } else {
            Ok((Some(values_packet(block.guid, &fields)?), first))
        }
    }
}
