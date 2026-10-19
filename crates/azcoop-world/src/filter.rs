//! The per-packet filter of the visibility bridge: a port of
//! `Bridge.filter_packet` / `set_name_response` (visibility_bridge.py, 0.0.14).
//!
//! It decides what happens to each packet of the game's own outgoing batch:
//! keep, rewrite or drop it. It is a pure function; everything the Python
//! method changes on the bridge (registering a character name, noting a name
//! query, handing a world packet to the host's replication, forcing a progress
//! resend, counting a suppression) is returned as [`Effects`] for the caller to
//! apply, so the decision itself can be tested against the Python.

use crate::builders::character_name;
use crate::{is_world, object_packet, objects, Reader, Result, PROGRESSION, SELF, UPDATE};

/// Who the batch belongs to and which peers exist.
pub struct FilterCtx<'a> {
    /// The player number this client plays (1 = host).
    pub number: u32,
    pub members: &'a [u32],
    pub guests: &'a [u32],
    /// The character-name response already registered for `number`, if any.
    pub own_name_response: Option<&'a [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Keep(Vec<u8>),
    Drop,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Effects {
    /// Register this body as `number`'s character name (none registered before).
    pub register_name_response: Option<Vec<u8>>,
    /// `name_queries[number].add(player)`: the native reply names a remote player.
    pub name_query: Option<u32>,
    /// Host: pass the original packet to `capture_world`.
    pub capture_world: bool,
    /// Guest: the own-player progression changed, force a progress repair.
    pub progress_resend: bool,
    /// Guest: the packet was suppressed (`counts['guest_suppressed']`).
    pub suppressed: bool,
}

/// `Bridge.set_name_response`: validates the reply and says whether to register it.
fn name_response(ctx: &FilterCtx, body: &[u8]) -> Result<Option<Vec<u8>>> {
    character_name(body)?;
    let guid = u64::from_le_bytes(body.get(..8).ok_or("short name reply")?.try_into().unwrap());
    if !ctx.members.contains(&ctx.number) || guid != SELF {
        return Err("Character name does not belong to its authenticated player".into());
    }
    match ctx.own_name_response {
        Some(previous) if previous != body => Err("Character identity changed during the session".into()),
        Some(_) => Ok(None),
        None => Ok(Some(body.to_vec())),
    }
}

/// `Bridge.filter_packet`.
pub fn filter_packet(ctx: &FilterCtx, opcode: u16, body: &[u8]) -> Result<(Action, Effects)> {
    let mut effects = Effects::default();
    if opcode == 0x51 {
        character_name(body)?;
        let guid = u64::from_le_bytes(body.get(..8).ok_or("short name reply")?.try_into().unwrap());
        if guid == SELF {
            effects.register_name_response = name_response(ctx, body)?;
        } else if (0xFF0101..=0xFF0104).contains(&guid) {
            let other = (guid - 0xFF0100) as u32;
            if ctx.members.contains(&other) && other != ctx.number {
                effects.name_query = Some(other);
            }
            // The native single-player reply contains the local name.
            return Ok((Action::Drop, effects));
        }
    }
    if ctx.number == 1 && opcode == 0x14A {
        let mut reader = Reader::new(body);
        reader.take(4)?;
        reader.guid(true, false)?;
        let target = reader.guid(true, false)?;
        if ctx.guests.iter().any(|g| target == 0xFF0100 + *g as u64) {
            return Ok((Action::Drop, effects)); // replaced after the guest's own native defenses
        }
    }
    if !is_world(opcode) {
        return Ok((Action::Keep(body.to_vec()), effects));
    }
    if ctx.number == 1 {
        effects.capture_world = true;
        return Ok((Action::Keep(body.to_vec()), effects));
    }
    if opcode == UPDATE {
        let blocks = objects(body, false, None)?;
        let allowed: Vec<_> = blocks.iter().filter(|b| b.guid == SELF || b.guid >> 48 == 0x4000).cloned().collect();
        if !allowed.is_empty() {
            if allowed.iter().any(|b| b.guid == SELF && PROGRESSION.iter().any(|k| b.fields.contains_key(k))) {
                effects.progress_resend = true;
            }
            let kept = if allowed.len() == blocks.len() { body.to_vec() } else { object_packet(&allowed) };
            return Ok((Action::Keep(kept), effects));
        }
    }
    effects.suppressed = true;
    Ok((Action::Drop, effects))
}

/// `Bridge.set_name_response(number, body)` as a free function: validates the
/// reply and returns it when it is to be registered for the first time.
pub fn set_name_response(members: &[u32], number: u32, previous: Option<&[u8]>, body: &[u8]) -> Result<Option<Vec<u8>>> {
    let ctx = FilterCtx { number, members, guests: &[], own_name_response: previous };
    name_response(&ctx, body)
}
