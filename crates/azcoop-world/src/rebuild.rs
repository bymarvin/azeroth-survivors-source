//! The per-batch rebuild of the visibility bridge: a port of the part of
//! `Bridge.__call__` (visibility_bridge.py, 0.0.14) that takes the game's own
//! outgoing server batch, filters it, appends everything this player must see
//! (names, remote players, replicated world, progress repair, attacks, hits,
//! notices, markers) and re-encrypts it.
//!
//! Pure: the bridge state it reads and changes is passed in ([`Bridge`],
//! [`Feed`]); the effects that need the game (host world capture, party
//! markers) are callbacks. Nothing here touches memory, time or randomness.

use crate::builders::{character_name, clone_player, retarget_monster};
use crate::filter::{filter_packet, Action, FilterCtx};
use crate::session::{decode_ground_movement, is_movement_opcode, HeaderCipher};
use crate::{objects, values_packet, Reader, Result, DISPLAY_ID, HOST, MONSTER, PROGRESSION, SELF, UPDATE};
use std::collections::{BTreeMap, BTreeSet};

/// The scratch buffer the game gets the new batch in.
pub const MAX_BATCH: usize = 1_048_576;
/// `HOST_AVATAR`: the packed GUID 0xFF0101 (cheap scan before parsing).
pub const HOST_AVATAR: [u8; 4] = [0x07, 0x01, 0x01, 0xFF];

pub type Packet = (u16, Vec<u8>);

/// What the bridge knows about one recipient.
#[derive(Default)]
pub struct Feed {
    /// Remote players already created for this recipient.
    pub created: BTreeSet<u32>,
    /// Players whose character name this recipient still has to receive.
    pub name_queries: BTreeSet<u32>,
    /// The progression last sent to this recipient.
    pub progress_sent: Option<[u32; 3]>,
    /// Host world packets waiting for this recipient (guests).
    pub world_pending: Vec<Packet>,
    pub attack_packets: Vec<Packet>,
    pub hurt_packets: Vec<Packet>,
    pub notice_packets: Vec<Packet>,
}

/// Session-wide state a batch rebuild reads (and the name registry it extends).
#[derive(Default)]
pub struct Bridge {
    pub members: Vec<u32>,
    pub guests: Vec<u32>,
    pub shared_world: bool,
    /// `len(router.players) == len(members)`.
    pub all_present: bool,
    /// Login templates in insertion order.
    pub templates: Vec<(u32, Vec<u8>)>,
    /// Router poses: (x, y, z, facing) per player number.
    pub poses: BTreeMap<u32, [f64; 4]>,
    /// First element of `native_states[n]`.
    pub phases: BTreeMap<u32, u32>,
    pub remote_display: BTreeMap<u64, u32>,
    pub progress: Option<[u32; 3]>,
    pub name_responses: BTreeMap<u32, Vec<u8>>,
    pub feeds: BTreeMap<u32, Feed>,
    /// Packets dropped from guests (`counts['guest_suppressed']`).
    pub guest_suppressed: u64,
}

/// What happened that the caller has to apply or log, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// `remote_display_changed(recipient, guid, display)`.
    Display { guid: u64, display: u32 },
    /// A remote player was created for the recipient (logged once the batch is written).
    Created { player: u32, body: Vec<u8> },
    /// A character name was delivered (logged once the batch is written).
    Named { player: u32, body: Vec<u8> },
    /// `remote_create`: a remote player's avatar is created for the recipient.
    RemoteCreate { player: u32, guid: u64 },
    /// `shared_progress`: the host progression was (re)sent.
    SharedProgress { progress: [u32; 3] },
    /// `guest_attack_delivered` / `guest_hurt_delivered`
    AttackDelivered { opcode: u16, body: Vec<u8> },
    HurtDelivered { opcode: u16, body: Vec<u8> },
    /// `remote_pose`: a relayed movement reached the recipient (`player` may be negative for a foreign GUID).
    RemotePose { player: i64, pose: [f64; 4], opcode: u16, body: Vec<u8> },
    /// Where `append_markers` ran: its own events belong here.
    Markers,
}

pub struct Rebuilt {
    /// The batch to hand to the game (`None`: unchanged).
    pub data: Option<Vec<u8>>,
    /// New server cipher position (store as `server_states[number]` when shared).
    pub end: (usize, u8),
    pub events: Vec<Event>,
    /// A guest took its world backlog: the host-world byte counter restarts.
    pub world_bytes_reset: bool,
    /// Increments of `counts['created']`, `counts['relayed']` and `counts['world_delivered']`.
    pub created: u64,
    pub relayed: u64,
    pub world_delivered: u64,
}

/// `encrypt_packets`: header-encrypt complete server packets from a cipher position.
pub fn encrypt_packets(packets: &[Packet], key: &[u8], index: usize, previous: u8) -> Result<(Vec<u8>, usize, u8)> {
    let mut cipher = HeaderCipher::new(key).map_err(|_| "Invalid native server cipher state".to_string())?;
    if index >= 40 {
        return Err("Invalid native server cipher state".into());
    }
    cipher.index = index;
    cipher.previous = previous;
    let mut out = Vec::new();
    for (opcode, body) in packets {
        let size = body.len() + 2;
        if size > 0xFFFF {
            return Err("Server packet too large".into());
        }
        let mut header = (size as u16).to_be_bytes().to_vec();
        header.extend_from_slice(&opcode.to_le_bytes());
        out.extend_from_slice(&cipher.encrypt(&header));
        out.extend_from_slice(body);
    }
    Ok((out, cipher.index, cipher.previous))
}

/// `decrypt_batch`: complete serialized server packets and the cipher position after them.
pub fn decrypt_batch(data: &[u8], key: &[u8], index: usize, previous: u8) -> Result<(Vec<Packet>, usize, u8)> {
    if data.len() > MAX_BATCH || index >= 40 {
        return Err("Invalid server batch".into());
    }
    let mut cipher = HeaderCipher::new(key)?;
    cipher.index = index;
    cipher.previous = previous;
    let (mut packets, mut offset) = (Vec::new(), 0usize);
    while offset < data.len() {
        if offset + 4 > data.len() {
            return Err("Truncated server header".into());
        }
        let header = cipher.decrypt(&data[offset..offset + 4]);
        let size = u16::from_be_bytes([header[0], header[1]]) as usize;
        if size < 2 || offset + size + 2 > data.len() {
            return Err("Truncated server body".into());
        }
        packets.push((u16::from_le_bytes([header[2], header[3]]), data[offset + 4..offset + size + 2].to_vec()));
        offset += size + 2;
    }
    Ok((packets, cipher.index, cipher.previous))
}

/// What the host's MONSTER retargeting reads of the bridge.
#[derive(Clone, Default)]
pub struct RetargetInfo {
    pub all_present: bool,
    pub guests: Vec<u32>,
    pub phases: BTreeMap<u32, u32>,
    pub poses: BTreeMap<u32, [f64; 4]>,
}

impl RetargetInfo {
    pub fn of(bridge: &Bridge) -> RetargetInfo {
        RetargetInfo { all_present: bridge.all_present, guests: bridge.guests.clone(), phases: bridge.phases.clone(), poses: bridge.poses.clone() }
    }
}

/// The first half of a batch rebuild: decrypt the game's own batch, retarget host MONSTER packets and
/// run every packet through `filter` (`None` drops it). `Ok(None)`: the cipher position before the batch
/// is unknown, the batch is only appended to.
#[allow(clippy::too_many_arguments)]
pub fn decode_native(
    number: u32,
    original: &[u8],
    key: &[u8],
    start: Option<(usize, u8)>,
    end: (usize, u8),
    host_phase: u32,
    retarget: &RetargetInfo,
    filter: &mut dyn FnMut(u16, Vec<u8>) -> Result<Option<Vec<u8>>>,
) -> Result<Option<Vec<Packet>>> {
    let Some((index, previous)) = start else { return Ok(None) };
    let (decoded, end_index, end_previous) = decrypt_batch(original, key, index, previous)?;
    if (end_index, end_previous) != end {
        return Err("Native server batch cipher boundary changed".into());
    }
    let mut kept = Vec::with_capacity(decoded.len());
    for (opcode, mut body) in decoded {
        if number == 1 && opcode == MONSTER && retarget.all_present {
            let mut reader = Reader::new(&body);
            reader.guid(true, true)?;
            let range = reader.take(8)?;
            let float = |at: usize| f32::from_le_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]) as f64;
            let (x, y) = (float(range.start), float(range.start + 4));
            let living: Vec<u32> = retarget.guests.iter().copied().filter(|n| matches!(retarget.phases.get(n).copied().unwrap_or(0), 1..=3)).collect();
            if !living.is_empty() {
                let pose = |n: u32| retarget.poses.get(&n).copied().ok_or_else(|| "Unknown player pose".to_string());
                let mut nearest = (living[0], f64::INFINITY);
                for n in &living {
                    let p = pose(*n)?;
                    let distance = (p[0] - x).powi(2) + (p[1] - y).powi(2);
                    if distance < nearest.1 {
                        nearest = (*n, distance);
                    }
                }
                let host = pose(1)?;
                let guest = pose(nearest.0)?;
                body = retarget_monster(&body, (host[0], host[1]), (guest[0], guest[1]), host_phase != 4, true, 0xFF0100 + nearest.0 as u64)?;
            }
        }
        if let Some(filtered) = filter(opcode, body)? {
            kept.push((opcode, filtered));
        }
    }
    Ok(Some(kept))
}

/// One native server batch of player `number`.
///
/// * `original`: the batch the game wrote; `key`: its 40-byte header key.
/// * `start`: cipher position before the batch (`server_states[number]`), if known.
/// * `end`: cipher position the connection reports after it.
/// * `host_phase`: native phase of this client (host MONSTER retargeting).
/// * `capture`: host only, `capture_world(opcode, body)` for each kept world packet.
/// * `markers`: `append_markers(packets)` of party_markers (after the notices).
#[allow(clippy::too_many_arguments)]
pub fn rebuild_batch(
    bridge: &mut Bridge,
    number: u32,
    original: &[u8],
    key: &[u8],
    start: Option<(usize, u8)>,
    end: (usize, u8),
    host_phase: u32,
    capture: &mut dyn FnMut(u16, &[u8]) -> Result<()>,
    markers: &mut dyn FnMut(&Bridge, &mut Vec<Packet>) -> Result<()>,
) -> Result<Rebuilt> {
    let retarget = RetargetInfo::of(bridge);
    let native = {
        let mut filter = |opcode: u16, body: Vec<u8>| -> Result<Option<Vec<u8>>> {
            let ctx = FilterCtx {
                number,
                members: &bridge.members,
                guests: &bridge.guests,
                own_name_response: bridge.name_responses.get(&number).map(Vec::as_slice),
            };
            let (action, fx) = filter_packet(&ctx, opcode, &body)?;
            if let Some(registered) = fx.register_name_response {
                bridge.name_responses.insert(number, registered);
            }
            if let Some(other) = fx.name_query {
                bridge.feeds.entry(number).or_default().name_queries.insert(other);
            }
            if fx.capture_world {
                capture(opcode, &body)?;
            }
            if fx.progress_resend {
                bridge.feeds.entry(number).or_default().progress_sent = None;
            }
            if fx.suppressed {
                bridge.guest_suppressed += 1;
            }
            Ok(match action {
                Action::Keep(filtered) => Some(filtered),
                Action::Drop => None,
            })
        };
        decode_native(number, original, key, start, end, host_phase, &retarget, &mut filter)?
    };
    rebuild_append(bridge, number, native, original, key, start, end, markers)
}

/// The second half of a batch rebuild: append everything this player must see to the (filtered) native
/// packets, re-encrypt, and say what changed.
#[allow(clippy::too_many_arguments)]
pub fn rebuild_append(
    bridge: &mut Bridge,
    number: u32,
    native: Option<Vec<Packet>>,
    original: &[u8],
    key: &[u8],
    start: Option<(usize, u8)>,
    end: (usize, u8),
    markers: &mut dyn FnMut(&Bridge, &mut Vec<Packet>) -> Result<()>,
) -> Result<Rebuilt> {
    let mut events = Vec::new();
    let (mut created_count, mut relayed_count, mut delivered_count) = (0u64, 0u64, 0u64);
    let mut packets: Vec<Packet> = Vec::new();
    let mut created_packets: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut named_packets: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut feed = bridge.feeds.remove(&number).unwrap_or_default();
    let result = (|| -> Result<bool> {
        for other in feed.name_queries.iter().copied().collect::<Vec<_>>() {
            if let Some(response) = bridge.name_responses.get(&other) {
                let mut body = (0xFF0100 + other as u64).to_le_bytes().to_vec();
                body.extend_from_slice(&response[8..]);
                packets.push((0x51, body.clone()));
                named_packets.push((other, body));
            }
        }
        for (other, template) in &bridge.templates {
            if *other == number {
                continue;
            }
            let guid = 0xFF0100 + *other as u64;
            if !feed.created.contains(other) {
                let pose = *bridge.poses.get(other).ok_or_else(|| "Unknown player pose".to_string())?;
                let created = clone_player(template, guid, pose)?;
                packets.push((UPDATE, created.clone()));
                created_packets.push((*other, created));
                if let Some(display) = bridge.remote_display.get(&guid) {
                    // The login template predates a form learned since.
                    packets.push((UPDATE, values_packet(guid, &BTreeMap::from([(DISPLAY_ID, *display)]))?));
                }
                feed.created.insert(*other);
                feed.progress_sent = None;
                created_count += 1;
                events.push(Event::RemoteCreate { player: *other, guid });
            }
        }
        let mut world_taken = false;
        if bridge.shared_world && number != 1 && feed.created.contains(&1) {
            let pending = std::mem::take(&mut feed.world_pending);
            for (opcode, body) in &pending {
                if *opcode == UPDATE && body.windows(4).any(|w| w == HOST_AVATAR) {
                    for block in objects(body, false, None)? {
                        if block.guid == HOST {
                            if let Some(display) = block.fields.get(&DISPLAY_ID) {
                                events.push(Event::Display { guid: HOST, display: *display });
                            }
                        }
                    }
                }
            }
            delivered_count += pending.len() as u64;
            packets.extend(pending);
            world_taken = true;
        }
        if bridge.shared_world {
            if let Some(progress) = bridge.progress {
                // Also repair a guest bootstrap that arrived after the host snapshot.
                if feed.progress_sent != Some(progress) {
                    let fields: BTreeMap<u32, u32> = PROGRESSION.iter().copied().zip(progress).collect();
                    let guids = std::iter::once(SELF).chain(feed.created.iter().map(|o| 0xFF0100 + *o as u64));
                    for guid in guids {
                        packets.push((UPDATE, values_packet(guid, &fields)?));
                    }
                    feed.progress_sent = Some(progress);
                    events.push(Event::SharedProgress { progress });
                }
            }
        }
        for (opcode, body) in &feed.attack_packets {
            events.push(Event::AttackDelivered { opcode: *opcode, body: body.clone() });
        }
        packets.append(&mut feed.attack_packets);
        for (opcode, body) in &feed.hurt_packets {
            events.push(Event::HurtDelivered { opcode: *opcode, body: body.clone() });
        }
        packets.append(&mut feed.hurt_packets);
        let notices = std::mem::take(&mut feed.notice_packets);
        for (opcode, payload) in &notices {
            if *opcode == UPDATE
                && payload.get(..6) == Some(&[1, 0, 0, 0, 0, 0][..])
                && payload.get(6) == Some(&0x07)
                && payload.get(8..10) == Some(&[1, 0xff][..])
            {
                // Only the single-player VALUES shape the bridge writes for 0xFF0101..04.
                let blocks = objects(payload, false, None)?;
                let [block] = blocks.as_slice() else {
                    return Err("Expected exactly one object block".into());
                };
                if let Some(display) = block.fields.get(&DISPLAY_ID) {
                    if (0xFF0101..=0xFF0104).contains(&block.guid) {
                        events.push(Event::Display { guid: block.guid, display: *display });
                    }
                }
            }
            if is_movement_opcode(*opcode as u32) {
                let mut reader = Reader::configured(payload, false, HOST, None, None);
                let owner = reader.guid(true, false)? as i64 - 0xFF0100;
                let pose = decode_ground_movement(&payload[reader.pos..])?;
                relayed_count += 1;
                events.push(Event::RemotePose {
                    player: owner,
                    pose: [pose.x as f64, pose.y as f64, pose.z as f64, pose.facing as f64],
                    opcode: *opcode,
                    body: payload[reader.pos..].to_vec(),
                });
            }
        }
        packets.extend(notices);
        Ok(world_taken)
    })();
    bridge.feeds.insert(number, feed);
    let world_taken = result?;
    if bridge.shared_world {
        events.push(Event::Markers);
        markers(bridge, &mut packets)?;
    }
    let (data, index, previous) = match (&native, start) {
        (Some(kept), Some((index, previous))) => {
            let all: Vec<Packet> = kept.iter().cloned().chain(packets.iter().cloned()).collect();
            encrypt_packets(&all, key, index, previous)?
        }
        _ => {
            let (extra, index, previous) = encrypt_packets(&packets, key, end.0, end.1)?;
            ([original, &extra[..]].concat(), index, previous)
        }
    };
    let end_state = (index, previous);
    if data == original {
        return Ok(Rebuilt { data: None, end: end_state, events, world_bytes_reset: world_taken, created: created_count, relayed: relayed_count, world_delivered: delivered_count });
    }
    if data.len() > MAX_BATCH {
        return Err("Bridge output exceeds scratch buffer".into());
    }
    for (player, body) in created_packets {
        events.push(Event::Created { player, body });
    }
    for (player, body) in named_packets {
        character_name(&body)?;
        bridge.feeds.entry(number).or_default().name_queries.remove(&player);
        events.push(Event::Named { player, body });
    }
    Ok(Rebuilt { data: Some(data), end: end_state, events, world_bytes_reset: world_taken, created: created_count, relayed: relayed_count, world_delivered: delivered_count })
}
