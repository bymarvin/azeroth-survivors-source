//! Small packet builders and validators of the visibility bridge: a byte-exact
//! port of the pure helpers in `visibility_bridge.py` and `party_markers.py`
//! (0.0.14). Each function states the Python function it mirrors.

use crate::{pack_guid, Reader, Result, SELF};
use std::collections::BTreeMap;

/// `visibility_bridge.system_message`: opcode 0x96 notice.
pub fn system_message(text: &str) -> Result<(u16, Vec<u8>)> {
    let encoded = text.as_bytes();
    if encoded.len() > 4096 || encoded.contains(&0) {
        return Err("Invalid co-op notification".into());
    }
    let mut body = vec![0x0a];
    body.extend_from_slice(&[0u8; 12]);
    body.extend_from_slice(&(encoded.len() as u32 + 1).to_le_bytes());
    body.extend_from_slice(encoded);
    body.extend_from_slice(&[0, 0]);
    Ok((0x96, body))
}

/// `visibility_bridge.melee_packet`: noncritical 0x14A layout.
pub fn melee_packet(attacker: u64, target: u64, damage: u64) -> Result<Vec<u8>> {
    let damage = damage.min(0xFFFF_FFFF) as u32; // a u32 field: saturates instead of ending the run
    let mut out = 2u32.to_le_bytes().to_vec();
    out.extend_from_slice(&pack_guid(attacker));
    out.extend_from_slice(&pack_guid(target));
    out.extend_from_slice(&damage.to_le_bytes());
    out.push(1);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(damage as f32).to_le_bytes());
    for value in [damage, 0, 0, 1, 0, 0, 0] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(out)
}

/// A float as struct.pack('<f') stores it: NaN and infinity pass through, a
/// finite value that rounds to infinity is an overflow error.
fn pack_f32(value: f64) -> Result<[u8; 4]> {
    let narrowed = value as f32;
    if narrowed.is_infinite() && value.is_finite() {
        return Err("float too large to pack with f format".into());
    }
    Ok(narrowed.to_le_bytes())
}

/// `visibility_bridge.movement`: 28-byte ground movement body.
pub fn movement(x: f64, y: f64, z: f64, facing: f64, timestamp: u64) -> Result<Vec<u8>> {
    let mut out = vec![0u8; 4];
    out.extend_from_slice(&((timestamp & 0xFFFF_FFFF) as u32).to_le_bytes());
    for value in [x, y, z, facing] {
        out.extend_from_slice(&pack_f32(value)?);
    }
    out.extend_from_slice(&[0u8; 4]);
    Ok(out)
}

/// `visibility_bridge.character_name`: validates the captured 0x51 reply and
/// returns the name. Non-ASCII names are accepted when every character is
/// alphanumeric (Python's `isprintable` also admits other marks and
/// punctuation; those are rejected here, which fails closed).
pub fn character_name(body: &[u8]) -> Result<String> {
    let invalid = || "Invalid native character name response".to_string();
    let end = body.get(8..).and_then(|rest| rest.iter().position(|b| *b == 0)).map(|p| p + 8);
    let end = end.filter(|e| (9..=104).contains(e) && body.len() == e + 14 && body[e + 1] == 0).ok_or_else(invalid)?;
    let name = std::str::from_utf8(&body[8..end]).map_err(|_| invalid())?;
    let word = |at: usize| u32::from_le_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]);
    let (race, gender, class_id) = (word(end + 2), word(end + 6), word(end + 10));
    let printable = name.chars().all(|c| (' '..='~').contains(&c) || (!c.is_ascii() && c.is_alphanumeric()));
    if !printable || !(1..=255).contains(&race) || gender > 2 || !(1..=255).contains(&class_id) {
        return Err("Invalid native character identity".into());
    }
    Ok(name.to_string())
}

/// `visibility_bridge.clone_player`: the verified local-player create shape,
/// re-addressed to `guid` at `pose` (x, y, z, facing).
pub fn clone_player(body: &[u8], guid: u64, pose: [f64; 4]) -> Result<Vec<u8>> {
    const SHAPE: [u8; 12] = [0x01, 0, 0, 0, 0, 0x03, 0x07, 0xfe, 0xff, 0xff, 0x04, 0x71];
    if body.len() < 73 || body[..12] != SHAPE {
        return Err("Not the verified local-player creation shape".into());
    }
    if u32::from_le_bytes([body[12], body[13], body[14], body[15]]) != 0 {
        return Err("Unsupported initial movement flags".into());
    }
    let mut result = body.to_vec();
    let encoded = pack_guid(guid);
    if encoded.len() != 4 {
        return Err("Replacement GUID must retain packed width".into());
    }
    result[6..10].copy_from_slice(&encoded);
    result[11] &= !1; // clear SELF: the recipient keeps its own native avatar
    for (i, value) in pose.iter().enumerate() {
        result[20 + 4 * i..24 + 4 * i].copy_from_slice(&pack_f32(*value)?);
    }
    let count = result[68] as usize;
    let start = 69 + count * 4;
    let mask_bytes = &result[69.min(result.len())..start.min(result.len())];
    let mask_low = mask_bytes.first().copied().unwrap_or(0) as u32;
    let popcount: usize = mask_bytes.iter().map(|b| b.count_ones() as usize).sum();
    if mask_low & 3 != 3 || result.len() != start + popcount * 4 {
        return Err("Unexpected object field mask".into());
    }
    if u64::from_le_bytes(result[start..start + 8].try_into().unwrap()) != 0xFFFFFE {
        return Err("Object field GUID does not match local player".into());
    }
    result[start..start + 8].copy_from_slice(&guid.to_le_bytes());
    Ok(result)
}

/// `visibility_bridge.retarget_monster`: keeps the spline facing-target GUID
/// consistent with two-player pursuit. `host` / `guest` are (x, y).
pub fn retarget_monster(
    body: &[u8],
    host: (f64, f64),
    guest: (f64, f64),
    host_alive: bool,
    guest_alive: bool,
    guest_guid: u64,
) -> Result<Vec<u8>> {
    let mut reader = Reader::new(body);
    reader.guid(true, false)?;
    let range = reader.take(16)?;
    let position = &body[range];
    let float = |at: usize| f32::from_le_bytes([position[at], position[at + 1], position[at + 2], position[at + 3]]);
    let (x, y) = (float(0) as f64, float(4) as f64);
    if reader.integer(1)? != 3 || !guest_alive {
        return Ok(body.to_vec());
    }
    let offset = reader.pos;
    if reader.guid(false, false)? != SELF {
        return Ok(body.to_vec());
    }
    let guest_distance = (x - guest.0).powi(2) + (y - guest.1).powi(2);
    let host_distance = (x - host.0).powi(2) + (y - host.1).powi(2);
    if !host_alive || guest_distance < host_distance {
        reader.body[offset..offset + 8].copy_from_slice(&guest_guid.to_le_bytes());
    }
    Ok(reader.body)
}

/// `party_markers.native_guid`.
pub fn native_guid(player: u32, recipient: u32) -> u64 {
    if player == recipient {
        SELF
    } else {
        0xFF0100 + player as u64
    }
}

/// `party_markers.raid_packet`: `assignments` is player -> icon, `visible` the
/// players this recipient has been shown.
pub fn raid_packet(assignments: &BTreeMap<u32, u8>, recipient: u32, visible: &[u32]) -> (u16, Vec<u8>) {
    let mut body = vec![1u8];
    for (player, icon) in assignments {
        if *player == recipient || visible.contains(player) {
            body.push(*icon);
            body.extend_from_slice(&native_guid(*player, recipient).to_le_bytes());
        }
    }
    (0x321, body)
}

/// `party_markers.minimap_packet`: rows are (player, dx, dy, dead, name).
pub fn minimap_packet(rows: &[(u32, f64, f64, bool, String)], downed: bool) -> (u16, Vec<u8>) {
    let rows_text: Vec<String> = rows
        .iter()
        .map(|(n, dx, dy, dead, name)| {
            let hex: String = name.bytes().map(|b| format!("{b:02x}")).collect();
            format!("{n},{dx:.3},{dy:.3},{},{hex}", *dead as u8)
        })
        .collect();
    let text = format!("ATMARK\t{}|{}", downed as u8, rows_text.join(";")).into_bytes();
    let mut body = vec![1u8];
    body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    body.extend_from_slice(&SELF.to_le_bytes());
    body.extend_from_slice(&SELF.to_le_bytes());
    body.extend_from_slice(&(text.len() as u32 + 1).to_le_bytes());
    body.extend_from_slice(&text);
    body.extend_from_slice(&[0, 0]);
    (0x96, body)
}

/// `party_markers.reject_remote_marker_packet`: peers cannot drive the local
/// marker UI channel.
pub fn reject_remote_marker_packet(opcode: u16, body: &[u8]) -> Result<()> {
    let marker = b"ATMARK\t";
    if opcode == 0x96
        && body.get(1..5) == Some(&[0xff; 4][..])
        && body.windows(marker.len()).any(|w| w == marker)
    {
        return Err("Party marker snapshots are local-only".into());
    }
    Ok(())
}
