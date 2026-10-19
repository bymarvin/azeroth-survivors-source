//! Bounded parser and rewriter for the native world's object and combat
//! replication packets. A byte-exact port of `world_packets.py` (0.0.14), so the
//! native engine produces what the Python bridge produces.
//!
//! Pure functions on bytes: no I/O, no game memory, no globals. Every read is
//! bounds-checked and unknown layouts fail closed with an error instead of
//! guessing object boundaries. GUID remapping rewrites the actual GUID fields
//! (and re-packs them, which can change a packet's length), never searches for
//! byte patterns.

use std::collections::{BTreeMap, HashMap};

pub const SELF: u64 = 0xFFFFFE;
pub const HOST: u64 = 0xFF0101;
pub const UPDATE: u16 = 0xA9;
pub const DESTROY: u16 = 0xAA;
pub const MONSTER: u16 = 0xDD;
pub const COMBAT: [u16; 8] = [0x143, 0x144, 0x14A, 0x250, 0x24E, 0x131, 0x132, 0x1F3];
/// UNIT_LEVEL, PLAYER_XP, PLAYER_NEXT_LEVEL_XP.
pub const PROGRESSION: [u32; 3] = [34, 716, 717];
/// UNIT_FIELD_DISPLAYID (the druid capstone form model is set here).
pub const DISPLAY_ID: u32 = 131;
/// Models the native player-field builder sets besides the race default.
pub const FORM_DISPLAYS: [u32; 4] = [892, 8571, 2281, 2289];
/// Ground spells (Rain of Fire).
pub const DYNAMIC_OBJECT: u8 = 6;
/// play_limits.MAX_QUEUE: per-batch queues and packet lists.
pub const MAX_QUEUE: usize = 65_536;

pub mod auras;
pub mod builders;
pub mod guest_input;
pub mod filter;
pub mod host_world;
pub mod rebuild;
pub mod session;

pub type Result<T> = std::result::Result<T, String>;

pub fn is_world(opcode: u16) -> bool {
    matches!(opcode, UPDATE | DESTROY | MONSTER) || COMBAT.contains(&opcode)
}

/// Packs a GUID the way the protocol does: a mask byte, then the non-zero bytes.
pub fn pack_guid(guid: u64) -> Vec<u8> {
    let raw = guid.to_le_bytes();
    let mut out = vec![0u8];
    for (i, byte) in raw.iter().enumerate() {
        if *byte != 0 {
            out[0] |= 1 << i;
            out.push(*byte);
        }
    }
    out
}

/// Cursor over a packet body that can rewrite GUID fields in place.
pub struct Reader {
    pub body: Vec<u8>,
    pub pos: usize,
    remap_enabled: bool,
    player_guid: u64,
    local_guid: Option<u64>,
    guid_map: HashMap<u64, u64>,
}

impl Reader {
    /// Defaults of the Python `Reader`: remapping on, `player_guid` = HOST.
    pub fn new(body: &[u8]) -> Reader {
        Reader {
            body: body.to_vec(),
            pos: 0,
            remap_enabled: true,
            player_guid: HOST,
            local_guid: None,
            guid_map: HashMap::new(),
        }
    }

    pub fn configured(
        body: &[u8],
        remap_enabled: bool,
        player_guid: u64,
        local_guid: Option<u64>,
        guid_map: Option<&HashMap<u64, u64>>,
    ) -> Reader {
        Reader {
            body: body.to_vec(),
            pos: 0,
            remap_enabled,
            player_guid,
            local_guid,
            guid_map: guid_map.cloned().unwrap_or_default(),
        }
    }

    /// Advances over `size` bytes and returns their range.
    pub fn take(&mut self, size: usize) -> Result<std::ops::Range<usize>> {
        let end = self.pos.checked_add(size).filter(|end| *end <= self.body.len());
        let Some(end) = end else {
            return Err("Truncated native world packet".into());
        };
        let start = self.pos;
        self.pos = end;
        Ok(start..end)
    }

    /// Little-endian integer of 1..=8 bytes.
    pub fn integer(&mut self, size: usize) -> Result<u64> {
        debug_assert!(size <= 8);
        let range = self.take(size)?;
        let mut value = 0u64;
        for (i, byte) in self.body[range].iter().enumerate() {
            value |= (*byte as u64) << (8 * i);
        }
        Ok(value)
    }

    /// Skips everything that is left.
    pub fn take_rest(&mut self) -> Result<()> {
        let rest = self.body.len() - self.pos;
        self.take(rest).map(|_| ())
    }

    /// Reads a GUID (packed or plain 8 bytes). With `remap`, and if remapping is
    /// enabled, rewrites it in place to the mapped value and returns the ORIGINAL.
    pub fn guid(&mut self, packed: bool, remap: bool) -> Result<u64> {
        let start = self.pos;
        let guid = if packed {
            let mask = self.integer(1)?;
            let mut guid = 0u64;
            for i in 0..8 {
                if mask & (1 << i) != 0 {
                    guid |= self.integer(1)? << (i * 8);
                }
            }
            guid
        } else {
            self.integer(8)?
        };
        if remap && self.remap_enabled {
            let target = match self.guid_map.get(&guid) {
                Some(target) => *target,
                None if guid == SELF => self.player_guid,
                None if Some(guid) == self.local_guid => SELF,
                None => guid,
            };
            if target != guid {
                let replacement = if packed { pack_guid(target) } else { target.to_le_bytes().to_vec() };
                let new_end = start + replacement.len();
                self.body.splice(start..self.pos, replacement);
                self.pos = new_end;
            }
        }
        Ok(guid)
    }

    /// The whole body must have been consumed.
    pub fn end(&self) -> Result<()> {
        if self.pos != self.body.len() {
            return Err("Unparsed trailing world data".into());
        }
        Ok(())
    }
}

/// Sparse VALUES update; writes only the explicitly supplied native fields.
pub fn values_packet(guid: u64, fields: &BTreeMap<u32, u32>) -> Result<Vec<u8>> {
    if guid == 0 || fields.is_empty() || fields.keys().any(|k| *k >= 8160) {
        return Err("Invalid object values".into());
    }
    let count = (*fields.keys().next_back().unwrap() / 32 + 1) as usize;
    let mut mask = vec![0u8; count * 4];
    for k in fields.keys() {
        mask[(*k / 8) as usize] |= 1 << (*k % 8);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&pack_guid(guid));
    out.push(count as u8);
    out.extend_from_slice(&mask);
    for value in fields.values() {
        out.extend_from_slice(&value.to_le_bytes());
    }
    Ok(out)
}

fn movement_block(reader: &mut Reader) -> Result<()> {
    let flags = reader.integer(1)?;
    if flags & 0x20 != 0 {
        let mode = reader.integer(4)?;
        if mode & 0x400000 != 0 {
            return Err("Create spline is not reconstructed".into());
        }
        reader.take(20)?; // time, xyz, facing
        if mode & 0x2000000 != 0 {
            reader.take(24)?;
        }
        if mode & 0x200000 != 0 {
            reader.take(4)?;
        }
        reader.take(4)?;
        if mode & 0x2000 != 0 {
            reader.take(16)?;
        }
        if mode & 0x4000000 != 0 {
            reader.take(4)?;
        }
        reader.take(24)?; // six speeds
    } else if flags & 0x40 != 0 {
        reader.take(16)?;
    }
    if flags & 8 != 0 {
        reader.take(4)?;
    }
    if flags & 0x10 != 0 {
        reader.take(4)?;
    }
    if flags & 4 != 0 {
        reader.guid(true, true)?;
    }
    if flags & 2 != 0 {
        reader.take(4)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectBlock {
    pub kind: u8,
    pub guid: u64,
    pub object_type: Option<u8>,
    /// The block's bytes, after any GUID remapping.
    pub data: Vec<u8>,
    pub fields: BTreeMap<u32, u32>,
}

/// GUID-valued unit fields remapped by `objects` (field and field+1 form a u64).
const GUID_FIELDS: [u32; 9] = [0, 6, 8, 10, 12, 14, 16, 18, 20];

/// Parses an object update packet. With `remap`, GUIDs (and the standard
/// GUID-valued fields) are rewritten in the returned `data`.
pub fn objects(body: &[u8], remap: bool, guid_map: Option<&HashMap<u64, u64>>) -> Result<Vec<ObjectBlock>> {
    let mut r = Reader::configured(body, remap, HOST, None, guid_map);
    let count = r.integer(4)? as usize;
    if count > MAX_QUEUE || r.integer(1)? != 0 {
        return Err("Unsupported world object count/transport".into());
    }
    let mut result: Vec<ObjectBlock> = Vec::new();
    for _ in 0..count {
        let start = r.pos;
        let kind = r.integer(1)? as u8;
        if kind == 4 || kind == 5 {
            let size = r.integer(4)? as usize;
            if size > MAX_QUEUE || result.len() + size > MAX_QUEUE {
                return Err("World GUID list exceeds bound".into());
            }
            for _ in 0..size {
                let begin = r.pos;
                let guid = r.guid(true, true)?;
                let mut data = vec![kind];
                data.extend_from_slice(&1u32.to_le_bytes());
                data.extend_from_slice(&r.body[begin..r.pos]);
                result.push(ObjectBlock { kind, guid, object_type: None, data, fields: BTreeMap::new() });
            }
            continue;
        }
        if kind > 3 {
            return Err(format!("Unreconstructed update type {kind}"));
        }
        let guid = r.guid(true, true)?;
        let object_type = if kind == 2 || kind == 3 { Some(r.integer(1)? as u8) } else { None };
        if kind >= 1 {
            movement_block(&mut r)?;
        }
        let mut fields = BTreeMap::new();
        let mut offsets: BTreeMap<u32, usize> = BTreeMap::new();
        if kind != 1 {
            let mask_bytes = r.integer(1)? as usize * 4;
            let range = r.take(mask_bytes)?;
            let mask: Vec<u8> = r.body[range].to_vec();
            for field in 0..(mask_bytes as u32 * 8) {
                if mask[(field / 8) as usize] & (1 << (field % 8)) != 0 {
                    offsets.insert(field, r.pos);
                    fields.insert(field, r.integer(4)? as u32);
                }
            }
            for field in GUID_FIELDS {
                if remap && fields.contains_key(&field) {
                    let original = fields[&field] as u64 | ((fields.get(&(field + 1)).copied().unwrap_or(0) as u64) << 32);
                    let target = guid_map
                        .and_then(|map| map.get(&original).copied())
                        .unwrap_or(if original == HOST_SELF_KEY { HOST } else { original });
                    if target != original {
                        if !offsets.contains_key(&(field + 1)) && (target >> 32) != 0 {
                            return Err("Remapped GUID needs its high field".into());
                        }
                        let at = offsets[&field];
                        r.body[at..at + 4].copy_from_slice(&((target & 0xFFFF_FFFF) as u32).to_le_bytes());
                        if let Some(high) = offsets.get(&(field + 1)) {
                            r.body[*high..*high + 4].copy_from_slice(&((target >> 32) as u32).to_le_bytes());
                        }
                    }
                }
            }
        }
        result.push(ObjectBlock { kind, guid, object_type, data: r.body[start..r.pos].to_vec(), fields });
    }
    r.end()?;
    Ok(result)
}

/// `original == SELF` test used by the GUID-field remap in `objects`.
const HOST_SELF_KEY: u64 = SELF;

/// True for a ground-spell create; malformed type-6 creates fail closed.
pub fn dynamic_object(block: &ObjectBlock, native: bool) -> Result<bool> {
    if !(block.kind == 2 || block.kind == 3) || block.object_type != Some(DYNAMIC_OBJECT) {
        return Ok(false);
    }
    let reserved: u64 = if native { 0x0000_FFFF_FFC0_0000 } else { 0x0000_FFFF_FF00_0000 };
    let field = |k: u32| block.fields.get(&k).copied().unwrap_or(0) as u64;
    if block.guid >> 48 != 0xF100
        || block.guid & reserved != 0
        || (field(0) | (field(1) << 32)) != block.guid
        || block.fields.get(&2) != Some(&0x41)
        || !block.fields.contains_key(&6)
        || !block.fields.contains_key(&7)
    {
        return Err("Native dynamic object exceeds reconstructed layout".into());
    }
    Ok(true)
}

pub fn dynamic_caster(block: &ObjectBlock) -> Result<u64> {
    match (block.fields.get(&6), block.fields.get(&7)) {
        (Some(low), Some(high)) => Ok(*low as u64 | ((*high as u64) << 32)),
        _ => Err("Dynamic object has no caster fields".into()),
    }
}

pub fn object_packet(blocks: &[ObjectBlock]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    out.push(0);
    for block in blocks {
        out.extend_from_slice(&block.data);
    }
    out
}

/// Level-up healing must not make a still-downed avatar appear alive.
pub fn downed_player_values(body: &[u8]) -> Result<Vec<u8>> {
    let mut blocks = objects(body, false, None)?;
    let mut changed = false;
    for index in 0..blocks.len() {
        let block = &blocks[index];
        if block.guid == SELF && block.kind == 0 && block.fields.get(&22).copied().unwrap_or(0) != 0 {
            let mut fields = block.fields.clone();
            fields.insert(22, 0);
            let rebuilt = objects(&values_packet(SELF, &fields)?, false, None)?;
            let first = rebuilt.into_iter().next().ok_or("empty rebuilt values packet")?;
            blocks[index] = first;
            changed = true;
        }
    }
    Ok(if changed { object_packet(&blocks) } else { body.to_vec() })
}

/// Rewrites the actual GUID fields of a combat packet; never searches bytes.
pub fn remap_combat(
    opcode: u16,
    body: &[u8],
    player_guid: u64,
    local_guid: Option<u64>,
    guid_map: Option<&HashMap<u64, u64>>,
) -> Result<Vec<u8>> {
    let mut r = Reader::configured(body, true, player_guid, local_guid, guid_map);
    match opcode {
        DESTROY | 0x1F3 => {
            r.guid(false, true)?;
            r.take_rest()?;
        }
        MONSTER => {
            r.guid(true, true)?;
            r.take(16)?;
            if r.integer(1)? == 3 {
                r.guid(false, true)?;
            }
            r.take_rest()?;
        }
        0x143 => {
            r.guid(false, true)?;
            r.guid(false, true)?;
        }
        0x144 | 0x250 | 0x24E | 0x14A => {
            if opcode == 0x14A {
                r.take(4)?; // hit flags, then packed attacker and target
            }
            r.guid(true, true)?;
            r.guid(true, true)?;
            r.take_rest()?;
        }
        0x131 | 0x132 => {
            r.guid(true, true)?;
            r.guid(true, true)?;
            r.take(4)?;
            let flags = r.integer(2)?;
            if opcode == 0x131 {
                r.take(4)?;
            } else {
                for _ in 0..r.integer(1)? {
                    r.guid(false, true)?;
                }
                for _ in 0..r.integer(1)? {
                    r.guid(false, true)?;
                    if r.integer(1)? == 11 {
                        r.take(1)?; // reflect's outcome byte
                    }
                }
            }
            let mask = r.integer(2)?;
            if mask & (2 | 0x800 | 0x200 | 0x8000) != 0 {
                r.guid(true, true)?;
            }
            if mask & (0x10 | 0x1000) != 0 {
                r.guid(true, true)?;
            }
            if mask & 0x20 != 0 {
                r.take(12)?;
            }
            if mask & 0x40 != 0 {
                r.take(12)?;
            }
            if mask & 0x2000 != 0 {
                while r.integer(1)? != 0 {}
            }
            if flags & 0x20 != 0 {
                r.take(8)?;
            }
        }
        _ => return Err("Unreconstructed combat opcode".into()),
    }
    r.end()?;
    Ok(r.body)
}
