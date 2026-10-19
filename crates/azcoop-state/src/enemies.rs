//! The protocol 3 enemy delta codec: a port of the enemy parts of
//! `online_bridge.py` (record layout helpers, `apply_enemy_update`) and of
//! `GroupOnlineBridge.enemy_update` (the host's per-guest delta encoder).
//!
//! An update is `{seq, base, blob[, drop]}`. The blob concatenates entries
//! `<Q guid><B flags> [FULL: record [BOSS: <Q boss>]] [PATCH: runs]
//! [SPANS: debuff spans] [MOTION: <4d hp x y z>]`. A delta builds on the last
//! applied sequence; anything else asks for a full snapshot instead of failing.

use crate::{as_big, as_int, binary, unbinary, Result};
use azcoop_game::builds::Variant;
use azcoop_world::auras::Ordered;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const ENEMY_FULL: u8 = 1;
pub const ENEMY_PATCH: u8 = 2;
pub const ENEMY_SPANS_SET: u8 = 4;
pub const ENEMY_BOSS: u8 = 8;
pub const ENEMY_MOTION: u8 = 16;
pub const MAX_ENEMIES: usize = 32_768;
pub const MAX_ENEMY_HP: f64 = 1e15;

/// Record layout helpers of one build (module constants of `online_bridge.py`).
#[derive(Debug, Clone)]
pub struct Codec {
    pub flat: usize,
    volatile: [(usize, usize); 3],
    spans: [(usize, usize); 3],
    pub span_bytes: usize,
    /// (start of guid, end of guid + definition) inside the record.
    pub identity: (usize, usize),
    pub image_size: u64,
}

impl Codec {
    pub fn new(variant: Variant, image_size: u64) -> Codec {
        let member = |offset: u64| variant.enemy_offset(offset) as usize - 0x68;
        let spans = [(member(0x88), member(0x98)), (member(0x124), member(0x128)), (member(0x130), member(0x140))];
        Codec {
            flat: variant.enemy_layout().stride as usize - 0x68,
            volatile: [(0, 4), (member(0xE0), 4), (member(0xFC), 0x20)],
            span_bytes: spans.iter().map(|(a, b)| b - a).sum(),
            spans,
            identity: (member(0x78), member(0x80) + 8),
            image_size,
        }
    }

    /// `enemy_parts`: (stable bytes with the volatile parts and debuff spans zeroed, the spans).
    pub fn parts(&self, flat: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if flat.len() != self.flat {
            return Err("Invalid co-op enemy record length".into());
        }
        let mut stable = flat.to_vec();
        for (start, size) in self.volatile {
            stable[start..start + size].fill(0);
        }
        let mut spans = Vec::with_capacity(self.span_bytes);
        for (start, end) in self.spans {
            spans.extend_from_slice(&flat[start..end]);
            stable[start..end].fill(0);
        }
        Ok((stable, spans))
    }

    /// `with_spans`.
    pub fn with_spans(&self, flat: &[u8], spans: &[u8]) -> Result<Vec<u8>> {
        if spans.len() != self.span_bytes {
            return Err("Invalid co-op enemy debuff span".into());
        }
        let mut flat = flat.to_vec();
        let mut offset = 0;
        for (start, end) in self.spans {
            flat[start..end].copy_from_slice(&spans[offset..offset + end - start]);
            offset += end - start;
        }
        Ok(flat)
    }

    /// `enemy_patch_runs`: changed byte runs of two stable records; gaps under four bytes are merged.
    pub fn patch_runs(&self, old: &[u8], new: &[u8]) -> Vec<(usize, usize)> {
        let diff: Vec<u8> = old.iter().zip(new).map(|(a, b)| a ^ b).collect();
        let mut runs = Vec::new();
        let mut i = 0;
        while i < diff.len() {
            if diff[i] == 0 {
                i += 1;
                continue;
            }
            let start = i;
            let mut end = i + 1;
            loop {
                // up to three zero bytes followed by another changed byte extend the run
                let next = (end..(end + 4).min(diff.len())).find(|j| diff[*j] != 0);
                match next {
                    Some(j) => end = j + 1,
                    None => break,
                }
            }
            runs.push((start, end));
            i = end;
        }
        runs
    }

    /// `enemy_entry`.
    pub fn entry(&self, guid: u64, flags: u8, flat: &[u8], boss: Option<u64>, runs: &[(usize, usize)], spans: &[u8], motion: &[u8]) -> Result<Vec<u8>> {
        let mut out = guid.to_le_bytes().to_vec();
        out.push(flags);
        if flags & ENEMY_FULL != 0 {
            out.extend_from_slice(flat);
            if flags & ENEMY_BOSS != 0 {
                out.extend_from_slice(&boss.ok_or("boss flag without a boss")?.to_le_bytes());
            }
        }
        if flags & ENEMY_PATCH != 0 {
            if runs.len() > 255 {
                return Err("too many patch runs".into());
            }
            out.push(runs.len() as u8);
            for (start, end) in runs {
                out.push(*start as u8);
                out.push((end - start) as u8);
                out.extend_from_slice(&flat[*start..*end]);
            }
        }
        if flags & ENEMY_SPANS_SET != 0 {
            out.extend_from_slice(spans);
        }
        if flags & ENEMY_MOTION != 0 {
            out.extend_from_slice(motion);
        }
        Ok(out)
    }

    /// `checked_enemy_flat` / `validated_enemy`: the record belongs to `guid` and its definition lies in the image.
    pub fn check(&self, guid: u64, flat: &[u8], boss: Option<u64>) -> Result<()> {
        let id = self.identity.0;
        if flat.len() != self.flat || u64::from_le_bytes(flat[id..id + 8].try_into().unwrap()) != guid {
            return Err("Invalid co-op enemy snapshot".into());
        }
        let definition = u64::from_le_bytes(flat[id + 8..id + 16].try_into().unwrap());
        if definition >= self.image_size || (definition == 0 && boss.is_none()) {
            return Err("Invalid co-op enemy definition".into());
        }
        if boss.is_some_and(|b| b >= self.image_size - 0x58) {
            return Err("Invalid co-op boss definition".into());
        }
        Ok(())
    }
}

/// `enemy_motion`: exact hp and pose in 32 bytes.
pub fn motion_bytes(hp: f64, pose: [f64; 3]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, v) in [hp, pose[0], pose[1], pose[2]].iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------

/// One enemy of the host snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct Enemy {
    pub flat: Vec<u8>,
    pub hp: f64,
    pub pose: [f64; 3],
    pub boss: Option<u64>,
}

#[derive(Clone)]
struct Sent {
    stable: Vec<u8>,
    spans: Vec<u8>,
    motion: [u8; 32],
    boss: Option<u64>,
}

/// Host side: the delta encoder of one guest.
pub struct EnemyEncoder {
    codec: Codec,
    sent: Option<Ordered<Sent>>,
    sequence: u64,
    pub full_requested: bool,
}

impl EnemyEncoder {
    pub fn new(codec: Codec) -> EnemyEncoder {
        EnemyEncoder { codec, sent: None, sequence: 0, full_requested: false }
    }

    /// `GroupOnlineBridge.enemy_update(peer, now)`. `view` is the host snapshot in its
    /// insertion order; `periodic_full` is the optional diagnostic full snapshot.
    /// Returns the `enemy_update` object, or `None` when nothing changed.
    pub fn update(&mut self, view: &[(u64, Enemy)], periodic_full: bool) -> Result<Option<Value>> {
        let full = self.sent.is_none() || self.full_requested || periodic_full;
        let (low, high) = self.codec.identity;
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut now_view: Vec<(u64, Sent)> = Vec::with_capacity(view.len());
        let mut present = std::collections::HashSet::new();
        for (guid, enemy) in view {
            let (stable, spans) = self.codec.parts(&enemy.flat)?;
            let motion = motion_bytes(enemy.hp, enemy.pose);
            present.insert(*guid);
            let old = if full { None } else { self.sent.as_ref().and_then(|s| s.get(*guid)) };
            match old {
                Some(old) if old.boss == enemy.boss && old.stable[low..high] == stable[low..high] => {
                    let (mut flags, mut runs) = (0u8, Vec::new());
                    if old.stable != stable {
                        runs = self.codec.patch_runs(&old.stable, &stable);
                        flags |= ENEMY_PATCH;
                    }
                    if old.spans != spans {
                        flags |= ENEMY_SPANS_SET;
                    }
                    if old.motion != motion {
                        flags |= ENEMY_MOTION;
                    }
                    if flags != 0 {
                        parts.push(self.codec.entry(*guid, flags, &enemy.flat, None, &runs, &spans, &motion)?);
                    }
                }
                _ => {
                    let flags = ENEMY_FULL | ENEMY_MOTION | if enemy.boss.is_some() { ENEMY_BOSS } else { 0 };
                    parts.push(self.codec.entry(*guid, flags, &enemy.flat, enemy.boss, &[], &spans, &motion)?);
                }
            }
            now_view.push((*guid, Sent { stable, spans, motion, boss: enemy.boss }));
        }
        let drop: Vec<u64> = if full {
            Vec::new()
        } else {
            self.sent.as_ref().map(|s| s.keys().into_iter().filter(|g| !present.contains(g)).collect()).unwrap_or_default()
        };
        if !full && parts.is_empty() && drop.is_empty() {
            return Ok(None);
        }
        let base = if full { Value::Null } else { json!(self.sequence) };
        self.sequence += 1;
        let mut update = Map::new();
        update.insert("seq".into(), json!(self.sequence));
        update.insert("base".into(), base);
        update.insert("blob".into(), binary(&parts.concat()));
        if !drop.is_empty() {
            update.insert("drop".into(), json!(drop));
        }
        let mut sent = Ordered::default();
        for (guid, s) in now_view {
            sent.set(guid, s);
        }
        self.sent = Some(sent);
        if full {
            self.full_requested = false;
        }
        Ok(Some(Value::Object(update)))
    }
}

// ---------------------------------------------------------------------------

/// Guest side: the host enemy snapshot as applied from `enemy_update` messages.
#[derive(Debug, Clone, Default)]
pub struct EnemyMirror {
    pub seq: u64,
    pub snapshot: BTreeMap<u64, Enemy>,
    pub full_needed: bool,
}

impl EnemyMirror {
    /// `apply_enemy_update`. Unusable-but-honest updates (a delta that does not build on the
    /// last sequence, or for an enemy never seen) set `full_needed` and change nothing.
    pub fn apply(&mut self, codec: &Codec, update: &Value) -> Result<()> {
        let obj = update.as_object();
        let get = |k: &str| obj.and_then(|o| o.get(k));
        let seq = get("seq").and_then(as_big);
        let base = get("base");
        let drop = match get("drop") {
            None => Vec::new(),
            Some(Value::Array(a)) => a.clone(),
            Some(_) => return Err("Invalid co-op enemy update".into()),
        };
        let base_value: Option<i128> = match base {
            None | Some(Value::Null) => None,
            Some(v) => Some(as_big(v).ok_or("Invalid co-op enemy update")?),
        };
        match seq {
            Some(s) if 0 < s && s <= 1i128 << 53 && drop.len() <= MAX_ENEMIES => {}
            _ => return Err("Invalid co-op enemy update".into()),
        }
        let seq = seq.unwrap() as u64;
        if let Some(b) = base_value {
            if b != self.seq as i128 {
                self.full_needed = true;
                return Ok(());
            }
        }
        let empty = Value::String(String::new());
        let blob = get("blob").unwrap_or(&empty);
        let data = unbinary(blob, MAX_ENEMIES * 0x130)?;
        let mut snapshot: BTreeMap<u64, Enemy> = if base_value.is_none() { BTreeMap::new() } else { self.snapshot.clone() };
        for guid in &drop {
            let g = as_big(guid).ok_or("Invalid enemy identity")?;
            if let Ok(g) = u64::try_from(g) {
                snapshot.remove(&g);
            }
        }
        let size = data.len();
        let mut offset = 0usize;
        let truncated = || "Truncated co-op enemy update".to_string();
        while offset < size {
            if offset + 9 > size {
                return Err(truncated());
            }
            let guid = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            let flags = data[offset + 8];
            offset += 9;
            if flags & !0x1F != 0 || (flags & ENEMY_BOSS != 0 && flags & ENEMY_FULL == 0) || (flags & ENEMY_FULL != 0 && flags & ENEMY_PATCH != 0) {
                return Err("Invalid co-op enemy entry".into());
            }
            let previous = snapshot.get(&guid).cloned();
            let mut flat: Vec<u8>;
            let mut boss = previous.as_ref().and_then(|p| p.boss);
            if flags & ENEMY_FULL != 0 {
                // A short slice is not an error here: it fails the length check below.
                let end = (offset + codec.flat).min(size);
                flat = data[offset..end].to_vec();
                offset += codec.flat;
                let mut boss_value = None;
                if flags & ENEMY_BOSS != 0 {
                    if offset + 8 > size {
                        return Err(truncated());
                    }
                    boss_value = Some(u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()));
                    offset += 8;
                }
                codec.check(guid, &flat, boss_value)?;
                boss = boss_value;
            } else if let Some(p) = &previous {
                flat = p.flat.clone();
            } else {
                self.full_needed = true; // a delta for an enemy this guest never saw
                return Ok(());
            }
            if flags & ENEMY_PATCH != 0 {
                if offset >= size {
                    return Err(truncated());
                }
                let runs = data[offset];
                offset += 1;
                for _ in 0..runs {
                    if offset + 2 > size {
                        return Err(truncated());
                    }
                    let (start, length) = (data[offset] as usize, data[offset + 1] as usize);
                    let end = start + length;
                    if length == 0 || end > codec.flat || (start < codec.identity.1 && end > codec.identity.0) {
                        return Err("Invalid co-op enemy patch".into());
                    }
                    let chunk_end = (offset + 2 + length).min(size);
                    let chunk = &data[offset + 2..chunk_end];
                    if chunk.len() != length {
                        return Err(truncated());
                    }
                    flat[start..end].copy_from_slice(chunk);
                    offset += 2 + length;
                }
            }
            if flags & ENEMY_SPANS_SET != 0 {
                let end = (offset + codec.span_bytes).min(size);
                flat = codec.with_spans(&flat, &data[offset..end])?;
                offset += codec.span_bytes;
            }
            let (hp, pose);
            if flags & ENEMY_MOTION != 0 {
                if offset + 32 > size {
                    return Err(truncated());
                }
                let v: [f64; 4] = std::array::from_fn(|i| f64::from_le_bytes(data[offset + i * 8..offset + i * 8 + 8].try_into().unwrap()));
                offset += 32;
                if !(v[0].is_finite() && (0.0..=MAX_ENEMY_HP).contains(&v[0])) {
                    return Err("Invalid numeric co-op field".into());
                }
                hp = v[0];
                pose = [finite_f(v[1])?, finite_f(v[2])?, finite_f(v[3])?];
            } else if let Some(p) = &previous {
                hp = p.hp;
                pose = p.pose;
            } else {
                self.full_needed = true;
                return Ok(());
            }
            snapshot.insert(guid, Enemy { flat, hp, pose, boss });
        }
        if offset != size {
            return Err(truncated());
        }
        if snapshot.len() > MAX_ENEMIES {
            return Err("Too many co-op enemies".into());
        }
        self.snapshot = snapshot;
        self.seq = seq;
        self.full_needed = false;
        Ok(())
    }
}

fn finite_f(v: f64) -> Result<f64> {
    if v.is_finite() && (-100000.0..=100000.0).contains(&v) {
        Ok(v)
    } else {
        Err("Invalid numeric co-op field".into())
    }
}

// as_int is part of the public helpers used by callers.
#[allow(dead_code)]
fn _keep(v: &Value) -> Option<i64> {
    as_int(v)
}
