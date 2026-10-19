//! `guest_auras.validate_auras`: strict validation of the `auras` field a guest sends.

use crate::{as_big, as_int, Result};
use azcoop_world::auras::{enemy_guid, Aura, DEBUFF_SLOTS, MAX_ENEMIES, MAX_SPELL};
use serde_json::Value;

/// Returns `(guid, debuffs)` in the order a Python dict would hold them: a repeated
/// GUID keeps the position of its first entry and the value of its last.
pub fn validate_auras(auras: &Value) -> Result<Vec<(u64, Vec<Aura>)>> {
    let list = auras.as_array().filter(|a| a.len() <= MAX_ENEMIES).ok_or("Invalid guest aura batch")?;
    let mut result: Vec<(u64, Vec<Aura>)> = Vec::new();
    for entry in list {
        let pair = entry.as_array().filter(|e| e.len() == 2).ok_or("Invalid guest aura entry")?;
        let guid = as_big(&pair[0]).filter(|g| (0..=u64::MAX as i128).contains(g) && enemy_guid(*g as u64)).ok_or("Invalid guest aura entry")? as u64;
        let debuffs_json = pair[1].as_array().filter(|d| d.len() <= DEBUFF_SLOTS.len()).ok_or("Invalid guest aura entry")?;
        let mut debuffs = Vec::with_capacity(debuffs_json.len());
        for aura in debuffs_json {
            let a = aura.as_array().filter(|a| a.len() == 4).ok_or("Invalid guest aura")?;
            let v: Option<Vec<i64>> = a.iter().map(as_int).collect();
            let v = v.ok_or("Invalid guest aura")?;
            if !(0 < v[0] && v[0] as u64 <= MAX_SPELL) || !(0..=0xF).contains(&v[1]) || !(0..=0xFF).contains(&v[2]) || !(0..=0xFF).contains(&v[3]) {
                return Err("Invalid guest aura".into());
            }
            debuffs.push([v[0] as u32, v[1] as u32, v[2] as u32, v[3] as u32]);
        }
        match result.iter_mut().find(|(g, _)| *g == guid) {
            Some(existing) => existing.1 = debuffs,
            None => result.push((guid, debuffs)),
        }
    }
    Ok(result)
}
