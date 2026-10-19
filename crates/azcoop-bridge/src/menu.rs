//! The party menu's host side (`party_menu.py`): which zone the host's native Enter selection published.

use crate::client::{Client, Result};

/// Memory reads of the party menu (the client's `memory`, or a test image).
pub type Reader<'a> = dyn FnMut(u64, usize) -> Result<Vec<u8>> + 'a;

/// `party_menu.ZONES`, in the native table order.
pub const ZONES: [&str; 9] = ["elwynn", "duskwood", "wsg", "ab", "feralas", "arena", "av", "brm", "aq"];

/// Every zone name any supported build knows (0.97.1 added ungoro, sm and naxx): what a message from the host may name.
pub const ALL_ZONES: [&str; 12] = ["elwynn", "duskwood", "wsg", "ungoro", "ab", "feralas", "arena", "sm", "av", "brm", "aq", "naxx"];

/// The zones of this build in the native table order: from the profile, the nine of 0.95.0 when it lists none.
pub fn zones_of(menu: Option<&azcoop_game::profile::Menu>) -> Vec<String> {
    match menu {
        Some(menu) if !menu.zones.is_empty() => menu.zones.clone(),
        _ => ZONES.iter().map(|z| z.to_string()).collect(),
    }
}

/// `host_zone(client, account, config)`: the selected zone, clamped to what the class has unlocked
/// (the reviewed native per-class unlock clamp, without writing saves).
pub fn host_zone(client: &mut dyn Client, account: u64, config: u64, zones: &[String]) -> Result<String> {
    zone_in(&mut |address, length| client.memory(address, length), account, config, zones)
}

/// [`host_zone`] over any memory, for the nine zones of 0.95.0.
pub fn zone_from(memory: &mut Reader<'_>, account: u64, config: u64) -> Result<&'static str> {
    let zones: Vec<String> = ZONES.iter().map(|z| z.to_string()).collect();
    let name = zone_in(memory, account, config, &zones)?;
    Ok(ZONES.iter().find(|z| **z == name).copied().expect("a zone of the list"))
}

/// The selected zone of `config`, clamped to the class's unlocks, for the zone list of the build.
pub fn zone_in(memory: &mut Reader<'_>, account: u64, config: u64, zones: &[String]) -> Result<String> {
    let head = memory(config + 0x20, 16)?;
    let pointer = u64::from_le_bytes(head[..8].try_into().unwrap());
    let length = u64::from_le_bytes(head[8..16].try_into().unwrap());
    if !(1..=16).contains(&length) {
        return Err("Invalid native zone name".into());
    }
    let name = memory(pointer, length as usize)?;
    let selected = zones.iter().position(|z| z.as_bytes() == name.as_slice()).ok_or("Unknown native zone")?;
    let class_id = memory(config + 0x38, 1)?[0];
    let head = memory(account + 0x20, 16)?;
    let pointer = u64::from_le_bytes(head[..8].try_into().unwrap());
    let count = u64::from_le_bytes(head[8..16].try_into().unwrap());
    if count > 32 {
        return Err("Invalid native class unlocks".into());
    }
    let entries = if count > 0 { memory(pointer, count as usize * 16)? } else { Vec::new() };
    let unlocked = (0..entries.len())
        .step_by(16)
        .find(|i| entries[*i] == class_id)
        .map_or(1, |i| u64::from_le_bytes(entries[i + 8..i + 16].try_into().unwrap()));
    let unlocked = unlocked.clamp(1, zones.len() as u64) as usize;
    Ok(zones[selected.min(unlocked - 1)].clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny memory image: the config (zone name pointer/length at +0x20, class at +0x38) and the account's unlock entries.
    fn image(zone: &str, class: u8, unlocked: u64) -> impl FnMut(u64, usize) -> Result<Vec<u8>> {
        let name = zone.as_bytes().to_vec();
        move |address, length| {
            let mut out = vec![0u8; length];
            let put = |out: &mut Vec<u8>, base: u64, at: u64, bytes: &[u8]| {
                for (i, b) in bytes.iter().enumerate() {
                    let a = at + i as u64;
                    if a >= base && a < base + length as u64 {
                        out[(a - base) as usize] = *b;
                    }
                }
            };
            // config at 0x1000: name pointer 0x3000, length, class
            put(&mut out, address, 0x1020, &0x3000u64.to_le_bytes());
            put(&mut out, address, 0x1028, &(name.len() as u64).to_le_bytes());
            put(&mut out, address, 0x1038, &[class]);
            put(&mut out, address, 0x3000, &name);
            // account at 0x2000: one entry (class, unlocked count) at 0x4000
            put(&mut out, address, 0x2020, &0x4000u64.to_le_bytes());
            put(&mut out, address, 0x2028, &1u64.to_le_bytes());
            put(&mut out, address, 0x4000, &[class]);
            put(&mut out, address, 0x4008, &unlocked.to_le_bytes());
            Ok(out)
        }
    }

    #[test]
    fn the_zone_list_follows_the_build() {
        let nine = zones_of(None);
        assert_eq!(nine.len(), 9);
        let twelve: Vec<String> = ALL_ZONES.iter().map(|z| z.to_string()).collect();
        // ungoro is the fourth zone of 0.97.1: selected and unlocked, it stays; a class with 3 unlocked zones is clamped to wsg
        assert_eq!(zone_in(&mut image("ungoro", 3, 12), 0x2000, 0x1000, &twelve).unwrap(), "ungoro");
        assert_eq!(zone_in(&mut image("naxx", 3, 12), 0x2000, 0x1000, &twelve).unwrap(), "naxx");
        assert_eq!(zone_in(&mut image("naxx", 3, 3), 0x2000, 0x1000, &twelve).unwrap(), "wsg");
        assert!(zone_in(&mut image("naxx", 3, 12), 0x2000, 0x1000, &nine).is_err(), "0.95.0 does not know naxx");
        assert_eq!(zone_in(&mut image("aq", 3, 99), 0x2000, 0x1000, &nine).unwrap(), "aq", "nine zones: the unlock count is clamped to 9");
    }
}
