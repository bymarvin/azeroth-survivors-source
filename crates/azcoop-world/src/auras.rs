//! Guest debuffs (DoTs) on shared enemies: a port of `guest_auras.py` (0.0.15).
//!
//! `OwnAuras` (guest side) collects the debuffs of the player's own enemy mirrors
//! and reports changes; `AuraOverlay` (host side) places guest debuffs into the
//! free debuff slots of the shared enemies and returns sparse VALUES updates.
//! Order matters (recency decides what is dropped at the bound), so the maps keep
//! Python's dict insertion order.

use crate::ObjectBlock;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const DEBUFF_SLOTS: std::ops::Range<u32> = 32..48;
pub const MAX_ENEMIES: usize = 32_768;
pub const MAX_SPELL: u64 = 0xFFFF_FFFF;

/// (spell, flags, level, applications)
pub type Aura = [u32; 4];

pub fn spell_field(slot: u32) -> u32 {
    47 + slot
}

/// (field, shift, mask) of a slot's flags, level and applications.
pub fn packed(slot: u32) -> [(u32, u32, u32); 3] {
    [(95 + slot / 8, slot % 8 * 4, 0xF), (101 + slot / 4, slot % 4 * 8, 0xFF), (113 + slot / 4, slot % 4 * 8, 0xFF)]
}

/// Closed form of {spell_field(s)} + {packed(s) fields} over the debuff slots (checked in the unit test).
fn is_aura_field(field: u32) -> bool {
    matches!(field, 79..=94 | 99..=100 | 109..=112 | 121..=124)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_form_matches_the_definition() {
        for field in 0..300u32 {
            let defined = DEBUFF_SLOTS.clone().any(|s| spell_field(s) == field || packed(s).iter().any(|(f, _, _)| *f == field));
            assert_eq!(is_aura_field(field), defined, "field {field}");
        }
    }
}

pub fn enemy_guid(guid: u64) -> bool {
    guid >> 48 == 0xF130
}

/// `{slot: (spell, flags, level, applications)}` of one unit's aura fields.
pub fn slot_auras(fields: &BTreeMap<u32, u32>) -> BTreeMap<u32, Aura> {
    let mut result = BTreeMap::new();
    for slot in DEBUFF_SLOTS {
        let spell = fields.get(&spell_field(slot)).copied().unwrap_or(0);
        if spell != 0 {
            let [f, l, a] = packed(slot).map(|(field, shift, mask)| (fields.get(&field).copied().unwrap_or(0) >> shift) & mask);
            result.insert(slot, [spell, f, l, a]);
        }
    }
    result
}

/// A dict with Python's insertion order: `set` keeps the position of an existing
/// key, `remove` then `set` moves it to the end.
#[derive(Debug, Clone)]
pub struct Ordered<V> {
    map: HashMap<u64, (u64, V)>,
    order: BTreeMap<u64, u64>,
    stamp: u64,
}

impl<V> Default for Ordered<V> {
    fn default() -> Self {
        Ordered { map: HashMap::new(), order: BTreeMap::new(), stamp: 0 }
    }
}

impl<V> Ordered<V> {
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn contains(&self, key: u64) -> bool {
        self.map.contains_key(&key)
    }
    pub fn get(&self, key: u64) -> Option<&V> {
        self.map.get(&key).map(|(_, v)| v)
    }
    pub fn get_mut(&mut self, key: u64) -> Option<&mut V> {
        self.map.get_mut(&key).map(|(_, v)| v)
    }
    pub fn set(&mut self, key: u64, value: V) {
        if let Some(entry) = self.map.get_mut(&key) {
            entry.1 = value;
        } else {
            self.stamp += 1;
            self.order.insert(self.stamp, key);
            self.map.insert(key, (self.stamp, value));
        }
    }
    pub fn remove(&mut self, key: u64) -> Option<V> {
        let (stamp, value) = self.map.remove(&key)?;
        self.order.remove(&stamp);
        Some(value)
    }
    pub fn first_key(&self) -> Option<u64> {
        self.order.values().next().copied()
    }
    pub fn keys(&self) -> Vec<u64> {
        self.order.values().copied().collect()
    }
}

// ---------------------------------------------------------------------------

/// Guest side: debuffs of this player's native mirrors, sent when they change.
pub struct OwnAuras {
    limit: usize,
    fields: Ordered<BTreeMap<u32, u32>>,
    inactive: Ordered<()>,
    sent: HashMap<u64, Vec<Aura>>,
    changed: BTreeSet<u64>,
    pub dropped: u64,
}

impl OwnAuras {
    pub fn new(limit: usize) -> OwnAuras {
        OwnAuras { limit, fields: Ordered::default(), inactive: Ordered::default(), sent: HashMap::new(), changed: BTreeSet::new(), dropped: 0 }
    }

    pub fn observe(&mut self, block: &ObjectBlock) {
        if !enemy_guid(block.guid) {
            return;
        }
        if block.kind == 4 {
            self.destroy(block.guid);
            return;
        }
        if matches!(block.kind, 2 | 3) && self.forget(block.guid) {
            self.changed.insert(block.guid);
        }
        if !block.fields.keys().any(|f| is_aura_field(*f)) {
            return;
        }
        let state = self.fields.remove(block.guid);
        self.inactive.remove(block.guid);
        let mut state = match state {
            Some(s) => s,
            None => {
                if self.fields.len() >= self.limit {
                    self.drop_oldest();
                }
                BTreeMap::new()
            }
        };
        for (field, value) in &block.fields {
            if is_aura_field(*field) {
                state.insert(*field, *value);
            }
        }
        self.fields.set(block.guid, state);
        self.changed.insert(block.guid);
    }

    fn forget(&mut self, guid: u64) -> bool {
        self.inactive.remove(guid);
        self.fields.remove(guid).is_some()
    }

    fn drop_oldest(&mut self) {
        let guid = self.inactive.first_key().or_else(|| self.fields.first_key()).expect("a full table is not empty");
        self.forget(guid);
        self.changed.insert(guid);
        self.dropped += 1;
    }

    pub fn destroy(&mut self, guid: u64) {
        if self.forget(guid) || self.sent.contains_key(&guid) {
            self.changed.insert(guid);
        }
    }

    /// Changed enemies `[(guid, debuffs)]`, at most `limit`; the rest next time.
    pub fn take_changes(&mut self, limit: usize) -> Vec<(u64, Vec<Aura>)> {
        let mut result = Vec::new();
        for guid in self.changed.clone() {
            if result.len() >= limit {
                break;
            }
            self.changed.remove(&guid);
            let state = self.fields.get(guid);
            let debuffs: Vec<Aura> = state.map(slot_auras).unwrap_or_default().into_values().collect();
            if debuffs != self.sent.get(&guid).cloned().unwrap_or_default() {
                result.push((guid, debuffs.clone()));
                if debuffs.is_empty() {
                    self.sent.remove(&guid);
                } else {
                    self.sent.insert(guid, debuffs.clone());
                }
            }
            if let Some(state) = self.fields.get(guid) {
                if debuffs.is_empty() {
                    if state.values().any(|v| *v != 0) {
                        self.inactive.set(guid, ()); // keeps packed flags a later spell write may rely on
                    } else {
                        self.forget(guid);
                    }
                }
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------

/// Host side: places guest debuffs into free debuff slots of the shared enemies.
pub struct AuraOverlay {
    limit: usize,
    pub dropped: u64,
    host: HashMap<u64, BTreeMap<u32, u32>>,
    guests: Ordered<BTreeMap<u32, Vec<Aura>>>,
    slots: HashMap<u64, BTreeMap<u32, (u32, u32)>>,
    emitted: HashMap<u64, BTreeMap<u32, u32>>,
    pub dirty: BTreeSet<u64>,
}

impl AuraOverlay {
    pub fn new(limit: usize) -> AuraOverlay {
        AuraOverlay { limit, dropped: 0, host: HashMap::new(), guests: Ordered::default(), slots: HashMap::new(), emitted: HashMap::new(), dirty: BTreeSet::new() }
    }

    pub fn host_block(&mut self, block: &ObjectBlock) {
        if !enemy_guid(block.guid) {
            return;
        }
        if block.kind == 4 {
            self.destroy(block.guid);
            return;
        }
        if matches!(block.kind, 2 | 3) {
            self.host.remove(&block.guid);
            self.emitted.remove(&block.guid);
            if self.guests.contains(block.guid) {
                self.dirty.insert(block.guid);
            }
        }
        if !block.fields.keys().any(|f| is_aura_field(*f)) {
            return;
        }
        let state = self.host.entry(block.guid).or_default();
        let emitted = self.emitted.get_mut(&block.guid);
        let mut emitted = emitted;
        for (field, value) in &block.fields {
            if is_aura_field(*field) {
                state.insert(*field, *value);
                if let Some(e) = emitted.as_deref_mut() {
                    e.remove(field);
                }
            }
        }
        if self.guests.contains(block.guid) {
            self.dirty.insert(block.guid);
        }
    }

    pub fn destroy(&mut self, guid: u64) {
        self.host.remove(&guid);
        self.guests.remove(guid);
        self.slots.remove(&guid);
        self.emitted.remove(&guid);
        self.dirty.remove(&guid);
    }

    /// `auras` come from `validate_auras`: `(guid, debuffs)` in message order.
    pub fn guest_auras(&mut self, player: u32, auras: &[(u64, Vec<Aura>)]) {
        for (guid, debuffs) in auras {
            let mut owners = self.guests.remove(*guid).unwrap_or_default();
            if !debuffs.is_empty() {
                owners.insert(player, debuffs.clone());
            } else {
                owners.remove(&player);
            }
            if !owners.is_empty() {
                self.guests.set(*guid, owners); // most recently changed last
            }
            self.dirty.insert(*guid);
        }
        while self.guests.len() > self.limit {
            let oldest = self.guests.first_key().unwrap();
            self.guests.remove(oldest);
            self.dirty.insert(oldest);
            self.dropped += 1;
        }
    }

    pub fn drop_player(&mut self, player: u32) {
        for guid in self.guests.keys() {
            if self.guests.get(guid).is_some_and(|o| o.contains_key(&player)) {
                self.guest_auras(player, &[(guid, Vec::new())]);
            }
        }
    }

    /// `[(guid, {field: value})]` to write for every dirty enemy the clients know.
    pub fn updates(&mut self, visible: &HashSet<u64>) -> Vec<(u64, BTreeMap<u32, u32>)> {
        let mut result = Vec::new();
        for guid in self.dirty.clone() {
            if !visible.contains(&guid) {
                continue;
            }
            let fields = self.overlay(guid);
            if !fields.is_empty() {
                result.push((guid, fields));
            }
        }
        self.dirty = self.dirty.iter().copied().filter(|g| !visible.contains(g) && self.guests.contains(*g)).collect();
        if self.host.len() > 4 * MAX_ENEMIES {
            let gone: Vec<u64> = self.host.keys().copied().filter(|g| !visible.contains(g)).collect();
            for guid in gone {
                self.destroy(guid);
            }
        }
        result
    }

    fn overlay(&mut self, guid: u64) -> BTreeMap<u32, u32> {
        let empty = BTreeMap::new();
        let host = self.host.get(&guid).unwrap_or(&empty);
        let used: BTreeSet<u32> = DEBUFF_SLOTS.filter(|s| host.get(&spell_field(*s)).copied().unwrap_or(0) != 0).collect();
        let host_spells: BTreeSet<u32> = used.iter().map(|s| host[&spell_field(*s)]).collect();
        // wanted: (player, spell) -> aura, in insertion order.
        let mut wanted: Vec<((u32, u32), Aura)> = Vec::new();
        if let Some(owners) = self.guests.get(guid) {
            for (player, auras) in owners {
                for aura in auras {
                    if !host_spells.contains(&aura[0]) && !wanted.iter().any(|(k, _)| *k == (*player, aura[0])) {
                        wanted.push(((*player, aura[0]), *aura));
                    }
                }
            }
        }
        let previous = self.slots.get(&guid).cloned().unwrap_or_default();
        let mut assigned: BTreeMap<u32, (u32, u32)> =
            previous.into_iter().filter(|(s, key)| !used.contains(s) && wanted.iter().any(|(k, _)| k == key)).collect();
        let mut free: Vec<u32> = DEBUFF_SLOTS.rev().filter(|s| !used.contains(s) && !assigned.contains_key(s)).collect();
        for (key, _) in &wanted {
            if !assigned.values().any(|v| v == key) && !free.is_empty() {
                assigned.insert(free.remove(0), *key);
            }
        }
        if assigned.is_empty() {
            self.slots.remove(&guid);
        } else {
            self.slots.insert(guid, assigned.clone());
        }
        let mut desired: BTreeMap<u32, u32> = BTreeMap::new();
        for slot in DEBUFF_SLOTS {
            if used.contains(&slot) {
                continue;
            }
            let aura = match assigned.get(&slot) {
                Some(key) => wanted.iter().find(|(k, _)| k == key).map(|(_, a)| *a).unwrap(),
                None => [0, 0, 0, 0],
            };
            desired.insert(spell_field(slot), aura[0]);
            for ((field, shift, mask), value) in packed(slot).into_iter().zip(&aura[1..]) {
                let base = desired.get(&field).copied().unwrap_or_else(|| host.get(&field).copied().unwrap_or(0));
                desired.insert(field, base & !(mask << shift) | (value << shift));
            }
        }
        let emitted = self.emitted.entry(guid).or_default();
        let fields: BTreeMap<u32, u32> = desired
            .into_iter()
            .filter(|(f, v)| emitted.get(f).copied().unwrap_or_else(|| host.get(f).copied().unwrap_or(0)) != *v)
            .collect();
        for (f, v) in &fields {
            emitted.insert(*f, *v);
        }
        fields
    }
}

// ---- state views (tests and logs) -------------------------------------------

/// `[(guid, [(field, value)])]` in recency order.
pub type FieldsView = Vec<(u64, Vec<(u32, u32)>)>;

impl OwnAuras {
    /// (fields in recency order, inactive in order, sent sorted, changed, dropped)
    pub fn state(&self) -> (FieldsView, Vec<u64>, Vec<(u64, Vec<Aura>)>, Vec<u64>, u64) {
        let fields = self.fields.keys().into_iter().map(|g| (g, self.fields.get(g).unwrap().iter().map(|(k, v)| (*k, *v)).collect())).collect();
        let mut sent: Vec<(u64, Vec<Aura>)> = self.sent.iter().map(|(g, a)| (*g, a.clone())).collect();
        sent.sort();
        (fields, self.inactive.keys(), sent, self.changed.iter().copied().collect(), self.dropped)
    }
}

/// Overlay state: host fields (sorted), guest debuffs (recency order), slots (sorted),
/// emitted (sorted), dirty, dropped.
pub struct OverlayView {
    pub host: FieldsView,
    pub guests: Vec<(u64, Vec<(u32, Vec<Aura>)>)>,
    pub slots: Vec<(u64, Vec<(u32, u32, u32)>)>,
    pub emitted: FieldsView,
    pub dirty: Vec<u64>,
    pub dropped: u64,
}

impl AuraOverlay {
    pub fn state(&self) -> OverlayView {
        let sorted_map = |m: &HashMap<u64, BTreeMap<u32, u32>>| {
            let mut v: FieldsView = m.iter().map(|(g, f)| (*g, f.iter().map(|(k, x)| (*k, *x)).collect())).collect();
            v.sort();
            v
        };
        let mut slots: Vec<(u64, Vec<(u32, u32, u32)>)> =
            self.slots.iter().map(|(g, s)| (*g, s.iter().map(|(slot, (p, sp))| (*slot, *p, *sp)).collect())).collect();
        slots.sort();
        OverlayView {
            host: sorted_map(&self.host),
            guests: self.guests.keys().into_iter().map(|g| (g, self.guests.get(g).unwrap().iter().map(|(p, a)| (*p, a.clone())).collect())).collect(),
            slots,
            emitted: sorted_map(&self.emitted),
            dirty: self.dirty.iter().copied().collect(),
            dropped: self.dropped,
        }
    }
}
