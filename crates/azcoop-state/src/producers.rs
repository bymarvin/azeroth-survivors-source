//! Host-side producers of the incremental state fields: ports of
//! `ReceiptBook` / `prune_receipts` (damage receipts, protocol 5 rules) and of the
//! loot (`chests` -> `chest_update`) delta of `GroupOnlineBridge.thin_snapshot`.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Cumulative damage receipts of one guest that remember which entries changed.
/// Receipts of enemies that are gone are forgotten once sent and announced as `[guid, 0]`.
#[derive(Default, Debug, Clone)]
pub struct ReceiptBook {
    receipts: HashMap<i128, f64>,
    dirty: BTreeSet<i128>,
    forgotten: BTreeSet<i128>,
}

impl ReceiptBook {
    pub fn new() -> ReceiptBook {
        ReceiptBook::default()
    }

    /// `book[guid] = value`: marks the target as changed.
    pub fn set(&mut self, guid: i128, value: f64) {
        self.receipts.insert(guid, value);
        self.dirty.insert(guid);
    }

    pub fn get(&self, guid: i128) -> Option<f64> {
        self.receipts.get(&guid).copied()
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Every receipt (order unspecified).
    pub fn items(&self) -> Vec<(i128, f64)> {
        self.receipts.iter().map(|(g, v)| (*g, *v)).collect()
    }

    /// `book.forget(guid)`: only for entries that exist (the Python raises otherwise).
    pub fn forget(&mut self, guid: i128) -> Result<(), String> {
        self.receipts.remove(&guid).ok_or_else(|| "no receipt to forget".to_string())?;
        self.forgotten.insert(guid);
        Ok(())
    }

    /// Forgotten enemies first as `[guid, 0]` (a forget precedes a later write of the same enemy),
    /// then the changed receipts. The order inside each group is unspecified in the Python (set
    /// order) and irrelevant to the receiver.
    pub fn take_changes(&mut self) -> Vec<(i128, f64)> {
        let mut changed: Vec<(i128, f64)> = self.forgotten.iter().map(|g| (*g, 0.0)).collect();
        changed.extend(self.dirty.iter().filter_map(|g| self.receipts.get(g).map(|v| (*g, *v))));
        self.forgotten.clear();
        self.dirty.clear();
        changed
    }

    /// `prune_receipts`' body for one book: forget receipts of gone enemies with nothing in flight.
    /// `alive`: the host enemy snapshot GUIDs; `pending`: GUIDs with pending damage; `owned`: GUIDs
    /// that still have damage owners.
    pub fn prune(&mut self, alive: &HashSet<u64>, pending: &HashSet<i128>, owned: &HashSet<i128>) {
        let gone: Vec<i128> = self
            .receipts
            .keys()
            .copied()
            .filter(|g| !u64::try_from(*g).is_ok_and(|g| alive.contains(&g)) && !pending.contains(g) && !owned.contains(g) && !self.dirty.contains(g))
            .collect();
        for guid in gone {
            let _ = self.forget(guid);
        }
    }

    pub fn dirty(&self) -> Vec<i128> {
        self.dirty.iter().copied().collect()
    }
}

/// Per-guest loot baseline: only changed objects go out, a congested link keeps the old baseline.
#[derive(Default, Debug, Clone)]
pub struct ChestSync {
    /// The last baseline in the host's dict order (drops are announced in that order).
    sent: Option<Vec<(i128, Value)>>,
}

impl ChestSync {
    pub fn new() -> ChestSync {
        ChestSync::default()
    }

    /// `current`: `[(guid, value)]` as the host holds them. Returns the `chest_update` object, if any.
    pub fn update(&mut self, current: &[(i128, Value)], congested: bool) -> Option<Value> {
        if congested {
            return None;
        }
        let ordered = ordered_unique(current);
        let update = match &self.sent {
            None => Some(json!({"full": true, "set": current_in_order(current)})),
            Some(previous) => {
                let before: HashMap<i128, &Value> = previous.iter().map(|(g, v)| (*g, v)).collect();
                let now: HashSet<i128> = ordered.iter().map(|(g, _)| *g).collect();
                let changed: Vec<Value> = ordered.iter().filter(|(g, v)| before.get(g).map_or(true, |p| *p != v)).map(|(g, v)| json!([g.to_string_value(), v])).collect();
                let removed: Vec<Value> = previous.iter().filter(|(g, _)| !now.contains(g)).map(|(g, _)| g.to_string_value()).collect();
                if changed.is_empty() && removed.is_empty() {
                    None
                } else {
                    Some(json!({"full": false, "set": changed, "drop": removed}))
                }
            }
        };
        self.sent = Some(ordered);
        update
    }
}

/// A GUID as a JSON integer (u64 range included).
trait ToValue {
    fn to_string_value(&self) -> Value;
}
impl ToValue for i128 {
    fn to_string_value(&self) -> Value {
        if let Ok(v) = u64::try_from(*self) {
            json!(v)
        } else {
            json!(i64::try_from(*self).unwrap_or(0))
        }
    }
}

fn ordered_unique(current: &[(i128, Value)]) -> Vec<(i128, Value)> {
    let mut out: Vec<(i128, Value)> = Vec::new();
    for (g, v) in current {
        match out.iter_mut().find(|(x, _)| x == g) {
            Some(existing) => existing.1 = v.clone(),
            None => out.push((*g, v.clone())),
        }
    }
    out
}

fn current_in_order(current: &[(i128, Value)]) -> Vec<Value> {
    ordered_unique(current).iter().map(|(g, v)| json!([g.to_string_value(), v])).collect()
}

/// Host side: the encounter-reward history every guest must acknowledge (`BossRewards`).
#[derive(Debug, Clone, Default)]
pub struct BossRewardLog {
    pub sequence: u64,
    events: Vec<(u64, u32, i64)>,
    applied: BTreeMap<u32, u64>,
}

pub const MAX_REWARD_HISTORY: usize = 65_536;

impl BossRewardLog {
    pub fn new(guests: &[u32]) -> BossRewardLog {
        BossRewardLog { sequence: 0, events: Vec::new(), applied: guests.iter().map(|g| (*g, 0)).collect() }
    }

    /// `publish_reward(map, boss)`; `boss` is -1 for the guardian.
    pub fn publish(&mut self, map: u32, boss: i64) -> Result<u64, String> {
        if self.events.len() >= MAX_REWARD_HISTORY {
            return Err("Unacknowledged encounter reward history exceeds bound".into());
        }
        self.sequence += 1;
        self.events.push((self.sequence, map, boss));
        Ok(self.sequence)
    }

    /// A guest's `boss_reward_ack`: monotonic and never ahead of what was published; acknowledged
    /// events (by every guest) leave the history.
    pub fn acknowledge(&mut self, guest: u32, ack: u64) -> Result<(), String> {
        let applied = self.applied.get_mut(&guest).ok_or("Invalid boss reward acknowledgement")?;
        if !(*applied <= ack && ack <= self.sequence) {
            return Err("Invalid boss reward acknowledgement".into());
        }
        *applied = ack;
        let acknowledged = self.applied.values().copied().min().unwrap_or(self.sequence);
        self.events.retain(|e| e.0 > acknowledged);
        Ok(())
    }

    /// The `boss_rewards` list of the state message.
    pub fn events_json(&self) -> Vec<Value> {
        self.events.iter().map(|(sequence, map, boss)| json!({"sequence": sequence, "map": map, "boss": boss})).collect()
    }
}
