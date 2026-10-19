//! A dict with Python's insertion order for arbitrary keys: `set` keeps the position of an existing
//! key, `remove` then `set` moves it to the end.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

#[derive(Debug, Clone)]
pub struct OrdMap<K: Hash + Eq + Clone, V> {
    map: HashMap<K, (u64, V)>,
    order: BTreeMap<u64, K>,
    stamp: u64,
}

impl<K: Hash + Eq + Clone, V> Default for OrdMap<K, V> {
    fn default() -> Self {
        OrdMap { map: HashMap::new(), order: BTreeMap::new(), stamp: 0 }
    }
}

impl<K: Hash + Eq + Clone, V> OrdMap<K, V> {
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|(_, v)| v)
    }
    pub fn set(&mut self, key: K, value: V) {
        if let Some(entry) = self.map.get_mut(&key) {
            entry.1 = value;
        } else {
            self.stamp += 1;
            self.order.insert(self.stamp, key.clone());
            self.map.insert(key, (self.stamp, value));
        }
    }
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let (stamp, value) = self.map.remove(key)?;
        self.order.remove(&stamp);
        Some(value)
    }
    pub fn first_key(&self) -> Option<K> {
        self.order.values().next().cloned()
    }
    pub fn keys(&self) -> Vec<K> {
        self.order.values().cloned().collect()
    }
    /// Removes every entry the predicate rejects.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        let doomed: Vec<K> = self.order.values().filter(|k| !keep(k, &self.map[*k].1)).cloned().collect();
        for key in doomed {
            self.remove(&key);
        }
    }
}
