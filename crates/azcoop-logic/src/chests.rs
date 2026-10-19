//! Loot pickups and paid chests: a port of `sync_chests` (native_guest_combat.py).
//!
//! The host owns the loot. A guest that stands at a chest or loot object (and nearer to it
//! than the host, unless the host is down) reserves it with a *claim*; the host checks the
//! claim against its own loot vector, removes the object through the native REMOVE_LOOT and
//! credits the pickup to the whole party. Gold-priced chests are paid on the guest's balance
//! and refunded if the claim fails.

use crate::economy::{Economy, MAX_COUNTER};
use crate::{Call, Event, Io, Result};
use azcoop_world::{values_packet, SELF, UPDATE};
use std::collections::BTreeMap;

pub const MAX_NATIVE_OBJECTS: u64 = 1_000_000;
const LOOT_STRIDE: u64 = 0x48;

/// One loot object: (slot index, position, kind, value).
#[derive(Debug, Clone, PartialEq)]
pub struct Chest {
    pub index: u64,
    pub position: [f64; 3],
    pub kind: u32,
    pub value: u32,
}

/// The loot claim dict.
#[derive(Debug, Clone, PartialEq)]
pub struct Claim {
    pub guid: i128,
    /// Absent in the dict means player 2.
    pub player: Option<u32>,
    pub cost: f64,
    pub status: String,
    pub range: f64,
    pub multiplier: f64,
    pub xp_multiplier: f64,
}

impl Claim {
    pub fn player(&self) -> u32 {
        self.player.unwrap_or(2)
    }

    fn event(&self, name: &str) -> Event {
        let mut e = Event::new(name).num("guid", self.guid as f64);
        if let Some(p) = self.player {
            e = e.num("player", p as f64);
        }
        e.num("cost", self.cost).text("status", &self.status).num("range", self.range).num("multiplier", self.multiplier).num("xp_multiplier", self.xp_multiplier)
    }
}

fn f32_round(x: f64) -> f64 {
    x as f32 as f64
}

fn dist2(a: [f64; 3], b: [f64; 3]) -> f64 {
    let mut sum = 0.0;
    for i in 0..3 {
        sum += (a[i] - b[i]).powi(2);
    }
    sum
}

impl Economy {
    /// `sync_chests(client, context)`: true when it called into the game.
    pub fn sync_chests(&mut self, io: &mut dyn Io, number: u32, now: f64) -> Result<bool> {
        if number == 1 {
            return self.sync_chests_host(io, now);
        }
        self.sync_chests_guest(io, number)
    }

    fn sync_chests_host(&mut self, io: &mut dyn Io, now: f64) -> Result<bool> {
        let head = io.read_bytes(0x5C8, 16)?;
        let (_pointer, count) = (u64::from_le_bytes(head[..8].try_into().unwrap()), u64::from_le_bytes(head[8..16].try_into().unwrap()));
        if count > MAX_NATIVE_OBJECTS {
            return Err("Native loot count exceeds bound".into());
        }
        let data = if count > 0 { io.read_loot(count * LOOT_STRIDE)? } else { Vec::new() };
        self.chests.clear();
        for i in (0..data.len()).step_by(LOOT_STRIDE as usize) {
            let kind = u32::from_le_bytes(data[i + 0x20..i + 0x24].try_into().unwrap());
            if kind <= 6 {
                let f = |at: usize| f32::from_le_bytes(data[i + at..i + at + 4].try_into().unwrap()) as f64;
                self.chests.insert(
                    u64::from_le_bytes(data[i + 0x28..i + 0x30].try_into().unwrap()),
                    Chest {
                        index: i as u64 / LOOT_STRIDE,
                        position: [f(0x34), f(0x38), f(0x3C)],
                        kind,
                        value: u32::from_le_bytes(data[i + 0x24..i + 0x28].try_into().unwrap()),
                    },
                );
            }
        }
        let Some(claim) = self.chest_claim.clone() else { return Ok(false) };
        if claim.status != "reserved" {
            return Ok(false);
        }
        let chest = u64::try_from(claim.guid).ok().and_then(|g| self.chests.get(&g)).cloned();
        let guest = *self.poses.get(&claim.player()).ok_or("Unknown guest pose")?;
        let out_of_reach = chest.as_ref().map_or(true, |c| dist2(c.position, guest) > claim.range.powi(2));
        if out_of_reach {
            self.chest_claim.as_mut().unwrap().status = "refund".into();
            return Ok(false);
        }
        let chest = chest.unwrap();
        io.call(Call::RemoveLoot { index: chest.index })?;
        // completed()
        let claim_mut = self.chest_claim.as_mut().unwrap();
        match chest.kind {
            0 => {
                let multiplier = {
                    let mut sum = 0.0;
                    for n in &self.members {
                        sum += self.xp_multipliers.get(n).copied().unwrap_or(1.0) - 1.0;
                    }
                    (1.0 + sum).max(0.0) as f32 as f64
                };
                let product = f32_round(chest.value as f64 * multiplier);
                let amount = ((product + 0.5).floor()).max(1.0);
                if amount > MAX_COUNTER as f64 {
                    return Err("Guest pickup XP exceeds bound".into());
                }
                self.pickup_xp_pending += amount as i128;
                claim_mut.status = "collected".into();
                io.record(Event::new("guest_xp_pickup").num("amount", amount).num("guid", claim_mut.guid as f64));
            }
            1 => {
                let product = f32_round(chest.value as f64 * claim_mut.multiplier);
                let amount = (product + 0.5).floor();
                if !(0.0..=MAX_COUNTER as f64).contains(&amount) {
                    return Err("Guest pickup gold exceeds bound".into());
                }
                let amount = amount as i128;
                let word = |b: Vec<u8>| u32::from_le_bytes(b[..4].try_into().unwrap()) as i128;
                let gold = word(io.read_bytes(0x4A8, 4)?);
                let earned = word(io.read_bytes(0x6D0, 4)?);
                let balance = (gold + amount).min(MAX_COUNTER); // u32 saturates, never ends the run
                if balance - gold < amount {
                    self.note_bound(io, "gold_balance", amount - (balance - gold), now, vec![("player", 1.0), ("balance", balance as f64)]);
                }
                io.put_bytes(0x4A8, &(balance as u32).to_le_bytes());
                io.put_bytes(0x6D0, &((earned + amount).min(MAX_COUNTER) as u32).to_le_bytes());
                let copper = (balance * 10000).min(MAX_COUNTER) as u32;
                self.notice.entry(1).or_default().push((UPDATE, values_packet(SELF, &BTreeMap::from([(1176u32, copper)]))?));
                self.queue_gold(amount);
                let picker = self.chest_claim.as_ref().unwrap().player() as f64;
                self.chest_claim.as_mut().unwrap().status = "collected".into();
                io.record(Event::new("shared_gold_pickup").num("amount", amount as f64).num("picker", picker));
            }
            3..=6 => claim_mut.status = "collected".into(),
            _ => {
                claim_mut.status = "removed".into();
                io.record(Event::new("guest_chest_removed").num("guid", claim_mut.guid as f64));
            }
        }
        Ok(true)
    }

    fn sync_chests_guest(&mut self, io: &mut dyn Io, number: u32) -> Result<bool> {
        let mut claim = self.chest_claim.clone();
        let phase = self.native_states.get(&number).ok_or("Unknown player state")?[0];
        if claim.as_ref().is_some_and(|c| c.player() != number) {
            return Ok(false);
        }
        if claim.as_ref().is_some_and(|c| c.status == "collected") {
            self.chest_claim = None;
            claim = None;
        }
        if let Some(c) = claim.as_ref().filter(|c| c.status == "refund") {
            self.change_guest_gold(io, number, c.cost as i128)?;
            io.record(c.event("guest_chest_refunded"));
            self.chest_claim = None;
        } else if let Some(c) = claim.as_ref().filter(|c| c.status == "removed" && phase == 1 && !self.paused) {
            // Native chest purchase: next cost = trunc(float32(cost * 1.3) + 5).
            let product = f32_round(c.cost * 1.2999999523162842);
            let cost = f32_round(product + 5.0).trunc() as u32;
            io.put_bytes(0x894, &cost.to_le_bytes());
            for field in [0x6D4u64, 0x864] {
                let value = u32::from_le_bytes(io.read_bytes(field, 4)?[..4].try_into().unwrap());
                // struct.pack('<I', value + 1) raises past the u32 range.
                io.put_bytes(field, &value.checked_add(1).ok_or("'I' format requires 0 <= number <= 4294967295")?.to_le_bytes());
            }
            self.chest_claim = None;
            io.record(Event::new("guest_chest_awarded").num("guid", c.guid as f64).num("cost", c.cost));
            io.call(Call::OfferChoices { kind: 1 })?;
            return Ok(true);
        }
        if self.chest_claim.is_some() || self.draining || phase != 1 || self.paused {
            return Ok(false);
        }
        let guest = *self.poses.get(&number).ok_or("Unknown player pose")?;
        let host = *self.poses.get(&1).ok_or("Unknown host pose")?;
        let word = |b: Vec<u8>| u32::from_le_bytes(b[..4].try_into().unwrap());
        let gold = word(io.read_bytes(0x4A8, 4)?);
        let cost = word(io.read_bytes(0x894, 4)?);
        let float = |b: Vec<u8>| f32::from_le_bytes(b[..4].try_into().unwrap()) as f64;
        let radius = float(io.read_bytes(0x510, 4)?);
        let multiplier = float(io.read_bytes(0x528, 4)?);
        let xp_multiplier = float(io.read_bytes(0x514, 4)?);
        let ok = |v: f64| v.is_finite() && (0.0..=1000.0).contains(&v);
        if !(ok(radius) && ok(multiplier) && ok(xp_multiplier)) {
            crate::skips::note(&mut |e| io.record(e), "pickup_profile_invalid", number as u64, vec![("values", crate::finite_text(&[radius, multiplier, xp_multiplier]))]);
            return Ok(false); // tried again on the next write
        }
        let host_down = self.native_states.get(&1).ok_or("Unknown host state")?[0] == 4;
        for (guid, chest) in self.chests.clone() {
            let (price, reach) = if chest.kind == 2 { (cost, 3.0) } else { (0, radius) };
            let (gd, hd) = (dist2(chest.position, guest), dist2(chest.position, host));
            if gold >= price && gd <= reach * reach && (gd < hd || host_down) {
                self.change_guest_gold(io, number, -(price as i128))?;
                self.chest_claim = Some(Claim { guid: guid as i128, player: Some(number), cost: price as f64, status: "reserved".into(), range: reach, multiplier, xp_multiplier });
                io.record(Event::new("guest_loot_reserved").num("guid", guid as f64).num("cost", price as f64).num("kind", chest.kind as f64));
                break;
            }
        }
        Ok(false)
    }
}
