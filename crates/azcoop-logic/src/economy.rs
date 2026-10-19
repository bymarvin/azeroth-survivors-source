//! Shared XP, shared gold and talent choices: ports of `queue_gold`, `party_xp_multiplier`,
//! `mirror_xp`, `sync_talents`, `choices_owed`, `capture_pickup_gold`, `apply_shared_gold`,
//! `change_guest_gold` (native_guest_combat.py / visibility_bridge.py) and the AWARD_XP hook's
//! queueing. XP and gold earned on the host are queued for every guest and credited to each
//! guest's own game; talents stay independent per player.

use crate::{Call, Event, Io, Packet, Result};
use azcoop_world::{values_packet, SELF, UPDATE};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_COUNTER: i128 = 0xFFFF_FFFF;

fn copper(gold: i128) -> i128 {
    (gold * 10000).min(MAX_COUNTER)
}

#[derive(Default)]
pub struct Economy {
    pub members: Vec<u32>,
    pub guests: Vec<u32>,
    /// Guest 2's slot and the per-guest queues for the others.
    pub xp_pending: i128,
    pub gold_pending: i128,
    pub xp_queues: BTreeMap<u32, i128>,
    pub gold_by_guest: BTreeMap<u32, i128>,
    pub xp_multipliers: BTreeMap<u32, f64>,
    pub native_states: BTreeMap<u32, [u64; 4]>,
    pub ready: BTreeSet<u32>,
    pub talent_paused: BTreeSet<u32>,
    pub draining: bool,
    pub paused: bool,
    pub notice: BTreeMap<u32, Vec<Packet>>,
    /// Address of the bridge's pickup-gold counter (0 = none) and the total already queued.
    pub gold_counter: u64,
    pub gold_seen: i128,
    /// Raw Game offset of the guardian's pending reward choices in this build.
    pub guardian_offset: u64,
    pub bound_dropped: BTreeMap<String, i128>,
    pub bound_logged: BTreeMap<String, f64>,
    // --- loot and chest claims (chests.rs)
    pub poses: BTreeMap<u32, [f64; 3]>,
    /// Host: the loot vector as last read, keyed by GUID.
    pub chests: BTreeMap<u64, crate::chests::Chest>,
    pub chest_claim: Option<crate::chests::Claim>,
    pub pickup_xp_pending: i128,
}

impl Economy {
    /// `queue_gold(amount)`.
    pub fn queue_gold(&mut self, amount: i128) {
        if self.guests.contains(&2) {
            self.gold_pending += amount;
        }
        for v in self.gold_by_guest.values_mut() {
            *v += amount;
        }
    }

    /// The AWARD_XP hook on the host: queue the award for every guest.
    pub fn host_xp_award(&mut self, number: u32, amount: u32, io: &mut dyn Io) {
        if number == 1 {
            if self.guests.contains(&2) {
                self.xp_pending += amount as i128;
            }
            for guest in self.guests.clone() {
                if guest != 2 {
                    *self.xp_queues.entry(guest).or_insert(0) += amount as i128;
                }
            }
            io.record(Event::new("native_xp_award").num("amount", amount as f64));
        }
    }

    /// `party_xp_multiplier()`: bonuses add, base multipliers never accumulate.
    pub fn party_xp_multiplier(&self) -> f64 {
        let mut sum = 0.0;
        for n in &self.members {
            sum += self.xp_multipliers.get(n).copied().unwrap_or(1.0) - 1.0;
        }
        (1.0 + sum).max(0.0) as f32 as f64
    }

    /// `note_bound(state, amount, **details)`: counted, logged at most once a minute per state.
    pub fn note_bound(&mut self, io: &mut dyn Io, state: &str, amount: i128, now: f64, details: Vec<(&str, f64)>) {
        *self.bound_dropped.entry(state.into()).or_insert(0) += amount;
        if now >= self.bound_logged.get(state).copied().unwrap_or(0.0) {
            self.bound_logged.insert(state.into(), now + 60.0);
            let mut event = Event::new("bounded_state_dropped").text("state", state).num("dropped", self.bound_dropped[state] as f64);
            for (k, v) in details {
                event = event.num(k, v);
            }
            io.record(event);
        }
    }

    /// `mirror_xp(client, context, phase)`: the host's run XP on a guest, also while it is down.
    pub fn mirror_xp(&mut self, io: &mut dyn Io, number: u32, phase: u64) -> Result<bool> {
        let pending = if number == 2 { self.xp_pending } else { self.xp_queues.get(&number).copied().unwrap_or(0) };
        if number == 1 || !(1..=4).contains(&phase) || pending == 0 {
            return Ok(false);
        }
        let amount = pending.min(MAX_COUNTER); // one native u32 award; the rest next batch
        if number == 2 {
            self.xp_pending -= amount;
        } else {
            *self.xp_queues.get_mut(&number).unwrap() -= amount;
        }
        io.call(Call::AwardXp { amount: amount as u64 })?;
        io.record(Event::new("native_xp_mirrored").num("amount", amount as f64));
        Ok(true)
    }

    /// `choices_owed(client)`: open chest and guardian choices (level-ups are state[3]).
    pub fn choices_owed(&self, io: &mut dyn Io) -> Result<i128> {
        let word = |b: Vec<u8>| u32::from_le_bytes(b[..4].try_into().unwrap()) as i128;
        let mut owed = word(io.read_bytes(0x864, 4)?);
        owed += word(io.read_raw(self.guardian_offset, 4)?);
        Ok(owed)
    }

    /// `sync_talents(client, context)`.
    pub fn sync_talents(&mut self, io: &mut dyn Io, number: u32) -> Result<bool> {
        if !self.ready.contains(&number) || self.paused || self.draining {
            return Ok(false);
        }
        let [phase, _, _, pending] = *self.native_states.get(&number).ok_or("Unknown player state")?;
        if pending > 0 && phase == 1 {
            // Zero XP invokes the native chooser without awarding another point.
            io.call(Call::AwardXp { amount: 0 })?;
            io.record(Event::new("talents_opened").num("player", number as f64).num("pending", pending as f64));
            return Ok(true);
        }
        let waiting = self.native_states.values().any(|s| s[0] == 2 || (matches!(s[0], 1 | 3) && s[3] > 0));
        if !((phase == 3 && self.talent_paused.contains(&number)) || (waiting && phase == 1)) {
            return Ok(false);
        }
        // Open chest/guardian choices count like level-ups: OFFER_CHOICES opens phase 2 without
        // checking the phase, and RESUME only leaves phase 3, so a player who owes a choice
        // resumes first and is never paused.
        let owed = pending as i128 + self.choices_owed(io)?;
        if phase == 3 && self.talent_paused.contains(&number) && (owed != 0 || !waiting) {
            self.talent_paused.remove(&number);
            io.call(Call::Resume)?;
            io.record(Event::new("talent_wait_ended").num("player", number as f64).num("owed", owed as f64));
            return Ok(true);
        }
        if waiting && phase == 1 && owed == 0 {
            self.talent_paused.insert(number);
            io.call(Call::Pause)?;
            io.record(Event::new("talent_wait_started").num("player", number as f64));
            return Ok(true);
        }
        Ok(false)
    }

    /// `capture_pickup_gold(client)`: gold the host collected since the last look.
    pub fn capture_pickup_gold(&mut self, io: &mut dyn Io) -> Result<()> {
        if self.gold_counter == 0 {
            return Ok(());
        }
        let earned = u64::from_le_bytes(io.read_abs(self.gold_counter, 8)?[..8].try_into().unwrap()) as i128;
        let delta = earned - self.gold_seen;
        if !(0..=MAX_COUNTER).contains(&delta) {
            return Err("Shared pickup gold exceeds bound".into());
        }
        self.queue_gold(delta);
        self.gold_seen = earned;
        if delta != 0 {
            io.record(Event::new("shared_gold_pickup").num("amount", delta as f64));
        }
        Ok(())
    }

    /// `apply_shared_gold(client)`: credit the queued gold to this player's own game.
    pub fn apply_shared_gold(&mut self, io: &mut dyn Io, number: u32, now: f64) -> Result<()> {
        let pending = if number == 2 { self.gold_pending } else { self.gold_by_guest.get(&number).copied().unwrap_or(0) };
        if pending == 0 {
            return Ok(());
        }
        let word = |b: Vec<u8>| u32::from_le_bytes(b[..4].try_into().unwrap()) as i128;
        let gold = word(io.read_bytes(0x4A8, 4)?);
        let earned = word(io.read_bytes(0x6D0, 4)?);
        let amount = pending;
        // Native u32 balances saturate; the copper display field saturates earlier (gold x 10000).
        let (balance, total) = ((gold + amount).min(MAX_COUNTER), (earned + amount).min(MAX_COUNTER));
        if balance - gold < amount {
            self.note_bound(io, "gold_balance", amount - (balance - gold), now, vec![("player", number as f64), ("balance", balance as f64)]);
        }
        io.put_bytes(0x4A8, &(balance as u32).to_le_bytes());
        io.put_bytes(0x6D0, &(total as u32).to_le_bytes());
        let packet = values_packet(SELF, &BTreeMap::from([(1176u32, copper(balance) as u32)]))?;
        self.notice.entry(number).or_default().push((UPDATE, packet));
        if number == 2 {
            self.gold_pending = 0;
        } else {
            self.gold_by_guest.insert(number, 0);
        }
        io.record(Event::new("shared_gold_credited").num("player", number as f64).num("amount", amount as f64).num("balance", (gold + amount) as f64));
        Ok(())
    }

    /// `change_guest_gold(client, amount)`: a chest payment or refund on the guest's balance.
    pub fn change_guest_gold(&mut self, io: &mut dyn Io, number: u32, amount: i128) -> Result<()> {
        let current = u32::from_le_bytes(io.read_bytes(0x4A8, 4)?[..4].try_into().unwrap()) as i128;
        let gold = current + amount;
        if gold < 0 {
            return Err("Invalid chest payment balance".into());
        }
        let gold = gold.min(MAX_COUNTER); // u32 saturates
        io.put_bytes(0x4A8, &(gold as u32).to_le_bytes());
        let packet = values_packet(SELF, &BTreeMap::from([(1176u32, copper(gold) as u32)]))?;
        self.notice.entry(number).or_default().push((UPDATE, packet));
        Ok(())
    }
}
