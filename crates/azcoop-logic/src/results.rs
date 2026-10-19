//! The run evaluation's class-XP accounting: ports of `class_xp`, `remember_result_xp`,
//! `result_note`, `rearm_result` and `keep_open_result` (visibility_bridge.py).
//!
//! Native single-player credits the account's class XP once, when a run ends. In co-op a fall
//! is not the end of the run: when a downed player is revived (or the run is won together)
//! the evaluation must run again at the real end and credit the whole run once. `rearm_result`
//! opens the once-lock again and takes the fall's credit back, but only if nothing else changed
//! the account since the snapshot taken at the start of the run.
//!
//! Exception (2-PC test 2, 18.10.2026): a REVIVED player's evaluation counters (time survived, kills) start
//! again at the revival, so the next evaluation credits only the time since then (guest log: 170 XP at the fall,
//! 5 XP after the revival, the 170 taken back: the hero got no level). For `reason == "revival"` the fall's
//! credit therefore stays on the account and the next evaluation adds its own; the baseline moves up.
//! Assumption (one logged round so far, the guest of 18.10.2026): the evaluation parts (time survived, kills) restart at a
//! revival, so the evaluations do not overlap. Every fall after a revival logs `result_credit_kept` with the credit of its
//! own evaluation: a value as large as the whole run so far would mean overlap (then the take-back is needed again).

use crate::{Event, Io, Result};
use azcoop_game::builds::ResultEvaluation;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_CLASS_ENTRIES: u64 = 4096;

/// class -> (entry address, xp)
pub type ClassTable = BTreeMap<u8, (u64, u32)>;

#[derive(Default)]
pub struct Results {
    /// `None`: the build has no verified layout (nothing is rearmed).
    pub layout: Option<ResultEvaluation>,
    /// Class XP at run start (or after a won evaluation), per player.
    pub result_xp: BTreeMap<u32, BTreeMap<u8, u32>>,
    /// An open fall credit: (class, credited xp).
    pub result_open: BTreeMap<u32, (u8, u32)>,
    pub result_notes: BTreeSet<(u32, String)>,
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

impl Results {
    /// `class_xp(client, layout)`: the account's class XP table, or `None` if it does not look valid.
    pub fn class_xp(&self, io: &mut dyn Io, layout: &ResultEvaluation) -> Result<Option<ClassTable>> {
        let head = io.read_server(layout.account + 0x68, 16)?;
        let (entries, count) = (u64::from_le_bytes(head[..8].try_into().unwrap()), u64::from_le_bytes(head[8..16].try_into().unwrap()));
        if count > MAX_CLASS_ENTRIES || (count > 0 && entries == 0) {
            return Ok(None);
        }
        let table = if count > 0 { io.read_abs(entries, (count * 32) as usize)? } else { Vec::new() };
        let mut out = BTreeMap::new();
        for i in 0..count as usize {
            out.insert(table[i * 32 + 4], (entries + i as u64 * 32, u32le(&table, i * 32)));
        }
        Ok(Some(out))
    }

    /// `remember_result_xp(client)`: class XP at run start or after a finished (won) evaluation.
    pub fn remember_result_xp(&mut self, io: &mut dyn Io, number: u32) -> Result<()> {
        let table = match self.layout {
            Some(layout) => self.class_xp(io, &layout)?,
            None => None,
        };
        self.result_open.remove(&number);
        if let Some(table) = table {
            self.result_xp.insert(number, table.iter().map(|(c, (_, xp))| (*c, *xp)).collect());
        }
        Ok(())
    }

    /// `result_note(client, reason, **details)`: log a kept credit once per player and reason.
    pub fn result_note(&mut self, io: &mut dyn Io, number: u32, reason: &str, details: Vec<(&str, f64)>) {
        if self.result_notes.insert((number, reason.to_string())) {
            let mut e = Event::new("result_xp_kept").num("player", number as f64).text("reason", reason);
            for (k, v) in details {
                e = e.num(k, v);
            }
            io.record(e);
        }
    }

    /// `rearm_result(client, reason)`.
    pub fn rearm_result(&mut self, io: &mut dyn Io, number: u32, reason: &str) -> Result<()> {
        let Some(layout) = self.layout else {
            self.result_note(io, number, "unsupported_build", vec![]);
            return Ok(());
        };
        let lock = io.read_server(layout.lock, 1)?[0];
        let last = io.read_server(layout.last_phase, 1)?[0];
        io.put_server(layout.lock, &[0]);
        let rearmed = |io: &mut dyn Io, taken: f64, cls: Option<u8>| {
            let mut e = Event::new("result_rearmed").num("xp_taken_back", taken);
            if let Some(c) = cls {
                e = e.num("cls", c as f64);
            }
            io.record(e.num("player", number as f64).text("reason", reason).num("was_locked", lock as f64).num("last_phase", last as f64));
        };
        if lock == 0 {
            rearmed(io, 0.0, None); // no evaluation since the last rearm
            return Ok(());
        }
        let baseline = self.result_xp.get(&number).cloned();
        let table = self.class_xp(io, &layout)?;
        let cls = io.read_server(layout.class_id, 1)?[0];
        let victory = u32le(&io.read_server(layout.victory, 4)?, 0);
        match (&baseline, &table) {
            (None, _) | (_, None) => {
                self.result_note(io, number, if baseline.is_none() { "no_snapshot" } else { "invalid_table" }, vec![]);
            }
            (Some(baseline), Some(table)) => {
                if last != 4 || victory != 0 {
                    self.result_note(io, number, "not_a_fall_evaluation", vec![("last_phase", last as f64), ("victory", victory as f64)]);
                } else if table.iter().any(|(c, (_, xp))| *c != cls && baseline.get(c) != Some(xp))
                    || baseline.keys().any(|c| !table.contains_key(c))
                    || table.get(&cls).map_or(0, |t| t.1) < baseline.get(&cls).copied().unwrap_or(0)
                {
                    self.result_note(io, number, "account_changed_otherwise", vec![("cls", cls as f64)]);
                } else {
                    let base = baseline.get(&cls).copied().unwrap_or(0);
                    let (address, xp) = table.get(&cls).copied().map_or((None, base), |(a, x)| (Some(a), x));
                    let credited = xp - base;
                    if reason == "revival" {
                        // the credit stays; the next evaluation counts from the revival on and is added
                        io.put_server(layout.last_phase, &[0]);
                        self.result_xp.entry(number).or_default().insert(cls, xp);
                        io.record(Event::new("result_credit_kept").num("player", number as f64).num("cls", cls as f64).num("credited", credited as f64).text("reason", reason));
                        rearmed(io, 0.0, Some(cls));
                        return Ok(());
                    }
                    if credited != 0 {
                        io.put_abs(address.ok_or("no entry to restore")?, &base.to_le_bytes());
                    }
                    io.put_server(layout.last_phase, &[0]);
                    self.result_open.insert(number, (cls, credited));
                    rearmed(io, credited as f64, Some(cls));
                    return Ok(());
                }
            }
        }
        rearmed(io, 0.0, None);
        Ok(())
    }

    /// `keep_open_result(client)`: a run that ends without another evaluation keeps the fall credit, once.
    pub fn keep_open_result(&mut self, io: &mut dyn Io, number: u32) -> Result<()> {
        let Some((cls, credited)) = self.result_open.remove(&number) else { return Ok(()) };
        let layout = self.layout.ok_or("no verified layout")?;
        if io.read_server(layout.lock, 1)?[0] != 0 {
            return Ok(()); // a later evaluation credited the whole run already
        }
        let table = self.class_xp(io, &layout)?;
        let baseline = self.result_xp.get(&number).and_then(|m| m.get(&cls)).copied().unwrap_or(0);
        match table.as_ref().and_then(|t| t.get(&cls)) {
            Some((address, xp)) if *xp == baseline => {
                io.put_abs(*address, &baseline.checked_add(credited).ok_or("'I' format requires 0 <= number <= 4294967295")?.to_le_bytes());
                io.record(Event::new("result_open_credit_kept").num("player", number as f64).num("cls", cls as f64).num("credited", credited as f64));
            }
            _ => self.result_note(io, number, "open_credit_not_restored", vec![("cls", cls as f64), ("credited", credited as f64)]),
        }
        Ok(())
    }
}
