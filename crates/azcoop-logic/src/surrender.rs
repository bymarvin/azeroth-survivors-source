//! Giving up: ports of `native_phase_changed`, `player_surrendered` and `apply_party_surrender`
//! (native_guest_combat.py). A native "give up" is confirmed by the game's own surrender flag;
//! the host giving up ends the run for everybody, a guest giving up leaves the party.

use crate::revival::Room;
use crate::{Call, Event, Io, Result};

// The surrender flag is the build's own Game field (`Room::surrender_flag`, RawGameFields): 0.95.0 0x941, 0.97.1 0x949, 0.99.0 0x97D,
// 0.100.1 0x9A9 (REA 19.10.2026); the old shared constant 0x941 was wrong from 0.97.1 on.

impl Room {
    /// `native_phase_changed(client, number, previous, state)`. `previous` is the earlier state.
    pub fn native_phase_changed(&mut self, io: &mut dyn Io, number: u32, previous: Option<[u64; 4]>, state: [u64; 4]) -> Result<()> {
        if state[0] != 4 || previous.map_or(0, |p| p[0]) == 4 || !self.release_7264 {
            return Ok(());
        }
        if io.read_raw(self.surrender_flag, 1)?[0] == 1 {
            self.player_surrendered(io, number);
        }
        Ok(())
    }

    /// `player_surrendered(number)`.
    pub fn player_surrendered(&mut self, io: &mut dyn Io, number: u32) {
        if !self.surrendered.insert(number) {
            return;
        }
        if number == 1 {
            self.party_surrender = true;
        } else if !self.party_surrender && self.own_number == Some(number) {
            self.self_surrendered = true;
            self.stop_requested = true;
        }
        io.record(Event::new("player_surrendered").num("player", number as f64).num("party", self.party_surrender as u8 as f64));
    }

    /// `apply_party_surrender(client, context)`: true when the native surrender was queued.
    pub fn apply_party_surrender(&mut self, io: &mut dyn Io, number: u32) -> Result<bool> {
        if number == 1 || !self.party_surrender || !self.surrender_applied.insert(number) {
            return Ok(false);
        }
        let phase = self.native_states.get(&number).map_or(0, |s| s[0]);
        if !(1..=3).contains(&phase) || io.read_raw(0, 4)? == 2u32.to_le_bytes() {
            io.record(Event::new("party_surrender_applied").num("player", number as f64).num("native", 0.0).num("phase", phase as f64));
            return Ok(false);
        }
        if !self.release_7264 {
            return Err("Party surrender is bound to the 0.95.0 native function".into());
        }
        io.call(Call::Surrender)?;
        let flag = io.read_raw(self.surrender_flag, 1)?[0];
        io.record(Event::new("party_surrender_applied").num("player", number as f64).num("native", 1.0).num("phase", phase as f64).num("flag", flag as f64));
        Ok(true)
    }
}
