//! Shared pause, run transitions and victory: ports of the pause blocks of `Bridge.__call__`,
//! `completed_transition`, `request_victory_action` (visibility_bridge.py) and `shared_victory`
//! (native_guest_combat.py).
//!
//! Either player pauses or resumes the whole room; the request is mirrored to every game at its
//! next queue write, retried until the game's own phase matches. A downed player has no game
//! simulation to pause, so only its UI is switched.

use crate::revival::Room;
use crate::{Call, Event, Io, Result};

const FIELD_PHASE: u64 = 0x8BF;

/// What the caller knows about the request that arrived in the PAUSE/RESUME hook.
#[derive(Debug, Clone, Copy)]
pub struct PauseRequest {
    /// The call was not made by the bridge itself (no saved context, or flagged as a request).
    pub fresh: bool,
    /// The connection has a session in the router.
    pub in_sessions: bool,
    /// ... and that session selected a player.
    pub has_player: bool,
}

impl Room {
    /// The PAUSE/RESUME hook (`rva in (PAUSE, RESUME)` of `__call__`).
    pub fn pause_requested(&mut self, io: &mut dyn Io, number: u32, pause: bool, request: PauseRequest) -> Result<()> {
        if self.draining {
            // The native call still returns normally; a late Resume is repaired through the
            // owned Pause call at the next batch.
            self.paused = true;
            if !pause {
                self.pause_pending.insert(number, true);
            }
            return Ok(());
        }
        if request.fresh && request.in_sessions {
            let phase = io.read_bytes(FIELD_PHASE, 1)?[0];
            if phase == if pause { 1 } else { 3 } || phase == 4 {
                if !request.has_player {
                    return Err("Pause requires a selected authenticated player and boolean state".into());
                }
                self.paused = pause;
                let state = self.paused;
                for n in self.members.clone() {
                    self.pause_pending.insert(n, state);
                }
                io.record(Event::new("shared_pause_requested").num("player", number as f64).num("paused", state as u8 as f64));
            }
        }
        Ok(())
    }

    /// The `pause_pending` block of the queue write: true when it called into the game, so the
    /// caller retries the same queue write (or stops, for the UI-only case).
    pub fn apply_pause_pending(&mut self, io: &mut dyn Io, number: u32) -> Result<bool> {
        let Some(&paused) = self.pause_pending.get(&number) else { return Ok(false) };
        if !self.ready.contains(&number) {
            return Ok(false);
        }
        let phase = io.read_bytes(FIELD_PHASE, 1)?[0];
        if phase == 4 {
            self.pause_pending.remove(&number);
            io.call(if paused { Call::PauseUi } else { Call::ResumeUi })?;
            io.record(Event::new("shared_pause_applied").num("recipient", number as f64).num("paused", paused as u8 as f64).num("downed", 1.0));
            return Ok(true);
        }
        if phase == 1 || phase == 3 {
            if phase != if paused { 3 } else { 1 } {
                io.call(if paused { Call::Pause } else { Call::Resume })?;
                return Ok(true);
            }
            self.pause_pending.remove(&number);
            io.record(Event::new("shared_pause_applied").num("recipient", number as f64).num("paused", paused as u8 as f64));
        }
        Ok(false)
    }

    /// `completed_transition(number, command, phase)`: command 6 = play again, 9 = new hero.
    pub fn completed_transition(&mut self, io: &mut dyn Io, number: u32, command: u32, phase: Option<u64>) {
        if !(command == 6 || command == 9) || self.completed_players.contains(&number) {
            return;
        }
        let phase = phase.unwrap_or_else(|| self.native_states.get(&number).map_or(0, |s| s[0]));
        let all_down = self.members.iter().all(|n| self.native_states.get(n).map_or(0, |s| s[0]) == 4);
        if !(phase == 5 || phase == 4 && all_down) {
            return;
        }
        if self.guests.contains(&number) {
            // New Hero hands this server back to native menu ownership, so no later game batch
            // can retire these already-obsolete combat hits.
            self.clear_requests.push((number, "run_transition".to_string()));
        }
        self.completed_players.insert(number);
        io.record(
            Event::new("completed_run_transition")
                .num("player", number as f64)
                .text("action", if command == 6 { "again" } else { "new_hero" })
                .num("phase", phase as f64)
                .num("duration_seconds", self.host_clock),
        );
    }

    /// `request_victory_action(command)`: the host's pending decision cannot be replaced.
    pub fn request_victory_action(&mut self, io: &mut dyn Io, command: u32) -> Result<()> {
        if !(command == 8 || command == 9) {
            return Err("Unsupported victory choice".into());
        }
        if self.end_pending.contains_key(&1) {
            return Ok(());
        }
        let sequence = self.end_action.map_or(1, |(s, _)| s + 1);
        self.end_action = Some((sequence, command));
        for n in self.members.clone() {
            self.end_pending.insert(n, command);
        }
        io.record(Event::new("host_victory_action").num("sequence", sequence as f64).num("command", command as f64));
        Ok(())
    }

    /// `shared_victory(client)`: runs the native victory path on a guest, also one who was down.
    pub fn shared_victory(&mut self, io: &mut dyn Io, number: u32) -> Result<()> {
        io.rearm_result("shared_victory")?;
        io.put_bytes(0x7F0, &1u32.to_le_bytes());
        io.put_bytes(0x8B5, &[0]);
        io.put_bytes(FIELD_PHASE, &[1]);
        self.victory_requested = true;
        self.victory_guests.insert(number);
        io.record(Event::new("shared_victory_requested"));
        Ok(())
    }
}
