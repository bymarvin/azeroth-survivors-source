//! What the launcher needs from the core and what it may ask of it (Step 2: victory choice and next run).
//!
//! The Python launcher drove the Python bridge object directly: it read `record(**event)`, `run_over()`, `next_run_offer`,
//! `next_run_acks`, and called `request_victory_action(command)` and `offer_next_run(room, invite)`. With the core in the game
//! process the launcher is on the other side of the helper, so the same information travels as `Event` frames out and
//! `Command` frames in (see `azcoop_proto::ipc`). Everything here only observes the bridge or applies one of two validated
//! host decisions; the party's wire messages are not touched.

use crate::bridge::Bridge;
use crate::client::{Client, Result};
use crate::io::GameIo;
use crate::regs::Regs;
use azcoop_logic::Event;
use azcoop_world::builders::system_message;
use azcoop_proto::ipc::Command;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// One outgoing event: its name and flat fields.
pub type Outgoing = (String, Vec<(String, Value)>);

/// Remembers what the launcher was told, so each change is sent once.
#[derive(Default)]
pub struct Watch {
    phases: BTreeMap<u32, u64>,
    offers_sent: usize,
    acks: Option<BTreeSet<u32>>,
    run_over: Option<bool>,
}

fn event(name: &str, fields: Vec<(&str, Value)>) -> Outgoing {
    (name.to_string(), fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

impl Watch {
    /// The changes since the last call. `phases`: `native_states[n][0]` and the level per player; `offers`: the host's
    /// next-run offers a guest received, in arrival order; `acks`: the guests that confirmed the host's offer.
    pub fn poll(&mut self, phases: &BTreeMap<u32, (u64, u64)>, offers: &[Value], acks: &BTreeSet<u32>, run_over: bool) -> Vec<Outgoing> {
        let mut out = Vec::new();
        for (player, (phase, level)) in phases {
            if self.phases.get(player) != Some(phase) {
                self.phases.insert(*player, *phase);
                out.push(event("native_state", vec![("player", json!(player)), ("phase", json!(phase)), ("level", json!(level))]));
            }
        }
        if self.run_over != Some(run_over) {
            // the launcher assumes "not over" until told, so the first quiet poll sends nothing
            if self.run_over.is_some() || run_over {
                out.push(event("run_over", vec![("value", json!(run_over as u8))]));
            }
            self.run_over = Some(run_over);
        }
        while self.offers_sent < offers.len() {
            let offer = &offers[self.offers_sent];
            self.offers_sent += 1;
            out.push(event("next_run_offer", vec![("room", offer["room"].clone()), ("invite", offer["invite"].clone())]));
        }
        if self.acks.as_ref() != Some(acks) && !(self.acks.is_none() && acks.is_empty()) {
            out.push(event("next_run_acks", vec![("acks", json!(acks.iter().collect::<Vec<_>>()))]));
        }
        self.acks = Some(acks.clone());
        out
    }
}

impl Bridge {
    /// The launcher-relevant changes of this bridge since the last call (cheap: compares a few small maps).
    pub fn control_events(&mut self, watch: &mut Watch) -> Vec<Outgoing> {
        let phases: BTreeMap<u32, (u64, u64)> = self.room.native_states.iter().map(|(n, s)| (*n, (s[0], s[1]))).collect();
        let run_over = self.room.completed_players.contains(&1) || self.room.team_defeat.contains(&1) || self.room.party_surrender;
        let over_here = run_over || !self.room.team_defeat.is_empty() || !self.room.completed_players.is_empty();
        if over_here && !self.run_over_hint {
            self.run_over_hint = true;
            self.next_run_hint();
        }
        let (offers, acks): (&[Value], BTreeSet<u32>) = match self.online.as_ref() {
            Some(online) => (&online.group.next_runs, online.group.next_run_acks.clone()),
            None => (&[], BTreeSet::new()),
        };
        watch.poll(&phases, offers, &acks, run_over)
    }

    /// 2-PC test 2: after the defeat both players pressed Start in the game menu and played alone, because the party's next run is
    /// the launcher's Next run button, not a game button. Say so in the game itself, once per run.
    fn next_run_hint(&mut self) {
        let host = self.online.as_ref().map_or(true, |o| o.number == 1);
        let text = if host {
            "The run is over. To keep playing together press Next run in the co-op launcher window. Starting from the game menu plays alone."
        } else {
            "The run is over. Wait for the host to press Next run in the co-op launcher; do not start from the game menu, that plays alone."
        };
        if let Ok(notice) = system_message(text) {
            for member in self.room.members.clone() {
                self.room.notice.entry(member).or_default().push(notice.clone());
            }
        }
    }

    /// One decision of the host's launcher. Refused (and logged) on a guest, outside the victory screen for the choice,
    /// and before the run is over for an offer; the launcher checks the same conditions, so a refusal means it raced the game.
    pub fn host_command(&mut self, client: &mut dyn Client, command: Command) -> Result<()> {
        let refuse = |client: &mut dyn Client, why: &str| {
            client.record(Event::new("command_refused").text("reason", why));
        };
        if command == Command::LeaveRun {
            // every role: the host is gone or the player leaves; the game's own "back to character select" evaluates and saves the run
            if !self.leave_requested {
                self.leave_requested = true;
                client.record(Event::new("leave_requested"));
            }
            return Ok(());
        }
        let Some(online_number) = self.online.as_ref().map(|o| o.number) else {
            refuse(client, "offline");
            return Ok(());
        };
        if online_number != 1 {
            refuse(client, "only the host decides");
            return Ok(());
        }
        match command {
            Command::VictoryAction(value) => {
                if self.room.native_states.get(&1).map_or(0, |s| s[0]) != 5 {
                    refuse(client, "not at the victory screen");
                    return Ok(());
                }
                let mut regs = Regs::default();
                let mut io = GameIo::new(client, &mut regs, &self.build.fields, &mut self.results);
                self.room.request_victory_action(&mut io, value)
            }
            Command::LeaveRun => Ok(()), // handled above
            Command::OfferNextRun { room, invite } => {
                let over = self.room.completed_players.contains(&1) || self.room.team_defeat.contains(&1) || self.room.party_surrender;
                if !over {
                    refuse(client, "the run is not over");
                    return Ok(());
                }
                let guests: Vec<f64> = self.room.members.iter().filter(|n| **n != 1).map(|n| *n as f64).collect();
                let online = self.online.as_mut().expect("checked above");
                online.group.next_run_offer = Some(json!({"room": room, "invite": invite}));
                online.group.next_run_acks.clear();
                client.record(Event::new("next_run_offered").text("room", &room).list("guests", guests));
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phases(list: &[(u32, u64, u64)]) -> BTreeMap<u32, (u64, u64)> {
        list.iter().map(|(n, p, l)| (*n, (*p, *l))).collect()
    }

    fn names(events: &[Outgoing]) -> Vec<String> {
        events.iter().map(|e| e.0.clone()).collect()
    }

    #[test]
    fn a_phase_change_is_sent_once() {
        let mut watch = Watch::default();
        let none = BTreeSet::new();
        let first = watch.poll(&phases(&[(1, 0, 1)]), &[], &none, false);
        assert_eq!(names(&first), ["native_state"]);
        assert!(watch.poll(&phases(&[(1, 0, 1)]), &[], &none, false).is_empty());
        let next = watch.poll(&phases(&[(1, 5, 18), (2, 1, 17)]), &[], &none, false);
        assert_eq!(names(&next), ["native_state", "native_state"]);
        assert_eq!(next[0].1[0], ("player".to_string(), json!(1)));
        assert_eq!(next[0].1[1], ("phase".to_string(), json!(5)));
    }

    #[test]
    fn run_over_is_sent_when_it_turns_true_and_when_it_turns_back() {
        let mut watch = Watch::default();
        let none = BTreeSet::new();
        assert!(watch.poll(&phases(&[]), &[], &none, false).is_empty(), "the launcher assumes not over");
        assert_eq!(names(&watch.poll(&phases(&[]), &[], &none, true)), ["run_over"]);
        assert!(watch.poll(&phases(&[]), &[], &none, true).is_empty());
        let back = watch.poll(&phases(&[]), &[], &none, false);
        assert_eq!(back[0].1, vec![("value".to_string(), json!(0))]);
    }

    #[test]
    fn an_already_over_run_is_reported_at_the_first_poll() {
        let mut watch = Watch::default();
        let first = watch.poll(&phases(&[]), &[], &BTreeSet::new(), true);
        assert_eq!(names(&first), ["run_over"]);
    }

    #[test]
    fn each_offer_reaches_the_launcher_once_in_order() {
        let mut watch = Watch::default();
        let none = BTreeSet::new();
        let offers = vec![json!({"room": "a", "invite": "i1"})];
        let first = watch.poll(&phases(&[]), &offers, &none, false);
        assert_eq!(first[0].0, "next_run_offer");
        assert_eq!(first[0].1[0], ("room".to_string(), json!("a")));
        assert!(watch.poll(&phases(&[]), &offers, &none, false).is_empty());
        let more = vec![offers[0].clone(), json!({"room": "b", "invite": "i2"})];
        let second = watch.poll(&phases(&[]), &more, &none, false);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].1[0], ("room".to_string(), json!("b")));
    }

    #[test]
    fn acks_are_sent_on_change_and_not_while_empty_at_the_start() {
        let mut watch = Watch::default();
        assert!(watch.poll(&phases(&[]), &[], &BTreeSet::new(), false).is_empty());
        let acks: BTreeSet<u32> = [2].into_iter().collect();
        let sent = watch.poll(&phases(&[]), &[], &acks, false);
        assert_eq!(sent[0].1[0], ("acks".to_string(), json!([2])));
        assert!(watch.poll(&phases(&[]), &[], &acks, false).is_empty());
        let cleared = watch.poll(&phases(&[]), &[], &BTreeSet::new(), false);
        assert_eq!(cleared[0].1[0], ("acks".to_string(), json!([])), "a new offer clears the acks and the launcher hears it");
    }
}
