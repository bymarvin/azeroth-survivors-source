//! Core events the launcher reacts to, collected from the engine's `record` and sent over the pipe as `Kind::Event`
//! (relay mode only: the launcher is the other end). The bridge's own change watcher
//! (`azcoop_bridge::control::Watch`) adds phase changes, `run_over` and the next-run offers.

use azcoop_logic::{Detail, Event};
use serde_json::{json, Value};
use std::sync::Mutex;

/// The recorded events the Python launcher's `record` override reacted to (`room_client.py`).
pub const FORWARDED: [&str; 9] = [
    "host_departed",
    "leave_applied",
    "host_victory_action",
    "party_waiting_for_map",
    "party_restart_requires_lobby",
    "team_defeat_shown",
    "completed_run_transition",
    "next_run_rejected",
    "shared_restart_requested",
];

/// More than this waiting for the pipe means nobody reads (no launcher): the oldest go.
const LIMIT: usize = 256;

static OUT: Mutex<Vec<(String, Vec<(String, Value)>)>> = Mutex::new(Vec::new());

fn number(x: f64) -> Value {
    if x.fract() == 0.0 && x.abs() < 9.0e15 {
        json!(x as i64)
    } else {
        json!(x)
    }
}

/// The event's fields as JSON (numbers, texts and number lists; nested items are left out).
pub fn fields(event: &Event) -> Vec<(String, Value)> {
    event
        .details
        .iter()
        .filter_map(|(key, detail)| {
            let value = match detail {
                Detail::Num(x) => number(*x),
                Detail::Text(t) => json!(t),
                Detail::List(l) => Value::Array(l.iter().map(|x| number(*x)).collect()),
                Detail::Items(_) => return None,
            };
            Some((key.clone(), value))
        })
        .collect()
}

/// Called for every recorded event: keeps the ones the launcher wants.
pub fn tee(event: &Event) {
    if !FORWARDED.contains(&event.name.as_str()) {
        return;
    }
    let mut out = OUT.lock().unwrap_or_else(|e| e.into_inner());
    if out.len() >= LIMIT {
        out.remove(0);
    }
    out.push((event.name.clone(), fields(event)));
}

/// What was kept since the last call.
pub fn take() -> Vec<(String, Vec<(String, Value)>)> {
    std::mem::take(&mut *OUT.lock().unwrap_or_else(|e| e.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The queue is process-wide: the two tests must not interleave.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn only_the_launchers_events_are_kept_and_fields_become_json() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        take();
        tee(&Event::new("native_xp_award").num("amount", 5.0));
        tee(&Event::new("host_departed").text("reason", "ConnectionError").num("after_run", 1.0));
        tee(&Event::new("host_victory_action").num("sequence", 2.0).num("command", 8.0));
        tee(&Event::new("party_waiting_for_map").num("player", 2.0).text("note", "x").list("l", vec![1.0, 2.5]));
        let kept = take();
        assert_eq!(kept.len(), 3);
        assert_eq!(kept[0].0, "host_departed");
        assert_eq!(kept[0].1[1], ("after_run".to_string(), json!(1)));
        assert_eq!(kept[1].0, "host_victory_action");
        assert_eq!(kept[1].1, vec![("sequence".to_string(), json!(2)), ("command".to_string(), json!(8))]);
        assert_eq!(kept[2].1[2], ("l".to_string(), json!([1, 2.5])));
        assert!(take().is_empty());
    }

    #[test]
    fn a_pile_without_a_reader_is_bounded() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        take();
        for i in 0..(LIMIT + 10) {
            tee(&Event::new("team_defeat_shown").num("player", i as f64));
        }
        let kept = take();
        assert_eq!(kept.len(), LIMIT);
        assert_eq!(kept[0].1[0].1, json!(10), "the oldest were dropped");
    }
}
