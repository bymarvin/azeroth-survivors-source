//! Local message format between the DLL (inside the game) and the helper
//! (azcoop-net.exe), carried over a per-user named pipe.
//!
//! Frame: `u32 payload_len` + `u16 kind` + `u16 flags` + payload, all
//! little-endian, payload at most `MAX_IPC`. Only gameplay data crosses this
//! pipe: no paths or addresses. The only commands are the launcher's two room decisions ([`Command`]), validated field by
//! field. Both ends validate every field.

use serde_json::Value;

pub const IPC_VERSION: u16 = 1;
/// A `State` message carries one co-op message (up to `transport::MAX_MESSAGE`, 32 MiB) plus its envelope.
pub const MAX_IPC: usize = (32 << 20) + 4096;
pub const HEADER: usize = 8;

/// Message kinds. Unknown kinds are ignored by the receiver (forward-compatible).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Kind {
    /// DLL -> helper: ipc version, protocol, build id, game sha256, game pid.
    Hello = 1,
    /// helper -> DLL: accepted + role, or refused + reason.
    HelloAck = 2,
    /// DLL -> helper (host): extracted WORLD packets as a JSON object.
    World = 3,
    /// helper -> DLL (guest): validated remote WORLD packets.
    RemoteWorld = 4,
    /// helper -> DLL: connection state (connected / latency / closing).
    Status = 5,
    /// both: empty, once a second.
    Heartbeat = 6,
    /// both: orderly shutdown with a reason code.
    Goodbye = 7,
    /// both: one co-op `state` (or `goodbye`) message of a peer, `{"peer": n, "message": {...}}`. DLL -> helper: send it to
    /// peer `n`; helper -> DLL: it arrived from peer `n`. The content is the Python mod's message, unchanged.
    State = 8,
    /// DLL -> launcher (relay mode only): one core event the launcher reacts to, `{"event": "...", ...}` (see [`event_payload`]).
    Event = 9,
    /// launcher -> DLL (relay mode only): one of the launcher's room decisions ([`Command`]).
    Command = 10,
}

impl Kind {
    pub fn from_u16(value: u16) -> Option<Kind> {
        Some(match value {
            1 => Kind::Hello,
            2 => Kind::HelloAck,
            3 => Kind::World,
            4 => Kind::RemoteWorld,
            5 => Kind::Status,
            6 => Kind::Heartbeat,
            7 => Kind::Goodbye,
            8 => Kind::State,
            9 => Kind::Event,
            10 => Kind::Command,
            _ => return None,
        })
    }
}

/// A decoded IPC message: a kind, flags and a JSON payload (empty = Null).
#[derive(Clone, Debug)]
pub struct Message {
    pub kind: Kind,
    pub flags: u16,
    pub payload: Value,
}

impl Message {
    pub fn new(kind: Kind, payload: Value) -> Message {
        Message { kind, flags: 0, payload }
    }

    /// Serialize to one framed message. A Null payload becomes an empty body.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let body = if self.payload.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&self.payload).map_err(|e| e.to_string())?
        };
        if body.len() > MAX_IPC {
            return Err("ipc message exceeds size limit".into());
        }
        let mut out = Vec::with_capacity(HEADER + body.len());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.kind as u16).to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Splits whole framed messages from a buffer; returns them and bytes consumed.
/// An unknown kind is skipped (consumed but not returned), keeping the stream
/// in sync with a newer peer.
pub fn split_messages(buffer: &[u8]) -> Result<(Vec<Message>, usize), String> {
    let mut messages = Vec::new();
    let mut offset = 0;
    while buffer.len() - offset >= HEADER {
        let len = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
        if len > MAX_IPC {
            return Err("ipc message exceeds size limit".into());
        }
        if buffer.len() - offset < HEADER + len {
            break;
        }
        let raw_kind = u16::from_le_bytes(buffer[offset + 4..offset + 6].try_into().unwrap());
        let flags = u16::from_le_bytes(buffer[offset + 6..offset + 8].try_into().unwrap());
        let body = &buffer[offset + HEADER..offset + HEADER + len];
        offset += HEADER + len;
        if let Some(kind) = Kind::from_u16(raw_kind) {
            let payload = if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(body).map_err(|e| e.to_string())?
            };
            messages.push(Message { kind, flags, payload });
        }
    }
    Ok((messages, offset))
}

/// Builds the HELLO payload the DLL sends first.
pub fn hello(protocol: u64, build_id: &str, game_sha256: &str, game_pid: u32) -> Value {
    serde_json::json!({
        "ipc": IPC_VERSION,
        "protocol": protocol,
        "build": build_id,
        "game_sha256": game_sha256,
        "game_pid": game_pid,
    })
}

/// The helper's verdict on a HELLO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelloVerdict {
    /// All checks passed; the DLL may start capture once Status says connected.
    Accept { role: String },
    /// Refused with a reason the launcher can show the player verbatim.
    Refuse { reason: String },
}

/// Checks a HELLO payload against the helper's own protocol/build/game.
/// Rejects anything malformed or mismatched with a readable reason; never
/// panics on hostile input.
pub fn check_hello(
    hello: &Value,
    protocol: u64,
    build_id: &str,
    game_sha256: &str,
    role: &str,
) -> HelloVerdict {
    let refuse = |reason: &str| HelloVerdict::Refuse { reason: reason.to_string() };
    if hello["ipc"].as_u64() != Some(IPC_VERSION as u64) {
        return refuse("The co-op helper and the game mod are different versions. Reinstall the co-op mod.");
    }
    if hello["protocol"].as_u64() != Some(protocol) {
        return refuse("This player's co-op version differs. Both players need the same co-op hotfix.");
    }
    if hello["build"].as_str() != Some(build_id) {
        return refuse("The co-op helper and the game mod come from different builds. Reinstall the co-op mod.");
    }
    if hello["game_sha256"].as_str() != Some(game_sha256) {
        return refuse("This game version is not supported by the co-op mod.");
    }
    HelloVerdict::Accept { role: role.to_string() }
}

/// Builds a HELLO_ACK from a verdict.
pub fn hello_ack(verdict: &HelloVerdict) -> Value {
    match verdict {
        HelloVerdict::Accept { role } => serde_json::json!({"accepted": true, "ipc": IPC_VERSION, "role": role}),
        HelloVerdict::Refuse { reason } => serde_json::json!({"accepted": false, "reason": reason}),
    }
}

/// The payload of a [`Kind::State`] message.
pub fn state_payload(peer: u32, message: Value) -> Value {
    serde_json::json!({"peer": peer, "message": message})
}

/// Splits a [`Kind::State`] payload into the peer number (2..=4 from the DLL on the host, 1 on a guest) and the message.
pub fn parse_state(payload: &Value) -> Result<(u32, Value), String> {
    let peer = payload["peer"].as_u64().filter(|p| (1..=4).contains(p)).ok_or("state message without a valid peer")? as u32;
    match payload.get("message") {
        Some(message @ Value::Object(_)) => Ok((peer, message.clone())),
        _ => Err("state message without a message object".into()),
    }
}

/// The payload of a [`Kind::Status`] message about one peer: `event` is `connected` or `lost` (with a reason).
pub fn peer_status(peer: u32, event: &str, reason: &str) -> Value {
    serde_json::json!({"peer": peer, "event": event, "reason": reason})
}

/// Longest `room` / `invite` text of a next-run offer (the directory's ids are far shorter).
pub const MAX_OFFER_TEXT: usize = 128;

/// The launcher's decisions the core carries out. Only the host's launcher sends them; a guest's core refuses them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// The victory screen's choice: 8 keep fighting, 9 new hero (`request_victory_action`).
    VictoryAction(u32),
    /// Invite every guest to the next room (`offer_next_run`).
    OfferNextRun { room: String, invite: String },
    /// Leave the run properly (back to character select, which runs the class-XP evaluation and saves) before the launcher closes
    /// the game: a guest whose host left. Accepted by every role.
    LeaveRun,
}

fn offer_text(value: &Value, what: &str) -> Result<String, String> {
    let text = value.as_str().ok_or_else(|| format!("{what} is not a text"))?;
    if text.is_empty() || text.len() > MAX_OFFER_TEXT || !text.bytes().all(|b| (0x21..0x7F).contains(&b)) {
        return Err(format!("{what} is not a printable word of at most {MAX_OFFER_TEXT} characters"));
    }
    Ok(text.to_string())
}

/// Parses a [`Kind::Command`] payload: `{"command": "victory_action", "value": 8|9}` or
/// `{"command": "offer_next_run", "room": "...", "invite": "..."}`. Anything else is an error, never a guess.
pub fn parse_command(payload: &Value) -> Result<Command, String> {
    match payload.get("command").and_then(Value::as_str) {
        Some("victory_action") => match payload.get("value").and_then(Value::as_u64) {
            Some(v @ (8 | 9)) => Ok(Command::VictoryAction(v as u32)),
            _ => Err("victory_action needs the value 8 or 9".into()),
        },
        Some("offer_next_run") => Ok(Command::OfferNextRun { room: offer_text(&payload["room"], "room")?, invite: offer_text(&payload["invite"], "invite")? }),
        Some("leave_run") => Ok(Command::LeaveRun),
        _ => Err("unknown command".into()),
    }
}

/// The payload of a [`Command`] (what the launcher sends).
pub fn command_payload(command: &Command) -> Value {
    match command {
        Command::VictoryAction(v) => serde_json::json!({"command": "victory_action", "value": v}),
        Command::OfferNextRun { room, invite } => serde_json::json!({"command": "offer_next_run", "room": room, "invite": invite}),
        Command::LeaveRun => serde_json::json!({"command": "leave_run"}),
    }
}

/// The payload of a [`Kind::Event`]: the event's fields as one flat JSON object with `event` first.
pub fn event_payload(name: &str, fields: Vec<(String, Value)>) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("event".into(), Value::String(name.to_string()));
    for (key, value) in fields {
        if key != "event" {
            map.insert(key, value);
        }
    }
    Value::Object(map)
}

#[cfg(test)]
mod command_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn commands_round_trip() {
        for command in [Command::VictoryAction(8), Command::VictoryAction(9), Command::OfferNextRun { room: "r-1a2b".into(), invite: "K7QF-2M3D".into() }, Command::LeaveRun] {
            assert_eq!(parse_command(&command_payload(&command)).unwrap(), command);
        }
    }

    #[test]
    fn bad_commands_are_refused() {
        for bad in [
            json!(null),
            json!({}),
            json!({"command": "victory_action"}),
            json!({"command": "victory_action", "value": 7}),
            json!({"command": "victory_action", "value": -8}),
            json!({"command": "victory_action", "value": "8"}),
            json!({"command": "offer_next_run", "room": "a"}),
            json!({"command": "offer_next_run", "room": "", "invite": "x"}),
            json!({"command": "offer_next_run", "room": "a b", "invite": "x"}),
            json!({"command": "offer_next_run", "room": "a
b", "invite": "x"}),
            json!({"command": "offer_next_run", "room": "x".repeat(MAX_OFFER_TEXT + 1), "invite": "x"}),
            json!({"command": "offer_next_run", "room": 5, "invite": "x"}),
            json!({"command": "stop"}),
        ] {
            assert!(parse_command(&bad).is_err(), "{bad}");
        }
        assert!(parse_command(&json!({"command": "offer_next_run", "room": "x".repeat(MAX_OFFER_TEXT), "invite": "y"})).is_ok());
    }

    #[test]
    fn new_kinds_survive_the_framing_and_an_older_peer_skips_them() {
        let event = Message::new(Kind::Event, event_payload("run_over", vec![("value".into(), json!(1))]));
        let command = Message::new(Kind::Command, command_payload(&Command::VictoryAction(8)));
        let mut wire = event.encode().unwrap();
        wire.extend(command.encode().unwrap());
        let (messages, used) = split_messages(&wire).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(messages.len(), 2);
        assert_eq!((messages[0].kind, messages[1].kind), (Kind::Event, Kind::Command));
        assert_eq!(messages[0].payload["event"], "run_over");
        assert_eq!(Kind::from_u16(9), Some(Kind::Event));
        assert_eq!(Kind::from_u16(10), Some(Kind::Command));
        assert_eq!(Kind::from_u16(11), None);
    }

    #[test]
    fn event_payload_keeps_event_first_and_ignores_a_field_named_event() {
        let p = event_payload("native_state", vec![("player".into(), json!(1)), ("event".into(), json!("evil"))]);
        assert_eq!(p["event"], "native_state");
        assert_eq!(p["player"], 1);
    }
}

/// Longest grace window a DLL may ask for (seconds).
pub const MAX_GRACE_SECONDS: u64 = 600;

/// HELLO of a DLL that wants a lost link to stay open for `grace_seconds` (Step 3): `resume {v: 1, grace_s}`. A helper without
/// the feature ignores the field, so the DLL then simply gets today's behaviour.
pub fn hello_resume(protocol: u64, build_id: &str, game_sha256: &str, game_pid: u32, grace_seconds: u64) -> Value {
    let mut value = hello(protocol, build_id, game_sha256, game_pid);
    value["resume"] = serde_json::json!({"v": 1, "grace_s": grace_seconds});
    value
}

/// The grace window a HELLO asked for, if it asked validly (version 1, 1..=[`MAX_GRACE_SECONDS`] seconds).
pub fn resume_grace(hello: &Value) -> Option<u64> {
    let resume = hello.get("resume")?;
    if resume.get("v")?.as_u64()? != 1 {
        return None;
    }
    let grace = resume.get("grace_s")?.as_u64()?;
    (1..=MAX_GRACE_SECONDS).contains(&grace).then_some(grace)
}

/// `Status connected` about one peer; `epoch` counts how often that slot came back (0 = the first link).
pub fn peer_connected(peer: u32, epoch: u64) -> Value {
    serde_json::json!({"peer": peer, "event": "connected", "reason": "", "epoch": epoch})
}

#[cfg(test)]
mod resume_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_grace_window_travels_in_the_hello_and_is_bounded() {
        let plain = hello(5, "b", "s", 1);
        assert_eq!(resume_grace(&plain), None);
        assert_eq!(resume_grace(&hello_resume(5, "b", "s", 1, 90)), Some(90));
        assert_eq!(check_hello(&hello_resume(5, "b", "s", 1, 90), 5, "b", "s", "host"), HelloVerdict::Accept { role: "host".into() });
        for bad in [0u64, MAX_GRACE_SECONDS + 1, u64::MAX] {
            assert_eq!(resume_grace(&hello_resume(5, "b", "s", 1, bad)), None, "{bad}");
        }
        let mut wrong_version = hello_resume(5, "b", "s", 1, 90);
        wrong_version["resume"]["v"] = json!(2);
        assert_eq!(resume_grace(&wrong_version), None);
        let mut not_a_number = hello_resume(5, "b", "s", 1, 90);
        not_a_number["resume"]["grace_s"] = json!("90");
        assert_eq!(resume_grace(&not_a_number), None);
    }

    #[test]
    fn a_connected_status_names_the_epoch() {
        assert_eq!(peer_connected(2, 3), json!({"peer": 2, "event": "connected", "reason": "", "epoch": 3}));
        assert_eq!(peer_status(2, "down", "x")["event"], "down");
    }
}
