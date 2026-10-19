//! Relay transforms between the DLL pipe and the TLS peer link.
//!
//! Host: a `World` IPC message from the DLL -> the payload sent over TLS.
//! Guest: a payload received over TLS -> a `RemoteWorld` IPC message to the DLL,
//! after validating the world list the way online_bridge.receive_state does
//! (opcode in the WORLD allowlist, base64 fields within bounds).
//!
//! The full main loop (two threads bridging pipe<->TLS) lives in main.rs; these
//! pure transforms are what the tests pin down.

use azcoop_proto::ipc::{Kind, Message};
use serde_json::{json, Value};

/// world_packets.WORLD: UPDATE, DESTROY, MONSTER and the combat opcodes.
pub const WORLD: [u64; 11] = [0xA9, 0xAA, 0xDD, 0x143, 0x144, 0x14A, 0x250, 0x24E, 0x131, 0x132, 0x1F3];
/// Max base64 length for one packet body (1 MiB decoded).
const MAX_FIELD_B64: usize = (1_048_576 + 2) / 3 * 4;

pub fn is_world(opcode: u64) -> bool {
    WORLD.contains(&opcode)
}

/// Host side: extract the payload to send over TLS from a DLL `World` message.
/// Returns `None` for any other kind (ignored by the relay).
pub fn host_forward(msg: &Message) -> Option<Value> {
    if msg.kind == Kind::World {
        Some(msg.payload.clone())
    } else {
        None
    }
}

/// Validate a world list received over TLS, the way the Python guest does, and
/// wrap it as a `RemoteWorld` IPC message for the DLL. Rejects anything
/// malformed so the DLL never applies an unvalidated packet.
pub fn guest_wrap(payload: &Value) -> Result<Message, String> {
    let entries = payload["world"].as_array().ok_or("co-op message has no world list")?;
    for entry in entries {
        let pair = entry.as_array().filter(|p| p.len() == 2).ok_or("invalid co-op world entry")?;
        let opcode = pair[0].as_u64().ok_or("invalid co-op world opcode")?;
        if !is_world(opcode) {
            return Err("unsupported co-op world packet".into());
        }
        let text = pair[1].as_str().ok_or("invalid binary co-op field")?;
        if text.len() > MAX_FIELD_B64 {
            return Err("co-op field exceeds bound".into());
        }
    }
    Ok(Message::new(Kind::RemoteWorld, json!({ "world": entries })))
}
