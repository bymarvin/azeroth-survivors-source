//! Network-thread side of the co-op slice (host and guest), pure and testable.
//!
//! Host: `WorldExtractor` turns captured WRITE batch records (ring kind 2)
//! into the world packets a guest needs: decrypt the headers with the
//! per-connection cipher state, keep WORLD opcodes, encode them exactly like
//! `online_bridge.send_state` does for its `world` field: `[opcode, base64]`.
//!
//! Guest: `accept_world` validates a received world list the way
//! `online_bridge.receive_state` does (opcode in WORLD, strict base64, size
//! bounds, renderer backlog bound) and returns the packets for the apply step.
//!
//! The slice message is `{"kind":"native_world","world":[…]}`: native↔native
//! only. A Python guest expects the full bridge `state` message; producing that
//! is the bridge port (next milestone), not this transport slice.

use crate::cipher::{self, CipherState, KEY_LEN};
// Batch record prefix (hook::capture_batch layout): key(40) + end index(1) +
// end previous(1) + connection(8). Defined here; the capture hook uses it.
pub const BATCH_PREFIX: usize = KEY_LEN + 2 + 8;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;

/// `world_packets.WORLD`: UPDATE, DESTROY, MONSTER and the combat opcodes.
pub const WORLD: [u16; 11] = [0xA9, 0xAA, 0xDD, 0x143, 0x144, 0x14A, 0x250, 0x24E, 0x131, 0x132, 0x1F3];
/// `online_bridge`: a guest whose pending world bytes exceed this has fallen behind.
pub const MAX_WORLD_BACKLOG: usize = 524_288;
const MAX_FIELD: usize = 1_048_576;

pub fn is_world(opcode: u16) -> bool {
    WORLD.contains(&opcode)
}

#[derive(Default, Debug, Clone, Copy)]
pub struct ExtractStats {
    pub batches: u64,
    /// First batch on a connection: its start state is unknown, so it only
    /// seeds the cipher state (the Python bridge also starts from a known state).
    pub seeded: u64,
    /// Decrypt end state differs from the game's: other headers were enciphered
    /// in between. Resynchronised from the game's state, batch skipped.
    pub resyncs: u64,
    pub packets: u64,
    pub world_packets: u64,
    pub errors: u64,
}

#[derive(Default)]
pub struct WorldExtractor {
    states: HashMap<u64, CipherState>,
    pub stats: ExtractStats,
}

impl WorldExtractor {
    /// Feeds one batch record (`hook::capture_batch` layout) and returns the
    /// WORLD packets it contained, in order.
    pub fn feed(&mut self, record: &[u8]) -> Vec<(u16, Vec<u8>)> {
        if record.len() < BATCH_PREFIX {
            self.stats.errors += 1;
            return Vec::new();
        }
        self.stats.batches += 1;
        let key: &[u8; KEY_LEN] = record[..KEY_LEN].try_into().unwrap();
        let end = CipherState { index: record[KEY_LEN], previous: record[KEY_LEN + 1] };
        let connection = u64::from_le_bytes(record[KEY_LEN + 2..BATCH_PREFIX].try_into().unwrap());
        let data = &record[BATCH_PREFIX..];
        let Some(start) = self.states.insert(connection, end) else {
            self.stats.seeded += 1;
            return Vec::new();
        };
        match cipher::decrypt_batch(data, key, start) {
            Ok((packets, decrypted_end)) if decrypted_end == end => {
                self.stats.packets += packets.len() as u64;
                let world: Vec<_> = packets.into_iter().filter(|(op, _)| is_world(*op)).collect();
                self.stats.world_packets += world.len() as u64;
                world
            }
            Ok(_) => {
                self.stats.resyncs += 1;
                Vec::new()
            }
            Err(_) => {
                self.stats.errors += 1;
                Vec::new()
            }
        }
    }
}

/// `[[opcode, base64(body)], …]`, as `online_bridge.send_state` builds `world`.
pub fn world_entries(packets: &[(u16, Vec<u8>)]) -> Value {
    let engine = base64::engine::general_purpose::STANDARD;
    Value::Array(packets.iter().map(|(op, body)| json!([op, engine.encode(body)])).collect())
}

pub fn world_message(packets: &[(u16, Vec<u8>)]) -> Value {
    json!({"kind": "native_world", "world": world_entries(packets)})
}

/// Guest side: validate and decode a `world` list like `receive_state`.
/// `backlog` is the guest's not-yet-rendered world bytes (bounded).
pub fn accept_world(message: &Value, backlog: &mut usize) -> Result<Vec<(u16, Vec<u8>)>, String> {
    let entries = message["world"].as_array().ok_or("co-op message has no world list")?;
    let engine = base64::engine::general_purpose::STANDARD;
    let mut packets = Vec::with_capacity(entries.len());
    for entry in entries {
        let pair = entry.as_array().filter(|p| p.len() == 2).ok_or("invalid co-op world entry")?;
        let opcode = pair[0].as_u64().filter(|op| *op <= u16::MAX as u64).ok_or("invalid co-op world opcode")? as u16;
        if !is_world(opcode) {
            return Err("unsupported co-op world packet".into());
        }
        let text = pair[1].as_str().ok_or("invalid binary co-op field")?;
        if text.len() > (MAX_FIELD + 2) / 3 * 4 {
            return Err("invalid binary co-op field".into());
        }
        let body = engine.decode(text).map_err(|_| "invalid binary co-op field".to_string())?;
        if body.len() > MAX_FIELD {
            return Err("co-op field exceeds bound".into());
        }
        *backlog += body.len() + 4;
        packets.push((opcode, body));
    }
    if *backlog > MAX_WORLD_BACKLOG {
        return Err("co-op renderer fell behind".into());
    }
    Ok(packets)
}

// ---- Guest apply: build the outgoing batch with remote packets injected -----
//
// Mirrors visibility_bridge.py's WRITE injection. Two cases, exactly as there:
//   * a batch start state is known (a prior batch was seen): decrypt the
//     existing batch from that start, check its end equals the connection's
//     recorded boundary, then re-encipher existing + injected packets from the
//     same start - one consistent batch;
//   * no prior state: encipher just the injected packets from the connection's
//     current end state and append them to the existing batch bytes.
// Returns the new batch bytes and the new cipher end state. Pure; the in-game
// write (scratch buffer + context rewrite) is a separate, OFF-by-default path.

use crate::cipher::encrypt_packets;

pub fn inject_into_batch(
    original: &[u8],
    key: &[u8; KEY_LEN],
    batch_start: Option<CipherState>,
    connection_end: CipherState,
    inject: &[(u16, Vec<u8>)],
) -> Result<(Vec<u8>, CipherState), String> {
    match batch_start {
        Some(start) => {
            let (mut packets, end) = cipher::decrypt_batch(original, key, start)?;
            if end != connection_end {
                return Err("native server batch cipher boundary changed".into());
            }
            packets.extend_from_slice(inject);
            Ok(encrypt_packets(&packets, key, start))
        }
        None => {
            let (extra, end) = encrypt_packets(inject, key, connection_end);
            let mut data = original.to_vec();
            data.extend_from_slice(&extra);
            Ok((data, end))
        }
    }
}
