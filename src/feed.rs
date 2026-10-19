//! What the host's own game says about the local player, read-only (M3/M7 data path):
//!
//! * **client direction** (`queue == connection.client_queue + 0x10` at WRITE): the player's own
//!   packets as the server queues them. Movement frames give the pose and the movement
//!   notices the Python bridge relays (`ClientFrames` + `decode_ground_movement`).
//! * **SERIALIZE** bootstrap packets: the login "player create" template (0xA9 with the verified
//!   local-player shape) and the character name reply (0x51).
//!
//! The game thread only copies bytes into a ring (hook.rs); this module parses them on the
//! consumer thread and keeps the latest results. Nothing here writes to the game.

use azcoop_world::builders::{character_name, clone_player};
use azcoop_world::session::{decode_ground_movement, is_movement_opcode, ClientFrames, HeaderCipher, Pose};
use std::collections::BTreeMap;

pub const KIND_CLIENT: u32 = 3;
pub const KIND_SERIALIZE: u32 = 4;
/// Record prefix of a client batch: key (40) + index (1) + previous (1) + connection (8).
pub const CLIENT_PREFIX: usize = 40 + 2 + 8;
/// The verified shape of the login local-player create (`visibility_bridge`: `body[:12]`).
pub const TEMPLATE_PREFIX: [u8; 12] = [0x01, 0, 0, 0, 0, 0x03, 0x07, 0xfe, 0xff, 0xff, 0x04, 0x71];

#[derive(Default)]
pub struct Feed {
    parsers: BTreeMap<u64, ClientFrames>,
    pub batches: u64,
    pub frames: u64,
    pub moves: u64,
    pub unsupported_moves: u64,
    pub errors: u64,
    pub opcodes: BTreeMap<u32, u64>,
    pub last_move: Option<(u32, Vec<u8>, Pose)>,
    /// The login template (validated) and the character name.
    pub template: Option<Vec<u8>>,
    pub name: Option<String>,
    pub template_errors: u64,
}

impl Feed {
    /// A client-direction record: key, cipher state before the batch, connection, bytes.
    pub fn client_record(&mut self, record: &[u8]) {
        if record.len() < CLIENT_PREFIX {
            self.errors += 1;
            return;
        }
        self.batches += 1;
        let connection = u64::from_le_bytes(record[42..50].try_into().unwrap());
        let data = &record[CLIENT_PREFIX..];
        if !self.parsers.contains_key(&connection) {
            let Ok(mut cipher) = HeaderCipher::new(&record[..40]) else {
                self.errors += 1;
                return;
            };
            cipher.index = record[40] as usize;
            cipher.previous = record[41];
            self.parsers.insert(connection, ClientFrames::new(Some(cipher)));
        }
        let parser = self.parsers.get_mut(&connection).unwrap();
        match parser.feed(data) {
            Ok(frames) => {
                for (opcode, body) in frames {
                    self.frames += 1;
                    *self.opcodes.entry(opcode).or_default() += 1;
                    if is_movement_opcode(opcode) {
                        match decode_ground_movement(&body) {
                            Ok(pose) => {
                                self.moves += 1;
                                self.last_move = Some((opcode, body, pose));
                            }
                            Err(_) => self.unsupported_moves += 1,
                        }
                    }
                }
            }
            Err(_) => {
                // Resynchronise from the next record rather than guessing.
                self.errors += 1;
                self.parsers.remove(&connection);
            }
        }
    }

    /// A SERIALIZE record: `opcode:u16, size:u32, body`.
    pub fn serialize_record(&mut self, record: &[u8]) {
        if record.len() < 6 {
            self.errors += 1;
            return;
        }
        let opcode = u16::from_le_bytes([record[0], record[1]]);
        let body = &record[6..];
        match opcode {
            0xA9 if self.template.is_none() && body.starts_with(&TEMPLATE_PREFIX) => {
                // Validate before registering, like the Python.
                let pose = body.get(20..36).map(|p| {
                    std::array::from_fn::<f64, 4, _>(|i| f32::from_le_bytes(p[4 * i..4 * i + 4].try_into().unwrap()) as f64)
                });
                match pose.map(|p| clone_player(body, 0xFF0101, p)) {
                    Some(Ok(_)) => self.template = Some(body.to_vec()),
                    _ => self.template_errors += 1,
                }
            }
            0x51 if self.name.is_none() => match character_name(body) {
                Ok(name) => self.name = Some(name),
                Err(_) => self.template_errors += 1,
            },
            _ => {}
        }
    }

    pub fn summary(&self) -> String {
        let pose = self.last_move.as_ref().map_or("none".to_string(), |(op, _, p)| format!("op {op:#x} at {:.1}, {:.1}, {:.1} facing {:.2}", p.x, p.y, p.z, p.facing));
        let mut top: Vec<(&u32, &u64)> = self.opcodes.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        let top: Vec<String> = top.iter().take(5).map(|(o, n)| format!("{o:#x}x{n}")).collect();
        format!(
            "feed: client batches {} frames {} moves {} unsupported {} errors {}, last move {pose}, top opcodes [{}]; template {}, name {}",
            self.batches,
            self.frames,
            self.moves,
            self.unsupported_moves,
            self.errors,
            top.join(" "),
            self.template.as_ref().map_or("none".to_string(), |t| format!("ok ({} bytes)", t.len())),
            self.name.as_deref().map_or("none".to_string(), |n| format!("'{n}'")),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azcoop_world::builders::movement;

    const RECORDINGS: [&str; 2] = [
        r"reference\0931\analysis\room-player-1.jsonl",
        r"reference\010\analysis\room-player-1.jsonl",
    ];

    fn unhex(t: &str) -> Option<Vec<u8>> {
        (t.len() % 2 == 0).then(|| (0..t.len()).step_by(2).filter_map(|i| u8::from_str_radix(&t[i..i + 2], 16).ok()).collect())
    }

    /// Client frames as the server queue holds them: header (size BE, opcode LE) enciphered, body clear.
    fn client_batch(cipher: &mut HeaderCipher, frames: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (opcode, body) in frames {
            let mut header = ((body.len() + 4) as u16).to_be_bytes().to_vec();
            header.extend_from_slice(&opcode.to_le_bytes());
            out.extend_from_slice(&cipher.encrypt(&header));
            out.extend_from_slice(body);
        }
        out
    }

    fn record(key: &[u8; 40], state: (u8, u8), connection: u64, data: &[u8]) -> Vec<u8> {
        let mut r = key.to_vec();
        r.push(state.0);
        r.push(state.1);
        r.extend_from_slice(&connection.to_le_bytes());
        r.extend_from_slice(data);
        r
    }

    #[test]
    fn client_movement_is_parsed_across_batches_and_a_bad_batch_resyncs() {
        println!("[ .... ] feed: client frames, movement, resync");
        let key: [u8; 40] = std::array::from_fn(|i| (i * 7 + 3) as u8);
        let mut encipher = HeaderCipher::new(&key).unwrap();
        encipher.index = 5;
        encipher.previous = 0x42;
        let mut feed = Feed::default();
        let move_body = |x: f64| movement(x, 2.0, 3.0, 0.5, 100).unwrap();
        // First batch: a heartbeat (0xEE) and a ground move (0xB5) plus a non-movement frame.
        let first = client_batch(&mut encipher, &[(0xEE, move_body(10.0)), (0x1234, vec![1, 2, 3]), (0xB5, move_body(11.0))]);
        feed.client_record(&record(&key, (5, 0x42), 77, &first));
        // Second batch: the cipher continues; the record repeats the (now stale) connection state, which is ignored.
        let second = client_batch(&mut encipher, &[(0xBA, move_body(12.0))]);
        feed.client_record(&record(&key, (9, 9), 77, &second));
        assert_eq!((feed.batches, feed.frames, feed.moves, feed.errors), (2, 4, 3, 0));
        let (opcode, _, pose) = feed.last_move.clone().unwrap();
        assert_eq!((opcode, pose.x), (0xBA, 12.0));
        assert_eq!(feed.opcodes[&0x1234], 1);
        // An unsupported movement mode (swimming flags) is counted, not parsed.
        let mut swim = move_body(1.0);
        swim[..4].copy_from_slice(&0x0020_0000u32.to_le_bytes());
        let third = client_batch(&mut encipher, &[(0xB5, swim)]);
        feed.client_record(&record(&key, (0, 0), 77, &third));
        assert_eq!(feed.unsupported_moves, 1);
        // Garbage resets that connection's parser; the next record reseeds it from the state it carries.
        let mut bad = encipher.encrypt(&[0, 2, 0xB5, 0, 0, 0]); // a frame size below its own header
        bad.extend_from_slice(&[1, 2]);
        feed.client_record(&record(&key, (0, 0), 77, &bad));
        assert_eq!(feed.errors, 1);
        let mut fresh = HeaderCipher::new(&key).unwrap();
        let again = client_batch(&mut fresh, &[(0xB5, move_body(13.0))]);
        feed.client_record(&record(&key, (0, 0), 77, &again));
        assert_eq!(feed.moves, 4);
        assert!(feed.summary().contains("moves 4"));
        println!("[  OK  ] feed: client frames, movement, resync ({})", feed.summary());
    }

    #[test]
    fn bootstrap_template_and_name_are_validated() {
        println!("[ .... ] feed: SERIALIZE bootstrap template and name");
        let (mut template, mut name) = (None, None);
        for path in RECORDINGS {
            let Ok(text) = std::fs::read_to_string(path) else { continue };
            for line in text.lines() {
                let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else { continue };
                let Some(body) = event["body"].as_str().and_then(unhex) else { continue };
                match event["event"].as_str() {
                    Some("native_player_create") if template.is_none() => template = Some(body),
                    Some("character_name_registered") if name.is_none() && body.len() > 8 && body[..8] == 0xFFFFFEu64.to_le_bytes() => name = Some(body),
                    _ => {}
                }
            }
        }
        let (Some(template), Some(name)) = (template, name) else {
            println!("[ WARN ] recordings missing, skipped");
            return;
        };
        let serialize = |opcode: u16, body: &[u8]| {
            let mut r = opcode.to_le_bytes().to_vec();
            r.extend_from_slice(&(body.len() as u32).to_le_bytes());
            r.extend_from_slice(body);
            r
        };
        let mut feed = Feed::default();
        feed.serialize_record(&serialize(0xA9, &template));
        feed.serialize_record(&serialize(0x51, &name));
        assert!(feed.template.is_some() && feed.name.is_some(), "{}", feed.summary());
        // A mutated template and a bad name are counted, not registered.
        let mut other = Feed::default();
        let mut bad = template.clone();
        bad[20] ^= 0xFF;
        bad[69] = 255;
        other.serialize_record(&serialize(0xA9, &bad));
        other.serialize_record(&serialize(0x51, &name[..10]));
        assert!(other.template.is_none() && other.name.is_none());
        assert_eq!(other.template_errors, 2);
        println!("[  OK  ] feed: SERIALIZE bootstrap ({})", feed.summary());
    }
}
