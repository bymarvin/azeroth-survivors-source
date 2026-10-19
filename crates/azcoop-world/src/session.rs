//! Client-direction framing and movement decoding: a byte-exact port of the
//! relevant parts of `sessions.py` (0.0.14) and `validate_movement_packet`
//! from `world_packets.py`.
//!
//! The header cipher is the game's own rolling 40-byte-key header obfuscation,
//! not authentication. Bodies are not encrypted. Everything here is bounded and
//! fails closed: an unknown layout is an error, never a guess.

use crate::{Reader, Result};

pub const LOGIN: u32 = 0x003D;
pub const HEARTBEAT: u32 = 0x00EE;
/// u16 big-endian size plus its two-byte prefix.
pub const MAX_FRAME: usize = 65_537;
pub const KEY_LEN: usize = 40;

/// `MOVEMENT_OPCODES`: 0xB5..=0xCB without 0xC7, plus 0xDA, 0xDB and HEARTBEAT.
pub fn is_movement_opcode(opcode: u32) -> bool {
    ((0xB5..0xCC).contains(&opcode) && opcode != 0xC7) || opcode == 0xDA || opcode == 0xDB || opcode == HEARTBEAT
}

/// One direction's rolling 40-byte-key header state.
#[derive(Clone)]
pub struct HeaderCipher {
    key: [u8; KEY_LEN],
    pub index: usize,
    pub previous: u8,
}

impl HeaderCipher {
    pub fn new(key: &[u8]) -> Result<HeaderCipher> {
        let key: [u8; KEY_LEN] = key.try_into().map_err(|_| "Expected a verified 40-byte session key".to_string())?;
        Ok(HeaderCipher { key, index: 0, previous: 0 })
    }

    pub fn decrypt(&mut self, header: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(header.len());
        for value in header {
            out.push(value.wrapping_sub(self.previous) ^ self.key[self.index]);
            self.previous = *value;
            self.index = (self.index + 1) % KEY_LEN;
        }
        out
    }

    /// Inverse of `decrypt` (used by tests to build realistic client streams).
    pub fn encrypt(&mut self, header: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(header.len());
        for value in header {
            self.previous = (value ^ self.key[self.index]).wrapping_add(self.previous);
            out.push(self.previous);
            self.index = (self.index + 1) % KEY_LEN;
        }
        out
    }
}

/// Incremental client frames. Cipher state is consumed once per header, even
/// when its payload arrives in a later read.
pub struct ClientFrames {
    pub cipher: Option<HeaderCipher>,
    buffer: Vec<u8>,
    pending: Option<(u32, usize)>,
}

impl ClientFrames {
    pub fn new(cipher: Option<HeaderCipher>) -> ClientFrames {
        ClientFrames { cipher, buffer: Vec::new(), pending: None }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<(u32, Vec<u8>)>> {
        if chunk.len() > MAX_FRAME || self.buffer.len() + chunk.len() > 2 * MAX_FRAME {
            return Err("Input batch exceeds the bounded decoder buffer".into());
        }
        self.buffer.extend_from_slice(chunk);
        let mut packets = Vec::new();
        loop {
            if self.pending.is_none() {
                if self.buffer.len() < 6 {
                    break;
                }
                let mut header: Vec<u8> = self.buffer.drain(..6).collect();
                if let Some(cipher) = self.cipher.as_mut() {
                    header = cipher.decrypt(&header);
                }
                let size = u16::from_be_bytes([header[0], header[1]]) as usize;
                if size < 4 {
                    return Err("Client frame length excludes its opcode".into());
                }
                let opcode = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
                self.pending = Some((opcode, size - 4));
            }
            let (opcode, length) = self.pending.unwrap();
            if self.buffer.len() < length {
                break;
            }
            packets.push((opcode, self.buffer.drain(..length).collect()));
            self.pending = None;
        }
        Ok(packets)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pose {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub facing: f32,
}

fn f32_at(body: &[u8], at: usize) -> f32 {
    f32::from_le_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]])
}

/// Validated ground/falling movement, including the native jump tail.
/// Transport, swimming and flight remain unsupported; client time is never
/// used as the authoritative simulation clock.
pub fn decode_ground_movement(body: &[u8]) -> Result<Pose> {
    if body.len() < 28 {
        return Err("Truncated movement body".into());
    }
    let flags = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    if flags & !0x71FF != 0 {
        return Err("Movement flags require an unimplemented mode".into());
    }
    let expected = if flags & 0x2000 != 0 { 44 } else { 28 };
    if body.len() != expected {
        return Err("Invalid ground/jump movement length".into());
    }
    let (x, y, z, facing) = (f32_at(body, 8), f32_at(body, 12), f32_at(body, 16), f32_at(body, 20));
    let mut values = vec![x, y, z, facing];
    if flags & 0x2000 != 0 {
        values.extend((0..4).map(|i| f32_at(body, 28 + 4 * i)));
    }
    if !values.iter().all(|v| v.is_finite()) {
        return Err("Non-finite movement".into());
    }
    Ok(Pose { x, y, z, facing })
}

/// A relayed movement packet: packed player GUID (0xFF0100 + number) followed by
/// a movement body. Returns the player number.
pub fn validate_movement_packet(body: &[u8], members: &[u64], owner: Option<u64>) -> Result<u64> {
    let mut reader = Reader::configured(body, false, crate::HOST, None, None);
    let guid = reader.guid(true, false)?;
    let number = guid
        .checked_sub(0xFF0100)
        .filter(|n| members.contains(n) && owner.map_or(true, |o| *n == o))
        .ok_or_else(|| "Movement packet belongs to another player".to_string())?;
    decode_ground_movement(&body[reader.pos..])?;
    Ok(number)
}
