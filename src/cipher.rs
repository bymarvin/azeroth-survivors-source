//! The native server's packet-header cipher, ported from `sessions.py`
//! (`HeaderCipher`) and `visibility_bridge.py` (`decrypt_batch`,
//! `encrypt_packets`).
//!
//! Only the 4-byte header of each packet (u16 big-endian size incl. opcode,
//! u16 little-endian opcode) is enciphered with a rolling 40-byte key; bodies
//! are plain. This is the game's own framing, not authentication. A WRITE
//! batch holds complete server packets; decrypting it needs the key and the
//! cipher state (index, previous) at the start of the batch, which is the end
//! state of the previous batch on the same connection.

pub const KEY_LEN: usize = 40;
pub const MAX_BATCH: usize = 1_048_576;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CipherState {
    pub index: u8,
    pub previous: u8,
}

/// Decrypts every packet header in `data`. Returns (opcode, body) pairs and
/// the cipher state after the last header, like `decrypt_batch`.
pub fn decrypt_batch(
    data: &[u8],
    key: &[u8; KEY_LEN],
    start: CipherState,
) -> Result<(Vec<(u16, Vec<u8>)>, CipherState), String> {
    if data.len() > MAX_BATCH || start.index as usize >= KEY_LEN {
        return Err("invalid server batch".into());
    }
    let (mut index, mut previous) = (start.index as usize, start.previous);
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if offset + 4 > data.len() {
            return Err("truncated server header".into());
        }
        let mut header = [0u8; 4];
        for (slot, &value) in header.iter_mut().zip(&data[offset..offset + 4]) {
            *slot = value.wrapping_sub(previous) ^ key[index];
            previous = value;
            index = (index + 1) % KEY_LEN;
        }
        let size = u16::from_be_bytes([header[0], header[1]]) as usize;
        if size < 2 || offset + size + 2 > data.len() {
            return Err("truncated server body".into());
        }
        let opcode = u16::from_le_bytes([header[2], header[3]]);
        packets.push((opcode, data[offset + 4..offset + size + 2].to_vec()));
        offset += size + 2;
    }
    Ok((packets, CipherState { index: index as u8, previous }))
}

/// Inverse of `decrypt_batch` (Python `encrypt_packets`); used by tests and
/// the loopback harness to build realistic batches.
pub fn encrypt_packets(
    packets: &[(u16, Vec<u8>)],
    key: &[u8; KEY_LEN],
    start: CipherState,
) -> (Vec<u8>, CipherState) {
    let (mut index, mut previous) = (start.index as usize, start.previous);
    let mut out = Vec::new();
    for (opcode, body) in packets {
        let size = (body.len() + 2) as u16;
        let header = [size.to_be_bytes()[0], size.to_be_bytes()[1], opcode.to_le_bytes()[0], opcode.to_le_bytes()[1]];
        for value in header {
            previous = (value ^ key[index]).wrapping_add(previous);
            index = (index + 1) % KEY_LEN;
            out.push(previous);
        }
        out.extend_from_slice(body);
    }
    (out, CipherState { index: index as u8, previous })
}
