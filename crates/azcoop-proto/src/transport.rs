//! PROTOCOL 5 wire codec, byte-compatible with `coop_transport.py`.
//!
//! Two frame kinds share one length-prefixed envelope (`!I` big-endian length
//! + body):
//! * **control** (`encode`/`decode_control`) — handshake and keepalives: a
//!   compact JSON object, never compressed, as `coop_transport.encode`.
//! * **gameplay** (`frame`/`frame_payload`) — `{"seq":N,"payload":{…}[,ctrl]}`,
//!   compressed to `b"Z" + zlib(body)` when the body reaches `COMPRESS_FROM`
//!   and that is smaller, as `coop_transport.frame_bytes`.
//!
//! Only the transport is reimplemented here; packet *contents* stay the JSON
//! the Python mod already exchanges, so a native host and a Python
//! 0.0.10-community guest interoperate. QUIC/PROTOCOL 4 is a later milestone.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde_json::Value;
use std::io::Write;

/// 3: enemy record patches. 4: guest companions/auras (bridge fields). 5: the
/// 0.0.12 play limits. The framing and handshake are identical across 3..=5;
/// peers on a different version are refused at the handshake.
pub const PROTOCOL: u64 = 5;
/// One co-op message (play_limits.MAX_MESSAGE, 32 MiB: a full 32 768-enemy
/// snapshot fits). Also the hard bound on any inflated frame.
pub const MAX_MESSAGE: usize = 32 << 20;
pub const COMPRESS_FROM: usize = 512;

/// Serialize a JSON value exactly like `json.dumps(…, separators=(',', ':'))`:
/// compact, and with object key order preserved (serde_json `preserve_order`).
pub fn compact(value: &Value) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if !(1..=MAX_MESSAGE).contains(&body.len()) {
        return Err("co-op message exceeds size limit".into());
    }
    Ok(body)
}

fn with_length(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Control frame (handshake, keepalive): length + compact JSON, uncompressed.
pub fn encode(message: &Value) -> Result<Vec<u8>, String> {
    Ok(with_length(&compact(message)?))
}

/// Decode a control frame body (the bytes after the 4-byte length) as a JSON
/// object; rejects non-objects and non-finite numbers, like `receive`.
pub fn decode_control(body: &[u8]) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if !value.is_object() {
        return Err("co-op message must be an object".into());
    }
    Ok(value)
}

fn zlib_compress(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(body).map_err(|e| e.to_string())?;
    encoder.finish().map_err(|e| e.to_string())
}

/// Gameplay frame: `{"seq":N,"payload":<payload>[,<control>]}`, zlib-wrapped
/// when it helps. `payload` and `control` are already-serialized JSON
/// fragments, composed textually exactly as `coop_transport.frame_bytes`.
pub fn frame(sequence: u64, payload: &Value, control: Option<&[u8]>) -> Result<Vec<u8>, String> {
    frame_body(sequence, &compact(payload)?, control)
}

/// [`frame`] for a payload that is already compact JSON (the sender serialized it on its own thread).
pub fn frame_body(sequence: u64, payload: &[u8], control: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let mut body = Vec::with_capacity(payload.len() + 48);
    body.extend_from_slice(br#"{"seq":"#);
    body.extend_from_slice(sequence.to_string().as_bytes());
    body.extend_from_slice(br#","payload":"#);
    body.extend_from_slice(payload);
    if let Some(control) = control {
        body.push(b',');
        body.extend_from_slice(control);
    }
    body.push(b'}');

    if body.len() >= COMPRESS_FROM {
        let mut packed = vec![b'Z'];
        packed.extend_from_slice(&zlib_compress(&body)?);
        if packed.len() < body.len() {
            body = packed;
        }
    }
    if !(1..=MAX_MESSAGE).contains(&body.len()) {
        return Err("co-op frame exceeds size limit".into());
    }
    Ok(with_length(&body))
}

/// Decode a gameplay frame body (bytes after the length), inflating a
/// `b"Z"`-prefixed body with a bounded output size, like `frame_payload`.
pub fn frame_payload(body: &[u8]) -> Result<Value, String> {
    let json = match body.first() {
        Some(b'Z') => {
            // Inflate with a hard output bound while streaming (like Python's
            // decompress(max_length=MAX_MESSAGE + 1)), so a small compressed
            // "bomb" can never allocate more than MAX_MESSAGE + 1 bytes.
            inflate_bounded(&body[1..])?
        }
        Some(b'{') => body.to_vec(),
        _ => return Err("unknown co-op frame encoding".into()),
    };
    serde_json::from_slice(&json).map_err(|e| e.to_string())
}

/// Inflates a zlib stream with a hard output bound, like Python's
/// `decompressobj().decompress(data, MAX_MESSAGE + 1)` plus its `eof` and
/// `unused_data` checks. Output capacity never grows past MAX_MESSAGE + 1, so
/// a small compressed "bomb" cannot allocate more than that. Rejects a stream
/// that ends early (truncated) or is followed by extra bytes (trailing data).
pub fn inflate_bounded(input: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::{Decompress, FlushDecompress, Status};
    let limit = MAX_MESSAGE + 1;
    let mut inflater = Decompress::new(true);
    let mut out: Vec<u8> = Vec::with_capacity(input.len().saturating_mul(4).clamp(64, limit));
    loop {
        if out.len() > MAX_MESSAGE {
            return Err("decompressed co-op message exceeds size limit".into());
        }
        if out.len() == out.capacity() {
            out.reserve_exact(out.capacity().min(limit - out.len()).max(1));
        }
        let (in_before, out_before) = (inflater.total_in() as usize, out.len());
        let status = inflater
            .decompress_vec(&input[in_before..], &mut out, FlushDecompress::None)
            .map_err(|e| format!("corrupt compressed co-op message: {e}"))?;
        if status == Status::StreamEnd {
            break;
        }
        let progressed = inflater.total_in() as usize != in_before || out.len() != out_before;
        if !progressed && out.len() < out.capacity() {
            return Err("truncated compressed co-op message".into());
        }
    }
    if out.len() > MAX_MESSAGE {
        return Err("decompressed co-op message exceeds size limit".into());
    }
    if inflater.total_in() as usize != input.len() {
        return Err("trailing data after compressed co-op message".into());
    }
    Ok(out)
}

/// Splits as many whole length-prefixed frames as are buffered, returning each
/// body (without the 4-byte length) and how many bytes were consumed. The
/// caller drains `consumed` bytes from the front of its buffer.
pub fn split_frames(buffer: &[u8]) -> Result<(Vec<Vec<u8>>, usize), String> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while buffer.len() - offset >= 4 {
        let size = u32::from_be_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
        if !(1..=MAX_MESSAGE).contains(&size) {
            return Err("co-op message exceeds size limit".into());
        }
        if buffer.len() - offset < size + 4 {
            break;
        }
        frames.push(buffer[offset + 4..offset + 4 + size].to_vec());
        offset += 4 + size;
    }
    Ok((frames, offset))
}
