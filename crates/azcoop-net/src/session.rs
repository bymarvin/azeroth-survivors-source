//! The HELLO handshake and a framed message reader over an [`Endpoint`].
//!
//! The helper additionally checks that the connecting process id equals the
//! game pid the launcher passed it, so only the launched game - not some other
//! local process of the same user - is accepted as the DLL side.

use azcoop_proto::ipc::{self, HelloVerdict, Kind, Message, MAX_IPC};

use crate::endpoint::Endpoint;

/// Buffers bytes from an endpoint and hands back whole IPC messages.
pub struct Reader<'a> {
    endpoint: &'a Endpoint,
    buffer: Vec<u8>,
    queue: std::collections::VecDeque<Message>,
}

impl<'a> Reader<'a> {
    pub fn new(endpoint: &'a Endpoint) -> Reader<'a> {
        Reader { endpoint, buffer: Vec::new(), queue: std::collections::VecDeque::new() }
    }

    /// Next whole message, reading from the pipe as needed. `Ok(None)` means the
    /// peer closed the channel.
    pub fn next(&mut self) -> Result<Option<Message>, String> {
        loop {
            if let Some(msg) = self.queue.pop_front() {
                return Ok(Some(msg));
            }
            let (messages, consumed) = ipc::split_messages(&self.buffer)?;
            if !messages.is_empty() {
                self.buffer.drain(..consumed);
                self.queue.extend(messages);
                continue;
            }
            let mut chunk = [0u8; 16 * 1024];
            let n = self.endpoint.read(&mut chunk)?;
            if n == 0 {
                return Ok(None);
            }
            if self.buffer.len() + n > 2 * MAX_IPC {
                return Err("ipc read backlog exceeded".into());
            }
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Helper side: receive HELLO, verify the client pid and the HELLO fields,
/// answer HELLO_ACK. Returns the agreed role on success; on any mismatch it
/// sends the refusal (so the launcher can show the reason) and returns `Err`.
/// Convenience wrapper that owns its Reader; use `helper_accept_with` when the
/// same Reader must carry on into the message pump.
pub fn helper_accept(
    endpoint: &Endpoint,
    expected_game_pid: u32,
    protocol: u64,
    build_id: &str,
    game_sha256: &str,
    role: &str,
) -> Result<String, String> {
    let mut reader = Reader::new(endpoint);
    helper_accept_with(&mut reader, expected_game_pid, protocol, build_id, game_sha256, role)
}

/// Same as `helper_accept`, on a caller-owned Reader so bytes that arrive right
/// after HELLO are not lost when the handshake returns.
pub fn helper_accept_with(
    reader: &mut Reader<'_>,
    expected_game_pid: u32,
    protocol: u64,
    build_id: &str,
    game_sha256: &str,
    role: &str,
) -> Result<String, String> {
    helper_accept_resume(reader, expected_game_pid, protocol, build_id, game_sha256, role).map(|(role, _)| role)
}

/// [`helper_accept_with`] that also returns the grace window (seconds) the DLL asked for in its HELLO (`resume`), if any.
pub fn helper_accept_resume(
    reader: &mut Reader<'_>,
    expected_game_pid: u32,
    protocol: u64,
    build_id: &str,
    game_sha256: &str,
    role: &str,
) -> Result<(String, Option<u64>), String> {
    let endpoint = reader.endpoint;
    // The connecting process must be the game the launcher started.
    let client_pid = endpoint.peer_pid(true)?;
    if client_pid != expected_game_pid {
        let verdict = HelloVerdict::Refuse {
            reason: "A different process tried to use the co-op channel.".into(),
        };
        let _ = endpoint.write_all(&Message::new(Kind::HelloAck, ipc::hello_ack(&verdict)).encode()?);
        return Err(format!("client pid {client_pid} != launched game pid {expected_game_pid}"));
    }

    let first = reader.next()?.ok_or("peer closed before HELLO")?;
    if first.kind != Kind::Hello {
        return Err(format!("expected HELLO, got {:?}", first.kind));
    }
    let verdict = ipc::check_hello(&first.payload, protocol, build_id, game_sha256, role);
    endpoint.write_all(&Message::new(Kind::HelloAck, ipc::hello_ack(&verdict)).encode()?)?;
    match verdict {
        HelloVerdict::Accept { role } => Ok((role, ipc::resume_grace(&first.payload))),
        HelloVerdict::Refuse { reason } => Err(reason),
    }
}

/// DLL side: send HELLO, read HELLO_ACK. Returns the role the helper assigned,
/// or the refusal reason.
pub fn dll_hello(
    endpoint: &Endpoint,
    protocol: u64,
    build_id: &str,
    game_sha256: &str,
    game_pid: u32,
) -> Result<String, String> {
    dll_hello_with(endpoint, ipc::hello(protocol, build_id, game_sha256, game_pid))
}

/// [`dll_hello`] that asks the helper to keep a lost link open for `grace_seconds` (Step 3).
pub fn dll_hello_resume(
    endpoint: &Endpoint,
    protocol: u64,
    build_id: &str,
    game_sha256: &str,
    game_pid: u32,
    grace_seconds: u64,
) -> Result<String, String> {
    dll_hello_with(endpoint, ipc::hello_resume(protocol, build_id, game_sha256, game_pid, grace_seconds))
}

fn dll_hello_with(endpoint: &Endpoint, hello: serde_json::Value) -> Result<String, String> {
    endpoint.write_all(&Message::new(Kind::Hello, hello).encode()?)?;
    let mut reader = Reader::new(endpoint);
    let ack = reader.next()?.ok_or("peer closed before HELLO_ACK")?;
    if ack.kind != Kind::HelloAck {
        return Err(format!("expected HELLO_ACK, got {:?}", ack.kind));
    }
    if ack.payload["accepted"].as_bool() == Some(true) {
        Ok(ack.payload["role"].as_str().unwrap_or("guest").to_string())
    } else {
        Err(ack.payload["reason"].as_str().unwrap_or("co-op handshake refused").to_string())
    }
}
