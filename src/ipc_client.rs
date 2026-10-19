//! DLL side of the local pipe to the network helper (azcoop-net.exe).
//!
//! The helper owns the pipe server; the DLL connects as the client. After a
//! HELLO/HELLO_ACK handshake the IPC thread pumps gameplay data:
//!   * host: drains WORLD byte-records the capture produces and sends them;
//!   * guest: receives RemoteWorld messages and hands them to an apply hook.
//!
//! Only this one thread touches the pipe; game threads still only push into the
//! lock-free rings. The game never waits on the helper: if the pipe breaks the
//! thread returns and the DLL stays in measure-only mode.

use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use azcoop_proto::ipc::{self, Kind, Message, MAX_IPC};
use serde_json::{json, Value};
use windows_sys::Win32::Foundation::{GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING};

/// Count of RemoteWorld messages handed to the apply hook (diagnostics).
pub static APPLIED: AtomicU64 = AtomicU64::new(0);
/// Count of WORLD messages sent to the helper (diagnostics).
pub static SENT: AtomicU64 = AtomicU64::new(0);

/// Validated session id (1..=64 hex), mirrored from the helper's rule so the
/// name is a single path element.
fn valid_session(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One overlapped read or write that waits for its own completion. The pipe handles are opened
/// `FILE_FLAG_OVERLAPPED`, so a thread blocked in a read does not hold up a write from another thread
/// (a synchronous handle serializes them, which would stall the writer until the peer sends something).
/// Returns the byte count, or the Windows error code.
fn overlapped(handle: HANDLE, buf: *mut u8, len: u32, write: bool) -> Result<usize, u32> {
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, CloseHandle};
    use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Threading::CreateEventW;
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    unsafe {
        let event = CreateEventW(null(), 1, 0, null());
        if event.is_null() {
            return Err(GetLastError());
        }
        let mut ov: OVERLAPPED = std::mem::zeroed();
        ov.hEvent = event;
        let ok = if write {
            WriteFile(handle, buf as _, len, null_mut(), &mut ov)
        } else {
            ReadFile(handle, buf as _, len, null_mut(), &mut ov)
        };
        if ok == 0 {
            let code = GetLastError();
            if code != ERROR_IO_PENDING {
                CloseHandle(event);
                return Err(code);
            }
        }
        let mut done = 0u32;
        let ok = GetOverlappedResult(handle, &ov, &mut done, 1);
        let code = if ok == 0 { GetLastError() } else { 0 };
        CloseHandle(event);
        if ok == 0 { Err(code) } else { Ok(done as usize) }
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A connected client end of the pipe. Closes the handle on drop.
pub struct Pipe {
    handle: HANDLE,
}

// A pipe handle is usable from several threads; the handle is opened for overlapped I/O, so one thread's read
// does not hold up another thread's write.
unsafe impl Send for Pipe {}
unsafe impl Sync for Pipe {}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

impl Pipe {
    /// Connect to the helper's pipe for `session`.
    pub fn connect(session: &str) -> Result<Pipe, String> {
        if !valid_session(session) {
            return Err("invalid session id".into());
        }
        let name = wide(&format!(r"\\.\pipe\azcoop-{session}"));
        let handle = unsafe {
            CreateFileW(name.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0 as HANDLE)
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!("connect pipe: Windows error {}", unsafe { GetLastError() }));
        }
        Ok(Pipe { handle })
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        match overlapped(self.handle, buf.as_mut_ptr(), buf.len() as u32, false) {
            Ok(read) => Ok(read),
            Err(109) | Err(233) => Ok(0),
            Err(code) => Err(format!("pipe read: Windows error {code}")),
        }
    }

    pub fn write_all(&self, buf: &[u8]) -> Result<(), String> {
        let mut sent = 0usize;
        while sent < buf.len() {
            let wrote = overlapped(self.handle, buf[sent..].as_ptr() as *mut u8, (buf.len() - sent) as u32, true)
                .map_err(|code| format!("pipe write: Windows error {code}"))?;
            if wrote == 0 {
                return Err("pipe write: wrote nothing".into());
            }
            sent += wrote;
        }
        Ok(())
    }
}

/// Buffers bytes from the pipe and yields whole IPC messages.
///
/// One Reader must be used for the whole connection (handshake AND pump): a
/// single read may bring in HELLO_ACK plus the messages that follow it, and a
/// Reader dropped after the handshake would lose them.
pub struct Reader<'a> {
    pipe: &'a Pipe,
    buffer: Vec<u8>,
    queue: std::collections::VecDeque<Message>,
}

impl<'a> Reader<'a> {
    pub fn new(pipe: &'a Pipe) -> Reader<'a> {
        Reader { pipe, buffer: Vec::new(), queue: std::collections::VecDeque::new() }
    }

    pub fn pipe(&self) -> &'a Pipe {
        self.pipe
    }

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
            let n = self.pipe.read(&mut chunk)?;
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

/// Send HELLO and read HELLO_ACK; returns the role the helper assigned or the
/// refusal reason.
pub fn handshake(
    reader: &mut Reader<'_>,
    protocol: u64,
    build_id: &str,
    game_sha256: &str,
    game_pid: u32,
) -> Result<String, String> {
    handshake_resume(reader, protocol, build_id, game_sha256, game_pid, None)
}

/// [`handshake`] that asks the helper to keep a lost peer link open for `grace` seconds (Step 3).
pub fn handshake_resume(
    reader: &mut Reader<'_>,
    protocol: u64,
    build_id: &str,
    game_sha256: &str,
    game_pid: u32,
    grace: Option<u64>,
) -> Result<String, String> {
    let hello = match grace {
        Some(seconds) => ipc::hello_resume(protocol, build_id, game_sha256, game_pid, seconds),
        None => ipc::hello(protocol, build_id, game_sha256, game_pid),
    };
    reader.pipe().write_all(&Message::new(Kind::Hello, hello).encode()?)?;
    let ack = reader.next()?.ok_or("helper closed before HELLO_ACK")?;
    if ack.kind != Kind::HelloAck {
        return Err(format!("expected HELLO_ACK, got {:?}", ack.kind));
    }
    if ack.payload["accepted"].as_bool() == Some(true) {
        Ok(ack.payload["role"].as_str().unwrap_or("guest").to_string())
    } else {
        Err(ack.payload["reason"].as_str().unwrap_or("co-op handshake refused").to_string())
    }
}

/// Receiver for validated remote WORLD payloads (the game-apply step). The
/// prototype hook just counts; applying packets into the game is the
/// capture/cipher-dependent part (parked on wip/batch-capture).
pub type ApplyWorld = dyn Fn(&Value) + Send + Sync;

/// Guest pump: block on the pipe, apply each RemoteWorld payload, until the
/// pipe closes or a goodbye arrives. One-way (host WORLD -> guest apply).
pub fn pump_guest(reader: &mut Reader<'_>, apply: &ApplyWorld) -> Result<(), String> {
    loop {
        match reader.next()? {
            Some(msg) => match msg.kind {
                Kind::RemoteWorld => {
                    apply(&msg.payload);
                    APPLIED.fetch_add(1, Relaxed);
                }
                Kind::Goodbye => return Ok(()),
                _ => {}
            },
            None => return Ok(()),
        }
    }
}

/// Bytes waiting on the pipe without blocking (PeekNamedPipe).
fn bytes_available(pipe: &Pipe) -> Result<u32, String> {
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let mut avail = 0u32;
    let ok = unsafe {
        PeekNamedPipe(pipe.handle, null_mut(), 0, null_mut(), &mut avail, null_mut())
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        if code == 109 || code == 233 {
            return Err("pipe closed".into());
        }
        return Err(format!("PeekNamedPipe: Windows error {code}"));
    }
    Ok(avail)
}

/// Host pump: send pending WORLD payloads, and watch (without blocking) for a
/// goodbye or a closed pipe. `outgoing` returns the next payload or None; when
/// idle it is called again after a short sleep. One-way (host WORLD -> guest).
pub fn pump_host(reader: &mut Reader<'_>, mut outgoing: impl FnMut() -> Option<Value>) -> Result<(), String> {
    let pipe = reader.pipe();
    loop {
        let mut did_send = false;
        while let Some(payload) = outgoing() {
            pipe.write_all(&Message::new(Kind::World, payload).encode()?)?;
            SENT.fetch_add(1, Relaxed);
            did_send = true;
        }
        // Non-blocking check for an incoming goodbye / close.
        if bytes_available(pipe)? > 0 {
            match reader.next()? {
                Some(msg) if msg.kind == Kind::Goodbye => return Ok(()),
                Some(_) => {}
                None => return Ok(()),
            }
        }
        if !did_send {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}

/// Send a goodbye (best-effort) before shutdown.
pub fn goodbye(pipe: &Pipe) {
    let _ = pipe.write_all(&Message::new(Kind::Goodbye, json!({"reason": "dll"})).encode().unwrap_or_default());
}
