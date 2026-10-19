//! Local channel between the helper (server) and the DLL in the game (client).
//!
//! Restricted three ways so only the game on this machine, run by this user,
//! can talk to the helper:
//!   1. the channel's access list grants the current user's account only
//!      (protected list, no inherited entries);
//!   2. remote clients are refused (PIPE_REJECT_REMOTE_CLIENTS);
//!   3. a single server instance, and each side compares the other end's
//!      process id to the one the launcher passed it.
//!
//! The name carries a random session id from the launcher; it is validated as
//! plain hex so it can never extend into another path.

use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const BUFFER: u32 = 64 * 1024;

/// A session id must be 1..=64 plain hex chars, so the name stays a single path
/// element with no separators, dots or wildcards.
pub fn valid_session(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The channel name for a session id (caller must have validated it).
pub fn endpoint_name(session: &str) -> String {
    format!(r"\\.\pipe\azcoop-{session}")
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error(what: &str) -> String {
    format!("{what}: Windows error {}", unsafe { GetLastError() })
}

/// Owns a security descriptor allocated by Windows and frees it on drop.
struct OwnedSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
}

impl Drop for OwnedSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe { LocalFree(self.descriptor as _) };
        }
    }
}

/// Current user's SID as a string (e.g. "S-1-5-21-..."). Used to build the
/// access list so only this account can open the channel.
fn current_user_sid() -> Result<String, String> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_error("OpenProcessToken"));
        }
        let token = OwnedHandle::from_raw_handle(token as _);
        // First call: ask for the required size.
        let mut needed = 0u32;
        GetTokenInformation(as_handle(&token), TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err(last_error("GetTokenInformation(size)"));
        }
        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(as_handle(&token), TokenUser, buffer.as_mut_ptr() as _, needed, &mut needed) == 0 {
            return Err(last_error("GetTokenInformation"));
        }
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut sid_ptr: *mut u16 = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_ptr) == 0 {
            return Err(last_error("ConvertSidToStringSidW"));
        }
        let mut len = 0usize;
        while *sid_ptr.add(len) != 0 {
            len += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_ptr, len));
        LocalFree(sid_ptr as _);
        Ok(sid)
    }
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

fn as_handle(handle: &OwnedHandle) -> HANDLE {
    use std::os::windows::io::AsRawHandle;
    handle.as_raw_handle() as HANDLE
}

/// Build a security descriptor that grants full access to the current user's
/// SID only: SDDL `D:P(A;;GA;;;<sid>)` - a protected DACL (`P`, no inherited
/// entries) with one allow-all ace for this account.
fn user_only_security() -> Result<OwnedSecurity, String> {
    let sid = current_user_sid()?;
    let sddl = wide(&format!("D:P(A;;GA;;;{sid})"));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1 as u32,
            &mut descriptor,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW"));
    }
    Ok(OwnedSecurity { descriptor })
}

/// A connected channel end. Reads and writes raw bytes; the IPC framing lives
/// in `azcoop_proto::ipc`. Closes the handle on drop.
pub struct Endpoint {
    handle: OwnedHandle,
}

impl Endpoint {
    /// Process id of the other end.
    pub fn peer_pid(&self, server_side: bool) -> Result<u32, String> {
        let mut pid = 0u32;
        let ok = unsafe {
            if server_side {
                GetNamedPipeClientProcessId(as_handle(&self.handle), &mut pid)
            } else {
                GetNamedPipeServerProcessId(as_handle(&self.handle), &mut pid)
            }
        };
        if ok == 0 {
            return Err(last_error("GetNamedPipe*ProcessId"));
        }
        Ok(pid)
    }

    /// Read into `buf`; returns the number of bytes, 0 when the peer closed.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        match overlapped(as_handle(&self.handle), buf.as_mut_ptr(), buf.len() as u32, false) {
            Ok(read) => Ok(read),
            // A closed pipe surfaces as an error; report 0 so the caller ends cleanly.
            Err(109) | Err(233) => Ok(0), // ERROR_BROKEN_PIPE / ERROR_PIPE_NOT_CONNECTED
            Err(code) => Err(format!("ReadFile: Windows error {code}")),
        }
    }

    /// Cancels a read another thread is blocked in (it then fails), so that thread can end.
    pub fn cancel_io(&self) {
        unsafe { windows_sys::Win32::System::IO::CancelIoEx(as_handle(&self.handle), null_mut()) };
    }

    /// Bytes waiting to be read, without blocking (`PeekNamedPipe`). Err when the peer closed.
    pub fn available(&self) -> Result<u32, String> {
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        let mut avail = 0u32;
        let ok = unsafe { PeekNamedPipe(as_handle(&self.handle), null_mut(), 0, null_mut(), &mut avail, null_mut()) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(if code == 109 || code == 233 { "pipe closed".to_string() } else { format!("PeekNamedPipe: Windows error {code}") });
        }
        Ok(avail)
    }

    /// Write all of `buf`.
    pub fn write_all(&self, buf: &[u8]) -> Result<(), String> {
        let mut sent = 0usize;
        while sent < buf.len() {
            let wrote = overlapped(as_handle(&self.handle), buf[sent..].as_ptr() as *mut u8, (buf.len() - sent) as u32, true)
                .map_err(|code| format!("WriteFile: Windows error {code}"))?;
            if wrote == 0 {
                return Err("WriteFile: wrote nothing".into());
            }
            sent += wrote;
        }
        Ok(())
    }
}

/// Create the single server instance for `session` and block until the one
/// client connects. The access list grants only the current user.
pub fn serve(session: &str) -> Result<Endpoint, String> {
    if !valid_session(session) {
        return Err("invalid session id".into());
    }
    let security = user_only_security()?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.descriptor,
        bInheritHandle: 0,
    };
    let name = wide(&endpoint_name(session));
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, // exactly one instance
            BUFFER,
            BUFFER,
            0,
            &mut attrs,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateNamedPipeW"));
    }
    let endpoint = Endpoint { handle: unsafe { OwnedHandle::from_raw_handle(handle as _) } };
    // Wait for the client. ERROR_PIPE_CONNECTED means it connected first - fine.
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_IO_PENDING};
        use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
        use windows_sys::Win32::System::Threading::CreateEventW;
        let event = CreateEventW(null(), 1, 0, null());
        if event.is_null() {
            return Err(last_error("CreateEventW"));
        }
        let mut ov: OVERLAPPED = std::mem::zeroed();
        ov.hEvent = event;
        let connected = ConnectNamedPipe(handle, &mut ov);
        let result = if connected != 0 {
            Ok(())
        } else {
            match GetLastError() {
                ERROR_PIPE_CONNECTED => Ok(()),
                ERROR_IO_PENDING => {
                    let mut done = 0u32;
                    if GetOverlappedResult(handle, &ov, &mut done, 1) != 0 { Ok(()) } else { Err(format!("ConnectNamedPipe: Windows error {}", GetLastError())) }
                }
                code => Err(format!("ConnectNamedPipe: Windows error {code}")),
            }
        };
        CloseHandle(event);
        result?;
    }
    Ok(endpoint)
}

/// Connect to the helper's channel for `session` (the DLL side).
pub fn connect(session: &str) -> Result<Endpoint, String> {
    if !valid_session(session) {
        return Err("invalid session id".into());
    }
    let name = wide(&endpoint_name(session));
    let handle = unsafe {
        CreateFileW(name.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0 as HANDLE)
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateFileW(connect)"));
    }
    Ok(Endpoint { handle: unsafe { OwnedHandle::from_raw_handle(handle as _) } })
}
