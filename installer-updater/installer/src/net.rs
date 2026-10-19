//! HTTPS downloads through WinHTTP (winhttp.dll): part of every Windows and of Wine/Proton, no external tool.
//!
//! HTTPS only (plain HTTP only for local tests), at most 5 redirects and never from HTTPS to HTTP, the final
//! address checked again, a size limit per download, interrupted downloads continue (HTTP Range), 3 retries.

use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::ptr::null;

type Handle = *mut c_void;

#[link(name = "winhttp")]
extern "system" {
    fn WinHttpOpen(agent: *const u16, access: u32, proxy: *const u16, bypass: *const u16, flags: u32) -> Handle;
    fn WinHttpConnect(session: Handle, server: *const u16, port: u16, reserved: u32) -> Handle;
    fn WinHttpOpenRequest(connect: Handle, verb: *const u16, object: *const u16, version: *const u16,
                          referrer: *const u16, accept: *const *const u16, flags: u32) -> Handle;
    fn WinHttpSetOption(handle: Handle, option: u32, buffer: *const c_void, length: u32) -> i32;
    fn WinHttpSetTimeouts(handle: Handle, resolve: i32, connect: i32, send: i32, receive: i32) -> i32;
    fn WinHttpAddRequestHeaders(request: Handle, headers: *const u16, length: u32, modifiers: u32) -> i32;
    fn WinHttpSendRequest(request: Handle, headers: *const u16, length: u32, optional: *const c_void,
                          optional_length: u32, total: u32, context: usize) -> i32;
    fn WinHttpReceiveResponse(request: Handle, reserved: *mut c_void) -> i32;
    fn WinHttpQueryHeaders(request: Handle, level: u32, name: *const u16, buffer: *mut c_void, length: *mut u32,
                           index: *mut u32) -> i32;
    fn WinHttpQueryOption(handle: Handle, option: u32, buffer: *mut c_void, length: *mut u32) -> i32;
    fn WinHttpReadData(request: Handle, buffer: *mut c_void, length: u32, read: *mut u32) -> i32;
    fn WinHttpCloseHandle(handle: Handle) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

const ACCESS_DEFAULT_PROXY: u32 = 0;
const FLAG_SECURE: u32 = 0x0080_0000;
const OPTION_REDIRECT_POLICY: u32 = 88;
const OPTION_MAX_REDIRECTS: u32 = 89;
const OPTION_URL: u32 = 34;
const REDIRECT_DISALLOW_HTTPS_TO_HTTP: u32 = 1;
const ADDREQ_FLAG_ADD: u32 = 0x2000_0000;
const QUERY_STATUS_CODE: u32 = 19;
const QUERY_FLAG_NUMBER: u32 = 0x2000_0000;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

struct Guard(Handle);

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

fn check(handle: Handle, what: &str) -> Result<Guard, String> {
    if handle.is_null() { Err(format!("{what} failed (WinHTTP error {})", unsafe { GetLastError() })) } else { Ok(Guard(handle)) }
}

fn ok(result: i32, what: &str) -> Result<(), String> {
    if result != 0 { Ok(()) } else { Err(format!("{what} failed (WinHTTP error {})", unsafe { GetLastError() })) }
}

/// (secure, host, port, path+query) of an absolute http(s) address; nothing else is accepted.
pub fn parse(url: &str) -> Result<(bool, String, u16, String), String> {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(format!("not an http(s) address: {url}"));
    };
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') || authority.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return Err(format!("invalid host in {url}"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(']') || authority.starts_with('[') => {
            (host.to_string(), port.parse::<u16>().map_err(|_| format!("invalid port in {url}"))?)
        }
        _ => (authority.to_string(), if secure { 443 } else { 80 }),
    };
    if path.contains(|c: char| c.is_whitespace() || c.is_control()) || path.contains('#') {
        return Err(format!("invalid path in {url}"));
    }
    Ok((secure, host, port, path.to_string()))
}

/// One attempt: status code, bytes appended or written; the file is never longer than `limit`.
fn attempt(url: &str, target: &Path, resume: bool, allow_http: bool, limit: u64) -> Result<u64, String> {
    let (secure, host, port, path) = parse(url)?;
    if !secure && !allow_http {
        return Err(format!("refusing a non-HTTPS address: {url}"));
    }
    let have = if resume { std::fs::metadata(target).map(|m| m.len()).unwrap_or(0) } else { 0 };
    let session = check(unsafe { WinHttpOpen(wide("azsurvivors-installer/2").as_ptr(), ACCESS_DEFAULT_PROXY, null(), null(), 0) },
                        "WinHttpOpen")?;
    ok(unsafe { WinHttpSetTimeouts(session.0, 15_000, 15_000, 30_000, 60_000) }, "WinHttpSetTimeouts")?;
    let connect = check(unsafe { WinHttpConnect(session.0, wide(&host).as_ptr(), port, 0) }, "WinHttpConnect")?;
    let request = check(unsafe {
        WinHttpOpenRequest(connect.0, wide("GET").as_ptr(), wide(&path).as_ptr(), null(), null(), null(),
                           if secure { FLAG_SECURE } else { 0 })
    }, "WinHttpOpenRequest")?;
    let (redirects, policy) = (5u32, REDIRECT_DISALLOW_HTTPS_TO_HTTP);
    ok(unsafe { WinHttpSetOption(request.0, OPTION_MAX_REDIRECTS, (&redirects as *const u32).cast(), 4) }, "redirect limit")?;
    ok(unsafe { WinHttpSetOption(request.0, OPTION_REDIRECT_POLICY, (&policy as *const u32).cast(), 4) }, "redirect policy")?;
    if have > 0 {
        let header = wide(&format!("Range: bytes={have}-"));
        ok(unsafe { WinHttpAddRequestHeaders(request.0, header.as_ptr(), u32::MAX, ADDREQ_FLAG_ADD) }, "Range header")?;
    }
    ok(unsafe { WinHttpSendRequest(request.0, null(), 0, null(), 0, 0, 0) }, &format!("connection to {host}"))?;
    ok(unsafe { WinHttpReceiveResponse(request.0, std::ptr::null_mut()) }, &format!("response from {host}"))?;
    let mut final_url = vec![0u16; 4096];
    let mut length = (final_url.len() * 2) as u32;
    if unsafe { WinHttpQueryOption(request.0, OPTION_URL, final_url.as_mut_ptr().cast(), &mut length) } != 0 {
        let address = String::from_utf16_lossy(&final_url[..(length as usize / 2).min(final_url.len())]);
        if !address.starts_with("https://") && !allow_http {
            return Err(format!("redirected to a non-HTTPS address: {address}"));
        }
    }
    let (mut status, mut size) = (0u32, 4u32);
    ok(unsafe { WinHttpQueryHeaders(request.0, QUERY_STATUS_CODE | QUERY_FLAG_NUMBER, null(),
                                    (&mut status as *mut u32).cast(), &mut size, std::ptr::null_mut()) }, "status")?;
    let append = match status {
        206 if have > 0 => true,
        200 => false,
        416 if have > 0 => return Ok(have), // Already complete; the caller checks size and SHA-256.
        _ => return Err(format!("download of {url} failed (HTTP {status})")),
    };
    let mut file = OpenOptions::new().create(true).write(true).append(append).truncate(!append).open(target)
        .map_err(|e| format!("cannot write {}: {e}", target.display()))?;
    let mut written = if append { have } else { 0 };
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let mut read = 0u32;
        ok(unsafe { WinHttpReadData(request.0, buffer.as_mut_ptr().cast(), buffer.len() as u32, &mut read) },
           &format!("download of {url}"))?;
        if read == 0 {
            break;
        }
        written += read as u64;
        if written > limit {
            return Err(format!("{url} is larger than allowed"));
        }
        file.write_all(&buffer[..read as usize]).map_err(|e| format!("cannot write {}: {e}", target.display()))?;
    }
    drop((request, connect, session));
    Ok(written)
}

/// Download `url` to `target` (continue a partial file if `resume`), at most `limit` bytes, 3 retries.
pub fn download(url: &str, target: &Path, resume: bool, allow_http: bool, limit: u64) -> Result<(), String> {
    let mut last = String::new();
    for attempt_number in 0..4 {
        if attempt_number > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        match attempt(url, target, resume || attempt_number > 0, allow_http, limit) {
            Ok(_) => return Ok(()),
            Err(error) if error.contains("refusing") || error.contains("non-HTTPS") || error.contains("larger than")
                || error.contains("HTTP 4") => return Err(error),
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(parse("https://github.com/a/b?x=1").unwrap(), (true, "github.com".into(), 443, "/a/b?x=1".into()));
        assert_eq!(parse("http://127.0.0.1:8080/f").unwrap(), (false, "127.0.0.1".into(), 8080, "/f".into()));
        assert_eq!(parse("https://example.org").unwrap().3, "/");
        for bad in ["ftp://x/y", "https://user@host/", "https://host:99999/", "https://ho st/", "file:///c:/x", "https:///x"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn plain_http_needs_the_test_switch() {
        let target = std::env::temp_dir().join("azs-net-test.bin");
        let error = download("http://127.0.0.1:9/x", &target, false, false, 10).unwrap_err();
        assert!(error.contains("refusing"), "{error}");
    }
}
