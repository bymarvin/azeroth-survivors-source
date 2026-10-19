//! Is the co-op Python runtime usable? (installer and updater; shared like net.rs and unzip.rs)
//!
//! A python.exe alone proves nothing: an antivirus quarantine or an interrupted copy can remove a package
//! (cryptography) or one of its DLLs (_cffi_backend), and then every Python step, the updater's signature check
//! included, stops with ModuleNotFoundError. The probe imports what the updater and the launcher need first and
//! makes one Ed25519 key (the signature check's backend). A failure means: restore the runtime from the signed
//! release before any Python runs.

use std::path::Path;
use std::process::{Command, Stdio};

#[link(name = "kernel32")]
extern "system" {
    fn SetErrorMode(mode: u32) -> u32;
}
// A python.exe whose python312.dll is missing would show Windows' modal "DLL not found" box and wait for a click;
// the probe's child inherits this error mode and just fails.
const SEM_FAILCRITICALERRORS: u32 = 0x0001;
const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;

const PROBE: &str = "import ssl, zlib, lzma, json, hashlib, select, socket, ctypes\n\
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n\
Ed25519PrivateKey.generate().public_key()\n";

/// None when the runtime works, otherwise the reason (the last line Python printed, or why it did not start).
pub fn runtime_problem(python: &Path) -> Option<String> {
    if !python.is_file() {
        return Some(format!("{} is missing", python.display()));
    }
    let previous = unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX) };
    let result = Command::new(python).args(["-I", "-B", "-c", PROBE]).stdin(Stdio::null()).output();
    unsafe { SetErrorMode(previous) };
    let output = match result {
        Ok(output) => output,
        Err(error) => return Some(format!("the co-op Python does not start ({error})")),
    };
    if output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stderr);
    let last = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string();
    Some(match (last.is_empty(), output.status.code()) {
        (false, _) => last,
        (true, Some(code)) if code < 0 => format!("the co-op Python cannot start (exit 0x{:08X}, for example a missing DLL)", code as u32),
        (true, code) => format!("the co-op Python ended with {code:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_python_is_a_problem() {
        let problem = runtime_problem(Path::new("Z:/does/not/exist/python.exe")).unwrap();
        assert!(problem.contains("is missing"), "{problem}");
    }
}
