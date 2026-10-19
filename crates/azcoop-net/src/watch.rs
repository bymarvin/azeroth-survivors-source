//! Watches the game process the helper serves: when it ends, the exit code says how (a kill, a crash, a fast fail, a clean exit).

use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE};

/// What an exit code means for a game process.
pub fn describe_exit(code: u32) -> String {
    let name = match code {
        0 => "clean exit",
        1 => "exit code 1 (an error exit)",
        101 => "exit code 101 (a Rust panic ending the process)",
        0xC000_0005 => "ACCESS_VIOLATION",
        0xC000_00FD => "STACK_OVERFLOW",
        0xC000_001D => "ILLEGAL_INSTRUCTION",
        0xC000_0094 => "INTEGER_DIVIDE_BY_ZERO",
        0xC000_0409 => "STACK_BUFFER_OVERRUN / fast fail (a Rust abort ends here)",
        0xC000_0374 => "HEAP_CORRUPTION",
        0xC000_013A => "CONTROL_C_EXIT (console closed)",
        0x4000_0015 => "FATAL_APP_EXIT",
        _ => "other",
    };
    format!("{code:#010x} ({name})")
}

/// Starts a thread that logs how the process `pid` ended, through `log`. `None` if the process cannot be opened; otherwise a flag
/// that turns true once the line is written (see [`wait_logged`]).
pub fn watch_exit(pid: u32, log: impl Fn(&str) + Send + 'static) -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let raw = handle as usize;
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = done.clone();
    let started = std::thread::Builder::new()
        .name("game-exit-watch".into())
        .spawn(move || unsafe {
            let handle = raw as *mut std::ffi::c_void;
            if WaitForSingleObject(handle, INFINITE) == WAIT_OBJECT_0 {
                let mut code = 0u32;
                if GetExitCodeProcess(handle, &mut code) != 0 {
                    log(&format!("game process {pid} ended: {}", describe_exit(code)));
                }
            }
            CloseHandle(handle);
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .is_ok();
    started.then_some(done)
}

/// Gives the watcher up to `seconds` to write its line (the helper often ends right after the game).
pub fn wait_logged(done: &Option<std::sync::Arc<std::sync::atomic::AtomicBool>>, seconds: f64) {
    if let Some(done) = done {
        let end = std::time::Instant::now() + std::time::Duration::from_secs_f64(seconds);
        while !done.load(std::sync::atomic::Ordering::SeqCst) && std::time::Instant::now() < end {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_named() {
        assert!(describe_exit(0xC000_0409).contains("fast fail"));
        assert!(describe_exit(0xC000_0005).contains("ACCESS_VIOLATION"));
        assert!(describe_exit(101).contains("panic"));
        assert!(describe_exit(7).contains("other"));
    }

    #[test]
    fn a_process_that_ends_is_reported_with_its_code() {
        let child = std::process::Command::new("cmd").args(["/C", "exit 3"]).spawn().unwrap();
        let pid = child.id();
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = lines.clone();
        let done = watch_exit(pid, move |l| sink.lock().unwrap().push(l.to_string()));
        assert!(done.is_some());
        wait_logged(&done, 10.0);
        let got = lines.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("0x00000003") && got[0].contains(&pid.to_string()), "{}", got[0]);
        let mut child = child;
        let _ = child.wait();
    }
}
