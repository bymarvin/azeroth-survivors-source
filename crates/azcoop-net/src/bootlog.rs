//! Boot-log style file logger for the helper, one flushed line at a time.
//! No secrets (tokens, invite) are ever passed in by callers.

use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static LOG: OnceLock<Mutex<Option<File>>> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();

pub fn init(path: &str) {
    let _ = START.set(Instant::now());
    let _ = LOG.set(Mutex::new(File::create(path).ok()));
}

fn line(tag: &str, text: &str) {
    let secs = START.get().map_or(0.0, |s| s.elapsed().as_secs_f64());
    let formatted = format!("[{tag}] {secs:>8.3}s {text}\r\n");
    if let Some(lock) = LOG.get() {
        if let Ok(mut guard) = lock.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = file.write_all(formatted.as_bytes());
            }
        }
    }
    // Also to stderr so the launcher can see it live.
    eprint!("{formatted}");
}

pub fn info(text: &str) {
    line(" INFO ", text);
}
pub fn warn(text: &str) {
    line(" WARN ", text);
}
pub fn error(text: &str) {
    line("FAILED", text);
}
