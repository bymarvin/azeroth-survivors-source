//! Boot-log style file log in the game folder, written line by line.
//!
//! Every line is written with one `write_all` on an unbuffered file, so a
//! crash or a killed process never loses a finished line.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

/// `x.log` -> `x.1.log` -> ... -> `x.<keep>.log`; the oldest is dropped. Failures are ignored (the log then simply starts over).
pub fn rotate(path: &Path, keep: usize) {
    let numbered = |n: usize| -> std::path::PathBuf {
        let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let name = match path.extension() {
            Some(extension) => format!("{stem}.{n}.{}", extension.to_string_lossy()),
            None => format!("{stem}.{n}"),
        };
        path.with_file_name(name)
    };
    if keep == 0 || !path.exists() {
        return;
    }
    let _ = std::fs::remove_file(numbered(keep));
    for n in (1..keep).rev() {
        let _ = std::fs::rename(numbered(n), numbered(n + 1));
    }
    let _ = std::fs::rename(path, numbered(1));
}

pub struct Log {
    file: Mutex<Option<File>>,
    start: Instant,
}

impl Log {
    pub fn open(path: &Path) -> Log {
        Log { file: Mutex::new(File::create(path).ok()), start: Instant::now() }
    }

    /// Like [`Log::open`], but the log of the previous start is kept: `x.log` becomes `x.1.log`, `x.1.log` becomes `x.2.log`, and so on up
    /// to `keep` older logs (a player who tests several rounds in a row would otherwise lose every log but the last one).
    pub fn open_rotating(path: &Path, keep: usize) -> Log {
        rotate(path, keep);
        Log::open(path)
    }

    fn line(&self, label: &str, text: &str) {
        let line = format!("[{label}] {:>8.3}s {text}\r\n", self.start.elapsed().as_secs_f64());
        if let Ok(mut file) = self.file.lock() {
            if let Some(file) = file.as_mut() {
                let _ = file.write_all(line.as_bytes());
            }
        }
    }

    /// For a crash handler: write the line only if the log is not busy (never wait for a lock the faulting thread may hold).
    pub fn try_info(&self, text: &str) {
        let line = format!("[ INFO ] {:>8.3}s {text}
", self.start.elapsed().as_secs_f64());
        if let Ok(mut file) = self.file.try_lock() {
            if let Some(file) = file.as_mut() {
                let _ = file.write_all(line.as_bytes());
            }
        }
    }

    pub fn begin(&self, step: &str) -> Instant {
        self.line(" .... ", step);
        Instant::now()
    }
    pub fn ok(&self, step: &str, started: Instant, metric: &str) {
        let ms = started.elapsed().as_secs_f64() * 1000.0;
        self.line("  OK  ", &format!("{step} ({ms:.1} ms, {metric})"));
    }
    pub fn failed(&self, step: &str, reason: &str) {
        self.line("FAILED", &format!("{step}: {reason}"));
    }
    pub fn info(&self, text: &str) {
        self.line(" INFO ", text);
    }
    pub fn warn(&self, text: &str) {
        self.line(" WARN ", text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("azcoop-log-rotate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_logs_of_earlier_starts_are_kept_up_to_the_limit() {
        let dir = folder("keep");
        let path = dir.join("azeroth-coop-native-p2.log");
        for round in 1..=5 {
            let log = Log::open_rotating(&path, 3);
            log.info(&format!("start {round}"));
        }
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        assert!(read("azeroth-coop-native-p2.log").contains("start 5"));
        assert!(read("azeroth-coop-native-p2.1.log").contains("start 4"));
        assert!(read("azeroth-coop-native-p2.2.log").contains("start 3"));
        assert!(read("azeroth-coop-native-p2.3.log").contains("start 2"));
        assert!(!dir.join("azeroth-coop-native-p2.4.log").exists(), "only three older logs are kept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_first_start_and_a_zero_limit_work() {
        let dir = folder("first");
        let path = dir.join("x.log");
        rotate(&path, 3); // nothing there: nothing happens
        let log = Log::open_rotating(&path, 0);
        log.info("only");
        drop(log);
        assert!(path.exists() && !dir.join("x.1.log").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
