//! Azeroth Survivors Together co-op updater (online, self-updating).
//!
//! Put it into the game folder (next to Start-Coop.cmd) and double-click it.
//! It runs the embedded updater_v2.py (on top of reconstruction/self_update.py,
//! with game_patch.py) with the game folder's own .coop-runtime Python: signed
//! release description from GitHub, only changed files downloaded (game files
//! as binary patches), backup, verification, rollback.
//! When a release needs a newer updater, self_update.py leaves the verified
//! new exe next to this one (<name>.new) and exits with 3; this exe renames
//! itself to <name>.old, puts the new one in its place and starts it.
//! When a release changes .coop-runtime (locked while its python.exe runs),
//! self_update.py copies the runtime to coop-update/runtime and exits with 5;
//! this exe runs it again from the copy and removes the copy afterwards.

use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

// WinHTTP download and ZIP reader of the installer (one source): the repair of a folder without the co-op
// Python runtime cannot use Python.
#[path = "../../../installer/src/net.rs"]
#[allow(dead_code)]
mod net;
#[path = "../../../installer/src/unzip.rs"]
#[allow(dead_code)]
mod unzip;
#[path = "../../../installer/src/health.rs"]
mod health;
mod repair;
#[path = "../../../installer/src/runtime.rs"]
mod runtime;

static SELF_UPDATE: &str = include_str!("../../../../reconstruction/self_update.py");
// Updater 2: game file patches. self_update.py stays the bound game folder copy;
// updater_v2.py extends it and is the script this exe runs.
static GAME_PATCH: &str = include_str!("../../game_patch.py");
static UPDATER_V2: &str = include_str!("../../updater_v2.py");
const UPDATER_VERSION: &str = match option_env!("COOP_UPDATER_VERSION") {
    Some(version) => version,
    // 5: repairs a folder without .coop-runtime / package-manifest.json (release 0.0.22).
    // 6: also a damaged runtime (python.exe there, a package or DLL missing) and the real runtime archive with
    //    .coop-runtime and .tools (release 0.0.23).
    // 7: optional co-op channels (0.99.0 DLL beta) below the co-op folder, with the server switch (release 0.0.24).
    None => "7",
};
// Test builds only: an additional trusted key for signed test releases.
const TEST_KEY: Option<&str> = option_env!("COOP_UPDATER_TEST_KEY");
const SELF_UPDATE_READY: i32 = 3;
const RUNTIME_BUSY: i32 = 5;
const RUNTIME_COPY: &str = "runtime";
const REPLACED_PID: &str = "COOP_UPDATER_REPLACED_PID";

#[link(name = "kernel32")]
extern "system" {
    fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
}

fn log(tag: &str, text: &str) {
    println!("[{:^6}] {}", tag, text);
    let _ = io::stdout().flush();
}

/// A double-click gives this process its own console; a terminal shares its one.
fn own_console() -> bool {
    let mut list = [0u32; 4];
    unsafe { GetConsoleProcessList(list.as_mut_ptr(), list.len() as u32) <= 1 }
}

fn finish(code: i32) -> ExitCode {
    if own_console() && !env::args().any(|a| a == "--no-pause") {
        println!();
        print!("Press Enter to close this window . . . ");
        let _ = io::stdout().flush();
        let _ = io::stdin().lock().read_line(&mut String::new());
    }
    ExitCode::from(code.clamp(0, 255) as u8)
}

fn python(folder: &Path) -> PathBuf {
    folder.join(".coop-runtime").join("python.exe")
}

/// The folders to look at: placed into the game folder, or into a subfolder of it.
fn candidates(exe: &Path) -> Vec<PathBuf> {
    let Some(here) = exe.parent() else { return Vec::new() };
    [Some(here.to_path_buf()), here.parent().map(Path::to_path_buf)].into_iter().flatten().collect()
}

/// The game folder to update. An old or damaged one (no runtime and/or manifest) is repaired first.
fn find_root(exe: &Path) -> Option<PathBuf> {
    match repair::classify(&candidates(exe)) {
        repair::Verdict::Complete(root) => Some(root),
        repair::Verdict::Repair(probe) => {
            let args: Vec<String> = env::args().skip(1).collect();
            if let Err(error) = repair::repair(&probe, &repair::options(&args)) {
                log("FAILED", &format!("Repair of {}: {error}", probe.folder.display()));
                log(" INFO ", "Nothing else was changed. Run the updater again when the problem is solved.");
                return None;
            }
            Some(probe.folder)
        }
        repair::Verdict::NotFound(probes) => {
            log("FAILED", "This is not an Azeroth Survivors Together co-op folder.");
            for line in repair::not_found_lines(&probes) {
                log(" INFO ", &line);
            }
            None
        }
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn run_script(interpreter: &Path, script: &Path, exe: &Path, root: &Path, runtime_free: bool) -> io::Result<i32> {
    let mut command = Command::new(interpreter);
    command
        .args(["-I", "-B"])
        .arg(script)
        .args(["--updater-version", UPDATER_VERSION, "--updater-exe"])
        .arg(exe)
        .args(["--game"])
        .arg(root)
        .current_dir(root);
    if runtime_free {
        command.arg("--runtime-free");
    }
    if let Ok(pid) = env::var(REPLACED_PID) {
        command.args(["--ignore-pid", &pid]);
    }
    if let Some(key) = TEST_KEY {
        command.args(["--extra-trusted-key", key]);
    }
    // Pass through options for diagnostics (for example --release-url of a test server).
    command.args(env::args().skip(1).filter(|a| a != "--no-pause"));
    Ok(command.status()?.code().unwrap_or(1))
}

/// Windows releases the files of an ended process with a short delay.
fn remove_copy(copy: &Path) {
    for _ in 0..20 {
        if fs::remove_dir_all(copy).is_ok() || !copy.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    log(" WARN ", &format!("Could not remove {}; it is removed on the next start", copy.display()));
}

fn main() -> ExitCode {
    let exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            log("FAILED", &format!("Cannot find the updater itself: {error}"));
            return finish(2);
        }
    };
    let _ = fs::remove_file(with_suffix(&exe, ".old")); // Left by the last self-update.
    let Some(root) = find_root(&exe) else {
        return finish(2);
    };
    // python.exe alone proves nothing: a quarantined package or DLL stops every Python step (the signature check
    // too) with ModuleNotFoundError. Restore the runtime from the signed release first.
    if let Some(problem) = health::runtime_problem(&python(&root)) {
        log(" WARN ", &format!("The co-op runtime is damaged ({problem}); it is restored from the signed release"));
        let args: Vec<String> = env::args().skip(1).collect();
        if let Err(error) = repair::fetch_runtime(&root, &repair::options(&args)) {
            log("FAILED", &format!("Repair of the co-op runtime: {error}"));
            return finish(2);
        }
        if let Some(problem) = health::runtime_problem(&python(&root)) {
            log("FAILED", &format!("The co-op runtime still does not work after the repair ({problem}).                                     Security software may be removing its files: allow the game folder and run the updater again."));
            return finish(2);
        }
        log("  OK  ", "Co-op runtime restored");
    }
    let folder = root.join("coop-update");
    let script = folder.join("updater_v2.py");
    let prepared = fs::create_dir_all(&folder)
        .and_then(|_| fs::write(folder.join("self_update.py"), SELF_UPDATE))
        .and_then(|_| fs::write(folder.join("game_patch.py"), GAME_PATCH))
        .and_then(|_| fs::write(&script, UPDATER_V2));
    if let Err(error) = prepared {
        log("FAILED", &format!("Cannot prepare the updater: {error}. Nothing was changed."));
        return finish(2);
    }
    let copy = root.join("coop-update").join(RUNTIME_COPY);
    let _ = fs::remove_dir_all(&copy); // Left by an interrupted run.
    let mut code = match run_script(&python(&root), &script, &exe, &root, false) {
        Ok(code) => code,
        Err(error) => {
            log("FAILED", &format!("Could not start the co-op Python: {error}. Nothing was changed."));
            return finish(2);
        }
    };
    if code == RUNTIME_BUSY {
        // The release replaces .coop-runtime: Windows locks python.exe and its DLLs while they run,
        // so the script copied the runtime and runs again from the copy.
        log(" INFO ", "Running the updater from a copy of the co-op Python runtime");
        code = match run_script(&copy.join("python.exe"), &script, &exe, &root, true) {
            Ok(code) => code,
            Err(error) => {
                log("FAILED", &format!("Could not start the runtime copy: {error}. Nothing was changed."));
                2
            }
        };
        remove_copy(&copy);
    }
    if code != SELF_UPDATE_READY {
        return finish(code);
    }
    // Windows lets a running exe be renamed, not overwritten.
    let new = with_suffix(&exe, ".new");
    let old = with_suffix(&exe, ".old");
    if let Err(error) = fs::rename(&exe, &old).and_then(|_| fs::rename(&new, &exe)) {
        let _ = fs::rename(&old, &exe);
        log("FAILED", &format!("Could not replace the updater: {error}. Nothing was changed."));
        return finish(2);
    }
    log(" INFO ", "Starting the new updater");
    let status = Command::new(&exe)
        .args(env::args().skip(1))
        .arg("--no-pause")
        .env(REPLACED_PID, std::process::id().to_string())
        .current_dir(&root)
        .status();
    finish(status.ok().and_then(|s| s.code()).unwrap_or(1))
}
