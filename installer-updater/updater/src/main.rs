//! Azeroth Survivors Together co-op updater as one file.
//!
//! Put it into the game folder (next to Start-Coop.cmd) and double-click it.
//! It carries the update zip, extracts it with the game folder's own
//! .coop-runtime Python and runs the same coop-update/update.py as
//! Update-Coop.cmd: version check, backup, install, hash check, rollback.
//! The window stays open only when it was started by double-click.

use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

static PACKAGE: &[u8] = include_bytes!(env!("COOP_UPDATE_ZIP"));

// Extracts the embedded zip into the game folder (as a manual extraction
// would), removes it, then runs the updater exactly like Update-Coop.cmd.
const BOOTSTRAP: &str = r#"
import os, runpy, sys, zipfile
root, package = sys.argv[1], sys.argv[2]
try:
    with zipfile.ZipFile(package) as archive:
        for name in archive.namelist():
            target = os.path.realpath(os.path.join(root, name))
            if not target.startswith(os.path.realpath(root) + os.sep):
                raise ValueError('unexpected path in update: ' + name)
        archive.extractall(root)
finally:
    os.remove(package)
script = os.path.join(root, 'coop-update', 'update.py')
sys.argv = [script]
runpy.run_path(script, run_name='__main__')
"#;

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

fn finish(code: u8) -> ExitCode {
    if own_console() && !env::args().any(|a| a == "--no-pause") {
        println!();
        print!("Press Enter to close this window . . . ");
        let _ = io::stdout().flush();
        let _ = io::stdin().lock().read_line(&mut String::new());
    }
    ExitCode::from(code)
}

fn game_folder() -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    let here = exe.parent()?.to_path_buf();
    // Placed into the game folder, or into a subfolder of it.
    [here.clone(), here.parent()?.to_path_buf()]
        .into_iter()
        .find(|folder| python(folder).is_file() && folder.join("package-manifest.json").is_file())
}

fn python(folder: &Path) -> PathBuf {
    folder.join(".coop-runtime").join("python.exe")
}

fn main() -> ExitCode {
    let Some(root) = game_folder() else {
        log("FAILED", "This is not an Azeroth Survivors Together co-op folder.");
        log(" INFO ", "Put this file into your game folder (where Start-Coop.cmd is) and run it there.");
        return finish(2);
    };
    let package = root.join(format!("coop-update-{}.zip", std::process::id()));
    log(" .... ", "Unpack update");
    if let Err(error) = fs::write(&package, PACKAGE) {
        log("FAILED", &format!("Unpack update: {error}. Nothing was changed."));
        return finish(2);
    }
    log("  OK  ", &format!("Unpack update ({} MiB)", PACKAGE.len() >> 20));
    let status = Command::new(python(&root))
        .args(["-I", "-B", "-c", BOOTSTRAP])
        .arg(&root)
        .arg(&package)
        .current_dir(&root)
        .status();
    let _ = fs::remove_file(&package);
    match status {
        Ok(status) => finish(status.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(error) => {
            log("FAILED", &format!("Could not start the co-op Python: {error}. Nothing was changed."));
            finish(2)
        }
    }
}
