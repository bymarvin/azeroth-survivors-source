//! Azeroth Survivors Together web installer (no admin rights).
//!
//! Installs or updates the co-op game folder from the signed release, without questions:
//! 1. folder: where the installer is. Next to it in "Azeroth Survivors Together"
//!    (so a Downloads folder does not get 1179 loose files); the installer's own
//!    folder if that already is a game folder (Start-Coop.cmd or
//!    package-manifest.json), is named "Azeroth Survivors Together" or holds
//!    nothing else. --dir overrides. An installation is updated (its own updater
//!    exe does that), never overwritten. No write access (e.g. Program Files):
//!    a clear message and stop, never an admin prompt;
//! 2. at least 3 GiB free (downloads + temp);
//! 3. latest.json + latest.json.sig: the Ed25519 signature is checked here
//!    against the keys of the embedded reconstruction/self_update.py;
//! 4. the runtime archive named in it (GitHub; SHA-256 and size checked,
//!    interrupted downloads continue) is unpacked by the built-in ZIP reader (src/unzip.rs);
//! 5. the embedded updater (updater_v2.py on top of self_update.py and
//!    game_patch.py) installs everything else with that runtime: signed paths
//!    only, game files from the signed source list, SHA-256 checks, user areas
//!    untouched, resumable downloads;
//! 6. new installations: desktop and Start menu shortcut "Azeroth Survivors Together"
//!    to Start-Coop.cmd (--no-shortcuts: none); at the end the folder opens in Explorer.
//! Downloads use WinHTTP (src/net.rs: HTTPS only, at most 5 redirects, resumable). No external tool is
//! needed, so it also runs under Wine/Proton (curl.exe and tar.exe do not exist there).
//! Boot-log lines on the console and in <folder>\coop-update\install.log.

mod health;
mod net;
mod runtime;
mod unzip;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Mutex;
use std::time::Instant;

static SELF_UPDATE: &str = include_str!("../../../reconstruction/self_update.py");
static GAME_PATCH: &str = include_str!("../../updater/game_patch.py");
static UPDATER_V2: &str = include_str!("../../updater/updater_v2.py");
const RELEASE_URL: &str = "https://github.com/bymarvin/azeroth-survivors-together/releases/latest/download/";
const PRODUCT: &str = "azeroth-survivors-together";
const UPDATER_VERSION: &str = "4";
const UPDATER_ASSET: &str = "Azeroth-Survivors-Together-Updater.exe";
const NEEDED_SPACE: u64 = 3 << 30;
const RUNTIME_LIMIT: u64 = 512 << 20;
// Test builds only: an additional trusted key for signed test releases.
const TEST_KEY: Option<&str> = option_env!("COOP_INSTALLER_TEST_KEY");
static LOG: Mutex<Option<File>> = Mutex::new(None);

#[link(name = "kernel32")]
extern "system" {
    fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    fn GetDiskFreeSpaceExW(dir: *const u16, free: *mut u64, total: *mut u64, total_free: *mut u64) -> i32;
}

fn log(tag: &str, text: &str) {
    let line = format!("[{:^6}] {}", tag, text);
    println!("{line}");
    let _ = io::stdout().flush();
    if let Some(file) = LOG.lock().unwrap().as_mut() {
        let _ = writeln!(file, "{line}");
    }
}

struct Step(&'static str, Instant);

fn step(name: &'static str) -> Step {
    log(" .... ", name);
    Step(name, Instant::now())
}

impl Step {
    fn ok(self, info: &str) {
        let seconds = self.1.elapsed().as_secs_f64();
        log("  OK  ", &format!("{} ({seconds:.1} s{}{})", self.0, if info.is_empty() { "" } else { ", " }, info));
    }
}

struct Options {
    dir: Option<PathBuf>,
    shortcuts: bool,
    release_url: String,
    allow_local_http: bool,
    no_pause: bool,
    open: bool,
    needed_space: u64,
    shortcut_folder: Option<PathBuf>,
}

fn options() -> Result<Options, String> {
    let mut o = Options { dir: None, shortcuts: true, release_url: RELEASE_URL.into(), allow_local_http: false,
                          no_pause: false, open: true, needed_space: NEEDED_SPACE, shortcut_folder: None };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dir" => o.dir = Some(PathBuf::from(args.next().ok_or("--dir needs a folder")?)),
            "--yes" | "--shortcuts" => {} // Older options: there are no questions any more, shortcuts are the default.
            "--no-shortcuts" => o.shortcuts = false,
            "--no-pause" => o.no_pause = true,
            "--no-open" => o.open = false,
            // Diagnostics/tests, like the updater: another release address, local HTTP, a space limit, a folder
            // for the shortcuts instead of the desktop and Start menu.
            "--release-url" => o.release_url = args.next().ok_or("--release-url needs an address")?,
            "--allow-local-http" => o.allow_local_http = true,
            "--needed-space" => o.needed_space = args.next().and_then(|v| v.parse().ok()).ok_or("--needed-space needs bytes")?,
            "--shortcut-folder" => o.shortcut_folder = Some(PathBuf::from(args.next().ok_or("--shortcut-folder needs a folder")?)),
            "--help" | "-h" => {
                println!("Azeroth Survivors Together installer: installs next to itself, no questions\n  \
                          --dir <folder>   install or update this folder instead\n  \
                          --no-shortcuts   no desktop / Start menu shortcut\n  \
                          --no-open        do not open the folder at the end\n  --no-pause");
                std::process::exit(0);
            }
            other => return Err(format!("unknown option {other} (--help lists them)")),
        }
    }
    if !o.release_url.ends_with('/') {
        o.release_url.push('/');
    }
    Ok(o)
}

/// A double-click gives this process its own console; a terminal shares its one.
fn own_console() -> bool {
    let mut list = [0u32; 4];
    unsafe { GetConsoleProcessList(list.as_mut_ptr(), list.len() as u32) <= 1 }
}

fn finish(code: u8, no_pause: bool) -> ExitCode {
    if own_console() && !no_pause {
        print!("\nPress Enter to close this window . . . ");
        let _ = io::stdout().flush();
        let _ = io::stdin().lock().read_line(&mut String::new());
    }
    ExitCode::from(code)
}

const FOLDER_NAME: &str = "Azeroth Survivors Together";

fn is_game_folder(dir: &Path) -> bool {
    dir.join("Start-Coop.cmd").is_file() || dir.join("package-manifest.json").is_file()
}

/// Where to install without asking: see the top of this file.
fn choose_folder(o: &Options) -> Result<PathBuf, String> {
    if let Some(dir) = &o.dir {
        return Ok(if dir.is_absolute() { dir.clone() } else { env::current_dir().map_err(|e| e.to_string())?.join(dir) });
    }
    let exe = env::current_exe().map_err(|e| format!("cannot find the installer's own folder: {e}"))?;
    let here = exe.parent().ok_or("the installer has no folder")?.to_path_buf();
    let alone = fs::read_dir(&here).map(|entries| entries.filter_map(Result::ok)
        .all(|e| e.path() == exe || e.file_name() == "coop-update")).unwrap_or(false);
    let named = here.file_name().is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(FOLDER_NAME));
    Ok(if is_game_folder(&here) || named || alone { here } else { here.join(FOLDER_NAME) })
}

/// Create the folder and prove that files can be written there (Program Files needs admin rights: stop instead).
fn check_writable(dir: &Path) -> Result<(), String> {
    let refuse = |e: io::Error| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            format!("No write access to {} (folders like Program Files need admin rights). Nothing was installed. \
                     Move the installer to a folder of your own, e.g. Downloads, Documents or D:\\Games, and start it again.",
                    dir.display())
        } else {
            format!("cannot write to {}: {e}. Nothing was installed.", dir.display())
        }
    };
    fs::create_dir_all(dir.join("coop-update")).map_err(refuse)?;
    let probe = dir.join("coop-update").join("write-test.tmp");
    fs::write(&probe, b"ok").map_err(refuse)?;
    fs::remove_file(&probe).map_err(refuse)
}

fn system32(tool: &str) -> PathBuf {
    let root = env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    Path::new(&root).join("System32").join(tool)
}

fn free_space(dir: &Path) -> Option<u64> {
    let wide: Vec<u16> = dir.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, &mut total_free) };
    (ok != 0).then_some(free)
}

/// Download through WinHTTP (also under Wine/Proton, where curl.exe does not exist): HTTPS only (unless
/// --allow-local-http), at most 5 redirects, resumable, at most `limit` bytes.
fn download(o: &Options, url: &str, target: &Path, resume: bool, limit: u64) -> Result<(), String> {
    net::download(url, target, resume, o.allow_local_http, limit)
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The release keys of the embedded self_update.py (one source of truth), plus a test key in test builds.
fn trusted_keys() -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(start) = SELF_UPDATE.find("TRUSTED_KEYS = (") {
        let rest = &SELF_UPDATE[start + 16..];
        let end = rest.find(')').unwrap_or(0);
        keys.extend(rest[..end].split('\'').skip(1).step_by(2).map(str::to_string));
    }
    keys.extend(TEST_KEY.map(str::to_string));
    keys
}

fn verify(data: &[u8], signature: &[u8]) -> Option<String> {
    let signature = Signature::from_slice(signature).ok()?;
    trusted_keys().into_iter().find(|key| {
        base64::engine::general_purpose::STANDARD.decode(key).ok()
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
            .and_then(|raw| VerifyingKey::from_bytes(&raw).ok())
            .is_some_and(|k| k.verify(data, &signature).is_ok())
    })
}

fn safe_asset(name: &str) -> bool {
    !name.is_empty() && name.len() <= 200 && !name.contains("..")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

fn is_installation(dir: &Path) -> bool {
    dir.join("package-manifest.json").is_file() && dir.join(".coop-runtime").join("python.exe").is_file()
}

/// Run the embedded updater with the folder's runtime (or a copy of it, like the updater exe).
fn run_updater(o: &Options, dir: &Path) -> Result<i32, String> {
    let work = dir.join("coop-update");
    fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    for (name, text) in [("self_update.py", SELF_UPDATE), ("game_patch.py", GAME_PATCH), ("updater_v2.py", UPDATER_V2)] {
        fs::write(work.join(name), text).map_err(|e| format!("cannot write {name}: {e}"))?;
    }
    let run = |python: &Path, runtime_free: bool| -> Result<i32, String> {
        let mut command = Command::new(python);
        command.args(["-I", "-B"]).arg(work.join("updater_v2.py"))
            .args(["--updater-version", UPDATER_VERSION, "--game"]).arg(dir)
            .args(["--release-url", &o.release_url]).current_dir(dir);
        if o.allow_local_http {
            command.arg("--allow-local-http");
        }
        if runtime_free {
            command.arg("--runtime-free");
        }
        if let Some(key) = TEST_KEY {
            command.args(["--extra-trusted-key", key]);
        }
        Ok(command.status().map_err(|e| format!("cannot start the co-op Python: {e}"))?.code().unwrap_or(1))
    };
    let mut code = run(&dir.join(".coop-runtime").join("python.exe"), false)?;
    if code == 5 {
        // The release changes the runtime this Python runs from: the script copied it, run from the copy.
        let copy = work.join("runtime");
        code = run(&copy.join("python.exe"), true)?;
        for _ in 0..20 {
            if fs::remove_dir_all(&copy).is_ok() || !copy.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    Ok(code)
}

#[repr(C)]
struct Guid(u32, u16, u16, [u8; 8]);
const FOLDERID_DESKTOP: Guid = Guid(0xB4BFCC3A, 0xDB2C, 0x424C, [0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41]);
const FOLDERID_PROGRAMS: Guid = Guid(0xA77F5D77, 0x2E2B, 0x44C3, [0xA6, 0xA2, 0xAB, 0xA6, 0x01, 0x05, 0x4A, 0x51]);

#[link(name = "shell32")]
extern "system" {
    fn SHGetKnownFolderPath(id: *const Guid, flags: u32, token: *mut std::ffi::c_void, path: *mut *mut u16) -> i32;
}
#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(memory: *mut std::ffi::c_void);
}

/// The user's real Desktop / Start menu Programs folder (also when redirected, e.g. to OneDrive).
fn known_folder(id: &Guid) -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;
    let mut raw: *mut u16 = std::ptr::null_mut();
    let result = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut raw) };
    let path = if result == 0 && !raw.is_null() {
        let length = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        Ok(PathBuf::from(std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(raw, length) })))
    } else {
        Err(format!("SHGetKnownFolderPath failed ({result:#x})"))
    };
    unsafe { CoTaskMemFree(raw.cast()) };
    path
}

/// Where the two shortcuts go: the known folders, or <folder>\Desktop and \Programs (--shortcut-folder, tests).
fn shortcut_paths(test_folder: Option<&Path>) -> Result<[PathBuf; 2], String> {
    let (desktop, programs) = match test_folder {
        Some(t) => (t.join("Desktop"), t.join("Programs")),
        None => (known_folder(&FOLDERID_DESKTOP)?, known_folder(&FOLDERID_PROGRAMS)?),
    };
    Ok([desktop.join("Azeroth Survivors Together.lnk"), programs.join("Azeroth Survivors Together.lnk")])
}

/// PowerShell gets finished paths as single-quoted literals ('' for a quote inside), nothing to evaluate.
fn shortcut_script(dir: &Path, links: &[PathBuf; 2]) -> String {
    let quote = |p: &Path| format!("'{}'", p.display().to_string().replace('\'', "''"));
    format!("$w = New-Object -ComObject WScript.Shell; \
             foreach ($p in @({}, {})) {{ $s = $w.CreateShortcut($p); $s.TargetPath = {}; \
             $s.WorkingDirectory = {}; $s.IconLocation = {}; \
             $s.Description = 'Azeroth Survivors Together co-op'; $s.Save() }}",
            quote(&links[0]), quote(&links[1]), quote(&dir.join("Start-Coop.cmd")), quote(dir),
            quote(Path::new(&format!("{},0", dir.join("AzerothSurvivors.exe").display()))))
}

fn shortcuts(dir: &Path, test_folder: Option<&Path>) -> Result<(), String> {
    let links = shortcut_paths(test_folder)?;
    let status = Command::new(system32(r"WindowsPowerShell\v1.0\powershell.exe"))
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &shortcut_script(dir, &links)])
        .status().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("PowerShell exit {:?}", status.code()));
    }
    match links.iter().find(|link| !link.is_file()) {
        Some(missing) => Err(format!("{} was not created", missing.display())),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_folders_exist() {
        for id in [&FOLDERID_DESKTOP, &FOLDERID_PROGRAMS] {
            let folder = known_folder(id).expect("known folder");
            assert!(folder.is_absolute() && folder.is_dir(), "{}", folder.display());
        }
        let links = shortcut_paths(None).unwrap();
        assert!(links.iter().all(|l| l.file_name().unwrap() == "Azeroth Survivors Together.lnk"));
    }

    #[test]
    fn script_quotes_paths_and_evaluates_nothing() {
        let dir = Path::new(r"D:\Games\O'Brien's Azeroth");
        let links = [PathBuf::from(r"C:\Users\x\Desktop\Azeroth Survivors Together.lnk"),
                     PathBuf::from(r"C:\Users\x\Programs\Azeroth Survivors Together.lnk")];
        let script = shortcut_script(dir, &links);
        assert!(script.contains(r"'D:\Games\O''Brien''s Azeroth\Start-Coop.cmd'"), "{script}");
        assert!(!script.contains("Join-Path") && !script.contains("[Environment]"), "{script}");
    }

    #[test]
    fn shortcuts_are_created_with_the_real_powershell_line() {
        let base = env::temp_dir().join(format!("azs-shortcut-test-{}", std::process::id()));
        let game = base.join("O'Brien game");
        for sub in ["Desktop", "Programs"] {
            fs::create_dir_all(base.join(sub)).unwrap();
        }
        fs::create_dir_all(&game).unwrap();
        shortcuts(&game, Some(&base)).expect("shortcuts");
        assert!(base.join("Desktop").join("Azeroth Survivors Together.lnk").is_file());
        assert!(base.join("Programs").join("Azeroth Survivors Together.lnk").is_file());
        let _ = fs::remove_dir_all(&base);
    }
}

const RELOCATED: &str = "COOP_INSTALLER_RELOCATED";

/// The updater refuses a folder that a program still runs from, the installer included. Inside the target folder
/// it therefore continues from a copy in %TEMP% (same console and options, --dir set) and this process ends.
fn relocate(dir: &Path) -> Result<bool, String> {
    let temp = env::temp_dir();
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    if let Ok(entries) = fs::read_dir(&temp) {
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("azsurvivors-installer-") && name.ends_with(".exe") && entry.path() != exe {
                let _ = fs::remove_file(entry.path()); // Copies of earlier runs; one still running stays.
            }
        }
    }
    let inside = fs::canonicalize(&exe).ok().zip(fs::canonicalize(dir).ok()).is_some_and(|(e, d)| e.starts_with(d));
    if !inside || env::var_os(RELOCATED).is_some() {
        return Ok(false);
    }
    let copy = temp.join(format!("azsurvivors-installer-{}.exe", std::process::id()));
    fs::copy(&exe, &copy).map_err(|e| format!("cannot copy the installer to {}: {e}", temp.display()))?;
    Command::new(&copy).args(env::args_os().skip(1)).arg("--dir").arg(dir).env(RELOCATED, "1").spawn()
        .map_err(|e| format!("cannot start the installer copy: {e}"))?;
    Ok(true)
}

fn install(o: &Options) -> Result<(), String> {
    let dir = choose_folder(o)?;
    if relocate(&dir)? {
        return Err(String::from(RELOCATED));
    }
    let existing = is_installation(&dir);
    log(" INFO ", &format!("Folder {} ({})", dir.display(),
                           if existing { "existing installation: update" } else { "new installation" }));
    // A damaged runtime (a quarantined package or DLL) stops every Python step, the installed updater's too:
    // the runtime is restored from the signed release and the embedded updater installs the rest.
    let damaged = if existing { health::runtime_problem(&dir.join(".coop-runtime").join("python.exe")) } else { None };
    if let Some(problem) = &damaged {
        log(" WARN ", &format!("The co-op runtime is damaged ({problem}); it is restored from the signed release"));
    }
    let s = step("Write access");
    check_writable(&dir)?;
    s.ok("");
    *LOG.lock().unwrap() = OpenOptions::new().create(true).append(true).open(dir.join("coop-update").join("install.log")).ok();

    if !existing {
        let s = step("Free disk space");
        let free = free_space(&dir).ok_or("cannot read the free disk space")?;
        if free < o.needed_space {
            return Err(format!("{:.1} GiB free on that drive, {:.1} GiB needed. Nothing was installed. Free some space \
                                or move the installer to another drive and start it again.",
                               free as f64 / (1u64 << 30) as f64, o.needed_space as f64 / (1u64 << 30) as f64));
        }
        s.ok(&format!("{:.1} GiB free", free as f64 / (1u64 << 30) as f64));
    } else if damaged.is_none() && dir.join(UPDATER_ASSET).is_file() {
        // An installation updates itself with its own updater exe (self-update, runtime copy, rollback).
        let s = step("Update with the installed updater");
        let mut command = Command::new(dir.join(UPDATER_ASSET));
        command.arg("--no-pause").args(["--release-url", &o.release_url]).current_dir(&dir);
        if o.allow_local_http {
            command.arg("--allow-local-http");
        }
        let status = command.status().map_err(|e| format!("cannot start {UPDATER_ASSET}: {e}"))?;
        if !status.success() {
            return Err(format!("the update failed (exit {:?}); the folder keeps its previous version", status.code()));
        }
        s.ok("done");
        return done(o, &dir, false);
    }

    let work = dir.join("coop-update").join("install");
    fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let s = step("Read signed release description");
    download(o, &format!("{}latest.json", o.release_url), &work.join("latest.json"), false, 256 << 10)?;
    download(o, &format!("{}latest.json.sig", o.release_url), &work.join("latest.json.sig"), false, 4096)?;
    let data = fs::read(work.join("latest.json")).map_err(|e| e.to_string())?;
    let signature = fs::read(work.join("latest.json.sig")).map_err(|e| e.to_string())?;
    if data.len() > 256 << 10 {
        return Err("latest.json is larger than allowed".into());
    }
    let key = verify(&data, &signature).ok_or("the release description is not signed by a trusted key; nothing was installed")?;
    let latest: serde_json::Value = serde_json::from_slice(&data).map_err(|e| format!("latest.json: {e}"))?;
    if latest["format"] != 1 || latest["product"] != PRODUCT {
        return Err("latest.json is not an Azeroth Survivors Together release description".into());
    }
    let version = latest["version"].as_str().unwrap_or("?").to_string();
    s.ok(&format!("co-op {version}, signed by {}...", &key[..12]));

    if !dir.join(".coop-runtime").join("python.exe").is_file() || damaged.is_some() {
        let runtime = &latest["archives"]["runtime"];
        let (asset, digest, size) = (runtime["asset"].as_str().unwrap_or(""), runtime["sha256"].as_str().unwrap_or(""),
                                     runtime["size"].as_u64().unwrap_or(0));
        if !safe_asset(asset) || digest.len() != 64 || size == 0 || size > RUNTIME_LIMIT {
            return Err("latest.json lists an invalid runtime archive".into());
        }
        let s = step("Download the co-op runtime");
        let archive = work.join(asset);
        if !(archive.is_file() && sha256_file(&archive).ok().as_deref() == Some(digest)) {
            download(o, &format!("{}{asset}", o.release_url), &archive, true, size)?;
        }
        let got = fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
        if got != size || sha256_file(&archive).map_err(|e| e.to_string())? != digest {
            let _ = fs::remove_file(&archive);
            return Err(format!("{asset} does not match its signed size/SHA-256 (removed); run the installer again"));
        }
        s.ok(&format!("{:.1} MiB, SHA-256 matches the release", size as f64 / (1u64 << 20) as f64));
        let s = step("Unpack the co-op runtime");
        // Own ZIP reader (no tar.exe under Wine/Proton); the archive's SHA-256 was checked above. Unpacked into a
        // staging folder first, then one rename per folder: a damaged runtime is replaced whole, never half.
        let stage = work.join("runtime-stage");
        let _ = fs::remove_dir_all(&stage);
        fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
        unzip::extract(&archive, &stage, 4 << 30).map_err(|e| format!("unpacking the runtime failed: {e}"))?;
        let (files, warnings) = runtime::install(&stage, &dir, &work.join("replaced"))?;
        let _ = fs::remove_dir_all(&stage);
        for warning in warnings {
            log(" WARN ", &warning);
        }
        if !dir.join(".coop-runtime").join("python.exe").is_file() {
            return Err("unpacking the runtime failed: no .coop-runtime/python.exe".into());
        }
        if let Some(problem) = health::runtime_problem(&dir.join(".coop-runtime").join("python.exe")) {
            return Err(format!("the co-op runtime still does not work after unpacking ({problem}); security software                                 may be removing its files: allow the game folder and run the installer again"));
        }
        s.ok(&format!("{files} files"));
    }

    log(" INFO ", "Installing all files with the co-op updater (signed paths, SHA-256 checks)");
    let code = run_updater(o, &dir)?;
    if code != 0 {
        return Err(format!("the installation stopped (updater exit {code}); run the installer again to continue"));
    }
    done(o, &dir, true)
}

/// Shortcuts for a new installation (an update leaves the user's shortcuts alone), the folder in Explorer.
fn done(o: &Options, dir: &Path, new: bool) -> Result<(), String> {
    if new && o.shortcuts {
        let s = step("Shortcuts");
        match shortcuts(dir, o.shortcut_folder.as_deref()) {
            Ok(()) => s.ok("desktop and Start menu: Azeroth Survivors Together"),
            Err(error) => log(" WARN ", &format!("Shortcuts: {error} (start Start-Coop.cmd in the folder instead)")),
        }
    }
    log("  OK  ", &format!("Done - start Start-Coop.cmd (folder {}).", dir.display()));
    if o.open && own_console() {
        let _ = Command::new(env::var("SystemRoot").map(|r| Path::new(&r).join("explorer.exe"))
                             .unwrap_or_else(|_| PathBuf::from("explorer.exe"))).arg(dir).spawn();
    }
    Ok(())
}

fn main() -> ExitCode {
    let o = match options() {
        Ok(o) => o,
        Err(error) => {
            log("FAILED", &error);
            return finish(2, false);
        }
    };
    log(" INFO ", "Azeroth Survivors Together installer (no admin rights needed)");
    match install(&o) {
        Ok(()) => finish(0, o.no_pause),
        Err(error) if error == RELOCATED => ExitCode::SUCCESS, // The copy in %TEMP% carries on in this console.
        Err(error) => {
            log("FAILED", &error);
            finish(2, o.no_pause)
        }
    }
}
