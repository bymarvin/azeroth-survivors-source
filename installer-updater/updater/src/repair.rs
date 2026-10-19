//! Repair of an old or damaged co-op folder, in Rust: no Python is needed (and none may be there).
//!
//! The updater used to stop at "This is not an Azeroth Survivors Together co-op folder" when .coop-runtime
//! (python.exe) or package-manifest.json was missing, for example after an old installation or after a copy
//! that dropped the hidden dot folder. A folder with AzerothSurvivors.exe and Start-Coop.cmd (or the
//! reconstruction folder) is a co-op game folder that can be repaired:
//! 1. latest.json + latest.json.sig are fetched and the Ed25519 signature is checked against the release keys
//!    of the embedded self_update.py (the same check as the installer and the Python updater);
//! 2. a missing runtime comes from the signed release: SHA-256 and size are checked, the built-in ZIP reader
//!    unpacks it (no tar.exe under Wine/Proton) into a staging folder first, so that only `.coop-runtime`
//!    can reach the game folder;
//! 3. everything else, including a missing package-manifest.json, is done by the normal updater run that
//!    follows (updater_v2.py compares every file with the signed manifest and installs what differs).
//! Player data (coop-lab/personal, coop-region.txt, characters*.txt) is never touched: nothing here writes
//! outside .coop-runtime and coop-update.
//! Downloads use WinHTTP (shared with the installer: HTTPS only, resumable, at most 5 redirects).

use super::{log, net, runtime, unzip, SELF_UPDATE, TEST_KEY};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const RELEASE_URL: &str = "https://github.com/bymarvin/azeroth-survivors-together/releases/latest/download/";
const PRODUCT: &str = "azeroth-survivors-together";
const RUNTIME_LIMIT: u64 = 512 << 20;
const UNPACKED_LIMIT: u64 = 4 << 30;
const LATEST_LIMIT: u64 = 256 << 10;

#[link(name = "kernel32")]
extern "system" {
    fn GetDiskFreeSpaceExW(dir: *const u16, free: *mut u64, total: *mut u64, total_free: *mut u64) -> i32;
}

/// What one candidate folder contains.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub folder: PathBuf,
    pub exe: bool,
    pub start: bool,
    pub reconstruction: bool,
    pub runtime: bool,
    pub manifest: bool,
}

/// The real name of `name` inside `folder`, also when only the capitalisation differs (a case-sensitive Linux file
/// system below Wine, or a copy that changed names).
fn find_entry(folder: &Path, name: &str) -> Option<PathBuf> {
    let exact = folder.join(name);
    if exact.exists() {
        return Some(exact);
    }
    fs::read_dir(folder).ok()?.filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(name)).map(|e| e.path())
}

fn has_file(folder: &Path, name: &str) -> bool {
    find_entry(folder, name).is_some_and(|p| p.is_file())
}

fn has_dir(folder: &Path, name: &str) -> bool {
    find_entry(folder, name).is_some_and(|p| p.is_dir())
}

impl Probe {
    pub fn of(folder: &Path) -> Probe {
        Probe {
            folder: folder.to_path_buf(),
            exe: has_file(folder, "AzerothSurvivors.exe"),
            start: has_file(folder, "Start-Coop.cmd"),
            reconstruction: has_dir(folder, "reconstruction"),
            runtime: find_entry(folder, ".coop-runtime").is_some_and(|d| has_file(&d, "python.exe")),
            manifest: has_file(folder, "package-manifest.json"),
        }
    }

    /// Runtime and manifest are there: the normal updater run works.
    pub fn complete(&self) -> bool {
        self.runtime && self.manifest
    }

    /// A co-op game folder, whatever is missing: the game exe and its co-op launcher or sources.
    pub fn game(&self) -> bool {
        self.exe && (self.start || self.reconstruction)
    }

    fn markers(&self) -> [(&'static str, bool); 5] {
        [("AzerothSurvivors.exe", self.exe), ("Start-Coop.cmd", self.start), ("reconstruction", self.reconstruction),
         (".coop-runtime/python.exe", self.runtime), ("package-manifest.json", self.manifest)]
    }

    pub fn found(&self) -> Vec<&'static str> {
        self.markers().iter().filter(|m| m.1).map(|m| m.0).collect()
    }

    pub fn missing_parts(&self) -> Vec<&'static str> {
        [(".coop-runtime/python.exe", self.runtime), ("package-manifest.json", self.manifest)]
            .iter().filter(|m| !m.1).map(|m| m.0).collect()
    }
}

pub enum Verdict {
    /// Runtime and manifest are there.
    Complete(PathBuf),
    /// A co-op game folder without runtime and/or manifest.
    Repair(Probe),
    /// Neither candidate looks like a co-op game folder.
    NotFound(Vec<Probe>),
}

/// The folders to look at are the updater's own folder, then the one above it (a subfolder of the game folder).
pub fn classify(candidates: &[PathBuf]) -> Verdict {
    let probes: Vec<Probe> = candidates.iter().map(|folder| Probe::of(folder)).collect();
    if let Some(done) = probes.iter().find(|p| p.complete()) {
        return Verdict::Complete(done.folder.clone());
    }
    match probes.iter().find(|p| p.game()) {
        Some(p) => Verdict::Repair(p.clone()),
        None => Verdict::NotFound(probes),
    }
}

/// The lines after "This is not an Azeroth Survivors Together co-op folder": where was looked, what was found.
pub fn not_found_lines(probes: &[Probe]) -> Vec<String> {
    let mut lines = Vec::new();
    for probe in probes {
        let found = probe.found();
        lines.push(format!("Looked in {}: {}", probe.folder.display(),
                           if found.is_empty() { "none of the co-op files".to_string() } else { format!("found {}", found.join(", ")) }));
    }
    lines.push("A co-op game folder has AzerothSurvivors.exe plus Start-Coop.cmd (or the reconstruction folder). \
                A missing .coop-runtime or package-manifest.json is repaired by this updater.".to_string());
    lines.push("Put this file into your game folder (where Start-Coop.cmd is) and run it there.".to_string());
    lines
}

pub struct Options {
    pub release_url: String,
    pub allow_http: bool,
}

/// --release-url and --allow-local-http are diagnostics (test servers); the Python updater gets them as well.
pub fn options(args: &[String]) -> Options {
    let mut o = Options { release_url: RELEASE_URL.into(), allow_http: false };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--release-url" => if let Some(url) = it.next() { o.release_url = url.clone() },
            "--allow-local-http" => o.allow_http = true,
            _ => {}
        }
    }
    if !o.release_url.ends_with('/') {
        o.release_url.push('/');
    }
    o
}

struct Step(&'static str, Instant);

fn step(name: &'static str) -> Step {
    log(" .... ", name);
    Step(name, Instant::now())
}

impl Step {
    fn ok(self, info: &str) {
        log("  OK  ", &format!("{} ({:.1} s{}{})", self.0, self.1.elapsed().as_secs_f64(), if info.is_empty() { "" } else { ", " }, info));
    }
}

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

fn sha256_file(path: &Path) -> std::io::Result<String> {
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

fn free_space(dir: &Path) -> Option<u64> {
    let wide: Vec<u16> = dir.as_os_str().to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, &mut total_free) };
    (ok != 0).then_some(free)
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / (1u64 << 30) as f64
}

/// Fetch what the normal updater run needs and cannot fetch itself: the runtime (it runs the updater's Python).
pub fn repair(probe: &Probe, o: &Options) -> Result<(), String> {
    let root = &probe.folder;
    let missing = probe.missing_parts();
    log(" INFO ", &format!("Old or damaged co-op folder {}: missing {}", root.display(), missing.join(" and ")));
    log(" INFO ", "Repairing from the signed release. Player data and settings are not touched.");
    if !probe.runtime && find_entry(root, "coop-runtime").is_some_and(|p| p.is_dir()) {
        // A file manager under Linux often drops the leading dot of hidden folders when it copies.
        log(" WARN ", "Found a folder coop-runtime without the leading dot (a copy lost it); it is ignored and the real .coop-runtime comes from the release");
    }
    if probe.runtime {
        // Only the manifest is missing: the updater run that follows compares every file with the signed
        // manifest and writes package-manifest.json itself.
        log(" INFO ", "The co-op runtime is there; package-manifest.json is rebuilt by the update that follows");
        return Ok(());
    }
    fetch_runtime(root, o)
}

/// Download the signed release's runtime archive and install it into `root` (missing folder: put in place;
/// present but damaged: merged, so missing and changed files come back). Nothing else in the folder is written.
pub fn fetch_runtime(root: &Path, o: &Options) -> Result<(), String> {
    let work = root.join("coop-update").join("repair");
    let s = step("Write access");
    fs::create_dir_all(&work).map_err(|e| format!("cannot write to {}: {e}. Nothing was changed.", root.display()))?;
    let probe_file = work.join("write-test.tmp");
    fs::write(&probe_file, b"ok").and_then(|_| fs::remove_file(&probe_file))
        .map_err(|e| format!("cannot write to {}: {e}. Nothing was changed.", root.display()))?;
    s.ok("");

    let s = step("Read signed release description");
    net::download(&format!("{}latest.json", o.release_url), &work.join("latest.json"), false, o.allow_http, LATEST_LIMIT)?;
    net::download(&format!("{}latest.json.sig", o.release_url), &work.join("latest.json.sig"), false, o.allow_http, 4096)?;
    let data = fs::read(work.join("latest.json")).map_err(|e| e.to_string())?;
    let signature = fs::read(work.join("latest.json.sig")).map_err(|e| e.to_string())?;
    if data.len() as u64 > LATEST_LIMIT {
        return Err("latest.json is larger than allowed".into());
    }
    let key = verify(&data, &signature).ok_or("the release description is not signed by a trusted key; nothing was changed")?;
    let latest: serde_json::Value = serde_json::from_slice(&data).map_err(|e| format!("latest.json: {e}"))?;
    if latest["format"] != 1 || latest["product"] != PRODUCT {
        return Err("latest.json is not an Azeroth Survivors Together release description".into());
    }
    s.ok(&format!("co-op {}, signed by {}...", latest["version"].as_str().unwrap_or("?"), &key[..key.len().min(12)]));

    let runtime = &latest["archives"]["runtime"];
    let (asset, digest, size) = (runtime["asset"].as_str().unwrap_or(""), runtime["sha256"].as_str().unwrap_or(""),
                                 runtime["size"].as_u64().unwrap_or(0));
    if !safe_asset(asset) || digest.len() != 64 || size == 0 || size > RUNTIME_LIMIT {
        return Err("latest.json lists an invalid runtime archive".into());
    }
    let s = step("Free disk space");
    let needed = size * 4 + (256 << 20);
    let free = free_space(root).ok_or("cannot read the free disk space")?;
    if free < needed {
        return Err(format!("{:.1} GiB free on that drive, {:.1} GiB needed. Nothing was changed. Free some space and run the updater again.",
                           gib(free), gib(needed)));
    }
    s.ok(&format!("{:.1} GiB free", gib(free)));

    let s = step("Download the co-op runtime");
    let archive = work.join(asset);
    if !(archive.is_file() && sha256_file(&archive).ok().as_deref() == Some(digest)) {
        net::download(&format!("{}{asset}", o.release_url), &archive, true, o.allow_http, size)?;
    }
    let got = fs::metadata(&archive).map(|m| m.len()).unwrap_or(0);
    if got != size || sha256_file(&archive).map_err(|e| e.to_string())? != digest {
        let _ = fs::remove_file(&archive);
        return Err(format!("{asset} does not match its signed size/SHA-256 (removed); run the updater again"));
    }
    s.ok(&format!("{:.1} MiB, SHA-256 matches the release", size as f64 / (1u64 << 20) as f64));

    let s = step("Unpack the co-op runtime");
    let stage = work.join("runtime-stage");
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
    unzip::extract(&archive, &stage, UNPACKED_LIMIT).map_err(|e| format!("unpacking the runtime failed: {e}"))?;
    // Staging first, then one rename per folder (old one aside, new one in, rollback on failure).
    let (files, warnings) = runtime::install(&stage, root, &work.join("replaced"))?;
    let _ = fs::remove_dir_all(&stage);
    if !root.join(".coop-runtime").join("python.exe").is_file() {
        return Err("unpacking the runtime failed: no .coop-runtime/python.exe".into());
    }
    s.ok(&format!("{files} files"));
    for warning in warnings {
        log(" WARN ", &warning);
    }
    let _ = fs::remove_file(&archive);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("azs-repair-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(folder: &Path, name: &str) {
        let path = folder.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"x").unwrap();
    }

    #[test]
    fn complete_folder_is_updated_as_before() {
        let game = temp("complete");
        for name in ["AzerothSurvivors.exe", "Start-Coop.cmd", ".coop-runtime/python.exe", "package-manifest.json"] {
            touch(&game, name);
        }
        assert!(matches!(classify(&[game.clone()]), Verdict::Complete(f) if f == game));
        // Updater in a subfolder of the game folder.
        let sub = game.join("coop-update");
        fs::create_dir_all(&sub).unwrap();
        assert!(matches!(classify(&[sub, game.clone()]), Verdict::Complete(f) if f == game));
        let _ = fs::remove_dir_all(&game);
    }

    #[test]
    fn old_folder_without_manifest_or_runtime_is_repaired() {
        let old = temp("old");
        for name in ["AzerothSurvivors.exe", "Start-Coop.cmd", ".coop-runtime/python.exe"] {
            touch(&old, name);
        }
        let Verdict::Repair(probe) = classify(&[old.clone()]) else { panic!("no repair") };
        assert_eq!(probe.missing_parts(), ["package-manifest.json"]);
        let bare = temp("bare");
        touch(&bare, "AzerothSurvivors.exe");
        fs::create_dir_all(bare.join("reconstruction")).unwrap(); // Start-Coop.cmd may be missing when reconstruction is there.
        let Verdict::Repair(probe) = classify(&[bare.clone(), bare.parent().unwrap().to_path_buf()]) else { panic!("no repair") };
        assert_eq!(probe.missing_parts(), [".coop-runtime/python.exe", "package-manifest.json"]);
        assert_eq!(probe.folder, bare);
        let _ = fs::remove_dir_all(old);
        let _ = fs::remove_dir_all(bare);
    }

    #[test]
    fn foreign_folder_is_refused_with_a_precise_message() {
        let foreign = temp("foreign");
        touch(&foreign, "AzerothSurvivors.exe"); // The single-player game alone is not a co-op folder.
        touch(&foreign, "Data/patch.MPQ");
        let parent = foreign.parent().unwrap().to_path_buf();
        let Verdict::NotFound(probes) = classify(&[foreign.clone(), parent]) else { panic!("accepted") };
        let lines = not_found_lines(&probes);
        assert!(lines[0].contains("found AzerothSurvivors.exe") && !lines[0].contains("Start-Coop.cmd"), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("Looked in")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("Start-Coop.cmd") && l.contains("repaired")), "{lines:?}");
        let _ = fs::remove_dir_all(foreign);
    }

    #[test]
    fn other_capitalisation_and_a_lost_dot_are_handled() {
        let game = temp("case");
        for name in ["azerothsurvivors.EXE", "START-COOP.CMD", "Package-Manifest.JSON", ".Coop-Runtime/PYTHON.exe"] {
            touch(&game, name);
        }
        assert!(matches!(classify(&[game.clone()]), Verdict::Complete(f) if f == game));
        let lost = temp("lost-dot");
        for name in ["AzerothSurvivors.exe", "Start-Coop.cmd", "package-manifest.json", "coop-runtime/python.exe"] {
            touch(&lost, name);
        }
        let Verdict::Repair(probe) = classify(&[lost.clone()]) else { panic!("no repair") };
        assert_eq!(probe.missing_parts(), [".coop-runtime/python.exe"]);
        let _ = fs::remove_dir_all(game);
        let _ = fs::remove_dir_all(lost);
    }

    #[test]
    fn options_read_the_diagnostic_arguments() {
        let args: Vec<String> = ["--release-url", "http://127.0.0.1:1/x", "--allow-local-http"].iter().map(|s| s.to_string()).collect();
        let o = options(&args);
        assert_eq!((o.release_url.as_str(), o.allow_http), ("http://127.0.0.1:1/x/", true));
        assert_eq!(options(&[]).release_url, RELEASE_URL);
    }
}
