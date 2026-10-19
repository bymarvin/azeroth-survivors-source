//! Put an unpacked runtime archive in place (installer and updater; shared like net.rs and unzip.rs).
//!
//! The release's runtime zip holds `.coop-runtime` (the Python runtime) and `.tools` (tool libraries); nothing else
//! may come out of it (unzip.rs already refuses "..", drives and absolute paths; links are refused here). The
//! archive is unpacked completely into a staging folder first. Each folder then replaces its old version by two
//! renames on the same drive: the old one is moved aside into coop-update, the new one moved in, the old one
//! removed. A failed move puts the old one back, so the game folder never holds half a runtime. A damaged runtime
//! (a quarantined package or DLL) is replaced as a whole. Player data lives outside these folders and is never
//! touched. `.tools` is only needed by development tools: a failure there is reported, not fatal.

use std::fs;
use std::path::Path;

pub const ENTRIES: [&str; 2] = [".coop-runtime", ".tools"];

pub fn count_files(dir: &Path) -> usize {
    fs::read_dir(dir).map(|entries| entries.filter_map(Result::ok)
        .map(|e| if e.path().is_dir() { count_files(&e.path()) } else { 1 }).sum()).unwrap_or(0)
}

fn links(dir: &Path) -> Option<String> {
    for entry in fs::read_dir(dir).ok()?.filter_map(Result::ok) {
        let kind = fs::symlink_metadata(entry.path()).ok()?.file_type();
        if kind.is_symlink() {
            return Some(entry.path().display().to_string());
        }
        if kind.is_dir() {
            if let Some(found) = links(&entry.path()) {
                return Some(found);
            }
        }
    }
    None
}

/// Check the staging folder: `.coop-runtime` with python.exe, maybe `.tools`, nothing else, no links.
pub fn check_stage(stage: &Path) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = fs::read_dir(stage).map_err(|e| e.to_string())?
        .filter_map(Result::ok).map(|e| e.file_name().to_string_lossy().to_string()).collect();
    names.sort();
    if !names.iter().any(|n| n == ".coop-runtime") || names.iter().any(|n| !ENTRIES.contains(&n.as_str())) {
        return Err(format!("the runtime archive holds unexpected top-level entries ({}); nothing was changed", names.join(", ")));
    }
    if !stage.join(".coop-runtime").join("python.exe").is_file() {
        return Err("the runtime archive has no .coop-runtime/python.exe; nothing was changed".into());
    }
    if let Some(link) = links(stage) {
        return Err(format!("the runtime archive holds a link ({link}); nothing was changed"));
    }
    Ok(names)
}

/// Swap one folder: `aside` (inside coop-update, same drive) keeps the old version until the new one is in place.
fn swap(from: &Path, to: &Path, aside: &Path) -> Result<(), String> {
    if aside.exists() {
        fs::remove_dir_all(aside).map_err(|e| format!("cannot clear {} (left by an earlier repair): {e}", aside.display()))?;
    }
    let had_old = to.exists();
    if had_old {
        fs::rename(to, aside).map_err(|e| format!(
            "cannot move the old {} aside ({e}): close the game and the co-op launcher; security software may be \
             locking it. Nothing was changed", to.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()))?;
    }
    if let Err(error) = fs::rename(from, to) {
        if had_old {
            let _ = fs::rename(aside, to); // Put the old one back: never half a runtime.
        }
        return Err(format!("cannot put the new {} in place ({error}); the old one is kept",
                           to.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()));
    }
    if had_old {
        let _ = fs::remove_dir_all(aside); // A locked leftover is cleared by the next repair.
    }
    Ok(())
}

/// Install a checked staging folder into `root`; returns the number of runtime files and warnings (`.tools`).
pub fn install(stage: &Path, root: &Path, work: &Path) -> Result<(usize, Vec<String>), String> {
    let names = check_stage(stage)?;
    fs::create_dir_all(work).map_err(|e| e.to_string())?;
    let mut warnings = Vec::new();
    let mut files = 0;
    for name in &names {
        let (from, to) = (stage.join(name), root.join(name));
        let count = count_files(&from);
        match swap(&from, &to, &work.join(format!("{}.old", name.trim_start_matches('.')))) {
            Ok(()) => files += count,
            Err(error) if name == ".tools" => warnings.push(format!(".tools (development tools only): {error}")),
            Err(error) => return Err(error),
        }
    }
    Ok((files, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("azs-runtime-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(folder: &Path, name: &str, body: &[u8]) {
        let path = folder.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    #[test]
    fn only_the_runtime_folders_with_python_are_accepted() {
        let stage = temp("names");
        touch(&stage, ".coop-runtime/python.exe", b"x");
        touch(&stage, "coop-lab/personal/characters.txt", b"x");
        assert!(check_stage(&stage).unwrap_err().contains("unexpected top-level"));
        fs::remove_dir_all(stage.join("coop-lab")).unwrap();
        touch(&stage, ".tools/python/pefile.py", b"x");
        assert_eq!(check_stage(&stage).unwrap(), [".coop-runtime", ".tools"]);
        fs::remove_file(stage.join(".coop-runtime/python.exe")).unwrap();
        assert!(check_stage(&stage).unwrap_err().contains("no .coop-runtime/python.exe"));
        let only_tools = temp("tools-only");
        touch(&only_tools, ".tools/python/pefile.py", b"x");
        assert!(check_stage(&only_tools).unwrap_err().contains("unexpected top-level"));
        let _ = fs::remove_dir_all(stage);
        let _ = fs::remove_dir_all(only_tools);
    }

    #[test]
    fn a_damaged_runtime_is_replaced_as_a_whole_and_player_data_stays() {
        let (root, stage, work) = (temp("swap"), temp("swap-stage"), temp("swap-work"));
        touch(&root, ".coop-runtime/python.exe", b"old");
        touch(&root, ".coop-runtime/Lib/stale.py", b"old");
        touch(&root, "coop-lab/personal/characters.txt", b"hero");
        touch(&root, "characters.txt", b"sp");
        touch(&stage, ".coop-runtime/python.exe", b"new");
        touch(&stage, ".coop-runtime/Lib/site-packages/cryptography/__init__.py", b"new");
        touch(&stage, ".tools/python/pefile.py", b"new");
        let (files, warnings) = install(&stage, &root, &work).unwrap();
        assert_eq!((files, warnings.len()), (3, 0));
        assert_eq!(fs::read(root.join(".coop-runtime/python.exe")).unwrap(), b"new");
        assert!(!root.join(".coop-runtime/Lib/stale.py").exists());
        assert!(root.join(".coop-runtime/Lib/site-packages/cryptography/__init__.py").is_file());
        assert!(root.join(".tools/python/pefile.py").is_file());
        assert_eq!(fs::read(root.join("coop-lab/personal/characters.txt")).unwrap(), b"hero");
        assert_eq!(fs::read(root.join("characters.txt")).unwrap(), b"sp");
        assert!(!work.join("coop-runtime.old").exists());
        for dir in [root, stage, work] {
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_failed_move_keeps_the_old_runtime() {
        let (root, stage, work) = (temp("rollback"), temp("rollback-stage"), temp("rollback-work"));
        touch(&root, ".coop-runtime/python.exe", b"old");
        touch(&stage, ".coop-runtime/python.exe", b"new");
        // The new folder cannot be moved in: its source vanishes after the check (stands in for a locked file).
        let names = check_stage(&stage).unwrap();
        assert_eq!(names, [".coop-runtime"]);
        let missing = stage.join("gone");
        let error = swap(&missing, &root.join(".coop-runtime"), &work.join("coop-runtime.old")).unwrap_err();
        assert!(error.contains("the old one is kept"), "{error}");
        assert_eq!(fs::read(root.join(".coop-runtime/python.exe")).unwrap(), b"old");
        for dir in [root, stage, work] {
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_fresh_folder_gets_the_runtime_moved_in() {
        let (root, stage, work) = (temp("fresh"), temp("fresh-stage"), temp("fresh-work"));
        touch(&stage, ".coop-runtime/python.exe", b"new");
        assert_eq!(install(&stage, &root, &work).unwrap().0, 1);
        assert!(root.join(".coop-runtime/python.exe").is_file());
        for dir in [root, stage, work] {
            let _ = fs::remove_dir_all(dir);
        }
    }
}
