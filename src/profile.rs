//! Reads the co-op address profile (data only) and resolves hook addresses.
//!
//! Sources, first match wins:
//!   1. %AZCOOP_PROFILE% (a file in either format below)
//!   2. <game>\analysis\active-hooks.json        hooks.<NAME>.candidates[0]
//!   3. <game>\reconstruction\release-*.json     adapter_profile.addresses,
//!      mapped from the reference RVA in reconstruction\reviewed-hooks.json
//!      (2. may also be in this format, as in the 0.93.1 package)
//! Every source must name the running executable's SHA-256.

use serde_json::Value;
use std::path::{Path, PathBuf};

/// Reference-build RVAs (reviewed-hooks.json), used when the reviewed-hooks
/// file is absent next to a release profile.
const REFERENCE_RVAS: [(&str, u64); 2] = [("WRITE", 88_634_928), ("TICK", 87_801_968)];

pub struct HookAddress {
    pub rva: u64,
    /// Reviewed byte pattern and mask (reference build), if present.
    pub pattern: Option<(Vec<u8>, Vec<u8>)>,
}

pub struct Resolved {
    pub source: PathBuf,
    json: Value,
    reviewed: Option<Value>,
    game_sha256: String,
    /// Return address of the native batch call site (adapter contract), if known.
    pub batch_return_rva: Option<u64>,
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect()
}

fn hex_rva(value: &Value) -> Option<u64> {
    u64::from_str_radix(value.as_str()?.trim_start_matches("0x"), 16).ok()
}

impl Resolved {
    /// The whole release file (for `azcoop_game::builds::register_runtime`).
    pub fn json(&self) -> &Value {
        &self.json
    }

    /// The reviewed byte patterns describe the *reference* build. They can only
    /// validate hook bytes exactly when the running executable is that build
    /// (e.g. WRITE happens to be byte-identical across 0.84.3/0.93.1, but TICK
    /// is not). Otherwise the reviewed-port address is the trust anchor and we
    /// fall back to a build-independent entry prologue.
    pub fn patterns_authoritative(&self) -> bool {
        self.reviewed
            .as_ref()
            .and_then(|r| r["reference_sha256"].as_str())
            .is_some_and(|sha| sha == self.game_sha256)
    }

    /// Translates a reviewed struct offset to this build (adapter `fields`),
    /// like `updated_layout.field(domain, offset)`. Missing evidence is an error.
    pub fn field(&self, domain: &str, reference: u64) -> Result<u64, String> {
        self.json["adapter_profile"]["fields"]
            .as_array()
            .and_then(|fields| {
                fields.iter().find(|f| f["domain"].as_str() == Some(domain) && f["reference"].as_u64() == Some(reference))
            })
            .and_then(|f| f["candidate"].as_u64())
            .ok_or(format!("profile has no field {domain}+{reference:#x}"))
    }

    /// Address and reviewed pattern of one hook by its reviewed name.
    pub fn hook(&self, name: &str) -> Result<HookAddress, String> {
        let reviewed = self.reviewed.as_ref().map(|r| &r["hooks"][name]);
        let pattern = reviewed
            .and_then(|h| h["pattern"].as_str().and_then(hex).zip(h["mask"].as_str().and_then(hex)));
        let reference = reviewed
            .and_then(|h| h["reference_rva"].as_u64())
            .or_else(|| REFERENCE_RVAS.iter().find(|(n, _)| *n == name).map(|(_, r)| *r))
            .ok_or(format!("{name} has no reference address"))?;
        let rva = if let Some(candidates) = self.json["hooks"][name]["candidates"].as_array() {
            match candidates.as_slice() {
                [only] => only.as_u64().ok_or(format!("{name} candidate is not a number"))?,
                _ => return Err(format!("{name} has {} candidates, need exactly one", candidates.len())),
            }
        } else {
            let addresses =
                self.json["adapter_profile"]["addresses"].as_array().ok_or("profile has no hooks and no addresses")?;
            addresses
                .iter()
                .find(|row| row["reference"].as_u64() == Some(reference))
                .and_then(|row| row["candidate"].as_u64())
                .ok_or(format!("profile has no address for {name} reference {reference:#x}"))?
        };
        Ok(HookAddress { rva, pattern })
    }
}

fn from_json(json: Value, source: &Path, game: &Path, sha256: &str) -> Result<Resolved, String> {
    let adapter = &json["adapter_profile"];
    let named = json["sha256"].as_str().or(adapter["sha256"].as_str()).unwrap_or("");
    if named != sha256 {
        return Err(format!("profile is for {named:.16}…, game is {sha256:.16}…"));
    }
    let batch_return_rva = hex_rva(&adapter["native_live_contracts"]["batch"]["return_rva"]);
    let reviewed = read_json(&game.join(r"reconstruction\reviewed-hooks.json")).ok();
    Ok(Resolved { source: source.to_path_buf(), json, reviewed, game_sha256: sha256.to_string(), batch_return_rva })
}

pub fn resolve(game: &Path, sha256: &str) -> Result<Resolved, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os("AZCOOP_PROFILE") {
        candidates.push(path.into());
    }
    candidates.push(game.join(r"analysis\active-hooks.json"));
    // Release profiles (release-0.84.3.json, release-0315cf38.json, …); the
    // one naming this executable's SHA-256 wins.
    if let Ok(entries) = std::fs::read_dir(game.join("reconstruction")) {
        let mut releases: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                name.starts_with("release-") && name.ends_with(".json")
            })
            .collect();
        releases.sort();
        candidates.extend(releases);
    }
    let mut errors = Vec::new();
    for path in candidates {
        if !path.is_file() {
            continue;
        }
        match read_json(&path).and_then(|json| from_json(json, &path, game, sha256)) {
            Ok(resolved) => return Ok(resolved),
            Err(error) => errors.push(format!("{}: {error}", path.display())),
        }
    }
    if errors.is_empty() {
        errors.push("no profile file found".into());
    }
    Err(errors.join("; "))
}
