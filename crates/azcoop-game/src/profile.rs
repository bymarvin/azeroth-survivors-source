//! The co-op address profile of one build (release-*.json) and the reviewed
//! hook table (reviewed-hooks.json): every hook's address, every translated
//! struct field.

use crate::Result;
use serde_json::Value;
use std::collections::BTreeMap;

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect()
}

#[derive(Debug, Clone)]
pub struct Hook {
    pub name: String,
    /// Address in the reviewed reference build.
    pub reference_rva: u64,
    /// Address in this build (`adapter_profile.addresses`).
    pub rva: u64,
    pub pattern: Vec<u8>,
    pub mask: Vec<u8>,
}

/// One hash-bound native dispatch whose table lookup the adapter guards (`dispatch_guards`).
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchGuard {
    /// `cast_tag` or `loot_tag`.
    pub kind: String,
    pub rva: u64,
    pub expected: Vec<u8>,
    pub table_rva: u64,
    pub maximum: u64,
    pub continuation_rva: u64,
    pub mandatory_runtime_guard: bool,
}

/// `menu_contract` of the release file: the addresses the party menu needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Menu {
    /// MAP_SELECT entry (the profile's hook table has the same function).
    pub map_select: u64,
    /// Return address of the explicit native Enter selection: only a call from there publishes the host map.
    pub host_map_return: u64,
    /// The native Enter command tag: 10 up to 0.93.1, 11 in 0.95.0.
    pub enter_tag: u32,
    /// Guest login: the branch that checks the requested map (a 2-byte `jnz`), where it continues, and where the
    /// requested map's length sits relative to RBP.
    pub login: Option<MenuLogin>,
    /// Guest map clamp: the code site (with the bytes it must hold) that picks the zone, and the allocation path it jumps to.
    pub clamp: Option<MapClamp>,
    /// The zone names in the native table order (`map_selection.names`); empty: the nine zones of 0.95.0 and before.
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuLogin {
    pub branch: u64,
    pub continuation: u64,
    pub requested_length_stack: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapClamp {
    pub site: u64,
    pub expected: Vec<u8>,
    pub allocation_path: u64,
}

/// Key range of the Game fields the bridge read at family constants (see [`RawGameFields`]): 0x10000 + the legacy (0.84.3) Game
/// offset, the coordinate system of `GAME_FIELDS`.
pub const RAW_GAME_KEY: u64 = 0x1_0000;

/// Game fields (Game-relative) that used to be family constants in the bridge. Since 19.10.2026 (0.100.1 port: Game+0x4F8 was read
/// hard-coded) they come from the profile, voted by the port pipeline and checked by the REA chat; a profile-described build without
/// a row is refused at start ("no value without a reference"). Compiled builds keep their reviewed constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawGameFields {
    /// The pending ordinary impact Vec (ptr, len), records of 0x50.
    pub impacts: u64,
    pub guardian_kills: u64,
    /// The pending guardian reward choices (u32).
    pub guardian_choices: u64,
    /// The native surrender flag (byte), read by the 0.95.0 code family only.
    pub surrender_flag: u64,
}

impl RawGameFields {
    /// legacy key -> per compiled build its reviewed value. References: 0.84.3/0.93.1/0.95.0 the Python bridge's constants (live
    /// verified in their releases); 0.97.1 surrender 0x949 the REA chat 19.10.2026 (`mov bl,[rdi+0x949]` at 0x54b68f5, the 0.95.0
    /// `mov bl,[rdi+0x941]` at 0x546f525), its other three unchanged from 0.97.0 (REA votes 0.97.1 -> 0.99.0).
    pub fn resolve(profile: &Profile, variant: crate::builds::Variant) -> Result<RawGameFields> {
        use crate::builds::Variant::*;
        let compiled = |legacy: u64| -> Option<u64> {
            Some(match (variant, legacy) {
                (V0843, 0x5B8) => 0x5B8,
                (V0843, 0x6E8) => 0x6E8,
                (V0843, 0x888) => 0x888,
                (V0843, 0x941) => 0x941,
                (V0931 | V7264 | V971, 0x5B8) => 0x4F8,
                (V0931 | V7264 | V971, 0x6E8) => 0x664,
                (V0931 | V7264 | V971, 0x888) => 0x8E4,
                (V0931 | V7264, 0x941) => 0x941,
                (V971, 0x941) => 0x949,
                _ => return None,
            })
        };
        let get = |legacy: u64, what: &str| -> Result<u64> {
            match profile.field("game", (RAW_GAME_KEY + legacy) as i64) {
                Ok(v) => u64::try_from(v).map_err(|_| format!("game+{:#x} ({what}) resolves negative", RAW_GAME_KEY + legacy)),
                Err(_) => compiled(legacy).ok_or_else(|| format!(
                    "the profile has no verified game+{:#x} ({what}); this build is refused until the port records it", RAW_GAME_KEY + legacy)),
            }
        };
        Ok(RawGameFields {
            impacts: get(0x5B8, "pending ordinary impacts")?,
            guardian_kills: get(0x6E8, "guardian kill count")?,
            guardian_choices: get(0x888, "pending guardian reward choices")?,
            surrender_flag: get(0x941, "surrender flag")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub sha256: String,
    pub release_version: String,
    pub hooks: BTreeMap<String, Hook>,
    /// (domain, reference offset) -> offset in this build.
    pub fields: BTreeMap<(String, i64), i64>,
    pub addresses: BTreeMap<u64, u64>,
    pub dispatch_guards: Vec<DispatchGuard>,
    pub menu: Option<Menu>,
    /// `patch_preconditions`: (reviewed address, reference bytes) -> this build's bytes of the same instructions. The candidate
    /// may encode them in more or fewer bytes (a patch site of 14 reference bytes can be 16 here), so the generated code must
    /// use these, not a read of the same length from the executable.
    pub patches: BTreeMap<(u64, Vec<u8>), Vec<u8>>,
}

impl Profile {
    pub fn parse(release: &str, reviewed: &str) -> Result<Profile> {
        let release: Value = serde_json::from_str(release).map_err(|e| format!("release json: {e}"))?;
        let reviewed: Value = serde_json::from_str(reviewed).map_err(|e| format!("reviewed json: {e}"))?;
        let adapter = &release["adapter_profile"];
        let mut addresses = BTreeMap::new();
        for row in adapter["addresses"].as_array().ok_or("profile has no addresses")? {
            let (Some(r), Some(c)) = (row["reference"].as_u64(), row["candidate"].as_u64()) else {
                return Err("bad address row".into());
            };
            if addresses.insert(r, c).is_some_and(|old| old != c) {
                return Err(format!("reference {r:#x} has two different candidates"));
            }
        }
        let mut fields = BTreeMap::new();
        for row in adapter["fields"].as_array().ok_or("profile has no fields")? {
            let (Some(d), Some(r), Some(c)) = (row["domain"].as_str(), row["reference"].as_i64(), row["candidate"].as_i64()) else {
                return Err("bad field row".into());
            };
            if fields.insert((d.to_string(), r), c).is_some_and(|old| old != c) {
                return Err(format!("field {d}+{r:#x} has two different candidates"));
            }
        }
        let mut hooks = BTreeMap::new();
        for (name, h) in reviewed["hooks"].as_object().ok_or("reviewed file has no hooks")? {
            let reference_rva = h["reference_rva"].as_u64().ok_or_else(|| format!("{name}: no reference_rva"))?;
            let rva = *addresses.get(&reference_rva).ok_or_else(|| format!("{name}: no address for reference {reference_rva:#x}"))?;
            let pattern = h["pattern"].as_str().and_then(unhex).ok_or_else(|| format!("{name}: bad pattern"))?;
            let mask = h["mask"].as_str().and_then(unhex).ok_or_else(|| format!("{name}: bad mask"))?;
            if pattern.len() != mask.len() || pattern.is_empty() {
                return Err(format!("{name}: pattern and mask differ in length"));
            }
            hooks.insert(name.clone(), Hook { name: name.clone(), reference_rva, rva, pattern, mask });
        }
        let mut patches = BTreeMap::new();
        for row in adapter["patches"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
            let bad = || "bad patch row".to_string();
            let key = (row["reference"].as_u64().ok_or_else(bad)?, row["expected"].as_str().and_then(unhex).ok_or_else(bad)?);
            let candidate = row["candidate_bytes"].as_str().and_then(unhex).ok_or_else(bad)?;
            if key.1.is_empty() || candidate.is_empty() || patches.insert(key, candidate).is_some() {
                return Err("bad or duplicate patch row".into());
            }
        }
        let mut dispatch_guards = Vec::new();
        for row in adapter["dispatch_guards"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
            let bad = || "bad dispatch guard row".to_string();
            dispatch_guards.push(DispatchGuard {
                kind: row["kind"].as_str().ok_or_else(bad)?.to_string(),
                rva: row["rva"].as_u64().ok_or_else(bad)?,
                expected: row["expected"].as_str().and_then(unhex).ok_or_else(bad)?,
                table_rva: row["table_rva"].as_u64().ok_or_else(bad)?,
                maximum: row["maximum"].as_u64().ok_or_else(bad)?,
                continuation_rva: row["continuation_rva"].as_u64().ok_or_else(bad)?,
                mandatory_runtime_guard: row["mandatory_runtime_guard"].as_bool().unwrap_or(false),
            });
        }
        let contract = &release["menu_contract"];
        let menu = match (contract["map_select"].as_u64(), contract["host_map_return"].as_u64()) {
            (Some(map_select), Some(host_map_return)) => {
                let login = &contract["login"];
                let clamp = &contract["map_clamp"];
                Some(Menu {
                    map_select,
                    host_map_return,
                    enter_tag: contract["enter_tag"].as_u64().unwrap_or(10) as u32,
                    login: match (login["branch"].as_u64(), login["continuation"].as_u64(), login["requested_length_stack"].as_u64()) {
                        (Some(branch), Some(continuation), Some(requested_length_stack)) => Some(MenuLogin { branch, continuation, requested_length_stack }),
                        _ => None,
                    },
                    clamp: match (clamp["site"].as_u64(), clamp["expected"].as_str().and_then(unhex), clamp["allocation_path"].as_u64()) {
                        (Some(site), Some(expected), Some(allocation_path)) => Some(MapClamp { site, expected, allocation_path }),
                        _ => None,
                    },
                    zones: contract["map_selection"]["names"]
                        .as_array()
                        .map(|names| names.iter().filter_map(|n| n.as_str().map(str::to_string)).collect())
                        .unwrap_or_default(),
                })
            }
            _ => None,
        };
        Ok(Profile {
            sha256: adapter["sha256"].as_str().ok_or("profile has no sha256")?.to_string(),
            release_version: adapter["release_version"].as_str().unwrap_or("").to_string(),
            hooks,
            fields,
            addresses,
            dispatch_guards,
            menu,
            patches,
        })
    }

    /// `updated_layout.field(domain, offset)`: missing evidence is an error.
    pub fn field(&self, domain: &str, reference: i64) -> Result<i64> {
        self.fields.get(&(domain.to_string(), reference)).copied().ok_or_else(|| format!("profile has no field {domain}+{reference:#x}"))
    }

}

#[cfg(test)]
mod raw_field_tests {
    use super::*;

    #[test]
    fn raw_game_fields_come_from_the_profile_compiled_builds_keep_their_constants_runtime_builds_need_a_row() {
        use crate::builds::Variant;
        let mut profile = Profile { sha256: String::new(), release_version: String::new(), hooks: Default::default(), fields: Default::default(),
                                    addresses: Default::default(), dispatch_guards: Vec::new(), menu: None, patches: Default::default() };
        let v971 = RawGameFields::resolve(&profile, Variant::V971).unwrap();
        assert_eq!((v971.impacts, v971.guardian_choices, v971.surrender_flag), (0x4F8, 0x8E4, 0x949), "a compiled build: its reviewed constants");
        let refused = RawGameFields::resolve(&profile, Variant::Runtime).unwrap_err();
        assert!(refused.contains("refused") && refused.contains("pending ordinary impacts"), "{refused}");
        for (legacy, value) in [(0x5B8u64, 0x510i64), (0x6E8, 0x67C), (0x888, 0x93C), (0x941, 0x9A9)] {
            profile.fields.insert(("game".to_string(), (RAW_GAME_KEY + legacy) as i64), value);
        }
        let runtime = RawGameFields::resolve(&profile, Variant::Runtime).unwrap();
        assert_eq!(runtime, RawGameFields { impacts: 0x510, guardian_kills: 0x67C, guardian_choices: 0x93C, surrender_flag: 0x9A9 }, "0.100.1 rows");
        assert_eq!(RawGameFields::resolve(&profile, Variant::V7264).unwrap().impacts, 0x510, "a row wins over a compiled constant too");
        println!("[  OK  ] raw Game fields: rows, compiled constants, runtime refused without rows");
    }
}
