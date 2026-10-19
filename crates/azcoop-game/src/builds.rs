//! Per-build constants that are not adapter-profile entries: a port of the
//! tables in `updated_layout.py` (FAMILY, RESULT_EVALUATION, ENEMY_LAYOUTS,
//! ADDRESSES) for the three supported builds, and the supported-build table.

use crate::Result;
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variant {
    /// 0.84.3
    V0843,
    /// 0.93.1
    V0931,
    /// 0.95.0
    V7264,
    /// 0.97.1 (the same code family as 0.95.0 with shifted addresses and struct offsets; its constants come from `tools/port`)
    V971,
    /// A build of the 0.95.0 code family that is not compiled in: its constants come from the `variant_constants` section of its
    /// profile file (`register_runtime`), so a new game build of this family needs a data file, not a new DLL.
    Runtime,
}

/// The per-build constants of a [`Variant::Runtime`] build, read from its profile (`tools/port/variant_constants.py` writes them).
#[derive(Debug, Clone)]
pub struct RuntimeBuild {
    pub sha256: String,
    pub version: String,
    pub family: Family,
    pub result_evaluation: ResultEvaluation,
    pub enemy_layout: EnemyLayout,
    pub pursuit: PursuitRegisters,
}

/// The registers the pursuit patch has to know (x86 numbers: rax 0 .. rdi 7, r8 8 .. r15 15): the enemy cursor and the XMM that holds the
/// interpolated enemy xy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PursuitRegisters {
    pub cursor: u8,
    pub xy: u8,
}

static RUNTIME: OnceLock<RuntimeBuild> = OnceLock::new();

fn number(value: &Value, what: &str) -> Result<u64> {
    value.as_u64().ok_or_else(|| format!("variant_constants: {what} is not a number"))
}

fn signed(value: &Value, what: &str) -> Result<i64> {
    value.as_i64().ok_or_else(|| format!("variant_constants: {what} is not a number"))
}

fn list<const N: usize>(value: &Value, what: &str) -> Result<[u64; N]> {
    let items = value.as_array().filter(|a| a.len() == N).ok_or_else(|| format!("variant_constants: {what} needs {N} numbers"))?;
    let mut out = [0u64; N];
    for (i, item) in items.iter().enumerate() {
        out[i] = number(item, what)?;
    }
    Ok(out)
}

/// `[[skip, slot, game field], ...]`: see [`Family::skipped_pointer_locals`]. Required: a profile without the list was not checked by
/// `tools/port/skipped_locals.py` and is refused.
fn pointer_locals(value: &Value) -> Result<&'static [[i64; 3]]> {
    let items = value.as_array().ok_or("variant_constants: skipped_pointer_locals is missing (run tools/port/skipped_locals.py)")?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let [skip, slot, field] = signed_list::<3>(item, "skipped_pointer_locals")?;
        if !(0..=1).contains(&skip) || slot < 0 || field < 0 {
            return Err(format!("variant_constants: skipped_pointer_locals entry {item} is not [skip 0|1, slot, game field]"));
        }
        out.push([skip, slot, field]);
    }
    // once per process (register_runtime): the list lives as long as the build
    Ok(Box::leak(out.into_boxed_slice()))
}

fn signed_list<const N: usize>(value: &Value, what: &str) -> Result<[i64; N]> {
    let items = value.as_array().filter(|a| a.len() == N).ok_or_else(|| format!("variant_constants: {what} needs {N} numbers"))?;
    let mut out = [0i64; N];
    for (i, item) in items.iter().enumerate() {
        out[i] = signed(item, what)?;
    }
    Ok(out)
}

/// Reads the `variant_constants` section of a release profile (`{"code_family": "7264", "version": ..., "family": .., "result_evaluation": ..,
/// "enemy_layout": .., "pursuit": ..}`) and makes the build known to [`Variant::from_sha256`]. Only the 0.95.0 code family can be described by
/// data; anything else is refused with the reason. Once per process.
pub fn register_runtime(release: &Value) -> Result<Variant> {
    let sha256 = release["adapter_profile"]["sha256"].as_str().or(release["sha256"].as_str()).ok_or("the profile names no executable")?.to_string();
    let c = &release["variant_constants"];
    if c.is_null() {
        return Err("the profile has no variant_constants section".into());
    }
    if c["code_family"].as_str() != Some("7264") {
        return Err(format!("variant_constants: code family {:?} is not described by data (only \"7264\")", c["code_family"]));
    }
    let f = &c["family"];
    let family = Family {
        impact_return: number(&f["impact_return"], "impact_return")?,
        impact_victim_slot: signed(&f["impact_victim_slot"], "impact_victim_slot")?,
        world_slots: signed_list(&f["world_slots"], "world_slots")?,
        path_field: list(&f["path_field"], "path_field")?,
        path_field_slots: signed_list(&f["path_field_slots"], "path_field_slots")?,
        recycle: [list(&f["recycle"][0], "recycle[0]")?, list(&f["recycle"][1], "recycle[1]")?],
        run_meter: list(&f["run_meter"], "run_meter")?,
        skipped_pointer_locals: pointer_locals(&f["skipped_pointer_locals"])?,
    };
    let r = &c["result_evaluation"];
    let result_evaluation = ResultEvaluation {
        lock: number(&r["lock"], "lock")?,
        last_phase: number(&r["last_phase"], "last_phase")?,
        account: number(&r["account"], "account")?,
        class_id: number(&r["class_id"], "class_id")?,
        victory: number(&r["victory"], "victory")?,
        sites: list(&r["sites"], "sites")?,
    };
    let e = &c["enemy_layout"];
    let enemy_layout = EnemyLayout { stride: number(&e["stride"], "stride")?, guid_offset: number(&e["guid_offset"], "guid_offset")?, guid_gap: number(&e["guid_gap"], "guid_gap")? };
    let p = &c["pursuit"];
    let pursuit = PursuitRegisters { cursor: number(&p["cursor"], "pursuit.cursor")? as u8, xy: number(&p["xy"], "pursuit.xy")? as u8 };
    if pursuit.cursor > 15 || pursuit.xy > 15 {
        return Err("variant_constants: pursuit registers are 0..15".into());
    }
    let build = RuntimeBuild { sha256: sha256.clone(), version: c["version"].as_str().unwrap_or("runtime").to_string(), family, result_evaluation, enemy_layout, pursuit };
    match RUNTIME.set(build) {
        Ok(()) => {}
        Err(_) if RUNTIME.get().is_some_and(|b| b.sha256 == sha256) => {}
        Err(_) => return Err("a different runtime build is already registered in this process".into()),
    }
    Ok(Variant::Runtime)
}

/// The registered runtime build.
pub fn runtime() -> Option<&'static RuntimeBuild> {
    RUNTIME.get()
}

pub const SUPPORTED: [(Variant, &str, &str); 4] = [
    (Variant::V0843, "0.84.3", "dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306"),
    (Variant::V0931, "0.93.1", "0315cf387f4f807512ac965763ed81ae58e7f20dd94547a7541ee8eae3135f66"),
    (Variant::V7264, "0.95.0", "7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30"),
    (Variant::V971, "0.97.1", "a762d045a8cbcc02a92dcce75bed59ab3216ab45ab546ef0b0b77b1b46ea0fee"),
];

impl Variant {
    pub fn from_sha256(sha256: &str) -> Result<Variant> {
        if let Some(found) = SUPPORTED.iter().find(|(_, _, s)| *s == sha256).map(|(v, _, _)| *v) {
            return Ok(found);
        }
        match RUNTIME.get() {
            Some(build) if build.sha256 == sha256 => Ok(Variant::Runtime),
            _ => Err(format!("unsupported game build {sha256:.16}")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Variant::Runtime => RUNTIME.get().map_or("runtime", |b| b.version.as_str()),
            _ => SUPPORTED.iter().find(|(v, _, _)| *v == self).unwrap().1,
        }
    }

    /// The registers of the pursuit patch (see [`PursuitRegisters`]).
    pub fn pursuit_registers(self) -> PursuitRegisters {
        match self {
            Variant::V0843 => PursuitRegisters { cursor: 6, xy: 15 },
            Variant::V0931 => PursuitRegisters { cursor: 15, xy: 12 },
            Variant::V7264 => PursuitRegisters { cursor: 12, xy: 15 },
            Variant::V971 => PursuitRegisters { cursor: 7, xy: 13 },
            Variant::Runtime => RUNTIME.get().map_or(PursuitRegisters { cursor: 12, xy: 15 }, |b| b.pursuit),
        }
    }

    /// `release_47e4()`: the 47e4 family and its successors.
    pub fn is_47e4(self) -> bool {
        self != Variant::V0843
    }

    /// `release_0931()`: 0.93.1 data layout (0.95.0 keeps it).
    pub fn is_0931(self) -> bool {
        matches!(self, Variant::V0931 | Variant::V7264 | Variant::V971 | Variant::Runtime)
    }

    /// The 0.95.0 code family: 0.95.0 itself and the builds ported from it.
    pub fn is_7264_family(self) -> bool {
        matches!(self, Variant::V7264 | Variant::V971 | Variant::Runtime)
    }

    pub fn family(self) -> Option<Family> {
        match self {
            Variant::V0843 => None,
            Variant::Runtime => RUNTIME.get().map(|b| b.family),
            Variant::V0931 => Some(Family {
                impact_return: 0x547C5BE,
                impact_victim_slot: 0xB0,
                world_slots: [0x330, 0x298, 0x48],
                path_field: [0x54A228D, 0x54A229F, 0x54A235E],
                path_field_slots: [0x70, 0x88, 0x270, -0x20],
                recycle: [[0x54FF552, 0x54FF56F, 0x54FF60E], [0x54FF682, 0x54FF69F, 0x54FF729]],
                run_meter: [0x549A90C, 0x549A91E, 0x54C6E00],
                // UNVERIFIED: no install dump of 0.93.1 here for tools/port/skipped_locals.py; the code before this list did the same
                skipped_pointer_locals: &[],
            }),
            Variant::V7264 => Some(Family {
                impact_return: 0x545CCCE,
                impact_victim_slot: 0xB0,
                world_slots: [0x330, 0x298, 0x48],
                path_field: [0x5483125, 0x548313A, 0x54831FC],
                path_field_slots: [0x90, 0xA8, 0x290, 0x0],
                recycle: [[0x550ACF2, 0x550AD0F, 0x550ADAE], [0x550AE22, 0x550AE3F, 0x550AEC9]],
                run_meter: [0x547B6AC, 0x547B6BE, 0x54A7FA0],
                // UNVERIFIED: no install dump of 0.95.0 here for tools/port/skipped_locals.py; the code before this list did the same
                skipped_pointer_locals: &[],
            }),
            // 0.97.1: every value comes from the instruction alignment 0.95.0 -> 0.97.1 (tools/port/variant_constants.py); the target slot
            // of the path field (the last of `path_field_slots`) was read by hand: old `subps xmm9,[rbp+0]` is `subps xmm9,[rbp+0x10]`.
            Variant::V971 => Some(Family {
                impact_return: 0x54A38DE,
                impact_victim_slot: 0xC0,
                world_slots: [0x340, 0x318, 0x60],
                path_field: [0x54CBA90, 0x54CBAA5, 0x54CBB67],
                path_field_slots: [0x98, 0xB8, 0x2A0, 0x10],
                recycle: [[0x5535E42, 0x5535E5F, 0x5535EFE], [0x5535F72, 0x5535F8F, 0x5536019]],
                run_meter: [0x54C34CC, 0x54C34DE, 0x54EFE70],
                // tools/port/skipped_locals.py on 0.97.1 (a762d045, port-0971/pipeline-test6/patches-new.json): no pointer local
                skipped_pointer_locals: &[],
            }),
        }
    }

    pub fn result_evaluation(self) -> ResultEvaluation {
        match self {
            Variant::V0843 => ResultEvaluation { lock: 0xDFA, last_phase: 0xDFC, account: 0x940, class_id: 0x35C, victory: 0x820, sites: [0x53E6438, 0x53E6461] },
            Variant::V0931 => ResultEvaluation { lock: 0xFBA, last_phase: 0xFBC, account: 0x9A8, class_id: 0x294, victory: 0x868, sites: [0x53F0E88, 0x53F0EB1] },
            Variant::V7264 => ResultEvaluation { lock: 0xFBA, last_phase: 0xFBC, account: 0x9A8, class_id: 0x294, victory: 0x868, sites: [0x542E3F8, 0x542E421] },
            Variant::V971 => ResultEvaluation { lock: 0xFC2, last_phase: 0xFC4, account: 0x9B0, class_id: 0x294, victory: 0x870, sites: [0x5453D5F, 0x5453D88] },
            Variant::Runtime => RUNTIME.get().map(|b| b.result_evaluation).expect("a runtime build is registered before it is used"),
        }
    }

    pub fn enemy_layout(self) -> EnemyLayout {
        match self {
            Variant::V0843 => EnemyLayout { stride: 0x148, guid_offset: 0x78, guid_gap: 12 },
            Variant::V0931 | Variant::V7264 | Variant::V971 => EnemyLayout { stride: 0x160, guid_offset: 0x88, guid_gap: 28 },
            Variant::Runtime => RUNTIME.get().map(|b| b.enemy_layout).expect("a runtime build is registered before it is used"),
        }
    }

    /// `enemy_offset(offset)`: a reviewed/0.84.3 record member offset in this build.
    pub fn enemy_offset(self, offset: u64) -> u64 {
        if !self.is_47e4() {
            return offset;
        }
        let offset = if offset >= 0x70 { offset + 0x10 } else { offset };
        if self.is_0931() && offset >= 0x13C {
            offset + 4
        } else {
            offset
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Family {
    pub impact_return: u64,
    pub impact_victim_slot: i64,
    pub world_slots: [i64; 3],
    pub path_field: [u64; 3],
    pub path_field_slots: [i64; 4],
    pub recycle: [[u64; 3]; 2],
    pub run_meter: [u64; 3],
    /// `[skip, slot, game field]`: a frame local `[rbp+slot]` holding `&Game.<field>` (legacy key of the profile's `game` field table)
    /// that the game sets only inside the native region a downed-host continuation skips (skip 0: `downed_world_code`, 1:
    /// `downed_hazards_code`) and reads after it. The continuation rebuilds it; left stale it crashed 0.100.1 (`[rbp+0xa8]` = &clock).
    /// Found in the build's code by `tools/port/skipped_locals.py`.
    pub skipped_pointer_locals: &'static [[i64; 3]],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultEvaluation {
    pub lock: u64,
    pub last_phase: u64,
    pub account: u64,
    pub class_id: u64,
    pub victory: u64,
    pub sites: [u64; 2],
}

/// Enemy record layout. The record struct starts at +0x68 of an entry:
/// `u32 dead; <guid_gap bytes>; u64 guid; 96 bytes; f32 hp; 24 bytes;
/// f32 start[3]; f32 end[3]; f32 began; f32 duration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnemyLayout {
    pub stride: u64,
    pub guid_offset: u64,
    pub guid_gap: u64,
}

/// `game_field(legacy_offset)` accepts only these reviewed legacy offsets.
pub const GAME_FIELDS: [u64; 27] = [
    0x33C, 0x488, 0x498, 0x4A0, 0x4A8, 0x4F8, 0x4FC, 0x510, 0x514, 0x528, 0x568, 0x570, 0x5C8, 0x5E0, 0x618, 0x6D0,
    0x6D4, 0x730, 0x7F0, 0x7F8, 0x808, 0x85C, 0x860, 0x864, 0x894, 0x8B5, 0x8BF,
];

/// `updated_layout.ADDRESSES`: legacy RVA -> reviewed RVA (the reference build's address space).
pub const ADDRESSES: &[(u64, u64)] = &[
    (0x53FCC02, 0x5408372), (0x65EFA08, 0x6631EA0), (0x539FC26, 0x53C2246), (0x53A0160, 0x53C2780),
    (0x53DC9F5, 0x53E7625), (0x53DCA04, 0x53E7634), (0x53E1254, 0x53EC644), (0x53E1B4E, 0x53ECF3E),
    (0x53E1B5C, 0x53ECF4C), (0x53E2C7B, 0x53EE06B), (0x53E370A, 0x53EEB1E), (0x53E371B, 0x53EEB2F),
    (0x53EA3A8, 0x53F5808), (0x53F186E, 0x53FCCB7), (0x53F5FDB, 0x5401557), (0x566ED90, 0x568AC10),
    (0x6622698, 0x6663360), (0x5809A24, 0x581C4AC), (0x65F6848, 0x6638CE0), (0x6623E50, 0x6664B18),
    (0x53FF52B, 0x540ACBB), (0x53FF531, 0x540ACC1), (0x5402BF3, 0x540E4CD), (0x53E5580, 0x53F09C0),
    (0x53E5430, 0x53F0870), (0x53E6069, 0x53F14A9), (0x53E1898, 0x53ECC88), (0x53E1883, 0x53ECC73),
    (0x53FE9EC, 0x540A17C), (0x53FF2DF, 0x540AA6F), (0x53FF322, 0x540AAB2), (0x53FE96D, 0x540A0FD),
    (0x53FF014, 0x540A7A4), (0x53E75EF, 0x53F2A2F), (0x53E7D9E, 0x53F31DE), (0x53E7ED8, 0x53F3318),
    (0x53FE970, 0x540A100), (0x53EA280, 0x53F56E0), (0x53E3381, 0x53EE781), (0x53E2EB6, 0x53EE2A8),
    (0x53E6B22, 0x53F1F62),
];

/// `reviewed_rva(_reviewed(legacy))` for a legacy RVA: reviewed address, then this build's address.
pub fn reviewed(legacy: u64) -> Result<u64> {
    ADDRESSES.iter().find(|(l, _)| *l == legacy).map(|(_, r)| *r).ok_or_else(|| format!("Updated relocation not reviewed: {legacy:x}"))
}
