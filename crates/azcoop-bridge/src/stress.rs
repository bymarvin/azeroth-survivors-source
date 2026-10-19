//! Late-game stress test (cargo feature `test-hooks` only, never in a shipped DLL; release.ps1 refuses any AZCOOP_TEST_ string).
//! AZCOOP_TEST_STRESS=<json file> turns on, per the file: the run clock jumped to minute 25 at the host's first batch in the world,
//! the spawn bonus (population cap and spawn debt, 4.0 = 5x), immortal heroes (every HURT skipped), level-up picks by ability key and
//! a damage factor for one spell at the native DAMAGE entry (a jump to a cave: cmp r9d, spell; mulss xmm2, factor). Every address
//! and offset comes from that file, each with its reference (tools/port/stress/stress-<hash8>.json); none is written here.

use crate::client::{Client, Result};
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct DamageCave {
    pub entry_rva: u64,
    /// the build's own first bytes at the entry (whole instructions, no RIP-relative operand), checked before the jump goes in
    pub prologue: Vec<u8>,
    pub spell: u32,
    pub factor: f32,
}

#[derive(Debug, Clone, Default)]
pub struct Picks {
    /// Game-relative offset of the offered choices Vec (ptr, len)
    pub vector: u64,
    pub stride: u64,
    /// offset of the key's (ptr, len) inside an entry
    pub key: u64,
    /// an entry is an ability choice when its u64 at `tag` equals `ability_tag`
    pub tag: u64,
    pub ability_tag: u64,
    /// player number -> wanted keys, first match wins
    pub wanted: Vec<(u32, Vec<String>)>,
}

#[derive(Debug, Clone, Default)]
pub struct Stress {
    pub sha256: String,
    pub clock_seconds: Option<f32>,
    /// Game-relative offset of the next-wave time (f32), moved with the clock
    pub next_wave: Option<u64>,
    pub spawn_bonus: Option<f64>,
    /// XP the host gets once with the clock jump (native AWARD_XP; guests get it mirrored), so level-ups and picks happen
    pub xp_boost: Option<u64>,
    /// the host's victory choice when the run is won (8 = keep fighting), so the run goes on for the whole test
    pub victory_command: Option<u32>,
    pub godmode: bool,
    pub damage: Option<DamageCave>,
    pub picks: Option<Picks>,
}

fn num(v: &Value, key: &str) -> Option<u64> {
    let x = v.get(key)?;
    x.as_u64().or_else(|| x.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
}

fn hex_bytes(text: &str) -> std::result::Result<Vec<u8>, String> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len()).step_by(2).map(|i| u8::from_str_radix(clean.get(i..i + 2).ok_or("odd hex")?, 16).map_err(|e| e.to_string())).collect()
}

impl Stress {
    /// The configuration of AZCOOP_TEST_STRESS, or None. A file for another build than `sha256` is refused (an error).
    pub fn load(sha256: &str) -> Result<Option<Stress>> {
        let Ok(path) = std::env::var("AZCOOP_TEST_STRESS") else { return Ok(None) };
        let text = std::fs::read_to_string(&path).map_err(|e| format!("stress config {path}: {e}"))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("stress config {path}: {e}"))?;
        Stress::parse(&v, sha256).map(Some)
    }

    pub fn parse(v: &Value, sha256: &str) -> Result<Stress> {
        let file_sha = v["sha256"].as_str().unwrap_or("").to_lowercase();
        if file_sha.is_empty() || !sha256.to_lowercase().starts_with(&file_sha[..file_sha.len().min(64)]) {
            return Err(format!("stress config is for build {file_sha:.8}, the game is {sha256:.8}"));
        }
        let mut s = Stress { sha256: file_sha, godmode: v["godmode"].as_bool().unwrap_or(false), ..Default::default() };
        s.clock_seconds = v["clock_seconds"].as_f64().map(|x| x as f32);
        s.next_wave = num(v, "next_wave_field");
        s.spawn_bonus = v["spawn_bonus"].as_f64();
        s.xp_boost = v["xp_boost"].as_u64();
        s.victory_command = v["victory_command"].as_u64().map(|c| c as u32);
        if let Some(d) = v.get("damage").filter(|d| d.is_object()) {
            s.damage = Some(DamageCave {
                entry_rva: num(d, "entry_rva").ok_or("damage.entry_rva")?,
                prologue: hex_bytes(d["prologue"].as_str().ok_or("damage.prologue")?)?,
                spell: num(d, "spell").ok_or("damage.spell")? as u32,
                factor: d["factor"].as_f64().ok_or("damage.factor")? as f32,
            });
            if s.damage.as_ref().unwrap().prologue.len() < 14 {
                return Err("damage.prologue must hold at least the 14 bytes the jump replaces".into());
            }
        }
        if let Some(p) = v.get("picks").filter(|p| p.is_object()) {
            let mut wanted = Vec::new();
            if let Some(map) = p["wanted"].as_object() {
                for (player, keys) in map {
                    let keys: Vec<String> = keys.as_array().map(|a| a.iter().filter_map(|k| k.as_str().map(String::from)).collect()).unwrap_or_default();
                    wanted.push((player.parse::<u32>().map_err(|_| "picks.wanted keys are player numbers")?, keys));
                }
            }
            s.picks = Some(Picks { vector: num(p, "vector_field").ok_or("picks.vector_field")?, stride: num(p, "stride").ok_or("picks.stride")?,
                                   key: num(p, "key_offset").ok_or("picks.key_offset")?, tag: num(p, "tag_offset").ok_or("picks.tag_offset")?,
                                   ability_tag: num(p, "ability_tag").ok_or("picks.ability_tag")?, wanted });
        }
        Ok(s)
    }

    /// The machine code of the damage cave at `cave` (absolute): factor at the end, the moved prologue, the jump back.
    pub fn damage_cave_code(d: &DamageCave, base: u64, cave: u64) -> Vec<u8> {
        let mut code = Vec::new();
        code.extend([0x41, 0x81, 0xF9]); // cmp r9d, imm32
        code.extend(d.spell.to_le_bytes());
        code.extend([0x75, 0x10]); // jne over push, mov, mulss, pop (16 bytes)
        code.push(0x50); // push rax
        code.extend([0x48, 0xB8]); // mov rax, imm64 (the factor's address, patched below)
        let factor_slot = code.len();
        code.extend(0u64.to_le_bytes());
        code.extend([0xF3, 0x0F, 0x59, 0x10]); // mulss xmm2, [rax]
        code.push(0x58); // pop rax
        code.extend(&d.prologue);
        code.extend(azcoop_patch::absolute_jump(base + d.entry_rva + d.prologue.len() as u64));
        let factor_at = cave + code.len() as u64;
        code.extend(d.factor.to_le_bytes());
        code[factor_slot..factor_slot + 8].copy_from_slice(&factor_at.to_le_bytes());
        code
    }

    /// Puts the damage cave in (host, first TICK): the entry must still hold the configured prologue.
    pub fn install_damage(&self, client: &mut dyn Client) -> Result<()> {
        let Some(d) = &self.damage else { return Ok(()) };
        let base = client.base();
        let live = client.memory(base + d.entry_rva, d.prologue.len())?;
        if live != d.prologue {
            return Err("stress: the DAMAGE entry does not hold the configured prologue".into());
        }
        // the cave address is only known after the buffer exists: build once with a placeholder, then rebuild at the real address
        let probe = Stress::damage_cave_code(d, base, 0);
        let cave = client.executable_buffer(&probe, Some(base + d.entry_rva))?;
        let code = Stress::damage_cave_code(d, base, cave);
        client.put(cave, &code)?;
        let mut jump = azcoop_patch::absolute_jump(cave);
        jump.resize(d.prologue.len(), 0x90);
        client.patch(base + d.entry_rva, &jump)?;
        client.record(azcoop_logic::Event::new("test_stress_damage_cave").num("spell", d.spell as f64).num("factor", d.factor as f64));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_parses_and_refuses_another_build() {
        let v: Value = serde_json::json!({"sha256": "17abcc4c", "clock_seconds": 1500.0, "next_wave_field": "0x994", "spawn_bonus": 4.0, "godmode": true,
            "damage": {"entry_rva": "0x54d4ff0", "prologue": "0102030405060708090a0b0c0d0e", "spell": 5308, "factor": 10.0},
            "picks": {"vector_field": "0x588", "stride": "0xa0", "key_offset": "0x80", "tag_offset": "0x78", "ability_tag": "0x8000000000000000",
                      "wanted": {"1": ["execute"], "2": ["holy_nova"]}}});
        let s = Stress::parse(&v, &format!("17abcc4c{}", "0".repeat(56))).unwrap();
        assert_eq!((s.next_wave, s.spawn_bonus, s.godmode), (Some(0x994), Some(4.0), true));
        assert_eq!(s.picks.as_ref().unwrap().wanted.len(), 2);
        assert!(Stress::parse(&v, &"d1bb8a08".repeat(8)).is_err(), "a file for another build is refused");
        let d = s.damage.unwrap();
        let code = Stress::damage_cave_code(&d, 0x7FF7_0000_0000, 0x1000);
        assert_eq!(&code[..3], &[0x41, 0x81, 0xF9]);
        assert_eq!(u32::from_le_bytes(code[3..7].try_into().unwrap()), 5308);
        assert_eq!(f32::from_le_bytes(code[code.len() - 4..].try_into().unwrap()), 10.0);
        // the jne skips exactly push/mov/mulss/pop
        assert_eq!(code[8] as usize, 1 + 10 + 4 + 1);
    }
}

#[cfg(test)]
mod config_file {
    #[test]
    fn the_017abcc4c_config_builds_a_cave() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/port/stress/stress-17abcc4c.json");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let s = super::Stress::parse(&v, "17abcc4caad41f4150b0a05cc9bf8c428a4666121c49091db19f887a9b79eb7b").unwrap();
        let d = s.damage.unwrap();
        let code = super::Stress::damage_cave_code(&d, 0x7FF6_0000_0000, 0x7FF6_1000_0000);
        println!("CAVE {}", code.iter().map(|b| format!("{b:02x}")).collect::<String>());
        assert_eq!(d.prologue.len(), 19);
    }
}
