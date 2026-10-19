//! Generated machine code and byte patches of the co-op adapter, per game build.
//!
//! A port of the generators in `visibility_bridge.py`, `native_guest_combat.py` and
//! `updated_layout.py`. The output must equal the Python's byte for byte for every
//! supported build (differential tests against the verbatim generators), because the
//! patches sit in the running game's code.
//!
//! Everything here is pure: the bytes the Python reads from the candidate executable
//! (`expected_bytes`) come through the [`Image`] trait, and addresses of buffers the
//! caller allocates in the game process are plain parameters.

use azcoop_game::builds::{Family, Variant, ADDRESSES};
use azcoop_game::profile::Profile;

pub mod damage;
pub mod guards;
pub mod install;
pub mod pursuit;
pub mod recycle;
pub mod ui;
pub mod world;

pub type Result<T> = std::result::Result<T, String>;

/// Code bytes of the candidate executable by RVA (the Python's `candidate.get_data`).
pub trait Image {
    fn bytes(&self, rva: u64, len: usize) -> Result<Vec<u8>>;
}

/// One supported build: its profile, its code and the build-family predicates.
pub struct Ctx<'a> {
    pub variant: Variant,
    pub profile: &'a Profile,
    pub image: &'a dyn Image,
}

pub fn hx(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len()).step_by(2).map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("hex literal")).collect()
}

pub fn absolute_jump(address: u64) -> Vec<u8> {
    let mut out = vec![0xFF, 0x25, 0, 0, 0, 0];
    out.extend_from_slice(&address.to_le_bytes());
    out
}

/// `struct.pack('<I', v)` of a value that may be out of range.
pub fn pack_u32(v: i128) -> Result<[u8; 4]> {
    u32::try_from(v).map(|x| x.to_le_bytes()).map_err(|_| "'I' format requires 0 <= number <= 4294967295".to_string())
}

pub fn pack_i32(v: i128) -> Result<[u8; 4]> {
    i32::try_from(v).map(|x| x.to_le_bytes()).map_err(|_| "'i' format requires -2147483648 <= number <= 2147483647".to_string())
}

pub fn pack_u64(v: i128) -> Result<[u8; 8]> {
    u64::try_from(v).map(|x| x.to_le_bytes()).map_err(|_| "'Q' format requires 0 <= number <= 18446744073709551615".to_string())
}

/// `branch_bytes(source, target, opcode=..., size=...)`: an already-translated branch.
pub fn branch_bytes(source: u64, target: u64, opcode: &[u8], size: usize) -> Result<Vec<u8>> {
    let short = opcode.len() == 1 && (opcode[0] == 0xEB || (0x70..=0x7F).contains(&opcode[0]));
    let long = opcode == [0xE8] || opcode == [0xE9] || (opcode.len() == 2 && opcode[0] == 0x0F && (0x80..=0x8F).contains(&opcode[1]));
    let width = if short { 1 } else { 4 };
    if !(short || long) || size < opcode.len() + width {
        return Err("Unsupported generated branch encoding".into());
    }
    let operand = target as i128 - source as i128 - opcode.len() as i128 - width as i128;
    let limit = 1i128 << (width * 8 - 1);
    if !(-limit..limit).contains(&operand) {
        return Err("Relocated branch is out of range; a reviewed trampoline is required".into());
    }
    let mut out = opcode.to_vec();
    out.extend_from_slice(&operand.to_le_bytes()[..width]);
    out.resize(size, 0x90);
    Ok(out)
}

/// A snippet of code whose structure-field displacements can be translated per build:
/// `code_fields(code, domain, registers)` of `updated_layout.py`, with the memory
/// operands declared instead of decoded.
#[derive(Debug, Clone, Default)]
pub struct Snip {
    pub bytes: Vec<u8>,
    marks: Vec<Mark>,
}

#[derive(Debug, Clone)]
struct Mark {
    at: usize,
    width: usize,
    reg: &'static str,
}

pub enum P<'a> {
    /// Literal instruction bytes (hex).
    Raw(&'a str),
    /// A displacement of a memory operand on `reg` (`width` 1 or 4 bytes).
    Mem(i64, usize, &'static str),
}

impl Snip {
    /// Append literal instruction bytes (hex).
    pub fn raw(&mut self, text: &str) -> &mut Snip {
        self.bytes.extend(hx(text));
        self
    }

    /// Append a displacement of a memory operand on `reg`.
    pub fn mem(&mut self, disp: i64, width: usize, reg: &'static str) -> &mut Snip {
        self.marks.push(Mark { at: self.bytes.len(), width, reg });
        self.bytes.extend_from_slice(&disp.to_le_bytes()[..width]);
        self
    }

    pub fn new(pieces: &[P]) -> Snip {
        let mut snip = Snip::default();
        for piece in pieces {
            match piece {
                P::Raw(text) => snip.bytes.extend(hx(text)),
                P::Mem(disp, width, reg) => {
                    snip.marks.push(Mark { at: snip.bytes.len(), width: *width, reg });
                    snip.bytes.extend_from_slice(&disp.to_le_bytes()[..*width]);
                }
            }
        }
        snip
    }

    /// `code_fields(code, domain, registers)`: translate the displacements owned by `registers`.
    pub fn fields(mut self, ctx: &Ctx, domain: &str, registers: &[&str]) -> Result<Snip> {
        for mark in &self.marks {
            if !registers.contains(&mark.reg) {
                continue;
            }
            let raw = &self.bytes[mark.at..mark.at + mark.width];
            let before: i64 = if mark.width == 1 { raw[0] as i8 as i64 } else { i32::from_le_bytes(raw.try_into().unwrap()) as i64 };
            let after = ctx.field(domain, before)?;
            if after == before {
                continue;
            }
            let limit = 1i64 << (8 * mark.width - 1);
            if !(-limit..limit).contains(&after) {
                return Err("Native field relocation needs a different instruction encoding".into());
            }
            let at = mark.at;
            self.bytes[at..at + mark.width].copy_from_slice(&after.to_le_bytes()[..mark.width]);
        }
        Ok(self)
    }

    /// `game_frame_code(code)`: the update-frame slots addressed through RBP.
    pub fn game_frame(self, ctx: &Ctx) -> Result<Snip> {
        self.fields(ctx, "game_update_frame", &["rbp"])
    }
}

impl<'a> Ctx<'a> {
    pub fn is_0843(&self) -> bool {
        self.variant == Variant::V0843
    }
    pub fn is_47e4(&self) -> bool {
        self.variant.is_47e4()
    }
    pub fn is_0931(&self) -> bool {
        self.variant.is_0931()
    }
    pub fn is_7264(&self) -> bool {
        self.variant.is_7264_family()
    }

    pub fn family(&self) -> Result<Family> {
        self.variant.family().ok_or_else(|| "this build has no 47e4 family constants".to_string())
    }

    /// `reviewed_rva(address)`: an explicit reviewed RVA in this build.
    pub fn reviewed_rva(&self, reviewed: u64) -> Result<u64> {
        self.profile.addresses.get(&reviewed).copied().ok_or_else(|| format!("profile has no address for {reviewed:#x}"))
    }

    /// `relocated(legacy)` / `updated_layout.rva(legacy)`.
    pub fn rva(&self, legacy: u64) -> Result<u64> {
        let reviewed = ADDRESSES.iter().find(|(l, _)| *l == legacy).map(|(_, r)| *r).ok_or_else(|| format!("Updated relocation not reviewed: {legacy:x}"))?;
        self.reviewed_rva(reviewed)
    }

    /// `reviewed_bytes(address, expected)`: the build's own code at the translated address.
    pub fn reviewed_bytes(&self, reviewed: u64, expected: &[u8]) -> Result<Vec<u8>> {
        // a typed adapter profile carries the candidate's own bytes for every patch precondition (`patch_preconditions`)
        if !self.profile.patches.is_empty() {
            return self.profile.patches.get(&(reviewed, expected.to_vec())).cloned().ok_or_else(|| format!("Unresolved adapter patch at {reviewed:x}"));
        }
        let actual = self.image.bytes(self.reviewed_rva(reviewed)?, expected.len())?;
        if actual.len() != expected.len() {
            return Err("Truncated relocated patch".into());
        }
        Ok(actual)
    }

    /// `expected_bytes(legacy, expected)`.
    pub fn expected_bytes(&self, legacy: u64, expected: &[u8]) -> Result<Vec<u8>> {
        let reviewed = ADDRESSES.iter().find(|(l, _)| *l == legacy).map(|(_, r)| *r).ok_or_else(|| format!("Updated relocation not reviewed: {legacy:x}"))?;
        self.reviewed_bytes(reviewed, expected)
    }

    /// `field(domain, reviewed_offset)`.
    pub fn field(&self, domain: &str, reviewed_offset: i64) -> Result<i64> {
        if domain.is_empty() || reviewed_offset < 0 {
            return Err("Invalid native field contract".into());
        }
        let translated = self.profile.field(domain, reviewed_offset)?;
        if translated < 0 && !domain.ends_with("_frame") {
            return Err(format!("Unresolved native field {domain}+{reviewed_offset:x}"));
        }
        Ok(translated)
    }

    /// `game_field(legacy_offset)`: only the reviewed legacy offsets of the Game object.
    pub fn game_field(&self, legacy: u64) -> Result<u64> {
        if !azcoop_game::builds::GAME_FIELDS.contains(&legacy) {
            return Err("Updated game field has not been reviewed".into());
        }
        Ok(self.field("game", legacy as i64 + 0x10)? as u64)
    }

    /// `reviewed_branch(source, target, ...)`: both endpoints are reviewed RVAs.
    pub fn reviewed_branch(&self, source: u64, target: u64, opcode: &[u8], size: usize) -> Result<Vec<u8>> {
        branch_bytes(self.reviewed_rva(source)?, self.reviewed_rva(target)?, opcode, size)
    }
}
