//! A minimal, bounds-checked PE32+ reader: sections and RVA to file bytes.

use crate::Result;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

pub struct Pe<'a> {
    data: &'a [u8],
    pub image_base: u64,
    pub image_size: u32,
    pub sections: Vec<Section>,
}

fn u16_at(d: &[u8], at: usize) -> Result<u16> {
    d.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| "truncated PE".to_string())
}
fn u32_at(d: &[u8], at: usize) -> Result<u32> {
    d.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or_else(|| "truncated PE".to_string())
}

impl<'a> Pe<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Pe<'a>> {
        if data.get(..2) != Some(b"MZ") {
            return Err("not a PE file".into());
        }
        let nt = u32_at(data, 0x3C)? as usize;
        if data.get(nt..nt + 4) != Some(b"PE\0\0") {
            return Err("missing PE signature".into());
        }
        let count = u16_at(data, nt + 6)? as usize;
        let optional_size = u16_at(data, nt + 20)? as usize;
        let optional = nt + 24;
        if u16_at(data, optional)? != 0x20B {
            return Err("not a PE32+ image".into());
        }
        let image_base = u64::from_le_bytes(
            data.get(optional + 24..optional + 32).ok_or("truncated PE")?.try_into().unwrap(),
        );
        let image_size = u32_at(data, optional + 56)?;
        let table = optional + optional_size;
        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let at = table + i * 40;
            let name_bytes = data.get(at..at + 8).ok_or("truncated section table")?;
            let end = name_bytes.iter().position(|b| *b == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
                virtual_size: u32_at(data, at + 8)?,
                virtual_address: u32_at(data, at + 12)?,
                raw_size: u32_at(data, at + 16)?,
                raw_offset: u32_at(data, at + 20)?,
                characteristics: u32_at(data, at + 36)?,
            });
        }
        Ok(Pe { data, image_base, image_size, sections })
    }

    /// The file bytes backing `len` bytes at `rva`, if one section holds them all.
    pub fn bytes_at(&self, rva: u64, len: usize) -> Result<&'a [u8]> {
        let section = self
            .sections
            .iter()
            .find(|s| rva >= s.virtual_address as u64 && rva < s.virtual_address as u64 + s.virtual_size.max(s.raw_size) as u64)
            .ok_or_else(|| format!("RVA {rva:#x} is in no section"))?;
        let inside = rva - section.virtual_address as u64;
        if inside + len as u64 > section.raw_size as u64 {
            return Err(format!("RVA {rva:#x}+{len} is not file-backed"));
        }
        let start = section.raw_offset as usize + inside as usize;
        self.data.get(start..start + len).ok_or_else(|| "section beyond end of file".to_string())
    }

    /// True if the section holding `rva` is executable.
    pub fn is_code(&self, rva: u64) -> bool {
        self.sections
            .iter()
            .find(|s| rva >= s.virtual_address as u64 && rva < s.virtual_address as u64 + s.virtual_size as u64)
            .is_some_and(|s| s.characteristics & 0x2000_0000 != 0)
    }
}
