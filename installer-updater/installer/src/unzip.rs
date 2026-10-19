//! Unpack the signed runtime archive (a plain ZIP: stored or deflate) without tar.exe (absent under Wine).
//!
//! The archive's SHA-256 is checked against the signed release before this runs. Still, every member is checked:
//! relative paths only (no drive, no "..", no absolute path), no encryption, sizes and CRC-32 as declared, and the
//! whole archive at most `limit` bytes unpacked.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

fn u16_at(data: &[u8], at: usize) -> usize {
    u16::from_le_bytes([data[at], data[at + 1]]) as usize
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (n, entry) in table.iter_mut().enumerate() {
        let mut c = n as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        *entry = c;
    }
    !data.iter().fold(!0u32, |c, &b| table[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8))
}

/// The member's path below `root`, or an error for anything that could leave it.
fn member_path(root: &Path, name: &str) -> Result<PathBuf, String> {
    let name = name.replace('\\', "/");
    let relative = Path::new(&name);
    if name.is_empty() || name.contains(':') || name.starts_with('/') ||
            relative.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(format!("unsafe path in the runtime archive: {name}"));
    }
    Ok(root.join(relative))
}

/// Unpack every member into `root`; returns the number of files.
pub fn extract(archive: &Path, root: &Path, limit: u64) -> Result<usize, String> {
    let mut file = File::open(archive).map_err(|e| e.to_string())?;
    let length = file.metadata().map_err(|e| e.to_string())?.len();
    let tail = length.min(65_557) as usize;
    let mut end = vec![0u8; tail];
    file.seek(SeekFrom::Start(length - tail as u64)).map_err(|e| e.to_string())?;
    file.read_exact(&mut end).map_err(|e| e.to_string())?;
    let eocd = (0..=tail.saturating_sub(22)).rev().find(|&i| u32_at(&end, i) == 0x0605_4b50)
        .ok_or("the runtime archive is not a ZIP file")?;
    let (count, directory_size, directory_at) =
        (u16_at(&end, eocd + 10), u32_at(&end, eocd + 12) as u64, u32_at(&end, eocd + 16) as u64);
    if directory_at + directory_size > length || count == 0xFFFF {
        return Err("the runtime archive's directory is damaged".into());
    }
    let mut directory = vec![0u8; directory_size as usize];
    file.seek(SeekFrom::Start(directory_at)).map_err(|e| e.to_string())?;
    file.read_exact(&mut directory).map_err(|e| e.to_string())?;
    let (mut at, mut files, mut total) = (0usize, 0usize, 0u64);
    for _ in 0..count {
        if at + 46 > directory.len() || u32_at(&directory, at) != 0x0201_4b50 {
            return Err("the runtime archive's directory is damaged".into());
        }
        let (flags, method, crc) = (u16_at(&directory, at + 8), u16_at(&directory, at + 10), u32_at(&directory, at + 16));
        let (packed, size) = (u32_at(&directory, at + 20) as u64, u32_at(&directory, at + 24) as u64);
        let (name_length, extra, comment) = (u16_at(&directory, at + 28), u16_at(&directory, at + 30), u16_at(&directory, at + 32));
        let local = u32_at(&directory, at + 42) as u64;
        let name = String::from_utf8(directory.get(at + 46..at + 46 + name_length).ok_or("damaged name")?.to_vec())
            .map_err(|_| "a member name is not UTF-8".to_string())?;
        at += 46 + name_length + extra + comment;
        let target = member_path(root, &name)?;
        if name.ends_with('/') {
            fs::create_dir_all(&target).map_err(|e| format!("cannot create {}: {e}", target.display()))?;
            continue;
        }
        if flags & 1 != 0 || !matches!(method, 0 | 8) || packed == 0xFFFF_FFFF || size == 0xFFFF_FFFF {
            return Err(format!("{name}: unsupported ZIP member (encrypted, method {method} or ZIP64)"));
        }
        total += size;
        if total > limit {
            return Err("the runtime archive unpacks larger than allowed".into());
        }
        let mut header = [0u8; 30];
        file.seek(SeekFrom::Start(local)).map_err(|e| e.to_string())?;
        file.read_exact(&mut header).map_err(|e| e.to_string())?;
        if u32_at(&header, 0) != 0x0403_4b50 {
            return Err(format!("{name}: damaged local header"));
        }
        let data_at = local + 30 + u16_at(&header, 26) as u64 + u16_at(&header, 28) as u64;
        if data_at + packed > length {
            return Err(format!("{name}: data beyond the archive"));
        }
        let mut data = vec![0u8; packed as usize];
        file.seek(SeekFrom::Start(data_at)).map_err(|e| e.to_string())?;
        file.read_exact(&mut data).map_err(|e| e.to_string())?;
        let content = if method == 0 { data } else {
            miniz_oxide::inflate::decompress_to_vec_with_limit(&data, size as usize)
                .map_err(|_| format!("{name}: damaged or larger than declared"))?
        };
        if content.len() as u64 != size || crc32(&content) != crc {
            return Err(format!("{name}: size or CRC-32 does not match"));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        fs::write(&target, content).map_err(|e| format!("cannot write {}: {e}", target.display()))?;
        files += 1;
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ZIP written by hand: one stored and one deflated member (miniz_oxide compresses).
    fn archive(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let (mut body, mut directory) = (Vec::new(), Vec::new());
        for (name, data, deflate) in entries {
            let packed = if *deflate { miniz_oxide::deflate::compress_to_vec(data, 6) } else { data.to_vec() };
            let method: u16 = if *deflate { 8 } else { 0 };
            let offset = body.len() as u32;
            let mut header = Vec::new();
            header.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            header.extend_from_slice(&[20, 0, 0, 0]);
            header.extend_from_slice(&method.to_le_bytes());
            header.extend_from_slice(&[0, 0, 0, 0]);
            header.extend_from_slice(&crc32(data).to_le_bytes());
            header.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            header.extend_from_slice(&(data.len() as u32).to_le_bytes());
            header.extend_from_slice(&(name.len() as u16).to_le_bytes());
            header.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&header);
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&packed);
            directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            directory.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            directory.extend_from_slice(&method.to_le_bytes());
            directory.extend_from_slice(&[0, 0, 0, 0]);
            directory.extend_from_slice(&crc32(data).to_le_bytes());
            directory.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
            directory.extend_from_slice(&[0; 12]);
            directory.extend_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(name.as_bytes());
        }
        let at = body.len() as u32;
        let count = entries.len() as u16;
        body.extend_from_slice(&directory);
        body.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.extend_from_slice(&count.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        body.extend_from_slice(&(directory.len() as u32).to_le_bytes());
        body.extend_from_slice(&at.to_le_bytes());
        body.extend_from_slice(&[0, 0]);
        body
    }

    fn folder(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("azs-unzip-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn stored_and_deflated_members() {
        let root = folder("ok");
        let big = b"runtime ".repeat(10_000);
        fs::write(root.join("a.zip"), archive(&[(".coop-runtime/python.exe", b"MZ stub", false),
                                                 (".coop-runtime/Lib/os.py", &big, true)])).unwrap();
        assert_eq!(extract(&root.join("a.zip"), &root.join("out"), 1 << 30).unwrap(), 2);
        assert_eq!(fs::read(root.join("out/.coop-runtime/Lib/os.py")).unwrap(), big);
        assert_eq!(fs::read(root.join("out/.coop-runtime/python.exe")).unwrap(), b"MZ stub");
    }

    #[test]
    fn unsafe_damaged_or_oversized_archives_are_refused() {
        let root = folder("bad");
        for (name, bytes) in [("escape", archive(&[("../evil.txt", b"x", false)])),
                              ("absolute", archive(&[("C:/evil.txt", b"x", false)])),
                              ("big", archive(&[("big.bin", &[0u8; 4096], true)]))] {
            fs::write(root.join(name), bytes).unwrap();
            assert!(extract(&root.join(name), &root.join("out"), 1024).is_err(), "{name}");
        }
        let mut damaged = archive(&[("f.txt", b"hello world hello world", true)]);
        damaged[35] ^= 0xFF;
        fs::write(root.join("damaged"), damaged).unwrap();
        assert!(extract(&root.join("damaged"), &root.join("out"), 1 << 20).is_err());
        assert!(!root.join("evil.txt").exists() && !root.join("out/../evil.txt").exists());
    }

    #[test]
    fn crc32_reference() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
