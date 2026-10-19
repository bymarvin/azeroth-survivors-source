//! Build script: forwards every export of the system avrt.dll and embeds the
//! version resource.
//!
//! The export list is committed in res/avrt-exports.txt (taken from %SystemRoot%\System32\avrt.dll),
//! so the proxy never misses a function. Every export is a PE forwarder to the
//! system DLL by its full path: the Windows loader resolves it, this DLL
//! contains no wrapper code for them.

use std::{env, fs, path::PathBuf};

fn u16_at(b: &[u8], o: usize) -> usize {
    u16::from_le_bytes([b[o], b[o + 1]]) as usize
}

fn u32_at(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize
}

fn c_str(b: &[u8], o: usize) -> String {
    let end = b[o..].iter().position(|&c| c == 0).expect("unterminated export name");
    String::from_utf8(b[o..o + end].to_vec()).expect("export name is not UTF-8")
}

/// (ordinal, name) of every named export of a PE32+ image.
fn exports(image: &[u8]) -> Vec<(usize, String)> {
    let pe = u32_at(image, 0x3c);
    assert_eq!(&image[pe..pe + 4], b"PE\0\0", "not a PE image");
    let sections = u16_at(image, pe + 6);
    let optional_size = u16_at(image, pe + 20);
    let optional = pe + 24;
    assert_eq!(u16_at(image, optional), 0x20b, "not a 64-bit image");
    let table = optional + optional_size;
    let to_offset = |rva: usize| -> usize {
        for i in 0..sections {
            let s = table + 40 * i;
            let (vsize, va, raw_size, raw) =
                (u32_at(image, s + 8), u32_at(image, s + 12), u32_at(image, s + 16), u32_at(image, s + 20));
            if va <= rva && rva < va + vsize.max(raw_size) {
                return rva - va + raw;
            }
        }
        panic!("RVA {rva:#x} is outside every section");
    };
    let directory = to_offset(u32_at(image, optional + 112));
    let base = u32_at(image, directory + 16);
    let names = u32_at(image, directory + 24);
    let name_table = to_offset(u32_at(image, directory + 32));
    let ordinal_table = to_offset(u32_at(image, directory + 36));
    let mut list: Vec<(usize, String)> = (0..names)
        .map(|i| {
            let name = c_str(image, to_offset(u32_at(image, name_table + 4 * i)));
            (base + u16_at(image, ordinal_table + 2 * i), name)
        })
        .collect();
    list.sort();
    list
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=res/version.res");
    println!("cargo:rerun-if-changed=res/avrt-exports.txt");
    println!("cargo:rerun-if-env-changed=AZCOOP_AVRT_FROM_SYSTEM");

    // The export list is committed (res/avrt-exports.txt): a build never reads the build machine's System32 (cross builds on Linux,
    // reproducible output). AZCOOP_AVRT_FROM_SYSTEM=1 on a Windows machine compares it with the system DLL and fails on a difference.
    let committed = fs::read_to_string("res/avrt-exports.txt").expect("res/avrt-exports.txt");
    let mut list: Vec<(usize, String)> = committed
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (ordinal, name) = l.trim().split_once(' ').expect("'ordinal name' per line");
            (ordinal.parse().expect("ordinal"), name.to_string())
        })
        .collect();
    list.sort();
    assert!(list.iter().any(|(_, n)| n == "AvSetMmThreadCharacteristicsW"), "unexpected avrt.dll export list");
    if env::var("AZCOOP_AVRT_FROM_SYSTEM").is_ok_and(|v| v == "1") {
        let root = env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let system = PathBuf::from(&root).join(r"System32\avrt.dll");
        let image = fs::read(&system).unwrap_or_else(|e| panic!("cannot read {}: {e}", system.display()));
        assert_eq!(exports(&image), list, "the system avrt.dll exports differ from res/avrt-exports.txt: update the file");
    }
    // The forwarders name the standard system folder; the DLL warns at runtime when %SystemRoot% is elsewhere.
    let system_root = r"C:\Windows";

    let mut report = String::new();
    for (ordinal, name) in &list {
        // Absolute path of the system DLL: a bare "avrt.X" would resolve back
        // to this module. This is the build machine's %SystemRoot%
        // (C:\Windows on standard installs; checked at runtime). Linked with
        // rust-lld (.cargo/config.toml): MSVC link.exe 14.51 treats the
        // forwarder target as a symbol and fails with LNK2001.
        println!(r"cargo:rustc-cdylib-link-arg=/EXPORT:{name}={system_root}\System32\avrt.{name},@{ordinal}");
        report.push_str(&format!("{ordinal} {name}\n"));
    }
    println!("cargo:rustc-env=AZCOOP_FORWARD_ROOT={system_root}");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out.join("avrt-exports.txt"), report).unwrap();

    // The version resource is committed compiled (res/version.res, made from res/version.rc with rc.exe or llvm-rc): no resource
    // compiler in the build, the same bytes on every build machine. lld-link takes a .res file as input.
    let res = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("res").join("version.res");
    println!("cargo:rustc-cdylib-link-arg={}", res.display());
}
