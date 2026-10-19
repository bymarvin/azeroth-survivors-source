// Embed an application manifest: run as the invoking user (no admin prompt; without it Windows
// installer detection would ask for admin rights because of "installer" in the name) and with the Windows 10/11 compatibility id.
fn main() {
    println!("cargo:rerun-if-env-changed=COOP_INSTALLER_TEST_KEY");
    let out = std::env::var("OUT_DIR").unwrap();
    let manifest = std::path::Path::new(&out).join("installer.manifest");
    std::fs::write(&manifest, r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="AzerothSurvivorsTogether.Installer" version="1.0.0.0"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application>
  </compatibility>
</assembly>
"#).unwrap();
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}", manifest.display());
    resources("Azeroth Survivors Together installer", "Azeroth-Survivors-Together-Installer.exe");
}

// Windows resources: VERSIONINFO (company, product, description, version from COOP-VERSION.txt, MIT) and the
// icon coop-lab/azsurvivors.ico, compiled with the Windows SDK's rc.exe (no extra crates). Unsigned exes with
// complete version information, an icon and no packer trigger fewer heuristic antivirus alarms.
// Reproducible: /Brepro (no time stamp), /PDBALTPATH:%_PDB% (the separate PDB by name only, no build path).
fn resources(description: &str, original: &str) {
    use std::path::{Path, PathBuf};
    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = crate_dir.ancestors().find(|d| d.join("COOP-VERSION.txt").is_file())
        .expect("COOP-VERSION.txt not found above the crate").to_path_buf();
    let version_file = root.join("COOP-VERSION.txt");
    let icon = root.join("coop-lab").join("azsurvivors.ico");
    println!("cargo:rerun-if-changed={}", version_file.display());
    println!("cargo:rerun-if-changed={}", icon.display());
    let text = std::fs::read_to_string(&version_file).unwrap();
    let release = text.trim().split('-').next().unwrap().to_string();
    let mut numbers: Vec<u32> = release.split('.').map(|n| n.parse().expect("numeric COOP-VERSION")).collect();
    numbers.resize(4, 0);
    let commas = numbers.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    let dotted = numbers.iter().map(u32::to_string).collect::<Vec<_>>().join(".");
    let escape = |p: &Path| p.display().to_string().replace('\\', "\\\\");
    let script = format!(r#"1 ICON "{icon}"
1 VERSIONINFO
FILEVERSION {commas}
PRODUCTVERSION {commas}
FILEFLAGSMASK 0x3F
FILEFLAGS 0x0
FILEOS 0x40004
FILETYPE 0x1
FILESUBTYPE 0x0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "Azeroth Survivors Together"
      VALUE "FileDescription", "{description}"
      VALUE "FileVersion", "{dotted}"
      VALUE "InternalName", "{original}"
      VALUE "LegalCopyright", "MIT"
      VALUE "OriginalFilename", "{original}"
      VALUE "ProductName", "Azeroth Survivors Together"
      VALUE "ProductVersion", "{release}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#, icon = escape(&icon));
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out.join("resources.rc"), script).unwrap();
    let rc = std::env::var_os("RC_EXE").map(PathBuf::from).or_else(|| {
        let kits = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
        let mut found: Vec<PathBuf> = std::fs::read_dir(kits).ok()?.filter_map(Result::ok)
            .map(|e| e.path().join("x64").join("rc.exe")).filter(|p| p.is_file()).collect();
        found.sort();
        found.pop()
    }).expect("rc.exe of the Windows SDK not found (set RC_EXE)");
    let status = std::process::Command::new(&rc).arg("/nologo").arg("/fo").arg(out.join("resources.res"))
        .arg(out.join("resources.rc")).status().expect("rc.exe could not be started");
    assert!(status.success(), "rc.exe failed");
    println!("cargo:rustc-link-arg-bins={}", out.join("resources.res").display());
    println!("cargo:rustc-link-arg-bins=/Brepro");
    println!("cargo:rustc-link-arg-bins=/PDBALTPATH:%_PDB%");
}
