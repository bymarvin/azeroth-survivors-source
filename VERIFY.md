# Verify the released binaries against this source

The native binaries are built **reproducibly**: the same source + the same pinned toolchain produce the same bytes on
any machine, so you can rebuild them yourself and check the hash matches the release.

## Released SHA-256

| File | SHA-256 | Built from |
|---|---|---|
| `avrt.dll` (native co-op engine) | `34bb35d2a3fc42ede1e821ea963c99df38bb695f3d88b089c8a7aed5c5c9855a` | this repo — `cargo … -p azeroth-coop-native` |
| `azcoop-net.exe` (network helper) | `07317673dc3141e1076d26ce4a889d47304d8788ba045b2ecfe1330920dd7ad5` | this repo — `cargo … -p azcoop-net` |
| Installer | `84e75f33…` | the installer crate — **not yet in this repo** (see note) |
| Updater (format 7) | `99f07188…` | the updater crate — **not yet in this repo** (see note) |

> Note: the Rust installer and updater crates live in the launcher release repo, not the DLL workspace; add their
> sources before publishing so these two hashes can be reproduced here too. The Python updater that ships in the
> package is in `launcher/reconstruction/self_update.py`.

Verified reproduction of `avrt.dll` and `azcoop-net.exe` from this repo alone: both hashes above match (see CI,
`.github/workflows/audit.yml`, and `scripts/reproduce.ps1`).

## How to reproduce (Windows, the shipped build)

1. Install Rust via rustup. The toolchain is pinned in `rust-toolchain.toml` (**1.99.0**, with `rust-src`/MSVC as
   needed); rustup installs it automatically on first build. Use the MSVC toolchain (`x86_64-pc-windows-msvc`).
2. From the repo root run the release build (it sets the reproducibility flags for you):

   ```powershell
   powershell -NoProfile -File tools\build\release.ps1
   ```

   It builds with `cargo build --release --locked -p azeroth-coop-native -p azcoop-net` and
   `RUSTFLAGS = --remap-path-prefix=<repo>=/azcoop --remap-path-prefix=<cargo home>=/cargo`
   `--remap-path-prefix=<rust sysroot>=/rust -C debuginfo=0 -C link-arg=/DEBUG:NONE -C link-arg=/TIMESTAMP:1`,
   then prints each binary's SHA-256 and checks there are no local paths and no `AZCOOP_TEST_` strings in the output.
3. Compare the printed SHA-256 to the table above. `scripts/reproduce.ps1` does the build and the comparison in one
   step and exits non-zero on any mismatch.

Why the flags matter: `--remap-path-prefix` removes the build machine's paths from the binary, `-C debuginfo=0` /
`/DEBUG:NONE` drop the PDB (whose GUID differs per build), and `/TIMESTAMP:1` pins the PE timestamp — together they
make the output bytes depend only on the source and toolchain.

## Reproduce on CI

`.github/workflows/audit.yml` runs on every push: it runs the hygiene gate, then rebuilds `avrt.dll` and
`azcoop-net.exe` with the pinned toolchain and fails if either hash does not match the value in `scripts/reproduce.ps1`.
