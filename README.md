# Azeroth Survivors Together — co-op source (public audit copy)

This repository is the **source for everything the co-op mod ships** — the native co-op engine DLL, its network
helper, the Python launcher/room client/updater, and the build scripts — published so anyone can read exactly what
runs on their machine and rebuild the shipped binaries byte-for-byte. **There is no cryptocurrency mining, no
telemetry, and no network use beyond forming and running a co-op game.** See [AUDIT.md](AUDIT.md) for the full,
evidence-backed account and [VERIFY.md](VERIFY.md) to reproduce the released hashes yourself.

It is an add-on for the single-player game *Azeroth Survivors* (a.k.a. *wenilla-rogue*). **No game code, assets, or
data are included or redistributed** — the mod only loads alongside a copy of the game the player already owns.

## What is here

| Path | What it is |
|---|---|
| `src/`, `crates/`, `build.rs`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `res/` | The native co-op engine **`avrt.dll`** and the network helper **`azcoop-net.exe`** (Rust). `avrt.dll` is a proxy DLL: it forwards every real `avrt.dll` export to the system DLL and adds the co-op core. |
| `dllshim/` | The small Python shim that selects the native engine, prepares the co-op folder, and launches the game with the DLL. |
| `launcher/` | The Python launcher, room browser / lobby client, peer transport, relay, and self-updater that ship in the package. |
| `payload/` | The verified per-build DLL profiles and the reviewed hook table that ship in the `native` channel payload (data only — hook addresses and field offsets, no game code). |
| `tools/` | Build and release scripts: the reproducible DLL build, the channel-payload staging, and the release packager. |
| `scripts/hygiene_gate.py` | A gate (run in CI) that fails if anything that must not be public — local paths, secrets, keys, game assets, reverse-engineering material, or an unguarded test hook — is present. |
| `.github/workflows/audit.yml` | CI that runs the hygiene gate and rebuilds `avrt.dll`, comparing its hash to the released one. |

## What is deliberately NOT here

Game executable/data/assets; any decompiled game code or reverse-engineering notes; the private signing key; secrets,
tokens, SSH keys, or server credentials; and local machine paths. The hygiene gate enforces this on every push.

The live-test switches (`AZCOOP_TEST_*`) exist only behind the Cargo feature `test-hooks` and are **never** in a
shipped build — the release build is compiled without the feature and the release script refuses any binary that
still contains the string. See [AUDIT.md](AUDIT.md#test-hooks).

## License

**A license has not been chosen yet** — see [LICENSE](LICENSE). Do not treat this as released under any license until
the owner fills it in.
