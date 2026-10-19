# Azeroth Survivors Together - source

Source code of everything the Azeroth Survivors Together co-op mod ships, so anyone can read and audit it.

- `crates/` Rust workspace: the in-process co-op engine (`avrt.dll`, a proxy for the game's `avrt.dll`), the network helper `azcoop-net.exe`, protocol, state, game-logic and patch crates.
- `dllshim/` Python shim that starts the engine and carries the party channel.
- `launcher/` the Python launcher, room browser, updater and the lobby/relay client code as shipped in the package.
- `payload/` the profile and hook data shipped with the Native engine (per game build).
- `tools/`, `scripts/` build, release and packaging scripts, plus `scripts/hygiene_gate.py` (checks that no game files, keys or private material are in this repo).
- Signed releases: https://github.com/bymarvin/azeroth-survivors-together/releases

## What it does and does not do
- It only talks to the co-op lobby/relay servers (`lobby.azsurvivors-*.duckdns.org`, TCP 47771 for the relay), GitHub release downloads (updates, game-file mirror) and, in LAN mode, other PCs on your local network or VPN.
- It does not mine anything, does not use your GPU/CPU beyond the game and the small network helper, and does not read or send your personal files. Your own game folder is only read; the co-op works on a copy.
- Saves of the single-player game are never written by the co-op (separate co-op profile).
- Updates are signed (Ed25519); the public key is in the source. No game assets or decompiled code are included here.

Build instructions and hash verification will follow (`VERIFY.md`). License: MIT.
