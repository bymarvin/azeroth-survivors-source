# Audit notes

A plain account of what the co-op mod does, for anyone checking that it is safe. Everything below is in the source in
this repo; file references point at it.

## What it is, in one paragraph

*Azeroth Survivors Together* adds cooperative play to the single-player game *Azeroth Survivors*. It ships a proxy DLL
(`avrt.dll`), a small network helper (`azcoop-net.exe`), and a Python launcher. The DLL loads into the game, forwards
every real `avrt.dll` call to the system DLL, and runs a co-op "core" that keeps two or more players' games in sync.
The launcher handles the lobby, the party connection, and updates. **No game code or data is included or shipped; the
mod only runs next to a copy of the game the player already has.**

## No mining, no telemetry, no hidden network use

- The DLL does **not** open any network socket itself. All networking is the helper `azcoop-net.exe` carrying the
  party's own game messages, plus the launcher's lobby/update traffic listed below. There is no analytics or telemetry
  endpoint anywhere in the source.
- There is **no cryptocurrency mining, no GPU compute beyond the game's own rendering, and no background work when no
  co-op game is running.** The co-op core only runs while the game is in a co-op session.
- The one place the code contacts a well-known public address is to **read the computer's own LAN IP**: it opens a UDP
  socket toward `8.8.8.8` and reads the local interface address without sending data (`launcher/reconstruction/`
  `lan_mode.py`, `port_mapping.py`). This is a standard "which of my interfaces reaches the internet" trick, not a
  server the mod talks to.

## Network endpoints (exact hosts/ports)

| Purpose | Where | Host / port |
|---|---|---|
| Update check | `launcher/reconstruction/self_update.py` | `https://github.com/bymarvin/azeroth-survivors-together/releases/latest/download/` — **HTTPS only**, at most 5 redirects and only to GitHub; `latest.json` is Ed25519-signed and verified before anything is downloaded (public key below). |
| Co-op directory / lobby (internet rooms) | `launcher/reconstruction/room_client.py` | An HTTPS directory the **host** pins and shares in its invite (`PinnedDirectory.url`); there is no hard-coded central server. The default local test directory is `http://127.0.0.1:47770` (loopback, dev only). |
| Co-op over LAN (no internet) | `room_client.py`, `lan_mode.py` | The guest connects straight to the host's address on the local network; no directory, no internet. |
| Party data between players | `azcoop-net.exe` (`crates/azcoop-net`), `launcher/reconstruction/coop_transport.py` | A direct peer connection between the players; when a direct connection fails, an optional relay (`launcher/relay/server.py`, port `47771`) tunnels the same encrypted party stream. |
| NAT traversal | `launcher/reconstruction/port_mapping.py` | UPnP / PCP / NAT-PMP to the local router, and SSDP multicast `239.255.255.250` for UPnP discovery — all to the local network, not a server. |

The release signing public key (Ed25519, base64, embedded in the updater, `self_update.py` `TRUSTED_KEYS`):
`KT0uZ26Iiq4BoCNZPNuYDOWFCMJJenW83dALTZFyMjc=`. The private key exists only on the release machine and is **not** in
this repo.

## What the DLL hooks, and why

The co-op core installs a fixed, reviewed set of hooks into the game — 16 function-entry hooks and 6 breakpoint sites
on the shipped builds. Every site, its address on each supported game build, and the exact bytes are listed in
`payload/common/reconstruction/reviewed-hooks.json` and the per-build profiles `payload/builds/*/reconstruction/
release-*.json`. The source that generates the patched code is in `crates/azcoop-patch` and `crates/azcoop-bridge`.
In plain terms the hooks let the core:

- read the world and party state each tick and send/apply the other players' positions, enemies, and hits
  (`azcoop-bridge`, `azcoop-state`, `azcoop-logic`);
- agree a map between host and guests (the host publishes the chosen map; a guest's "enter" waits for it — see the
  guest-flow note below);
- keep both games' combat, spawns, loot, and run results identical (`azcoop-logic`);
- continue the world safely while the host is briefly down, without touching the player's save.

The hooks only ever read and write the running game's own memory to mirror state between the players. They do not
patch files on disk, do not touch other processes, and do not persist anything outside the co-op folder.

## How the player's save is protected

The native engine runs from a **copy** of the game it makes under the co-op folder (`native/`); it reads the player's
installed game read-only to make that copy and never writes the real install. Co-op heroes live in a separate profile
folder (`coop-lab/personal-native`), never the single-player save, so a co-op session cannot corrupt the normal game.
The updater verifies a signature on every release before replacing any file.

## <a name="test-hooks"></a>Test hooks are never shipped

The repo contains late-game/test switches named `AZCOOP_TEST_*` (e.g. a stress test and a deterministic-crash check).
They compile **only** behind the Cargo feature `test-hooks`, which the release build does not enable, so the strings
are not even present in the shipped binary. The release script (`tools/build/release.ps1`) and the payload stager
(`tools/pack/stage_channel_payload.py`) both **refuse** any binary that still contains `AZCOOP_TEST_`. The hygiene
gate (`scripts/hygiene_gate.py`) fails if any `AZCOOP_TEST_` env read is not behind that feature guard.

## Threat model

- **A malicious release** is prevented by the Ed25519 signature on `latest.json` and on each file; the updater only
  accepts HTTPS from GitHub and a verified signature.
- **A malicious peer** can only send party messages, which the core validates (bounded sizes, sequence/ack checks,
  guard patches on guest-side damage and spawns); a bad message is dropped, not executed.
- **A malicious directory/relay** sees only the encrypted party stream and connection metadata, never game files or
  the player's save.
- **The mod itself**: this repo plus the reproducible build (see [VERIFY.md](VERIFY.md)) lets anyone confirm the
  shipped `avrt.dll` is exactly this source and nothing else.

## What is intentionally not in this repo

Game executable/data/assets, any decompiled game code or reverse-engineering notes, the private signing key, secrets,
tokens, SSH keys, server credentials, and local machine paths. `scripts/hygiene_gate.py` enforces this and runs in CI.
