CURRENT STATUS (2026-10-13, updated v0.73 build)
The root EXE has since changed to SHA-256 bc6649e91f270bc424f8120955aa1de5a7f31b3ea909588ae34545d26928c548.
Automatic structural discovery, scoped native checks and all nine four-player
acceptance suites now pass for this EXE. The resolver activated its verified
profile automatically; two fresh launches revalidated it in about 2 seconds
each and preserved the previous verified profile byte-for-byte.
Four-client disposable tests place players 1/2/3/4 at top-left/top-right/
bottom-left/bottom-right of the primary desktop work area. The verified 1100x700
viewport is preserved, so small desktops can still have partial overlap.
Current-build tests have already exercised combat, movement, shared XP/gold,
independent talents/rewards, revival, map unlock/save reloads, both victory
choices and native menu Quit. All 18 required cases passed in one source-bound run.
Actual guest/host X-button closure also passed. Windows debug-heap overhead caused
slow closing; the normal-heap comparison closed the host in 0.94 seconds.
The launcher applies that setting only to game processes. Final profile
revalidation passed all nine suites and 18 required cases.
Start-Coop.cmd opens the room browser using the configured shared directory.
Passing a directory URL as its first argument overrides that default. A remote
host must publish a reachable game address/port; no relay deployment is supplied.
The directory needs a persistent Python process behind HTTPS, not static hosting.

Four native clients and four separate TLS peers passed local integration checks.
Public/private rooms, host-only Start and native per-player character selection
are connected. The updated game is the default; all lab launches are windowed.
Independent boss loot and final-boss shared gold passed four native clients;
unlocks and earned gear survived a full process restart in isolated profiles.
Host map enforcement passed the conflicting native class/map loading check.
Four separate TLS peers passed boss rewards and both host-only victory choices,
including a Mage alongside Warriors. All four network players passed pause,
resume and revival checks with level/XP preserved and every notification delivered.
Four-player native chest contention and guest pickups passed with private spending
preserved. A staged native save retained unlocks, talent points and equipped loot
after commit and reopening in a different profile. Those native results concern
the previous reviewed build. See analysis/UPDATE-COMPATIBILITY.md for current-build evidence.
Remote co-op has not been verified by the local acceptance tests.
Internet hosting/deployment is deferred by the user (2026-10-13). Four-player
verification of the currently installed changed build passed local acceptance.

Normal room launches stage the local SP characters.txt in coop-lab/personal.
At session exit, including disconnect, native saved progress is copied back only
if the original SP save stayed unchanged. Backups and conflicts stay in that folder.
Diagnostic verifiers use isolated saves and never write the user's SP progress.

Hook updates: reviewed instruction signatures plus whole mapped-runtime proof
automatically accept equivalent packaging, image rebasing and fully proven
function-address relocations. Changed code triggers dependency discovery and is
rejected until all required runtime
dependencies can be verified. Structural discovery now includes typed native
fields, menu/effect/helper contracts and automatic disposable entry/ownership
observations. Current-build four-player acceptance and activation passed.
This is not a universal future-version guarantee.
See analysis/UPDATE-COMPATIBILITY.md and .agent/CONTINUITY.md for current evidence.
Offline checks: python -m unittest discover -s reconstruction -p "test_*.py"

PLAYING WITH OTHER PCS
Everyone needs the same game build, this co-op folder and 64-bit Python
(verified with Python 3.12). On another PC, install the existing dependencies:
  python -m pip install -r reconstruction/requirements.txt
Launch Start-Coop.cmd with the same HTTPS room-directory URL. The directory can run on web hosting
that supports a persistent Python process and HTTPS, or on a VPS. Static-only
hosting is insufficient. This project does not supply a hosted directory/relay.
The host's Connection settings must contain an address reachable by the guests
and a forwarded TCP game port (default 47771). Then create a public/private room,
join it, and let the host press Start. Each player uses their own native save,
class, gear and talents. Start opens everyone's character menu together.
The host confirms the map by entering the game. Guests can choose class/gear
meanwhile, then press Enter after the host confirms; an early Enter is rejected
and may briefly show the native entering indicator before it resets.
The guest's lobby page shows an amber waiting banner, then a green "You can
enter now" banner with the confirmed map. The browser tab title changes too.
As soon as the host starts, guests see "The host has started the game" and
an explicit notice that their game opens automatically once connected.
The host selects the map; guests join that map even if
their class has not unlocked it. A guest departure removes only that guest and
resumes the remaining party. Host departure ends the session for everyone.
Joining an already-running game is not supported.
After New Hero, return to the room browser and form a new room for the next run.
If game files change while the launcher is open, restart it for fresh verification.

Directory behind an existing HTTPS reverse proxy:
  python reconstruction/lobby_server.py --bind 127.0.0.1 --port 47770

HISTORICAL CHECKPOINTS BELOW (some describe old builds and two-player limits)
--shared-world now selects native_guest_combat.py. It runs the guest's native
melee/spell actions against owned enemy mirrors and applies their resulting
damage to the host world. Native combat, independent choices, shared actual XP,
revival, downed pause/resume, shared gold and private chests have live checks.
This remains a local, build-pinned development adapter, not finished online co-op.

Gold pickups by either player credit both balances, including the picker bonus.
Chest purchases charge only the opener and offer only that player's native chest
choices. Spending is not mirrored. A stale guest claim refunds its reserved cost.
verify_economy.py checks both pickup owners and both chest owners against native
balances and opened-chest counters. The extended check also verifies a guest XP
pickup reaches both native progression states; it delivered 599/599 updates.

Enemy spawns alternate between living players, using native terrain placement
around each current position. Total spawn rate and population cap scale from 1.0
to 1.5 as separation grows from 0 to 100 yards. Set COOP_SPAWN_BONUS_DISTANCE to tune
the maximum-bonus distance. Death sends spawns to the survivor; revival restores
alternation without a catch-up burst. A 200-yard test recorded 17 spawns each while
both lived, 23 normal + 11 extra spawns and 1723/1723 world updates. The native arena
center clamp is bypassed only for the co-op spawn context. verify_spawn_balance.py
checks allocation, actual placement, the bonus and dead-player exclusion.

The local adapter waits for both windows to finish loading before combat starts.
Each player spends their own native talent credits; the other waits until both
have chosen. Manual talent selection and Escape pause/resume from both windows
were verified visually and in native event records.
A survivor within 5 yards for 3 continuous unpaused seconds revives the fallen
player at half maximum HP, preserving XP and talents. Both guest and host revival
passed a native test with the world clock advancing during death (1456/1456
world updates delivered). The initial host-down crash was fixed by restoring
four native container pointers required by the remaining world update code.
Enemy pursuit selects the nearer living player; a synthetic-position native
check confirmed the enemy moved toward the guest. Both players receive native
defeat screens on a full-team death. Again restarts both isolated processes and
resets the bridge session; assets reload. A fresh post-restart session passed
combat, independent talents, shared XP and pause tests (1080/1080 updates).
Run verify_pursuit.py, verify_team_defeat.py and verify_restart.py for those checks.
Host victory now invokes the guest's native completion path, including native
results, achievements and save handling. verify_victory.py forces the native
objective and checks both phase5 states and both delivered victory callbacks.
Living-player and downed-guest tests passed with 57/57 and 55/55 world updates.
Guest enemy debuffs replay through the native host effect dispatcher; private
healing/shields stay with their owner. verify_debuffs.py verified actual host slow,
weakening and stun fields/timers. Its extended native DOT allocation check passed
three periodic packets and three authoritative 2-HP hits (6 total), 842/842 world
updates. This verifies periodic processing, not every class's talent/proc setup.
Boss mirrors use native boss constructors and preserve their separately owned
ability storage. Guest native health/power updates also refresh the host avatar.
Native boss radial and delayed ground attacks check both players independently.
Ground/charge targeting chooses the nearer living player; radial distance checks
retain the host position and check the guest separately. verify_enemy_area.py
--boss 4 passed both-inside, guest-outside and guest-only-inside cases plus ground
hits,1587/1587 world updates. Host-down ground/projectile continuation is pending.
Run verify_revival.py for a bounded disposable revival check and verify_coop.py
for combat/progression/pause checks. The latest manual pause run delivered all
8655 world updates. Evidence: analysis/coop-ui-controls.jsonl and
analysis/coop-revival-world-continues.jsonl.
This is not fully playable: complete guest ability/debuff/class coverage,
performance-ready interception and online transport
remain unfinished. Debug-handler timing does not measure total suspension/GPU
cost. The historical checkpoints below describe earlier states and limitations.

Native player movement and host-world prototype

HISTORICAL CHECKPOINT: basic guest melee (superseded above)
Guest basic melee now calls the host's native damage routine against a nearby
shared enemy. Range, damage and cooldown use the guest's native class profile
and scalar melee modifiers. Native health/death/XP side-effects are retained;
verified-format swing packets identify the guest separately on both clients.
This remains partial combat: no guest active abilities, crit rolls or ranged
attacks. Host damage modifiers/procs can still influence guest hits because
the native damage routine uses the host game object. Complete independent
talent combat and two-player pursuit/aggro are not reconstructed.

Incoming native melee hits now choose the nearer participating player (exact
overlaps alternate). Redirected hits run the guest's native HURT routine with
its own defenses, update actual HP, and replicate hit/health packets to both.
This covers existing host-generated melee opportunities: pursuit still chases
the host. Guest reactive attacks cannot yet damage shared enemies, and ranged/
area incoming damage is not redirected. Revival is requested but NOT implemented;
host death still stops its single-player simulation. Do not call this full co-op.

Host XP awards are replayed once through the guest's native XP routine. Actual
levels, earned stats and independent talent menus advance, beyond display-only
updates. The diagnostic chooses slot 0 for the host and slot 1 for the guest;
normal runs leave each player's choices to them.

Pause/resume hooks now queue the same explicit state for both players, and use
native pause/resume routines on each existing server thread, preserving CPU/XMM
state. Either selected player can request resume; duplicate requests are
idempotent and mirrored calls cannot echo into fresh requests. Choosing talents,
ready, death and victory are not forcibly changed into playing. Requests wait
while a client is outside playing/paused. A live native-handler test verified
host pause / guest resume / guest pause / host resume, both phase bytes and the
host simulation clock frozen during pause and advancing after resume. This
does not verify the Escape key binding or visually inspect the menus.

The login batch precedes full game initialization. A failed test exposed an
early START call; startup now waits for native movement dispatch before reading
guest combat containers or calling START. That one-shot readiness hook is then
removed. Failed trace: analysis/coop-native-startup-failure.jsonl.

After bootstrap, shared-world packets are decoded/filtered/re-encrypted in whole
native queue batches. The serializer breakpoint is removed. The 35-second run
used 28 bootstrap serializer stops and 1,012 batch reads, delivered all 285 world
packets in order, and exited normally. Logging uses buffered writes. Queue
debugger stops remain; this is a reduction, NOT proof of a smooth or freeze-free
game. Both clients were stopped after each bounded check.

Two isolated real EXEs connect through SessionRouter. Live movement from BOTH
clients was captured and relayed; the user confirmed seeing the other player
move. Native opcodes, flags and timestamps are now preserved for movement
animation instead of replacing everything with a stationary heartbeat.

With --shared-world, the guest's simulation tick is disabled in memory. Host
enemy creates, movement, health/state updates, despawns, melee damage and spell
launch/damage packets are forwarded in order, mapping the host's local GUID to
its remote avatar. The user confirmed matching enemies AND visible host attacks.
Guest basic melee contributes authoritative damage and receives redirected
enemy melee hits. This is partial co-op. Inventory,
loot, saves, zone changes and reconnect are unfinished.
There is no network listener or online transport.

Run from this folder's parent with the existing bundled Python:
  & '%USERPROFILE%\...' reconstruction/visibility_bridge.py --seconds 180 --shared-world
Add --demo to animate remote avatars using explicitly synthetic positions.
Without --shared-world, native enemy/combat simulations remain independent.
Both sandbox configs are set to 1100x700 windowed mode. Both characters initially
overlap; move one to separate them. Close a test game to end the whole probe.
Only this exact lab EXE hash is supported; other builds fail closed.
The debugger changes process memory only. Original EXE and assets are untouched.
Test saves/logs live in coop-lab/bridge-player-1 and bridge-player-2.
On a timed exit it pauses simulation and drains replication for up to five
seconds, then terminates both owned clients. An emergency stop or failure still
terminates immediately. To stop a running probe
without UI automation, create coop-lab/stop-bridge.txt; the adapter consumes it.
All test processes were stopped after the user reported poor responsiveness.

PERFORMANCE / FREEZE LIMIT
A race in the old suspend/single-step debugger could strand a thread when two
breakpoint events overlapped. It now emulates the verified PUSH instruction
without manual thread suspension; both packet streams ran beyond four minutes.
However, every remaining queue debugger exception still pauses that process's threads. This is
not a performance-ready mod, even with low total CPU use. Logs show live shader
compilation/model loading during startup. Two clients used about 1.8 GB RAM each
at the final sample; GPU saturation and system-wide stall causes were NOT measured.
Do not claim the whole-PC responsiveness problem is diagnosed or fixed.
Replace per-packet debugger interception with buffered in-process hooks before
longer play tests; additional heavy runs were stopped, not silently continued.

Other limitations: only stationary initial player
creation and basic ground movement are supported; unsupported movement modes
are skipped. Remote appearances copy the initial character packet; animation,
equipment changes, names, reconnection and zone changes need further work.
The adapter is a diagnostic prototype, not a distributable multiplayer mod.

Files: native_probe.py (temporary debugger), visibility_bridge.py (native/session
adapter), world_packets.py (bounded object/combat parser and GUID remapping).
Seventeen unittest checks pass, including captured native world packets, combat GUID
fields, exact host/guest packet order, cipher continuation and breakpoint emulation.
Evidence: analysis/movement-windowed-fixed.jsonl, shared-world-first.jsonl and
shared-world-animation-check.jsonl, plus saved guest packet traces. The first
shared-world run captured and delivered 3,057 packets in exact order; the final
animation trace delivered 673/673 and resolved caster 0xff0101 as indexed=true.
New evidence: analysis/shared-progress-batch-check.jsonl and
analysis/native-controls-check.jsonl. analysis/probe_native_controls.py reproduces
the bounded native call smoke check without input or forced state changes.
No authentication keys are persisted. Original EXE, lab EXE and MPQ hashes match
the baseline. No Git repository is present, so no commit was created.

Run reconstruction/verify_coop.py with the same Python for the bounded 55-second
native test (automatically selects different talents). It checks both pause
directions, real enemy HP loss, swing delivery, independent choices, matching XP
and ordered world delivery. Evidence: analysis/coop-native-verification.jsonl.
Latest bounded check: 14 guest attacks including 4 kills; 14 incoming enemy hits
reduced native guest HP by 37.4014 in total, with matching hit/health delivery to
both clients. Both reached level 5 / XP 6 with different talent choices. All
1189 host world packets arrived in order. All four native pause/resume cases
passed. Both owned clients stopped. Earlier test failed strict world equality
at timed shutdown (926 captured / 925 delivered); evidence retained in
analysis/coop-incoming-before-drain.jsonl. The drain change fixes that observed
shutdown case; emergency termination can still discard in-flight updates.
Next: isolate guest talent/proc effects, reconstruct guest abilities and enemy
targeting, visually verify attacks/menu controls, and replace debugger queue
stops. Survivor revival, online transport and shared loot remain. User requested
local testing for now; no second-PC or internet verification has been performed.

HISTORICAL REFERENCE-MODEL NOTES (before the native adapter)

STATUS
This is an executable-informed Python reference implementation, not original
Rust source, a binary-compatible replacement, or a working multiplayer patch.
It deliberately runs without a network listener or any new dependencies.
The reference module alone does not connect to the EXE; see the adapter above.

RUN THE CHECK
From the game folder:
  & '%USERPROFILE%\...' -m unittest discover -s reconstruction -v
Or use any existing Python 3.10+ interpreter with that same -m command.

WHAT IS RECONSTRUCTED
- Client frame header: two-byte big-endian length (opcode included), then a
  four-byte little-endian opcode. Payload follows unencrypted.
- Native rolling header decryption: plaintext byte = (ciphertext - previous
  ciphertext) modulo 256, XOR session_key[index]; index wraps at 40 bytes.
- Fragmented/coalesced frames and headers whose body arrives later.
- Basic 28-byte ground movement: flags, client time, X/Y/Z, orientation,
  fall time. Native player pose lives at game+0x488..0x494.
- Login opcode 0x003d with a 64-bit character ID, and the native movement
  dispatch range. Other opcodes are explicitly unsupported.

NEW CO-OP BEHAVIOR (NOT CLAIMED TO EXIST IN THE ORIGINAL)
- Separate player objects keyed by ID, each owned by an account.
- Each authenticated connection selects its own character.
- Movement is routed only to that selected character.
- Selecting another account's character or an already connected character fails.
- Disconnect releases that character without touching the other player.
- Reconnect selects the existing character and retains its reference-model pose.
- A snapshot exposes all connected player poses for a future replication layer.

TRUST BOUNDARY
attach_authenticated() is a trusted adapter entry, not a login/password API.
It does not verify SRP proofs or perform authentication. A future adapter must
authenticate first and initialize a separate receive cipher for each connection.
None as a key is for plaintext tests, not an authentication bypass mode.

Unknown opcodes, short/invalid frames, oversized input batches, unsupported
movement flags and non-finite coordinates are rejected. A failed session is
detached so a corrupted cipher/parser state cannot be reused. Basic movement
still trusts finite positions: map limits, speed, collision and combat authority
are not implemented. Do not expose this reference model to untrusted clients.

EVIDENCE AND LIMITS
Native evidence is pinned to SHA256:
900F6EA6313A2EB4EF8D7D06C706D559A046F2EC68055B4204E42048DF0413A5
See ../analysis/world-frame-parser-disassembly.txt and
../analysis/server-tick-disassembly.txt. The parser's native malformed-length
handling is intentionally tightened here: lengths smaller than an opcode fail.
Native zero-filling of truncated movement data is not reproduced.

See ../analysis/session-handler-addresses.json for decoded native jump-table
targets, and ../analysis/SESSION-LAYOUT.txt for field offsets and confidence.
Public Benilla protocol files are corroborating references, not proof that the
public source version exactly matches this extended build.

The isolated runtime trace confirmed MSG_MOVE_HEARTBEAT 0x00ee with length 28,
flags 0, facing 1.6000 and rounded position [-9396.00,-633.00,68.02]. This
executable's trace DOES NOT include payload hex. Tests construct synthetic
bytes from the observed format/rounded values; they do not claim packet capture
or a native-vs-reference differential test. Upstream trace code with hex output
is newer/different from this executable's behavior.

TEST COVERAGE
Three runnable tests cover the known header-cipher vector, cipher-key wrap,
byte-by-byte fragmentation, coalesced packets, two independent player positions,
ownership, duplicate login, disconnect/reconnect, movement before login,
malformed input, unsupported modes/opcodes and non-finite coordinates.

NOT YET RECONSTRUCTED / NEXT INTEGRATION WORK
1. Finish native character enumeration, login/reset and logout semantics; map
   the selected character ID and lifecycle to the single shared game object.
2. Capture payload bytes through a verified native transport hook or reconstruct
   the matching client transport; compare against this parser.
3. Implement the authenticated transport and server outbound framing/encryption,
   entity creation and movement replication so real clients can see both players.
4. Refactor the remaining shared gameplay state (health, abilities, enemies,
   damage, upgrades and saves) without splitting enemies into separate worlds.

This milestone starts the reconstruction; it does not complete online co-op.

HISTORICAL CHECKPOINT: native XP / independent talents (before guest melee)
The guest now starts using native START and receives each host AWARD_XP amount
once through its own native routine. The live trace confirms both actual game
objects reached level 2 / XP 0 / one talent due. Guest produced independent
talent options; this supersedes the display-only limitation above. Choosing and
using guest talents in combat still requires verification; guest damage is not
implemented. Added START/AWARD_XP/CHOOSE hooks in native_probe/visibility_bridge.
Evidence: analysis/native-xp-independent-talents.jsonl. UI testing was stopped
by physical Escape, and both clients were stopped. Twelve existing tests pass;
new routing needs dedicated coverage. Pause/resume gameplay verification pending.
212 world packets captured, 211 delivered before interruption (one still queued).
