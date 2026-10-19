"""Unknown-build mode of the DLL shim: a game build the Python adapter does not know but a DLL profile describes (the Native engine).

The launcher keeps everything it does for a known build (lobby, rooms, relay, the party's channels, the personal save, crash reports).
Its session start (`room_client.RoomClient.play`) imports the Python game bridges, which are bound to the 0.95.0 addresses; in this
mode they are never loaded: stand-in modules take their names, the compatibility check is the DLL profile naming the executable's
SHA-256, and `native_probe.run` is `dll_shim.dll_run` with the game described here. The core in the game does all game logic.

Lives in dllshim/ (the launcher's source identity hashes every .py in reconstruction/).
"""
import hashlib
import json
import os
import sys
import types
from collections import Counter
from pathlib import Path

# Builds the Python adapter knows (their sessions keep the normal shim): 0.84.3, 0.92.0, 0.93.1 (reference), 0.95.0.
PYTHON_BUILDS = frozenset((
    'dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306',
    '47e4ab65c1ad7366e554171a6a28b0272141664010a50795371129b203111bf2',
    '0315cf387f4f807512ac965763ed81ae58e7f20dd94547a7541ee8eae3135f66',
    '20d4ce5fb1232dac64bc00a4d8c9f2bcae43fb8373ea3fa95350ab8c4f20d618',
    '7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30',
))


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8 << 20):
            h.update(chunk)
    return h.hexdigest()


def dll_profile(root, sha, executable=None):
    """(path, verified) of the DLL profile (reconstruction/release-*.json) that names `sha` and carries variant_constants, or None.
    The channel layout keeps it next to the game copy (<root>/native/reconstruction, one release-<hash8>.json per supported build), the tester pack in <root>/reconstruction."""
    folders = ([Path(executable).parent / 'reconstruction'] if executable else []) + [Path(root) / 'reconstruction']
    for path in [p for folder in dict.fromkeys(folders) for p in sorted(folder.glob('release-*.json'))]:
        try:
            release = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        adapter = release.get('adapter_profile') or {}
        if adapter.get('sha256') == sha and isinstance(release.get('variant_constants'), dict):
            return path, adapter.get('adapter_contracts_verified') is True
    return None


def detect(root, executable):
    """(sha, profile path, verified) when the session must run in unknown-build mode, else None (the launcher's normal path, which
    refuses a build it does not know itself). An unverified profile is returned too: the session is then refused, never guessed.
    AZCOOP_UNKNOWN_BUILD=0 turns the mode off."""
    if os.environ.get('AZCOOP_UNKNOWN_BUILD') == '0' or not Path(executable).is_file():
        return None
    sha = sha256(executable)
    if sha in PYTHON_BUILDS:
        return None
    found = dll_profile(root, sha, executable)
    return (sha, *found) if found else None


class Game:
    """What dll_shim.dll_run needs to know about the game (instead of the Python adapter's native_probe)."""

    def __init__(self, root, executable, sha):
        self.ROOT, self.EXECUTABLE, self.ACTIVE_HASH = Path(root), Path(executable), sha
        self.DATA = Path(executable).parent / 'Data'

    @staticmethod
    def ensure_windowed(folder):
        path = Path(folder) / 'config.toml'
        if not path.exists():
            path.write_text('[cvars]\ngxWindow = "1"\ngxResolution = "1100x700"\n', encoding='utf-8')


class DllBridge:
    """The launcher's bridge object for a session whose game logic runs in the core: state the launcher reads, the gameplay log,
    and the decisions it queues (dll_shim forwards them as core commands)."""

    def __init__(self, output=None, number=1, channels=None):
        self.output, self.number, self.channels = output, number, dict(channels or {})
        self.autostart, self.host_map, self.stop_requested = True, None, False
        self.native_states, self.counts, self.departed = {}, Counter(), set()
        self.peer_finished, self.connection_failure, self.connection_after_run = False, None, False

    def record(self, **event):
        self.counts[str(event.get('event'))] += 1
        if self.output is not None:
            try:
                self.output.write(json.dumps(event, default=str) + '\n')
            except (OSError, ValueError):
                pass

    def poll_network(self):
        pass  # the party's channels belong to dll_shim's Forwarder

    def diagnostic_summary(self):
        return dict(mode='dll-unknown-build', counts=dict(self.counts))


class PartyMenu:
    """Stand-in for the Python party menu: the core owns the map choice and the login."""


def install(root, executable, sha, profile, verified=True):
    """Registers the stand-ins before the launcher's room client is loaded. With an unverified profile every session is refused
    at the launcher's compatibility check (the room browser still works)."""
    import dll_shim
    game = Game(root, executable, sha)
    DllBridge.run_over = dll_shim.bridge_run_over
    DllBridge.request_victory_action = dll_shim.bridge_request_victory_action
    DllBridge.offer_next_run = dll_shim.bridge_offer_next_run

    def run(seconds, players, callback, *, player_numbers=None):
        return dll_shim.dll_run(seconds, players, callback, player_numbers=player_numbers, game=game)

    def resolve_reviewed_profile(binary, **_):
        if not verified:
            raise ValueError(f'This game build ({sha[:8]}) has a co-op profile that is not verified yet: co-op refused. '
                             'Use the normal co-op folder, or wait for a beta update.')
        if sha256(binary) != sha:
            raise ValueError('The game changed after the launcher started. Restart the launcher.')
        return dict(sha256=sha, dll_profile=str(profile), mode='dll-unknown-build')

    stand_ins = {
        'native_probe': dict(ROOT=game.ROOT, EXECUTABLE=game.EXECUTABLE, ACTIVE_HASH=sha, DATA=game.DATA,
                             ensure_windowed=game.ensure_windowed, run=run),
        'group_online': dict(GroupOnlineBridge=DllBridge),
        'native_guest_combat': dict(NativeCombatBridge=DllBridge),
        'party_menu': dict(PartyMenu=PartyMenu),
        'build_hooks': dict(resolve_reviewed_profile=resolve_reviewed_profile),
    }
    for name, values in stand_ins.items():
        module = types.ModuleType(name, f'unknown-build stand-in ({profile.name})')
        module.__dict__.update(values)
        sys.modules[name] = module
    dll_shim.log('INFO' if verified else 'WARN', f'unknown-build mode: game {sha[:16]} runs from the DLL profile {profile.name}'
                 + ('; the Python game bridges stay unloaded' if verified else ' (NOT verified: sessions are refused)'))
    return game
