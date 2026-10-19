"""The start path of the co-op engines: which room client the launcher starts, with which game, and the restarts.

coop_launcher.py calls `prepare_launcher(root)` before its save setup and `run(root, command)` instead of starting
reconstruction/room_client.py itself:

* engine native (the default; coop-lab/coop-engine.txt missing, unreadable or "native"): game_channel.prepare_native at EVERY start
  (signed entry known and enabled, rollout includes this install, a supported copy of the player's game in <root>/native/ - copied
  now if needed, with progress -, its verified profile and the DLL files there). Then dllshim/dll_room_client.py with
  COOP_EXECUTABLE = <root>/native/AzerothSurvivors.exe and AZCOOP_HELPER = <root>/native/azcoop-net.exe.
* engine classic, or any native check failing: the launcher's own room client (0.95.0), unchanged. A failed native check prints its
  sentence and starts Classic for THIS start only; the player's choice is not rewritten (the next start tries Native again).
* start_failed: the native room client ending with an error within START_WINDOW seconds starts Classic at once (same command, same
  --port); the next launcher start tries Native again (a launcher killed in between starts Classic once, START_FAILED_HOLD).
* coop-lab/engine-last.json records every start: {chosen, engine, code, text, supported, time}.
* COOP_CHANNEL_RESTART=1: the room browser may end with exit code 3 after an engine switch; the same command is started again with
  the choice read anew. Any other exit code ends the launcher as before.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import game_channel  # noqa: E402

RESTART = 3          # the room browser's exit code after an engine switch (WP3 contract)
# the Native engine's own co-op heroes (savegame chat, 18.10.2026): never the 0.95.0 profile, whose saves a newer game could damage;
# one folder for every native build, the game carries its saves forward itself
PROFILE_FOLDERS = {game_channel.NATIVE: 'coop-lab/personal-native'}
MAX_RESTARTS = 20    # a restart loop is a bug, not a feature
START_WINDOW = 60    # a native room client that ends with an error this soon did not start
START_FAILED_HOLD = 24 * 3600  # after a start_failed the next start (within a day) is Classic once


def say(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def _held_by_start_failed(root):
    last = game_channel.last_start(root)
    return bool(last and last.get('code') == 'start_failed' and last.get('engine') == game_channel.NATIVE
                and time.time() - float(last.get('time') or 0) < START_FAILED_HOLD)


def choose(root):
    """(engine that starts, code, text): native only if chosen and every check passes; else classic with the reason."""
    chosen = game_channel.engine(root)
    if chosen != game_channel.NATIVE:
        return game_channel.CLASSIC, None, None
    if _held_by_start_failed(root):
        return game_channel.CLASSIC, 'start_failed', ('The last Native start failed. ' + game_channel.CLASSIC_NOTE +
                                                       ' The next start tries the Native engine again.')
    try:
        game_channel.prepare_native(root, say)
    except game_channel.Refused as refused:
        code = refused.code if refused.code in game_channel.CODES else 'start_failed'
        return game_channel.CLASSIC, code, f'{refused.text} {game_channel.CLASSIC_NOTE}'
    return game_channel.NATIVE, None, None


def plan(root, command, environ=None):
    """(command, environment, engine) for one start of the room browser; records engine-last.json."""
    root = Path(root)
    env = dict(os.environ if environ is None else environ)
    env['COOP_CHANNEL_RESTART'] = '1'
    chosen = game_channel.engine(root)
    used, code, text = choose(root)
    game_channel.write_last(root, chosen, used, code, text)
    if used == game_channel.NATIVE:
        folder = game_channel.channel_folder(root)
        env['COOP_EXECUTABLE'] = str(folder / game_channel.EXE)
        env['AZCOOP_HELPER'] = str(folder / 'azcoop-net.exe')
        env['COOP_CHANNEL'] = game_channel.NATIVE
        env['COOP_PROFILE_FOLDER'] = PROFILE_FOLDERS[game_channel.NATIVE]
        room = root / 'reconstruction' / 'room_client.py'
        shim = HERE / 'dll_room_client.py'
        rewritten = [str(shim) if Path(str(part)) == room else part for part in command]
        want = game_channel.expected(root)
        say('  OK  ', f'Co-op engine Native: game {want[1]} (build {want[0][:8]}) in {folder}')
        return rewritten, env, game_channel.NATIVE
    if code:
        say(' WARN ', text)
    say('  OK  ', 'Co-op engine Classic (0.95.0)')
    for name in ('COOP_EXECUTABLE', 'AZCOOP_HELPER', 'COOP_CHANNEL', 'COOP_PROFILE_FOLDER'):
        env.pop(name, None)
    return list(command), env, game_channel.CLASSIC


def prepare_launcher(root, environ=None):
    """In the launcher process before its save setup (the first-start question): the co-op profile of the engine this start uses.
    Runs the same checks as plan(), so a failing native check already falls back here (and the room browser starts Classic too)."""
    environ = os.environ if environ is None else environ
    used, _, _ = choose(root)
    if used == game_channel.NATIVE:
        environ['COOP_PROFILE_FOLDER'] = PROFILE_FOLDERS[game_channel.NATIVE]
        return game_channel.NATIVE
    environ.pop('COOP_PROFILE_FOLDER', None)
    return game_channel.CLASSIC


def run(root, command, call=subprocess.call, clock=time.monotonic):
    """Starts the room browser of the engine; again (same command, same --port) after an engine switch (exit code 3), and with
    Classic at once when the native room client fails to start."""
    for _ in range(MAX_RESTARTS):
        started, env, used = plan(root, command)
        began = clock()
        code = call(started, env=env)
        if used == game_channel.NATIVE and code not in (0, RESTART) and clock() - began < START_WINDOW:
            text = f'The Native engine did not start (exit code {code}). {game_channel.CLASSIC_NOTE}'
            say(' WARN ', text)
            game_channel.write_last(root, game_channel.engine(root), game_channel.NATIVE, 'start_failed', text)
            continue  # the next plan() starts Classic (held by start_failed), same command and port
        if code != RESTART:
            return code
        say(' INFO ', f'Engine switch requested: the room browser starts again ({game_channel.engine(root)}).')
    say('FAILED', f'The room browser asked for a restart {MAX_RESTARTS} times in a row; the co-op stops.')
    return 1
