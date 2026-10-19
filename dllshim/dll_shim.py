"""DLL test shim for the Python co-op launcher (two-player test, host side).

The launcher keeps everything it does today: room list, lobby, UPnP / relay routes, the party's peer channels
(`coop_transport.Channel`). Only the part that ran the game under the Python debugger bridge is replaced:
`native_probe.run` starts the game with the in-process Rust core (`avrt.dll`, AZCOOP_ENGINE=1) and then only
carries the party's `state` messages between the peer channels and the core:

    peer channels  <->  this process  <->  azcoop-net.exe --mode relay  <->  pipe  <->  avrt.dll in the game

No game logic runs here. The frames are the helper's IPC frames (`u32 length, u16 kind, u16 flags`, JSON body).

Besides the party's messages the core and the launcher talk over two more frame kinds (Step 2, victory choice and next run):
`Event` (core -> launcher: phase changes, `run_over`, the next-run offer a guest received, the acks the host got) is replayed
on the launcher's bridge object as the `record(**event)` calls and attributes the launcher already reads; `Command`
(launcher -> core: the victory choice and the next-run offer) is queued by the bridge methods the launcher already calls.
"""
import json
import os
import queue
import secrets
import select
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

KIND_HELLO, KIND_HELLO_ACK, KIND_STATUS, KIND_GOODBYE, KIND_STATE, KIND_EVENT, KIND_COMMAND = 1, 2, 5, 7, 8, 9, 10
BUILD_ID = 'coop2-test'
MAX_FRAME = (32 << 20) + 4096


def log(level, text):
    print(f'[{level:^6}] {text}', flush=True)


EXIT_NAMES = {0: 'clean exit', 1: 'exit code 1', 101: 'exit code 101 (a Rust panic ending the process)', 0xC0000005: 'ACCESS_VIOLATION',
              0xC00000FD: 'STACK_OVERFLOW', 0xC000001D: 'ILLEGAL_INSTRUCTION', 0xC0000094: 'INTEGER_DIVIDE_BY_ZERO',
              0xC0000409: 'STACK_BUFFER_OVERRUN / fast fail (a Rust abort ends here)', 0xC0000374: 'HEAP_CORRUPTION'}


def exit_text(code):
    unsigned = code & 0xFFFFFFFF
    return f'{unsigned:#010x} ({EXIT_NAMES.get(unsigned, "other")})'


def frame(kind, payload=None):
    body = b'' if payload is None else json.dumps(payload, separators=(',', ':'), allow_nan=False).encode('utf-8')
    return struct.pack('<IHH', len(body), kind, 0) + body


def split_frames(buffer):
    """Whole frames at the front of `buffer` (a bytearray), removed from it; unknown kinds are skipped by the caller."""
    out = []
    while len(buffer) >= 8:
        length, kind, _ = struct.unpack_from('<IHH', buffer)
        if length > MAX_FRAME:
            raise ValueError('ipc frame exceeds the size limit')
        if len(buffer) < 8 + length:
            break
        body = bytes(buffer[8:8 + length])
        del buffer[:8 + length]
        out.append((kind, json.loads(body) if body else None))
    return out


class Forwarder:
    """Carries messages between peer channels and the helper's TCP connection. Pure and testable: it owns
    no process, only a socket and the channel objects (anything with send/drain/finish)."""

    def __init__(self, sock, channels):
        self.sock = sock
        self.channels = dict(channels)
        self.buffer = bytearray()
        self.helper_gone = False
        self.goodbye = False
        self.events = []  # core events not yet handed to the launcher's bridge object
        self.sent = self.received = 0
        sock.setblocking(False)

    def _write(self, data):
        view = memoryview(data)
        deadline = time.monotonic() + 10
        while len(view):
            try:
                n = self.sock.send(view)
                view = view[n:]
            except (BlockingIOError, InterruptedError):
                if time.monotonic() > deadline:
                    raise TimeoutError('the helper does not read')
                select.select([], [self.sock], [], 0.05)

    def announce(self):
        for peer in sorted(self.channels):
            self._write(frame(KIND_STATUS, dict(peer=peer, event='connected', reason='')))

    def lose(self, peer, error):
        # the reason text is what tells a relay timeout from a closed tunnel; the core only gets the exception's name
        log('WARN', f'peer {peer} link lost: {type(error).__name__}: {error}')
        self.channels.pop(peer, None)
        self._write(frame(KIND_STATUS, dict(peer=peer, event='lost', reason=type(error).__name__)))

    def step(self, wait=0.005):
        """One round: channels -> helper, helper -> channels. Returns False once the helper or the DLL is gone."""
        for peer, channel in list(self.channels.items()):
            try:
                messages = channel.drain()
            except (ConnectionError, TimeoutError, queue.Full) as error:
                self.lose(peer, error)
                continue
            for message in messages:
                self._write(frame(KIND_STATE, dict(peer=peer, message=message)))
                self.sent += 1
        readable, _, _ = select.select([self.sock], [], [], wait)
        if not readable:
            return True
        try:
            data = self.sock.recv(1 << 20)
        except (BlockingIOError, InterruptedError):
            return True
        except OSError:
            data = b''
        if not data:
            self.helper_gone = True
            return False
        self.buffer.extend(data)
        for kind, payload in split_frames(self.buffer):
            if kind == KIND_GOODBYE:
                self.goodbye = True
                return False
            if kind == KIND_EVENT:
                if isinstance(payload, dict) and isinstance(payload.get('event'), str):
                    self.events.append(payload)
                continue
            if kind != KIND_STATE or not isinstance(payload, dict):
                continue
            peer, message = payload.get('peer'), payload.get('message')
            channel = self.channels.get(peer)
            if channel is None or not isinstance(message, dict):
                continue
            try:
                channel.send(message)
                self.received += 1
            except (ConnectionError, TimeoutError, queue.Full, ValueError) as error:
                self.lose(peer, error)
        return True

    def command(self, payload):
        """Sends one launcher decision to the core (see `bridge_request_victory_action`, `bridge_offer_next_run`)."""
        self._write(frame(KIND_COMMAND, payload))

    def take_events(self):
        out, self.events = self.events, []
        return out

    def finish(self):
        for channel in list(self.channels.values()):
            try:
                channel.finish()
            except Exception:
                pass


def dispatch_events(callback, events):
    """Replays the core's events on the launcher's bridge object: its state, then its `record(**event)`."""
    for payload in events:
        name = payload.get('event')
        try:
            if name == 'native_state' and isinstance(payload.get('player'), int) and isinstance(payload.get('phase'), int):
                states = getattr(callback, 'native_states', None)
                if isinstance(states, dict):
                    states[payload['player']] = (payload['phase'], int(payload.get('level') or 0), 0, 0)
            elif name == 'run_over':
                callback.core_run_over = bool(payload.get('value'))
            elif name == 'host_departed':
                # a guest's core saw the host leave (goodbye or lost link): the same end the Python bridge reached in
                # `connection_ended`; the launcher then closes this game (and joins the next room it was invited to)
                # The game is asked to leave the run properly first (class-XP evaluation and save), see `Leave`;
                # the loop in `dll_run` closes it afterwards.
                callback.peer_finished = True
                callback.leave_requested = True
                if payload.get('reason') in ('ConnectionError', 'TimeoutError'):  # a lost link; an orderly 'left' is not
                    callback.connection_after_run = bool(payload.get('after_run'))
            elif name == 'leave_applied':
                callback.leave_applied = True
            elif name == 'next_run_acks' and isinstance(payload.get('acks'), list):
                callback.next_run_acks = {a for a in payload['acks'] if isinstance(a, int)}
            elif name == 'next_run_offer' and isinstance(payload.get('room'), str) and isinstance(payload.get('invite'), str):
                offered = getattr(callback, 'next_run_offered', None)
                if offered is not None:
                    offered(dict(room=payload['room'], invite=payload['invite']))
            record = getattr(callback, 'record', None)
            if record is not None:
                record(**payload)
        except Exception as error:  # one odd event never ends the round
            log('WARN', f'core event {name!r} not applied: {type(error).__name__}: {error}')


def flush_commands(callback, forwarder):
    """Sends the decisions the launcher queued on its bridge object (`core_commands`) to the core."""
    queued = getattr(callback, 'core_commands', None)
    while queued:
        forwarder.command(queued.pop(0))


# The launcher calls these on its bridge object; with the core in the game they only queue / read what the core reports.
def bridge_run_over(self):
    return bool(getattr(self, 'core_run_over', False))


def bridge_request_victory_action(self, command):
    if command not in (8, 9):
        raise ValueError('Unsupported victory choice')
    self.__dict__.setdefault('core_commands', []).append(dict(command='victory_action', value=command))


def bridge_offer_next_run(self, room, invite):
    self.next_run_offer = dict(room=room, invite=invite)
    self.next_run_acks = set()
    self.__dict__.setdefault('core_commands', []).append(dict(command='offer_next_run', room=room, invite=invite))
    record = getattr(self, 'record', None)
    if record is not None:
        record(event='next_run_offered', room=room, guests=[])


def helper_blocked_text(helper_exe, error):
    """The message for a refused start of the network helper (antivirus, SmartScreen, a blocked download or a locked file)."""
    return (f'Windows refused to start {Path(helper_exe).name} ({type(error).__name__}: {error}). Most likely your antivirus or Windows '
            f'SmartScreen blocked it. Add an exclusion for the folder {Path(helper_exe).parent}, or right-click the file, '
            f'open Properties and tick Unblock, then start the co-op again. Without it you cannot play together.')


LEAVE_WAIT = 10.0   # seconds the game gets to evaluate and save after it was asked to leave
LEAVE_SETTLE = 1.0   # seconds after the save file changed (the game may still be writing)


def crash_lines(path):
    """The schema-2 crash lines ({"event":"native_crash",...}, CRASH-REPORT-FORMAT.md) the core wrote into its crash log this session
    (the core recreates the file at every game start). Unreadable or foreign lines are skipped."""
    out = []
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return out
    for line in text.splitlines():
        if line.startswith('{"event":"native_crash"') and len(line) <= 4096:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and event.get('schema') == 2:
                out.append(event)
    return out


# The game's sound cvars (benilla [cvars] in <BENILLA_HOME>/config.toml; the same names in 0.95.0 and 0.99.0): all 0 = silent.
MUTE_CVARS = ('MasterVolume', 'SoundVolume', 'MusicVolume', 'AmbienceVolume', 'MasterSoundEffects', 'EnableMusic', 'EnableAmbience',
              'EnableErrorSpeech', 'Sound_EnableSoundWhenGameIsInBG')


def mute_profile(folder):
    """Test runs only (callback.mute): every sound cvar = "0" in the throwaway profile's config.toml, other lines kept. Never used for a
    player's real profile."""
    import re
    path = Path(folder) / 'config.toml'
    text = path.read_text(encoding='utf-8') if path.exists() else ''
    if not re.search(r'(?m)^\[cvars\]\s*$', text):
        text = text.rstrip() + ('\n' if text.strip() else '') + '[cvars]\n'
    for name in MUTE_CVARS:
        line = f'{name} = "0"'
        if re.search(rf'(?m)^{re.escape(name)}\s*=.*$', text):
            text = re.sub(rf'(?m)^{re.escape(name)}\s*=.*$', line, text)
        else:
            text = re.sub(r'(?m)^\[cvars\]\s*$', '[cvars]\n' + line, text, count=1)
    path.write_text(text if text.endswith('\n') else text + '\n', encoding='utf-8')
    log('INFO', f'volume 0 in profile ({path})')


def save_stamp(path):
    """(modification time, size) of the game's save file, None while it does not exist."""
    try:
        info = Path(path).stat()
    except OSError:
        return None
    return info.st_mtime_ns, info.st_size


class Leave:
    """The graceful leave of a guest whose host is gone: the core is asked once to take the game back to character select (which runs
    the run evaluation and writes the save); the game is closed when the save file changed and settled, or after `LEAVE_WAIT`."""

    def __init__(self, save_file, now):
        self.save_file, self.started, self.sent = Path(save_file), now, False
        self.baseline = save_stamp(self.save_file)
        self.changed_at = None
        self.last = self.baseline
        self.why = ''

    def step(self, callback, forwarder, now):
        """True when the game may be closed now. Sends the command on the first call."""
        if not self.sent:
            forwarder.command(dict(command='leave_run'))
            self.sent = True
        stamp = save_stamp(self.save_file)
        if stamp is not None and stamp != self.baseline and (self.changed_at is None or stamp != self.last):
            self.changed_at = now  # written, or still being written: the settle time starts again
        self.last = stamp
        if self.changed_at is not None and now - self.changed_at >= LEAVE_SETTLE:
            self.why = 'the save was written'
            return True
        if now - self.started >= LEAVE_WAIT:
            self.why = 'timeout' + ('' if getattr(callback, 'leave_applied', False) else ' (the game did not take the command)')
            return True
        return False


def dll_run(seconds, players, callback, *, player_numbers=None, game=None):
    """Replaces `native_probe.run` for one player: start the game with the core and carry the party's messages.

    `game`: an object with ROOT, EXECUTABLE, ACTIVE_HASH, DATA and ensure_windowed(folder) for a build the Python launcher does not
    know (a port test, tools/port/coop_live.py); without it the launcher's native_probe describes the game."""
    if game is None:
        import native_probe as probe
        import party_markers
    else:
        probe, party_markers = game, None
    root = Path(probe.ROOT)
    helper_exe = Path(os.environ.get('AZCOOP_HELPER') or root / 'azcoop-net.exe')
    if not helper_exe.is_file() or not (Path(probe.EXECUTABLE).parent / 'avrt.dll').is_file():
        raise RuntimeError('This folder has no azcoop-net.exe / avrt.dll: start it with Start-Coop-DLL.cmd from the DLL test pack')
    number = (player_numbers or [1])[0]
    channels = dict(getattr(callback, 'channels', None) or {})
    folder = Path(getattr(callback, 'profile_folder', None) or root / f'coop-lab/bridge-updated-player-{number}')
    folder.mkdir(parents=True, exist_ok=True)
    probe.ensure_windowed(folder)
    if getattr(callback, 'mute', False):
        mute_profile(folder)  # live tests start silent (the user's rule); a player's game is never muted
    if party_markers is not None and probe.ACTIVE_HASH in party_markers.SUPPORTED_HASHES:
        party_markers.install_minimap(folder)
    for name in ('appdata', 'localappdata'):
        (folder / name).mkdir(exist_ok=True)
    session = secrets.token_hex(8)
    stderr_log = folder / 'stderr.log'
    env = dict(os.environ, APPDATA=str(folder / 'appdata'), LOCALAPPDATA=str(folder / 'localappdata'), BENILLA_HOME=str(folder),
               WOW_ROGUE_SAVE=str(folder / 'characters.txt'), WOW_DATA=str(getattr(probe, 'DATA', None) or root / 'Data'), WOW_ROGUE_UPDATE='0',
               WOW_ROGUE_AUTOSTART=str(int(getattr(callback, 'autostart', True))), WOW_CHAR='Hero',
               RUST_LOG=os.environ.get('COOP_RUST_LOG', 'info'), WOW_MOVE_TRACE=str(folder / 'packets.log'),
               WOW_MOVE_TRACE_TAGS=os.environ.get('COOP_TRACE_TAGS', 'in,out,snd,move'),
               AZCOOP_ENGINE='1', AZCOOP_PLAYER=str(number), AZCOOP_SESSION=session, AZCOOP_BUILD=BUILD_ID,
               AZCOOP_STDERR_LOG=str(stderr_log))
    env.setdefault('COOP_PLAYERS', os.environ.get('COOP_PLAYERS', '1'))
    if not getattr(callback, 'autostart', True):
        env.pop('WOW_CHAR', None)
    logs = [open(folder / n, 'wb') for n in ('stdout.log', 'stderr.log')]
    helper_log = open(folder / 'azcoop-net-launcher.log', 'ab')
    game = helper = sock = None
    forwarder = leave = None
    try:
        log('....', f'starting the game as player {number} with the in-process core (session {session})')
        game = subprocess.Popen([str(probe.EXECUTABLE)], cwd=folder, env=env, stdout=logs[0], stderr=logs[1],
                                creationflags=subprocess.CREATE_NO_WINDOW)
        token = secrets.token_hex(32)
        try:
            helper = subprocess.Popen(
                [str(helper_exe), '--role', 'host' if number == 1 else 'guest', '--mode', 'relay', '--session', session,
                 '--game-pid', str(game.pid), '--build', BUILD_ID, '--game-sha', probe.ACTIVE_HASH, '--relay-token', token],
                cwd=folder, stdout=subprocess.PIPE, stderr=helper_log)
        except PermissionError as error:
            # 2-PC test 2: the guest's PC refused to start azcoop-net.exe (WinError 5), the game then ran alone without a party
            raise RuntimeError(helper_blocked_text(helper_exe, error)) from error
        line = helper.stdout.readline().decode('ascii', 'replace').strip()
        if not line.startswith('relay port '):
            raise RuntimeError(f'the helper did not start: {line!r}')
        sock = socket.create_connection(('127.0.0.1', int(line.split()[2])), timeout=10)
        sock.sendall(frame(KIND_HELLO, dict(token=token)))
        sock.settimeout(10)
        head = sock.recv(8)
        if len(head) < 8 or struct.unpack('<IHH', head)[1] != KIND_HELLO_ACK:
            raise RuntimeError('the helper refused the launcher')
        length = struct.unpack('<IHH', head)[0]
        if length:
            sock.recv(length)
        forwarder = Forwarder(sock, channels)
        forwarder.announce()
        log('  OK  ', f'game pid {game.pid}, helper pid {helper.pid}; carrying the party between {len(channels)} peer channel(s) and the core')
        while game.poll() is None:
            poll = getattr(callback, 'poll_network', None)
            if poll is not None:
                poll()  # the launcher's own part: Leave, commands, next-run bookkeeping
            if getattr(callback, 'stop_requested', False):
                log('INFO', 'stop requested: closing the game')
                break
            if getattr(callback, 'leave_requested', False):
                if leave is None:
                    leave = Leave(folder / 'characters.txt', time.monotonic())
                    log('INFO', 'the host is gone: asking the game to leave the run (evaluation and save) before closing it')
                if leave.step(callback, forwarder, time.monotonic()):
                    log('INFO', f'leaving done: {leave.why}, closing the game')
                    break
            flush_commands(callback, forwarder)
            alive = forwarder.step()
            dispatch_events(callback, forwarder.take_events())
            if not alive:
                log('INFO', 'the helper ended' if forwarder.helper_gone else 'the core said goodbye')
                break
        return None
    finally:
        if game is not None:
            code = game.poll()
            if code is not None:
                text = exit_text(code)
                log('INFO', f'the game ended: {text}')
                # the core's crash report (module, access, frames) into the launcher's gameplay log, which the crash upload carries
                suffix = '' if number == 1 else f'-p{number}'
                for event in crash_lines(Path(probe.EXECUTABLE).parent / f'azcoop-crash{suffix}.log'):
                    fault = event.get('fault') or {}
                    log('WARN', f'native crash {event.get("code")} at {fault.get("module")}+{fault.get("offset")} ({fault.get("where")})')
                    record = getattr(callback, 'record', None)
                    if record is not None:
                        try:
                            record(**event)
                        except Exception as error:
                            log('WARN', f'crash line not recorded: {type(error).__name__}: {error}')
                try:
                    (folder / 'azcoop-game-exit.txt').write_text(time.strftime('%H:%M:%S') + ' ' + text + chr(10), encoding='utf-8')
                except OSError:
                    pass
        if forwarder is not None:
            forwarder.finish()
            log('INFO', f'party messages: {forwarder.sent} to the core, {forwarder.received} to the peers')
        if sock is not None:
            try:
                sock.sendall(frame(KIND_GOODBYE, dict(reason='launcher')))
            except OSError:
                pass
            sock.close()
        if game is not None and game.poll() is None:
            game.terminate()
            try:
                game.wait(10)
            except subprocess.TimeoutExpired:
                game.kill()
        if helper is not None and helper.poll() is None:
            try:
                helper.wait(5)
            except subprocess.TimeoutExpired:
                helper.kill()
        for stream in (*logs, helper_log):
            stream.close()


def install():
    """Patch the launcher process: the game runs with the core, the party's channels stay in Python."""
    import group_online
    import native_probe
    native_probe.run = dll_run
    group_online.GroupOnlineBridge.poll_network = lambda self: None  # the channels belong to the Forwarder now
    # the run's end, the victory choice and the next-run offer live in the core: the launcher's calls become commands
    group_online.GroupOnlineBridge.run_over = bridge_run_over
    group_online.GroupOnlineBridge.request_victory_action = bridge_request_victory_action
    group_online.GroupOnlineBridge.offer_next_run = bridge_offer_next_run
    log('INFO', 'DLL test shim installed: the game will run with the in-process core')
