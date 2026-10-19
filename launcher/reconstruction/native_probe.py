"""Build-pinned debugger adapter. Only launches/edits disposable lab processes.

No on-disk EXE edits. Breakpoints capture plaintext world packets, never auth
keys. All owned processes are terminated on exit, including on adapter failure.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import tempfile
from updated_layout import rva as relocated, configure, reviewed_bytes, field

ROOT = Path(__file__).resolve().parents[1]
HASH = '900f6ea6313a2eb4ef8d7d06c706d559a046f2ec68055b4204e42048df0413a5'
TICK, SERIALIZE, WRITE = 0x5399A40, 0x53C9E50, 0x546A180
PAUSE, RESUME = 0x53F17D0, 0x53F5E70
START, AWARD_XP, CHOOSE = 0x53F1A50, 0x53F4510, 0x54154E0
DAMAGE = 0x53FF4B0
# Player damage to one enemy (one native hit or one batch delta) and enemy hits
# on players: plausibility bounds far above endless play (play_limits.py), not
# anti-cheat: co-op peers are trusted friends.
from play_limits import MAX_ENEMY_DAMAGE, MAX_HIT_DAMAGE, MAX_COUNTER, MAX_NATIVE_READ, MAX_QUEUE  # noqa: E402
from crash_modules import (ModuleTable, classify, crash_event, describe, image_size, parse_exception,  # noqa: E402
                           parse_load_dll, parse_unload_dll, STACK_BYTES)
MOVE = 0x53D59D0
HURT = 0x53D1950
DEFEAT_UI = 0x53F5AE0
UI_COMMAND = 0x53A8950
SPAWN = 0x53FE7B0
FIND_SPAWN = 0x53FF160
APPLY_EFFECT = 0x541DBD0
APPLY_DOT = 0x545B240
ENEMY_AOE = 0x53E6063
GROUND_AOE = 0x53E1881
ENEMY_TARGET = 0x53E5577
SPAWN_BOSS = 0x53FCB90
HUD_DELIVER = 0x53A0160
MAP_SELECT = None
BOSS_DEATH = None
MENU_CONTRACT = None
MENU_LOGIN = None
SPAWN_LOOT, REMOVE_LOOT, OFFER_CHOICES = 0x5404880, 0x5405B40, 0x540D310
BUILD = os.environ.get('COOP_BUILD', 'updated')
OBSERVE_UPDATE = __name__ == '__main__' and '--observe-update' in sys.argv
TEST_UPDATE_DAMAGE = __name__ == '__main__' and '--test-update-damage' in sys.argv
TEST_UPDATE_BOSS = __name__ == '__main__' and ('--test-update-boss' in sys.argv or TEST_UPDATE_DAMAGE)
TEST_UPDATE_PROGRESSION = __name__ == '__main__' and ('--test-update-progression' in sys.argv or TEST_UPDATE_BOSS)
TEST_UPDATE_CALLS = __name__ == '__main__' and ('--test-update-calls' in sys.argv or TEST_UPDATE_PROGRESSION)
if OBSERVE_UPDATE and TEST_UPDATE_CALLS:
    raise ValueError('Read-only observation and candidate calls are separate tests')
if BUILD not in ('legacy', 'updated'):
    raise ValueError('COOP_BUILD must be legacy or updated')
EXECUTABLE = ROOT / ('AzerothSurvivors.exe' if BUILD == 'updated' else 'coop-lab/AzerothSurvivors.exe')
_diagnostic_executable = os.environ.get('COOP_EXECUTABLE')
_candidate_adapter = os.environ.get('COOP_CANDIDATE_PROFILE')
_candidate_home = None
if _candidate_adapter:
    if BUILD != 'updated' or OBSERVE_UPDATE or TEST_UPDATE_CALLS:
        raise ValueError('Full adapter acceptance and scoped update tests are separate')
    _candidate_home = Path(os.environ.get('COOP_CANDIDATE_HOME', '')).resolve()
    _candidate_parent = (ROOT / 'coop-lab/compatibility-tests').resolve()
    if _candidate_parent not in _candidate_home.parents or not _candidate_home.is_dir():
        raise ValueError('Candidate acceptance requires a disposable compatibility-test directory')
if _diagnostic_executable:
    # Diagnostic selection only: it receives the same compatibility and launch
    # hash checks as the default executable, and cannot bless a new game build.
    EXECUTABLE = Path(_diagnostic_executable).resolve(strict=True)
ACTIVE_HASH = ('20d4ce5fb1232dac64bc00a4d8c9f2bcae43fb8373ea3fa95350ab8c4f20d618'
               if BUILD == 'updated' else HASH)
IMAGE_SIZE = 126312448 if BUILD == 'updated' else 125792256
if BUILD == 'updated':
    # Bootstrap entries are resolved only from reviewed, unique signatures.
    from build_hooks import resolve_reviewed_profile, UPDATED_HASH
    if _candidate_adapter:
        from build_hooks import load_isolated_adapter_profile
        _profile, _adapter_runtime = load_isolated_adapter_profile(EXECUTABLE, _candidate_adapter, with_runtime=True)
    elif OBSERVE_UPDATE or TEST_UPDATE_CALLS:
        from build_hooks import discover_observation_profile
        _profile = discover_observation_profile(EXECUTABLE, candidate_calls=TEST_UPDATE_CALLS,
                                                progression_calls=TEST_UPDATE_PROGRESSION, boss_calls=TEST_UPDATE_BOSS,
                                                damage_calls=TEST_UPDATE_DAMAGE)
    else:
        _profile = resolve_reviewed_profile(
            EXECUTABLE, allow_runtime_relocation=True,
            report_directory=ROOT / 'analysis/diagnostic-hooks' if _diagnostic_executable else None)
    _resolved = {name: row['candidates'][0] for name, row in _profile['hooks'].items()}
    ACTIVE_HASH = _profile['sha256']
    if OBSERVE_UPDATE or TEST_UPDATE_CALLS or _candidate_adapter or _profile.get('status') == 'verified_adapter':
        IMAGE_SIZE = _profile['image_size']
    configure(None)
    if _candidate_adapter or _profile.get('status') == 'verified_adapter':
        from runtime_addresses import RuntimeAddresses
        configure(_adapter_runtime if _candidate_adapter else RuntimeAddresses.from_adapter_profile(
            ROOT / 'reconstruction/reference-metadata.json', EXECUTABLE,
            _profile['adapter_profile'], isolated=bool(_candidate_adapter)))
    if _profile.get('status') == 'verified_runtime_relocation':
        from runtime_addresses import RuntimeAddresses
        _runtime = RuntimeAddresses(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe',
                                    EXECUTABLE, _profile['relocation_profile']['moves'])
        if _runtime.profile['sha256'] != ACTIVE_HASH:
            raise ValueError('Executable changed while preparing native addresses')
        configure(_runtime)
    TICK, SERIALIZE, WRITE = 0x53BC070, 0x543D620, 0x5487630
    PAUSE, RESUME, START = 0x53FCC80, 0x5401520, 0x53FCE50
    AWARD_XP, CHOOSE, MOVE = 0x53FFBC0, 0x5420AD0, 0x53E05D0
    DAMAGE, HURT = 0x540AC40, 0x53DBFD0
    SPAWN, SPAWN_BOSS, FIND_SPAWN = 0x5409F40, 0x5408300, 0x540A8F0
    SPAWN_LOOT, REMOVE_LOOT, OFFER_CHOICES = 0x5410160, 0x5411420, 0x5418CA0
    APPLY_EFFECT, DEFEAT_UI, UI_COMMAND = 0x5429180, 0x5401190, 0x53CAF70
    APPLY_DOT = 0x5478540
    MAP_SELECT = 0x539A680
    BOSS_DEATH = 0x540C39A
    ENEMY_AOE, GROUND_AOE, ENEMY_TARGET, HUD_DELIVER = 0x53F14A3, 0x53ECC71, 0x53F09B7, 0x53C2780
    _hook_reference = {}
    for _name in ('TICK', 'SERIALIZE', 'WRITE', 'PAUSE', 'RESUME', 'START', 'AWARD_XP',
                  'CHOOSE', 'MOVE', 'DAMAGE', 'HURT', 'SPAWN', 'SPAWN_BOSS', 'FIND_SPAWN',
                  'SPAWN_LOOT', 'REMOVE_LOOT', 'OFFER_CHOICES', 'APPLY_EFFECT', 'DEFEAT_UI',
                  'UI_COMMAND', 'ENEMY_AOE', 'GROUND_AOE', 'ENEMY_TARGET', 'HUD_DELIVER', 'APPLY_DOT', 'MAP_SELECT', 'BOSS_DEATH'):
        if (OBSERVE_UPDATE or TEST_UPDATE_CALLS) and _name not in _resolved:
            globals()[_name] = None
            continue
        _hook_reference[_resolved[_name]] = globals()[_name]
        globals()[_name] = _resolved[_name]
    if not (OBSERVE_UPDATE or TEST_UPDATE_CALLS):
        MENU_CONTRACT = _profile.get('menu_contract')
        if MENU_CONTRACT is not None:
            MENU_LOGIN = MENU_CONTRACT['login']['branch']
k = C.WinDLL('kernel32', use_last_error=True)


def api(name, result, *args):
    f = getattr(k, name)
    f.restype, f.argtypes = result, args
    return f


read = api('ReadProcessMemory', W.BOOL, W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p)
write = api('WriteProcessMemory', W.BOOL, W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p)
protect = api('VirtualProtectEx', W.BOOL, W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, C.c_void_p)
flush = api('FlushInstructionCache', W.BOOL, W.HANDLE, C.c_void_p, C.c_size_t)
get_context = api('GetThreadContext', W.BOOL, W.HANDLE, C.c_void_p)
set_context = api('SetThreadContext', W.BOOL, W.HANDLE, C.c_void_p)
wait = api('WaitForDebugEvent', W.BOOL, C.c_void_p, W.DWORD)
cont = api('ContinueDebugEvent', W.BOOL, W.DWORD, W.DWORD, W.DWORD)
close = api('CloseHandle', W.BOOL, W.HANDLE)
allocate = api('VirtualAllocEx', C.c_void_p, W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, W.DWORD)
final_path = api('GetFinalPathNameByHandleW', W.DWORD, W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD)
windows_dir = api('GetSystemWindowsDirectoryW', W.UINT, W.LPWSTR, W.UINT)


def handle_path(handle):
    """Path of an open file handle (a loaded DLL), or None; only its file name ever leaves the launcher."""
    try:
        buffer = C.create_unicode_buffer(1024)
        length = final_path(handle, buffer, 1024, 0)
        return buffer.value if 0 < length < 1024 else None
    except Exception:
        return None


def system_directory():
    try:
        buffer = C.create_unicode_buffer(260)
        return buffer.value if 0 < windows_dir(buffer, 260) < 260 else None
    except Exception:
        return None


WINDOWS_DIR = system_directory()


def checked(ok):
    if not ok:
        raise C.WinError(C.get_last_error())
    return ok


def q(data, offset=0):
    return struct.unpack_from('<Q', data, offset)[0]


CONTEXT_REGISTERS = dict(zip(('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'), range(120, 248, 8)))


def validate_bootstrap_owner(client, rva, context, contracts):
    """Enforce the changed-build interception ABI before adapter reads/writes."""
    if rva == TICK:
        flag, timestamp = struct.unpack('<I4xd', client.memory(q(context, 128), 16))
        if flag not in (0, 1) or not math.isfinite(timestamp):
            raise ValueError('Native server header violates its bootstrap contract')
        return
    if not client.server:
        if rva in (HUD_DELIVER, SERIALIZE):
            raise ValueError('Native output arrived before its server owner was captured')
        return
    if rva == HUD_DELIVER:
        hud = contracts['hud']
        owner = (q(client.memory(q(context, 160) + hud['server_stack_offset'], 8))
                 if 'server_stack_offset' in hud else q(context, CONTEXT_REGISTERS[hud['server_register']]))
        if (owner != client.server
                or q(context, 128) != q(client.memory(owner + hud['receiver_field'], 8))
                or q(context, 120) != q(client.memory(owner + hud['vtable_field'], 8))):
            raise ValueError('Native HUD receiver violates its owned server contract')
    if rva not in (WRITE, SERIALIZE):
        return
    batch, vector = contracts['batch'], contracts['connection']
    if rva == WRITE and q(client.memory(q(context, 152), 8)) != client.base + int(batch['return_rva'], 16):
        return
    pointer, count = (q(client.memory(client.server + vector[key], 8)) for key in ('pointer_field', 'count_field'))
    capacity = q(client.memory(client.server + vector['capacity_field'], 8))
    if not 0 <= count <= capacity <= 16 or (count and not pointer):
        raise ValueError('Native connection vector violates allocation bounds')
    if rva == WRITE and batch.get('connection_source') == 'owned_queue':
        matches = [pointer + i * vector['element_size'] for i in range(count)
                   if q(client.memory(pointer + i * vector['element_size'] + batch['queue_field'], 8))
                   + batch['queue_offset'] == q(context, 128)]
        if len(matches) != 1:
            raise ValueError('Native outgoing queue has no unique owned connection')
        connection = matches[0]
    else:
        connection = q(context, 128 if rva == SERIALIZE else CONTEXT_REGISTERS[batch['connection_register']])
    owned = (count > 0 and pointer <= connection < pointer + count * vector['element_size']
             and (connection - pointer) % vector['element_size'] == 0)
    if rva == SERIALIZE and not owned:
        # Login also serializes through connections not yet owned by this
        # server vector. Leave those calls completely native: no packet reads,
        # filtering, template capture or callback until ownership is established.
        return False
    if not owned:
        raise ValueError('Native packet connection is outside the owned vector')
    if rva == WRITE:
        owner = (q(client.memory(q(context, 160) + vector['server_stack_offset'], 8))
                 if 'server_stack_offset' in vector else q(context, CONTEXT_REGISTERS[vector['server_register']]))
        if owner != client.server:
            raise ValueError('Native batch uses another server owner')
        frame = q(context, CONTEXT_REGISTERS[batch['packet_stack_register']])
        if (q(client.memory(connection + batch['queue_field'], 8)) + batch['queue_offset'] != q(context, 128)
                or q(client.memory(frame + batch['packet_buffer_stack_offset'], 8)) != q(context, 136)
                or q(client.memory(frame + batch['packet_length_stack_offset'], 8)) != q(context, 184)):
            raise ValueError('Native batch frame disagrees with its outgoing arguments')
        ui = batch['ui_vector']
        ui_frame = q(context, CONTEXT_REGISTERS[ui['stack_register']])
        capacity, count = (q(client.memory(ui_frame + ui[key], 8)) for key in ('capacity', 'count'))
        if not 0 <= count <= capacity <= MAX_QUEUE:
            raise ValueError('Native batch UI vector violates allocation bounds')


CONNECTIONS = field('server', 0x918) if BUILD == 'updated' else 0x908


def game_field(legacy_offset):
    if BUILD == 'updated' and legacy_offset not in (0x33C, 0x488, 0x498, 0x4A0, 0x4A8, 0x4F8, 0x4FC,
            0x510, 0x514, 0x528, 0x568, 0x570, 0x5C8, 0x5E0, 0x618, 0x6D0, 0x6D4, 0x730,
            0x7F0, 0x7F8, 0x808, 0x85C, 0x860, 0x864, 0x894, 0x8B5, 0x8BF):
        raise ValueError('Updated game field has not been reviewed')
    return field('game', legacy_offset + 0x10) if BUILD == 'updated' else legacy_offset


def defeat_ui_code(base):
    """Use native result serialization and native Vec allocation/ownership."""
    call = lambda rva: b'\x48\xb8' + struct.pack('<Q', base + rva) + b'\xff\xd0'
    code = bytearray(bytes.fromhex('53 57 4883ec48 4889cb 488d4c2430 4889da'))
    code.extend(b'\x49\xb8' + struct.pack('<Q', base + relocated(0x6622698)))
    code.extend(bytes.fromhex('41b906000000') + call(DEFEAT_UI))
    length, capacity, pointer = ((0x610, 0x600, 0x608) if BUILD == 'updated' else (0x600, 0x5F0, 0x5F8))
    if BUILD == 'updated':
        length, capacity, pointer = (field('game', offset) for offset in (length, capacity, pointer))
    code.extend(b'\x48\x8b\xbb' + struct.pack('<I', length) + b'\x48\x3b\xbb' + struct.pack('<I', capacity))
    reserve = b'\x48\x8d\x8b' + struct.pack('<I', capacity) + call(relocated(0x566ED90))
    code.extend(b'\x75' + bytes([len(reserve)]) + reserve)
    code.extend(b'\x48\x8b\x83' + struct.pack('<I', pointer) + bytes.fromhex('488d0c7f 0f10442430 0f1104c8'))
    code.extend(bytes.fromhex('488b542440 488954c810 48ffc7 4889bb') + struct.pack('<I', length))
    code.extend(bytes.fromhex('4883c448 5f 5b c3'))
    return bytes(code)


def ensure_windowed(folder):
    """Keep disposable lab profiles windowed, including newly created profiles."""
    path = folder / 'config.toml'
    original = path.read_text(encoding='utf-8') if path.exists() else ''
    text = original
    section = re.search(r'(?m)^\[cvars\]\s*\r?$', text)
    if section is None:
        text = text.rstrip() + '\n[cvars]\n'
        section = re.search(r'(?m)^\[cvars\]\s*\r?$', text)
    start = section.end()
    following = re.search(r'(?m)^\[', text[start:])
    end = start + following.start() if following else len(text)
    body = text[start:end]
    window = re.compile(r'(?m)^gxWindow\s*=.*$')
    if window.search(body):
        body = window.sub('gxWindow = "1"', body)
    else:
        body = body.rstrip() + '\ngxWindow = "1"\n'
    if not re.search(r'(?m)^gxResolution\s*=', body):
        body = body.rstrip() + '\ngxResolution = "1100x700"\n'
    text = text[:start] + body + text[end:]
    if text != original:
        path.write_text(text, encoding='utf-8')


# Live test games start silent (user request 18.10.2026): the game's own sound CVars in the disposable profile.
TEST_SILENCE = {'MasterSoundEffects': '0', 'MasterVolume': '0', 'SoundVolume': '0', 'MusicVolume': '0',
                'AmbienceVolume': '0', 'EnableMusic': '0', 'EnableAmbience': '0', 'EnableErrorSpeech': '0',
                'Sound_EnableSoundWhenGameIsInBG': '0'}


def mute_test_profile(folder):
    """Volume 0 in a disposable test profile's config.toml ([cvars]); never called for a player's own profile."""
    path = folder / 'config.toml'
    text = path.read_text(encoding='utf-8') if path.exists() else ''
    section = re.search(r'(?m)^\[cvars\]\s*\r?$', text)
    if section is None:
        text = text.rstrip() + '\n[cvars]\n'
        section = re.search(r'(?m)^\[cvars\]\s*\r?$', text)
    start = section.end()
    following = re.search(r'(?m)^\[', text[start:])
    end = start + following.start() if following else len(text)
    body = text[start:end]
    for name, value in TEST_SILENCE.items():
        line = re.compile(rf'(?m)^{name}\s*=.*$')
        if line.search(body):
            body = line.sub(f'{name} = "{value}"', body)
        else:
            body = body.rstrip() + f'\n{name} = "{value}"\n'
    path.write_text(text[:start] + body + text[end:], encoding='utf-8')


class Native:
    def __init__(self, number, autostart=True, profile_folder=None, character_name='Hero', test_corner_slot=None):
        if C.sizeof(C.c_void_p) != 8:
            raise RuntimeError('Co-op requires 64-bit Python for the 64-bit game')
        if hashlib.sha256(EXECUTABLE.read_bytes()).hexdigest() != ACTIVE_HASH:
            raise RuntimeError('Executable changed after hook verification; restart co-op')
        self.number = number
        self.folder = Path(profile_folder) if profile_folder else (
            _candidate_home / f'player-{number}' if _candidate_home else
            ROOT / f'coop-lab/bridge-{"updated-" if BUILD == "updated" else ""}player-{number}')
        if _candidate_home and _candidate_home not in self.folder.resolve().parents:
            raise ValueError('Candidate game saves must remain inside the disposable test directory')
        self.folder.mkdir(exist_ok=True)
        ensure_windowed(self.folder)
        if _candidate_home:  # Only disposable acceptance/test profiles; a player's own settings are never touched.
            mute_test_profile(self.folder)
            print(f'[ INFO ] volume 0 in profile {self.folder.name} (test game starts silent)', flush=True)
        from party_markers import SUPPORTED_HASHES, install_minimap
        if ACTIVE_HASH in SUPPORTED_HASHES:
            install_minimap(self.folder)
        for name in ('appdata', 'localappdata'):
            (self.folder / name).mkdir(exist_ok=True)
        env = dict(os.environ, APPDATA=str(self.folder / 'appdata'),
                   LOCALAPPDATA=str(self.folder / 'localappdata'), BENILLA_HOME=str(self.folder),
                   WOW_ROGUE_SAVE=str(self.folder / 'characters.txt'), WOW_DATA=str(ROOT / 'Data'),
                   WOW_ROGUE_UPDATE='0', WOW_ROGUE_AUTOSTART=str(int(autostart)), WOW_CHAR=character_name,
                   RUST_LOG=os.environ.get('COOP_RUST_LOG', 'info'),
                   WOW_MOVE_TRACE=str(self.folder / 'packets.log'),
                   WOW_MOVE_TRACE_TAGS=os.environ.get('COOP_TRACE_TAGS', 'in,out,snd,move'))
        # Keep native breakpoints without Windows' debug-heap teardown slowdown.
        env['_NO_DEBUG_HEAP'] = '1'
        if not autostart:
            env.pop('WOW_CHAR', None)
        self.window_placement = None
        if test_corner_slot is not None:
            if not _candidate_home or test_corner_slot != number or number not in (1, 2, 3, 4):
                raise ValueError('Corner placement requires a disposable local candidate test')
            from native_window_layout import TestWindowPlacement
            import tomllib
            viewport = tomllib.loads((self.folder / 'config.toml').read_text(encoding='utf-8'))['cvars']['gxResolution']
            self.window_placement = TestWindowPlacement(0, number, viewport)
        self.logs = [open(self.folder / n, 'wb') for n in ('stdout.log', 'stderr.log')]
        self.process = subprocess.Popen([str(EXECUTABLE)],
            cwd=self.folder, env=env, stdout=self.logs[0], stderr=self.logs[1],
            creationflags=2 | subprocess.CREATE_NO_WINDOW)
        if self.window_placement is not None:
            self.window_placement.pid = self.process.pid
        self.threads, self.breakpoints = {}, {}
        self.modules = ModuleTable()  # Crash report schema 2: which module or co-op buffer a fault lies in.
        self.handle = self.base = self.server = self.connection = 0
        self.installed = False
        self.captured = 0
        self.disable_hooks = set()
        self.extra_hooks = ()
        self.call_return = 0
        self.saved_context = None
        adapter = _profile.get('adapter_profile', {}) if BUILD == 'updated' else {}
        self.adapter_live_contracts = adapter.get('native_live_contracts')
        self.damage_guard_contract = adapter.get('damage_guard')
        self.effect_guard_contract = adapter.get('effect_guard')
        self.dispatch_guard_contracts = adapter.get('dispatch_guards', ())

    def memory(self, address, size):
        if not 0 <= size <= MAX_NATIVE_READ:
            raise ValueError('Unreasonable native read')
        b = C.create_string_buffer(size)
        checked(read(self.handle, address, b, size, None))
        return b.raw

    def put(self, address, data):
        checked(write(self.handle, address, data, len(data), None))

    def patch(self, address, data):
        old = W.DWORD()
        checked(protect(self.handle, address, len(data), 0x40, C.byref(old)))
        self.put(address, data)
        checked(protect(self.handle, address, len(data), old.value, C.byref(W.DWORD())))
        checked(flush(self.handle, address, len(data)))

    def executable_buffer(self, data, *, near=None):
        if OBSERVE_UPDATE or TEST_UPDATE_CALLS:
            raise ValueError('Update observation cannot install executable adapters')
        if near is None:
            address = checked(allocate(self.handle, None, len(data), 0x3000, 4))
        else:
            address = 0
            start = (self.base + IMAGE_SIZE + 0xffff) & ~0xffff
            for candidate in range(start, min(start + 0x10000000, near + 0x7fff0000), 0x10000):
                address = allocate(self.handle, candidate, len(data), 0x3000, 4)
                if address:
                    break
            if not address:
                raise RuntimeError('No nearby memory for the native dispatch guard')
        self.put(address, data)
        checked(protect(self.handle, address, len(data), 0x20, C.byref(W.DWORD())))
        checked(flush(self.handle, address, len(data)))
        self.modules.add(address, len(data), 'co-op code', 'coop')
        return address

    def context(self, tid):
        # Windows AMD64 CONTEXT requires 16-byte alignment.
        storage = C.create_string_buffer(1248)
        offset = (-C.addressof(storage)) % 16
        context = (C.c_ubyte * 1232).from_buffer(storage, offset)
        struct.pack_into('<I', context, 48, 0x10000B)  # Control, integer and XMM state.
        checked(get_context(self.threads[tid], context))
        return context

    def install(self):
        guards = {guard['rva']: guard for guard in (
            getattr(self, 'damage_guard_contract', None), getattr(self, 'effect_guard_contract', None)) if guard}
        for rva in dict.fromkeys((TICK, SERIALIZE, WRITE, *self.extra_hooks, *guards)):
            if MENU_CONTRACT is not None and rva == MENU_LOGIN and self.number == 1:
                continue  # Host uses its original single-player unlock check.
            address = self.base + rva
            expected = b'\x41\x57' if rva == SERIALIZE else b'\x41\x56' if rva == FIND_SPAWN else b'\x55'
            if rva == ENEMY_AOE:
                expected = bytes.fromhex('0f82c7f3ffff')
            elif rva == GROUND_AOE:
                expected = bytes.fromhex('7215')
            elif rva == ENEMY_TARGET:
                expected = bytes.fromhex('f2410f108998040000' if BUILD == 'updated' else 'f2410f108988040000')
            elif rva == HUD_DELIVER:
                expected = bytes.fromhex('ff5020')
            elif rva == BOSS_DEATH:
                expected = bytes.fromhex('488b8578010000')
            elif MENU_CONTRACT is not None and rva == MENU_LOGIN:
                expected = bytes.fromhex(MENU_CONTRACT['login']['expected'])
                if len(expected) != 2 or expected[0] != 0x75:
                    raise ValueError('Unsupported native menu login branch')
            if rva in guards:
                expected = bytes.fromhex(guards[rva]['expected'])
            elif (OBSERVE_UPDATE or TEST_UPDATE_CALLS) and hex(rva) in _profile.get('observation_sites', {}):
                expected = bytes.fromhex(_profile['observation_sites'][hex(rva)]['expected'])
            elif TEST_UPDATE_DAMAGE and rva == _profile['damage_call_contract']['guard_instruction']['rva']:
                expected = bytes.fromhex(_profile['damage_call_contract']['guard_instruction']['expected'])
            elif BUILD == 'updated' and rva != MENU_LOGIN:
                expected = reviewed_bytes(_hook_reference[rva], expected)
            original = self.memory(address, len(expected))
            if original != expected:
                raise RuntimeError(f'Unexpected instruction at RVA {rva:x}: {original.hex()}')
            self.breakpoints[address] = original
            self.patch(address, b'\xcc')
        self.installed = True

    def call_before(self, context, rva, argument, second=0, *, damage=None, after=None, request=False, ui_only=False, position=None, amount=1, effect=None, spell=0, periodic=None, melee=True, entry_code=None):
        """Run a verified void(game*) function on the stopped server thread.

        Restore its complete register context before retrying the queue writer.
        The caller already holds the native game lock. Never use a remote thread.
        """
        if OBSERVE_UPDATE:
            raise ValueError('Update observation cannot invoke native functions')
        if TEST_UPDATE_CALLS:
            contract = next((row for row in _profile['candidate_call_contract']['entries'].values()
                             if row['entry'] == rva), None)
            if (contract is None or argument != getattr(self, 'observed_game', None)
                    or any((request, ui_only, entry_code is not None, damage is not None and rva != DAMAGE, position is not None,
                            effect is not None, periodic is not None, spell != 0, amount != 1))):
                raise ValueError('Call is outside the isolated candidate contract')
            bounds = contract.get('second', {'min': 0, 'max': 0})
            maximum = bounds.get('max')
            if rva == SPAWN_BOSS:
                boss = candidate_boss_definition(self, argument, _profile['boss_call_contract'])
                bounds = {'min': boss['pointer']}
                maximum = boss['pointer']
            if rva == DAMAGE:
                damage_contract = _profile['damage_call_contract']
                source = damage_contract['fields']['source_tag']
                if int.from_bytes(self.memory(argument + source['offset'], source['width']), 'little') > damage_contract['guard_instruction']['maximum']:
                    raise ValueError('Native damage source tag is outside the proved dispatch domain')
                candidate_enemy_state(self, argument, damage_contract, second)
                bounds, maximum = {'min': second}, second
                allowed = contract['damage_bounds']
                if (not isinstance(damage, (int, float)) or not math.isfinite(damage)
                        or not allowed['min_exclusive'] < damage <= allowed['max'] or not melee):
                    raise ValueError('Candidate melee damage is outside its proved bound')
            if bounds.get('exclusive_max') == 'choices_count':
                field_spec = _profile['progression_call_contract']['fields']['choices_count']
                count = int.from_bytes(self.memory(argument + field_spec['offset'], field_spec['width']), 'little')
                if not 1 <= count <= 32:
                    raise ValueError('Candidate choice count is outside its native bound')
                maximum = count - 1
            if type(second) is not int or maximum is None or not bounds['min'] <= second <= maximum:
                raise ValueError('Candidate call integer argument is outside its bound')
            if self.memory(argument + contract['game_phase_offset'], 1)[0] != contract['initial_phase']:
                raise ValueError('Candidate call is outside its admitted native phase')
            expected = bytes.fromhex(contract['expected'])
            if self.memory(self.base + rva, len(expected)) != expected:
                raise ValueError('Candidate call entry changed')
        owned_entry = rva is None and isinstance(entry_code, bytes) and 1 <= len(entry_code) <= 4096
        if (not owned_entry and rva not in (PAUSE, RESUME, START, AWARD_XP, CHOOSE, DAMAGE, HURT, DEFEAT_UI, UI_COMMAND, SPAWN, SPAWN_LOOT, REMOVE_LOOT, OFFER_CHOICES, APPLY_EFFECT, APPLY_DOT, SPAWN_BOSS)) or self.saved_context is not None:
            raise ValueError('Unsupported or nested native call')
        if rva == SPAWN_BOSS and not self.base <= second < self.base + IMAGE_SIZE - 0x58:
            raise ValueError('Unverified boss definition')
        if rva in (DAMAGE, HURT, APPLY_DOT) and (damage is None or not 0 < damage <= (
                MAX_ENEMY_DAMAGE if rva == DAMAGE else MAX_HIT_DAMAGE)):
            raise ValueError('Invalid native damage')
        if rva == APPLY_DOT:
            if periodic is None or len(periodic) != 3 or not 1 <= second <= 0xFFFFFFFF:
                raise ValueError('Invalid periodic effect')
            duration, ticks, clock = periodic
            if not (math.isfinite(duration) and 0 < duration <= 3600 and
                    isinstance(ticks, int) and 1 <= ticks <= 1000 and math.isfinite(clock) and clock >= 0):
                raise ValueError('Invalid periodic timing')
        if rva == SPAWN and (position is None or len(position) != 3 or
                             not all(math.isfinite(v) for v in position) or not 0 <= second <= 11):
            raise ValueError('Invalid native mirror spawn')
        if rva == SPAWN_LOOT and (position is None or len(position) != 3 or
                                 not all(math.isfinite(v) for v in position) or
                                 second not in (0, 1, 2) or not 1 <= amount <= MAX_COUNTER):
            raise ValueError('Invalid native loot spawn')
        if rva == OFFER_CHOICES and second not in (0, 1, 2):
            raise ValueError('Invalid native choice kind')
        if rva == APPLY_EFFECT:
            if effect is None or len(effect) != 12 or not 0 <= spell <= 0xFFFFFFFF:
                raise ValueError('Invalid native enemy effect')
            kind, value, duration = struct.unpack('<Iff', effect)
            if (kind not in (1, 2, 3, 4, 10) or not math.isfinite(value) or
                    not 0 <= value <= (1 if kind in (1, 10) else 3600) or
                    (kind in (1, 10) and (not math.isfinite(duration) or not 0 <= duration <= 3600))):
                raise ValueError('Unsupported native enemy effect')
        if owned_entry:
            if not hasattr(self, 'owned_call_entries'):
                self.owned_call_entries = {}
            if entry_code not in self.owned_call_entries:
                self.owned_call_entries[entry_code] = self.executable_buffer(entry_code)
            entry = self.owned_call_entries[entry_code]
        else:
            entry = self.base + rva
        if rva == DEFEAT_UI:
            if not hasattr(self, 'defeat_ui_entry'):
                self.defeat_ui_entry = self.executable_buffer(defeat_ui_code(self.base))
            entry = self.defeat_ui_entry
        if ui_only:
            if rva not in (PAUSE, RESUME):
                raise ValueError('Only pause UI can bypass gameplay state')
            # Same native stack frame, followed by its owned JSON allocation path.
            # Do not unroot or revive a dead character merely to change its menu.
            prefix = bytes.fromhex('55 56 57 53 4881ec88000000 488dac2480000000 48c74500feffffff')
            if self.memory(entry + 1, len(prefix) - 1) != prefix[1:]:
                raise RuntimeError('Native pause UI prologue changed')
            if not hasattr(self, 'pause_ui_entries'):
                self.pause_ui_entries = {}
            if rva not in self.pause_ui_entries:
                target = self.base + relocated(0x53F186E if rva == PAUSE else 0x53F5FDB)
                self.pause_ui_entries[rva] = self.executable_buffer(
                    prefix + b'\x48\x89\xce\xff\x25\0\0\0\0' + struct.pack('<Q', target))
            entry = self.pause_ui_entries[rva]
        if not self.call_return:
            self.call_return = checked(allocate(self.handle, None, 4096, 0x3000, 4))
            self.modules.add(self.call_return, 4096, 'co-op call return', 'coop')
            self.put(self.call_return, b'\xcc')
            checked(protect(self.handle, self.call_return, 4096, 0x20, C.byref(W.DWORD())))
            checked(flush(self.handle, self.call_return, 1))
        self.saved_context = bytes(context)
        self.after_call, self.call_is_request = after, request
        stack = q(context, 152) - 0x100
        if stack % 16 != 8:
            raise ValueError('Unexpected native function-entry stack alignment')
        self.put(stack, struct.pack('<Q', self.call_return))
        struct.pack_into('<Q', context, 152, stack)
        struct.pack_into('<Q', context, 128, argument)
        struct.pack_into('<Q', context, 136, second)
        if rva == APPLY_EFFECT:
            self.put(stack + 0x60, effect)
            struct.pack_into('<Q', context, 184, stack + 0x60)
            self.put(stack + 0x28, struct.pack('<Q', spell))
        elif rva == APPLY_DOT:
            struct.pack_into('<Q', context, 184, 0)  # Physical school.
            struct.pack_into('<f', context, 464, damage)  # XMM3 total damage.
            # Updated effects carry a tagged source plus source GUID (48-byte entries).
            args = ((duration, ticks, 0, 0, 0, 1, clock) if BUILD == 'updated'
                    else (duration, ticks, 0, 0, 1, clock))
            self.put(stack + 0x28, struct.pack('<f4xQf4xQQQf4x' if BUILD == 'updated' else '<f4xQf4xQQf4x', *args))
        struct.pack_into('<Q', context, 248, entry)
        if rva == DAMAGE:
            struct.pack_into('<f', context, 448, damage)  # Third argument: XMM2.
            struct.pack_into('<Q', context, 192, 0)  # Basic melee, no spell ID.
            self.put(stack + 0x28, struct.pack('<QQQ', 0, 0, 1))
        elif rva == HURT:
            struct.pack_into('<f', context, 432, damage)
            struct.pack_into('<Q', context, 184, second)
            struct.pack_into('<Q', context, 192, int(melee))
        elif rva == SPAWN:
            self.put(stack + 0x60, struct.pack('<I3f', 1, *position))
            struct.pack_into('<Q', context, 184, stack + 0x60)
        elif rva == SPAWN_LOOT:
            self.put(stack + 0x60, struct.pack('<3f', *position))
            struct.pack_into('<Q', context, 184, amount)
            struct.pack_into('<Q', context, 192, stack + 0x60)
        elif rva == OFFER_CHOICES:
            struct.pack_into('<Q', context, 184, 1)

    def breakpoint(self, tid, address, callback):
        context = self.context(tid)
        struct.pack_into('<Q', context, 248, address)
        rva = address - self.base
        live = getattr(self, 'adapter_live_contracts', None)
        instrument = True
        if live:
            instrument = validate_bootstrap_owner(self, rva, context, live) is not False
        guard = getattr(self, 'damage_guard_contract', None)
        effect_guard = getattr(self, 'effect_guard_contract', None)
        if guard and rva == guard['rva']:
            emulate_damage_tag_guard(self, context, guard)
        elif effect_guard and rva == effect_guard['rva']:
            tag = emulate_effect_tag_guard(self, context, effect_guard)
            if hasattr(callback, 'record'):
                seen = getattr(self, 'effect_guard_tags', set())
                if tag not in seen:
                    callback.record(event='native_effect_dispatch_guard', player=self.number, tag=tag)
                    seen.add(tag)
                    self.effect_guard_tags = seen
        elif instrument:
            callback(self, rva, context)
        elif not getattr(self, 'unowned_serializer_seen', False):
            self.unowned_serializer_seen = True
            if hasattr(callback, 'record'):
                callback.record(event='native_serializer_left_unmodified', player=self.number,
                    caller_rva=q(self.memory(q(context, 152), 8)) - self.base)
        if live and rva == TICK:
            if self.server != q(context, 128):
                raise ValueError('Adapter did not retain the captured native server')
            self.observed_game = self.server + live['game']['game_offset']
        if address - self.base == TICK or address - self.base in self.disable_hooks:
            self.patch(address, self.breakpoints[address])
            del self.breakpoints[address]
        elif q(context, 248) == address:
            emulate_entry_push(context, self.breakpoints[address], self.put)
        checked(set_context(self.threads[tid], context))

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        for log in self.logs:
            log.close()


def run(seconds, players, callback, *, player_numbers=None):
    if _candidate_adapter and not 5 <= seconds <= 360:
        raise ValueError('Candidate party acceptance must be bounded to 5–360 seconds')
    if OBSERVE_UPDATE and (type(callback) is not UpdateObservation or players != 1
                           or player_numbers is not None or not 5 <= seconds <= 300):
        raise ValueError('Update observation requires the bounded disposable observer')
    if TEST_UPDATE_CALLS and (type(callback) is not UpdateCallTest or players != 1
                             or player_numbers is not None or not 5 <= seconds <= 300):
        raise ValueError('Candidate calls require the bounded disposable call test')
    executable = EXECUTABLE
    if hashlib.sha256(executable.read_bytes()).hexdigest() != ACTIVE_HASH:
        raise RuntimeError('Unsupported lab executable; refusing to instrument')
    if BUILD == 'updated' and not (OBSERVE_UPDATE or TEST_UPDATE_CALLS) and ((getattr(callback, 'shared_world', False) and
            not getattr(callback, 'updated_world_probe', False)) or
            not set(getattr(callback, 'extra_hooks', ())).issubset({PAUSE, RESUME, START, AWARD_XP, CHOOSE, MOVE, HURT,
                UI_COMMAND, SPAWN, FIND_SPAWN, REMOVE_LOOT, APPLY_EFFECT, ENEMY_AOE, GROUND_AOE, ENEMY_TARGET, HUD_DELIVER, MAP_SELECT, BOSS_DEATH, MENU_LOGIN})):
        raise RuntimeError('Updated build gameplay hooks are not verified yet')
    if not (OBSERVE_UPDATE or TEST_UPDATE_CALLS or _candidate_adapter) and not _diagnostic_executable and (ROOT / 'AzerothSurvivors.exe').exists():
        if BUILD == 'updated':
            # Revalidate the launch proof; the legacy prefix scanner is a development audit.
            resolve_reviewed_profile(executable, allow_runtime_relocation=True)
        else:
            subprocess.run([sys.executable, str(ROOT / 'analysis/check_build_hooks.py'),
                            '--if-changed'], cwd=ROOT, check=True)
    clients = {}
    launched = []
    import loop_profile
    profiler = loop_profile.start(callback, wait, cont)
    wait_event, continue_event = (profiler.wait, profiler.cont) if profiler else (wait, cont)
    try:
        for number in (player_numbers if player_numbers is not None else range(1, players + 1)):
            client = Native(number, autostart=getattr(callback, 'autostart', True),
                            profile_folder=getattr(callback, 'profile_folders', {}).get(
                                number, getattr(callback, 'profile_folder', None)),
                            character_name=getattr(callback, 'character_names', {}).get(number, 'Hero'),
                            test_corner_slot=(number if _candidate_home and
                                os.environ.get('COOP_TEST_WINDOW_CORNERS') == '1' and
                                len(getattr(callback, 'members', ())) == 4 else None))
            client.extra_hooks = getattr(callback, 'extra_hooks', ())
            client.debug_seconds, client.debug_events, client.debug_longest = 0.0, 0, 0.0
            clients[client.process.pid] = client
            launched.append(client)
        deadline = time.monotonic() + seconds
        drain_started = None
        while clients:
            for client in clients.values():
                placement = getattr(client, 'window_placement', None)
                if placement is not None:
                    placed = placement.poll()
                    if placed is not None and hasattr(callback, 'record'):
                        callback.record(event='test_window_placed', **placed)
            poll = getattr(callback, 'poll_network', None)
            if poll is not None:
                poll()
            if getattr(callback, 'stop_requested', False):
                deadline = min(deadline, time.monotonic())
            if getattr(callback, 'restart_requested', False):
                break
            if time.monotonic() >= deadline:
                finish = getattr(callback, 'finish_ready', None)
                if drain_started is None:
                    drain_started = time.monotonic()
                    if hasattr(callback, 'record'):
                        callback.record(event='shutdown_drain_started', states=dict(getattr(callback, 'native_states', {})),
                                        counters=dict(getattr(callback, 'counts', {})))
                ready = finish is None or finish()
                if ready or time.monotonic() >= deadline + 5:
                    if hasattr(callback, 'record'):
                        callback.record(event='shutdown_drain_finished', ready=ready,
                                        elapsed=time.monotonic() - drain_started,
                                        states=dict(getattr(callback, 'native_states', {})),
                                        counters=dict(getattr(callback, 'counts', {})),
                                        pause_pending=dict(getattr(callback, 'pause_pending', {})),
                                        pending_damage=dict(getattr(callback, 'damage_pending', {})),
                                        pending_effects=len(getattr(callback, 'effects_pending', ())),
                                        quiesced_peers=sorted(getattr(callback, 'quiesced_peers', ())),
                                        pending_claim=getattr(callback, 'chest_claim', None),
                                        accepted_hits={2: len(getattr(callback, 'guest_hits', ())),
                                            **{n: len(hits) for n, hits in getattr(callback, 'hit_queues', {}).items()}})
                    if not ready:
                        raise TimeoutError('Co-op shutdown did not drain accepted work; see shutdown_drain_finished')
                    break
            if (ROOT / 'coop-lab/stop-bridge.txt').exists():
                (ROOT / 'coop-lab/stop-bridge.txt').unlink()
                return
            event = C.create_string_buffer(176)
            if not wait_event(event, 100):
                if C.get_last_error() == 121:
                    continue
                raise C.WinError(C.get_last_error())
            kind, pid, tid = struct.unpack_from('<III', event)
            client = clients[pid]
            event_started = time.perf_counter()
            status = 0x10002
            exited = None
            try:
                if kind == 3:
                    client.handle, thread, client.base = struct.unpack_from('<QQQ', event, 24)
                    client.threads[tid] = thread
                    if q(event, 16):
                        close(q(event, 16))
                    client.modules.add(client.base, image_size(client.memory, client.base) or IMAGE_SIZE,
                                       EXECUTABLE.name, 'game')
                elif kind == 2:
                    client.threads[tid] = q(event, 16)
                elif kind == 4:
                    handle = client.threads.pop(tid, None)
                    if handle:
                        close(handle)
                elif kind == 6:
                    # LOAD_DLL: hFile at +16, lpBaseOfDll at +24. Name and size are best effort.
                    file, dll_base = parse_load_dll(event)
                    try:
                        path = handle_path(file) if file else None
                        client.modules.add(dll_base, image_size(client.memory, dll_base), path, classify(path, WINDOWS_DIR))
                    except Exception:
                        pass
                    if file:
                        close(file)
                elif kind == 7:
                    client.modules.remove(parse_unload_dll(event))
                elif kind == 5:
                    code = struct.unpack_from('<I', event, 16)[0]
                    client.exited = True
                    clients.pop(pid)
                    # The process address space is gone. Remove it before any
                    # party callback or shutdown gate can inspect native memory.
                    callback_clients = getattr(callback, 'clients', None)
                    if isinstance(callback_clients, dict):
                        callback_clients.pop(client.number, None)
                    exited = code
                elif kind == 1:
                    code = struct.unpack_from('<I', event, 16)[0]
                    address = q(event, 32)
                    guard = getattr(client, 'dispatch_guard_traps', {}).get(address)
                    if code == 0xC000001D and guard is not None:
                        if hasattr(callback, 'record'):
                            callback.record(event='native_contract_failure', player=client.number,
                                            contract=guard, rva=address - client.base)
                        raise RuntimeError(f'Client {client.number}: native {guard} compatibility guard failed; '
                                           'the changed game used an unverified dispatch value')
                    if code == 0x80000003 and address == client.call_return and client.saved_context is not None:
                        restored = client.context(tid)
                        restored[:] = client.saved_context
                        checked(set_context(client.threads[tid], restored))
                        client.saved_context = None
                        client.call_is_request = False
                        after, client.after_call = client.after_call, None
                        if after is not None:
                            after()
                    elif code == 0x80000003 and address in client.breakpoints:
                        if profiler:
                            profiler.hook(client, address - client.base)
                        client.breakpoint(tid, address, callback)
                    elif code == 0x80000003 and not client.installed:
                        client.install()
                    else:
                        status = 0x80010001
                        if not struct.unpack_from('<I', event, 168)[0]:
                            info = parse_exception(event)[3]
                            stack, rsp = b'', 0
                            try:
                                crash = client.context(tid)
                                rsp = q(crash, 152)
                                stack = client.memory(rsp, STACK_BYTES)
                            except Exception:
                                pass  # A thread or stack that cannot be read still gets a crash report.
                            report = crash_event(client.modules, player=client.number, code=code, address=address,
                                                 first_chance=False, game_base=client.base, info=info,
                                                 stack=stack, rsp=rsp)
                            if hasattr(callback, 'record'):
                                callback.record(**report)
                            raise RuntimeError(f'Client {client.number}: {describe(code, address, client.base, report)}')
            finally:
                checked(continue_event(pid, tid, status))
                duration = time.perf_counter() - event_started
                client.debug_seconds += duration
                client.debug_events += 1
                client.debug_longest = max(client.debug_longest, duration)
                if duration >= .25 and hasattr(callback, 'record'):
                    callback.record(event='debug_handler_stall', player=client.number,
                                    kind=kind, seconds=round(duration, 3))
            if exited is not None:
                if hasattr(callback, 'record'):
                    callback.record(event='native_exit', player=client.number, code=exited)
                notify_exit = getattr(callback, 'native_exited', None)
                if notify_exit is not None:
                    notify_exit(client, exited)
                if exited != 0:
                    raise RuntimeError(f'Client {client.number} exited: {exited}')
    finally:
        loop_summary = {}
        if profiler:
            loop_profile.stop(profiler)
            try:
                loop_summary = profiler.summary()
            except Exception as error:  # Diagnostics must never mask the run's own outcome.
                loop_summary = dict(loop_profile_error=repr(error))
        for client in launched:
            if hasattr(callback, 'record'):
                callback.record(event='debug_overhead', player=client.number, events=client.debug_events,
                                handled_seconds=client.debug_seconds, longest_seconds=client.debug_longest,
                                **loop_summary)
            client.stop()
        # Drain exit notifications so debugged children really exit.
        until = time.monotonic() + 5
        while any(c.process.poll() is None for c in launched) and time.monotonic() < until:
            event = C.create_string_buffer(176)
            if wait(event, 100):
                _, pid, tid = struct.unpack_from('<III', event)
                cont(pid, tid, 0x10002)
        for client in launched:
            client.process.wait(timeout=2)


def emulate_entry_push(context, instruction, put):
    """Keep INT3 installed; emulate only the verified PUSH RBP/PUSH R15.

    No single-step window or manual thread suspension: overlapping queued
    breakpoint events cannot overwrite a pending resume list and deadlock.
    """
    register = {b'\x55': 160, b'\x41\x57': 240, b'\x41\x56': 232}.get(instruction)
    if register is None:
        raise ValueError('Unsupported breakpoint instruction')
    stack = q(context, 152) - 8
    put(stack, struct.pack('<Q', q(context, register)))
    struct.pack_into('<Q', context, 152, stack)
    struct.pack_into('<Q', context, 248, q(context, 248) + len(instruction))


class UpdateObservation:
    """Collect entry hits only; this cannot enable gameplay compatibility."""
    autostart = True
    extra_hooks = ()
    def __init__(self, output, folder):
        self.output, self.profile_folder = output, folder
        self.hits = {name: 0 for name in ('TICK', 'SERIALIZE', 'WRITE')}
        isolated = OBSERVE_UPDATE or TEST_UPDATE_CALLS
        self.hud = _profile.get('hud_contract') if isolated else None
        self.batch = _profile.get('batch_contract') if isolated else None
        self.connections = _profile.get('connection_contract') if isolated else None
        self.batch_hits = 0
        self.sites = {int(address, 16): row for address, row in _profile.get('observation_sites', {}).items()} if isolated else {}
        self.site_hits = set()
        self.game_contract = _profile.get('game_contract') if isolated else None
        self.game_frame = _profile.get('game_frame') if isolated else None
        if self.hud:
            self.hits['HUD_DELIVER'] = 0
            self.extra_hooks = (HUD_DELIVER,)
        self.extra_hooks += tuple(self.sites)

    def record(self, **event):
        self.output.write(json.dumps(event) + '\n')
        self.output.flush()

    def __call__(self, client, rva, context):
        registers = dict(zip(('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                              'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'), range(120, 248, 8)))
        if rva in self.sites:
            site = self.sites[rva]
            game = client.server + self.game_contract['game_offset']
            if site['kind'] == 'game_entry':
                if q(context, 128) != game:
                    raise ValueError('Observed Game entry does not belong to captured server')
                client.observed_game = game
                self.record(event='observation_game_owner', server_matches=True)
            else:
                owned = (getattr(client, 'observed_game', None) == game
                         and q(context, registers[site['base']]) == game)
                if not owned and site['kind'] != 'game_candidate_field':
                    raise ValueError('Observed native field does not belong to captured Game')
                if site['kind'] == 'game_field':
                    frame = q(context, registers[self.game_frame['stack_register']])
                    if q(client.memory(frame + self.game_frame['stack_offset'], 8)) != game:
                        raise ValueError('Observed native field does not belong to captured Game/frame')
                self.record(event='observation_game_field', old_rva=site['old_rva'], new_rva=site['new_rva'],
                            old_offset=site['old_offset'], new_offset=site['new_offset'], width=site['width'],
                            address_only=site['address_only'], owner_verified=owned, kind=site['kind'])
            self.site_hits.add(rva)
            # One-shot read only probe. Restore the complete original instruction
            # and execute it normally; no arbitrary instruction emulation.
            client.disable_hooks.add(rva)
            return
        name = next(name for name in self.hits if globals()[name] == rva)
        if q(context, 152) % 16 != (0 if name == 'HUD_DELIVER' else 8):
            raise ValueError(f'Observed {name} violates the entry stack contract')
        self.hits[name] += 1
        if self.hits[name] == 1:
            self.record(event='observation_entry', hook=name, rva=rva,
                        stack_aligned=True)
        if rva == TICK:
            # The only object fields inspected here are the discovered entry
            # contract's server flag/time; no game layout is assumed.
            flag, timestamp = struct.unpack('<I4xd', client.memory(q(context, 128), 16))
            if flag not in (0, 1) or not math.isfinite(timestamp):
                raise ValueError('Observed server header violates the discovered contract')
            self.record(event='observation_server_header', flag=flag,
                        time_finite=math.isfinite(timestamp))
            client.server = q(context, 128)
        elif name == 'WRITE' and self.batch:
            batch, vector = self.batch, self.connections
            if q(client.memory(q(context, 152), 8)) != client.base + int(batch['return_rva'], 16):
                return
            owner = q(context, registers[vector['server_register']])
            if owner != client.server:
                raise ValueError('Batch connection vector does not belong to captured server')
            capacity = q(client.memory(owner + vector['capacity_field'], 8))
            pointer = q(client.memory(owner + vector['pointer_field'], 8))
            count = q(client.memory(owner + vector['count_field'], 8))
            connection = q(context, registers[batch['connection_register']])
            if (not 0 < count <= capacity <= 16 or not pointer
                    or not pointer <= connection < pointer + count * vector['element_size']
                    or (connection - pointer) % vector['element_size']):
                raise ValueError('Batch connection is outside the discovered native vector')
            queue = q(client.memory(connection + batch['queue_field'], 8)) + batch['queue_offset']
            frame = q(context, registers[batch['packet_stack_register']])
            buffer = q(client.memory(frame + batch['packet_buffer_stack_offset'], 8))
            length = q(client.memory(frame + batch['packet_length_stack_offset'], 8))
            if queue != q(context, 128) or buffer != q(context, 136) or length != q(context, 184):
                raise ValueError('Batch argument roles disagree with discovered frame/connection fields')
            ui = batch['ui_vector']
            frame = q(context, registers[ui['stack_register']])
            capacity, count = (q(client.memory(frame + ui[key], 8)) for key in ('capacity', 'count'))
            if not 0 <= count <= capacity <= MAX_QUEUE:
                raise ValueError('Batch UI vector violates native allocation bounds')
            self.batch_hits += 1
            if self.batch_hits == 1:
                self.record(event='observation_batch_layout', server_matches=True, connection_matches=True,
                            packet_arguments_match=True, ui_bounds_valid=True)
        elif name == 'HUD_DELIVER':
            owner = q(context, registers[self.hud['server_register']])
            if owner != client.server:
                raise ValueError('HUD receiver does not belong to the observed server')
            if (q(context, 128) != q(client.memory(owner + self.hud['receiver_field'], 8))
                    or q(context, 120) != q(client.memory(owner + self.hud['vtable_field'], 8))):
                raise ValueError('HUD receiver/vtable field contract disagrees with runtime')
            if self.hits[name] == 1:
                self.record(event='observation_hud_owner', server_matches=True, fields_match=True)
            # Emulate precisely the intercepted native CALL [RAX+0x20]. This
            # continues its original callback; it does not inject a new call.
            target = q(client.memory(q(context, 120) + 0x20, 8))
            stack = q(context, 152) - 8
            client.put(stack, struct.pack('<Q', client.base + rva + 3))
            struct.pack_into('<Q', context, 152, stack)
            struct.pack_into('<Q', context, 248, target)


def candidate_enemy_state(client, game, contract, guid, *, require_alive=True):
    fields, enemy = contract['fields'], contract['enemy']
    pointer, count = (int.from_bytes(client.memory(game + fields[name]['offset'], fields[name]['width']), 'little')
                      for name in ('enemies_pointer', 'enemies_count'))
    if type(guid) is not int or not 0 < guid < 2**64 or not 0 <= count <= 10000 or count and not pointer:
        raise ValueError('Candidate damage target/vector is outside its bounds')
    matches = []
    for index in range(count):
        address = pointer + index * enemy['stride']
        row = client.memory(address, enemy['stride'])
        if q(row, enemy['guid']) == guid:
            hp, maximum = (struct.unpack_from('<f', row, enemy[name])[0] for name in ('hp', 'max_hp'))
            dead = int.from_bytes(row[enemy['dead']:enemy['dead'] + enemy['dead_width']], 'little')
            if not math.isfinite(hp) or not math.isfinite(maximum) or maximum <= 0 or hp > maximum:
                raise ValueError('Candidate damage target has invalid health')
            matches.append(dict(address=address, guid=guid, hp=hp, max_hp=maximum,
                                dead=dead == enemy['dead_value']))
    if len(matches) > 1 or require_alive and (not matches or matches[0]['dead'] or matches[0]['hp'] <= 0):
        raise ValueError('Candidate damage requires one existing live native Enemy')
    return matches[0] if matches else None


def emulate_effect_tag_guard(client, context, contract):
    """Preserve native MOV EAX,[R8], admitting only proved Effect12 variants."""
    expected = bytes.fromhex(contract['expected'])
    if (expected != bytes.fromhex('418b00') or contract.get('base') != 'r8'
            or contract.get('destination') != 'eax' or contract.get('offset') != 0
            or contract.get('width') != 4 or contract.get('maximum') != 10
            or contract.get('mandatory') is not True):
        raise ValueError('Effect dispatch guard instruction roles changed')
    borrowed = client.memory(q(context, CONTEXT_REGISTERS['r8']), 12)
    if len(borrowed) != 12:
        raise ValueError('Native effect argument is not a readable Effect12')
    tag = struct.unpack_from('<I', borrowed)[0]
    if tag > contract['maximum']:
        raise ValueError('Native effect dispatch used an unverified effect tag')
    struct.pack_into('<Q', context, CONTEXT_REGISTERS['rax'], tag)
    struct.pack_into('<Q', context, 248, client.base + contract['rva'] + len(expected))
    return tag


def emulate_damage_tag_guard(client, context, contract):
    """Emulate only the paired MOVZX load, enforcing the bound at dispatch."""
    import capstone
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    expected = bytes.fromhex(contract['expected'])
    instructions = list(decoder.disasm(expected, contract['rva']))
    if len(instructions) != 1 or instructions[0].size != len(expected):
        raise ValueError('Damage dispatch guard is not one complete instruction')
    ins = instructions[0]
    operands = ins.operands
    registers = dict(zip(('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                          'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'), range(120, 248, 8)))
    aliases = dict(zip(('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'), list(registers)[:8]))
    aliases.update({f'r{i}d': f'r{i}' for i in range(8, 16)})
    if (ins.mnemonic != 'movzx' or len(operands) != 2
            or operands[0].type != capstone.x86.X86_OP_REG or operands[0].size != 4
            or operands[1].type != capstone.x86.X86_OP_MEM or operands[1].size != 1
            or operands[1].mem.index or operands[1].mem.segment
            or ins.reg_name(operands[0].reg) != contract['destination']
            or ins.reg_name(operands[1].mem.base) != contract['base']
            or operands[1].mem.disp != contract['offset']
            or contract.get('mandatory') is not True or contract['maximum'] != 3):
        raise ValueError('Damage dispatch guard instruction roles changed')
    owner = q(context, registers[contract['base']])
    if owner != getattr(client, 'observed_game', None):
        raise ValueError('Damage dispatch does not belong to the captured Game')
    value = client.memory(owner + contract['offset'], 1)[0]
    if value > contract['maximum']:
        raise ValueError('Native damage dispatch used an unverified source tag')
    struct.pack_into('<Q', context, registers[aliases[contract['destination']]], value)
    struct.pack_into('<Q', context, 248, client.base + contract['rva'] + len(expected))
    return value


def candidate_boss_definition(client, game, contract):
    """Derive the one admitted boss argument from this Game's native map."""
    def value(name):
        row = contract['fields'][name]
        return int.from_bytes(client.memory(game + row['offset'], row['width']), 'little')
    length, pointer = value('map_length'), value('map_pointer')
    if not pointer or not 1 <= length <= 128:
        raise ValueError('Invalid native map identifier')
    name = client.memory(pointer, length).decode('utf-8')
    table, argument = contract['map_table'], contract['boss_argument']
    matches = [i for i, row in enumerate(table['rows']) if row['names'][0] == name]
    if len(matches) != 1 or len(table['rows']) != table['map_count']:
        raise ValueError('Native map has no unique proved boss table')
    address = client.base + table['candidate'] + matches[0] * argument['map_stride']
    pointer = q(client.memory(address + argument['array_pointer'], 8))
    count = q(client.memory(address + argument['array_count'], 8))
    if (count != argument['count'] or not client.base <= pointer
            or pointer + count * argument['stride'] > client.base + IMAGE_SIZE):
        raise ValueError('Native boss array violates its immutable bounds')
    pointer += argument['ordinal'] * argument['stride']
    definition = contract['boss_definition']
    name_pointer = q(client.memory(pointer + definition['name_pointer'], 8))
    name_length = q(client.memory(pointer + definition['name_length'], 8))
    if (not 1 <= name_length <= 512 or not client.base <= name_pointer
            or name_pointer + name_length > client.base + IMAGE_SIZE):
        raise ValueError('Native boss name is outside its immutable image')
    boss_name = client.memory(name_pointer, name_length).decode('utf-8')
    if boss_name != table['rows'][matches[0]]['bosses'][argument['ordinal']]['name']:
        raise ValueError('Native boss definition does not match the proved map')
    return dict(pointer=pointer, name=boss_name, map=name,
                entry=int.from_bytes(client.memory(pointer + definition['entry_id'], 4), 'little'),
                display=int.from_bytes(client.memory(pointer + definition['display_id'], 4), 'little'))


class UpdateCallTest(UpdateObservation):
    """Statically admitted pause/progression calls in one disposable native Game."""
    def __init__(self, output, folder):
        super().__init__(output, folder)
        self.entries = _profile['candidate_call_contract']['entries']
        self.returned, self.messages = set(), set()
        self.pending = None
        self.calls_complete = self.clean_exit = False
        self.progression = _profile.get('progression_call_contract')
        self.progression_award = None
        self.progression_choices = []
        self.progression_state_passed = self.progression_complete = False
        self.offered_ui = None
        self.consumed_ui = None
        self.progression_resume_seen = False
        self.boss_contract = _profile.get('boss_call_contract')
        self.boss_spawn = None
        self.boss_model_seen = self.boss_hud_seen = self.boss_complete = False
        self.boss_hud_health_seen = False
        self.damage_contract = _profile.get('damage_call_contract')
        self.damage_results = []
        self.damage_complete = False
        self.damage_kill_ui = False
        self.damage_guard_hits = 0
        self.damage_preparation_awards = 0
        if self.damage_contract:
            guard = self.damage_contract['guard_instruction']
            self.sites.pop(guard['rva'], None)
            self.extra_hooks = tuple(dict.fromkeys((*self.extra_hooks, guard['rva'])))

    def __call__(self, client, rva, context):
        if self.damage_contract and rva == self.damage_contract['guard_instruction']['rva']:
            tag = emulate_damage_tag_guard(client, context, self.damage_contract['guard_instruction'])
            self.damage_guard_hits += 1
            if self.damage_guard_hits == 1:
                self.record(event='candidate_damage_guard', tag=tag, owner_verified=True)
            return
        super().__call__(client, rva, context)
        if self.boss_contract:
            self.observe_boss(client, rva, context)
        if (rva != WRITE or not self.batch_hits
                or q(client.memory(q(context, 152), 8)) != client.base + int(self.batch['return_rva'], 16)):
            return
        # The periodic HUD and native menu notifications have different sinks.
        # Read the exact String vector already validated by the batch contract.
        ui = self.batch['ui_vector']
        if ui['stack_register'] != 'rbp' or ui['element_size'] != 24:
            raise ValueError('Unsupported candidate UI vector ABI')
        frame = q(context, 160)
        pointer = q(client.memory(frame + ui['pointer'], 8))
        count = q(client.memory(frame + ui['count'], 8))
        if not 0 <= count <= 4096 or count and not pointer:
            raise ValueError('Invalid candidate UI vector')
        for index in range(count):
            capacity, address, length = struct.unpack('<QQQ', client.memory(pointer + index * 24, 24))
            if not 0 <= length <= capacity <= 1048576 or length and not address:
                raise ValueError('Invalid candidate UI String')
            if length > (65536 if self.progression else 256):
                continue
            try:
                message = json.loads(client.memory(address, length))
            except (ValueError, UnicodeError):
                message = None
            if (self.damage_contract and isinstance(message, dict)
                    and message.get('type') == self.damage_contract['kill_ui']['type']):
                self.damage_kill_ui = True
                self.record(event='candidate_damage_kill_output', output=message)
            if (self.boss_spawn and self.boss_spawn.get('returned') and isinstance(message, dict)
                    and message.get('type') == self.boss_contract['boss_ui']['type']
                    and message.get(self.boss_contract['boss_ui']['name']) == self.boss_spawn['name']):
                self.boss_hud_seen = True
                self.record(event='candidate_boss_announcement', output=message)
            for name, entry in self.entries.items():
                if 'output_json' in entry and message == entry['output_json'] and name in self.returned:
                    self.messages.add(name)
                    self.record(event='candidate_call_output', call=name, output=message)
            if self.progression and message is not None:
                self.record(event='candidate_progression_output', output=message)
                ability = self.progression['ability_contract']
                if isinstance(message, dict) and message.get('type') == ability['offered_ui']['type']:
                    offered = message.get(ability['offered_ui']['array'])
                    if offered != self.consumed_ui:
                        self.offered_ui = offered
                if self.progression_choices and message == ability['consumption_ui']:
                    self.progression_resume_seen = True
            if self.returned == self.messages == {'PAUSE', 'RESUME'} and not self.calls_complete:
                self.calls_complete = True
                self.record(event='candidate_calls_complete', automatic_activation_allowed=False)
        if self.pending is not None:
            return
        game = client.server + self.game_contract['game_offset']
        if getattr(client, 'observed_game', None) != game:
            return
        if self.calls_complete:
            if self.progression:
                self.check_progression(client, context, game)
            if self.boss_contract and self.progression_complete and self.pending is None:
                if not self.damage_contract or self.prepare_damage_guard(client, context, game):
                    self.check_boss(client, context, game)
            if self.damage_contract and self.boss_complete and self.pending is None:
                self.check_damage(client, context, game)
            return
        name = 'PAUSE' if not self.returned else 'RESUME'
        if name in self.returned or name == 'RESUME' and 'PAUSE' not in self.messages:
            return
        entry = self.entries[name]
        phase = client.memory(game + entry['game_phase_offset'], 1)[0]
        if phase != entry['initial_phase']:
            return
        self.pending = name
        def returned():
            actual = client.memory(game + entry['game_phase_offset'], 1)[0]
            if actual != entry['final_phase']:
                raise ValueError(f'{name} candidate returned with unexpected phase {actual}')
            self.pending = None
            self.returned.add(name)
            self.record(event='candidate_call_return', call=name, phase=actual)
        client.call_before(context, entry['entry'], game, after=returned)
        self.record(event='candidate_call_started', call=name, phase=phase)

    def boss_enemies(self, client, game):
        fields = self.boss_contract['fields']
        pointer, count = (int.from_bytes(client.memory(game + fields[name]['offset'], fields[name]['width']), 'little')
                          for name in ('enemies_pointer', 'enemies_count'))
        if not 0 <= count <= 10000 or count and not pointer:
            raise ValueError('Candidate boss Enemy vector is outside its bounds')
        return pointer, count

    def prepare_damage_guard(self, client, context, game):
        """Acquire an offered native trigger ability before the test boss dies."""
        state = self.progression_state(client, game)
        names = {row['title'] for row in self.damage_contract['guard_trigger']['abilities']}
        if names.intersection(self.progression_abilities(client, state)):
            return True
        if state['phase'] != 1 or state['pending_talents']:
            return False
        if self.damage_preparation_awards >= 16:
            raise ValueError('Native offers did not supply a damage-guard trigger within16 XP awards')
        self.damage_preparation_awards += 1
        self.pending = 'AWARD_XP'
        def awarded():
            after = self.progression_state(client, game)
            if (after['level'], after['xp']) == (state['level'], state['xp']):
                raise ValueError('Guard preparation XP returned without native progression')
            self.pending = None
            self.record(event='candidate_guard_preparation_xp', amount=100, before=state, after=after)
        client.call_before(context, self.entries['AWARD_XP']['entry'], game, 100, after=awarded)
        return False

    def check_damage(self, client, context, game):
        if self.damage_complete:
            return
        if len(self.damage_results) == 2:
            if self.damage_guard_hits and all(row['world_output'] for row in self.damage_results) and self.damage_kill_ui:
                self.damage_complete = True
                self.record(event='candidate_damage_complete', guard_hits=self.damage_guard_hits,
                            automatic_activation_allowed=False)
            return
        if self.damage_results and not self.damage_results[-1]['world_output']:
            return
        entry = self.entries['DAMAGE']
        if client.memory(game + entry['game_phase_offset'], 1)[0] != entry['initial_phase']:
            return
        guid = self.boss_spawn['guid']
        before = candidate_enemy_state(client, game, self.damage_contract, guid)
        lethal = bool(self.damage_results)
        amount = 100000 if lethal else min(100, max(1, before['hp'] / 10))
        def progression():
            return {name: int.from_bytes(client.memory(game + row['offset'], row['width']), 'little')
                    for name, row in self.damage_contract['fields'].items()
                    if name in ('xp', 'boss_kills', 'rewards_count')}
        progress_before = progression()
        luck = self.damage_contract['fields']['luck']
        luck_before = client.memory(game + luck['offset'], luck['width']).hex()
        self.pending = 'DAMAGE'
        def damaged():
            after = candidate_enemy_state(client, game, self.damage_contract, guid, require_alive=False)
            dead = after is None or after['dead'] or after['hp'] <= 0
            if lethal and not dead or not lethal and (dead or after['hp'] >= before['hp']):
                raise ValueError('Native boss damage did not produce the required health/death transition')
            result = dict(lethal=lethal, amount=amount, before=before, after=after,
                          progress_before=progress_before, progress_after=progression(),
                          luck_before=luck_before, luck_after=client.memory(game + luck['offset'], luck['width']).hex(),
                          world_output=False)
            self.damage_results.append(result)
            self.pending = None
            self.record(event='candidate_damage_return', **result)
        client.call_before(context, entry['entry'], game, guid, damage=amount, after=damaged)

    def check_boss(self, client, context, game):
        if self.boss_spawn is not None:
            return
        entry = self.entries['SPAWN_BOSS']
        if client.memory(game + entry['game_phase_offset'], 1)[0] != entry['initial_phase']:
            return
        boss = candidate_boss_definition(client, game, self.boss_contract)
        _, count = self.boss_enemies(client, game)
        self.boss_spawn = boss
        self.pending = 'SPAWN_BOSS'
        def spawned():
            pointer, after_count = self.boss_enemies(client, game)
            if after_count != count + 1:
                raise ValueError('Native boss spawn did not add exactly one Enemy')
            enemy = self.boss_contract['enemy']
            row = client.memory(pointer + count * enemy['stride'], enemy['stride'])
            if q(row, enemy['definition_pointer']) != boss['pointer']:
                raise ValueError('Spawned Enemy has the wrong boss definition')
            guid = q(row, enemy['guid'])
            definition = self.boss_contract['boss_definition']
            if (guid >> definition['guid_entry_shift']) & definition['guid_entry_mask'] != boss['entry']:
                raise ValueError('Spawned boss GUID disagrees with its native entry')
            hp, maximum = (struct.unpack_from('<f', row, enemy[key])[0] for key in ('hp', 'max_hp'))
            positions = [struct.unpack_from('<fff', row, enemy[key]) for key in ('start_position', 'end_position')]
            if not (math.isfinite(hp) and math.isfinite(maximum) and 0 < hp <= maximum
                    and all(math.isfinite(v) for xyz in positions for v in xyz)):
                raise ValueError('Spawned boss has invalid native health or position')
            boss.update(guid=guid, hp=hp, max_hp=maximum, positions=positions, returned=True)
            self.pending = None
            self.record(event='candidate_boss_return', **boss)
        client.call_before(context, entry['entry'], game, boss['pointer'], after=spawned)

    def observe_boss(self, client, rva, context):
        if not self.boss_spawn or not self.boss_spawn.get('returned'):
            return
        boss = self.boss_spawn
        if rva == SERIALIZE:
            from world_packets import UPDATE, DESTROY, objects
            packet = client.memory(q(context, 136), 32)
            size, opcode = q(packet, 16), struct.unpack_from('<H', packet, 24)[0]
            if opcode == UPDATE:
                if not 0 < size <= 1048576:
                    raise ValueError('Candidate boss packet exceeds bounds')
                for block in objects(client.memory(q(packet, 8), size), remap=False):
                    if block.guid == boss['guid'] and self.damage_results:
                        result = self.damage_results[-1]
                        hp = block.fields.get(self.boss_contract['world_fields']['hp'])
                        expected = 0 if result['lethal'] else int(result['after']['hp'])
                        if type(hp) is int and 0 <= hp <= expected:
                            result['world_output'] = True
                            self.record(event='candidate_damage_world_health', lethal=result['lethal'], hp=hp, guid=block.guid)
                    if block.guid == boss['guid'] and block.kind in (2, 3):
                        # Record the exact native fields; model identity must be
                        # checked against the statically proved packet contract.
                        wire = self.boss_contract['world_fields']
                        if (block.fields.get(wire['display_id']) != boss['display']
                                or block.fields.get(wire['max_hp'], 0) <= 0
                                or block.fields.get(wire['hp']) != int(boss['hp'])
                                or block.fields.get(wire['max_hp']) != int(boss['max_hp'])):
                            raise ValueError('Boss CREATE does not match native model/health')
                        self.boss_model_seen = True
                        self.record(event='candidate_boss_model', guid=block.guid, fields=block.fields)
            elif opcode == DESTROY and self.damage_results and self.damage_results[-1]['lethal']:
                if size == 8 and q(client.memory(q(packet, 8), size)) == boss['guid']:
                    self.damage_results[-1]['world_output'] = True
                    self.record(event='candidate_damage_world_destroy', guid=boss['guid'])
        elif rva == HUD_DELIVER:
            length = q(context, 184)
            if not 0 < length <= 1048576:
                raise ValueError('Candidate boss HUD exceeds bounds')
            payload = json.loads(client.memory(q(context, 136), length))
            hud = payload.get('boss')
            if hud:
                self.record(event='candidate_boss_hud', boss=hud)
                schema = self.boss_contract['hud_fields']
                # Injected DAMAGE runs at WRITE after this frame's HUD may
                # already be serialized. Check native HUD ownership/HP before
                # those calls; subsequent damage is correlated with world HP.
                if hud.get(schema['name']) == boss['name'] and not self.damage_results:
                    pointer, count = self.boss_enemies(client, client.server + self.game_contract['game_offset'])
                    enemy = self.boss_contract['enemy']
                    matches = [row for index in range(count)
                               if q(row := client.memory(pointer + index * enemy['stride'], enemy['stride']), enemy['guid']) == boss['guid']]
                    if len(matches) != 1:
                        raise ValueError('Boss HUD refers to a missing or ambiguous native Enemy')
                    for key in ('hp', 'max_hp'):
                        value = hud.get(schema[key])
                        if (not isinstance(value, (int, float)) or not math.isfinite(value)
                                or struct.pack('<f', value) != matches[0][enemy[key]:enemy[key]+4]):
                            raise ValueError('Boss HUD health disagrees with the native Enemy')
                    self.boss_hud_health_seen = True
        if self.boss_model_seen and self.boss_hud_seen and self.boss_hud_health_seen and not self.boss_complete:
            self.boss_complete = True
            self.record(event='candidate_boss_complete', automatic_activation_allowed=False)

    def progression_state(self, client, game):
        return {name: int.from_bytes(client.memory(game + row['offset'], row['width']), 'little')
                for name, row in self.progression['fields'].items()}

    def check_progression(self, client, context, game):
        state = self.progression_state(client, game)
        if state['phase'] == 1 and self.progression_award is None:
            self.pending = 'AWARD_XP'
            self.progression_award = dict(before=state)
            def awarded():
                after = self.progression_state(client, game)
                if (after['level'], after['xp']) == (state['level'], state['xp']):
                    raise ValueError('Candidate XP call returned without changing progression')
                self.progression_award['after'] = after
                self.pending = None
                self.record(event='candidate_xp_return', amount=20, before=state, after=after)
            client.call_before(context, self.entries['AWARD_XP']['entry'], game, 20, after=awarded)
        elif state['phase'] == 2:
            count, pointer = state['choices_count'], state['choices_pointer']
            if not 1 <= count <= 32 or not pointer or state['choice_kind'] == 255:
                raise ValueError('Candidate native talent offer is invalid')
            if len(self.progression_choices) >= (32 if self.damage_contract else 16):
                raise ValueError('Candidate progression exceeded bounded talent calls')
            if self.offered_ui is None:
                return
            if not isinstance(self.offered_ui, list) or len(self.offered_ui) != count:
                raise ValueError('Native choice UI disagrees with the native offer count')
            schema = self.progression['ability_contract']['offered_ui']
            abilities_before = self.progression_abilities(client, state)
            options = [(index, row, row['title'][len(schema['title_prefix']):],
                        self.progression['ability_contract']['new_rank']) for index, row in enumerate(self.offered_ui)
                       if isinstance(row, dict) and row.get('kind') == schema['kind']
                       and isinstance(row.get('title'), str) and row['title'].startswith(schema['title_prefix'])]
            upgrade = self.progression['ability_contract'].get('upgrade_ui')
            if upgrade:
                upgrades = [(index, row, name, rank + upgrade['rank_delta'])
                    for index, row in enumerate(self.offered_ui) for name, rank in abilities_before.items()
                    if isinstance(row, dict) and row.get('kind') == upgrade['kind']
                    and type(row.get('rank')) is int and row['rank'] == rank + upgrade['rank_delta']
                    and row.get('title') == upgrade['title_format'].format(name=name, rank=row['rank'])]
                options = upgrades + options if self.progression_choices else options + upgrades
            if not options:
                return  # No guessed layout for unproved stat-only choices.
            if self.damage_contract:
                targets = {row['title'] for row in self.damage_contract['guard_trigger']['abilities']}
                # Keep native ability slots available until the guarded branch
                # has a real producer; every selection still uses the offer UI.
                options.sort(key=lambda option: (option[2] not in targets, option[2] not in abilities_before))
            selected, offer, label, expected_rank = options[0]
            offered = client.memory(pointer + selected * self.progression['choice_stride'], self.progression['choice_stride'])
            title = self.progression['choice_title']
            capacity, address, length = (q(offered, title[name]) for name in ('capacity', 'pointer', 'length'))
            if not 0 < length <= capacity <= title['max_bytes'] or not address:
                raise ValueError('Invalid native talent title String')
            if client.memory(address, length).decode('utf-8') != offer['title']:
                return  # Native UI still contains an earlier offer; wait for its replacement.
            if offer['kind'] == schema['kind'] and label in abilities_before:
                raise ValueError('Native new-ability offer names an already known ability')
            if upgrade and offer['kind'] == upgrade['kind']:
                delta = upgrade['rank_delta_source']
                tags, count, target = (q(offered, delta[name]) for name in
                    ('choice_pointer_offset', 'choice_count_offset', 'ability_index_offset'))
                capacity = q(offered, delta['choice_capacity_offset'])
                if (delta['element_size'] != 1 or not tags or not 1 <= count <= 32
                        or not count <= capacity < 2**63 or not 0 <= target < len(abilities_before)):
                    raise ValueError('Invalid native upgrade stat vector or ability index')
                if list(abilities_before)[target] != label:
                    raise ValueError('Native upgrade target disagrees with its offer title')
                if any(tag not in delta['allowed_tags'] for tag in client.memory(tags, count)):
                    raise ValueError('Native upgrade contains an unverified stat tag')
                expected_rank = abilities_before[label] + count
            self.consumed_ui, self.offered_ui = self.offered_ui, None
            self.pending = 'CHOOSE'
            def chosen():
                after = self.progression_state(client, game)
                pending_field = self.progression['pending_by_choice_kind'][state['choice_kind']]
                if state[pending_field] < 1 or after[pending_field] != state[pending_field] - 1:
                    raise ValueError('Candidate choice did not spend its native pending counter')
                abilities_after = self.progression_abilities(client, after)
                expected = dict(abilities_before, **{label: expected_rank})
                if abilities_after != expected:
                    self.record(event='candidate_choice_mismatch', selected=selected,
                                offer=offer, offered=offered.hex(), before=state, after=after,
                                abilities_before=abilities_before, expected=expected,
                                abilities_after=abilities_after)
                    raise ValueError('Chosen native ability does not match the offered name/rank')
                replacement = (client.memory(after['choices_pointer'], self.progression['choice_stride'])
                    if after['phase'] == 2 and after['choices_count'] and after['choices_pointer'] else None)
                if after == state and replacement == offered:
                    raise ValueError('Candidate choice returned without consuming or replacing its offer')
                row = dict(before=state, after=after, selected=selected, offered=offered.hex(),
                           ability=label, abilities_before=abilities_before, abilities_after=abilities_after,
                           choice_kind=offer['kind'], expected_rank=expected_rank,
                           output_verified=True)
                self.progression_choices.append(row)
                self.pending = None
                self.record(event='candidate_choice_return', **row)
            client.call_before(context, self.entries['CHOOSE']['entry'], game, selected, after=chosen)
        elif (state['phase'] == 1 and self.progression_award and self.progression_choices
                and state['level'] > self.progression_award['before']['level']
                and not self.progression_state_passed):
            self.progression_state_passed = True
            self.record(event='candidate_progression_state_passed', state=state,
                        choice_output_verified=True, automatic_activation_allowed=False)
        if self.progression_state_passed and self.progression_resume_seen and not self.progression_complete:
            self.progression_complete = True
            self.record(event='candidate_progression_complete', automatic_activation_allowed=False)

    def progression_abilities(self, client, state):
        contract = self.progression['ability_contract']
        pointer, count, capacity = (state['abilities_' + name] for name in ('pointer', 'count', 'capacity'))
        if not 0 <= count <= capacity <= 256 or count and not pointer:
            raise ValueError('Invalid native ability vector')
        definitions = client.base + contract['definitions_rva']
        result = {}
        for index in range(count):
            row = client.memory(pointer + index * contract['stride'], contract['stride'])
            definition = q(row, contract['definition_pointer'])
            relative = definition - definitions
            if not 0 <= relative < contract['definitions_count'] * contract['definition_stride'] or relative % contract['definition_stride']:
                raise ValueError('Native ability points outside the proved definition table')
            name_pointer = q(client.memory(definition + contract['name_pointer'], 8))
            length = q(client.memory(definition + contract['name_length'], 8))
            if not name_pointer or not 1 <= length <= 512:
                raise ValueError('Invalid native ability label')
            name = client.memory(name_pointer, length).decode('utf-8')
            rank = int.from_bytes(row[contract['rank_offset']:contract['rank_offset'] + contract['rank_width']], 'little')
            if not 1 <= rank <= 100 or name in result:
                raise ValueError('Invalid or duplicate native ability rank')
            result[name] = rank
        return result

    def native_exited(self, client, code):
        self.clean_exit = code == 0
        self.record(event='candidate_native_exit', code=code, calls_complete=self.calls_complete)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=20, choices=range(5, 301 if OBSERVE_UPDATE or TEST_UPDATE_CALLS else 121))
    parser.add_argument('--observe-update', action='store_true', help='Discover and observe entry hooks in a disposable process; never activate co-op')
    parser.add_argument('--test-update-calls', action='store_true', help='Test admitted native calls in one disposable process; never activate co-op')
    parser.add_argument('--test-update-progression', action='store_true', help='Also test admitted XP and native talent spending; never activate co-op')
    parser.add_argument('--test-update-boss', action='store_true', help='Also test a derived native boss spawn, model and HUD; never activate co-op')
    parser.add_argument('--test-update-damage', action='store_true', help='Also verify bounded native boss damage/death with a persistent dispatch guard')
    parser.add_argument('--bounded-cleanup', action='store_true', help='Permit timed cleanup for call-only verification; does not verify normal quit')
    parser.add_argument('--observation-report', type=Path, help='Isolated entry-test evidence destination')
    args = parser.parse_args()
    if args.bounded_cleanup and not TEST_UPDATE_CALLS:
        parser.error('--bounded-cleanup is only valid for isolated candidate calls')
    if TEST_UPDATE_CALLS:
        from build_hooks import probe_identity
        identity = probe_identity(EXECUTABLE)
        with tempfile.TemporaryDirectory(prefix='coop-update-calls-') as folder:
            with (args.observation_report or ROOT / 'analysis/update-call-test.jsonl').open('w', encoding='utf-8') as output:
                callback = UpdateCallTest(output, folder)
                callback.record(event='candidate_call_test_start', sha256=ACTIVE_HASH, identity=identity,
                                automatic_activation_allowed=False)
                callback.record(event='observation_start', sha256=ACTIVE_HASH, automatic_activation_allowed=False)
                run(args.seconds, 1, callback)
                callback.record(event='candidate_call_test_summary', returned=sorted(callback.returned),
                                messages=sorted(callback.messages), clean_exit=callback.clean_exit,
                                progression_complete=callback.progression_complete,
                                progression_state_passed=callback.progression_state_passed,
                                boss_complete=callback.boss_complete,
                                damage_complete=callback.damage_complete,
                                identity_unchanged=identity == probe_identity(EXECUTABLE),
                                automatic_activation_allowed=False)
                callback.record(event='observation_summary', hits=callback.hits, batch_hits=callback.batch_hits,
                                observed_sites=len(callback.site_hits),
                                unobserved_sites=[hex(rva) for rva in callback.sites if rva not in callback.site_hits],
                                automatic_activation_allowed=False)
        if identity != probe_identity(EXECUTABLE):
            raise RuntimeError('Executable or adapter changed during candidate call test; rerun with stable files')
        if not callback.calls_complete or not args.bounded_cleanup and not callback.clean_exit:
            raise RuntimeError('Candidate call test incomplete: both transitions, outputs and clean native exit are required')
        if TEST_UPDATE_PROGRESSION and not callback.progression_complete:
            raise RuntimeError('Candidate progression incomplete: XP, level increase and matching native talent consumption required')
        if TEST_UPDATE_BOSS and not callback.boss_complete:
            raise RuntimeError('Candidate boss incomplete: native spawn, matching model/health and boss HUD required')
        if TEST_UPDATE_DAMAGE and not callback.damage_complete:
            raise RuntimeError('Candidate damage incomplete: guarded native HP/death transitions and world/UI outputs required')
        print(json.dumps(dict(candidate_calls='passed', clean_exit=callback.clean_exit, gameplay_verified=False)))
        return
    if args.observe_update:
        with tempfile.TemporaryDirectory(prefix='coop-update-observation-') as folder:
            with (args.observation_report or ROOT / 'analysis/update-observation.jsonl').open('w', encoding='utf-8') as output:
                observer = UpdateObservation(output, folder)
                observer.record(event='observation_start', sha256=ACTIVE_HASH, automatic_activation_allowed=False)
                run(args.seconds, 1, observer)
                observer.record(event='observation_summary', hits=observer.hits, batch_hits=observer.batch_hits,
                                observed_sites=len(observer.site_hits), unobserved_sites=[hex(rva) for rva in observer.sites if rva not in observer.site_hits],
                                automatic_activation_allowed=False)
        if not all(observer.hits.values()) or observer.batch and not observer.batch_hits:
            raise RuntimeError(f'Entry observation incomplete: {observer.hits}')
        print(json.dumps(dict(observation='passed', hits=observer.hits, gameplay_verified=False)))
        return
    destination = ROOT / 'analysis/native-world-packets.jsonl'
    with destination.open('w', encoding='utf-8') as output:
        def capture(client, rva, context):
            if rva == TICK:
                client.server = q(context, 128)
                print(f'Client {client.number}: internal server located', flush=True)
            elif rva == SERIALIZE:
                client.connection = q(context, 128)
                packet = client.memory(q(context, 136), 32)
                size, opcode = q(packet, 16), struct.unpack_from('<H', packet, 24)[0]
                # Exclude authentication and account data from persisted captures.
                if opcode in (0xA9, 0x1F6, 0xEE, 0x236, 0x96):
                    body = client.memory(q(packet, 8), size)
                    output.write(json.dumps(dict(player=client.number, opcode=opcode, body=body.hex())) + '\n')
                    output.flush()
                    client.captured += 1
        run(args.seconds, 1, capture)
    print(f'World packet capture: {destination}')


if __name__ == '__main__':
    main()
