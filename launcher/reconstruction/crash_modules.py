"""Crash report schema 2 (analysis/CRASH-REPORT-FORMAT.md): name the module of a native fault.

The debugger keeps one ModuleTable per game process, fed by CREATE_PROCESS / LOAD_DLL / UNLOAD_DLL debug
events and by the co-op code buffers it allocates. crash_event() turns a second-chance exception into the
schema-2 `native_crash` event. Every lookup is best effort: a failure here never stops the crash report,
it only leaves a field empty. Only file names leave the process (never directories, user names or tokens).
"""
import bisect
import json
import re
import struct

SCHEMA = 2
MAX_MODULES = 4096          # A game process loads ~150; bound the table against a runaway loader.
MAX_FRAMES = 32
MAX_OTHER = 32
MAX_LINE = 4096
STACK_BYTES = 2048
WHERE = ('game', 'coop', 'system', 'other', 'unknown')
ACCESS = {0: 'read', 1: 'write', 8: 'execute'}
ACCESS_CODES = (0xC0000005, 0xC0000006)
_USER_PATH = re.compile(r'(?i)([A-Z]:[\\/]+Users[\\/]+|/home/|/Users/)[^\\/\r\n"]+')
_SAFE_NAME = re.compile(r'[^A-Za-z0-9._+\-~ ()\[\]]')


def file_name(path):
    """The last path component, printable and at most 64 characters; never a directory."""
    if not isinstance(path, str) or not path:
        return None
    name = re.split(r'[\\/]', path.rstrip('\\/'))[-1]
    if name.startswith('\\\\?\\'):
        name = name[4:]
    name = _SAFE_NAME.sub('_', name)[:64]
    return name or None


def classify(path, windows_dir):
    """'system' for files under the Windows directory, else 'other' (antivirus, overlay, drivers elsewhere)."""
    if not isinstance(path, str) or not path:
        return 'unknown'
    norm = path.replace('/', '\\').lower()
    for prefix in ('\\\\?\\', '\\??\\'):
        if norm.startswith(prefix):
            norm = norm[len(prefix):]
    root = (windows_dir or '').replace('/', '\\').lower().rstrip('\\')
    return 'system' if root and (norm == root or norm.startswith(root + '\\')) else 'other'


def image_size(read, base):
    """SizeOfImage from the PE headers in process memory (same offset for PE32 and PE32+), or None."""
    try:
        dos = read(base, 0x40)
        if dos[:2] != b'MZ':
            return None
        nt = struct.unpack_from('<I', dos, 0x3C)[0]
        if not 0 < nt < 0x1000:
            return None
        header = read(base + nt, 0x58)
        if header[:4] != b'PE\0\0' or struct.unpack_from('<H', header, 24)[0] not in (0x10B, 0x20B):
            return None
        size = struct.unpack_from('<I', header, 0x50)[0]
        return size if 0 < size <= 0x40000000 else None
    except Exception:
        return None


def parse_load_dll(event):
    """LOAD_DLL_DEBUG_EVENT (x64 DEBUG_EVENT, union at +16): (hFile, lpBaseOfDll)."""
    return struct.unpack_from('<QQ', event, 16)


def parse_unload_dll(event):
    """UNLOAD_DLL_DEBUG_EVENT: lpBaseOfDll at +16."""
    return struct.unpack_from('<Q', event, 16)[0]


def parse_exception(event):
    """EXCEPTION_DEBUG_EVENT: (code, address, first_chance, ExceptionInformation[:2]).

    EXCEPTION_RECORD64 at +16: ExceptionCode +16, ExceptionAddress +32, NumberParameters +40,
    ExceptionInformation[15] from +48; dwFirstChance at +168.
    """
    code = struct.unpack_from('<I', event, 16)[0]
    address = struct.unpack_from('<Q', event, 32)[0]
    count = min(struct.unpack_from('<I', event, 40)[0], 2)
    info = [struct.unpack_from('<Q', event, 48 + 8 * i)[0] for i in range(count)]
    return code, address, struct.unpack_from('<I', event, 168)[0] != 0, info


class ModuleTable:
    """Loaded modules and co-op code buffers of one process, looked up by address in O(log n)."""
    def __init__(self):
        self.bases, self.entries = [], {}   # sorted bases; base -> (end, name, where)
        self.dropped = 0

    def add(self, base, size, name, where):
        if not isinstance(base, int) or base <= 0:
            return
        if base not in self.entries:
            if len(self.entries) >= MAX_MODULES:
                self.dropped += 1
                return
            bisect.insort(self.bases, base)
        size = size if isinstance(size, int) and size > 0 else 0x1000
        self.entries[base] = (base + size, file_name(name) if where != 'coop' else name, where if where in WHERE else 'unknown')

    def remove(self, base):
        if base in self.entries:
            del self.entries[base]
            self.bases.pop(bisect.bisect_left(self.bases, base))

    def find(self, address):
        """(name, offset, where) of the module or buffer containing address, or None."""
        if not isinstance(address, int):
            return None
        i = bisect.bisect_right(self.bases, address) - 1
        if i < 0:
            return None
        base = self.bases[i]
        end, name, where = self.entries[base]
        return (name, address - base, where) if address < end else None

    def others(self):
        return sorted({name for _, name, where in self.entries.values() if where == 'other' and name})[:MAX_OTHER]


def _place(table, address):
    try:
        hit = table.find(address)
    except Exception:
        hit = None
    if hit is None:
        return dict(module=None, offset=hex(address), where='unknown')
    name, offset, where = hit
    return dict(module=None if where == 'coop' else name, offset=hex(offset), where=where)


def scrub(text):
    return _USER_PATH.sub(r'\1[redacted]', text)


def crash_event(table, *, player, code, address, first_chance, game_base, info=(), stack=b'', rsp=0):
    """The schema-2 native_crash event (dict). Schema-1 fields are computed first and always present."""
    event = dict(event='native_crash', player=player, rva=address - game_base,
                 stack_code_offsets=[(i, struct.unpack_from('<Q', stack, i)[0] - game_base)
                                     for i in range(0, len(stack) - 7, 8)
                                     if game_base <= struct.unpack_from('<Q', stack, i)[0] < game_base + 0x8000000])
    try:
        event.update(schema=SCHEMA, code=f'{code & 0xFFFFFFFF:08x}', first_chance=bool(first_chance),
                     fault=_place(table, address))
        if code in ACCESS_CODES and len(info) >= 2:
            target = info[1]
            hit = _place(table, target)
            event['access'] = dict(type=ACCESS.get(info[0], f'unknown {info[0]}'), address=hex(target),
                                   module=hit['module'] if hit['where'] not in ('unknown', 'coop') else None)
        frames = []
        for i in range(0, len(stack) - 7, 8):
            value = struct.unpack_from('<Q', stack, i)[0]
            hit = table.find(value)
            if hit is not None:
                name, offset, where = hit
                frames.append(dict(sp=i, module=None if where == 'coop' else name, offset=hex(offset), where=where))
                if len(frames) >= MAX_FRAMES:
                    break
        event['frames'] = frames
        event['modules_other'] = table.others()
    except Exception as error:  # The report must survive any lookup failure.
        event['schema_error'] = type(error).__name__
    return bounded(event)


def bounded(event):
    """Keep the JSON line within MAX_LINE: shorten frames, then the module list, then schema-1 offsets."""
    for key in ('frames', 'modules_other', 'stack_code_offsets'):
        while len(scrub(json.dumps(event))) > MAX_LINE and event.get(key):
            event[key] = event[key][:len(event[key]) // 2] if len(event[key]) > 1 else []
    return json.loads(scrub(json.dumps(event)))


def describe(code, address, game_base, event):
    """The human traceback line. Starts exactly like schema 1 ('... {code:x} at {address:x} (RVA …)') so
    existing greps keep matching, then names the module, the access and the game base when known."""
    line = f'unhandled native exception {code:x} at {address:x} (RVA {address - game_base:x})'
    try:
        fault = event.get('fault') or {}
        if fault.get('where') not in (None, 'game'):
            line += f' in {fault["module"]}+{fault["offset"]}' if fault.get('module') else f' in {fault["where"]} code'
        access = event.get('access')
        if access:
            line += f'; {access["type"]} {access["address"]}'
        if fault.get('where') not in (None, 'game'):
            line += f'; game base {game_base:x}'
    except Exception:
        pass
    return scrub(line)


def summary(player, event):
    """The traceback line for a crash event that arrived as data (DLL core via the shim), not as an exception."""
    try:
        code = str(event.get('code') or 'unknown')[:8]
        fault = event.get('fault') if isinstance(event.get('fault'), dict) else {}
        where = fault.get('where') or 'unknown'
        place = f'{fault["module"]}+{fault.get("offset")}' if fault.get('module') else f'{where} code {fault.get("offset", "?")}'
        line = f'Client {player}: unhandled native exception {code} in {place} ({where}; crash report of the co-op core)'
    except Exception:
        line = f'Client {player}: unhandled native exception (crash report of the co-op core)'
    return scrub(line)[:300]
