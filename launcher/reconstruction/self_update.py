"""Azeroth Survivors Together co-op self-updater (boot-log format).

One updater for every later version. It reads the signed release description
from GitHub, downloads only the files that differ from this game folder and
installs them like the offline updater: backup, verification, rollback.

Release files (one GitHub release, fixed names via releases/latest/download/):
  latest.json        signed: version, sequence, signing time, minimum updater,
                     updater exe, manifest and archive assets with SHA-256/size,
                     optional key rotation (keys.add / keys.retire)
  latest.json.sig    Ed25519 signature (64 bytes) of the exact latest.json bytes
  manifest-<v>.json  every package file: path, SHA-256, size and source, either
                     {"archive": "mod"|"runtime"} (an asset zip of mod files) or
                     {"url": "https://..."} (game files hosted elsewhere)
Integrity: latest.json is signed, every other file is pinned by SHA-256 in it.

Security rules: HTTPS only, also after redirects (at most 5, only to GitHub or
the hosts of signed game file addresses), size limits and timeouts on every
request, the signature must come from a trusted key (built in, or added by an
earlier signed release), never an older version than installed and never an
older signed release than the last one accepted here (replay). Only signed
manifest paths are written (no drives, ADS, '..', reserved names or links out
of the folder; archive members are copied one by one with their signed size);
player data (saves, profiles, addons, WTF, logs) never. External game file
addresses that answer with a web page (download page, captcha) stop the update
before anything is installed and point to the full package instead.
A release that changes .coop-runtime exits with RUNTIME_BUSY after copying the
runtime; the updater exe runs this script again from the copy (--runtime-free).
Signatures use the audited `cryptography` package shipped in .coop-runtime.
"""
import argparse
import base64
import ctypes
import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from pathlib import Path

UPDATER_VERSION = 1
PRODUCT = 'azeroth-survivors-together'
RELEASE_URL = 'https://github.com/bymarvin/azeroth-survivors-together/releases/latest/download/'
# Release signing keys (Ed25519, raw 32 bytes, base64). The private key exists
# only on the release machine (C:/Users/<you>/.azcoop-signing/).
TRUSTED_KEYS = ('KT0uZ26Iiq4BoCNZPNuYDOWFCMJJenW83dALTZFyMjc=',)
UPDATER_ASSET = 'Azeroth-Survivors-Together-Updater.exe'
EXE = 'AzerothSurvivors.exe'
STATE, TRUST = 'coop-update-state.json', 'coop-update-trust.json'
LATEST_LIMIT, MANIFEST_LIMIT = 256 * 1024, 8 * 1024 * 1024
SELF_UPDATE_READY = 3  # Exit code: the new updater exe waits next to the running one.
RUNTIME_BUSY = 5  # Exit code: restart from coop-update/<RUNTIME_COPY> with --runtime-free.
RUNTIME_COPY = 'runtime'
FULL_PACKAGE = 'Download the full Azeroth Survivors Together package instead and keep your saves folder.'
# Never written or deleted, even if a release manifest ever listed them: player
# data and settings (addons, WTF, saves, profiles, logs, room logs, backups).
USER_AREAS = ('benilla-config/', 'wtf/', 'interface/addons/', 'addons/', 'saves/', 'save/', 'profiles/', 'profile/',
              'logs/', 'collected-logs/', 'screenshots/', '.coop-rooms/', '.coop-pairing/', 'coop-update-backup-',
              'coop-update/')
USER_FILES = ('config.wtf', STATE, TRUST)
LOG = None
IGNORED_PIDS = set()  # An updater exe that replaced itself and still waits.


class Refused(Exception):
    """A check failed before anything was changed."""


class Offline(Refused):
    """The release server could not be reached."""


def log(tag, text):
    line = f'[{tag:^6}] {text}'
    print(line, flush=True)
    if LOG is not None:
        LOG.write(line + '\n')
        LOG.flush()


def step(name):
    log(' .... ', name)
    return time.time()


def done(name, started, info=''):
    log('  OK  ', f'{name} ({time.time() - started:.1f} s{", " + info if info else ""})')


def threads():
    try:
        kernel = ctypes.windll.kernel32
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.GetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.POINTER(ctypes.c_size_t),
                                                  ctypes.POINTER(ctypes.c_size_t))
        mask, system = ctypes.c_size_t(), ctypes.c_size_t()
        if kernel.GetProcessAffinityMask(kernel.GetCurrentProcess(), ctypes.byref(mask), ctypes.byref(system)):
            return max(1, min(16, bin(mask.value).count('1')))
    except (AttributeError, OSError):
        pass
    return 4


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def hash_all(paths, label):
    """Parallel streaming hashes with a progress line at least every ~10 s."""
    paths = list(paths)
    results, last = {}, time.time()
    with ThreadPoolExecutor(threads()) as pool:
        futures = {pool.submit(lambda p: sha256(p) if p.is_file() else None, p): p for p in paths}
        for count, future in enumerate(futures, 1):
            results[futures[future]] = future.result()
            if time.time() - last >= 10:
                last = time.time()
                log(f'{count * 100 // len(paths):>3} %', f'{label} {count}/{len(paths)} files')
    return results


def user_area(path):
    lower = path.lower()
    name = lower.rsplit('/', 1)[-1]
    return (any(lower.startswith(a) or f'/{a}' in lower for a in USER_AREAS) or name in USER_FILES
            or (lower.startswith('analysis/room-player-') and lower.endswith('.jsonl')) or name.endswith('.log'))


RESERVED = {'con', 'prn', 'aux', 'nul', 'conin$', 'conout$',
            *(f'{d}{i}' for d in ('com', 'lpt') for i in [*'0123456789', '¹', '²', '³'])}


def safe_path(path):
    """A relative release path that Windows stores as written: no drive, ADS, '..', reserved or odd names."""
    if not isinstance(path, str) or not path or len(path) > 240 or path.startswith('/') or '\\' in path:
        return False
    if any(ord(c) < 32 or c in ':*?"<>|' for c in path):
        return False
    for part in path.split('/'):
        if part in ('', '.', '..') or part != part.rstrip(' .') or part.split('.')[0].lower() in RESERVED:
            return False
    return True


def parse_version(text):
    """'0.0.11-community+game-7264d50b' -> (0, 0, 11)."""
    core = text.strip().split('-', 1)[0].split('+', 1)[0]
    parts = core.split('.')
    if not 1 <= len(parts) <= 4 or not all(p.isdigit() for p in parts):
        raise ValueError(f'Invalid version {text!r}')
    return tuple(int(p) for p in parts)


def find_game(start):
    # The updater lives in <game>/coop-update or in <game>/reconstruction; started
    # from a subfolder of the game folder also works.
    for folder in (start, start.parent, start.parent.parent):
        if (folder / 'package-manifest.json').is_file() and (folder / EXE).is_file():
            return folder
    raise Refused('No Azeroth Survivors Together co-op folder found next to this updater. '
                  'Put the updater into your game folder (where Start-Coop.cmd is) and run it there.')


def parent_pid():
    """The starter's process id without os.getppid(): CPython asks PssCaptureSnapshot for it on Windows, which
    Wine/Proton (Linux players) does not implement (OSError WinError 1168). A toolhelp snapshot works on Windows
    and Wine alike; os.getppid() is only the fallback, and 0 (skipped) when that fails as well."""
    try:
        class Entry(ctypes.Structure):
            _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD), ('th32ProcessID', wintypes.DWORD),
                        ('th32DefaultHeapID', ctypes.c_size_t), ('th32ModuleID', wintypes.DWORD),
                        ('cntThreads', wintypes.DWORD), ('th32ParentProcessID', wintypes.DWORD),
                        ('pcPriClassBase', ctypes.c_long), ('dwFlags', wintypes.DWORD), ('szExeFile', ctypes.c_wchar * 260)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
        kernel.Process32FirstW.argtypes = kernel.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(Entry))
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        snapshot = kernel.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
        if snapshot and snapshot != wintypes.HANDLE(-1).value:
            try:
                entry = Entry(dwSize=ctypes.sizeof(Entry))
                me, ok = os.getpid(), kernel.Process32FirstW(snapshot, ctypes.byref(entry))
                while ok:
                    if entry.th32ProcessID == me:
                        return entry.th32ParentProcessID
                    ok = kernel.Process32NextW(snapshot, ctypes.byref(entry))
            finally:
                kernel.CloseHandle(snapshot)
    except (OSError, AttributeError, ValueError):
        pass
    try:
        return os.getppid()
    except OSError:
        return 0


def processes_in(root):
    """Programs started from inside the game folder (game, co-op launcher), except this updater and its starter."""
    try:
        psapi, kernel = ctypes.WinDLL('psapi'), ctypes.WinDLL('kernel32')
    except OSError:
        return []
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                  ctypes.POINTER(wintypes.DWORD))
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    pids = (wintypes.DWORD * 8192)()
    size = wintypes.DWORD()
    if not psapi.EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(size)):
        return []
    prefix = os.path.normcase(str(root)).rstrip(os.sep) + os.sep
    found = []
    mine = (0, os.getpid(), parent_pid())
    for pid in pids[:size.value // ctypes.sizeof(wintypes.DWORD)]:
        if pid in mine or pid in IGNORED_PIDS:  # This updater and its starters.
            continue
        handle = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            continue
        try:
            buffer, length = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
            if kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
                if os.path.normcase(buffer.value).startswith(prefix):
                    found.append(f'{Path(buffer.value).name} (process {pid})')
        finally:
            kernel.CloseHandle(handle)
    return found


def writable(path):
    """A running exe, a read-only file or one another program holds open refuses writing."""
    try:
        with open(path, 'r+b'):
            return True
    except OSError:
        return False


def ensure_closed(root):
    running = processes_in(root)
    if running or not writable(root / EXE):
        raise Refused(f'Still running from this folder: {", ".join(running) or EXE + " is in use"}. '
                      'Close the game and the co-op launcher, then run the updater again. Nothing was changed.')


# ---------------------------------------------------------------- network

GITHUB_HOSTS = ('github.com', '.githubusercontent.com')  # Release assets redirect to *.githubusercontent.com.
MAX_REDIRECTS = 5
PROGRESS_BYTES = 8 * 2**20  # Downloads from this size on report progress once a second.


class NotDirect(Refused):
    """An external game file address is a web page (download page, captcha), not the file itself."""


class Net:
    """HTTPS to allowed hosts only (redirects included, at most 5), bounded sizes, timeouts, resumable downloads."""

    def __init__(self, base_url, timeout=10.0, allow_local_http=False):
        self.base, self.timeout, self.allow_local_http = base_url, timeout, allow_local_http
        self.hosts = set()
        self.check_scheme(base_url)
        self.allow(base_url)
        net = self

        class Redirect(urllib.request.HTTPRedirectHandler):
            max_redirections = MAX_REDIRECTS

            def redirect_request(self, req, fp, code, msg, headers, newurl):
                net.check_url(newurl)
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        context = ssl.create_default_context()
        self.opener = urllib.request.build_opener(Redirect, urllib.request.HTTPSHandler(context=context))
        self.opener.addheaders = [('User-Agent', f'{PRODUCT}-updater/{UPDATER_VERSION}')]

    @staticmethod
    def host(url):
        return (urllib.parse.urlsplit(url).hostname or '').lower()

    def allow(self, url):
        """Allow the host of a signed address (release base, external game file sources)."""
        self.hosts.add(self.host(url))

    def check_scheme(self, url):
        if url.startswith('https://'):
            return
        if self.allow_local_http and url.startswith(('http://127.0.0.1:', 'http://localhost:')):
            return
        raise Refused(f'Refusing a non-HTTPS address: {url.split("?")[0]}')

    def check_url(self, url):
        self.check_scheme(url)
        host = self.host(url)
        if host in self.hosts or any(host == h or (h.startswith('.') and host.endswith(h)) for h in GITHUB_HOSTS):
            return
        raise Refused(f'Refusing an address on a host that is not allowed: {host}')

    def url(self, asset):
        return self.base + asset

    def open(self, request):
        try:
            return self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            if 300 <= error.code < 400:
                raise Refused(f'Too many redirects (more than {MAX_REDIRECTS}) for '
                              f'{request.full_url.rsplit("/", 1)[-1]}') from error
            raise

    def fetch(self, url, limit):
        self.check_url(url)
        try:
            with self.open(urllib.request.Request(url)) as response:
                data = response.read(limit + 1)
        except urllib.error.HTTPError as error:
            raise Refused(f'Release server answered {error.code} for {url.rsplit("/", 1)[-1]}') from error
        except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
            raise Offline(f'Release server not reachable ({getattr(error, "reason", error)})') from error
        if len(data) > limit:
            raise Refused(f'{url.rsplit("/", 1)[-1]} is larger than allowed ({limit} bytes)')
        return data

    def download(self, url, target, size, digest, external=False):
        """Resume a partial download (HTTP Range) and verify size and SHA-256.

        external: a game file on another host; a web page instead of the file
        (download page, captcha) raises NotDirect instead of a hash failure.
        """
        self.check_url(url)
        target.parent.mkdir(parents=True, exist_ok=True)
        part = target.with_name(target.name + '.part')
        if target.is_file() and target.stat().st_size == size and sha256(target) == digest:
            return 'cached'
        for attempt in range(3):
            have = part.stat().st_size if part.exists() else 0
            if have > size:
                part.unlink()
                have = 0
            request = urllib.request.Request(url, headers={'Range': f'bytes={have}-'} if have else {})
            try:
                with self.open(request) as response:
                    kind = (response.headers.get('Content-Type') or '').lower()
                    if external and kind.startswith(('text/html', 'application/xhtml')):
                        raise NotDirect(f'{target.name}: {self.host(response.geturl())} answers with a web page, '
                                        'not the file (a download page or captcha)')
                    if have and response.status != 206:
                        have = 0  # The server ignored the range: start again.
                    mode = 'ab' if have else 'wb'
                    with open(part, mode) as stream:
                        written = have
                        # Big files: one progress line per second (MiB, MiB/s, ETA), so a slow source never looks
                        # like a hang (0.0.25: a 478 MiB game file took minutes without a line).
                        started = last = time.monotonic()
                        while True:
                            chunk = response.read(1 << 20)
                            if not chunk:
                                break
                            now = time.monotonic()
                            if size >= PROGRESS_BYTES and now - last >= 1.0:
                                last = now
                                rate = (written - have) / max(now - started, 1e-3)
                                eta = (size - written) / rate if rate > 0 else 0
                                log(f'{100 * written // size:3d} %', f'{target.name}: {written / 2**20:.0f}/{size / 2**20:.0f} MiB '
                                                                    f'from {self.host(response.geturl())}, {rate / 2**20:.1f} MiB/s, '
                                                                    f'about {eta:.0f} s left')
                            if written == 0 and external and chunk.lstrip()[:15].lower().startswith(
                                    (b'<!doctype html', b'<html')):
                                raise NotDirect(f'{target.name}: the address returns a web page, not the file')
                            written += len(chunk)
                            if written > size:
                                if external:
                                    raise NotDirect(f'{target.name}: the address returns something else than the '
                                                    'signed file (larger)')
                                raise Refused(f'{target.name}: server sent more than the signed size')
                            stream.write(chunk)
            except Refused as error:
                if external and not isinstance(error, NotDirect):  # Redirect to plain HTTP or another host.
                    raise NotDirect(f'{target.name}: {error}') from error
                raise
            except urllib.error.HTTPError as error:
                if error.code == 416 and have == size:
                    pass  # Already complete.
                elif external and error.code in (401, 403, 404, 410, 429):
                    raise NotDirect(f'{target.name}: the download address answered {error.code}') from error
                else:
                    raise Refused(f'Download {target.name}: server answered {error.code}') from error
            except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException) as error:
                if attempt == 2:
                    raise Offline(f'Download {target.name} interrupted ({getattr(error, "reason", error)}); '
                                  'run the updater again to continue') from error
                log(' WARN ', f'Download {target.name} interrupted, continuing ({attempt + 1}/3)')
                continue
            if part.stat().st_size == size:
                break
        if not part.exists() or part.stat().st_size != size:
            raise Offline(f'Download {target.name} incomplete; run the updater again to continue')
        if sha256(part) != digest:
            part.unlink()
            raise Refused(f'Download {target.name} does not match its signed SHA-256 (removed). '
                          'Run the updater again; if it persists, report it.')
        os.replace(part, target)
        return 'downloaded'


# ---------------------------------------------------------------- trust

def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return default


def trusted_keys(root, builtin=TRUSTED_KEYS):
    store = load_json(root / TRUST, {})
    keys = [k for k in (*builtin, *store.get('added', [])) if k not in store.get('retired', [])]
    return list(dict.fromkeys(keys)) or list(builtin)


def verify(data, signature, keys):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if len(signature) != 64:
        return None
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(signature, data)
            return key
        except (InvalidSignature, ValueError):
            continue
    return None


def validate_latest(latest):
    if not isinstance(latest, dict) or latest.get('format') != 1 or latest.get('product') != PRODUCT:
        raise Refused('latest.json is not an Azeroth Survivors Together release description')
    for field in ('version', 'signed_at'):
        if not isinstance(latest.get(field), str):
            raise Refused(f'latest.json has no {field}')
    parse_version(latest['version'])
    if type(latest.get('sequence')) is not int or type(latest.get('min_updater')) is not int:
        raise Refused('latest.json has no sequence or minimum updater version')
    for entry in [latest.get('manifest'), latest.get('updater'), *(latest.get('archives') or {}).values()]:
        if (not isinstance(entry, dict) or not isinstance(entry.get('asset'), str) or not safe_path(entry['asset'])
                or '/' in entry['asset'] or type(entry.get('size')) is not int or len(entry.get('sha256', '')) != 64):
            raise Refused('latest.json lists an invalid asset')
    full = latest.get('full_package')
    if full is not None and not (isinstance(full, dict) and isinstance(full.get('url'), str)
                                 and full['url'].startswith('https://')):
        raise Refused('latest.json has an invalid full package address')
    keys = latest.get('keys') or {}
    if not isinstance(keys, dict) or not all(isinstance(k, str) and valid_key(k) for k in
                                             [*keys.get('add', []), *keys.get('retire', [])]):
        raise Refused('latest.json announces an invalid key')


def valid_key(text):
    try:
        return len(base64.b64decode(text, validate=True)) == 32
    except ValueError:
        return False


def read_latest(net, root, builtin=TRUSTED_KEYS):
    """Fetch and verify latest.json; returns (latest, raw bytes, signing key)."""
    data = net.fetch(net.url('latest.json'), LATEST_LIMIT)
    signature = net.fetch(net.url('latest.json.sig'), 1024)
    key = verify(data, signature, trusted_keys(root, builtin))
    if key is None:
        raise Refused('The release description is not signed by a trusted key. Nothing was changed.')
    try:
        latest = json.loads(data)
    except ValueError as error:
        raise Refused('latest.json is not valid JSON') from error
    validate_latest(latest)
    return latest, data, key


def installed_version(root):
    try:
        return (root / 'COOP-VERSION.txt').read_text(encoding='utf-8').strip()
    except OSError:
        return '0.0.0'


def compare(root, latest):
    """'newer' / 'same'; refuse downgrade and replay of an older signed release."""
    installed = installed_version(root)
    state = load_json(root / STATE, {})
    if latest['sequence'] < state.get('sequence', 0) or latest['signed_at'] < state.get('signed_at', ''):
        raise Refused(f'The server offers an older signed release (sequence {latest["sequence"]}, signed '
                      f'{latest["signed_at"]}) than the one already accepted here ({state.get("sequence")}). '
                      'Nothing was changed.')
    if parse_version(latest['version']) < parse_version(installed):
        raise Refused(f'The server offers co-op {latest["version"]}, older than the installed {installed}. '
                      'Nothing was changed.')
    return 'newer' if parse_version(latest['version']) > parse_version(installed) else 'same'


def check(root, base_url=RELEASE_URL, timeout=3.0, allow_local_http=False, builtin=TRUSTED_KEYS):
    """For the launcher: (status, version) where status is newer/same/offline/invalid; never raises."""
    try:
        net = Net(base_url, timeout=timeout, allow_local_http=allow_local_http)
        latest, _, _ = read_latest(net, root, builtin)
        return compare(root, latest), latest['version']
    except Offline:
        return 'offline', None
    except (Refused, ValueError):
        return 'invalid', None


# ---------------------------------------------------------------- install

def install(root, staged, target, delete, label, manifest='package-manifest.json'):
    """Write staged files {path: source file} over root with backup and full rollback.

    manifest: the installed file list written last (a channel component keeps its own, see CHANNEL_MANIFEST)."""
    changed = sorted(staged)
    blocked = [p for p in changed + delete + [manifest] if (root / p).exists() and not writable(root / p)]
    if blocked:
        raise Refused(f'{len(blocked)} files are read-only or locked (for example {blocked[0]}). '
                      'Close the game, remove the write protection and run the updater again. Nothing was changed.')
    backup_bytes = sum((root / p).stat().st_size for p in changed + delete if (root / p).exists())
    largest = max([Path(staged[p]).stat().st_size for p in changed] or [0])
    need = backup_bytes + largest + 64 * 2**20
    free = shutil.disk_usage(root).free
    if free < need:
        raise Refused(f'Not enough free disk space: {free / 2**20:.0f} MiB free, {need / 2**20:.0f} MiB needed. '
                      'Free some space and run the updater again. Nothing was changed.')
    backup = root / f'coop-update-backup-{time.strftime("%Y%m%d-%H%M%S")}'
    replaced, added, deleted, manifest_written = [], [], [], False
    try:
        started = step('Back up replaced files')
        for p in changed + delete + [manifest]:
            if (root / p).exists():
                (backup / p).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(root / p, backup / p)
        done('Back up replaced files', started, backup.name)

        started = step('Install new files')
        for p in changed:
            destination = root / p
            existed = destination.exists()
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + '.coop-new')
            try:
                shutil.copyfile(staged[p], temporary)
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
            (replaced if existed else added).append(p)
        for p in delete:
            (root / p).unlink()
            deleted.append(p)
        manifest_written = True
        (root / manifest).write_text(json.dumps(target, indent=1, sort_keys=True), encoding='utf-8')
        done('Install new files', started, f'{len(replaced)} replaced, {len(added)} added, {len(deleted)} deleted')

        started = step('Verify written files')
        result = hash_all([root / p for p in changed], 'verify')
        wrong = [p for p in changed if result[root / p] != target[p]]
        if wrong:
            raise RuntimeError(f'Written file does not match the release: {wrong[0]}')
        done('Verify written files', started, f'{len(changed)} files match the release')
    except BaseException as error:
        log('FAILED', f'Update: {type(error).__name__}: {error}')
        started = step('Restore previous version')
        problems = []
        for p in added:
            try:
                (root / p).unlink(missing_ok=True)
            except OSError as problem:
                problems.append(f'{p}: {problem}')
        for p in replaced + deleted + ([manifest] if manifest_written else []):
            try:
                temporary = (root / p).with_name(Path(p).name + '.coop-restore')
                shutil.copy2(backup / p, temporary)
                os.replace(temporary, root / p)
            except OSError as problem:
                problems.append(f'{p}: {problem}')
        if problems:
            log('FAILED', f'Restore previous version: {len(problems)} files could not be restored, first {problems[0]}; '
                          f'copy them back from {backup.name} by hand')
        else:
            done('Restore previous version', started, f'{len(replaced) + len(deleted)} restored, {len(added)} removed; '
                                                     'the folder is as before')
        raise
    return backup


BASE_INSTALL = install  # Channels use these directly: updater_v2 wraps the module attributes for the default run.


class RuntimeBusy(Refused):
    """The release changes .coop-runtime, which this Python runs from: restart from a copy."""


class NeedFullPackage(Refused):
    """New game files exist but cannot be downloaded directly: the player needs the full package."""


def plan(root, target, files, runtime_free=False, manifest='package-manifest.json'):
    """Files to fetch (hash differs or missing) and old release files to delete (only if unchanged)."""
    installed = load_json(root / manifest, {})
    paths = [p for p in target if not user_area(p)]
    for p in target:
        if user_area(p):
            log(' WARN ', f'Player data or settings, never touched by the updater: {p}')
    local = hash_all([root / p for p in paths], 'scan')
    needed = sorted(p for p in paths if local[root / p] != target[p])
    removed = sorted(p for p in installed if p not in target and not user_area(p) and safe_path(p))
    current = hash_all([root / p for p in removed], 'scan')
    delete = [p for p in removed if current[root / p] == installed[p]]
    for p in removed:
        if current[root / p] not in (None, installed[p]):
            log(' WARN ', f'Not deleted (changed since the old release, kept as it is): {p}')
    runtime = [p for p in needed + delete if p.startswith('.coop-runtime/')]
    if runtime:
        running = Path(sys.executable).resolve()
        inside = (root / '.coop-runtime').resolve()
        if not runtime_free or running == inside or inside in running.parents:
            raise RuntimeBusy(f'This update changes the co-op Python runtime ({len(runtime)} files, for example '
                              f'{runtime[0]}), which this updater runs from')
    escaped = [p for p in needed + delete if not inside_root(root, p)]
    if escaped:
        raise Refused(f'{escaped[0]} would be written outside the game folder (a link in the folder?). '
                      'Nothing was changed.')
    return needed, delete


def inside_root(root, path):
    """The real location (links resolved) stays inside the game folder."""
    real_root = os.path.realpath(root)
    real = os.path.realpath(root / path)
    return os.path.normcase(real).startswith(os.path.normcase(real_root).rstrip(os.sep) + os.sep)


def extract_member(archive, name, size, digest, target):
    """Copy exactly one signed member; refuse links, wrong sizes and decompression bombs."""
    try:
        info = archive.getinfo(name)
    except KeyError:
        raise Refused(f'{name} is missing from the archive. Nothing was changed.') from None
    mode = (info.external_attr >> 16) & 0o170000
    if info.is_dir() or mode in (0o120000, 0o040000) or info.file_size != size or info.flag_bits & 0x1:
        raise Refused(f'{name} in the archive is not the signed plain file. Nothing was changed.')
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    try:
        with archive.open(info) as member, open(target, 'wb') as stream:
            while True:
                chunk = member.read(1 << 20)
                if not chunk:
                    break
                written += len(chunk)
                if written > size:  # Never trust the archive's own size fields.
                    raise Refused(f'{name} unpacks larger than signed. Nothing was changed.')
                stream.write(chunk)
    except (zipfile.BadZipFile, EOFError, zlib.error) as error:  # zipfile stops at the header size, then CRC.
        raise Refused(f'{name} in the archive is damaged ({error}). Nothing was changed.') from error
    if written != size or sha256(target) != digest:
        raise Refused(f'{name} does not match its signed SHA-256. Nothing was changed.')


def fetch_files(net, latest, files, needed, work):
    """Download everything for the needed paths before anything is installed; returns {path: staged file}.

    Game files on external hosts first: if they cannot be downloaded directly, nothing
    else is fetched and nothing is installed (NeedFullPackage).
    """
    staged, archives, external = {}, {}, []
    for p in needed:
        source = files[p]['source']
        if 'archive' in source:
            archives.setdefault(source['archive'], []).append(p)
        elif 'url' in source:
            external.append(p)
        else:
            raise Refused(f'manifest has no source for {p}')
    if any(a not in latest['archives'] for a in archives):
        raise Refused('latest.json does not list an archive the manifest needs. Nothing was changed.')
    total = sum(latest['archives'][a]['size'] for a in archives) + sum(files[p]['size'] for p in external)
    free = shutil.disk_usage(work.parent).free
    if free < total * 2 + 64 * 2**20:
        raise Refused(f'Not enough free disk space for the download: {free / 2**20:.0f} MiB free, '
                      f'{(total * 2 + 64 * 2**20) / 2**20:.0f} MiB needed. Nothing was changed.')
    for p in external:
        entry = files[p]
        started = step(f'Download {p}')
        target = work / 'files' / p
        try:
            how = net.download(entry['source']['url'], target, entry['size'], entry['sha256'], external=True)
        except NotDirect as error:
            full = (latest.get('full_package') or {}).get('url')
            raise NeedFullPackage(f'This update needs new game files that cannot be downloaded automatically '
                                  f'({error}). Nothing was changed. Download the full package'
                                  + (f' here: {full}' if full else ' from the release page')) from error
        done(f'Download {p}', started, f'{entry["size"] / 2**20:.1f} MiB {how}')
        staged[p] = target
    for name, paths in sorted(archives.items()):
        entry = latest['archives'][name]
        started = step(f'Download {entry["asset"]}')
        archive = work / 'download' / entry['asset']
        how = net.download(net.url(entry['asset']), archive, entry['size'], entry['sha256'])
        done(f'Download {entry["asset"]}', started, f'{entry["size"] / 2**20:.1f} MiB {how}')
        with zipfile.ZipFile(archive) as z:
            for p in paths:  # Only signed members; everything else in the archive is ignored.
                extract_member(z, p, files[p]['size'], files[p]['sha256'], work / 'files' / p)
                staged[p] = work / 'files' / p
    return staged


def self_update(net, latest, exe):
    """Fetch the newer updater exe next to the running one; the exe swaps itself."""
    entry = latest['updater']
    if exe is None:
        raise Refused(f'This update needs updater {latest["min_updater"]} or newer. Download {entry["asset"]} '
                      'and run it in your game folder. Nothing was changed.')
    started = step(f'Update the updater to version {entry.get("version")}')
    target = Path(exe).with_name(Path(exe).name + '.new')
    net.download(net.url(entry['asset']), target, entry['size'], entry['sha256'])
    done(f'Update the updater to version {entry.get("version")}', started, 'restarting with the new updater')
    return SELF_UPDATE_READY


def main(argv=None, builtin=TRUSTED_KEYS):
    global LOG
    ap = argparse.ArgumentParser(description='Azeroth Survivors Together co-op updater')
    ap.add_argument('--release-url', default=RELEASE_URL)
    ap.add_argument('--updater-version', type=int, default=UPDATER_VERSION)
    ap.add_argument('--updater-exe', help='path of the running updater exe (self-update)')
    ap.add_argument('--game', type=Path, help='game folder (default: next to this file)')
    ap.add_argument('--timeout', type=float, default=10.0)
    ap.add_argument('--allow-local-http', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--ignore-pid', type=int, action='append', default=[], help=argparse.SUPPRESS)
    # Set by the updater exe when it restarted this script from a copy of .coop-runtime.
    ap.add_argument('--runtime-free', action='store_true', help=argparse.SUPPRESS)
    # Only test builds of the updater exe pass this (compiled-in test key).
    ap.add_argument('--extra-trusted-key', action='append', default=[], help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    IGNORED_PIDS.update(args.ignore_pid)
    builtin = (*builtin, *args.extra_trusted_key)
    try:
        sys.stdout.reconfigure(errors='replace')
    except AttributeError:
        pass
    t0 = time.time()
    root = args.game.resolve() if args.game else find_game(Path(__file__).resolve().parent)
    work = root / 'coop-update'
    work.mkdir(exist_ok=True)
    LOG = (work / 'update.log').open('a', encoding='utf-8')
    log(' INFO ', f'Updater {args.updater_version}, game folder {root}, {threads()} threads')

    started = step('Game and co-op launcher are closed')
    ensure_closed(root)
    done('Game and co-op launcher are closed', started)

    started = step('Read signed release description')
    net = Net(args.release_url, timeout=args.timeout, allow_local_http=args.allow_local_http)
    latest, raw, key = read_latest(net, root, builtin)
    status = compare(root, latest)
    done('Read signed release description', started,
         f'co-op {latest["version"]} (sequence {latest["sequence"]}, signed {latest["signed_at"]}), '
         f'installed {installed_version(root)}')
    if latest['min_updater'] > args.updater_version:
        return self_update(net, latest, args.updater_exe)

    started = step('Read release file list')
    entry = latest['manifest']
    data = net.fetch(net.url(entry['asset']), min(entry['size'], MANIFEST_LIMIT))
    if len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise Refused('manifest does not match its signed SHA-256. Nothing was changed.')
    files = validate_files(json.loads(data), net)
    target = {p: e['sha256'] for p, e in files.items()}
    done('Read release file list', started, f'{len(files)} files')

    started = step('Compare with this folder')
    try:
        needed, delete = plan(root, target, files, args.runtime_free)
    except RuntimeBusy as error:
        if args.runtime_free or not args.updater_exe:
            raise Refused(f'{error}. Run {UPDATER_ASSET} in the game folder; it restarts from a copy of the '
                          'runtime. Nothing was changed.') from error
        log(' INFO ', f'{error}: restarting from a temporary copy of it')
        copy_runtime(root, work / RUNTIME_COPY)
        return RUNTIME_BUSY
    done('Compare with this folder', started, f'{len(needed)} files to download, {len(delete)} to delete')
    if not needed and not delete:
        accept(root, latest, key)
        if load_json(root / 'package-manifest.json', {}) != target:
            (root / 'package-manifest.json').write_text(json.dumps(target, indent=1, sort_keys=True), encoding='utf-8')
        log('  OK  ', f'Nothing to do: this folder is co-op {installed_version(root)}'
                      + (' (newer files already present)' if status == 'newer' else ''))
        sync_channels(net, latest, root)
        return 0

    staging = work / f'release-{latest["version"]}'
    staged = fetch_files(net, latest, files, needed, staging)
    started = step('Game and co-op launcher are closed')
    ensure_closed(root)  # The downloads may have taken a while.
    done('Game and co-op launcher are closed', started)
    backup = install(root, staged, target, delete, latest['version'])
    accept(root, latest, key)
    shutil.rmtree(staging / 'files', ignore_errors=True)
    log(' INFO ', f'Summary: co-op {installed_version(root)} in {time.time() - t0:.1f} s; backup in {backup.name} '
                  '(delete it once the game runs)')
    log('  OK  ', f'Installed co-op version: {installed_version(root)}. Start the game with Start-Coop.cmd.')
    sync_channels(net, latest, root)
    return 0


# ---------------------------------------------------------------- channels (0.0.24)
#
# An optional co-op channel (the DLL beta) lives in its own subfolder of the co-op folder, <root>/<id>/, next to a
# copy of the player's own game (WP2 copies AzerothSurvivors.exe and Data/ there; the updater never writes, deletes
# or downloads game files of a channel). The signed latest.json lists it under
# "channels": {id: {schema: 1, title, enabled, message, builds: [{version, exe_sha256, exe_size, enabled, message}],
#                   manifest, archives}}
# (an entry without "schema" in the first, single-build form {game: {...}} is read as a list of one; another schema
# makes the channel unavailable with a clear text, never a guess). Older updaters ignore "channels" (validate_latest
# only checks known keys). The channel's own signed file list tags build-specific files with "build": <exe_sha256>;
# untagged files are common. A channel is installed only where its folder exists (the player opted in): the common
# files plus the files of EVERY listed, switched-on build (the DLL picks its profile by the running exe's own hash;
# file names never collide), so a player who updates the game and copies a supported build again plays at once.
# Files of a build switched off or no longer listed are removed (only if unchanged; a changed file is kept). The
# copy's exe SHA-256 decides only the launcher's switch and <root>/<id>/channel-build.json. The installed files are
# listed in <root>/<id>/channel-manifest.json (written last), so the default update never sees them; every change
# uses the same backup and rollback.
# coop-update/channels.json carries the server's switch to the launcher: {id: {enabled, message, title, sequence,
# build, supported, builds, rollout, schema}}; enabled = the channel is on AND the copy's build is listed and on (absent = enabled);
# builds = the signed list [{version, exe_sha256, exe_size, enabled}] newest first, so the launcher can check a game
# before copying it; rollout = {percent, included}: the signed share of folders (default 100) and whether this folder's
# stable local bucket (coop-update/install-id, never sent) is in it - the lever to pause or limit within minutes by a
# new signed latest.json without a client update (files stay installed, so raising it again is instant). A channel switched off is paused (nothing in its folder changes; the launcher starts 0.95.0 at
# its next start, a running game is never touched). Offline, the last signed state stays; an older signed release
# is refused by compare() before anything is written, so a replay cannot switch one on.

CHANNEL_SCHEMA = 1
CHANNEL_MANIFEST = 'channel-manifest.json'
CHANNEL_BUILD = 'channel-build.json'
CHANNELS_STATE = 'coop-update/channels.json'
CHANNEL_ID = re.compile(r'[a-z0-9][a-z0-9.-]{0,39}')
SHA256 = re.compile(r'[0-9a-f]{64}')
CHANNEL_FILES, CHANNEL_BYTES = 512, 512 * 2**20  # Caps of one channel manifest (files, total size).
CHANNEL_BUILDS = 32
INSTALL_ID = 'coop-update/install-id'  # Random, local only (never sent): the rollout bucket of this folder.
GAME_COPY = (EXE.lower(), 'data/')  # The player's own game copy in a channel folder: never a channel file.
BASE_FETCH, BASE_ENSURE_CLOSED = fetch_files, ensure_closed  # The originals (updater_v2 replaces the attributes).


def version_key(text):
    """'0.100.1' -> (0, 100, 1) for newest-first lists; odd text sorts last."""
    try:
        return tuple(int(part) for part in text.split('.'))
    except ValueError:
        return ()


def channel_builds(entry):
    """The listed builds of a channel entry (the single-build form as a list of one), or None if malformed."""
    if 'schema' not in entry and isinstance(entry.get('game'), dict):
        builds = [dict(entry['game'], enabled=True)]
    else:
        builds = entry.get('builds')
    if not isinstance(builds, list) or not 1 <= len(builds) <= CHANNEL_BUILDS:
        return None
    seen = set()
    for build in builds:
        if (not isinstance(build, dict) or not isinstance(build.get('version'), str) or not build['version']
                or not isinstance(build.get('exe_sha256'), str) or not SHA256.fullmatch(build['exe_sha256'])
                or type(build.get('exe_size')) is not int or build['exe_size'] <= 0
                or type(build.get('enabled', True)) is not bool
                or (build.get('message') is not None and not isinstance(build['message'], str))
                or build['exe_sha256'] in seen):
            return None
        seen.add(build['exe_sha256'])
    return [dict(b, enabled=b.get('enabled', True)) for b in builds]


def valid_channel(cid, entry):
    """A well-formed channel entry (signed); anything odd makes the channel unavailable, never the release."""
    if not (isinstance(cid, str) and CHANNEL_ID.fullmatch(cid) and safe_path(cid) and isinstance(entry, dict)):
        return False
    if 'schema' in entry and entry['schema'] != CHANNEL_SCHEMA:
        return False
    if type(entry.get('enabled')) is not bool or channel_builds(entry) is None:
        return False
    if entry.get('message') is not None and not isinstance(entry['message'], str):
        return False
    rollout = entry.get('rollout', {'percent': 100})
    if not isinstance(rollout, dict) or type(rollout.get('percent')) is not int or not 0 <= rollout['percent'] <= 100:
        return False
    if not entry['enabled']:
        return True  # A paused channel needs no files.
    archives = entry.get('archives')
    if not isinstance(archives, dict) or not archives:
        return False
    for asset_entry in [entry.get('manifest'), *archives.values()]:
        if (not isinstance(asset_entry, dict) or not isinstance(asset_entry.get('asset'), str)
                or not safe_path(asset_entry['asset']) or '/' in asset_entry['asset']
                or type(asset_entry.get('size')) is not int or len(asset_entry.get('sha256', '')) != 64):
            return False
    return True


def channel_entries(latest):
    """{id: entry with "builds"} of the well-formed channels of a verified release; others are logged and left out."""
    channels = latest.get('channels')
    if channels is None:
        return {}
    if not isinstance(channels, dict):
        log(' WARN ', 'latest.json lists channels in an unknown form; no channel is offered')
        return {}
    good = {}
    for cid, entry in channels.items():
        if isinstance(entry, dict) and 'schema' in entry and entry['schema'] != CHANNEL_SCHEMA:
            log(' WARN ', f'The channel {cid!r} needs a newer updater (schema {entry["schema"]!r}); it is not offered '
                          'by this one. Run Azeroth-Survivors-Together-Updater.exe again after the next update.')
        elif valid_channel(cid, entry):
            good[cid] = dict(entry, builds=channel_builds(entry))
        else:
            log(' WARN ', f'latest.json has an invalid entry for the channel {cid!r}; it is not offered')
    return good


def supported(entry):
    """Versions of the listed, switched-on builds, newest first."""
    return [b['version'] for b in newest_first(entry) if b['enabled']]


def newest_first(entry):
    """The listed builds, newest version first."""
    return sorted(entry['builds'], key=lambda b: version_key(b['version']), reverse=True)


def copy_build(folder, entry):
    """(build entry or None, exe SHA-256 or None) of the game copy in a channel folder; the size is checked first."""
    exe = folder / EXE
    try:
        size = exe.stat().st_size
    except OSError:
        return None, None
    if size not in {b['exe_size'] for b in entry['builds']}:
        return None, None
    digest = sha256(exe)
    return next((b for b in entry['builds'] if b['exe_sha256'] == digest and b['exe_size'] == size), None), digest


def local_channels(root):
    """Channel ids this folder knows: an existing channel folder or an earlier state entry."""
    known = set(load_json(root / CHANNELS_STATE, {}))
    return {cid for cid in known if isinstance(cid, str) and CHANNEL_ID.fullmatch(cid)} | {
        d.name for d in root.iterdir() if d.is_dir() and CHANNEL_ID.fullmatch(d.name)
        and (d / CHANNEL_MANIFEST).is_file()}


def channel_status(root, cid, entry):
    """(enabled, message, build version or None) for the launcher: channel on AND the copy's build listed and on."""
    if not entry['enabled']:
        return False, entry.get('message') or 'This channel is paused; the co-op starts 0.95.0.', None
    folder = root / cid
    if not (folder / EXE).is_file():
        return True, None, None  # Not copied yet: the launcher's setup decides.
    build, _ = copy_build(folder, entry)
    if build is None:
        return False, (f'Your game copy in {cid} is not a supported version. Supported: '
                       f'{", ".join(supported(entry)) or "none at the moment"}. Update your game and copy it again in '
                       'the launcher\'s "Co-op channel" setup.'), None
    if not build['enabled']:
        return False, build.get('message') or f'The co-op for game {build["version"]} is paused; the co-op starts 0.95.0.', build['version']
    return True, None, build['version']


def install_id(root):
    """This folder's random id (created once, local only): it decides the rollout bucket, it is never sent."""
    path = root / INSTALL_ID
    try:
        value = path.read_text(encoding='ascii').strip()
        if re.fullmatch(r'[0-9a-f]{32}', value):
            return value
    except (OSError, UnicodeDecodeError):
        pass
    value = os.urandom(16).hex()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode('ascii') + b'\n')
    return value


def rollout(root, cid, entry):
    """{percent, included}: the signed share of folders that use the channel; the bucket (0..99) is stable per folder."""
    percent = entry.get('rollout', {'percent': 100})['percent']
    bucket = int(hashlib.sha256(f'{install_id(root)}:{cid}'.encode('ascii')).hexdigest()[:8], 16) % 100
    return dict(percent=percent, included=bucket < percent)


def write_channel_state(root, latest, entries):
    """coop-update/channels.json for the launcher: every offered channel and every local one no longer offered."""
    state = {}
    for cid, e in entries.items():
        enabled, message, build = channel_status(root, cid, e)
        state[cid] = dict(schema=CHANNEL_SCHEMA, enabled=enabled, message=message, title=e.get('title'),
                          sequence=latest['sequence'], build=build, supported=supported(e),
                          builds=[{k: b[k] for k in ('version', 'exe_sha256', 'exe_size', 'enabled')}
                                  for b in newest_first(e)], rollout=rollout(root, cid, e))
    for cid in local_channels(root) - set(entries):
        state[cid] = dict(schema=CHANNEL_SCHEMA, enabled=False, sequence=latest['sequence'], build=None, supported=[],
                          builds=[], rollout=dict(percent=0, included=False), message='This channel is no longer offered; the co-op starts 0.95.0.')
    path = root / CHANNELS_STATE
    if load_json(path, None) == state:
        return state
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(state, indent=1, sort_keys=True), encoding='utf-8')
    os.replace(temporary, path)
    return state


def channel_files(manifest, cid, builds=None):
    """The signed file list of a channel: safe paths below its folder, never the game copy, within the caps;
    a "build" tag must name a listed build (builds: their exe SHA-256s; None = no build tags allowed)."""
    files = manifest.get('files') if isinstance(manifest, dict) else None
    if not isinstance(files, dict) or not files or len(files) > CHANNEL_FILES:
        raise Refused(f'The {cid} file list is empty or too long. Nothing was changed.')
    total = 0
    for p, entry in files.items():
        if (not safe_path(p) or p.lower() in (CHANNEL_MANIFEST, CHANNEL_BUILD) or p.lower().startswith(GAME_COPY)
                or user_area(p)):
            raise Refused(f'The {cid} file list names a file it may not write ({p!r}). Nothing was changed.')
        source = entry.get('source') if isinstance(entry, dict) else None
        if (not isinstance(source, dict) or set(source) != {'archive'} or not isinstance(source['archive'], str)
                or type(entry.get('size')) is not int or entry['size'] < 0
                or not isinstance(entry.get('sha256'), str) or len(entry['sha256']) != 64):
            raise Refused(f'The {cid} file list has an invalid entry for {p}. Nothing was changed.')
        if 'build' in entry and (not isinstance(entry['build'], str) or entry['build'] not in (builds or ())):
            raise Refused(f'The {cid} file list ties {p} to a build the release does not list. Nothing was changed.')
        total += entry['size']
    if total > CHANNEL_BYTES:
        raise Refused(f'The {cid} files are larger than allowed ({total / 2**20:.0f} MiB). Nothing was changed.')
    return files


def channel_target(net, entry, cid):
    """{path: file entry} of the common files plus those of every listed, switched-on build (signed list)."""
    data = net.fetch(net.url(entry['manifest']['asset']), min(entry['manifest']['size'], MANIFEST_LIMIT))
    if len(data) != entry['manifest']['size'] or hashlib.sha256(data).hexdigest() != entry['manifest']['sha256']:
        raise Refused(f'The {cid} file list does not match its signed SHA-256. Nothing was changed.')
    files = channel_files(json.loads(data), cid, {b['exe_sha256'] for b in entry['builds']})
    on = {b['exe_sha256'] for b in entry['builds'] if b['enabled']}
    return {p: e for p, e in files.items() if 'build' not in e or e['build'] in on}


def write_marker(folder, marker):
    """<id>/channel-build.json: the build of the game copy (removed when the copy is missing or unlisted)."""
    path = folder / CHANNEL_BUILD
    if marker is None:
        path.unlink(missing_ok=True)
    elif load_json(path, {}) != marker:
        path.write_text(json.dumps(marker, indent=1, sort_keys=True), encoding='utf-8')


def sync_channel(net, latest, root, cid, entry):
    """Bring one opted-in channel folder to its signed files: common + every switched-on build.

    Returns 'paused' / 'same' / 'installed'; the copy's build is reported, it never blocks the files."""
    folder = root / cid
    title = entry.get('title') or cid
    if not entry['enabled']:
        log(' INFO ', f'Channel {title} is paused by the release' + (f': {entry["message"]}' if entry.get('message') else '')
                      + '; the co-op starts 0.95.0. Nothing in its folder was changed.')
        return 'paused'
    build, _ = copy_build(folder, entry)
    if not (folder / EXE).is_file():
        log(' WARN ', f'Channel {title}: {cid}/{EXE} is missing. Copy your own game with the launcher\'s '
                      '"Co-op channel" setup (supported: ' + (", ".join(supported(entry)) or "none at the moment") + ').')
    elif build is None:
        log(' WARN ', f'Channel {title}: the game copy in {cid} is not a supported version (supported: '
                      f'{", ".join(supported(entry)) or "none at the moment"}). Update your game and copy it again with '
                      'the launcher\'s "Co-op channel" setup.')
    elif not build['enabled']:
        log(' INFO ', f'Channel {title}: game {build["version"]} is paused by the release'
                      + (f': {build["message"]}' if build.get('message') else '') + '; the co-op starts 0.95.0.')
    started = step(f'Read the {cid} file list')
    files = channel_target(net, entry, cid)
    unknown = sorted({e['source']['archive'] for e in files.values()} - set(entry['archives']))
    if unknown:
        raise Refused(f'The {cid} file list needs an archive the release does not list ({unknown[0]}). '
                      'Nothing was changed.')
    target = {p: e['sha256'] for p, e in files.items()}
    builds = ', '.join(supported(entry)) or 'none'
    done(f'Read the {cid} file list', started, f'{len(files)} files for game {builds}')
    started = step(f'Compare the {cid} folder')
    needed, delete = plan(folder, target, files, runtime_free=True, manifest=CHANNEL_MANIFEST)
    done(f'Compare the {cid} folder', started, f'{len(needed)} files to download, {len(delete)} to delete')
    marker = (dict(version=build['version'], exe_sha256=build['exe_sha256'], sequence=latest['sequence'])
              if build is not None else None)
    if not needed and not delete:
        if load_json(folder / CHANNEL_MANIFEST, {}) != target:
            (folder / CHANNEL_MANIFEST).write_text(json.dumps(target, indent=1, sort_keys=True), encoding='utf-8')
        write_marker(folder, marker)
        log('  OK  ', f'Channel {title} (game {builds}): nothing to do')
        return 'same'
    # Everything is downloaded and checked before the folder is touched; install() keeps a backup and rolls back.
    staged = BASE_FETCH(net, dict(archives=entry['archives']), files, needed, root / 'coop-update' / f'channel-{cid}')
    BASE_ENSURE_CLOSED(root)
    backup = BASE_INSTALL(folder, staged, target, delete, f'{cid} {builds}', manifest=CHANNEL_MANIFEST)
    write_marker(folder, marker)
    shutil.rmtree(root / 'coop-update' / f'channel-{cid}' / 'files', ignore_errors=True)
    log('  OK  ', f'Channel {title} (game {builds}): {len(needed)} files installed, {len(delete)} removed; '
                  f'backup in {cid}/{backup.name}')
    return 'installed'


def sync_channels(net, latest, root):
    """After the default update: the channel switch for the launcher and every opted-in channel folder.

    Never fails the default update: a channel problem is reported and leaves only its own folder as it was."""
    entries = channel_entries(latest)
    write_channel_state(root, latest, entries)
    results = {}
    for cid, entry in sorted(entries.items()):
        if not (root / cid).is_dir():
            continue  # Not opted in: nothing of the channel is written.
        try:
            results[cid] = sync_channel(net, latest, root, cid, entry)
        except (Refused, OSError, ValueError, zipfile.BadZipFile) as error:
            log('FAILED', f'Channel {entry.get("title") or cid}: {error} The 0.95.0 co-op is not affected.')
            results[cid] = 'failed'
    return results


def validate_files(manifest, net):
    """The signed file list: safe paths, hashes, sizes and HTTPS sources; external hosts become allowed."""
    files = manifest.get('files') if isinstance(manifest, dict) else None
    if not isinstance(files, dict):
        raise Refused('manifest has no file list. Nothing was changed.')
    for p, entry in files.items():
        if not safe_path(p):
            raise Refused(f'manifest lists an unsafe path ({p!r}). Nothing was changed.')
        source = entry.get('source') if isinstance(entry, dict) else None
        if (not isinstance(source, dict) or type(entry.get('size')) is not int or entry['size'] < 0
                or not isinstance(entry.get('sha256'), str) or len(entry['sha256']) != 64):
            raise Refused(f'manifest has an invalid entry for {p}. Nothing was changed.')
        if 'url' in source:
            if not isinstance(source['url'], str):
                raise Refused(f'manifest has an invalid source for {p}. Nothing was changed.')
            net.check_scheme(source['url'])
            net.allow(source['url'])
    return files


def copy_runtime(root, target):
    """Copy .coop-runtime so the updater can run from the copy while it replaces the original."""
    started = step('Copy the co-op Python runtime')
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(root / '.coop-runtime', target)
    count = sum(1 for p in target.rglob('*') if p.is_file())
    size = sum(p.stat().st_size for p in target.rglob('*') if p.is_file())
    done('Copy the co-op Python runtime', started, f'{count} files, {size / 2**20:.1f} MiB')


def accept(root, latest, key):
    """Remember the accepted release (replay protection) and announced key changes."""
    (root / STATE).write_text(json.dumps(dict(sequence=latest['sequence'], signed_at=latest['signed_at'],
                                              version=latest['version'], key=key), indent=1), encoding='utf-8')
    keys = latest.get('keys') or {}
    if keys.get('add') or keys.get('retire'):
        store = load_json(root / TRUST, {'added': [], 'retired': []})
        for k in keys.get('add', []):
            if k not in store['added']:
                store['added'].append(k)
        for k in keys.get('retire', []):
            if k not in store['retired'] and k != key:  # Never retire the key that signed this release.
                store['retired'].append(k)
        (root / TRUST).write_text(json.dumps(store, indent=1), encoding='utf-8')
        log(' INFO ', f'Release keys updated: {len(store["added"])} added, {len(store["retired"])} retired')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Offline as error:
        log('FAILED', f'{error}. Check your internet connection and try again. Nothing was changed.')
        sys.exit(4)
    except Refused as error:
        log('FAILED', str(error))
        sys.exit(2)
    except Exception as error:
        log('FAILED', f'{type(error).__name__}: {error}')
        sys.exit(1)
