"""The co-op engines: Native (DLL, in the game process; the default) and Classic (0.95.0, the Python line; always the fallback).

Native runs on a copy of the player's OWN game: found on this PC, checked against the signed list of supported builds, copied into
<root>/native/. Multi-build by design: a new game build is a new profile in the signed release, never a new launcher. Pure Python, no
GUI (the room browser's Engine panel calls it). Never bundles or uploads game files, never writes into the player's game folder.
Layout under the launcher install `root`:

    <root>/native/                     avrt.dll, azcoop-net.exe (the updater) + the copied game (here)
    <root>/native/reconstruction/      reviewed-hooks.json + one DLL profile per supported build (release-<hash8>.json); the DLL picks
                                       the profile of the exe it runs in
    <root>/coop-lab/coop-engine.txt    the player's choice: native (default; absent or unreadable = native) or classic
    <root>/coop-lab/engine-last.json   what the last start used and why (channel_start writes it)
    <root>/coop-update/channels.json   written by the updater from the signed release: {"native": {"schema", "enabled", "message",
                                       "title", "sequence", "build", "supported", "builds": [{version, exe_sha256, exe_size, enabled}],
                                       "rollout": {"percent", "included"}}}

Native is usable only if the entry exists, is enabled, the rollout includes this install and the copy's build is listed and enabled;
without channels.json (a fresh folder before its first update) the co-op starts Classic. Leftover <root>/dll-0.99.0 and <root>/dll-beta
folders (earlier test layouts) are ignored, never deleted. Refusals raise `Refused` with a player text (English, ASCII) and a code.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

CHANNEL = 'native'
NATIVE, CLASSIC = 'native', 'classic'
ENGINES = (NATIVE, CLASSIC)
DEFAULT_ENGINE = NATIVE
EXE = 'AzerothSurvivors.exe'
DLL_FILES = ('avrt.dll', 'azcoop-net.exe')
SPARE = 200 * 1024 * 1024
NEW_VERSION_NOTE = 'A new game version usually needs a few days before the Native engine supports it.'
CLASSIC_NOTE = 'Classic is used for this start.'
# the reason codes of a native start that falls back to Classic (the Engine panel derives its fix action from the code)
CODES = ('not_found', 'unsupported_build', 'no_space', 'copy_failed', 'payload_missing', 'paused', 'rollout_off', 'start_failed')


class Refused(Exception):
    def __init__(self, code, text):
        super().__init__(text)
        self.code, self.text = code, text


def channel_folder(root):
    return Path(root) / CHANNEL


_hashes = {}  # (path, size, mtime_ns) -> sha256: a status call asks several times, the exe is 130 MB


def _sha256(path):
    st = os.stat(path)
    key = (str(Path(path).resolve()), st.st_size, st.st_mtime_ns)
    if key in _hashes:
        return _hashes[key]
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8 << 20):
            h.update(chunk)
    _hashes[key] = h.hexdigest()
    return _hashes[key]


# ---- the server's entry ----------------------------------------------------------------------------------------------

def _entry_json(root):
    try:
        data = json.loads((Path(root) / 'coop-update' / 'channels.json').read_text(encoding='utf-8'))
        entry = data.get(CHANNEL) if isinstance(data, dict) else None
        return entry if isinstance(entry, dict) else None
    except (OSError, ValueError):
        return None


def _version_key(version):
    return tuple(int(x) for x in re.findall(r'\d+', str(version))) or (0,)


def builds(root):
    """Every build row of the signed list (enabled or not), newest first; none without channels.json."""
    entry = _entry_json(root)
    rows = entry.get('builds') if entry is not None and isinstance(entry.get('builds'), list) else []
    out = []
    for row in rows:
        if isinstance(row, dict) and re.fullmatch(r'[0-9a-f]{64}', str(row.get('exe_sha256', '')).lower()) and row.get('version'):
            out.append(dict(version=str(row['version']), exe_sha256=row['exe_sha256'].lower(), exe_size=row.get('exe_size'),
                            enabled=row.get('enabled', True) is not False))
    return sorted(out, key=lambda r: _version_key(r['version']), reverse=True)


def supported(root):
    """The enabled builds, newest first."""
    return [b for b in builds(root) if b['enabled']]


def supported_text(root):
    versions = [b['version'] for b in supported(root)]
    return ', '.join(versions) if versions else 'none at the moment'


def build_of(root, sha):
    sha = (sha or '').lower()
    return next((b for b in supported(root) if b['exe_sha256'] == sha), None)


def server_flags(root):
    """known (a signed entry exists), enabled, message, rollout_included."""
    entry = _entry_json(root)
    if entry is None:
        return dict(known=False, enabled=False, message=None, rollout_included=False)
    rollout = entry.get('rollout') if isinstance(entry.get('rollout'), dict) else {}
    return dict(known=True, enabled=entry.get('enabled', True) is not False,
                message=entry.get('message') if isinstance(entry.get('message'), str) else None,
                rollout_included=rollout.get('included', False) is True)


def enabled_by_server(root):
    return server_flags(root)['enabled']


# ---- profiles and versions -----------------------------------------------------------------------------------------------

def payload_profile(root, sha):
    """The installed, verified DLL profile of this build (reconstruction/release-<hash8>.json naming exactly this exe), or None."""
    sha = (sha or '').lower()
    path = channel_folder(root) / 'reconstruction' / f'release-{sha[:8]}.json'
    try:
        release = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    adapter = release.get('adapter_profile') or {}
    if isinstance(release.get('variant_constants'), dict) and adapter.get('adapter_contracts_verified') is True and \
            str(adapter.get('sha256', '')).lower() == sha:
        return path
    return None


def known_versions(root):
    """exe hash -> version: the signed list, the launcher's table and 0.95.0; the lobby labels rooms with it."""
    table = {}
    try:
        import launcher_profile
        table.update({sha: version for sha, version in getattr(launcher_profile, 'KNOWN_VERSIONS', {}).items()})
    except Exception:
        pass
    table.setdefault('7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30', '0.95.0')
    for row in builds(root):
        table[row['exe_sha256']] = row['version']
    return table


def exe_version(exe):
    """The version text the game carries before "update: up to date" ("0.99.0update: up to date"), or None."""
    try:
        data = Path(exe).read_bytes()
    except OSError:
        return None
    found = re.search(rb'(\d+\.\d+\.\d+)[\x00-\x1f]?update: up to date', data)  # 0.99.0: a 0x1e separator in between
    return found.group(1).decode('ascii') if found else None


def version_of(root, sha, exe=None):
    return known_versions(root).get(sha) or (exe_version(exe) if exe else None) or 'unknown'


def unsupported_text(root, version, build, where=''):
    return f'Your game{where} is version {version} (build {build}). The Native engine supports {supported_text(root)}. {NEW_VERSION_NOTE}'


def game_running():
    try:
        done = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {EXE}', '/FO', 'CSV', '/NH'], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=15)
        return EXE.lower() in (done.stdout or b'').decode('utf-8', 'replace').lower()
    except (OSError, subprocess.SubprocessError):
        return False


# ---- the player's engine choice and the last start ---------------------------------------------------------------------------

def engine(root):
    """The remembered choice: native or classic; absent or unreadable = native."""
    try:
        word = (Path(root) / 'coop-lab' / 'coop-engine.txt').read_text(encoding='utf-8').split()[0].strip().lower()
    except (OSError, UnicodeError, IndexError):
        return DEFAULT_ENGINE
    return word if word in ENGINES else DEFAULT_ENGINE


def set_engine(root, choice, coop_running=False):
    if choice not in ENGINES:
        raise Refused('not_ready', f'Unknown engine {choice!r}.')
    if coop_running or game_running():
        raise Refused('running', 'Close the game and leave the co-op round first.')
    before = engine(root)
    path = Path(root) / 'coop-lab' / 'coop-engine.txt'
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(choice + '\n', encoding='utf-8')
    os.replace(temporary, path)
    return dict(changed=before != choice, engine=choice)


def last_start(root):
    try:
        data = json.loads((Path(root) / 'coop-lab' / 'engine-last.json').read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def write_last(root, chosen, used, code=None, text=None):
    """coop-lab/engine-last.json: {chosen, engine, code, text, supported, time} (written at every start by channel_start)."""
    data = dict(chosen=chosen, engine=used, code=code, text=text, supported=[b['version'] for b in supported(root)], time=int(time.time()))
    path = Path(root) / 'coop-lab' / 'engine-last.json'
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(data, ensure_ascii=True) + '\n', encoding='utf-8')
        os.replace(temporary, path)
    except OSError:
        pass
    return data


# ---- the copy in the native folder -------------------------------------------------------------------------------------------

def _dll_files_ok(folder):
    for name in DLL_FILES:
        try:
            with open(folder / name, 'rb') as f:
                f.read(2)
        except OSError:
            return False
    return True


def copy_build(root):
    """(sha256, version, supported row or None) of the game copy in the native folder, or None without a complete copy."""
    folder = channel_folder(root)
    exe = folder / EXE
    if not exe.is_file() or not (folder / 'Data').is_dir():
        return None
    sha = _sha256(exe)
    return sha, version_of(root, sha, exe), build_of(root, sha)


def expected(root, for_copy=False):
    """(sha256, version) the engine starts: the copy's build if supported; without one (for_copy) the newest supported build."""
    copy = copy_build(root)
    if copy and copy[2]:
        return copy[0], copy[2]['version']
    if for_copy:
        newest = supported(root)
        return (newest[0]['exe_sha256'], newest[0]['version']) if newest else None
    return None


def missing(root):
    """'game' (no copy, or a copy of a build that is not supported: copy again), 'payload' (the DLL files or the copy's verified
    profile are not installed yet: the updater installs them at the next Start-Coop), or None."""
    copy = copy_build(root)
    if not copy or not copy[2]:
        return 'game'
    if not payload_profile(root, copy[0]) or not _dll_files_ok(channel_folder(root)):
        return 'payload'
    return None


def ready(root):
    return missing(root) is None


def newer_available(root):
    """A located game of a newer supported build than the copy (the panel offers "copy again"), or None."""
    copy = copy_build(root)
    if not copy or not copy[2]:
        return None
    mine = _version_key(copy[2]['version'])
    better = [e for e in locate(root) if e['sha256_ok'] and _version_key(e['version']) > mine]
    return better[0] if better else None


def channel_status(root, coop_running=False):
    flags, copy, newest = server_flags(root), copy_build(root), supported(root)
    needs = missing(root)
    target = (copy[0], copy[2]['version']) if copy and copy[2] else ((newest[0]['exe_sha256'], newest[0]['version']) if newest else ('', ''))
    return dict(engine=engine(root), last=last_start(root), rollout_included=flags['rollout_included'], known=flags['known'],
                ready=needs is None, missing=needs, enabled_by_server=flags['enabled'], message=flags['message'],
                game_running=game_running(), coop_running=bool(coop_running), folder=str(channel_folder(root)),
                version=target[1], build=target[0][:8], supported=[b['version'] for b in newest],
                copy_version=copy[1] if copy else None, copy_build=copy[0][:8] if copy else None, copy_supported=bool(copy and copy[2]))


# ---- finding the player's game -------------------------------------------------------------------------------------------

def _entry(root, folder, source):
    folder = Path(folder)
    exe = folder / EXE
    if not exe.is_file() or not (folder / 'Data').is_dir():
        return None
    sha = _sha256(exe)
    row = build_of(root, sha)
    size = sum(p.stat().st_size for p in (folder / 'Data').rglob('*') if p.is_file()) + exe.stat().st_size
    return dict(path=str(folder), version=row['version'] if row else version_of(root, sha, exe), build=sha[:8], sha256=sha,
                sha256_ok=row is not None, size=size, source=source)


def _steam_libraries():
    roots = []
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Valve\Steam') as key:
            roots.append(Path(winreg.QueryValueEx(key, 'SteamPath')[0]))
    except OSError:
        pass
    for base in list(roots):
        vdf = base / 'steamapps' / 'libraryfolders.vdf'
        try:
            roots += [Path(p.replace('\\\\', '\\')) for p in re.findall(r'"path"\s+"([^"]+)"', vdf.read_text(encoding='utf-8', errors='replace'))]
        except OSError:
            pass
    return [r / 'steamapps' / 'common' for r in dict.fromkeys(roots)]


def _candidates(root):
    """(folder, source) to look at: the folder the launcher remembers, Steam libraries, default paths."""
    out = []
    try:
        known = (Path(root) / 'coop-lab' / 'game-folder.txt').read_text(encoding='utf-8').strip()
        if known:
            out.append((Path(known), 'known'))
    except OSError:
        pass
    for common in _steam_libraries():
        try:
            out += [(d, 'steam') for d in common.iterdir() if (d / EXE).is_file()]
        except OSError:
            pass
    drives = [f'{c}:\\' for c in 'CDEFG' if os.path.isdir(f'{c}:\\')]
    names = ('AzerothSurvivors', 'Azeroth Survivors', 'Games\\AzerothSurvivors', 'Games\\Azeroth Survivors')
    out += [(Path(d) / n, 'default') for d in drives for n in names]
    for env in ('LOCALAPPDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)'):
        if os.environ.get(env):
            out += [(Path(os.environ[env]) / n, 'default') for n in ('AzerothSurvivors', 'Azeroth Survivors')]
    return out


def locate(root):
    """Every folder with a game found on this PC (unsupported builds too, sha256_ok False), supported and newest first. Read only."""
    seen, found = set(), []
    install = Path(root).resolve()  # never a game inside the co-op folder: the native copy, copies of earlier test layouts
    for folder, source in _candidates(root):
        try:
            key = folder.resolve()
        except OSError:
            continue
        if key in seen or key == install or install in key.parents:
            continue
        seen.add(key)
        entry = _entry(root, folder, source)
        if entry:
            found.append(entry)
    return sorted(found, key=lambda e: (not e['sha256_ok'], tuple(-x for x in _version_key(e['version']))))


def locate_folder(root, path):
    folder = Path(str(path).strip().strip('"'))
    entry = _entry(root, folder, 'picked') if folder.is_dir() else None
    if entry is None:
        raise Refused('not_found', f'No {EXE} with a Data folder in {folder}. Choose the folder of your Azeroth Survivors game.')
    return entry


# ---- copy (one background copy per root) ---------------------------------------------------------------------------

_copies = {}
_lock = threading.Lock()


def copy_progress(root):
    with _lock:
        job = _copies.get(str(Path(root).resolve()))
        return dict(job['progress']) if job else dict(state='idle', bytes=0, total=0, eta_s=None, reason='')


def copy_cancel(root):
    with _lock:
        job = _copies.get(str(Path(root).resolve()))
        if job:
            job['cancel'].set()
    return copy_progress(root)


def copy_start(root, path, coop_running=False):
    entry = locate_folder(root, path)
    if not entry['sha256_ok']:
        raise Refused('unsupported_build', unsupported_text(root, entry['version'], entry['build'], f' in {entry["path"]}') + ' Nothing was copied.')
    folder = channel_folder(root)
    source = Path(entry['path']).resolve()
    if source == folder.resolve():
        raise Refused('in_use', 'That is the co-op engine folder itself. Choose the folder of your own game.')
    if coop_running or game_running():
        raise Refused('running', 'Close the game and leave the co-op round first.')
    folder.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(folder).free < entry['size'] + SPARE:
        raise Refused('no_space', f'Not enough free space: {entry["size"] / 1e9:.1f} GB needed in {folder}.')
    key = str(Path(root).resolve())
    with _lock:
        if key in _copies and _copies[key]['progress']['state'] in ('copying', 'verifying'):
            return dict(_copies[key]['progress'])
        job = dict(progress=dict(state='copying', bytes=0, total=entry['size'], eta_s=None, reason=''), cancel=threading.Event())
        _copies[key] = job
    threading.Thread(target=_copy, args=(job, source, folder, entry['sha256']), daemon=True, name='engine-copy').start()
    return copy_progress(root)


def _copy(job, source, folder, sha):
    progress, started, done, parts = job['progress'], time.monotonic(), 0, []
    try:
        files = [source / EXE] + sorted(p for p in (source / 'Data').rglob('*') if p.is_file())
        for path in files:
            target = folder / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            part = target.with_name(target.name + '.part')
            parts.append(part)
            with open(path, 'rb') as src, open(part, 'wb') as dst:
                while chunk := src.read(8 << 20):
                    if job['cancel'].is_set():
                        raise InterruptedError
                    dst.write(chunk)
                    done += len(chunk)
                    rate = done / max(time.monotonic() - started, 0.1)
                    with _lock:
                        progress.update(bytes=done, eta_s=round((progress['total'] - done) / max(rate, 1)))
            os.replace(part, target)
        with _lock:
            progress.update(state='verifying')
        if _sha256(folder / EXE) != sha:
            raise Refused('copy_failed', 'The copied game differs from your game. Copy again.')
        for path in files[1:]:
            if (folder / path.relative_to(source)).stat().st_size != path.stat().st_size:
                raise Refused('copy_failed', f'The copy of {path.name} is incomplete. Copy again.')
        with _lock:
            progress.update(state='done', eta_s=0)
        try:
            (folder.parent / 'coop-lab').mkdir(exist_ok=True)
            (folder.parent / 'coop-lab' / 'game-folder.txt').write_text(str(source), encoding='utf-8')
        except OSError:
            pass
    except InterruptedError:
        with _lock:
            progress.update(state='cancelled', reason='Copy cancelled.')
    except Refused as refused:
        with _lock:
            progress.update(state='failed', reason=refused.text)
    except OSError as error:
        with _lock:
            progress.update(state='failed', reason=f'Copy failed: {error.strerror or error}. Your game folder was not changed.')
    finally:
        for part in parts:
            try:
                part.unlink()
            except OSError:
                pass


# ---- the native start pipeline (channel_start calls it at every native start) ------------------------------------------------

def _copy_now(root, entry, say):
    """The copy in the foreground of a start, a progress line per second; Refused(no_space / copy_failed) on failure."""
    copy_start(root, entry['path'])
    last = 0.0
    while True:
        p = copy_progress(root)
        if p['state'] not in ('copying', 'verifying'):
            break
        if time.monotonic() - last >= 1:
            last = time.monotonic()
            pct = int(100 * p['bytes'] / max(p['total'], 1))
            say(f'{pct:3d} %', f'copying your game {entry["version"]} for the Native engine: {p["bytes"] / 1e9:.2f}/{p["total"] / 1e9:.2f} GB'
                               + (f', about {p["eta_s"]} s left' if p.get('eta_s') is not None else ''))
        time.sleep(0.2)
    if p['state'] != 'done':
        raise Refused('copy_failed', f'Copying your game for the Native engine failed: {p["reason"] or p["state"]}')


def prepare_native(root, say=lambda tag, text: None):
    """Everything a native start needs, in order; returns None when Native can start, else Refused(code, player text). Copies the
    player's game when there is no supported copy yet (with progress), never touches the player's game folder."""
    flags = server_flags(root)
    if not flags['known']:
        raise Refused('rollout_off', 'The Native engine is not set up for this co-op folder yet (no signed release information).')
    if not flags['enabled']:
        raise Refused('paused', 'The Native engine is paused by the server.' + (f' {flags["message"]}' if flags['message'] else ''))
    if not flags['rollout_included']:
        raise Refused('rollout_off', 'The Native engine is not enabled for this install yet.')
    if 'onedrive' in str(Path(root).resolve()).lower():
        raise Refused('copy_failed', 'The co-op folder is inside OneDrive, which can hold game files offline. Move the whole co-op folder '
                                     'to a plain folder such as C:\\Games.')
    copy = copy_build(root)
    if not copy or not copy[2]:
        found = locate(root)
        usable = [e for e in found if e['sha256_ok']]
        if not usable:
            if not found:
                raise Refused('not_found', 'The co-op did not find your Azeroth Survivors game. Pick its folder in the room browser (Engine).')
            first = found[0]
            raise Refused('unsupported_build', unsupported_text(root, first['version'], first['build'], f' in {first["path"]}'))
        try:
            _copy_now(root, usable[0], say)
        except Refused as refused:
            raise Refused(refused.code if refused.code in ('no_space', 'copy_failed') else 'copy_failed', refused.text)
        copy = copy_build(root)
        if not copy or not copy[2]:
            raise Refused('copy_failed', 'The copied game is not a supported build. Copy again.')
    if not payload_profile(root, copy[0]) or not _dll_files_ok(channel_folder(root)):
        blocked = next((n for n in DLL_FILES if not (channel_folder(root) / n).is_file()), None)
        raise Refused('payload_missing', f'The Native engine files for {copy[2]["version"]} are missing or blocked'
                                         + (f' ({blocked})' if blocked else '') + f', most likely by your antivirus. Allow the folder '
                                         f'{channel_folder(root)}; the next Start-Coop.cmd restores them.')
    return None
