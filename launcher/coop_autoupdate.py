"""Automatic co-op update before the launcher starts (Start-Coop.cmd, boot-log format).

Start-Coop.cmd runs this with the co-op Python before the launcher. It only
decides; the update itself runs in Azeroth-Survivors-Together-Updater.exe after
this Python has ended, so the runtime and every file are free:

  exit 0   start the launcher (no update, offline, skipped, switched off, error)
  exit 10  run the updater exe, then the launcher

Uses the bound reconstruction/self_update.py (signed release description,
SHA-256 of the updater asset). At most about 3 s when nothing is new or the
network is slow. Switch off with COOP_AUTO_UPDATE=0 or the file
coop-update/no-auto-update. Lines also go to coop-update/update.log.

Repair (0.0.20): when this folder already has the newest version, every package
file (never player data) is compared with the SIGNED release file list; a file
that differs or is missing (for example another AzerothSurvivors.exe: the room
shows "Game Unknown") also runs the updater exe, which restores it from its
signed source with backup and rollback and reports "Game files repaired".
Hashes are kept in coop-update/integrity-cache.json by size and modification
time, so only the first check (or a changed file) reads the files.
"""
import argparse
import hashlib
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'reconstruction'))  # -I leaves the script folder out.
INSTALL = 10
UPDATER = 'Azeroth-Survivors-Together-Updater.exe'


def damaged(what, error):
    """A co-op file or the runtime is missing or damaged (quarantine, interrupted copy): the updater exe restores it
    from the signed release (Updater 6 also a damaged runtime). Without it the player gets the download hint."""
    print(f'[ WARN ] {what} is missing or damaged ({type(error).__name__}: {error}).', flush=True)
    if (ROOT / UPDATER).is_file():
        print(f'[ INFO ] Repairing with {UPDATER} ...', flush=True)
        return INSTALL
    print(f'[ INFO ] Download {UPDATER} from https://github.com/bymarvin/azeroth-survivors-together/releases/latest '
          'into this folder and run it.', flush=True)
    return 0


try:
    import self_update as su  # noqa: E402
except Exception as error:  # noqa: BLE001 - also a damaged runtime below it
    sys.exit(damaged('The co-op file reconstruction/self_update.py', error))

OFF_FILE = 'coop-update/no-auto-update'
CACHE = 'coop-update/integrity-cache.json'


def switched_off(root):
    return os.environ.get('COOP_AUTO_UPDATE', '1').strip() == '0' or (root / OFF_FILE).exists()


def enter_pressed():
    """True if the player pressed Enter (console only)."""
    try:
        import msvcrt
    except ImportError:
        return False
    while msvcrt.kbhit():
        if msvcrt.getwch() in '\r\n':
            return True
    return False


def wait_or_skip(seconds):
    """Count down; True if the player skipped with Enter."""
    end = time.monotonic() + seconds
    shown = None
    while (left := end - time.monotonic()) > 0:
        if enter_pressed():
            return True
        if shown != int(left) + 1:
            shown = int(left) + 1
            print(f'[ INFO ] Update starts in {shown} s (Enter = skip)', flush=True)
        time.sleep(.05)
    return enter_pressed()


def read_release(root, args, builtin):
    """(latest, status) or None within the time limit; never raises."""
    result = {}

    def ask():
        try:
            net = su.Net(args.release_url, timeout=args.timeout, allow_local_http=args.allow_local_http)
            latest, _, _ = su.read_latest(net, root, builtin)
            result['value'] = latest, su.compare(root, latest), net
        except su.Offline as error:
            result['error'] = f'offline ({error})'
        except ImportError as error:  # The runtime lost a package or DLL (the signature check needs it).
            result['error'] = f'{type(error).__name__}: {error}'
            result['damaged'] = error
        except Exception as error:  # Refused, damaged files: start as usual.
            result['error'] = f'{type(error).__name__}: {error}'
    worker = threading.Thread(target=ask, daemon=True)
    worker.start()
    worker.join(args.timeout)
    if worker.is_alive():
        return None, f'no answer within {args.timeout:.0f} s'
    if 'damaged' in result:
        raise result['damaged']
    return result.get('value'), result.get('error')


def ensure_updater(net, latest, root):
    """The updater exe ships with the package (from 0.0.13); only a missing one is downloaded (signed asset).

    An older exe in the folder updates itself (min_updater / its own new version after the install).
    """
    entry, exe = latest['updater'], root / su.UPDATER_ASSET
    if exe.is_file():
        return 'present'
    temporary = exe.with_name(exe.name + '.download')
    net.download(net.url(entry['asset']), temporary, entry['size'], entry['sha256'])
    os.replace(temporary, exe)
    return 'downloaded'


def signed_target(net, latest):
    """{path: sha256} of every package file of the signed release (player data left out)."""
    entry = latest['manifest']
    data = net.fetch(net.url(entry['asset']), min(entry['size'], su.MANIFEST_LIMIT))
    if len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise su.Refused('the release file list does not match its signed SHA-256')
    files = json.loads(data)['files']
    return {p: e['sha256'] for p, e in files.items() if su.safe_path(p) and not su.user_area(p)}


def differing(root, target):
    """(paths that differ from the signed release or are missing, files hashed now); hashes cached by size and mtime."""
    cache = su.load_json(root / CACHE, {})
    known, todo = {}, []
    for path in target:
        try:
            stat = (root / path).stat()
        except OSError:
            continue  # Missing: differs.
        key = [stat.st_size, stat.st_mtime_ns]
        hit = cache.get(path)
        if isinstance(hit, list) and hit[:2] == key:
            known[path] = hit
        else:
            todo.append((path, key))

    def digest(item):
        try:
            return su.sha256(root / item[0])
        except OSError:
            return None  # Locked or unreadable: neither cached nor called damaged.
    if todo:
        with ThreadPoolExecutor(su.threads()) as pool:
            for (path, key), value in zip(todo, pool.map(digest, todo)):
                if value is not None:
                    known[path] = key + [value]
    try:
        temporary = root / (CACHE + '.part')
        temporary.write_text(json.dumps(known), encoding='utf-8')
        os.replace(temporary, root / CACHE)
    except OSError:
        pass  # Only speed: the next check hashes again.
    unreadable = {path for path, _ in todo if path not in known and (root / path).exists()}
    wrong = sorted(p for p in target if p not in unreadable and (p not in known or known[p][2] != target[p]))
    return wrong, len(todo)


HEALS = 'coop-update/channel-heal.json'
MAX_HEALS = 2  # Restores of one channel per day: an antivirus that removes avrt.dll again gets a clear message, no loop.


def channel_targets(net, root, latest):
    """{id: {"<id>/<path>": sha256}} of the opted-in, switched-on channels: common + switched-on builds (signed)."""
    out = {}
    for cid, entry in su.channel_entries(latest).items():
        folder = root / cid
        if not folder.is_dir() or not entry['enabled']:
            continue  # Not opted in or paused: nothing to restore here.
        out[cid] = {f'{cid}/{path}': e['sha256'] for path, e in su.channel_target(net, entry, cid).items()}
    return out


def allow_heal(root, cid, wrong):
    """True when this channel may be restored again today; counts the restore."""
    heals = su.load_json(root / HEALS, {})
    today = time.strftime('%Y-%m-%d')
    entry = heals.get(cid) if isinstance(heals.get(cid), dict) else {}
    count = entry.get('count', 0) if entry.get('day') == today else 0
    if count >= MAX_HEALS:
        su.log(' WARN ', f'{cid}: {", ".join(wrong[:2])} went missing again after {count} repairs today. Security '
                         f'software is probably removing it: allow the folder {root / cid} in it, then start again. '
                         'The 0.95.0 co-op starts as usual.')
        return False
    heals[cid] = dict(day=today, count=count + 1, files=wrong[:5])
    try:
        (root / HEALS).write_text(json.dumps(heals, indent=1), encoding='utf-8')
    except OSError:
        pass
    return True


def main(argv=None, builtin=su.TRUSTED_KEYS):
    ap = argparse.ArgumentParser(description='Automatic co-op update check (Start-Coop.cmd)')
    ap.add_argument('--release-url', default=su.RELEASE_URL)
    ap.add_argument('--timeout', type=float, default=3.0)
    ap.add_argument('--countdown', type=float, default=5.0)
    ap.add_argument('--allow-local-http', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--extra-trusted-key', action='append', default=[], help=argparse.SUPPRESS)
    ap.add_argument('--game', type=Path, default=ROOT, help=argparse.SUPPRESS)
    args, _ = ap.parse_known_args(argv)  # Start-Coop passes the same diagnostic options to the updater exe.
    builtin = (*builtin, *args.extra_trusted_key)
    root = args.game
    try:
        (root / 'coop-update').mkdir(exist_ok=True)
        su.LOG = (root / 'coop-update' / 'update.log').open('a', encoding='utf-8')
    except OSError:
        su.LOG = None
    if switched_off(root):
        su.log(' INFO ', f'Automatic update is switched off (COOP_AUTO_UPDATE=0 or {OFF_FILE})')
        return 0
    started = su.step('Look for a co-op update')
    try:
        found, problem = read_release(root, args, builtin)
    except ImportError as error:
        su.done('Look for a co-op update', started, 'not possible: the co-op Python runtime is damaged')
        return damaged('A part of the co-op Python runtime', error)
    if found is None:
        su.done('Look for a co-op update', started, f'{problem}; starting as usual')
        return 0
    latest, status, net = found
    installed = su.installed_version(root)
    try:
        # The server's channel switch (0.0.24) for the launcher, from this verified release; offline it stays as it was.
        su.write_channel_state(root, latest, su.channel_entries(latest))
    except OSError as error:
        su.log(' WARN ', f'Could not write {su.CHANNELS_STATE} ({error})')
    if status != 'newer':
        su.done('Look for a co-op update', started, f'co-op {installed} is current')
        started = su.step('Check the game files against the signed release')
        try:
            target = signed_target(net, latest)
            try:
                channels = channel_targets(net, root, latest)
            except Exception as error:  # A channel problem never blocks the 0.95.0 check.
                su.log(' WARN ', f'Channel files not checked ({type(error).__name__}: {error})')
                channels = {}
            wrong, hashed = differing(root, {**target, **{p: d for files in channels.values() for p, d in files.items()}})
        except Exception as error:  # Network, damaged list: start as usual.
            su.done('Check the game files against the signed release', started,
                    f'not possible ({type(error).__name__}: {error}); starting as usual')
            return 0
        su.done('Check the game files against the signed release', started,
                f'{len(target) + sum(map(len, channels.values()))} files, {hashed} read, {len(wrong)} differ')
        for cid, files in channels.items():
            own = [p for p in wrong if p in files]
            if own and not allow_heal(root, cid, own):
                wrong = [p for p in wrong if p not in files]
        if not wrong:
            return 0
        su.log(' WARN ', f'{len(wrong)} game files differ from co-op {installed} (for example '
                         f'{", ".join(wrong[:3])}): they are repaired from the signed release (Enter = skip)')
    else:
        su.done('Look for a co-op update', started, f'co-op {latest["version"]} is available')
        su.log(' INFO ', f'Update {installed} -> {latest["version"]} will be installed... (Enter = skip)')
    if wait_or_skip(args.countdown):
        su.log(' INFO ', ('Update' if status == 'newer' else 'Repair') + ' skipped; starting the installed version')
        return 0
    started = su.step('Prepare the updater')
    try:
        how = ensure_updater(net, latest, root)
    except Exception as error:
        su.log('FAILED', f'Prepare the updater: {error}. Starting the installed version.')
        return 0
    su.done('Prepare the updater', started, f'{su.UPDATER_ASSET} {how}')
    return INSTALL


if __name__ == '__main__':
    try:
        sys.exit(main())
    except ImportError as error:  # A damaged runtime: repair instead of a launcher that fails later.
        sys.exit(damaged('A part of the co-op Python runtime', error))
    except Exception as error:  # Never block the launcher.
        print(f'[FAILED] Automatic update: {type(error).__name__}: {error}. Starting the installed version.', flush=True)
        sys.exit(0)
