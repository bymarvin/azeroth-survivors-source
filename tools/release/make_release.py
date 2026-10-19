"""Build the upload folder of one self-updater release (boot-log format).

  make_release.py --target <staged package folder> [--game-sources game-sources.json]
                  --updater-exe <built updater exe> [--updater-version N] [--min-updater N]
                  [--sequence N] [--announce-key KEY] [--retire-key KEY] [--key-dir DIR] [--out DIR]
                  [--full-package-url URL] [--no-check-urls] [--installer-exe EXE] [--publish | --publish-dry-run]

Output (upload everything except UPLOAD.txt as assets of ONE GitHub release):
  latest.json, latest.json.sig     signed release description (fixed names)
  manifest-<version>.json          every file with SHA-256, size and source
  mod-<version>.zip                mod files (reconstruction, analysis, relay, launcher)
  runtime-<version>.zip            .coop-runtime and .tools (normally never downloaded)
  Azeroth-Survivors-Together-Updater.exe
  Azeroth-Survivors-Together-Installer.exe   (with --installer-exe; must embed the signing key)
Game files (AzerothSurvivors.exe, Data/*) are never put on GitHub: their HTTPS
address comes from game-sources.json ({"<path>": "https://..."}) and their
SHA-256 from the staged package; UPLOAD.txt lists what must be reachable there.
A game file without an address (no direct host) gets the release page on
GitHub as its source (UNHOSTED). Folders that already have the file (same game
version) never download it. For a folder of another game version that address
answers with a web page at once, so the updater stops before downloading or
installing anything and shows the signed --full-package-url (works with the
bound self_update.py, no client change).
Every game file address is probed (first KiB via HTTP Range): it must deliver the
file itself with the signed size, not a web page. Hosts with a download page or
captcha in between (storage.to, uploadex and similar) cannot work; players then
get the signed --full-package-url instead and nothing is installed halfway.
"""
import os
import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'reconstruction'), str(ROOT / 'coop-lab/updater')]
import self_update  # noqa: E402
import sign_release  # noqa: E402


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def kind(path):
    if path == self_update.EXE or path.startswith('Data/'):
        return 'game'
    if path.startswith(('.coop-runtime/', '.tools/')):
        return 'runtime'
    return 'mod'


UNHOSTED = self_update.RELEASE_URL.split('/releases/')[0] + '/releases'  # Always a page, never the file.
INSTALLER_ASSET = 'Azeroth-Survivors-Together-Installer.exe'


def asset(path):
    return dict(asset=path.name, sha256=sha256(path), size=path.stat().st_size)


def probe(net, url, size):
    """None if the address delivers the file directly (size matches), else the reason."""
    try:
        request = urllib.request.Request(url, headers={'Range': 'bytes=0-1023'})
        with net.open(request) as response:
            kind = (response.headers.get('Content-Type') or '').lower()
            head = response.read(1024)
            total = response.headers.get('Content-Range', '').rpartition('/')[2]
            length = int(total) if total.isdigit() else int(response.headers.get('Content-Length') or -1)
    except urllib.error.HTTPError as error:
        return f'answers {error.code}'
    except (self_update.Refused, OSError, ValueError) as error:
        return str(error)
    if kind.startswith(('text/html', 'application/xhtml')) or head.lstrip()[:15].lower().startswith(
            (b'<!doctype html', b'<html')):
        return 'answers with a web page (download page or captcha), not the file'
    if response.status == 206 and length != size:
        return f'delivers {length} bytes, the file has {size}'
    if response.status == 200 and length not in (-1, size):
        return f'delivers {length} bytes, the file has {size}'
    return None


def build_channel(args, out, tag):
    """The signed entry of one channel (schema 1): its build list, file list and archive (reproducible), the switches.

    Common files come from --channel-common (or the older --channel-target); each --channel-build folder holds a
    build.json {version, exe_sha256, exe_size} and that build's files (tagged with its exe SHA-256 in the list).
    The older single-build form (--channel-game-version + --channel-game-exe) is one build without own files."""
    cid = args.channel_id
    if not self_update.CHANNEL_ID.fullmatch(cid):
        raise ValueError(f'unzulässige Kanal-ID {cid!r}')
    if not args.channel_title:
        raise ValueError('--channel-title ist nötig')
    builds, sources = [], []  # sources: (folder, exe_sha256 or None for common files)
    common = args.channel_common or args.channel_target
    if common:
        sources.append((common, None))
    if args.channel_game_exe:
        if not args.channel_game_version:
            raise ValueError('--channel-game-exe braucht --channel-game-version')
        builds.append(dict(version=args.channel_game_version, exe_sha256=sha256(args.channel_game_exe),
                           exe_size=args.channel_game_exe.stat().st_size, enabled=True))
    for folder in args.channel_build:
        info = json.loads((folder / 'build.json').read_text(encoding='utf-8'))
        build = dict(version=str(info['version']), exe_sha256=str(info['exe_sha256']).lower(),
                     exe_size=int(info['exe_size']), enabled=True)
        builds.append(build)
        sources.append((folder, build['exe_sha256']))
    for build in builds:
        if build['version'] in args.channel_build_disabled:
            build.update(enabled=False, message=args.channel_message)
    if not builds:
        raise ValueError('kein Build: --channel-build <Ordner> (oder --channel-game-exe) angeben')
    unknown = set(args.channel_build_disabled) - {b['version'] for b in builds}
    if unknown:
        raise ValueError(f'--channel-build-disabled nennt unbekannte Versionen: {sorted(unknown)}')
    if not 0 <= args.channel_rollout <= 100:
        raise ValueError('--channel-rollout ist ein Prozentwert 0..100')
    entry = dict(schema=self_update.CHANNEL_SCHEMA, title=args.channel_title, enabled=not args.channel_disabled,
                 message=args.channel_message if args.channel_disabled else None, builds=builds,
                 rollout=dict(percent=args.channel_rollout), files=0)
    if self_update.channel_builds(entry) is None:
        raise ValueError('Buildliste ungültig (Version, SHA-256, Größe, doppelte exe?)')
    files, members = {}, {}
    for folder, build in sources:
        if not folder.is_dir():
            raise ValueError(f'{folder} ist kein Ordner')
        for q in sorted(q for q in folder.rglob('*') if q.is_file()):
            rel = q.relative_to(folder).as_posix()
            if build is not None and rel == 'build.json':
                continue
            if (not self_update.safe_path(rel) or rel.lower() in (self_update.CHANNEL_MANIFEST, self_update.CHANNEL_BUILD)
                    or rel.lower().startswith(self_update.GAME_COPY) or self_update.user_area(rel)):
                raise ValueError(f'{rel} darf kein Kanal-Paket-Inhalt sein (Spielkopie, Spielerdaten oder unsicherer Pfad)')
            if rel in files:
                raise ValueError(f'{rel} kommt doppelt vor (Build-Dateien brauchen eigene Namen, z. B. mit SHA-Präfix)')
            files[rel] = dict(sha256=sha256(q), size=q.stat().st_size, source=dict(archive='channel'))
            if build is not None:
                files[rel]['build'] = build
            members[rel] = q
    if not files and entry['enabled']:
        raise ValueError('keine Kanal-Dateien')
    if len(files) > self_update.CHANNEL_FILES or sum(e['size'] for e in files.values()) > self_update.CHANNEL_BYTES:
        raise ValueError(f'{len(files)} Dateien: über der Grenze des Updaters')
    if files:
        archive = out / f'channel-{cid}-{tag}.zip'
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for rel in sorted(members):
                info = zipfile.ZipInfo(rel, date_time=(2020, 1, 1, 0, 0, 0))  # Reproducible archives.
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, members[rel].read_bytes())
        manifest = out / f'channel-{cid}-manifest-{tag}.json'
        manifest.write_text(json.dumps(dict(channel=cid, schema=self_update.CHANNEL_SCHEMA, files=files),
                                       indent=1, sort_keys=True), encoding='utf-8')
        self_update.channel_files(json.loads(manifest.read_text(encoding='utf-8')), cid,
                                  {b['exe_sha256'] for b in builds})  # The updater's own check.
        entry.update(manifest=asset(manifest), archives=dict(channel=asset(archive)))
    entry['files'] = len(files)
    return entry



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', type=Path, required=True)
    ap.add_argument('--game-sources', type=Path, help='{path: HTTPS address} of game files; without: full package only')
    ap.add_argument('--updater-exe', type=Path, required=True)
    ap.add_argument('--updater-version', type=int, default=self_update.UPDATER_VERSION)
    ap.add_argument('--min-updater', type=int, default=1)
    ap.add_argument('--sequence', type=int, help='default: seconds since 1970 (monotonic between releases)')
    ap.add_argument('--announce-key', action='append', default=[])
    ap.add_argument('--retire-key', action='append', default=[])
    ap.add_argument('--key-dir', type=Path, default=sign_release.KEY_DIR)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--full-package-url', default='https://azsurvivors.duckdns.org/full/Azeroth-Survivors-Together.zip',
                    help='HTTPS page or file of the full package (shown when game files cannot be downloaded directly); '
                         'default: the newest full zip on the server (publish_release --full-zip)')
    ap.add_argument('--full-zip', type=Path, help='with --publish: the full package zip for that address '
                                                  '(with --full-zip-remote only as fallback)')
    ap.add_argument('--full-zip-remote', action='store_true',
                    help='with --publish: the server builds the full zip itself (no upload of 1.4 GB)')
    ap.add_argument('--no-check-urls', action='store_true', help='do not probe the game file addresses')
    ap.add_argument('--allow-local-http', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--unhosted-source', default=UNHOSTED, help=argparse.SUPPRESS)  # Tests: a local page.
    ap.add_argument('--installer-exe', type=Path, help=f'built web installer, shipped as {INSTALLER_ASSET}')
    ap.add_argument('--publish', action='store_true',
                    help='after signing: game files to every source, the release to GitHub, a mirror to the server')
    ap.add_argument('--publish-dry-run', action='store_true', help='print the publish commands instead of running them')
    ap.add_argument('--gamefiles', type=Path, help='folder of coop-lab/updater/make_game_patches.py (gamefiles.json)')
    ap.add_argument('--gamefiles-url', action='append', default=[],
                    help='HTTPS base address of those assets, ending in /, e.g. '
                         'https://github.com/bymarvin/azeroth-survivors-gamefiles/releases/download/<tag>/; '
                         'several in the order the updater tries them (updater 4)')
    # 0.0.24/0.0.25: one co-op channel (the native DLL engine) in its own subfolder <root>/<id>/ (self_update.py).
    ap.add_argument('--channel-id', help='channel id = its folder below the co-op folder, e.g. native')
    ap.add_argument('--channel-rollout', type=int, default=100,
                    help='signed share of folders (0..100) that use the channel; 0 = everyone on the default path')
    ap.add_argument('--channel-target', type=Path, help='older name of --channel-common')
    ap.add_argument('--channel-common', type=Path, help='folder with the files common to every build (never the game copy)')
    ap.add_argument('--channel-build', type=Path, action='append', default=[],
                    help='folder of one supported build: build.json {version, exe_sha256, exe_size} + its files (repeatable)')
    ap.add_argument('--channel-build-disabled', action='append', default=[],
                    help='game version of a listed build that is paused (its profile pulled), repeatable')
    ap.add_argument('--channel-title', help='shown to the player, e.g. "Native (DLL)"')
    ap.add_argument('--channel-game-version', help='game version the channel needs, e.g. 0.99.0')
    ap.add_argument('--channel-game-exe', type=Path, help='that game exe (only its SHA-256 and size are signed)')
    ap.add_argument('--channel-disabled', action='store_true', help='kill switch: the channel is paused for everyone')
    ap.add_argument('--channel-message', help='text for the player while the channel is paused')
    args = ap.parse_args()

    t = time.time()
    log(' .... ', 'Paket lesen')
    target = json.loads((args.target / 'package-manifest.json').read_text(encoding='utf-8'))
    version = (args.target / 'COOP-VERSION.txt').read_text(encoding='utf-8').strip()
    sources = json.loads(args.game_sources.read_text(encoding='utf-8')) if args.game_sources else {}
    # Asset names: GitHub renames other characters (e.g. '+'), the signed names must stay exact.
    tag = re.sub(r'[^0-9A-Za-z._-]', '-', version)
    out = args.out or Path(os.environ.get('COOP_RELEASE_OUT', 'releases')) / f'github-{tag}'
    out.mkdir(parents=True, exist_ok=True)
    bad = [p for p in target if not self_update.safe_path(p) or self_update.user_area(p)]
    if bad:
        log('FAILED', f'Paket lesen: unzulässiger Pfad {bad[0]}')
        return 1
    wrong = [p for p in target if sha256(args.target / p) != target[p]]
    if wrong:
        log('FAILED', f'Paket lesen: {wrong[0]} passt nicht zum Paketmanifest')
        return 1
    shipped = target.get(self_update.UPDATER_ASSET)
    if shipped and (shipped != sha256(args.updater_exe) or args.min_updater < 3):
        # The package ships the updater: the release asset must be the same exe, and only updater 3+
        # can replace its own running exe as part of an update.
        log('FAILED', 'Paket lesen: die Updater-exe im Paket muss gleich --updater-exe sein und --min-updater >= 3')
        return 1
    log('  OK  ', f'Paket lesen ({time.time() - t:.1f} s, co-op {version}, {len(target)} Dateien'
                  + (', mit Updater-exe' if shipped else '') + ')')

    t = time.time()
    log(' .... ', 'Quellen der Spieldateien prüfen')
    net = self_update.Net('https://example.invalid/', allow_local_http=args.allow_local_http)
    hosted = sorted(p for p in target if kind(p) == 'game' and p in sources)
    offline = sorted(p for p in target if kind(p) == 'game' and p not in sources)
    if offline:
        if not args.full_package_url:
            log('FAILED', f'Quellen: {len(offline)} Spieldateien ohne Adresse (z. B. {offline[0]}) brauchen '
                          '--full-package-url')
            return 1
        log(' WARN ', f'{len(offline)} Spieldateien ohne Adresse (z. B. {offline[0]}): nur im Vollpaket; Ordner einer '
                      'anderen Spielversion bekommen den Vollpaket-Link')
    game = hosted
    try:
        for p in game:
            net.check_scheme(sources[p])
            net.allow(sources[p])
        if args.full_package_url and not args.full_package_url.startswith('https://'):
            raise self_update.Refused(f'Refusing a non-HTTPS address: {args.full_package_url}')
    except self_update.Refused as error:
        log('FAILED', f'Quellen: {error}')
        return 1
    if not args.no_check_urls and game:
        with ThreadPoolExecutor(min(self_update.threads(), len(game))) as pool:
            problems = list(pool.map(lambda p: probe(net, sources[p], (args.target / p).stat().st_size), game))
        bad = [(p, why) for p, why in zip(game, problems) if why]
        for p, why in bad:
            log(' WARN ', f'{p}: {sources[p].split("?")[0]} {why}')
        if bad:
            log('FAILED', f'Quellen: {len(bad)} Adressen liefern die Datei nicht direkt. Direkte HTTPS-Links nötig '
                          '(ohne Zwischenseite/Captcha), sonst bekommen Spieler nur den Hinweis aufs Vollpaket')
            return 1
    if not args.full_package_url:
        log(' WARN ', 'Kein --full-package-url: bei neuen Spieldateien ohne Direktlink sehen Spieler nur '
                      '"Vollpaket von der Release-Seite laden"')
    log('  OK  ', f'Quellen der Spieldateien prüfen ({time.time() - t:.1f} s, {len(game)} Spieldateien extern'
                  + (', Adressen nicht geprüft' if args.no_check_urls else ', alle liefern direkt') + ')')

    t = time.time()
    log(' .... ', 'Archive bauen')
    archives = {}
    for name in ('mod', 'runtime'):
        paths = sorted(p for p in target if kind(p) == name)
        path = out / f'{name}-{tag}.zip'
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for p in paths:
                info = zipfile.ZipInfo(p, date_time=(2020, 1, 1, 0, 0, 0))  # Reproducible archives.
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, (args.target / p).read_bytes())
        archives[name] = asset(path)
        log(' INFO ', f'{path.name}: {len(paths)} Dateien, {path.stat().st_size / 2**20:.1f} MiB')
    log('  OK  ', f'Archive bauen ({time.time() - t:.1f} s)')

    channels = {}
    if args.channel_id:
        t = time.time()
        log(' .... ', f'Kanal {args.channel_id}')
        try:
            channels[args.channel_id] = build_channel(args, out, tag)
        except (ValueError, OSError) as error:
            log('FAILED', f'Kanal {args.channel_id}: {error}')
            return 1
        entry = channels[args.channel_id]
        log('  OK  ', f'Kanal {args.channel_id} ({time.time() - t:.1f} s, '
                      + ('PAUSIERT (Kill-Switch), ' if not entry['enabled'] else '')
                      + f'Rollout {entry["rollout"]["percent"]} %, {entry["files"]} Dateien, Builds '
                      + ', '.join(f'{b["version"]} {b["exe_sha256"][:8]}' + ('' if b['enabled'] else ' (pausiert)')
                                  for b in entry['builds']) + ')')
        del entry['files']

    t = time.time()
    log(' .... ', 'Manifest und latest.json schreiben')
    files = {}
    patches = {}
    if args.gamefiles:
        # Updater 2: game files as binary patches / full assets from the game file release.
        patches = json.loads((args.gamefiles / 'gamefiles.json').read_text(encoding='utf-8'))
        urls = args.gamefiles_url
        good = urls and all(u.endswith('/') and (u.startswith('https://') or args.allow_local_http and
                                                  u.startswith('http://127.0.0.1:')) for u in urls)
        raw = any((v.get('full') or {}).get('encoding') == 'raw' for v in patches.values())
        need = 4 if len(urls) > 1 or raw else 2
        if args.min_updater < need or not good:
            log('FAILED', f'Spielpatches brauchen --min-updater {need} und --gamefiles-url https://.../ (mit /)'
                          + (' (mehrere Quellen oder Raw-Assets: Updater 4)' if need == 4 else ''))
            return 1
        stale = [p for p in patches if p not in target or patches[p]['sha256'] != target[p]]
        if stale:
            log('FAILED', f'Spielpatches passen nicht zum Paket: {stale[0]}')
            return 1
    for p in sorted(target):
        entry = dict(sha256=target[p], size=(args.target / p).stat().st_size)
        if kind(p) != 'game':
            entry['source'] = dict(archive=kind(p))
        elif p in patches:
            entry['source'] = dict(patches=[{k: e[k] for k in ('from_sha256', 'asset', 'sha256', 'size')}
                                            for e in patches[p]['patches']])
            if patches[p].get('full'):
                entry['source']['full'] = {k: patches[p]['full'][k] for k in ('asset', 'sha256', 'size', 'encoding')
                                           if k in patches[p]['full']}
        else:
            # Full package only: a page, never this file (stops at once, see UNHOSTED).
            entry['source'] = dict(url=sources.get(p, args.unhosted_source))
        files[p] = entry
    manifest = out / f'manifest-{tag}.json'
    body = dict(version=version, files=files)
    if patches:
        # Updater 2/3 read one "url"; updater 4 tries "urls" in this signed order.
        body['gamefiles'] = dict(urls=args.gamefiles_url) if args.min_updater >= 4 else dict(url=args.gamefiles_url[0])
    manifest.write_text(json.dumps(body, indent=1, sort_keys=True), encoding='utf-8')
    updater = out / self_update.UPDATER_ASSET
    updater.write_bytes(args.updater_exe.read_bytes())
    latest = dict(format=1, product=self_update.PRODUCT, version=version,
                  sequence=args.sequence or int(time.time()),
                  signed_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                  min_updater=args.min_updater,
                  updater=dict(asset(updater), version=args.updater_version),
                  manifest=asset(manifest), archives=archives,
                  keys=dict(add=args.announce_key, retire=args.retire_key))
    if args.full_package_url:
        latest['full_package'] = dict(url=args.full_package_url)
    if channels:
        latest['channels'] = channels  # Signed with everything else; updaters before 0.0.24 ignore it.
    data = json.dumps(latest, indent=1, sort_keys=True).encode('utf-8')
    self_update.validate_latest(latest)
    if channels and set(self_update.channel_entries(latest)) != set(channels):
        log('FAILED', 'Kanal: der Eintrag besteht die Prüfung des Updaters nicht')
        return 1
    (out / 'latest.json').write_bytes(data)
    log('  OK  ', f'Manifest und latest.json schreiben ({time.time() - t:.1f} s, sequence {latest["sequence"]})')

    t = time.time()
    log(' .... ', 'Signieren')
    signature = sign_release.sign_bytes(data, args.key_dir)
    (out / 'latest.json.sig').write_bytes(signature)
    key = sign_release.public(sign_release.load(args.key_dir))
    if self_update.verify(data, signature, [key]) != key:
        log('FAILED', 'Signieren: Signatur lässt sich nicht prüfen')
        return 1
    if key not in self_update.TRUSTED_KEYS:
        log(' WARN ', 'Signierschlüssel steht nicht in self_update.TRUSTED_KEYS (nur ein angekündigter Schlüssel '
                      'oder ein Test): bestehende Updater nehmen dieses Release nur nach einer Ankündigung an')
    log('  OK  ', f'Signieren ({time.time() - t:.1f} s, Schlüssel {key[:12]}...)')
    if args.installer_exe:
        # The installer trusts the keys of the self_update.py it embeds: this release's key must be among them.
        installer = args.installer_exe.read_bytes()
        if installer[:2] != b'MZ' or key.encode('ascii') not in installer:
            log('FAILED', f'Installer: {args.installer_exe} ist keine exe oder vertraut dem Signierschlüssel nicht')
            return 1
        (out / INSTALLER_ASSET).write_bytes(installer)
        log('  OK  ', f'Installer ({len(installer)} B, sha256 {sha256(out / INSTALLER_ASSET)[:16]}..., kennt den Schlüssel)')

    lines = [f'Release co-op {version} (sequence {latest["sequence"]})', '',
             'Upload as assets of ONE GitHub release (mark it "Latest"):']
    lines += [f'  {name}' for name in ('latest.json', 'latest.json.sig', manifest.name,
                                        f'mod-{tag}.zip', f'runtime-{tag}.zip', updater.name)
              + ((INSTALLER_ASSET,) if args.installer_exe else ())]
    lines += ['', 'Game files - must be downloadable at exactly these HTTPS addresses (never on GitHub):']
    lines += [f'  {p}  {files[p]["size"]} bytes  sha256 {files[p]["sha256"]}' + chr(10) + f'      {sources[p]}'
              for p in game] or ['  (none)']
    if patches:
        assets = sorted({e['asset'] for v in patches.values() for e in v['patches'] + ([v['full']] if v.get('full') else [])})
        lines += ['', f'Game file assets: upload to every game file source {", ".join(args.gamefiles_url)}',
                  f'  (from {args.gamefiles}):'] + [f'  {a}' for a in assets]
        lines += ['', 'Folders whose game files have neither a patch nor a full asset are sent to',
                  f'  {args.full_package_url or "MISSING --full-package-url (players see: from the release page)"}']
    else:
        lines += ['', f'Game files only in the full package ({len(offline)}): folders of another game version are sent to',
                  f'  {args.full_package_url or "MISSING --full-package-url (players see: from the release page)"}']
    (out / 'UPLOAD.txt').write_text(chr(10).join(lines) + chr(10), encoding='utf-8')
    log(' INFO ', f'Upload-Ordner {out} (siehe UPLOAD.txt)')
    if args.publish or args.publish_dry_run:
        sys.path.insert(0, str(Path(__file__).resolve().parent))  # python -I leaves the script folder out.
        import publish_release
        return publish_release.publish(out, latest, args.gamefiles_url, args.gamefiles, dry=not args.publish,
                                       full_zip=args.full_zip, full_zip_remote=args.full_zip_remote,
                                       key_dir=args.key_dir)
    return 0


if __name__ == '__main__':
    sys.exit(main())
