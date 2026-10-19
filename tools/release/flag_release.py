"""Flag-only republish: a new signed latest.json for an already published release folder, same assets.

The safety lever for a channel (the native DLL engine) within minutes and without a client update: pause or
re-enable it, limit its rollout share, switch one game build off or on, change the player message. Every other
byte of the release stays as it is (manifest, archives, exes, channel archive and file list); only latest.json
and latest.json.sig are new, with a higher sequence, so updaters take it and a replay of the older one is refused.

  flag_release.py --from <signed release folder> --out <new folder> --channel-id native [--rollout 0..100]
                  [--disable | --enable] [--message TEXT] [--build-off VERSION] [--build-on VERSION]
                  [--sequence N] [--key-dir DIR]

Then publish the new folder with publish_release.py (the existing GitHub release gets the two files replaced,
latest.json last; the server mirror the same).
"""
import argparse
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parents[1] / 'reconstruction'), str(HERE.parent / 'updater')]
import self_update  # noqa: E402
import sign_release  # noqa: E402

LATEST = ('latest.json', 'latest.json.sig')


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def main(argv=None):
    ap = argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument('--from', dest='source', type=Path, required=True, help='signed release folder (make_release --out)')
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--channel-id', required=True)
    ap.add_argument('--rollout', type=int, help='share of folders 0..100 (0 = everyone on the default path)')
    switch = ap.add_mutually_exclusive_group()
    switch.add_argument('--disable', action='store_true', help='kill switch: the channel is paused for everyone')
    switch.add_argument('--enable', action='store_true')
    ap.add_argument('--message', help='text for the player (paused channel or switched-off build)')
    ap.add_argument('--build-off', action='append', default=[], metavar='VERSION')
    ap.add_argument('--build-on', action='append', default=[], metavar='VERSION')
    ap.add_argument('--sequence', type=int, help='default: seconds since 1970, always above the source')
    ap.add_argument('--key-dir', type=Path, default=sign_release.KEY_DIR)
    args = ap.parse_args(argv)

    t = time.time()
    log(' .... ', f'Quelle prüfen ({args.source})')
    data, signature = ((args.source / name).read_bytes() for name in LATEST)
    key = sign_release.public(sign_release.load(args.key_dir))
    if self_update.verify(data, signature, [*self_update.TRUSTED_KEYS, key]) is None:
        log('FAILED', 'Quelle: latest.json.sig passt nicht (kein signiertes Release)')
        return 1
    latest = json.loads(data)
    self_update.validate_latest(latest)
    entry = (latest.get('channels') or {}).get(args.channel_id)
    if not isinstance(entry, dict):
        log('FAILED', f'Quelle: kein Kanal {args.channel_id!r} im Release')
        return 1
    referenced = [latest['manifest']['asset'], latest['updater']['asset'], *(a['asset'] for a in latest['archives'].values())]
    if entry.get('manifest'):
        referenced += [entry['manifest']['asset'], *(a['asset'] for a in entry['archives'].values())]
    missing = [name for name in referenced if not (args.source / name).is_file()]
    if missing:
        log('FAILED', f'Quelle: {missing[0]} fehlt im Ordner')
        return 1
    log('  OK  ', f'Quelle prüfen ({time.time() - t:.1f} s, co-op {latest["version"]}, sequence {latest["sequence"]})')

    t = time.time()
    log(' .... ', f'Schalter {args.channel_id}')
    before = json.dumps(entry, sort_keys=True)
    builds = {b['version']: b for b in self_update.channel_builds(entry) or []}
    unknown = sorted(set(args.build_off + args.build_on) - set(builds))
    if unknown or set(args.build_off) & set(args.build_on):
        log('FAILED', f'Schalter: unbekannte oder doppelt genannte Builds {unknown or sorted(set(args.build_off) & set(args.build_on))}')
        return 1
    if 'game' in entry and 'schema' not in entry:
        log('FAILED', 'Schalter: alte Einzel-Build-Form; nur Schema-1-Einträge werden umgeschaltet')
        return 1
    for build in entry['builds']:
        if build['version'] in args.build_off:
            build.update(enabled=False, message=args.message)
        elif build['version'] in args.build_on:
            build['enabled'] = True
            build.pop('message', None)
    if args.disable:
        if not entry.get('manifest'):
            log('FAILED', 'Schalter: der Kanal hat keine Dateien; ein Einschalten wäre danach nicht möglich')
            return 1
        entry.update(enabled=False, message=args.message or 'Paused for a fix; the co-op uses the classic engine.')
    elif args.enable:
        entry.update(enabled=True, message=None)
    elif args.message is not None and not args.build_off:
        entry['message'] = args.message
    if args.rollout is not None:
        if not 0 <= args.rollout <= 100:
            log('FAILED', 'Schalter: --rollout ist ein Prozentwert 0..100')
            return 1
        entry['rollout'] = dict(percent=args.rollout)
    if json.dumps(entry, sort_keys=True) == before:
        log('FAILED', 'Schalter: nichts geändert')
        return 1
    latest['sequence'] = max(args.sequence or int(time.time()), latest['sequence'] + 1)
    latest['signed_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    self_update.validate_latest(latest)
    if args.channel_id not in self_update.channel_entries(latest):
        log('FAILED', 'Schalter: der Eintrag besteht die Prüfung des Updaters nicht')
        return 1
    state = entry.get('rollout', {'percent': 100})['percent']
    log('  OK  ', f'Schalter {args.channel_id} ({time.time() - t:.1f} s, ' + ('AN' if entry['enabled'] else 'PAUSIERT')
                  + f', Rollout {state} %, Builds ' + ', '.join(f'{b["version"]}{"" if b["enabled"] else " aus"}'
                                                             for b in entry['builds']) + f', sequence {latest["sequence"]})')

    t = time.time()
    log(' .... ', 'Signieren und Ordner schreiben')
    if args.out.resolve() == args.source.resolve():
        log('FAILED', 'Ordner: --out muss ein neuer Ordner sein (die Quelle bleibt als Rückweg)')
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(set(referenced) | {'Azeroth-Survivors-Together-Installer.exe'}):
        if (args.source / name).is_file():
            shutil.copy2(args.source / name, args.out / name)
    data = json.dumps(latest, indent=1, sort_keys=True).encode('utf-8')
    signature = sign_release.sign_bytes(data, args.key_dir)
    if self_update.verify(data, signature, [key]) != key:
        log('FAILED', 'Signieren: Signatur lässt sich nicht prüfen')
        return 1
    (args.out / 'latest.json').write_bytes(data)
    (args.out / 'latest.json.sig').write_bytes(signature)
    (args.out / 'UPLOAD.txt').write_text(
        f'Flag-only republish of co-op {latest["version"]} (sequence {latest["sequence"]}): replace latest.json and '
        'latest.json.sig of the existing release (latest.json last); every other asset is unchanged.\n', encoding='utf-8')
    log('  OK  ', f'Signieren und Ordner schreiben ({time.time() - t:.1f} s, {args.out}, Schlüssel {key[:12]}...)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
