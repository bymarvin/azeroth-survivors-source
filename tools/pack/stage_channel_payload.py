"""Stages the multi-build Native engine payload for the release chat's make_release (WP1): the files that go into <root>/native/,
as one common folder and one folder per supported game build. Never the game (AzerothSurvivors.exe, Data/). Boot-log lines.

    python tools/pack/stage_channel_payload.py --out D:/AzerothCoopNative/dist/channel-native
        --build tools/port/profiles/release-d1bb8a08.draft.json D:/.../AzerothSurvivors-0.99.0.exe
        [--build <release-17abcc4c.json> <0.100.1 exe> ...] [--reviewed <reviewed-hooks.json>] [--release target/release]

Writes (make_release copies each folder's relative paths 1:1 into native/):
    <out>/common/avrt.dll, azcoop-net.exe, reconstruction/reviewed-hooks.json
    <out>/builds/<version>/build.json                          {version, exe_sha256, exe_size} (the exe is read here, not shipped)
    <out>/builds/<version>/reconstruction/release-<hash8>.json the build's verified DLL profile (the DLL picks it by its exe's hash)
    <out>/payload.sha256.txt                                    one line per file, LF, paths relative to <out>
Refuses an unverified profile, a profile that names another exe than the one given, two builds of one version, a stale helper and a
binary with a live-test switch.
"""
import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import game_channel  # noqa: E402


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8 << 20):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--build', nargs=2, action='append', metavar=('PROFILE', 'EXE'), required=True,
                    help='a supported build: its verified release-<hash8>.json and its game exe (read for sha256, size, version)')
    ap.add_argument('--reviewed', type=Path, default=Path('D:/AzerothCoopNative/dllpack-smooth/reconstruction/reviewed-hooks.json'))
    ap.add_argument('--release', type=Path, default=REPO / 'target/release')
    args = ap.parse_args()
    print('[ .... ] channel payload (multi-build)', flush=True)
    problems, builds = [], []
    for profile_path, exe_path in args.build:
        profile_path, exe_path = Path(profile_path), Path(exe_path)
        if not profile_path.is_file() or not exe_path.is_file():
            problems.append(f'missing {profile_path if not profile_path.is_file() else exe_path}')
            continue
        release = json.loads(profile_path.read_text(encoding='utf-8'))
        adapter = release.get('adapter_profile') or {}
        exe_sha = sha(exe_path)
        version = adapter.get('release_version') or game_channel.exe_version(exe_path)
        if adapter.get('adapter_contracts_verified') is not True or not isinstance(release.get('variant_constants'), dict):
            problems.append(f'{profile_path.name} is not a verified runtime profile')
        if str(adapter.get('sha256', '')).lower() != exe_sha:
            problems.append(f'{profile_path.name} names {str(adapter.get("sha256"))[:8]}, the exe {exe_path.name} is {exe_sha[:8]}')
        if not version:
            problems.append(f'no version for {exe_path} (neither in the profile nor in the exe)')
        builds.append(dict(version=version, exe_sha256=exe_sha, exe_size=exe_path.stat().st_size, profile=profile_path))
    versions = [b['version'] for b in builds]
    if len(set(versions)) != len(versions):
        problems.append(f'two builds of one version: {versions}')
    for f in (args.release / 'avrt.dll', args.release / 'azcoop-net.exe', args.reviewed):
        if not f.is_file():
            problems.append(f'missing {f}')
    for f in (args.release / 'avrt.dll', args.release / 'azcoop-net.exe'):
        # live-test switches (cargo feature test-hooks) never ship, same check as tools/build/release.ps1
        if f.is_file() and b'AZCOOP_TEST_' in f.read_bytes():
            problems.append(f'{f.name} contains a live-test switch (AZCOOP_TEST_): build without --features test-hooks')
    sources = list((REPO / 'crates/azcoop-net/src').rglob('*.rs')) + list((REPO / 'crates/azcoop-proto/src').rglob('*.rs'))
    if (args.release / 'azcoop-net.exe').is_file() and (args.release / 'azcoop-net.exe').stat().st_mtime < max(p.stat().st_mtime for p in sources):
        problems.append('azcoop-net.exe is older than its sources: run tools/build/release.ps1 first')
    for p in problems:
        print(f'[FAILED] {p}', flush=True)
    if problems:
        return 1
    for name in ('common', 'builds'):
        if (args.out / name).exists():
            shutil.rmtree(args.out / name)
    layout = {
        'common/avrt.dll': args.release / 'avrt.dll',
        'common/azcoop-net.exe': args.release / 'azcoop-net.exe',
        'common/reconstruction/reviewed-hooks.json': args.reviewed,
    }
    for b in builds:
        layout[f'builds/{b["version"]}/reconstruction/release-{b["exe_sha256"][:8]}.json'] = b['profile']
    lines = []
    for rel, src in layout.items():
        target = args.out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        lines.append(f'{sha(target)}  {rel}')
        print(f'[ INFO ] {rel}  {lines[-1][:16]}  {target.stat().st_size:,} bytes', flush=True)
    for b in builds:
        rel = f'builds/{b["version"]}/build.json'
        (args.out / rel).write_text(json.dumps(dict(version=b['version'], exe_sha256=b['exe_sha256'], exe_size=b['exe_size']), indent=1) + '\n',
                                    encoding='utf-8', newline='\n')
        lines.append(f'{sha(args.out / rel)}  {rel}')
    (args.out / 'payload.sha256.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
    newest = sorted(builds, key=lambda b: game_channel._version_key(b['version']), reverse=True)
    print(f'[  OK  ] channel payload: {len(layout)} files + {len(builds)} build.json in {args.out} (builds '
          f'{", ".join(b["version"] + " " + b["exe_sha256"][:8] for b in newest)}; no game files)', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
