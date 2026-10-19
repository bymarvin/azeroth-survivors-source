"""Hygiene gate for the public audit repo: fails (exit 1) if anything that must not be published is present.

Run from the repo root:  python scripts/hygiene_gate.py
CI runs it on every push (.github/workflows/audit.yml); a release must not be published while it fails.

It refuses:
  * local filesystem paths (C:\\Users\\<name>, D:\\..., /home/<name>) that leak the author's machine;
  * private keys / secrets / tokens (PEM private keys, SSH private keys, AWS keys, bearer tokens);
  * game assets or executables (the game's own exe/Data/MPQ/audio/texture files) and decompiled game code;
  * references to the private reverse-engineering material (the re-source tree, Ghidra projects, RE notes);
  * live-test switches (AZCOOP_TEST_*) outside a `#[cfg(feature = "test-hooks")]` guard;
  * non-loopback server addresses hard-coded as literals (real lobby/relay hosts or credentials).
Loopback (127.0.0.1, ::1, localhost) and the documentation placeholders TEST-NET (192.0.2.x, 198.51.100.x, 203.0.113.x)
and example.com are allowed.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
TEXT_SUFFIXES = {'.rs', '.py', '.toml', '.lock', '.json', '.md', '.ps1', '.sh', '.yml', '.yaml', '.txt', '.cfg', '.rc',
                 '.cmd', '.bat', '.cargo', '.gitignore', ''}
BINARY_OK = {'.res'}  # res/version.res is a compiled Windows version resource (no code); allowed, not scanned as text

# forbidden content patterns (name, regex, note)
FORBIDDEN = [
    ('windows user path', re.compile(r'[A-Za-z]:\\\\?Users\\\\?[^\s"\']+', re.I), 'leaks a local user profile path'),
    ('D: absolute path', re.compile(r'\bD:\\\\?[A-Za-z0-9 _.\\-]', ), 'leaks a local build-machine path'),
    ('unix home path', re.compile(r'/(?:home|Users)/(?!runner\b)[a-z0-9_.-]+/', re.I), 'leaks a local home path'),
    ('PEM private key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'), 'private signing/crypto key'),
    ('SSH private key', re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), 'SSH private key'),
    ('AWS access key', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), 'AWS access key id'),
    ('AWS secret', re.compile(r'aws_secret_access_key\s*=\s*\S+', re.I), 'AWS secret'),
    ('bearer/token literal', re.compile(r'(?:secret|token|password|passwd|api[_-]?key)\s*[=:]\s*["\'][^"\']{12,}["\']', re.I), 'possible hard-coded secret'),
    ('re-source reference', re.compile(r're-source|AzerothCoopNativee?-source|ghidra|\.gpr\b', re.I), 'private reverse-engineering material'),
    ('game asset/exe', re.compile(r'\b\w+\.(?:mpq|blp|m2|wmo|adt|wdt|wdl|dbc)\b', re.I), 'game asset filename'),
]
# non-loopback IPv4 literal (a real server address), excluding documentation TEST-NET ranges and 0.0.0.0
IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
ALLOWED_IP_PREFIX = ('127.', '0.0.0.0', '255.', '192.0.2.', '198.51.100.', '203.0.113.', '169.254.',
                     '10.', '192.168.', '8.8.8.8', '8.8.4.4') + tuple(f'172.{n}.' for n in range(16, 32)) \n                     + tuple(f'100.{n}.' for n in range(64, 128)) + tuple(f'{n}.' for n in range(224, 240))
# loopback, TEST-NET docs, RFC1918 LAN, link-local, CGNAT/Tailscale 100.64/10, IPv4 multicast (SSDP/UPnP), and the public
# resolvers 8.8.8.8/8.8.4.4 used only to read the local outbound interface address (no data is sent to them)
# AZCOOP_TEST_ must be inside a test-hooks feature guard; we track the nearest cfg on the preceding lines
TESTHOOK = re.compile(r'(?:env::var|std::env::var|getenv|environ(?:\.get)?\(|GetEnvironmentVariable)[^
]{0,40}AZCOOP_TEST_')
FEATURE_GUARD = re.compile(r'feature\s*=\s*"test-hooks"')
BINARY_EXT = {'.exe', '.dll', '.mpq', '.bin', '.png', '.jpg', '.jpeg', '.blp', '.wav', '.mp3', '.ogg', '.zip', '.7z',
              '.pdb', '.dmp', '.so', '.dylib', '.ico', '.ttf', '.dat'}


def scan():
    hits = []
    testhook_lines = []
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or SELF == path.resolve() or '.git' in path.parts:
            continue
        suffix = path.suffix.lower()
        rel = path.relative_to(ROOT).as_posix()
        if suffix in BINARY_EXT:
            hits.append((rel, 0, 'binary/asset file', f'a {suffix} file must not be in the audit repo'))
            continue
        if suffix in BINARY_OK:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='strict')
        except (UnicodeDecodeError, OSError):
            hits.append((rel, 0, 'non-text file', 'not valid UTF-8 text; a binary slipped in'))
            continue
        lines = text.splitlines()
        for n, line in enumerate(lines, 1):
            for name, rx, note in FORBIDDEN:
                if rx.search(line):
                    hits.append((rel, n, name, note))
            for m in IP.finditer(line):
                ip = m.group(0)
                if not ip.startswith(ALLOWED_IP_PREFIX) and all(0 <= int(o) <= 255 for o in ip.split('.')):
                    # ignore version-like numbers (all octets, but part of a larger dotted token e.g. 1.2.3.4 in a version)
                    hits.append((rel, n, 'non-loopback IP literal', f'{ip}: a real server address must not be hard-coded'))
            if TESTHOOK.search(line):
                guarded = any(FEATURE_GUARD.search(lines[k]) for k in range(max(0, n - 8), n))
                testhook_lines.append((rel, n, line.strip()[:100], guarded))
    return hits, testhook_lines


def main():
    sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
    print('[ .... ] hygiene gate: scanning the audit repo for content that must not be published')
    hits, testhooks = scan()
    unguarded = [t for t in testhooks if not t[3]]
    for rel, n, name, note in hits:
        print(f'[FAILED] {rel}:{n}: {name} — {note}')
    for rel, n, line, _ in unguarded:
        print(f'[FAILED] {rel}:{n}: AZCOOP_TEST_ outside a test-hooks feature guard — {line}')
    guarded = [t for t in testhooks if t[3]]
    if guarded:
        print(f'[ INFO ] {len(guarded)} AZCOOP_TEST_ reference(s) inside a #[cfg(feature="test-hooks")] guard (not shipped): '
              + ', '.join(f'{r}:{n}' for r, n, _, _ in guarded[:12]))
    total = len(hits) + len(unguarded)
    if total:
        print(f'[FAILED] hygiene gate: {total} issue(s); the repo is NOT clean to publish')
        return 1
    files = sum(1 for p in ROOT.rglob('*') if p.is_file() and '.git' not in p.parts)
    print(f'[  OK  ] hygiene gate: {files} files, no local paths, secrets, keys, game assets, RE material, or unguarded test hooks')
    return 0


if __name__ == '__main__':
    sys.exit(main())
