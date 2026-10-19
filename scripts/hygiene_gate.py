"""Hygiene gate for the public audit repo: fails (exit 1) if anything that must not be published is present.

Run from the repo root:  python scripts/hygiene_gate.py
CI runs it on every push (.github/workflows/audit.yml); a release must not be published while it fails.

It refuses:
  * local filesystem paths (C:\\Users\\<name>, D:\\..., /home/<name>) that leak the author's machine;
  * private keys / secrets / tokens (PEM private keys, SSH private keys, AWS keys, hard-coded tokens);
  * game assets or executables (the game's own exe/Data/MPQ/audio/texture files) and decompiled game code;
  * references to the private reverse-engineering material (the re-source tree, Ghidra projects);
  * live-test switches (AZCOOP_TEST_*): a real env read that is NOT behind `#[cfg(feature = "test-hooks")]`;
  * non-loopback public server addresses hard-coded as literals.

Allowed: loopback (127.0.0.1, ::1, localhost); the documentation TEST-NET ranges (192.0.2/198.51.100/203.0.113);
RFC1918 LAN (10/172.16-31/192.168); link-local (169.254); CGNAT / Tailscale (100.64.0.0/10); IPv4 multicast
(224-239, e.g. SSDP 239.255.255.250); the public resolvers 8.8.8.8 / 8.8.4.4 (used only to read the local outbound
interface address, no data sent); and ALL-CAPS placeholders such as __CLIENT_SECRET__ or <token>.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
BINARY_OK = {'.res'}  # res/version.res: a compiled Windows version resource (no code); allowed, not scanned as text
BINARY_EXT = {'.exe', '.dll', '.mpq', '.bin', '.png', '.jpg', '.jpeg', '.blp', '.wav', '.mp3', '.ogg', '.zip', '.7z',
              '.pdb', '.dmp', '.so', '.dylib', '.ico', '.ttf', '.dat', '.m2', '.wmo', '.adt', '.wdt', '.wdl', '.dbc'}

FORBIDDEN = [
    ('windows user path', re.compile(r'[A-Za-z]:\\\\?Users\\\\?[^\s"\']+', re.I), 'leaks a local user profile path'),
    ('D: absolute path', re.compile(r'\bD:\\\\?[A-Za-z0-9 _.\\-]'), 'leaks a local build-machine path'),
    ('unix home path', re.compile(r'/(?:home|Users)/(?!runner\b)[a-z0-9_.-]+/', re.I), 'leaks a local home path'),
    ('PEM private key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'), 'private key'),
    ('AWS access key', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), 'AWS access key id'),
    ('AWS secret', re.compile(r'aws_secret_access_key\s*=\s*\S+', re.I), 'AWS secret'),
    ('bearer/token literal', re.compile(r'(?:secret|token|password|passwd|api[_-]?key)\s*[=:]\s*["\'](?!__[A-Z0-9_]+__)(?!<)[^"\']{12,}["\']', re.I), 'possible hard-coded secret'),
    ('re-source reference', re.compile(r're-source|AzerothCoopNativee?-source|ghidra|\.gpr\b', re.I), 'private reverse-engineering material'),
    ('game asset name', re.compile(r'\b\w+\.(?:mpq|blp|m2|wmo|adt|wdt|wdl|dbc)\b', re.I), 'game asset filename'),
]
IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
ALLOWED_IP_PREFIX = ('127.', '0.0.0.0', '255.', '192.0.2.', '198.51.100.', '203.0.113.', '169.254.',
                     '10.', '192.168.', '8.8.8.8', '8.8.4.4') + tuple(f'172.{n}.' for n in range(16, 32))
TESTHOOK = re.compile(r'(?:env::var|std::env::var|getenv|environ(?:\.get)?\(|GetEnvironmentVariable)[^\n]{0,40}AZCOOP_TEST_')
FEATURE_GUARD = re.compile(r'feature\s*=\s*"test-hooks"')


def ip_allowed(ip):
    if ip.startswith(ALLOWED_IP_PREFIX):
        return True
    try:
        o = [int(x) for x in ip.split('.')]
    except ValueError:
        return True
    if not all(0 <= x <= 255 for x in o):
        return True  # not a real IPv4 (e.g. a version number)
    if o[0] == 100 and 64 <= o[1] <= 127:
        return True  # CGNAT / Tailscale 100.64.0.0/10
    if 224 <= o[0] <= 239:
        return True  # IPv4 multicast (SSDP/UPnP)
    return False


def gated_module_files():
    """Rust source files whose module is declared behind #[cfg(feature = "test-hooks")] in a lib.rs/mod.rs
    (e.g. `#[cfg(feature = "test-hooks")] pub mod stress;` gates all of stress.rs)."""
    stems = set()
    decl = re.compile(r'^\s*(?:pub\s+)?mod\s+([a-z0-9_]+)\s*;')
    for parent in list(ROOT.rglob('lib.rs')) + list(ROOT.rglob('mod.rs')):
        lines = parent.read_text(encoding='utf-8', errors='replace').splitlines()
        for n, line in enumerate(lines):
            m = decl.match(line)
            if m and any(FEATURE_GUARD.search(lines[k]) for k in range(max(0, n - 3), n)):
                stems.add((parent.parent / f'{m.group(1)}.rs').resolve())
                stems.add((parent.parent / m.group(1) / 'mod.rs').resolve())
    return stems


def scan():
    hits, testhooks = [], []
    gated = gated_module_files()
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or path.resolve() == SELF or {'.git', '__pycache__', 'target'} & set(path.parts):
            continue  # skip VCS, Python caches, and build output (target/ is gitignored, not repo content)
        rel = path.relative_to(ROOT).as_posix()
        suffix = path.suffix.lower()
        if suffix in BINARY_EXT:
            hits.append((rel, 0, 'binary/asset file', f'a {suffix} file must not be in the audit repo'))
            continue
        if suffix in BINARY_OK:
            continue
        try:
            lines = path.read_text(encoding='utf-8').splitlines()
        except (UnicodeDecodeError, OSError):
            hits.append((rel, 0, 'non-text file', 'not valid UTF-8; a binary slipped in'))
            continue
        for n, line in enumerate(lines, 1):
            for name, rx, note in FORBIDDEN:
                if rx.search(line):
                    hits.append((rel, n, name, note))
            for m in IP.finditer(line):
                if not ip_allowed(m.group(0)):
                    hits.append((rel, n, 'non-loopback IP literal', f'{m.group(0)}: a real server address must not be hard-coded'))
            if TESTHOOK.search(line):
                guarded = (path.resolve() in gated
                           or any(FEATURE_GUARD.search(lines[k]) for k in range(0, n)))
                testhooks.append((rel, n, line.strip()[:100], guarded))
    return hits, testhooks


def main():
    sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
    print('[ .... ] hygiene gate: scanning the audit repo for content that must not be published')
    hits, testhooks = scan()
    unguarded = [t for t in testhooks if not t[3]]
    for rel, n, name, note in hits:
        print(f'[FAILED] {rel}:{n}: {name} — {note}')
    for rel, n, line, _ in unguarded:
        print(f'[FAILED] {rel}:{n}: AZCOOP_TEST_ env read outside a test-hooks feature guard — {line}')
    guarded = [t for t in testhooks if t[3]]
    if guarded:
        print(f'[ INFO ] {len(guarded)} AZCOOP_TEST_ env read(s) behind #[cfg(feature="test-hooks")] (never shipped): '
              + ', '.join(f'{r}:{n}' for r, n, _, _ in guarded))
    total = len(hits) + len(unguarded)
    if total:
        print(f'[FAILED] hygiene gate: {total} issue(s); the repo is NOT clean to publish')
        return 1
    files = sum(1 for p in ROOT.rglob('*') if p.is_file() and '.git' not in p.parts)
    print(f'[  OK  ] hygiene gate: {files} files, no local paths, secrets, keys, game assets, RE material, or unguarded test hooks')
    return 0


if __name__ == '__main__':
    sys.exit(main())
