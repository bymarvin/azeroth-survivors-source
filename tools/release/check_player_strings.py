"""Gate: no "beta" / "opt-in" wording in what players see (0.0.25: the native engine is the default, not a beta).

  check_player_strings.py <package folder or tree> [--manifest package-manifest.json]

Checks the shipped files only (package-manifest.json when given, else the tree without coop-lab/, tests and
verifiers): string literals of .py files (docstrings and comments are developer notes and stay free), and the
text of .txt/.md/.html/.cmd/.ps1 files (cmd "rem"/"::" lines are comments). Boot-log format; exit 1 on a hit.
"""
import argparse
import io
import json
import re
import sys
import time
import tokenize
from pathlib import Path

WORDS = re.compile(r'(?i)\bbeta\b|\bopt[- ]?in\b|\bopt[- ]?out\b')
FSTRING_MIDDLE = getattr(tokenize, 'FSTRING_MIDDLE', -1)  # Python 3.12+: f-string text is its own token.
TEXT = ('.txt', '.md', '.html', '.htm', '.cmd', '.bat', '.ps1', '.js', '.css')


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def shipped(root, manifest):
    if manifest:
        return sorted(root / p for p in json.loads(Path(manifest).read_text(encoding='utf-8')))
    skip = ('coop-lab/', '.coop-runtime/', 'analysis/', '.git/', 'Data/')
    files = []
    for path in root.rglob('*'):
        rel = path.relative_to(root).as_posix()
        name = path.name
        if (path.is_file() and not rel.startswith(skip) and not name.startswith(('test_', 'verify_', 'e2e_'))
                and (path.suffix == '.py' or path.suffix.lower() in TEXT)):
            files.append(path)
    return sorted(files)


def python_hits(text):
    """(line, text) of string literals with the words; docstrings (a string statement) are skipped."""
    hits, previous = [], tokenize.NEWLINE
    statement_start = (tokenize.NEWLINE, tokenize.NL, tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING)
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        literal = (token.type == tokenize.STRING and previous not in statement_start) or token.type == FSTRING_MIDDLE
        if literal and WORDS.search(token.string):
            hits.append((token.start[0], token.string.strip()[:120]))
        if token.type != tokenize.COMMENT:
            previous = token.type
    return hits


def text_hits(path, text):
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip().lower()
        if path.suffix.lower() in ('.cmd', '.bat') and (stripped.startswith('rem ') or stripped.startswith('::')):
            continue
        if WORDS.search(line):
            hits.append((number, line.strip()[:120]))
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('root', type=Path)
    ap.add_argument('--manifest', type=Path)
    args = ap.parse_args(argv)
    t = time.time()
    log(' .... ', f'Spielertexte ohne beta/opt-in ({args.root})')
    files = [p for p in shipped(args.root, args.manifest) if p.suffix == '.py' or p.suffix.lower() in TEXT]
    found = 0
    for path in files:
        try:
            text = path.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        try:
            hits = python_hits(text) if path.suffix == '.py' else text_hits(path, text)
        except (tokenize.TokenError, SyntaxError):
            hits = text_hits(path, text)
        for line, snippet in hits:
            found += 1
            log(' WARN ', f'{path.relative_to(args.root).as_posix()}:{line}: {snippet}')
    if found:
        log('FAILED', f'Spielertexte: {found} Stellen mit beta/opt-in in {len(files)} geprüften Dateien')
        return 1
    log('  OK  ', f'Spielertexte ohne beta/opt-in ({time.time() - t:.1f} s, {len(files)} Dateien)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
