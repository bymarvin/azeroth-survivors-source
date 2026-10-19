"""Local launcher preferences and exception logs; never part of player packages."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import traceback
import uuid

REGIONS = ('eu', 'na', 'sa', 'as', 'oc', 'af', '')


def valid_preferences(value):
    if not isinstance(value, dict):
        return {}
    result = {}
    for key in ('player', 'name'):
        text = value.get(key)
        if isinstance(text, str) and 1 <= len(text.strip()) <= 48 and not any(ord(c) < 32 for c in text):
            result[key] = text.strip()
    if isinstance(value.get('region'), str) and value['region'] in REGIONS:
        result['region'] = value['region']
    return result


def game_version(binary, build):
    try:
        with Path(binary).with_name('.version').open(encoding='utf-8-sig') as source:
            value = source.read(65).strip()
        if re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?', value) and len(value) <= 32:
            return value
    except (OSError, UnicodeError):
        pass
    return {'dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306': '0.84.3',
            '47e4ab65c1ad7366e554171a6a28b0272141664010a50795371129b203111bf2': '0.92.0',
            '0315cf387f4f807512ac965763ed81ae58e7f20dd94547a7541ee8eae3135f66': '0.93.1',
            '7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30': '0.95.0',
            'd1bb8a08c167615fca13891c624485dc3d186a7dc4fb3121e2071bbb8415c1e3': '0.99.0',  # the 0.99.0 (DLL, beta) channel
            '72b51b222171059029eb762ce800c97614ea94f88de7c14543c5236a6fc34743': '0.77.6'}.get(build, 'Unknown')


class LauncherProfile:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.warning = None
        self.preferences = self.load()

    def load(self):
        try:
            with (self.folder / 'preferences.json').open(encoding='utf-8') as source:
                data = source.read(8193)
            return valid_preferences(json.loads(data)) if len(data) <= 8192 else {}
        except (OSError, ValueError):
            return {}

    def save(self, **updates):
        temporary = None
        try:
            # Reload so joining preserves the latest saved room name.
            settings = dict(self.load(), **valid_preferences(updates))
            self.folder.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.folder,
                                             prefix='preferences-', suffix='.tmp', delete=False) as output:
                temporary = Path(output.name)
                json.dump(settings, output, ensure_ascii=True, indent=2)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.folder / 'preferences.json')
            self.preferences, self.warning = settings, None
        except OSError as error:
            self.warning = f'Launcher preferences could not be saved: {type(error).__name__}. Check write access to {self.folder}.'
            print(self.warning, file=sys.stderr, flush=True)
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def log_exception(self, error, slot, stage='game session', quiet=False):
        role = 'host' if slot == 1 else 'guest'
        now = datetime.now(timezone.utc)
        log = self.folder / 'logs' / f'{now:%Y%m%dT%H%M%S%fZ}-{role}-{slot}-pid{os.getpid()}-{uuid.uuid4().hex[:8]}.log'
        details = ''.join(traceback.TracebackException.from_exception(error, capture_locals=False).format(chain=True))
        try:
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(f'{now.isoformat()} | {role} slot {slot} | {stage}\n{details}', encoding='utf-8')
        except OSError as failure:
            print(f'{role} {stage} failed; could not save traceback ({type(failure).__name__}).\n{details}', file=sys.stderr, flush=True)
            return None
        if not quiet:  # quiet: kept for the report, nothing shown to the player.
            concise = str(error).replace('\r', ' ').replace('\n', ' ')[:240]
            print(f'{role} slot {slot}: {stage} failed: {concise}. Full traceback: {log}', file=sys.stderr, flush=True)
        return log
