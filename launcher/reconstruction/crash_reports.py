"""Bounded crash reports and room-scoped upload permits (standard library only)."""
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import threading
import time
import sys
import urllib.request

MAX_REPORT = 1024 * 1024
TAIL_BYTES = 96 * 1024


def tail(path, limit):
    with Path(path).open('rb') as source:
        size = source.seek(0, 2)
        source.seek(max(0, size - limit))
        data = source.read(limit)
    return data.decode('utf-8', errors='replace'), size > limit


def scrub(text, private_values=()):
    for value in sorted((v for v in private_values if isinstance(v, str) and v), key=len, reverse=True):
        text = text.replace(value, '[redacted]')
    text = re.sub(r'(?i)([A-Z]:[\\/]+Users[\\/]+|/home/|/Users/)[^\\/\r\n"]+', r'\1[redacted]', text)
    text = re.sub(r'(?i)(Bearer\s+)[A-Za-z0-9._~+/-]+', r'\1[redacted]', text)
    return re.sub(r'(?i)("(?:token|ticket|invite|password|secret|authorization|name|character_name)"\s*:\s*)"(?:\\.|[^"\\\r\n])*"',
                  r'\1"[redacted]"', text)


def send_report(directory, permit, body, endpoint, expected_id=None):
    request = urllib.request.Request(directory + endpoint, body,
        {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + permit})
    with urllib.request.urlopen(request, timeout=5) as response:
        result = json.loads(response.read(4097))
    identifier = result.get('report_id') if isinstance(result, dict) else None
    if (not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{24}-[0-9]+-[1-4]', identifier)
            or expected_id is not None and identifier != expected_id):
        raise ValueError('Invalid diagnostic report receipt')
    return identifier


def upload_report(directory, permit, log, gameplay, framework, private_values=(), diagnostics=None):
    """Save the exact sanitized upload locally first; failures never replace the crash."""
    traceback, traceback_truncated = tail(log, 16 * 1024)
    try:
        events, events_truncated = tail(gameplay, TAIL_BYTES) if gameplay else ('', False)
    except OSError:
        events, events_truncated = '', False
    report = dict(traceback=scrub(traceback, private_values),
                  gameplay=scrub(events, private_values), framework=framework[:32],
                  traceback_truncated=traceback_truncated, gameplay_truncated=events_truncated)
    if diagnostics is not None:
        report['diagnostics'] = json.loads(scrub(json.dumps(diagnostics), private_values))
    body = json.dumps(report, ensure_ascii=True).encode('utf-8')
    if len(body) > MAX_REPORT:
        raise ValueError('Crash report exceeds bound')
    Path(log).with_suffix('.report.json').write_bytes(body)
    if not permit:
        return (f'Crash report saved locally: {Path(log).with_suffix(".report.json")}. LAN mode never uploads: '
                'to send it to the maintainers, attach that file (folder coop-lab\\launcher\\logs) on Discord.')
    identifier = send_report(directory, permit, body, '/crash-report')
    return 'Crash report uploaded: ' + identifier


def upload_completed(directory, permit, room, action, duration, framework, events, diagnostics, folder, private_values=()):
    """Freeze and save before returning; only the bounded HTTP upload is asynchronous.

    Completed means an observed end-of-run transition, not a bug-free session.
    A retry uses the original file, even after the next run changes live state.
    """
    identifier = f"{room['id']}-{room['run']}-{room['slot']}"
    if not re.fullmatch(r'[0-9a-f]{24}-[0-9]+-[1-4]', identifier):
        raise ValueError('Invalid completion identity')
    report = dict(room=room['id'], run=room['run'], slot=room['slot'], build=room['build'], version=room['version'],
                  outcome='completed', action=action, duration_seconds=duration,
                  framework=framework[:32], gameplay=events[-TAIL_BYTES:], diagnostics=diagnostics)
    body = scrub(json.dumps(report, ensure_ascii=True), private_values).encode('utf-8')
    if len(body) > MAX_REPORT:
        raise ValueError('Completion report exceeds bound')
    target = Path(folder) / (identifier + '.completed.json')
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open('xb') as output:
            output.write(body)
    except FileExistsError:
        body = target.read_bytes()
        if len(body) > MAX_REPORT:
            raise ValueError('Saved completion report exceeds bound')
    def worker():
        try:
            if not permit:
                raise ValueError('Upload permit unavailable')
            result = send_report(directory, permit, body, '/completed-report', identifier)
            print('Completion report uploaded: ' + result, file=sys.stderr, flush=True)
        except Exception as error:
            print(f'Completion report upload failed ({type(error).__name__}); local report retained: {identifier}',
                  file=sys.stderr, flush=True)
    thread = threading.Thread(target=worker, name='completed-report-upload', daemon=True)
    thread.start()
    return thread


class CrashReports:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.key = secrets.token_bytes(32)
        self.lock = threading.Lock()

    def permit(self, room):
        # Signed metadata survives room deletion, without retaining membership secrets.
        metadata = dict(room=room['id'], run=room['run'], slot=room['slot'],
                        build=room['build'], version=room['version'], expires=int(time.time()) + 86400)
        payload = json.dumps(metadata, separators=(',', ':')).encode().hex()
        return payload + '.' + hmac.new(self.key, payload.encode(), hashlib.sha256).hexdigest()

    def authorize(self, authorization):
        if not authorization.startswith('Bearer ') or len(authorization) > 2048:
            raise ValueError('Upload permit required')
        payload, signature = authorization[7:].split('.')
        if not hmac.compare_digest(signature, hmac.new(self.key, payload.encode(), hashlib.sha256).hexdigest()):
            raise ValueError('Invalid upload permit')
        metadata = json.loads(bytes.fromhex(payload))
        if metadata['expires'] < time.time():
            raise ValueError('Upload permit expired')
        return metadata

    def collect(self, metadata, report, *, completed=False):
        expected = {'traceback', 'gameplay', 'framework', 'traceback_truncated', 'gameplay_truncated'}
        if 'diagnostics' in report:
            expected.add('diagnostics')
            if not isinstance(report['diagnostics'], dict) or len(json.dumps(report['diagnostics'])) > 65536:
                raise ValueError('Invalid diagnostic summary')
        if completed:
            expected = {'room', 'run', 'slot', 'build', 'version', 'outcome', 'action',
                        'duration_seconds', 'framework', 'gameplay', 'diagnostics'}
            if (set(report) != expected or report['outcome'] != 'completed'
                    or report['action'] not in ('new_hero', 'again')
                    or type(report['duration_seconds']) not in (int, float)
                    or not math.isfinite(report['duration_seconds']) or not 0 <= report['duration_seconds'] <= 10000000
                    or any(report[k] != metadata[k] for k in ('room', 'run', 'slot', 'build', 'version'))
                    or any(not isinstance(report[k], str) for k in ('gameplay', 'framework'))
                    or len(report['framework']) > 32):
                raise ValueError('Invalid completion report')
        elif (set(report) != expected or
                any(not isinstance(report[k], str) for k in ('traceback', 'gameplay', 'framework')) or
                len(report['framework']) > 32 or
                any(type(report[k]) is not bool for k in ('traceback_truncated', 'gameplay_truncated'))):
            raise ValueError('Invalid crash report')
        identifier = f"{metadata['room']}-{metadata['run']}-{metadata['slot']}"
        if not re.fullmatch(r'[0-9a-f]{24}-[0-9]+-[1-4]', identifier):
            raise ValueError('Invalid report identity')
        document = dict(report, **{k: v for k, v in metadata.items() if k != 'expires'})
        document.update(report_id=identifier, received=datetime.now(timezone.utc).isoformat())
        data = json.dumps(document, ensure_ascii=True, indent=2).encode()
        with self.lock:
            self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            folder = self.folder / 'completed' if completed else self.folder
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = folder / (identifier + '.json')
            # One report per room/run/slot; retries never overwrite the first evidence.
            if not target.exists():
                files = [*self.folder.glob('*.json'), *self.folder.glob('completed/*.json')]
                if len(files) >= 1024 or sum(p.stat().st_size for p in files) + len(data) > 256 * MAX_REPORT:
                    raise OSError('Crash report storage is full')
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(descriptor, 'wb') as output:
                        output.write(data)
                except OSError:
                    target.unlink(missing_ok=True)
                    raise
        return dict(report_id=identifier)
