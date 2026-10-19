"""Folder locks of the co-op launcher with an owner record, a visible wait and a bounded timeout (0.0.24).

Windows releases an msvcrt byte lock when its process ends, even after a crash, kill or power loss, so a lock
file left behind never blocks by itself. What can block is a co-op window that is still running (hung, or a
second window in the same folder). The owner record next to the lock (<name>.owner.json: PID, process start
time, purpose, since) lets the waiting side say who holds it, notice an owner that has ended (PID reuse is
ruled out by the start time) and give up after a bounded time with a message that names the lock file.
"""
import atexit
import ctypes
import json
import os
import time
from pathlib import Path

STILL_ACTIVE = 259
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def process_started(pid):
    """Creation time (FILETIME ticks) of a running process, or None when it has ended or cannot be queried."""
    if os.name != 'nt' or type(pid) is not int or pid <= 0:
        return None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    handle = kernel.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        code = ctypes.c_ulong()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value != STILL_ACTIVE:
            return None
        times = [ctypes.c_ulonglong() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            return None
        return times[0].value
    finally:
        kernel.CloseHandle(handle)


class LockBusy(RuntimeError):
    def __init__(self, message, owner):
        super().__init__(message)
        self.owner = owner


class FolderLock:
    """One-byte msvcrt lock on `path` plus `<path stem>.owner.json`. Use as a context manager or acquire/release."""

    def __init__(self, path, purpose):
        self.path, self.purpose = Path(path), purpose
        self.owner_path = self.path.with_name(self.path.stem + '.owner.json')
        self.file = None

    def owner(self):
        """The recorded owner if that process is still the one that took the lock, else None."""
        try:
            record = json.loads(self.owner_path.read_text(encoding='utf-8'))
            pid, started = record.get('pid'), record.get('started')
        except (OSError, ValueError, AttributeError):
            return None
        if pid == os.getpid() or started is None or process_started(pid) != started:
            return None
        return record

    def describe(self, owner):
        if not owner:
            return 'another co-op window'
        since = time.strftime('%H:%M:%S', time.localtime(owner.get('since', 0)))
        return f'another co-op window (PID {owner.get("pid")}, {owner.get("purpose", "busy")}, since {since})'

    def try_lock(self):
        import msvcrt
        self.file.seek(0)
        try:
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def acquire(self, timeout=0, progress=None, waiting_text=None, busy_text=None):
        """Take the lock. While another window holds it, progress(text) about once a second; after `timeout`
        seconds (0 = do not wait) raise LockBusy with busy_text (or a default naming the lock file)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open('a+b')
        if self.file.seek(0, 2) == 0:
            self.file.write(b'0')
            self.file.flush()
        started = time.monotonic()
        shown = None
        while not self.try_lock():
            waited = time.monotonic() - started
            owner = self.owner()
            if waited >= timeout:
                self.file.close()
                self.file = None
                text = (busy_text or '{path} is held by {owner}. Close all co-op windows and start again; if none is '
                        'open, end the leftover "python.exe" of Azeroth Survivors Together in Task Manager.')
                raise LockBusy(text.format(path=self.path, owner=self.describe(owner), seconds=int(waited)), owner)
            if progress is not None and (shown is None or waited - shown >= 1):
                shown = waited
                text = (waiting_text or 'Waiting for {owner} to finish ({seconds} s)…')
                try:
                    progress(text.format(path=self.path, owner=self.describe(owner), seconds=int(waited)))
                except Exception:
                    pass  # A status line must never break the lock.
            time.sleep(.25)
        try:
            record = dict(pid=os.getpid(), started=process_started(os.getpid()), purpose=self.purpose, since=time.time())
            self.owner_path.write_text(json.dumps(record), encoding='utf-8')
        except OSError:
            pass  # The record only improves messages; the lock itself holds.
        atexit.register(self.release)
        return self

    def release(self):
        if self.file is None:
            return
        try:
            if self.owner() is None:  # Our own record (owner() ignores this PID) or none: remove it.
                try:
                    record = json.loads(self.owner_path.read_text(encoding='utf-8'))
                    if record.get('pid') == os.getpid():
                        self.owner_path.unlink()
                except (OSError, ValueError):
                    pass
            import msvcrt
            self.file.seek(0)
            try:
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        finally:
            self.file.close()
            self.file = None
            try:
                atexit.unregister(self.release)
            except Exception:
                pass

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *_):
        self.release()
