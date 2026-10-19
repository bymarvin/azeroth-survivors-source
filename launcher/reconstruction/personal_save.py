"""Stage native SP saves, retaining backups and refusing concurrent overwrite.

Mode "separate" (default, see save_mode.py): the co-op profile is the game's only save. Nothing in
%APPDATA%/wenilla-rogue is read or written and commit() does nothing. Mode "shared": the rest of this
module (copy in, merge back, backups, repair).

The co-op runs game 0.95.0. A single-player save written by a newer game (0.96+: `open` zone lines,
12 zones, PvP items) is handed to 0.95.0 as a compatible view, and the result is merged back into
the original instead of replacing it (rules: azs_savecompat / MERGE-RULES.md). A save that cannot
be read safely is never overwritten. A single-player save already damaged by an earlier co-op
write-back is repaired at start from the newest matching sp-backup.
"""
import hashlib
import base64
import binascii
import os
from pathlib import Path

import azs_rse1 as rse1
import azs_savecompat as compat
import save_mode

GAME_EXE = Path(__file__).resolve().parents[1] / 'AzerothSurvivors.exe'


def session_lock(folder):
    """The co-op session lock of this profile; a refusal names the window that holds it (0.0.24)."""
    from coop_lock import FolderLock, LockBusy
    lock = FolderLock(Path(folder) / 'session.lock', 'co-op session')
    try:
        return lock.acquire(busy_text='Your co-op character save is already in use by {owner}. Close that co-op '
                                      'window; if none is open, end the leftover "python.exe" of Azeroth Survivors '
                                      'Together in Task Manager, then start again.')
    except LockBusy as error:
        raise RuntimeError(str(error)) from None


class PersonalSave:
    def __init__(self, folder, source=None, exe=None, key=None, mode=save_mode.SEPARATE):
        if mode not in save_mode.MODES:
            raise ValueError('unknown save mode: ' + str(mode))
        self.mode = mode
        self.folder = Path(folder)
        if mode == save_mode.SEPARATE:
            # the co-op profile is the save; the single-player save is not even located
            self.source = None
            self.original = None
            self.staged = None
            self.notice = None
            self.unreadable = False
            self.original_text = self.given_text = None
            self.folder.mkdir(parents=True, exist_ok=True)
            self.target = self.folder / 'characters.txt'
            self.lock = session_lock(self.folder)
            return
        self.source = Path(source) if source else Path(os.environ['APPDATA']) / 'wenilla-rogue/characters.txt'
        self.exe = Path(exe) if exe else GAME_EXE
        self.key = key
        self.notice = None          # message for the player (repair done, save kept separately, ...)
        self.original_text = None   # plaintext of the original when it is newer than 0.95.0
        self.given_text = None      # what 0.95.0 got instead (compat view / last merged result)
        self.unreadable = False     # original could not be opened: never overwrite it
        self.staged = None          # bytes handed to the game
        self.folder.mkdir(parents=True, exist_ok=True)
        self.lock = session_lock(self.folder)
        try:
            self.original = self.source.read_bytes() if self.source.exists() else None
            if self.original is not None:
                self._repair_damage()
            self.target = self.folder / 'characters.txt'
            if self.target.exists():
                previous = self.target.read_bytes()
                if previous != self.original:
                    retained = self.folder / ('retained-' + hashlib.sha256(previous).hexdigest() + '.txt')
                    if not retained.exists():
                        retained.write_bytes(previous)
            if self.original is not None:
                self.staged = self._staged(self.original)
                self.target.write_bytes(self.staged)
            elif self.target.exists():
                # Never silently reuse another previous profile when SP is empty.
                self.target.unlink()
        except Exception:
            self.close()
            raise

    # ------------------------------------------------------------------ newer saves

    def _key_for(self, sealed):
        if self.key is None:
            self.key = rse1.key_from_exe(self.exe, sealed)
        return self.key

    def _open(self, sealed):
        return rse1.open_save(sealed, self._key_for(sealed))

    def _staged(self, original):
        """What 0.95.0 gets: the original itself, or its compatible view when it is newer."""
        try:
            _, text = self._open(original)
        except (rse1.Rse1Error, OSError):
            self.unreadable = True
            self.notice = ('Your single-player save could not be checked; the co-op keeps its '
                           'progress separately and will not overwrite it.')
            return original
        if not compat.newer_format_reasons(text):
            return original
        keep = self.folder / ('sp-original-' + hashlib.sha256(original).hexdigest() + '.txt')
        if not keep.exists():
            keep.write_bytes(original)
        self.original_text = text
        self.given_text = compat.compat_view(text)
        return rse1.seal(self.given_text, self.key)

    def _repair_damage(self):
        """An earlier co-op write-back may have dropped the zones of a newer save. Compare with
        the newest backup that is newer than 0.95.0 and merge the lost data back in."""
        try:
            _, current = self._open(self.original)
        except (rse1.Rse1Error, OSError):
            return
        backups = sorted(self.folder.glob('sp-backup-*.txt'), key=lambda p: p.stat().st_mtime, reverse=True)
        for backup in backups:
            try:
                _, before = self._open(backup.read_bytes())
            except (rse1.Rse1Error, OSError):
                continue
            if not compat.newer_format_reasons(before):
                continue
            lost, repaired = compat.damage_report(current, before)
            if not lost:
                return
            damaged = self.folder / ('damaged-' + hashlib.sha256(self.original).hexdigest() + '.txt')
            if not damaged.exists():
                damaged.write_bytes(self.original)
            fixed = rse1.seal(repaired, self.key)
            if self._open(fixed)[1] != repaired:
                return
            temporary = self.source.with_name('characters.coop.tmp')
            temporary.write_bytes(fixed)
            temporary.replace(self.source)
            self.original = fixed
            self.notice = 'Restored what an earlier co-op session lost: ' + '; '.join(lost)
            return

    def _merged(self, result):
        """The original with only the co-op's changes, sealed; raises when that is not safe."""
        _, result_text = self._open(result)
        merged, _ = compat.merge(self.original_text, self.given_text, result_text)
        before = compat.opened_zone_counts(self.original_text)
        after = compat.opened_zone_counts(merged)
        if any(after.get(c, -1) < rank for c, rank in before.items()):
            raise RuntimeError('Merging the co-op progress would lose zones; both saves retained separately')
        sealed = rse1.seal(merged, self.key)
        if self._open(sealed)[1] != merged:
            raise RuntimeError('Merged save did not reopen; both saves retained separately')
        return sealed, merged, result_text

    # ------------------------------------------------------------------ commit

    def commit(self):
        if self.mode == save_mode.SEPARATE:
            return  # the game saved into the co-op profile itself; nothing goes to the single-player save
        if not self.target.exists():
            return
        result = self.target.read_bytes()
        if result == self.original or result == self.staged:
            return
        if not 32 <= len(result) <= 4 * 1024 * 1024 or not result.startswith(b'RSE1:'):
            raise ValueError('Native save was not recognized; retained in the co-op profile')
        try:
            envelope = base64.b64decode(result[5:], validate=True)
        except binascii.Error:  # One damaged character can leave the base64 alphabet: same answer, clear text.
            raise ValueError('Native save envelope is damaged; retained in the co-op profile') from None
        if len(envelope) < 28:
            raise ValueError('Native save envelope is incomplete; retained in the co-op profile')
        if self.unreadable:
            raise RuntimeError('Single-player save could not be checked; co-op progress retained separately')
        merged_text = result_text = None
        if self.original_text is not None:
            try:
                result, merged_text, result_text = self._merged(result)
            except (rse1.Rse1Error, compat.MergeError, ValueError) as error:
                raise RuntimeError('Co-op progress could not be merged safely (%s); both saves retained separately' % error) from None
            if merged_text == self.original_text:
                self.given_text, self.staged = result_text, self.target.read_bytes()
                return  # 0.95.0 saved, but nothing the original lacks
        current = self.source.read_bytes() if self.source.exists() else None
        if current != self.original:
            raise RuntimeError('Single-player save changed during co-op; both saves retained separately')
        self.source.parent.mkdir(parents=True, exist_ok=True)
        if current is not None:
            backup = self.folder / ('sp-backup-' + hashlib.sha256(current).hexdigest() + '.txt')
            if not backup.exists():
                backup.write_bytes(current)
        temporary = self.source.with_name('characters.coop.tmp')
        temporary.write_bytes(result)
        temporary.replace(self.source)
        self.original = result
        if merged_text is not None:
            # the next round end merges onto this save; 0.95.0 now holds `result_text`
            self.original_text, self.given_text = merged_text, result_text
            self.staged = self.target.read_bytes()

    def close(self):
        self.lock.release()
