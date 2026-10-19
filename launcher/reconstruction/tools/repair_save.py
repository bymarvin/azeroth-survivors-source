"""Repair a single-player save whose zones an earlier co-op round lost (game 0.95.0 wrote a newer save back).

Started by Repair-Save.cmd in the game folder (game and co-op launcher closed), with the co-op's own Python:
  .coop-runtime\\python.exe reconstruction\\tools\\repair_save.py [--save <characters.txt>] [--backup <sp-backup-…txt>] [--write]

Without --backup the newest sp-backup-*.txt in coop-lab\\personal that is newer than 0.95.0 is used. Without
--write it only reports. With --write the damaged save is kept as characters-damaged-<time>.txt next to it, then
the repaired save replaces it. Co-op progress stays (talents, gold, items, ...); zones and newer data come back
from the backup. Rules: azs_savecompat (damage_report). Not part of the bound adapter identity (subfolder).
"""
import argparse
import os
import sys
import time
from pathlib import Path

GAME = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(GAME / 'reconstruction'))
import azs_rse1 as rse1  # noqa: E402
import azs_savecompat as compat  # noqa: E402


def log(tag, text):
    sys.stdout.write('[%s] %s\n' % (tag, text))
    sys.stdout.flush()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--exe', default=str(GAME / 'AzerothSurvivors.exe'), help='game exe (for the save key)')
    ap.add_argument('--save', default=str(Path(os.environ.get('APPDATA', '.')) / 'wenilla-rogue' / 'characters.txt'))
    ap.add_argument('--backup', help='sp-backup-*.txt (default: the newest newer-format one in coop-lab\\personal)')
    ap.add_argument('--personal', default=str(GAME / 'coop-lab' / 'personal'))
    ap.add_argument('--write', action='store_true', help='repair (otherwise only report)')
    a = ap.parse_args(argv)
    started = time.time()
    save = Path(a.save)
    log(' .... ', 'Reading the single-player save %s' % save)
    if not save.is_file():
        log('FAILED', 'No single-player save found at %s' % save)
        return 1
    current_bytes = save.read_bytes()
    try:
        key = rse1.key_from_exe(a.exe, current_bytes)
        _, current = rse1.open_save(current_bytes, key)
    except (rse1.Rse1Error, OSError) as error:
        log('FAILED', 'The save could not be opened (%s); nothing changed' % error)
        return 1
    log('  OK  ', 'Reading the single-player save (%d bytes)' % len(current_bytes))
    candidates = ([Path(a.backup)] if a.backup else
                  sorted(Path(a.personal).glob('sp-backup-*.txt'), key=lambda p: p.stat().st_mtime, reverse=True))
    for backup in candidates:
        try:
            _, before = rse1.open_save(backup.read_bytes(), key)
        except (rse1.Rse1Error, OSError) as error:
            log(' WARN ', '%s: %s' % (backup.name, error))
            continue
        if not compat.newer_format_reasons(before):
            log(' INFO ', '%s: an old (0.95) save, nothing could get lost' % backup.name)
            continue
        lost, repaired = compat.damage_report(current, before)
        if not lost:
            log('  OK  ', 'Nothing lost compared with %s' % backup.name)
            return 0
        for item in lost:
            log(' WARN ', 'Lost: ' + item)
        if not a.write:
            log(' INFO ', 'Checked only; repair with --write (source %s)' % backup.name)
            return 2  # Repair-Save.cmd asks whether to repair.
        if rse1.open_save(rse1.seal(repaired, key), key)[1] != repaired:
            log('FAILED', 'The repaired save did not read back; nothing written')
            return 1
        keep = save.with_name('characters-damaged-%s.txt' % time.strftime('%Y%m%d-%H%M%S'))
        keep.write_bytes(current_bytes)
        temporary = save.with_name('characters.repair.tmp')
        temporary.write_bytes(rse1.seal(repaired, key))
        temporary.replace(save)
        log('  OK  ', 'Repaired from %s, the old save kept as %s (%.1f s)' % (backup.name, keep.name, time.time() - started))
        return 0
    log(' INFO ', 'No backup of a newer save found in %s; nothing to repair' % a.personal)
    return 0


if __name__ == '__main__':
    sys.exit(main())
