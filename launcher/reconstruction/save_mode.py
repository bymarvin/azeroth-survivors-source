"""Which save the co-op game uses.

separate (default): the co-op game reads and writes only <game folder>\\coop-lab\\personal\\characters.txt.
    %APPDATA%\\wenilla-rogue is never read or written; the single-player save is never touched.
shared (opt-in): the single-player save is copied in at start and the co-op progress is merged back at the
    end (personal_save.PersonalSave with backups, merge rules, damage check and Repair-Save.cmd).

The choice is kept in coop-lab\\save-mode.txt. Switching to shared needs the confirmation word.
"""
import hashlib
import os
import time
from pathlib import Path

SEPARATE = 'separate'
SHARED = 'shared'
MODES = (SEPARATE, SHARED)
CONFIRM_WORD = 'SHARE'
MODE_FILE = Path('coop-lab') / 'save-mode.txt'
PROFILE = Path('coop-lab') / 'personal'

SHARED_WARNING = (
    'WARNING: shared saves link the co-op save with your single-player save.\n'
    'The co-op runs game 0.95.0. Mixing its save with a newer single-player game can corrupt or lose\n'
    'heroes, talents and unlocked zones. The co-op keeps backups and merges only what changed in the\n'
    'co-op, but nothing is risk-free.\n'
    'Before you continue, back up the folder %APPDATA%\\wenilla-rogue (copy it somewhere safe).\n'
    'Type ' + CONFIRM_WORD + ' to link the saves, anything else keeps them separate: ')

IMPORT_WARNING = (
    'Copy your single-player heroes into the co-op? This replaces the co-op heroes in coop-lab\\personal\n'
    '(a backup of them is kept next to it). Your single-player save is only read, never changed. [y/N]: ')

FIRST_START_QUESTION = (
    'The co-op keeps its own heroes, separate from your single-player save.\n'
    '  [1] start with new heroes (recommended)\n'
    '  [2] copy my single-player heroes into the co-op once (the single-player save stays unchanged)\n'
    'Choose 1 or 2 [1]: ')

NOTICE_OLD_INSTALL = (
    'NOTICE: co-op saves are now separate from the single-player save. Your single-player save stays as it '
    'is; the co-op continues with its heroes in coop-lab\\personal. To link both again (not recommended): '
    'Start-Coop.cmd --save-mode shared')


def mode_path(root):
    return Path(root) / MODE_FILE


PROFILE_ENV = 'COOP_PROFILE_FOLDER'  # a channel's own co-op profile (0.0.24: coop-lab\personal-0.99.0), set by the start path

FIRST_START_QUESTION_CHANNEL = (
    'This co-op channel keeps its own heroes, separate from your single-player save and from the 0.95.0 co-op.\n'
    '  [1] start with new heroes\n'
    '  [2] copy my single-player heroes into this channel once (the single-player save stays unchanged)\n'
    '  [3] copy my 0.95.0 co-op heroes into this channel once (the 0.95.0 co-op heroes stay unchanged)\n'
    'Choose 1, 2 or 3 [1]: ')


def profile_folder(root):
    """coop-lab\\personal, or the channel's own profile from COOP_PROFILE_FOLDER (relative to root or absolute)."""
    custom = os.environ.get(PROFILE_ENV, '').strip()
    if custom:
        path = Path(custom)
        return path if path.is_absolute() else Path(root) / path
    return Path(root) / PROFILE


def channel_profile(root):
    """A channel's own profile (a newer game than 0.95.0): always separate saves, imports copied unconverted."""
    return profile_folder(root) != Path(root) / PROFILE


def default_profile_save(root):
    """The 0.95.0 co-op heroes (the default profile), the source of an upgrade copy into a channel profile."""
    return Path(root) / PROFILE / 'characters.txt'


def profile_save(root):
    return profile_folder(root) / 'characters.txt'


def single_player_save():
    """Path of the single-player save. Only computed when shared mode or an import needs it."""
    return Path(os.environ['APPDATA']) / 'wenilla-rogue' / 'characters.txt'


def read_mode(root):
    if channel_profile(root):
        return SEPARATE  # shared saves convert for game 0.95.0: only the 0.95.0 channel has them
    try:
        word = mode_path(root).read_text(encoding='utf-8').split()[0].strip().lower()
    except (OSError, UnicodeError, IndexError):
        return SEPARATE
    return word if word in MODES else SEPARATE


def write_mode(root, mode):
    if mode not in MODES:
        raise ValueError('unknown save mode: ' + str(mode))
    path = mode_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(mode + '\n', encoding='utf-8')
    temporary.replace(path)


def first_start_notice(root):
    """Once after the update that made separate the default: returns the NOTICE for installs that used the
    old two-way copy (sp-backup files or a co-op profile exist), and fixes the mode to separate."""
    if channel_profile(root) or mode_path(root).exists():
        return None
    folder = profile_folder(root)
    used_before = folder.is_dir() and (any(folder.glob('sp-backup-*.txt')) or (folder / 'characters.txt').exists())
    write_mode(root, SEPARATE)
    return NOTICE_OLD_INSTALL if used_before else None


def profile_is_empty(root):
    return not profile_save(root).exists()


def status_line(root, mode=None):
    mode = mode or read_mode(root)
    if mode == SHARED:
        return ('[ WARN ] Saves: shared with the single-player save (%APPDATA%\\wenilla-rogue), two-way with backups, '
                'merge and repair; co-op profile ' + str(profile_folder(root)))
    return ('[ INFO ] Saves: separate – co-op heroes in ' + str(profile_save(root)) +
            '; the single-player save is not touched')


def choose_shared(root, ask, say=print):
    """Shows the warning and switches to shared only when the confirmation word is typed."""
    answer = ask(SHARED_WARNING)
    if (answer or '').strip() == CONFIRM_WORD:
        write_mode(root, SHARED)
        say('[  OK  ] Saves are now shared with the single-player save. Undo: Start-Coop.cmd --save-mode separate')
        return True
    write_mode(root, read_mode(root))
    say('[ INFO ] Not confirmed: saves stay ' + read_mode(root) + '.')
    return False


def import_single_player(root, source=None, exe=None, key=None, convert=None):
    """One-way copy single-player save -> co-op profile, as 0.95.0 can read it (newer data mapped by
    azs_savecompat.compat_view). The existing co-op profile is kept as profile-backup-<time>.txt.
    The single-player save is only read. Returns (backup path or None, note).
    In a channel profile (COOP_PROFILE_FOLDER, a newer game) nothing is converted: the save is copied as it is."""
    import azs_rse1 as rse1
    import azs_savecompat as compat
    source = Path(source) if source else single_player_save()
    original = source.read_bytes()
    exe = Path(exe) if exe else Path(root) / 'AzerothSurvivors.exe'
    key = key or rse1.key_from_exe(exe, original)
    nonce, text = rse1.open_save(original, key)
    reasons = compat.newer_format_reasons(text) if (not channel_profile(root) if convert is None else convert) else []
    if reasons:
        expected = compat.compat_view(text)
        sealed = rse1.seal(expected, key)
        note = 'converted for game 0.95.0 (%d newer entries mapped or left out)' % len(reasons)
    else:
        expected, sealed = text, original
        note = 'copied unchanged'
    if rse1.open_save(sealed, key)[1] != expected:
        raise ValueError('the converted save did not reopen')
    folder = profile_folder(root)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / 'characters.txt'
    backup = None
    if target.exists():
        old = target.read_bytes()
        if old == sealed:
            return None, 'already the same heroes'
        backup = folder / ('profile-backup-%s-%s.txt' % (time.strftime('%Y%m%d-%H%M%S'), hashlib.sha256(old).hexdigest()[:12]))
        backup.write_bytes(old)
    temporary = folder / 'characters.import.tmp'
    temporary.write_bytes(sealed)
    temporary.replace(target)
    return backup, note


def first_start(root, ask, say=print, **import_args):
    """Separate mode with an empty co-op profile: new heroes or a one-time copy of the single-player heroes."""
    channel = channel_profile(root)
    answer = (ask(FIRST_START_QUESTION_CHANNEL if channel else FIRST_START_QUESTION) or '1').strip()
    if channel and answer == '3':
        try:
            _, note = import_single_player(root, default_profile_save(root), convert=False,
                                           **{k: v for k, v in import_args.items() if k != 'source'})
        except (OSError, KeyError, ValueError) as error:
            say('[ WARN ] Could not copy the 0.95.0 co-op heroes (%s); this channel starts with new heroes.' % error)
            return False
        say('[  OK  ] 0.95.0 co-op heroes copied into this channel (' + note + ').')
        return True
    if answer != '2':
        say('[  OK  ] The co-op starts with new heroes.')
        return False
    try:
        _, note = import_single_player(root, **import_args)
    except (OSError, KeyError, ValueError) as error:
        say('[ WARN ] Could not copy the single-player heroes (%s); the co-op starts with new heroes.' % error)
        return False
    say('[  OK  ] Single-player heroes copied into the co-op (' + note + ').')
    return True


# ------------------------------------------------------------------ room browser "Saves" panel (0.0.23)
# The same rules as above without console questions: the page asks the player and sends the answer.
# Every change holds the profile lock (refused while a co-op round runs), backs up first and writes atomically.

class Refused(Exception):
    """A change the player cannot make right now; the message is shown as it is."""


GAME_RUNNING = 'Close the game first: saves cannot be changed while Azeroth Survivors is running.'
COOP_RUNNING = 'Close the co-op game first: saves cannot be changed while a co-op round is running.'
NO_APPDATA = 'The single-player save folder (APPDATA) is unknown; nothing changed.'


def game_running():
    """True while any AzerothSurvivors*.exe runs (single-player or co-op)."""
    if os.name != 'nt':
        return False
    import subprocess
    try:
        out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True, text=True, timeout=10,
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return any(line.strip('"').lower().startswith('azerothsurvivors') for line in out.splitlines())


class profile_lock:
    """The co-op session lock (personal_save.PersonalSave holds it while a round runs)."""

    def __init__(self, root):
        self.path = profile_folder(root) / 'session.lock'

    def __enter__(self):
        import msvcrt
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open('a+b')
        self.file.seek(0)
        try:
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.file.close()
            raise Refused(COOP_RUNNING) from None
        return self

    def __exit__(self, *_):
        import msvcrt
        self.file.seek(0)
        msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
        self.file.close()


def _stamp(data):
    return '%s-%s' % (time.strftime('%Y%m%d-%H%M%S'), hashlib.sha256(data).hexdigest()[:12])


def _source(source):
    try:
        return Path(source) if source else single_player_save()
    except KeyError:
        raise Refused(NO_APPDATA) from None


def _key_and_text(root, data, exe, key):
    import azs_rse1 as rse1
    key = key or rse1.key_from_exe(Path(exe) if exe else Path(root) / 'AzerothSurvivors.exe', data)
    return key, rse1.open_save(data, key)[1]


def single_player_state(root, exe=None, key=None, source=None):
    """'unknown' (no APPDATA), 'missing', 'old', 'newer' or 'unreadable'."""
    import azs_savecompat as compat
    try:
        data = _source(source).read_bytes()
    except Refused:
        return 'unknown'
    except OSError:
        return 'missing'
    try:
        _, text = _key_and_text(root, data, exe, key)
    except (OSError, ValueError):
        return 'unreadable'
    return 'newer' if compat.newer_format_reasons(text) else 'old'


def panel_status(root, exe=None, key=None, source=None):
    """Everything the Saves panel shows."""
    mode = read_mode(root)
    folder = profile_folder(root)
    kept = ('sp-', 'profile-backup-', 'damaged-', 'retained-')
    backups = [p for p in folder.glob('*.txt') if p.name.startswith(kept)] if folder.is_dir() else []
    return dict(mode=mode, line=status_line(root, mode), profile=str(profile_save(root)), heroes=not profile_is_empty(root),
                first_start=mode == SEPARATE and profile_is_empty(root), channel_profile=channel_profile(root),
                coop095_heroes=channel_profile(root) and default_profile_save(root).is_file(),
                single_player=single_player_state(root, exe, key, source), backups=len(backups), word=CONFIRM_WORD)


def set_mode_confirmed(root, mode, word=None, source=None, running=None):
    """Separate: always allowed (the undo). Shared: only with the exact word; the single-player save is copied to
    coop-lab\\personal\\sp-pre-share-<time>-<sha12>.txt before the mode changes."""
    if mode not in MODES:
        raise Refused('Unknown save mode.')
    if read_mode(root) == mode:
        return dict(changed=False, backup=None)
    if mode == SHARED:
        if channel_profile(root):
            raise Refused('Shared saves are only for the 0.95.0 co-op channel; this channel always keeps its own heroes.')
        if (word or '').strip() != CONFIRM_WORD:
            raise Refused('Not linked: type %s exactly to share saves. Nothing changed.' % CONFIRM_WORD)
        if game_running() if running is None else running:
            raise Refused(GAME_RUNNING)
    with profile_lock(root):
        backup = None
        if mode == SHARED:
            source = _source(source)
            if source.is_file():
                data = source.read_bytes()
                target = profile_folder(root) / ('sp-pre-share-%s.txt' % _stamp(data))
                target.write_bytes(data)
                if target.read_bytes() != data:
                    raise Refused('The backup of the single-player save failed; nothing changed.')
                backup = target.name
        write_mode(root, mode)
    return dict(changed=True, backup=backup)


def import_confirmed(root, source=None, exe=None, key=None):
    """One-way import of the single-player heroes (separate mode only), under the profile lock."""
    if read_mode(root) != SEPARATE:
        raise Refused('Importing is for separate saves; with shared saves the co-op already uses your single-player heroes.')
    source = _source(source)
    with profile_lock(root):
        try:
            key, _ = _key_and_text(root, source.read_bytes(), exe, key)
            backup, note = import_single_player(root, source, exe, key)
        except FileNotFoundError:
            raise Refused('No single-player save found; nothing changed.') from None
        except (OSError, ValueError) as error:
            raise Refused('The single-player save could not be read (%s); nothing changed.' % error) from None
    return dict(note=note, backup=backup.name if backup else None)


def import_coop_confirmed(root, exe=None, key=None):
    """Channel profile only: one upgrade copy of the 0.95.0 co-op heroes (never back), under the profile lock."""
    if not channel_profile(root):
        raise Refused('Copying the 0.95.0 co-op heroes is for the 0.99.0 channel.')
    source = default_profile_save(root)
    with profile_lock(root):
        try:
            key, _ = _key_and_text(root, source.read_bytes(), exe, key)
            backup, note = import_single_player(root, source, exe, key, convert=False)
        except FileNotFoundError:
            raise Refused('There are no 0.95.0 co-op heroes yet; nothing changed.') from None
        except (OSError, ValueError) as error:
            raise Refused('The 0.95.0 co-op heroes could not be read (%s); nothing changed.' % error) from None
    return dict(note=note, backup=backup.name if backup else None)


def repair_check(root, source=None, exe=None, key=None):
    """The check of Repair-Save.cmd (tools/repair_save.py), reading only.
    state: healthy | nothing_to_compare | damaged | missing | unreadable."""
    import azs_rse1 as rse1
    import azs_savecompat as compat
    try:
        data = _source(source).read_bytes()
    except (Refused, OSError):
        return dict(state='missing', lost=[], backup=None, sha256=None)
    sha = hashlib.sha256(data).hexdigest()
    try:
        key, current = _key_and_text(root, data, exe, key)
    except (OSError, ValueError):
        return dict(state='unreadable', lost=[], backup=None, sha256=sha)
    # sp-backups come from shared mode, which only the 0.95.0 profile has
    backups = sorted((Path(root) / PROFILE).glob('sp-backup-*.txt'), key=lambda p: p.stat().st_mtime, reverse=True)
    for backup in backups:
        try:
            _, before = rse1.open_save(backup.read_bytes(), key)
        except (rse1.Rse1Error, OSError):
            continue
        if not compat.newer_format_reasons(before):
            continue
        lost, _ = compat.damage_report(current, before)
        return dict(state='damaged' if lost else 'healthy', lost=lost, backup=backup.name, sha256=sha)
    return dict(state='nothing_to_compare', lost=[], backup=None, sha256=sha)


def repair_confirmed(root, sha256, source=None, exe=None, key=None, running=None):
    """Applies the checked repair, only if the save still has the checked SHA-256. The damaged save is kept as
    characters-damaged-<time>.txt next to it (as Repair-Save.cmd does)."""
    import azs_rse1 as rse1
    import azs_savecompat as compat
    if game_running() if running is None else running:
        raise Refused(GAME_RUNNING)
    source = _source(source)
    with profile_lock(root):
        check = repair_check(root, source, exe, key)
        if check['state'] != 'damaged':
            raise Refused('Nothing to repair.')
        if check['sha256'] != sha256:
            raise Refused('The save changed after the check; check again.')
        data = source.read_bytes()
        key, current = _key_and_text(root, data, exe, key)
        _, before = rse1.open_save((Path(root) / PROFILE / check['backup']).read_bytes(), key)
        lost, repaired = compat.damage_report(current, before)
        sealed = rse1.seal(repaired, key)
        if rse1.open_save(sealed, key)[1] != repaired:
            raise Refused('The repaired save did not read back; nothing written.')
        keep = source.with_name('characters-damaged-%s.txt' % time.strftime('%Y%m%d-%H%M%S'))
        keep.write_bytes(data)
        temporary = source.with_name('characters.repair.tmp')
        temporary.write_bytes(sealed)
        temporary.replace(source)
    return dict(lost=lost, kept=keep.name, backup=check['backup'])


def panel_request(root, data, open_folder=None):
    """One request of the Saves panel: {'op': 'status'|'mode'|'import'|'repair_check'|'repair'|'open_folder', ...}."""
    op = data.get('op')
    if op == 'status':
        return panel_status(root)
    if op == 'mode':
        return set_mode_confirmed(root, str(data.get('mode')), data.get('word'))
    if op == 'import':
        if data.get('confirm') is not True:
            raise Refused('Import not confirmed; nothing changed.')
        return import_confirmed(root)
    if op == 'import_coop':
        if data.get('confirm') is not True:
            raise Refused('Import not confirmed; nothing changed.')
        return import_coop_confirmed(root)
    if op == 'repair_check':
        return repair_check(root)
    if op == 'repair':
        if data.get('confirm') is not True:
            raise Refused('Repair not confirmed; nothing changed.')
        return repair_confirmed(root, str(data.get('sha256')))
    if op == 'open_folder':
        folder = profile_folder(root)
        folder.mkdir(parents=True, exist_ok=True)
        (open_folder or os.startfile)(str(folder))
        return dict(opened=str(folder))
    raise Refused('Unknown action.')
