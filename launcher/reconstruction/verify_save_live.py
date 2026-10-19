"""0.0.22 live save checks, one game window each (disposable profiles only).

  verify_save_live.py [--save097 <copy of a 0.97 save>] [--seconds 150]

Case separate: a fresh co-op profile (save mode "separate", no single-player save) is handed to game 0.95.0
through PersonalSave; the game must write its save there (RSE1, opens with this exe's key, counts our run: the run ends with one lethal hit).
Case save097 (with --save097 or COOP_SAVE097): game 0.95.0 loads a COPY of a newer (0.97) save and writes it back;
logged is what it kept (records, zones) — the assumption behind MERGE-RULES.md: 0.95.0 drops what it cannot read.
Both cases: the real %APPDATA%\\wenilla-rogue is neither written (every file's size and mtime before = after) nor
opened by this process (audit hook); the game itself runs with APPDATA and WOW_ROGUE_SAVE pointing into the profile.
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REAL = Path(os.environ.get('APPDATA', '')) / 'wenilla-rogue'
NO_SAVE_SECONDS = 60  # From the run start: 15 s play + lethal hit + run end must write the save well within this.
NO_END_SECONDS = 10  # The hero must fall within 10 s of the first lethal hit.
NO_START_SECONDS = 40  # Game load (~10 s) + 30 s in phase 0: the run did not start.


def log(tag, text):
    print(f'[{tag:^6}] {time.strftime("%H:%M:%S")} {text}', flush=True)


def snapshot():
    """Name, size and mtime of every file below the real single-player folder (stat only, nothing opened)."""
    if not REAL.is_dir():
        return {}
    return {p.relative_to(REAL).as_posix(): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in REAL.rglob('*') if p.is_file()}


def guard_real_folder(touched):
    real = str(REAL.resolve()).lower()

    def hook(event, args):
        if event == 'open' and args and isinstance(args[0], (str, bytes, os.PathLike)):
            path = os.fsdecode(args[0])
            try:
                full = str(Path(path).resolve()).lower()
            except (OSError, ValueError):
                return
            if full.startswith(real):
                touched.append(path)
                raise PermissionError(f'save check: {path} is the real single-player folder')
    sys.addaudithook(hook)


def play(folder, character, seconds, key_exe):
    """One window on `folder`'s characters.txt: start a run, end it with a lethal hit (the game writes its save at
    run end), stop a few seconds after the save was written."""
    import struct
    from native_guest_combat import NativeCombatBridge
    from party_menu import PartyMenu
    from native_probe import CHOOSE, HURT, game_field, run
    from verify_network_coop import NetworkCoopVerification
    target = folder / 'characters.txt'
    before = target.stat().st_mtime_ns if target.exists() else None
    started = time.monotonic()
    events = []

    class Session(PartyMenu, NativeCombatBridge):  # As room_client.play builds its solo game.
        written_at = None
        no_start = False
        defeat_hit = False
        playing_since = None
        reported = -1
        next_hit = 0.0
        first_hit = None
        no_end = None
        waited = None
        last_lethal_state = None
        loaded_at = None

        def record(self, **event):
            if event.get('event') in ('native_state', 'native_serialize', 'save_live_lethal_hit',
                                      'network_lethal_state', 'save_live_lethal_wait'):
                events.append(event)
            super().record(**event)

        def poll_network(self):
            now = time.monotonic()
            if self.playing_since is None and now - started > NO_START_SECONDS:
                self.no_start = True  # The run never began: stop instead of waiting the whole session.
                self.stop_requested = True
                return
            phase = self.native_states.get(1, (None,))[0]
            if phase == 0 and 1 in self.loaded and 1 not in self.ready:
                # The bridge starts the run once native movement proved the game constructed (MOVE -> ready; only
                # ready players reach before_batch). With a loaded save the diagnostic W can fall before the hero
                # lands and no movement is sent: the cleared loading screen proves the game too, so 8 s after it
                # the verifier marks the player ready and the bridge's own START follows.
                self.loaded_at = self.loaded_at or now
                if now - self.loaded_at >= 8:
                    self.ready.add(1)
                    self.record(event='save_live_ready_without_movement', player=1)
                    log(' WARN ', f'{folder.name}: no native movement 8 s after loading; run started without it')
            if (self.playing_since is not None and self.written_at is None
                    and now - self.playing_since > NO_SAVE_SECONDS):
                # Any other stall after the start (talent menu not taken, pause, no enemy for the hit): stop with the
                # phase instead of waiting the whole session.
                self.no_end = dict(stalled_phase=phase, lethal_state=self.last_lethal_state)
                self.stop_requested = True
                return
            if self.first_hit is not None and phase in (1, 2, 3) and now - self.first_hit > NO_END_SECONDS:
                # The hero still lives 10 s after the first lethal hit: stop with the reason, no hit storm.
                self.no_end = self.last_lethal_state
                self.stop_requested = True
                return
            written = target.exists() and target.stat().st_mtime_ns != before and target.stat().st_size > 0
            if written and self.written_at is None:
                self.written_at = now
                log(' INFO ', f'the game wrote {target.name} after {now - started:.0f} s')
            if int(now - started) % 10 == 0 and int(now - started) != self.reported:
                self.reported = int(now - started)
                log(' LIVE ', f'{folder.name}: {now - started:.0f} s, phase {self.native_states.get(1, (None,))[0]}, '
                              f'lethal hit {self.defeat_hit}, written {self.written_at is not None}')
            self.stop_requested = self.written_at is not None and now - self.written_at >= 5

        def before_batch(self, client, context):
            game = client.server + 0x10
            phase = self.native_states.get(client.number, (0,))[0]
            if phase == 2:  # Level-up: take a talent, as the boss tests do.
                count = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
                if 1 <= count <= 16:
                    client.call_before(context, CHOOSE, game, 0)
                    return True
            if phase == 1:
                now = time.monotonic()
                self.playing_since = self.playing_since or now
                if (not self.defeat_hit and self.enemy_snapshot and now - self.playing_since >= 15
                        and now >= self.next_hit):
                    # As verify_network_coop: native HURT ignores hits during a type-0xb guard buff; wait it out.
                    guards = NetworkCoopVerification.lethal_guard_buffs(self, client, game)
                    if guards:
                        if self.waited != len(guards):
                            self.waited = len(guards)
                            self.record(event='save_live_lethal_wait', player=client.number, guard_buffs=guards)
                        return super().before_batch(client, context)
                    self.defeat_hit = True
                    self.next_hit = now + 1  # At most one diagnostic hit per second (never starve the frame).
                    self.first_hit = self.first_hit or now
                    self.record(event='save_live_lethal_hit', player=client.number)
                    diagnose = NetworkCoopVerification.lethal_diagnostics(self, client, game)
                    diagnose('before')

                    def completed():
                        self.last_lethal_state = diagnose('after')
                        if self.last_lethal_state['phase'] == 1:
                            self.defeat_hit = False  # Ignored: again in a second.
                    client.call_before(context, HURT, game, next(iter(self.enemy_snapshot)), damage=100000,
                                       after=completed)
                    return True
            return super().before_batch(client, context)

    # The bridge starts the run (START) once all room members are loaded: a solo room has one member (Bridge reads
    # COOP_PLAYERS, default 2, so without this it waits for a second player forever: "Move to begin.").
    # The game's own diagnostic key holds W after 3 s as in the movement suite; the game inherits both from here.
    saved = {k: os.environ.get(k) for k in ('COOP_PLAYERS', 'WOW_ROGUE_KEY')}
    os.environ.update(COOP_PLAYERS='1', WOW_ROGUE_KEY='w@3')
    with (folder / 'save-live.jsonl').open('w', encoding='utf-8') as output:
        session = Session(output)
        session.autostart, session.host_map = True, 'elwynn'
        session.profile_folder = folder
        session.character_names = {1: character}
        getattr(session, 'start_log_writer', lambda: None)()
        try:
            run(seconds, 1, session, player_numbers=[1])
        except TimeoutError:
            if not (session.no_start or session.no_end is not None):  # A stop in phase 0 never drains; the clear reason follows below.
                raise
        finally:
            getattr(session, 'stop_log_writer', lambda: None)()
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    if session.no_end is not None:
        log('FAILED', f'{folder.name}: run did not end (no save {NO_END_SECONDS} s after the lethal hit or {NO_SAVE_SECONDS} s after the start); '
                      f'state after the last hit {session.no_end}')
        raise AssertionError(f'{folder.name}: run did not end after the lethal hit: {session.no_end}')
    if session.no_start:
        log('FAILED', f'{folder.name}: run did not start: no movement sent (phase 0 for {NO_START_SECONDS} s)')
        raise AssertionError(f'{folder.name}: run did not start: no movement sent')
    return session.written_at is not None, events


def opened(data, exe):
    import azs_rse1 as rse1
    key = rse1.key_from_exe(exe, data)
    return rse1.open_save(data, key)[1]


def summary(text):
    import azs_savecompat as compat
    kinds = {}
    for line in compat.split_lines(text):
        kinds[line.split('|')[0]] = kinds.get(line.split('|')[0], 0) + 1
    return dict(records=kinds, newer=compat.newer_format_reasons(text)[:3], zones=compat.opened_zone_counts(text))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--save097', type=Path, default=os.environ.get('COOP_SAVE097') or None)
    ap.add_argument('--seconds', type=int, default=150)
    args = ap.parse_args()
    import native_probe
    from personal_save import PersonalSave
    import save_mode
    home = native_probe._candidate_home
    if home is None:
        raise SystemExit('verify_save_live runs only as a candidate acceptance (disposable saves)')
    if not args.save097 or not Path(args.save097).is_file():
        raise SystemExit('verify_save_live needs --save097 or COOP_SAVE097: a COPY of a 0.97 save (never the real one)')
    exe = native_probe.EXECUTABLE
    touched = []
    before = snapshot()
    log(' INFO ', f'real single-player folder: {len(before)} files, watched (stat only)')
    guard_real_folder(touched)
    result = {}

    log(' .... ', 'separate: fresh co-op profile, no single-player save')
    folder = home / 'separate-profile'
    save = PersonalSave(folder, mode=save_mode.SEPARATE)
    try:
        assert not save.target.exists(), 'fresh profile is not empty'
        written, events = play(save.folder, 'Hero', args.seconds, exe)
        save.commit()  # separate: nothing to copy anywhere
    finally:
        save.close()
    assert written, 'the game did not write the fresh co-op profile'
    text = opened(save.target.read_bytes(), exe)
    # After a lost run 0.95.0 writes no pick line (no hero name), only its account records: our run must count.
    runs = next((int(f.split('=')[1]) for l in text.splitlines() if l.startswith('stat|')
                 for f in l.split('|')[1].split(',') if f.startswith('runs=')), 0)
    assert runs >= 1, ('the written save does not count our run', text[:200])
    result['separate'] = dict(written=True, serialize_events=sum(e['event'] == 'native_serialize' for e in events),
                              size=save.target.stat().st_size, **summary(text))
    log('  OK  ', f'separate: the game wrote its own profile ({result["separate"]["size"]} bytes, '
                  f'records {result["separate"]["records"]})')

    if True:  # The 0.97 round trip is part of the check (the copy is required above).
        log(' .... ', f'save097: game 0.95.0 loads and writes a copy of {Path(args.save097).name}')
        folder = home / 'save097-profile'
        folder.mkdir(parents=True, exist_ok=True)
        source_hash = hashlib.sha256(Path(args.save097).read_bytes()).hexdigest()
        shutil.copyfile(args.save097, folder / 'characters.txt')
        original = (folder / 'characters.txt').read_bytes()
        original_text = opened(original, exe)
        assert summary(original_text)['newer'], 'the --save097 copy is not newer than 0.95.0'
        name = next((l.split('|')[5] for l in original_text.splitlines() if l.startswith('pick|')), 'Hero')
        written, events = play(folder, name, args.seconds, exe)
        after = (folder / 'characters.txt').read_bytes()
        result['save097'] = dict(written=written and after != original, before=summary(original_text),
                                 after=summary(opened(after, exe)) if after != original else None,
                                 sha256_before=hashlib.sha256(original).hexdigest(),
                                 sha256_after=hashlib.sha256(after).hexdigest())
        if result['save097']['after']:
            lost = [k for k in result['save097']['before']['records'] if k not in result['save097']['after']['records']]
            result['save097']['records_dropped'] = lost
            log('  OK  ', f'save097: 0.95.0 wrote the save back; records dropped {lost}, zones before '
                          f'{result["save097"]["before"]["zones"]} after {result["save097"]["after"]["zones"]}')
        assert result['save097']['written'], 'save097: game 0.95.0 did not write the 0.97 save back'
        # The 0.97 save given to the check (itself a copy) is never touched: only its copy in the profile is played.
        assert hashlib.sha256(Path(args.save097).read_bytes()).hexdigest() == source_hash, 'save097 source changed'
        result['save097']['source_unchanged'] = source_hash
        log('  OK  ', f'save097: source copy unchanged (sha256 {source_hash[:16]}…), profile copy written by the game')

    after = snapshot()
    assert after == before, ('the real single-player folder changed',
                             sorted(set(before.items()) ^ set(after.items()))[:5])
    assert not touched, ('this process opened the real single-player folder', touched[:3])
    result['appdata_untouched'] = dict(files=len(after), opened=0)
    log('  OK  ', f'real single-player folder untouched ({len(after)} files, size and mtime equal, never opened)')
    print(json.dumps(dict(save_live=result)), flush=True)


if __name__ == '__main__':
    main()
