"""Native-picker check using disposable stand-in SP saves, never real SP data.

Inspect each picker and create its printed done marker to continue. The second
picker reads a fresh PersonalSave staging folder after the first commit.
"""
import hashlib
import json
import struct
import uuid
import argparse
import os
from pathlib import Path

from personal_save import PersonalSave

ROOT = Path(__file__).resolve().parents[1]


def native_unlocks(client, account):
    from native_probe import MENU_CONTRACT, ACTIVE_HASH
    from build_hooks import UPDATED_HASH
    if MENU_CONTRACT:
        if MENU_CONTRACT.get('sha256') != ACTIVE_HASH or not MENU_CONTRACT.get('menu_contract_verified'):
            raise ValueError('Native account schema is not verified for this executable')
        schema = MENU_CONTRACT['account_config']['account']
        if MENU_CONTRACT['account_config']['arguments']['rdx'] != 'account':
            raise ValueError('Native account argument changed')
    elif ACTIVE_HASH == UPDATED_HASH:
        schema = dict(unlock_pointer=0x20, unlock_count=0x28, unlock_stride=16,
                      entry_class=0, entry_unlocked_count=8)
    else:
        raise ValueError('No reviewed native account schema')
    pointer = struct.unpack('<Q', client.memory(account + schema['unlock_pointer'], 8))[0]
    count = struct.unpack('<Q', client.memory(account + schema['unlock_count'], 8))[0]
    if count > 32:
        raise ValueError('Invalid native unlock table')
    data = client.memory(pointer, count * schema['unlock_stride']) if count else b''
    return {str(data[i + schema['entry_class']]): struct.unpack_from('<Q', data,
            i + schema['entry_unlocked_count'])[0] for i in range(0, len(data), schema['unlock_stride'])}


def observed_baseline(path, executable_hash):
    row = json.loads(path.read_text())
    if (row.get('event') != 'native_progression_baseline' or row.get('sha256') != executable_hash
            or row.get('before_gameplay') is not True or type(row.get('player')) is not int
            or not 1 <= row['player'] <= 4 or not isinstance(row.get('classes'), dict)):
        raise ValueError('Invalid native pre-game progression observation')
    classes = row['classes']
    if len(classes) > 32 or any(not k.isdecimal() or type(v) is not int or not 0 <= v <= 9
                              for k, v in classes.items()):
        raise ValueError('Invalid observed native unlock table')
    return classes


def verify_unlock_reload(observed, required=None, before=None):
    if len(observed) != 2 or observed[0] != observed[1]:
        raise AssertionError('Native unlocks changed across the staged save reload')
    if required:
        class_id, count = required
        if any(classes.get(str(class_id), 1) < count for classes in observed):
            raise AssertionError('The party-earned map unlock was not present in the native saved profile')
        if before is not None and before.get(str(class_id), 1) >= count:
            raise AssertionError('The requested map was already unlocked before the party run')
    return bool(required and before is not None)


def staging_directory():
    parent = ROOT / 'coop-lab'
    if os.environ.get('COOP_CANDIDATE_PROFILE'):
        parent = Path(os.environ.get('COOP_CANDIDATE_HOME', '')).resolve()
        allowed = (ROOT / 'coop-lab/compatibility-tests').resolve()
        if allowed not in parent.parents or not parent.is_dir():
            raise ValueError('Candidate save checks require a disposable compatibility-test directory')
    directory = parent / ('save-staging-' + uuid.uuid4().hex[:12])
    directory.mkdir()
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, default=ROOT / 'coop-lab/boss-rewards-player-2/characters.txt')
    parser.add_argument('--automatic', action='store_true', help='Stop each stage after the native picker exposes its unlock table')
    parser.add_argument('--character', default='Hero', help='Existing character name for automatic native menu selection')
    parser.add_argument('--before-reference', type=Path,
                        help='Encrypted snapshot taken before the verified party victory; read through native picker')
    parser.add_argument('--before-observation', type=Path,
                        help='Build-bound native account observation captured before this party run')
    parser.add_argument('--require-unlock', type=int, nargs=2, metavar=('CLASS', 'COUNT'),
                        help='Require this newly earned class unlock in both native reloads')
    args = parser.parse_args()
    if args.require_unlock and (not args.automatic or not 1 <= args.require_unlock[1] <= 9):
        parser.error('--require-unlock needs --automatic and a map count from 1 to 9')
    if (args.before_reference or args.before_observation) and not args.require_unlock:
        parser.error('A pre-run baseline requires --require-unlock')
    if args.before_reference and args.before_observation:
        parser.error('Choose one pre-run baseline source')
    # Validate the disposable destination before importing the native launcher.
    directory = staging_directory()
    from native_probe import TICK, SERIALIZE, MAP_SELECT, ACTIVE_HASH, q, run
    baseline = observed_baseline(args.before_observation, ACTIVE_HASH) if args.before_observation else None
    reference = args.reference.resolve(strict=True)
    original = reference.read_bytes()
    if not original.startswith(b'RSE1:'):
        raise ValueError('Expected native encrypted diagnostic save')
    source = directory / 'stand-in-sp.txt'
    source.write_bytes(original)
    before_reference = args.before_reference.resolve(strict=True) if args.before_reference else None
    before_bytes = before_reference.read_bytes() if before_reference else None
    if before_bytes is not None and not before_bytes.startswith(b'RSE1:'):
        raise ValueError('Expected native encrypted pre-run save')
    before_source = directory / 'stand-in-before.txt'
    if before_bytes is not None:
        before_source.write_bytes(before_bytes)
    observed = []
    with (directory / 'verification.jsonl').open('w') as output:
        for stage in ((0, 1, 2) if before_reference else (1, 2)):
            marker = directory / f'picker-{stage}-done'
            current_source = before_source if stage == 0 else source
            save = PersonalSave(directory / f'picker-{stage}', current_source, mode='shared')
            class Picker:
                autostart = args.automatic
                character_names = {1: args.character}
                extra_hooks = (MAP_SELECT,)
                profile_folder = save.folder
                stop_requested = False
                def record(self, **event):
                    output.write(json.dumps(dict(stage=stage, **event)) + '\n')
                    output.flush()
                def poll_network(self):
                    self.stop_requested = marker.exists()
                def __call__(self, client, rva, context):
                    if rva == TICK:
                        client.server = q(context, 128)
                    elif rva == SERIALIZE:
                        client.disable_hooks.add(SERIALIZE)
                    elif rva == MAP_SELECT:
                        account = q(context, 136)
                        classes = native_unlocks(client, account)
                        self.record(event='native_loaded_unlocks', classes=classes)
                        if args.automatic and not marker.exists():
                            observed.append(classes)
                            marker.touch()
            try:
                print(json.dumps(dict(stage=stage, profile=str(save.folder), done_marker=str(marker))), flush=True)
                run(180, 1, Picker())
                if not marker.exists():
                    raise TimeoutError('Native picker inspection was not completed')
                save.commit()
                if current_source.read_bytes() != save.target.read_bytes():
                    raise AssertionError('Staged native save was not committed')
                output.write(json.dumps(dict(stage=stage, event='disposable_commit',
                    changed=current_source.read_bytes() != (before_bytes if stage == 0 else original),
                    sha256=hashlib.sha256(current_source.read_bytes()).hexdigest())) + '\n')
                output.flush()
            finally:
                save.close()
    if reference.read_bytes() != original:
        raise AssertionError('Reference diagnostic save changed')
    if before_reference and before_reference.read_bytes() != before_bytes:
        raise AssertionError('Pre-run reference save changed')
    before = observed.pop(0) if before_reference else baseline
    newly_earned = verify_unlock_reload(observed, args.require_unlock, before) if args.automatic else False
    print(json.dumps(dict(event='disposable_staging_complete', directory=str(directory),
                         native_unlock_reload_verified=bool(args.automatic),
                         expected_unlock_verified=bool(args.require_unlock),
                         newly_awarded_progression_verified=newly_earned)), flush=True)


if __name__ == '__main__':
    main()
