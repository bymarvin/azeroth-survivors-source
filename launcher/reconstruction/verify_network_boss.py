"""Disposable native boss encounter through each peer's real TLS bridge."""
import json
import hashlib
import os
import argparse
import struct
import subprocess
import sys
import time

from boss_rewards import RNG, native_map, reward_items
from group_online import GroupOnlineBridge
from native_probe import ROOT, CHOOSE, DAMAGE, HURT, SPAWN_BOSS, UI_COMMAND, MAP_SELECT, ACTIVE_HASH, allocate, checked, game_field, q, _candidate_home
from updated_layout import field, enemy_layout
from world_packets import UPDATE, objects, Reader


class NetworkBossVerification(GroupOnlineBridge):
    def __init__(self, output, number, channels):
        super().__init__(output, number, channels)
        self.profile_folder = (_candidate_home / f'player-{number}' if _candidate_home else
                               ROOT / f'coop-lab/boss-rewards-player-{number}')
        # Fresh candidate saves contain only the native diagnostic Hero. The
        # named characters belong to the older, manually prepared test saves.
        self.character_names = dict(enumerate(
            ('Hero',) * 4 if _candidate_home else ('Brodun', 'Kaorth', 'Ulenar', 'Morisa'), 1))
        self.boss_guid = None
        self.boss_spawned = False
        self.last_hit = -1
        self.roll_recorded = False
        self.result_recorded = False
        self.rng_before = None
        self.command = int(os.environ.get('COOP_VERIFY_VICTORY_COMMAND', '0'))
        self.guest_commands = 0
        self.victory_since = None
        self.action_since = None
        self.resumed_clock = None
        self.progression_baseline = None
        # --fall-before-victory: players 2, 3, 4, 1 each fall once (native lethal HURT) and are revived before
        # the boss is damaged; the victory must still unlock the next map and credit the class XP once.
        self.fall_order = (2, 3, 4, 1) if os.environ.get('COOP_VERIFY_FALL') == '1' else ()
        self.fall_step = 0  # The host advances it; peers follow its messages.
        self.fall_requested = self.fall_seen_down = None
        self.class_xp_start = self.class_xp_alive = None
        self.extra_hooks += (MAP_SELECT,)

    def __call__(self, client, rva, context):
        if rva == MAP_SELECT:
            if self.progression_baseline is None:
                from verify_save_staging import native_unlocks
                if client.number in self.ready:
                    raise AssertionError('Progression baseline was captured after gameplay began')
                self.progression_baseline = native_unlocks(client, q(context, 136))
                self.record(event='native_progression_baseline', player=client.number,
                            sha256=ACTIVE_HASH, before_gameplay=True, classes=self.progression_baseline)
            return
        return super().__call__(client, rva, context)

    def falls_pending(self):
        return self.fall_step < len(self.fall_order)

    def decorate(self, peer, message):
        super().decorate(peer, message)
        if self.number == 1 and self.fall_order:
            message['fall_step'] = self.fall_step

    def receive_peer(self, peer, message):
        super().receive_peer(peer, message)
        if self.number != 1 and 'fall_step' in message:
            step = message['fall_step']
            if type(step) is not int or not self.fall_step <= step <= len(self.fall_order):
                raise ValueError('Invalid fall step')
            self.fall_step = step

    def poll_network(self):
        super().poll_network()
        if self.number == 1 and self.command == 9 and self.action_since is not None:
            if time.monotonic() - self.action_since > 5:
                self.stop_requested = True

    def record(self, **event):
        if event.get('event') == 'independent_boss_reward':
            assert not self.roll_recorded, 'Repeated personal boss reward'
            client = self.clients[self.number]
            assert self.rng_before != client.memory(client.server + 0x10 + field('game', RNG), 32)
            event['class_id'] = client.memory(client.server + 0x10 + field('game', 0x34C), 1)[0]
            self.roll_recorded = True
        super().record(**event)

    def before_batch(self, client, context):
        game = client.server + 0x10
        if client.number not in self.ready:
            return super().before_batch(client, context)
        phase = self.native_states[client.number][0]
        if self.boss_reward_pending.get(client.number) and self.rng_before is None:
            self.rng_before = client.memory(game + field('game', RNG), 32)
        if self.fall_order:
            from updated_layout import result_evaluation
            table = self.class_xp(client, result_evaluation()) if client.number == self.number else None
            if table is not None and phase == 1:
                xp = {cls: value for cls, (_, value) in table.items()}
                if self.class_xp_start is None:
                    self.class_xp_start = xp
                    self.record(event='network_class_xp', player=client.number, stage='start', xp=xp)
                self.class_xp_alive = xp
            elif table is not None and phase == 5 and not self.result_recorded:
                self.record(event='network_class_xp', player=client.number, stage='victory',
                            before=self.class_xp_alive, xp={cls: value for cls, (_, value) in table.items()})
        if phase == 5 and not self.result_recorded:
            self.result_recorded = True
            self.record(event='network_boss_result', player=client.number,
                        class_id=client.memory(game + field('game', 0x34C), 1)[0],
                        items=reward_items(client),
                        gold=struct.unpack('<I', client.memory(game + game_field(0x4A8), 4))[0],
                        earned=struct.unpack('<I', client.memory(game + game_field(0x6D0), 4))[0])
        if phase == 5 and self.command and client.number != 1 and self.guest_commands < 2:
            command = 8 + self.guest_commands
            self.guest_commands += 1
            buffer = checked(allocate(client.handle, None, 0xE8, 0x3000, 4))
            client.put(buffer, struct.pack('<I', command) + bytes(0xE4))
            def rejected():
                assert self.end_action is None, 'Guest controlled victory'
                self.record(event='network_guest_choice_blocked', player=client.number, command=command)
            client.call_before(context, UI_COMMAND, client.server, buffer, request=True, after=rejected)
            return True
        phases = [self.native_states.get(n, (0,))[0] for n in self.members]
        if client.number == 1 and phases == [5] * len(self.members) and self.action_since is None:
            if self.victory_since is None:
                self.victory_since = time.monotonic()
            elif time.monotonic() - self.victory_since > 3 and not self.boss_reward_events:
                if not self.command:
                    self.stop_requested = True
                else:
                    self.action_since = time.monotonic()
                    buffer = checked(allocate(client.handle, None, 0xE8, 0x3000, 4))
                    client.put(buffer, struct.pack('<I', self.command) + bytes(0xE4))
                    client.call_before(context, UI_COMMAND, client.server, buffer, request=True)
                    return True
        if client.number == 1 and self.command == 8 and self.action_since is not None and phases == [1] * len(self.members):
            if self.resumed_clock is None:
                self.resumed_clock = self.host_clock
            elif self.host_clock > self.resumed_clock + 1:
                self.record(event='network_party_resumed', clock_delta=self.host_clock - self.resumed_clock)
                self.stop_requested = True
        if phase == 2:
            count = q(client.memory(game + game_field(0x618), 8))
            if not 1 <= count <= 16:
                raise ValueError('Invalid native talent choices')
            client.call_before(context, CHOOSE, game, (client.number - 1) % count)
            return True
        if self.falls_pending() and self.enemy_snapshot and self.ready == set(self.members):
            target = self.fall_order[self.fall_step]
            if client.number == 1:
                self.fall_seen_down = self.fall_seen_down or phases[target - 1] == 4
                if self.fall_seen_down and phases == [1] * len(self.members):
                    self.record(event='network_fall_revived', player=target)
                    self.fall_step += 1
                    self.fall_requested = self.fall_seen_down = None
                    return super().before_batch(client, context)
            if (client.number == target and phase == 1 and phases == [1] * len(self.members)
                    and self.fall_requested != target):
                from verify_network_coop import NetworkCoopVerification
                if NetworkCoopVerification.lethal_guard_buffs(self, client, game):
                    return super().before_batch(client, context)  # Native HURT ignores hits meanwhile.
                self.fall_requested = target
                self.record(event='network_lethal_hit', player=target)
                def completed():
                    if client.memory(game + game_field(0x8BF), 1)[0] == 1:
                        self.fall_requested = None  # A native HURT guard buff ignored the hit: again next batch.
                        self.record(event='network_lethal_retry', player=target)
                client.call_before(context, HURT, game, next(iter(self.enemy_snapshot)), damage=10 ** 7, after=completed)
                return True
        if phase == 1:
            client.put(game + game_field(0x4A0), struct.pack('<f', 100000))
            client.put(game + game_field(0x4F8), struct.pack('<f', 100000))
            if client.number == 1 and self.ready == set(self.members):
                if not self.boss_spawned:
                    self.boss_spawned = True
                    def completed():
                        pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x568), 16))
                        stride, guid_offset = enemy_layout()[:2]
                        self.boss_guid = q(client.memory(pointer + (count - 1) * stride + guid_offset, 8))
                        self.record(event='network_boss_spawned', guid=self.boss_guid)
                    # Boss ordinal 4 of the map this game actually loaded (next run: Duskwood, not Elwynn).
                    client.call_before(context, SPAWN_BOSS, game, native_map(client, game)[1] + 4 * 0x58,
                                       after=completed)
                    return True
                second = int(self.host_clock)
                if (self.boss_guid in self.enemy_snapshot and second >= 30 and second != self.last_hit
                        and not self.falls_pending()):
                    self.last_hit = second
                    client.call_before(context, DAMAGE, game, self.boss_guid, damage=100000)
                    return True
        return super().before_batch(client, context)


def verify(command=0):
    rows = [[json.loads(line) for line in (ROOT / f'analysis/group-online-{n}.jsonl').read_text().splitlines()]
            for n in range(1, 5)]
    summaries = [next(e for e in reversed(events) if e['event'] == 'summary') for events in rows]
    assert len([e for e in rows[0] if e['event'] == 'authoritative_boss_reward']) == 1
    for number, events in enumerate(rows[1:], 2):
        rolls = [e for e in events if e['event'] == 'independent_boss_reward']
        assert len(rolls) == 1 and rolls[0]['player'] == number, rolls
    results = [next(e for e in events if e['event'] == 'network_boss_result') for events in rows]
    assert len({r['gold'] for r in results}) == 1, results
    assert all(r['gold'] == r['earned'] and not r['items'] for r in results), results
    states = [s['states'][str(n)] for n, s in enumerate(summaries, 1)]
    expected_phases = (1, 3) if command == 8 else (5,)
    # Normal shutdown pauses active worlds while draining network packets.
    assert all(s[0] in expected_phases and s[1:3] == states[0][1:3] for s in states), states
    if command:
        for number, events in enumerate(rows[1:], 2):
            assert [e['command'] for e in events if e['event'] == 'network_guest_choice_blocked'] == [8, 9], number
        for number, events in enumerate(rows, 1):
            assert any(e['event'] == 'victory_action_applied' and e['command'] == command for e in events), number
            completions = [e for e in events if e['event'] == 'completed_run_transition' and e['player'] == number]
            assert len(completions) == (1 if command == 9 else 0), (number, completions)
            if completions:
                assert completions[0]['action'] == 'new_hero' and completions[0]['phase'] == 5
                assert completions[0]['duration_seconds'] > 0
        if command == 8:
            assert any(e['event'] == 'network_party_resumed' for e in rows[0])
    host = summaries[0]
    assert host['world_captured'] > 0 and host['world_captured'] == host['world_delivered'], host
    assert sum(s['world_delivered'] for s in summaries[1:]) == host['world_delivered'], summaries
    boss_guid = next(e['guid'] for e in rows[0] if e['event'] == 'network_boss_spawned')
    verify_boss_replication(rows, boss_guid)
    for n in range(1, 5):
        folder = (_candidate_home / f'player-{n}' if _candidate_home else
                  ROOT / f'coop-lab/boss-rewards-player-{n}')
        assert (folder / 'characters.txt').read_bytes().startswith(b'RSE1:')
        messages = [json.loads(line[7:]) for line in (folder / 'stdout.log').read_text().splitlines()
                    if line.startswith('rogue: {')]
        victories = [message for message in messages if message.get('type') == 'victory']
        assert len(victories) == 1 and victories[0]['gold'] == results[n-1]['gold'], victories
        if command == 9:
            verify_return_to_roster(messages)
    return dict(players=4, independent_rolls=3, gold=results[0]['gold'], delivered=host['world_delivered'])


def verify_falls(rows=None):
    """Every player fell once and was revived; its fall evaluation was re-armed; the victory credited once.

    0.0.22 hotfix (rearm_result, 2-PC test 18.10.2026): after a revival the fall credit STAYS on the account
    (result_credit_kept, rearm with xp_taken_back 0), because the evaluation after a revival counts only what
    happened since. Right before the victory evaluation the class XP is therefore start + that kept credit.
    """
    rows = rows or [[json.loads(line) for line in (ROOT / f'analysis/group-online-{n}.jsonl').read_text().splitlines()]
                    for n in range(1, 5)]
    assert [e['player'] for e in rows[0] if e['event'] == 'network_fall_revived'] == [2, 3, 4, 1], 'Fall order'
    kept_credit = {}
    for number, events in enumerate(rows, 1):
        revivals = [e for e in events if e['event'] == 'player_revived' and e['player'] == number]
        assert len(revivals) == 1, (number, revivals)
        rearmed = [e for e in events if e['event'] == 'result_rearmed' and e['player'] == number]
        # The fall ran the native once-per-run evaluation (lock set); the revival opened it again.
        revival = [e for e in rearmed if e['reason'] == 'revival']
        assert [(e['reason'], e['was_locked'], e['last_phase']) for e in revival] == [('revival', 1, 4)], (number, rearmed)
        # The shared victory may re-open an evaluation that never ran for a guest: nothing was
        # locked there and nothing may be taken back.
        others = [e for e in rearmed if e['reason'] != 'revival']
        assert all(e['reason'] == 'shared_victory' and e['was_locked'] == 0 and not e.get('xp_taken_back')
                   for e in others), (number, others)
        assert not [e for e in events if e['event'] == 'result_xp_kept'], number  # No credit left by an unclear account.
        # The revival keeps the fall credit (nothing taken back) and logs it exactly once.
        assert not revival[0].get('xp_taken_back'), (number, 'fall credit taken back at the revival', revival)
        kept = [e for e in events if e['event'] == 'result_credit_kept' and e['player'] == number]
        assert [e['reason'] for e in kept] == ['revival'], (number, kept)
        kept_credit[number] = kept[0]['credited']
        start = next(e for e in events if e['event'] == 'network_class_xp' and e['stage'] == 'start')
        victories = [e for e in events if e['event'] == 'network_class_xp' and e['stage'] == 'victory']
        assert len(victories) == 1, (number, 'victory evaluated more than once', victories)
        victory = victories[0]
        # Right before the victory evaluation: the start value plus the kept fall credit (nothing lost, nothing
        # twice); the victory evaluation then credits what happened since the revival.
        expected = dict(class_xp(start['xp']))
        cls = str(kept[0]['cls'])
        expected[cls] = expected.get(cls, 0) + kept[0]['credited']
        assert class_xp(victory['before']) == class_xp(expected), (number, start, kept[0], victory)
        assert sum(victory['xp'].values()) > sum(victory['before'].values()), (number, victory)
    return dict(falls=4, revivals=4, fall_credit_kept=kept_credit)


def class_xp(values):
    """Class XP with absent classes as 0: a fresh save has no entry before its class's first credit."""
    return {str(k): v for k, v in (values or {}).items() if v}


def check_unlock_records(number, class_id, records):
    """One player's reloaded victory save: the party-earned next map is open (newly) in that save."""
    complete = [r for r in records if r.get('event') == 'disposable_staging_complete']
    assert complete, (number, 'save reload did not complete')
    last = complete[-1]
    assert (last.get('native_unlock_reload_verified') and last.get('expected_unlock_verified')
            and last.get('newly_awarded_progression_verified')), (number, 'map unlock missing in the saved profile', last)
    return dict(class_id=class_id, map=2, unlocked=True)


def verify_return_to_roster(messages):
    types = [message.get('type') for message in messages]
    victory = types.index('victory')
    logout = types.index('logout', victory + 1)
    assert 'roster' in types[logout + 1:], 'Native character menu did not reopen after party victory'


def delivered_world_packets(recordings):
    """Resolve committed-delivery hashes without duplicating every native payload."""
    captured = [e for e in recordings[0] if e['event'] == 'world_captured']
    lookup = {}
    for event in captured:
        body = bytes.fromhex(event['body'])
        assert hashlib.sha256(body).hexdigest() == event['digest'], 'Captured world body hash changed'
        key = event['recipient'], event['opcode'], event['digest']
        assert key not in lookup or lookup[key] == body, 'Conflicting captured world body'
        lookup[key] = body
    result = [captured]
    for number, events in enumerate(recordings[1:], 2):
        packets = []
        for event in events:
            if event['event'] != 'world_delivered':
                continue
            key = number, event['opcode'], event['digest']
            assert key in lookup, (number, 'Native delivery has no matching host packet')
            body = lookup[key]
            if 'body' in event:
                assert bytes.fromhex(event['body']) == body, 'Guest body differs from acknowledged host packet'
            packets.append(dict(event, body=body.hex()))
        result.append(packets)
    return result


def verify_boss_replication(recordings, boss_guid):
    """Require native model/HP/attack inputs on every peer, not a pixel-render claim."""
    creates, hud = [], []
    delivered = delivered_world_packets(recordings)
    for number, events in enumerate(recordings, 1):
        packets = delivered[number-1]
        models, attacks = set(), 0
        for event in packets:
            body = bytes.fromhex(event['body'])
            if event['opcode'] == UPDATE:
                for block in objects(body, remap=False):
                    if block.guid == boss_guid and block.object_type == 3:
                        assert block.fields.get(22, 0) > 0, 'Boss created without positive HP'
                        assert block.fields.get(131, 0) > 0, 'Boss created without model'
                        models.add(block.fields[131])
            elif event['opcode'] in (0x14A, 0x132):
                reader = Reader(body, remap_enabled=False)
                if event['opcode'] == 0x14A:
                    reader.take(4)
                if reader.guid() == boss_guid:
                    attacks += 1
        assert len(models) == 1 and attacks, (number, models, attacks)
        samples = [e['boss'] for e in events if e['event'] == 'boss_hud_delivered' and e.get('boss')]
        assert samples and len({s['hp'] for s in samples}) > 1, (number, samples)
        creates.append(models)
        hud.append({(s['name'], s['hp'], s['hpMax']) for s in samples})
    assert all(model == creates[0] for model in creates), creates
    # Delivery may skip intermediate frames, but cannot invent a different HP.
    assert all(samples <= hud[0] for samples in hud[1:]), 'Guest boss HUD diverged from host'


def verify_saved_progression():
    """Reload every actual victory save; no inferred award or invented baseline."""
    unlocked = {}
    for number in range(1, 5):
        events = [json.loads(line) for line in (ROOT / f'analysis/group-online-{number}.jsonl').read_text().splitlines()]
        baselines = [e for e in events if e['event'] == 'native_progression_baseline']
        assert len(baselines) == 1 and baselines[0]['player'] == number
        result = next(e for e in events if e['event'] == 'network_boss_result')
        folder = (_candidate_home / f'player-{number}' if _candidate_home else
                  ROOT / f'coop-lab/boss-rewards-player-{number}')
        baseline = folder / 'progression-before.json'
        baseline.write_text(json.dumps(baselines[0]))
        character = 'Hero' if _candidate_home else ('Brodun', 'Kaorth', 'Ulenar', 'Morisa')[number-1]
        output = folder / 'progression-reload.txt'
        with output.open('w') as stream:
            subprocess.run([sys.executable, str(ROOT / 'reconstruction/verify_save_staging.py'),
                '--automatic', '--character', character, '--reference', str(folder / 'characters.txt'),
                '--before-observation', str(baseline), '--require-unlock', str(result['class_id']), '2'],
                stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=420)
        records = [json.loads(line) for line in output.read_text().splitlines() if line.startswith('{')]
        unlocked[number] = check_unlock_records(number, result['class_id'], records)
        print(f'[  OK  ] unlock_verified player {number} (class {result["class_id"]}: map 2 open in the '
              f'reloaded save, newly earned in this run)', flush=True)
    return dict(map_progression=True, saves=True, native_saved_players=4, unlock_verified=unlocked)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--victory-command', type=int, choices=(0, 8, 9), default=0)
    parser.add_argument('--fall-before-victory', action='store_true',
                        help='every player falls once and is revived before the boss victory (map unlock, class XP once)')
    args = parser.parse_args()
    if args.fall_before_victory and args.victory_command:
        parser.error('--fall-before-victory checks the plain victory')
    os.environ['COOP_VERIFY_VICTORY_COMMAND'] = str(args.victory_command)
    os.environ['COOP_VERIFY_FALL'] = '1' if args.fall_before_victory else '0'
    processes, outputs = [], []
    try:
        for n in range(1, 5):
            output = (ROOT / f'analysis/network-boss-{n}.txt').open('w')
            outputs.append(output)
            command_args = [sys.executable, str(ROOT / 'reconstruction/group_online.py'),
                    'host' if n == 1 else 'join', '--players', '4', '--seconds', '300', '--verify-boss']
            if n != 1:
                command_args += ['--slot', str(n)]
            processes.append(subprocess.Popen(command_args, stdout=output, stderr=subprocess.STDOUT))
            if n == 1:
                time.sleep(2)
        for process in processes:
            process.wait(timeout=420)
        assert [p.returncode for p in processes] == [0] * 4
        result = verify(args.victory_command)
        if args.fall_before_victory:
            result.update(verify_falls())
        if args.victory_command == 0:
            result.update(verify_saved_progression())
        if args.fall_before_victory:
            # The point of the 0.0.15 fix: after a fall and revival, every player's save has the next map.
            assert sorted(result.get('unlock_verified', {})) == [1, 2, 3, 4], result.get('unlock_verified')
            result['fall_revival_unlock'] = True
        print(json.dumps(result), flush=True)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        for output in outputs:
            output.close()
