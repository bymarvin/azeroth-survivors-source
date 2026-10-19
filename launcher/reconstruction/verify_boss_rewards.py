"""Bounded native boss kill: one authority event, independent guest gear rolls."""
import argparse
import json
import os
import struct
from pathlib import Path

from boss_rewards import RNG, reward_items
from native_probe import ROOT, BUILD, game_field, run
from verify_boss_visual import BossVerification


class BossRewardVerification(BossVerification):
    def __init__(self, output):
        super().__init__(output)
        self.rolls = {}
        self.result_items = {}
        self.rng_before = {}
        self.profile_folders = {n: ROOT / f'coop-lab/boss-rewards-player-{n}' for n in self.members}
        self.character_names = dict(enumerate(('Brodun', 'Kaorth', 'Ulenar', 'Morisa'), 1))

    def before_batch(self, client, context):
        if client.number in self.ready:
            pending = self.boss_reward_pending.get(client.number)
            if pending and client.number not in self.rng_before:
                self.rng_before[client.number] = client.memory(client.server + 0x10 + RNG, 32)
            if self.native_states[client.number][0] == 5 and client.number not in self.result_items:
                self.result_items[client.number] = reward_items(client)
                game = client.server + 0x10
                gold = struct.unpack('<I', client.memory(game + game_field(0x4A8), 4))[0]
                earned = struct.unpack('<I', client.memory(game + game_field(0x6D0), 4))[0]
                self.record(event='native_result_gear', player=client.number,
                            items=self.result_items[client.number], gold=gold, earned=earned)
        return super().before_batch(client, context)

    def record(self, **event):
        if event.get('event') == 'independent_boss_reward':
            number = event['player']
            if number in self.rolls:
                raise AssertionError('Boss awarded twice to one player')
            self.rolls[number] = event
            client = self.clients[number]
            after = client.memory(client.server + 0x10 + RNG, 32)
            assert self.rng_before[number] != after, 'Guest native loot RNG did not advance'
        super().record(**event)


def verify_recording(path, players):
    events = [json.loads(line) for line in path.read_text().splitlines()]
    deaths = [e for e in events if e['event'] == 'authoritative_boss_reward']
    rolls = [e for e in events if e['event'] == 'independent_boss_reward']
    results = [e for e in events if e['event'] == 'native_result_gear']
    members = set(range(1, players + 1))
    assert len(deaths) == 1, deaths
    assert len(rolls) == players - 1 and {e['player'] for e in rolls} == members - {1}, rolls
    assert {e['player'] for e in results} == members, results
    # Native victory consumes the temporary award Vec into the encrypted save.
    assert all(not e['items'] for e in results), results
    final_gold = []
    for number in members:
        folder = ROOT / f'coop-lab/boss-rewards-player-{number}'
        assert (folder / 'characters.txt').read_bytes().startswith(b'RSE1:'), number
        lines = (folder / 'stdout.log').read_text().splitlines()
        victories = [json.loads(line[7:]) for line in lines if line.startswith('rogue: {"type":"victory"')]
        assert len(victories) == 1, number
        final_gold.append(victories[0]['gold'])
    assert len(set(final_gold)) == 1, ('Final pickup gold diverged at victory', final_gold)
    summary = next(e for e in reversed(events) if e['event'] == 'summary')
    assert summary['world_captured'] == summary['world_delivered'], summary
    return dict(independent_rolls=len(rolls), victory_players=len(results),
                world_packets=summary['world_delivered'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--players', type=int, choices=(2, 3, 4), default=4)
    parser.add_argument('--seconds', type=int, default=300)
    parser.add_argument('--check-recording', type=Path)
    args = parser.parse_args()
    if args.check_recording:
        print(json.dumps(verify_recording(args.check_recording, args.players)))
        raise SystemExit(0)
    os.environ['COOP_PLAYERS'] = str(args.players)
    path = ROOT / f'analysis/{BUILD}-boss-reward-verification.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = BossRewardVerification(output)
        try:
            run(args.seconds, args.players, bridge)
        finally:
            bridge.record(event='summary', states=bridge.native_states,
                          reward_players=sorted(bridge.rolls), result_players=sorted(bridge.result_items),
                          **bridge.counts)
    assert len(bridge.boss_reward_events) == 1, bridge.boss_reward_events
    assert set(bridge.rolls) == set(bridge.guests), bridge.rolls
    assert set(bridge.result_items) == set(bridge.members), bridge.result_items
    assert all(state[0] == 5 for state in bridge.native_states.values()), bridge.native_states
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered']
    print(json.dumps(verify_recording(path, args.players)), flush=True)
