"""Disposable two-player check: enemies spawn and stay around a guest who walks away from the host.

The guest holds the game's own diagnostic W key (native press repeat, COOP_SPLIT_HOLD seconds) while the host
stands still. Every two host seconds the host records both poses, living enemies near each player and the
nearest player of every enemy seen for the first time. No positions are written; players are kept alive.

  verify_split_spawns.py [--seconds 90] [--hold 45]
"""
import argparse
import json
import math
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEAR = 30.0

if __name__ != '__main__':
    from group_online import GroupOnlineBridge
    from native_probe import CHOOSE, game_field
    from visibility_bridge import native_enemies

    class SplitSpawnVerification(GroupOnlineBridge):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            if getattr(self, 'input_contract', None) is not None:
                hold = float(os.environ.get('COOP_SPLIT_HOLD', '45'))
                if not 2 <= hold <= 120:
                    raise ValueError('Split hold must be 2..120 seconds')
                self.input_contract = dict(self.input_contract, hold_seconds=hold)
            self.split_sample = -1
            self.split_seen = set()
            self.split_owner = None
            self.split_last = None

        def record(self, **event):
            if event.get('event') == 'spawn_allocated':
                self.split_owner = event['player']
            return super().record(**event)

        def __call__(self, client, rva, context):
            from native_probe import FIND_SPAWN, q
            if rva != FIND_SPAWN or client.number != 1:
                return super().__call__(client, rva, context)
            out = q(context, 128)
            last = self.split_last
            if last and last['out'] == out:
                # The caller reuses the same frame buffer: it still holds the previous search result.
                x, y, z = struct.unpack('<3f', client.memory(out, 12))
                host = self.router.players[0xFF0101].pose
                self.record(event='split_spawn_result', owner=last['owner'], cloned=last['cloned'], center=last['center'],
                            result=[round(x, 1), round(y, 1)],
                            from_center=round(math.hypot(x - last['center'][0], y - last['center'][1]), 1),
                            from_host=round(math.hypot(x - host.x, y - host.y), 1))
            self.split_owner = None
            game_before = q(context, 136)
            result = super().__call__(client, rva, context)
            game_after = q(context, 136)
            center = struct.unpack('<2f', client.memory(game_after + game_field(0x488), 8))
            self.split_last = dict(out=out, owner=self.split_owner, cloned=game_after != game_before,
                                   center=[round(center[0], 1), round(center[1], 1)])
            return result

        def before_batch(self, client, context):
            game = client.server + 0x10
            phase = self.native_states[client.number][0]
            if phase == 2:
                count = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
                if not 1 <= count <= 16:
                    raise ValueError('Invalid native choices')
                client.call_before(context, CHOOSE, game, (client.number - 1) % count)
                return True
            if phase == 1:
                # Keep both players alive; enemies still spawn, chase and attack natively.
                client.put(game + game_field(0x4A0), struct.pack('<f', 1000))
                client.put(game + game_field(0x4F8), struct.pack('<f', 1000))
            if client.number == 1 and self.ready == set(self.members) and int(self.host_clock) // 2 != self.split_sample:
                self.split_sample = int(self.host_clock) // 2
                poses = {n: self.router.players[0xFF0100 + n].pose for n in self.members
                         if 0xFF0100 + n in self.router.players}
                if len(poses) == len(self.members):
                    enemies = native_enemies(client, game)
                    near = {n: 0 for n in poses}
                    first = {n: 0 for n in poses}
                    for guid, hp, (x, y, _) in enemies:
                        distance = {n: math.hypot(x - p.x, y - p.y) for n, p in poses.items()}
                        closest = min(distance, key=distance.get)
                        if distance[closest] <= NEAR:
                            near[closest] += 1
                        if guid not in self.split_seen:
                            self.split_seen.add(guid)
                            first[closest] += 1
                    self.record(event='split_sample', clock=round(self.host_clock, 1),
                                poses={n: [round(p.x, 1), round(p.y, 1)] for n, p in poses.items()},
                                separation=round(math.hypot(poses[1].x - poses[2].x, poses[1].y - poses[2].y), 1),
                                living=len(enemies), near=near, first_seen_nearest=first,
                                enemies=[[guid & 0xFFFFFFFF, round(x, 1), round(y, 1), round(hp, 1)] for guid, hp, (x, y, _) in enemies])
            return super().before_batch(client, context)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--hold', type=float, default=90)
    args = parser.parse_args()
    processes, outputs = [], []
    try:
        for number in (1, 2):
            output = (ROOT / f'analysis/group-network-{number}.txt').open('w')
            outputs.append(output)
            env = {k: v for k, v in os.environ.items() if k not in ('WOW_ROGUE_KEY', 'COOP_VERIFY_NATIVE_MOVEMENT')}
            if number == 2:
                env.update(WOW_ROGUE_KEY='w@3', COOP_VERIFY_NATIVE_MOVEMENT='1', COOP_SPLIT_HOLD=str(args.hold))
            command = [sys.executable, str(ROOT / 'reconstruction/group_online.py'), 'host' if number == 1 else 'join',
                       '--players', '2', '--seconds', str(args.seconds), '--verify-split']
            if number == 2:
                command += ['--slot', '2']
            processes.append(subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, env=env))
            if number == 1:
                time.sleep(2)
        for process in processes:
            process.wait(timeout=args.seconds + 240)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
        for output in outputs:
            output.close()
    codes = [p.returncode for p in processes]
    rows = [json.loads(line) for line in (ROOT / 'analysis/group-online-1.jsonl').read_text().splitlines()]
    samples = [r for r in rows if r['event'] == 'split_sample']
    apart = [s for s in samples if s['separation'] >= 45]  # beyond the native 55 recycle radius for guest-side enemies
    result = dict(codes=codes, samples=len(samples), max_separation=max((s['separation'] for s in samples), default=0),
                  apart_samples=len(apart),
                  guest_near_when_apart=[s['near']['2'] for s in apart],
                  host_near_when_apart=[s['near']['1'] for s in apart],
                  first_seen_near_guest_when_apart=sum(s['first_seen_nearest']['2'] for s in apart),
                  first_seen_near_host_when_apart=sum(s['first_seen_nearest']['1'] for s in apart))
    print(json.dumps(result), flush=True)
    passed = (codes == [0, 0] and len(apart) >= 5 and result['first_seen_near_guest_when_apart'] > 0
              and sum(1 for n in result['guest_near_when_apart'] if n > 0) >= len(apart) * 0.6)
    print('[  OK  ] split spawns' if passed else '[FAILED] split spawns', flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
