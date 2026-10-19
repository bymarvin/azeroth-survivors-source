"""Live equal spawn allocation and distance bonus with synthetic separated poses."""
import json
import math
import struct

from native_probe import ROOT, run
from native_guest_combat import NativeCombatBridge
from verify_coop import Verification
from sessions import Pose
from visibility_bridge import native_enemies


class SpawnVerification(Verification, NativeCombatBridge):
    def __init__(self, output):
        super().__init__(output)
        self.separated = False
        self.spawn_cases = []
        self.seen = set()
        self.near = {1: 0, 2: 0}

    def record(self, **event):
        if self.separated and event.get('event') == 'spawn_allocated':
            self.spawn_cases.append(event)
        super().record(**event)

    def before_batch(self, client, context):
        if self.finished and not self.separated and client.number == 2:
            host = self.router.players[0xFF0101].pose
            pose = Pose(host.x + 200, host.y, host.z, 0)
            self.router.players[0xFF0102].pose = pose
            client.put(client.server + 0x10 + 0x488, struct.pack('<4f', pose.x, pose.y, pose.z, pose.facing))
            self.separated = True
            self.seen = set(self.enemy_snapshot)
            self.record(event='synthetic_split', distance=200, max_bonus_distance=self.spawn_bonus_distance)
        if self.separated and client.number == 1:
            for guid, _, position in native_enemies(client, client.server + 0x10):
                if guid in self.seen:
                    continue
                self.seen.add(guid)
                distances = {n: math.hypot(position[0] - self.router.players[0xFF0100+n].pose.x,
                                          position[1] - self.router.players[0xFF0100+n].pose.y)
                             for n in (1, 2)}
                owner = min(distances, key=distances.get)
                self.near[owner] += 1
                self.record(event='spawn_position_observed', player=owner, distance=distances[owner], guid=guid)
        return super().before_batch(client, context)


def verify_recording(path):
    events = [json.loads(line) for line in path.read_text().splitlines()]
    start = next(i for i, event in enumerate(events) if event['event'] == 'synthetic_split')
    # A stationary character can die in this pressure test. Equal allocation
    # applies while both are alive; subsequent spawns belong to the survivor.
    cases = [e for e in events[start:] if e['event'] == 'spawn_allocated' and e['multiplier'] == 1.5]
    near = events[-1]['near']
    assert len(cases) >= 20, len(cases)
    assert abs(sum(e['player'] == 1 for e in cases) - sum(e['player'] == 2 for e in cases)) <= 1
    assert min(near.values()) >= 5, near
    baseline = sum(not e['bonus'] for e in cases)
    extra = sum(e['bonus'] for e in cases)
    assert abs(extra - baseline * .5) <= 2, (baseline, extra)
    phases = {}
    for event in events:
        if event['event'] == 'native_state':
            phases[event['player']] = event['phase']
        elif event['event'] == 'spawn_allocated':
            assert phases.get(event['player']) != 4, 'Spawn assigned to a downed player'
    assert events[-1]['world_captured'] == events[-1]['world_delivered']
    print(json.dumps(dict(baseline=baseline, extra=extra, near=near,
                          world=events[-1]['world_delivered'])))


if __name__ == '__main__':
    path = ROOT / 'analysis/coop-spawn-balance-verification.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = SpawnVerification(output)
        try:
            run(110, 2, bridge)
        finally:
            bridge.record(event='summary', near=bridge.near, **bridge.counts)
    verify_recording(path)
