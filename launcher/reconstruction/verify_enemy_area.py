"""Force native elite attackers near both characters to inspect area impacts."""
import json
import struct
import argparse

from native_probe import ROOT, SPAWN_BOSS, HURT, q, run
from native_guest_combat import NativeCombatBridge
from verify_coop import Verification
from sessions import Pose


class AreaVerification(Verification, NativeCombatBridge):
    def __init__(self, output, boss=1, downed=False):
        super().__init__(output)
        self.spawned = 0
        self.area_events = []
        self.area_hits_verified = []
        self.matrix = []
        self.boss_guid = None
        self.origin = None
        self.boss_kind = boss
        self.test_downed = downed
        self.down_requested = False
        self.downed_ground = 0

    def record(self, **event):
        if event.get('event') == 'native_enemy_area':
            self.area_events.append(event)
            if event.get('kind') == 'radial' and len(self.matrix) < 3:
                expected = [(True, True), (True, False), (False, True)][len(self.matrix)]
                actual = event['host_hit'], event['guest_hit']
                assert actual == expected, (actual, expected)
                self.matrix.append(actual)
            if event.get('kind') == 'ground' and event['guest_hit'] and self.native_states[1][0] == 4:
                self.downed_ground += 1
        if event.get('event') == 'guest_area_hurt':
            assert event['before'] > event['after']
            self.area_hits_verified.append(event)
        super().record(**event)

    def before_batch(self, client, context):
        if self.finished and self.native_states[client.number][0] == 1:
            game = client.server + 0x10
            # Disposable diagnostic only: survive all native elite attacks.
            client.put(game + 0x4A0, struct.pack('<f', 10000))
            if client.number == 1 and self.test_downed and len(self.matrix) == 3 and not self.down_requested:
                self.down_requested = True
                client.call_before(context, HURT, game, self.boss_guid, damage=100000)
                return True
            if self.origin is not None and self.matrix:
                guest = Pose(self.origin.x + 60, self.origin.y, self.origin.z, self.origin.facing)
                self.router.players[0xFF0102].pose = guest
                if client.number == 2:
                    client.put(game + 0x488, struct.pack('<4f', guest.x, guest.y, guest.z, guest.facing))
                elif len(self.matrix) >= 2:
                    pointer, count = struct.unpack('<QQ', client.memory(game + 0x568, 16))
                    for i in range(count):
                        enemy = pointer + i * 0x148
                        if q(client.memory(enemy + 0x78, 8)) == self.boss_guid:
                            client.put(enemy + 0xFC, struct.pack('<6f', *([guest.x + 2, guest.y, guest.z] * 2)))
                            client.put(enemy + 0x114, bytes(8))
                            break
            if client.number == 1 and self.spawned < 1:
                kind = self.boss_kind
                self.spawned += 1
                def completed():
                    pointer, count = struct.unpack('<QQ', client.memory(game + 0x568, 16))
                    enemy = pointer + (count - 1) * 0x148
                    pose = self.router.players[0xFF0101].pose
                    self.origin = pose
                    self.boss_guid = q(client.memory(enemy + 0x78, 8))
                    client.put(enemy + 0xFC, struct.pack('<6f', *([pose.x + 2, pose.y, pose.z] * 2)))
                    client.put(enemy + 0x114, bytes(8))
                    client.put(enemy + 0xE0, struct.pack('<ff', 10000, 10000))
                    self.record(event='diagnostic_elite_spawned', kind=kind, guid=q(client.memory(enemy + 0x78, 8)))
                client.call_before(context, SPAWN_BOSS, game, client.base + 0x65EFA08 + kind * 0x58, after=completed)
                return True
        return super().before_batch(client, context)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--boss', type=int, default=1, choices=range(5))
    parser.add_argument('--downed', action='store_true')
    args = parser.parse_args()
    path = ROOT / 'analysis/coop-enemy-area.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = AreaVerification(output, args.boss, args.downed)
        try:
            run(120 if args.downed else 95, 2, bridge)
        finally:
            bridge.record(event='summary', area_events=len(bridge.area_events), matrix=bridge.matrix,
                          guest_area_hits=len(bridge.area_hits_verified), downed_ground=bridge.downed_ground, **bridge.counts)
    assert bridge.area_events, 'No native radial impacts observed'
    assert bridge.matrix == [(True, True), (True, False), (False, True)], bridge.matrix
    assert len(bridge.area_hits_verified) == sum(e['guest_hit'] for e in bridge.area_events)
    if args.boss == 4:
        assert any(e.get('kind') == 'ground' and e['guest_hit'] for e in bridge.area_events)
    if args.downed:
        assert bridge.downed_ground > 0 and bridge.native_states[1][0] == 4
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered']
    print(json.dumps(dict(area_events=len(bridge.area_events), **bridge.counts)))
