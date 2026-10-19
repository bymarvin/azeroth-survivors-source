"""Native boss encounter: placement happens before its CREATE packet is built."""
import json
import math
import struct

from native_probe import ROOT, FIND_SPAWN, SPAWN_BOSS, DAMAGE, q, game_field, BUILD, run
from native_guest_combat import NativeCombatBridge
from updated_layout import rva as relocated
from verify_coop import Verification
from world_packets import UPDATE, SELF, objects, values_packet


class BossVerification(Verification, NativeCombatBridge):
    updated_world_probe = True
    def __init__(self, output):
        super().__init__(output)
        self.step = len(self.steps)  # Boss check; the control matrix has its own verifier.
        self.spawned = False
        self.boss_guid = None
        self.creates = []
        self.hud_samples = 0
        self.boss_seen = False
        self.boss_cleared = False
        self.health_boosted = set()
        self.last_hit = -1

    def __call__(self, client, rva, context):
        if (rva == FIND_SPAWN and client.number == 1 and
                q(client.memory(q(context, 152), 8)) == client.base + relocated(0x53FCC02)):
            pose = self.router.players[0xFF0101].pose
            position = (pose.x + 5 * math.cos(pose.facing),
                        pose.y + 5 * math.sin(pose.facing), pose.z)
            client.put(q(context, 128), struct.pack('<3f', *position))
            struct.pack_into('<Q', context, 120, q(context, 128))
            stack = q(context, 152)
            struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
            struct.pack_into('<Q', context, 152, stack + 8)
            self.record(event='diagnostic_boss_native_placement', position=position)
            return
        return super().__call__(client, rva, context)

    def record(self, **event):
        if event.get('event') == 'boss_hud_delivered':
            if event['player'] == 2:
                assert event['boss'] == self.host_boss_hud
                self.hud_samples += 1
            if event['boss']:
                self.boss_seen = True
            elif self.boss_seen and self.boss_guid is not None:
                self.boss_cleared = True
        super().record(**event)

    def filter_packet(self, number, opcode, body):
        if number == 1 and opcode == UPDATE:
            for block in objects(body, remap=False):
                if block.guid == self.boss_guid and block.object_type == 3:
                    self.creates.append(block.fields)
                    self.record(event='boss_entity_created', guid=block.guid, fields=block.fields)
        return super().filter_packet(number, opcode, body)

    def before_batch(self, client, context):
        game = client.server + 0x10
        if client.number in self.ready and self.native_states[client.number][0] == 1:
            # Disposable encounter protection, explicitly mirrored to the UI.
            client.put(game + game_field(0x4A0), struct.pack('<f', 100000))
            if client.number not in self.health_boosted:
                self.health_boosted.add(client.number)
                client.put(game + game_field(0x4F8), struct.pack('<f', 100000))
                self.notice_packets[client.number].append((UPDATE, values_packet(SELF, {22: 100000, 28: 100000})))
            second = int(self.host_clock)
            if client.number == 1 and self.boss_guid in self.enemy_snapshot and second >= 30 and second != self.last_hit:
                self.last_hit = second
                client.call_before(context, DAMAGE, game, self.boss_guid, damage=100000)
                return True
        if self.finished and client.number == 1 and not self.spawned and self.native_states[1][0] == 1:
            self.spawned = True
            game = client.server + 0x10
            def completed():
                pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x568), 16))
                self.boss_guid = q(client.memory(pointer + (count - 1) * 0x148 + 0x78, 8))
                self.record(event='diagnostic_boss_spawned', guid=self.boss_guid)
            client.call_before(context, SPAWN_BOSS, game, client.base + relocated(0x65EFA08) + 4 * 0x58, after=completed)
            return True
        return super().before_batch(client, context)


if __name__ == '__main__':
    with (ROOT / f'analysis/{BUILD}-boss-visual.jsonl').open('w', encoding='utf-8') as output:
        bridge = BossVerification(output)
        try:
            run(150, 2, bridge)
        finally:
            bridge.record(event='summary', boss_guid=bridge.boss_guid, hud_samples=bridge.hud_samples,
                          boss_seen=bridge.boss_seen, boss_cleared=bridge.boss_cleared, **bridge.counts)
    assert len(bridge.creates) == 1, bridge.creates
    assert bridge.boss_seen and bridge.hud_samples > 10
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered']
    print(json.dumps(dict(boss_seen=bridge.boss_seen, boss_cleared=bridge.boss_cleared, **bridge.counts)))
