"""Exercise native guest slow, weakening and stun against shared host enemies."""
import json
import struct

from native_probe import ROOT, APPLY_EFFECT, APPLY_DOT, q, game_field, BUILD, run
from native_guest_combat import NativeCombatBridge
from verify_coop import Verification


class DebuffVerification(Verification, NativeCombatBridge):
    def __init__(self, output):
        super().__init__(output)
        self.effects = [(1, .5, 8), (10, .25, 8), (2, 2, 0)]
        self.verified = []
        self.in_flight = False
        self.dot_target = None
        self.periodic_packets = 0
        self.periodic_damage = []

    def record(self, **event):
        if event.get('event') == 'native_guest_combat' and event['opcode'] == 0x24E:
            self.periodic_packets += 1
        if (event.get('event') == 'native_guest_damage_applied' and event['target'] == self.dot_target and
                abs(event['requested'] - 2) < .0001):
            assert abs(event['before'] - event['after'] - 2) < .0001
            self.periodic_damage.append(event)
        if event.get('event') == 'guest_effect_applied' and self.in_flight:
            host = self.clients[1]
            game = host.server + 0x10
            pointer, count = struct.unpack('<QQ', host.memory(game + game_field(0x568), 16))
            target = next(pointer + i * 0x148 for i in range(count)
                          if q(host.memory(pointer + i * 0x148 + 0x78, 8)) == event['target'])
            kind = event['kind']
            clock = struct.unpack('<f', host.memory(game + game_field(0x85C), 4))[0]
            if kind in (1, 10):
                value, expires = struct.unpack('<ff', host.memory(target + (0x88 if kind == 1 else 0x90), 8))
                assert value == (.5 if kind == 1 else .25)
            else:
                expires = struct.unpack('<f', host.memory(target + 0x130, 4))[0]
            assert expires > clock, (kind, expires, clock)
            self.verified.append(kind)
            self.in_flight = False
            event.update(verified_native_expiry=expires, clock=clock)
        super().record(**event)

    def before_batch(self, client, context):
        if (client.number == 2 and len(self.verified) == 3 and self.dot_target is None and
                self.native_states[2][0] == 1):
            game = client.server + 0x10
            pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x568), 16))
            for i in range(count):
                address = pointer + i * 0x148
                guid = q(client.memory(address + 0x78, 8))
                if self.provided_hp.get(guid, 0) > 30:
                    self.dot_target = guid
                    clock = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
                    client.call_before(context, APPLY_DOT, address, 12721, damage=6, periodic=(3, 3, clock))
                    return True
        if (self.finished and client.number == 2 and self.native_states[2][0] == 1 and
                not self.in_flight and len(self.verified) < len(self.effects) and self.provided_hp):
            target = next((guid for guid in self.provided_hp if guid in self.enemy_snapshot), None)
            if target is not None:
                self.in_flight = True
                effect = struct.pack('<Iff', *self.effects[len(self.verified)])
                client.call_before(context, APPLY_EFFECT, client.server + 0x10, target, effect=effect)
                return True
        return super().before_batch(client, context)


if __name__ == '__main__':
    path = ROOT / f'analysis/{BUILD}-debuff-verification.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = DebuffVerification(output)
        try:
            run(90, 2, bridge)
        finally:
            bridge.record(event='summary', verified=bridge.verified, periodic_packets=bridge.periodic_packets,
                          periodic_damage=len(bridge.periodic_damage), **bridge.counts)
    assert bridge.verified == [1, 10, 2], bridge.verified
    assert bridge.periodic_packets >= 3, bridge.periodic_packets
    assert len(bridge.periodic_damage) == 3, len(bridge.periodic_damage)
    assert not bridge.effects_pending and not bridge.damage_pending
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered']
    print(json.dumps(dict(effects=bridge.verified, periodic_packets=bridge.periodic_packets, **bridge.counts)))
