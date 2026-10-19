"""Research probe: exercise native guest player actions against a local mirror.

This does not yet apply the resulting ability damage to the authoritative host.
The probe's independent guest XP awards are suppressed.
"""
import json
import struct

from native_probe import ROOT, SPAWN, AWARD_XP, q, run
from visibility_bridge import absolute_jump, native_enemies
from world_packets import COMBAT
from verify_coop import Verification


class GuestAbilitiesVerification(Verification):
    def __init__(self, output):
        super().__init__(output)
        self.mirror = None
        self.guest_combat_packets = 0

    def __call__(self, client, rva, context):
        if client.number == 2 and rva == AWARD_XP and client.saved_context is None:
            stack = q(context, 152)
            struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
            struct.pack_into('<Q', context, 152, stack + 8)
            self.record(event='mirror_xp_suppressed')
            return
        return super().__call__(client, rva, context)

    def filter_packet(self, number, opcode, body):
        if number == 2 and self.mirror and opcode in COMBAT:
            self.guest_combat_packets += 1
            self.record(event='native_guest_combat', opcode=opcode, body=body.hex())
        return super().filter_packet(number, opcode, body)

    def before_batch(self, client, context):
        self.next_guest_attack = float('inf')
        if client.number == 2 and self.finished and self.mirror is None and self.native_states[2][0] == 1:
            game = client.server + 0x10
            pose = self.router.players[0xFF0102].pose
            before_count = struct.unpack('<Q', client.memory(game + 0x570, 8))[0]
            def completed():
                pointer, count = struct.unpack('<QQ', client.memory(game + 0x568, 16))
                assert count == before_count + 1, (before_count, count)
                # START already seeds four guest-local enemies. They are hidden
                # from rendering; retire them so this probe has one known target.
                for index in range(before_count):
                    client.put(pointer + index * 0x148 + 0x68, struct.pack('<I', 1))
                    client.put(pointer + index * 0x148 + 0xE0, bytes(4))
                address = pointer + before_count * 0x148
                self.mirror = struct.unpack('<Q', client.memory(address + 0x78, 8))[0]
                client.put(address + 0xE0, struct.pack('<ff', 100000, 100000))
                # Player actions run, while native independent world work is skipped.
                address = client.base + 0x53E2C7B
                expected = bytes.fromhex('f3410f10bd5c080000 f2410f108588040000')
                assert client.memory(address, len(expected)) == expected
                client.patch(address, absolute_jump(client.base + 0x53EA3A8) + b'\x90' * 4)
                client.patch(client.base + 0x53DC9F5, bytes.fromhex('0f85add90000'))
                self.record(event='native_guest_mirror_created', target=self.mirror)
            client.call_before(context, SPAWN, game, 0, position=(pose.x + 2, pose.y, pose.z), after=completed)
            return True
        return super().before_batch(client, context)


if __name__ == '__main__':
    path = ROOT / 'analysis/coop-guest-abilities-probe.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = GuestAbilitiesVerification(output)
        try:
            run(100, 2, bridge)
        finally:
            bridge.record(event='summary', native_guest_combat=bridge.guest_combat_packets, **bridge.counts)
    assert bridge.mirror and bridge.guest_combat_packets
    print(json.dumps(dict(native_guest_combat=bridge.guest_combat_packets)), flush=True)
