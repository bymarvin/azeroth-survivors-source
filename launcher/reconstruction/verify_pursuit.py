"""Disposable native pursuit check using explicitly synthetic test positions."""
import json
import struct
import time

from native_probe import ROOT, run
from sessions import Pose
from visibility_bridge import native_enemies
from verify_coop import Verification


class PursuitVerification(Verification):
    def __init__(self, output):
        super().__init__(output)
        self.target = None
        self.pursuit_verified = False

    def before_batch(self, client, context):
        if client.number == 1 and self.finished and not self.pursuit_verified:
            game = client.server + 0x10
            if all(s[0] == 1 for s in self.native_states.values()):
                pointer, count = struct.unpack('<QQ', client.memory(game + 0x568, 16))
                enemies = native_enemies(client, game)
                if self.target is None and enemies:
                    host = self.router.players[0xFF0101].pose
                    self.original_guest = self.router.players[0xFF0102].pose
                    self.router.players[0xFF0102].pose = Pose(host.x + 30, host.y, host.z, 0)
                    guid = enemies[0][0]
                    for index in range(count):
                        address = pointer + index * 0x148
                        if struct.unpack('<Q', client.memory(address + 0x78, 8))[0] == guid:
                            position = (host.x + 20, host.y, host.z)
                            client.put(address + 0xFC, struct.pack('<6f', *position, *position))
                            client.put(address + 0x114, bytes(16))
                            self.target = guid, position[0], time.monotonic()
                            self.record(event='synthetic_pursuit_setup', target=guid, host_x=host.x,
                                        guest_x=host.x + 30, enemy_x=position[0])
                            break
                elif self.target is not None:
                    guid, start_x, began = self.target
                    for index in range(count):
                        address = pointer + index * 0x148
                        if struct.unpack('<Q', client.memory(address + 0x78, 8))[0] == guid:
                            end_x = struct.unpack('<f', client.memory(address + 0x108, 4))[0]
                            if end_x > start_x + .1:
                                self.pursuit_verified = True
                                self.router.players[0xFF0102].pose = self.original_guest
                                self.record(event='guest_pursuit_verified', target=guid, start_x=start_x, end_x=end_x)
                    assert self.pursuit_verified or time.monotonic() - began < 8, 'Enemy did not pursue nearer guest'
        return super().before_batch(client, context)


if __name__ == '__main__':
    path = ROOT / 'analysis/coop-pursuit-verification.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = PursuitVerification(output)
        try:
            run(90, 2, bridge)
        finally:
            bridge.record(event='summary', pursuit_verified=bridge.pursuit_verified, **bridge.counts)
    assert bridge.pursuit_verified
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered']
    print(json.dumps(dict(pursuit_verified=True, **bridge.counts)), flush=True)
