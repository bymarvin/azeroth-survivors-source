"""Four native clients: independent choices, shared XP, gold, combat and delivery."""
import json
import struct

from native_guest_combat import NativeCombatBridge
from native_probe import ROOT, CHOOSE, SPAWN_LOOT, HURT, game_field, run
from verify_coop import Verification


class GroupVerification(Verification, NativeCombatBridge):
    def __init__(self, output):
        super().__init__(output)
        if len(self.members) != 4:
            raise ValueError('Set COOP_PLAYERS=4')
        self.choices = set()
        self.attacking = set()
        self.gold_before = None
        self.gold_verified = False
        self.killed, self.revived = [], []
        self.maps = {}

    def record(self, **event):
        if event.get('event') == 'native_guest_combat':
            self.attacking.add(event['player'])
        if event.get('event') == 'player_revived':
            assert tuple(event['progress_before'][:2]) == tuple(event['progress_after']), event
            self.revived.append(event['player'])
        super().record(**event)

    def balances(self):
        return [struct.unpack('<I', self.clients[n].memory(self.clients[n].server + 0x10 + game_field(0x4A8), 4))[0]
                for n in self.members]

    def before_batch(self, client, context):
        game = client.server + 0x10
        if client.number in self.ready and client.number not in self.maps:
            pointer, length = struct.unpack('<QQ', client.memory(game + 0x2D8, 16))
            assert 1 <= length <= 16
            self.maps[client.number] = client.memory(pointer, length).decode('ascii')
            assert len(set(self.maps.values())) == 1, self.maps
        if self.native_states[client.number][0] == 2:
            count = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
            if not 1 <= count <= 16:
                raise ValueError('Invalid choice count')
            self.choices.add(client.number)
            client.call_before(context, CHOOSE, game, (client.number - 1) % count)
            return True
        if self.ready == set(self.members) and all(s[0] == 1 for s in self.native_states.values()):
            if self.finished and self.killed == self.revived and len(self.killed) < 4 and self.world_guids:
                target = (2, 3, 4, 1)[len(self.killed)]
                if client.number == target:
                    self.killed.append(target)
                    client.call_before(context, HURT, game, next(iter(self.world_guids)), damage=100000)
                    return True
            if client.number == 1 and self.gold_before is None:
                self.gold_before = self.balances()
                pose = self.router.players[0xFF0101].pose
                client.call_before(context, SPAWN_LOOT, game, 1, amount=100, position=(pose.x, pose.y, pose.z))
                return True
            if self.gold_before is not None and not self.gold_verified:
                gains = [now - before for now, before in zip(self.balances(), self.gold_before)]
                if min(gains) >= 100 and len(set(gains)) == 1:
                    self.gold_verified = True
                    self.record(event='four_player_gold_verified', gain=gains[0])
        return super().before_batch(client, context)


if __name__ == '__main__':
    path = ROOT / 'analysis/updated-four-player-verification.jsonl'
    with path.open('w') as output:
        bridge = GroupVerification(output)
        try:
            run(240, 4, bridge)
        finally:
            result = dict(choices=sorted(bridge.choices), attacking=sorted(bridge.attacking),
                          gold_verified=bridge.gold_verified, revived=bridge.revived,
                          states=bridge.native_states, **bridge.counts)
            bridge.record(event='summary', **result)
    assert bridge.choices == {1, 2, 3, 4}, result
    assert bridge.attacking == {2, 3, 4}, result
    assert bridge.gold_verified, result
    assert bridge.finished and bridge.step == 8, result
    assert bridge.killed == bridge.revived == [2, 3, 4, 1], result
    assert len({s[1:3] for s in bridge.native_states.values()}) == 1, result
    assert bridge.counts['created'] == 12, result
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered'], result
    print(json.dumps(result))
