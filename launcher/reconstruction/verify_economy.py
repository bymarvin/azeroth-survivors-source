"""Native pickup and private chest checks with disposable loot and test positions."""
import json
import struct

from native_probe import ROOT, SPAWN_LOOT, game_field, BUILD, run
from native_guest_combat import NativeCombatBridge
from verify_coop import Verification
from sessions import Pose


class EconomyVerification(Verification, NativeCombatBridge):
    updated_world_probe = True

    def sync_revival(self, client, context):
        if BUILD == 'updated':
            return False  # Updated defeat UI is not enabled by this economy probe.
        return super().sync_revival(client, context)

    def __init__(self, output):
        super().__init__(output)
        self.economy_step = 0
        self.economy_before = None
        self.chest_price = 0
        self.xp_pickup_seen = False

    def record(self, **event):
        if event.get('event') == 'guest_xp_pickup':
            self.xp_pickup_seen = True
        super().record(**event)

    def balances(self):
        result = []
        for number in (1, 2):
            client = self.clients[number]
            game = client.server + 0x10
            gold = struct.unpack('<I', client.memory(game + game_field(0x4A8), 4))[0]
            earned, opened = struct.unpack('<II', client.memory(game + game_field(0x6D0), 8))
            result.append((gold, earned - gold, opened))
        return result

    def before_batch(self, client, context):
        game = client.server + 0x10
        if self.finished:
            if self.economy_step == 0 and client.number == 2:
                host = self.router.players[0xFF0101].pose
                pose = Pose(host.x + 30, host.y, host.z, 0)
                self.router.players[0xFF0102].pose = pose
                client.put(game + game_field(0x488), struct.pack('<4f', pose.x, pose.y, pose.z, pose.facing))
                self.economy_step = 1
            current = self.balances()
            if self.economy_step in (2, 4):
                amount = 100 if self.economy_step == 2 else 40
                if all(current[n][0] >= self.economy_before[n][0] + amount for n in (0, 1)):
                    assert current[0][0] - self.economy_before[0][0] == current[1][0] - self.economy_before[1][0]
                    self.record(event='economy_pickup_verified', picker=1 if amount == 100 else 2,
                                amount=amount, balances=current)
                    self.economy_step += 1
            elif self.economy_step in (6, 8):
                opener = 1 if self.economy_step == 6 else 0
                other = 1 - opener
                if current[opener][2] == self.economy_before[opener][2] + 1:
                    assert current[other][2] == self.economy_before[other][2], 'Chest awarded both players'
                    assert current[opener][1] == self.economy_before[opener][1] + self.chest_price
                    assert current[other][1] == self.economy_before[other][1], 'Chest charged the other player'
                    self.record(event='economy_chest_verified', opener=opener + 1,
                                cost=self.chest_price, balances=current)
                    self.economy_step += 1
            if (self.economy_step == 9 and client.number == 1 and
                    all(state[0] == 1 for state in self.native_states.values())):
                pose = self.router.players[0xFF0102].pose
                self.economy_step = 10
                client.call_before(context, SPAWN_LOOT, game, 0, amount=20,
                                   position=(pose.x, pose.y, pose.z))
                return True
            if (self.economy_step == 10 and self.xp_pickup_seen and not self.pickup_xp_pending and
                    not self.xp_pending and self.native_states[1][1:3] == self.native_states[2][1:3]):
                self.record(event='economy_guest_xp_verified', progress=self.native_states[1][1:3])
                self.economy_step = 11
            if (client.number == 1 and self.economy_step in (1, 3, 5, 7) and
                    all(state[0] == 1 for state in self.native_states.values())):
                recipient = 1 if self.economy_step in (1, 7) else 2
                kind = 1 if self.economy_step < 5 else 2
                amount = 100 if self.economy_step == 1 else 40 if self.economy_step == 3 else 1
                pose = self.router.players[0xFF0100 + recipient].pose
                self.economy_before = current
                owner = self.clients[recipient]
                self.chest_price = struct.unpack('<I', owner.memory(owner.server + 0x10 + game_field(0x894), 4))[0]
                self.economy_step += 1
                self.record(event='diagnostic_loot_spawn', kind=kind, recipient=recipient, amount=amount)
                client.call_before(context, SPAWN_LOOT, game, kind, amount=amount,
                                   position=(pose.x, pose.y, pose.z))
                return True
        return super().before_batch(client, context)


if __name__ == '__main__':
    path = ROOT / f'analysis/{BUILD}-economy-verification.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = EconomyVerification(output)
        try:
            run(100, 2, bridge)
        finally:
            bridge.record(event='summary', economy_step=bridge.economy_step, **bridge.counts)
    assert bridge.economy_step == 11, bridge.economy_step
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered']
    assert not bridge.gold_pending and not bridge.chest_claim
    print(json.dumps(dict(pickup_cases=2, chest_cases=2, world=bridge.counts['world_delivered'])))
