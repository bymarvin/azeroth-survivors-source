"""Force the native host objective and verify both native victory results."""
import argparse
import json
import struct

from native_probe import ROOT, HURT, run
from native_guest_combat import NativeCombatBridge
from verify_coop import Verification


class VictoryVerification(Verification, NativeCombatBridge):
    def __init__(self, output, downed=False):
        super().__init__(output)
        self.test_downed = downed
        self.down_requested = self.win_requested = False

    def before_batch(self, client, context):
        if self.finished and not self.win_requested and all(n in self.ready for n in (1, 2)):
            if self.test_downed and not self.down_requested and client.number == 2 and self.native_states[2][0] == 1:
                self.down_requested = True
                client.call_before(context, HURT, client.server + 0x10, 0, damage=100000)
                return True
            if (client.number == 1 and self.native_states[1][0] == 1 and
                    self.native_states[2][0] == (4 if self.test_downed else 1)):
                client.put(client.server + 0x10 + 0x7F0, struct.pack('<I', 1))
                client.put(client.server + 0x10 + 0x8B5, b'\x00')
                self.win_requested = True
                self.record(event='diagnostic_native_objective_completed', guest_downed=self.test_downed)
        return super().before_batch(client, context)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--downed', action='store_true')
    args = parser.parse_args()
    path = ROOT / ('analysis/coop-victory-downed.jsonl' if args.downed else 'analysis/coop-victory.jsonl')
    with path.open('w', encoding='utf-8') as output:
        bridge = VictoryVerification(output, args.downed)
        try:
            run(85, 2, bridge)
        finally:
            bridge.record(event='summary', states=bridge.native_states, **bridge.counts)
    assert bridge.win_requested and bridge.victory_requested
    assert all(state[0] == 5 for state in bridge.native_states.values()), bridge.native_states
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered']
    for client in bridge.clients.values():
        messages = []
        for line in (client.folder / 'stdout.log').read_text(errors='replace').splitlines():
            if line.startswith('rogue: {'):
                messages.append(json.loads(line[7:]))
        assert any(message.get('type') == 'victory' for message in messages), client.number
    print(json.dumps(dict(victory_players=2, guest_downed=args.downed, **bridge.counts)))
