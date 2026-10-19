"""Native host-only victory controls, including rejection of guest choices."""
import argparse
import json
import struct

from native_probe import ROOT, UI_COMMAND, allocate, checked, run
from verify_boss_visual import BossVerification


class VictoryControls(BossVerification):
    def __init__(self, output, command):
        super().__init__(output)
        self.command = command
        self.control_step = 0
        self.resumed_at = None
        self.verified = False

    def before_batch(self, client, context):
        phases = {n: state[0] for n, state in self.native_states.items()}
        if self.control_step < 2 and phases == {1: 5, 2: 5}:
            source = 2 if self.control_step == 0 else 1
            if client.number == source:
                if self.control_step == 1:
                    assert self.end_action is None, 'Guest controlled the victory decision'
                    self.record(event='guest_victory_choice_blocked', command=self.command)
                command = checked(allocate(client.handle, None, 0xE8, 0x3000, 4))
                client.put(command, struct.pack('<I', self.command) + bytes(0xE4))
                self.control_step += 1
                client.call_before(context, UI_COMMAND, client.server, command, request=True)
                return True
        if self.control_step == 2 and self.command == 8 and phases == {1: 1, 2: 1}:
            if self.resumed_at is None:
                self.resumed_at = self.host_clock
            elif self.host_clock > self.resumed_at + 1:
                self.verified = True
        return super().before_batch(client, context)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--command', type=int, choices=(8, 9), required=True)
    args = parser.parse_args()
    path = ROOT / f'analysis/updated-victory-control-{args.command}.jsonl'
    with path.open('w') as output:
        bridge = VictoryControls(output, args.command)
        try:
            run(110, 2, bridge)
        finally:
            if args.command == 9:
                bridge.verified = bridge.menu_players == {1, 2}
            result = dict(command=args.command, verified=bridge.verified,
                          menu=sorted(bridge.menu_players), states=bridge.native_states, **bridge.counts)
            bridge.record(event='summary', **result)
    assert bridge.verified, result
    print(json.dumps(result))
