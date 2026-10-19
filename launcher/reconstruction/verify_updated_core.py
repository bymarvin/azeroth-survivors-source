"""Updated-build native calls and shared pause; worlds are still independent."""
import json
import struct
import time

from native_probe import (BUILD, ROOT, WRITE, START, AWARD_XP, CHOOSE, MOVE,
                          PAUSE, RESUME, game_field, q, run)
from visibility_bridge import Bridge


class Verification(Bridge):
    def __init__(self, output):
        super().__init__(output)
        self.autostart = False
        self.extra_hooks = (START, MOVE, PAUSE, RESUME, AWARD_XP, CHOOSE)
        self.step = 0
        self.states = {}
        self.awarded = set()
        self.spent = set()
        self.requested = False
        self.checked_at = 0
        self.pause_clocks = None

    def __call__(self, client, rva, context):
        if rva == CHOOSE and client.number in self.awarded:
            self.spent.add(client.number)
        if (rva == WRITE and client.number in self.ready and
                q(client.memory(q(context, 152), 8)) == client.base + 0x53C2246):
            self.check_loading()
            game = client.server + 0x10
            phase = client.memory(game + game_field(0x8BF), 1)[0]
            level, xp = struct.unpack('<II', client.memory(game + game_field(0x498), 8))
            clock = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
            self.states[client.number] = (phase, level, xp, clock)
            if len(self.loaded) == 2 and phase == 0:
                client.call_before(context, START, game)
                return
            if len(self.states) == 2 and phase == 1 and client.number not in self.awarded:
                self.awarded.add(client.number)
                client.call_before(context, AWARD_XP, game, 20)
                return
            if phase == 2:
                client.call_before(context, CHOOSE, game, client.number - 1)
                return
            # Either player's normal native pause/resume entry must fan out.
            actions = ((1, PAUSE, 3), (2, RESUME, 1), (2, PAUSE, 3), (1, RESUME, 1))
            if self.step < len(actions) and len(self.spent) == 2:
                owner, command, expected = actions[self.step]
                if not self.requested and all(s[0] == (1 if command == PAUSE else 3) for s in self.states.values()):
                    if client.number == owner:
                        self.requested = True
                        self.checked_at = time.monotonic()
                        self.pause_clocks = None
                        client.call_before(context, command, game, request=True)
                        return
                if self.requested and not self.pause_pending and all(s[0] == expected for s in self.states.values()):
                    clocks = {n: s[3] for n, s in self.states.items()}
                    if self.pause_clocks is None:
                        self.pause_clocks = clocks
                        self.checked_at = time.monotonic()
                    elif time.monotonic() - self.checked_at > .5:
                        if expected == 3:
                            assert clocks == self.pause_clocks, 'Clock advanced while paused'
                        else:
                            assert all(clocks[n] > self.pause_clocks[n] for n in clocks), 'Clock did not resume'
                        self.record(event='updated_pause_verified', owner=owner, paused=expected == 3)
                        self.step += 1
                        self.requested = False
            if self.step == 4:
                self.stop_requested = True
        return super().__call__(client, rva, context)


def main():
    if BUILD != 'updated':
        raise RuntimeError('Set COOP_BUILD=updated for this verifier')
    with (ROOT / 'analysis/updated-core-verification.jsonl').open('w') as output:
        bridge = Verification(output)
        run(100, 2, bridge)
        result = dict(pause_cases=bridge.step, awarded=sorted(bridge.awarded),
                      independent_choices=sorted(bridge.spent), states=bridge.states,
                      **bridge.counts)
        bridge.record(event='summary', **result)
    assert bridge.step == 4 and bridge.spent == {1, 2}, result
    assert all(s[1] >= 2 for s in bridge.states.values()), result
    print(json.dumps(result))


if __name__ == '__main__':
    main()
