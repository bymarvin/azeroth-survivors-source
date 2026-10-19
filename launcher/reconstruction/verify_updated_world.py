"""Bounded updated-build host-world/XP probe; guest combat is not enabled."""
import json
import argparse

from native_probe import (BUILD, ROOT, WRITE, START, AWARD_XP, CHOOSE, MOVE,
                          PAUSE, RESUME, HURT, game_field, q, run)
from visibility_bridge import Bridge


class Verification(Bridge):
    updated_world_probe = True

    def __init__(self, output, combat=False):
        super().__init__(output, shared_world=True)
        self.extra_hooks = (START, MOVE, PAUSE, RESUME, AWARD_XP, CHOOSE)
        self.combat = combat
        if combat:
            self.extra_hooks += (HURT,)
        self.choices = set()
        self.hits = 0

    def record(self, **event):
        if event.get('event') == 'guest_damage':
            self.hits += 1
        super().record(**event)

    def before_batch(self, client, context):
        return super().before_batch(client, context) if self.combat else False

    def sync_revival(self, client, context):
        return False  # Do not call unported defeat/revival paths in this probe.

    def __call__(self, client, rva, context):
        if (rva == WRITE and client.number in self.ready and
                q(client.memory(q(context, 152), 8)) == client.base + 0x53C2246):
            game = client.server + 0x10
            if client.memory(game + game_field(0x8BF), 1)[0] == 2:
                self.choices.add(client.number)
                client.call_before(context, CHOOSE, game, client.number - 1)
                return
        return super().__call__(client, rva, context)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--combat', action='store_true', help='Enable the updated basic-melee port')
    args = parser.parse_args()
    if BUILD != 'updated':
        raise RuntimeError('Set COOP_BUILD=updated')
    with (ROOT / 'analysis/updated-world-verification.jsonl').open('w') as output:
        bridge = Verification(output, args.combat)
        run(90, 2, bridge)
        result = dict(states=bridge.native_states, choices=sorted(bridge.choices), guest_hits=bridge.hits,
                      **bridge.counts)
        bridge.record(event='summary', **result)
    assert bridge.counts['world_captured'] > 100, result
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered'], result
    assert bridge.native_states[1][1:3] == bridge.native_states[2][1:3], result
    assert bridge.choices == {1, 2}, result
    if args.combat:
        assert bridge.hits >= 3, result
    print(json.dumps(result))


if __name__ == '__main__':
    main()
