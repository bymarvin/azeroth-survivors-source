"""Force both native characters down and require both native defeat messages."""
import json

from native_probe import ROOT, HURT, run
from verify_coop import Verification


class TeamDefeatVerification(Verification):
    def __init__(self, output):
        super().__init__(output)
        self.killed = set()
        self.defeat_delivered = set()

    def record(self, **event):
        if event.get('event') == 'team_defeat_delivered':
            self.defeat_delivered.add(event['player'])
        super().record(**event)

    def before_batch(self, client, context):
        if self.finished and client.number not in self.killed and self.native_states[client.number][0] == 1:
            self.killed.add(client.number)
            client.call_before(context, HURT, client.server + 0x10,
                               next(iter(self.world_guids)), damage=100000)
            return True
        return super().before_batch(client, context)


if __name__ == '__main__':
    path = ROOT / 'analysis/coop-team-defeat-verification.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = TeamDefeatVerification(output)
        try:
            run(100, 2, bridge)
        finally:
            bridge.record(event='summary', defeat_delivered=sorted(bridge.defeat_delivered), **bridge.counts)
    assert bridge.defeat_delivered == {1, 2}, bridge.defeat_delivered
    assert all(state[0] == 4 for state in bridge.native_states.values())
    print(json.dumps(dict(defeat_delivered=sorted(bridge.defeat_delivered), **bridge.counts)), flush=True)
