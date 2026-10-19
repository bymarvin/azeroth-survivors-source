"""Native Again request followed by a fresh two-client combat session."""
import json
import struct

from native_probe import ROOT, UI_COMMAND, allocate, checked, run
from verify_coop import Verification, verify_recording
from verify_team_defeat import TeamDefeatVerification


class RestartVerification(TeamDefeatVerification):
    def before_batch(self, client, context):
        if self.defeat_delivered == {1, 2} and client.number == 2:
            command = checked(allocate(client.handle, None, 0xE8, 0x3000, 4))
            client.put(command, struct.pack('<I', 6) + bytes(0xE4))
            client.call_before(context, UI_COMMAND, client.server, command, request=True)
            return True
        return super().before_batch(client, context)


if __name__ == '__main__':
    with (ROOT / 'analysis/coop-restart-request.jsonl').open('w', encoding='utf-8') as output:
        bridge = RestartVerification(output)
        run(100, 2, bridge)
        assert bridge.restart_requested and bridge.defeat_delivered == {1, 2}
        bridge.record(event='restart_clients_closed')
    path = ROOT / 'analysis/coop-after-restart.jsonl'
    with path.open('w', encoding='utf-8') as output:
        fresh = Verification(output)
        run(90, 2, fresh)
        fresh.record(event='summary', **fresh.counts)
    verify_recording(path)
    print(json.dumps(dict(restarted=True, players=len(fresh.clients))), flush=True)
