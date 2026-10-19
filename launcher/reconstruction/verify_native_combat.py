"""Verify native guest spell/melee damage reaches authoritative shared enemies."""
import json
import math

from native_probe import ROOT, run
from native_guest_combat import NativeCombatBridge
from verify_coop import Verification


class NativeCombatVerification(Verification, NativeCombatBridge):
    def talent_slot(self, client, choices):
        if client.number == 2:
            # Prefer a real periodic ability when the native random offer has it.
            for line in reversed((client.folder / 'stdout.log').read_text(errors='replace').splitlines()):
                if line.startswith('rogue: {'):
                    try:
                        message = json.loads(line[7:])
                    except json.JSONDecodeError:
                        continue
                    if message.get('type') == 'choices':
                        for slot, choice in enumerate(message.get('choices', [])[:choices]):
                            if any(name in choice.get('title', '') for name in ('Deep Wounds', 'Rend', 'Rupture')):
                                self.record(event='diagnostic_periodic_talent', title=choice['title'])
                                return slot
                        break
        return super().talent_slot(client, choices)


if __name__ == '__main__':
    path = ROOT / 'analysis/coop-native-guest-combat.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = NativeCombatVerification(output)
        try:
            run(120, 2, bridge)
        finally:
            bridge.record(event='summary', native_combat=bridge.native_combat_packets,
                          pending=len(bridge.damage_pending), **bridge.counts)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    applied = [e for e in events if e['event'] == 'native_guest_damage_applied']
    assert applied and all(math.isclose(e['before'] - e['after'], min(e['before'], max(1, e['requested'])),
                                       rel_tol=1e-5, abs_tol=1e-4) for e in applied)
    assert {0x132, 0x250} <= {e['opcode'] for e in events if e['event'] == 'native_guest_combat'}
    assert bridge.finished and not bridge.damage_pending
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered']
    assert bridge.native_states[1][1:3] == bridge.native_states[2][1:3]
    assert not bridge.xp_pending
    print(json.dumps(dict(applied=len(applied), native_combat=bridge.native_combat_packets,
                          world=bridge.counts['world_delivered'])), flush=True)
