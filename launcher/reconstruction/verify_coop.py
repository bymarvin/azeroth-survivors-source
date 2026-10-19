"""Bounded live native-handler check. Chooses different talent slots automatically.

Does not synthesize keyboard input or claim verification of the Escape binding.
"""
import json
import math
import struct
import time

from native_probe import ROOT, PAUSE, RESUME, CHOOSE, game_field, run
from visibility_bridge import Bridge


class Verification(Bridge):
    def __init__(self, output):
        super().__init__(output, shared_world=True)
        self.steps = [(1, True), (2, False), (2, True), (1, False)]
        if len(self.members) > 2:
            self.steps = [(source, paused) for n in self.members
                          for source, paused in ((n, True), (n % len(self.members) + 1, False))]
        self.step, self.requested, self.observed = 0, False, None
        self.finished = False
        self.choice_started = {}

    def talent_slot(self, client, choices):
        return min(client.number - 1, choices - 1)

    def before_batch(self, client, context):
        game = client.server + 0x10
        if self.native_states[client.number][0] == 2:
            key = client.number, self.native_states[client.number][1], self.native_states[client.number][3]
            began = self.choice_started.setdefault(key, time.monotonic())
            if time.monotonic() - began < (1.5 if client.number == 2 else .1):
                return False
            choices = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
            if not 1 <= choices <= 16:
                raise ValueError('Unexpected native talent choices')
            slot = self.talent_slot(client, choices)
            self.record(event='diagnostic_choose', player=client.number, slot=slot)
            client.call_before(context, CHOOSE, game, slot)
            return True
        if len(self.native_states) == len(self.members) and self.step < len(self.steps):
            source, paused = self.steps[self.step]
            phases = [self.native_states[n][0] for n in self.members]
            if not self.requested and phases == ([1] * len(self.members) if paused else [3] * len(self.members)) and client.number == source:
                self.requested = True
                self.record(event='diagnostic_request', player=source, paused=paused)
                client.call_before(context, PAUSE if paused else RESUME, game, request=True)
                return True
            if self.requested and phases == ([3] * len(self.members) if paused else [1] * len(self.members)) and not self.pause_pending:
                host = self.clients[1]
                clock = struct.unpack('<f', host.memory(host.server + 0x10 + game_field(0x85C), 4))[0]
                if self.observed is None:
                    self.observed = time.monotonic(), clock
                elif time.monotonic() - self.observed[0] >= 1:
                    delta = clock - self.observed[1]
                    if (paused and delta != 0) or (not paused and delta <= 0):
                        raise AssertionError(f'Pause clock mismatch: paused={paused}, delta={delta}')
                    self.record(event='pause_verified', player=source, paused=paused, phases=phases, clock_delta=delta)
                    self.step += 1
                    self.requested, self.observed = False, None
        if self.step == len(self.steps) and not self.finished:
            self.finished = True
            self.record(event='pause_matrix_complete')
        return super().before_batch(client, context)


def verify_recording(path):
    events = [json.loads(line) for line in path.read_text().splitlines()]
    pauses = [(e['player'], e['paused']) for e in events if e['event'] == 'pause_verified']
    assert pauses == [(1, True), (2, False), (2, True), (1, False)], pauses
    hits = [e for e in events if e['event'] == 'guest_damage']
    assert hits and all(e['before'] > e['after'] for e in hits)
    for hit in hits:
        assert math.isclose(hit['damage'], min(hit['before'], max(1, hit['requested_damage'])),
                            rel_tol=1e-5, abs_tol=1e-4), 'Host modifiers changed guest damage'
        if hit['after'] > 0:
            assert hit['host_health_before'] == hit['host_health_after'], 'Guest hit healed the host'
    for number in (1, 2):
        delivered = [e for e in events if e['event'] == 'guest_attack_delivered' and e['recipient'] == number]
        assert len(delivered) == len(hits), (number, len(delivered), len(hits))
        choices = [e['slot'] for e in events if e['event'] == 'native_talent_choice' and e['player'] == number]
        assert choices and set(choices) == {number - 1}, choices
    states = [next(e for e in reversed(events) if e['event'] == 'native_state' and e['player'] == n) for n in (1, 2)]
    assert (states[0]['level'], states[0]['xp']) == (states[1]['level'], states[1]['xp'])
    assert states[0]['level'] >= 2
    hurts = [e for e in events if e['event'] == 'guest_hurt']
    redirected = [e for e in events if e['event'] == 'enemy_hit_redirected']
    assert len(hurts) == len(redirected), 'Accepted enemy hit was not applied'
    for n in (1, 2):
        received = [e for e in events if e['event'] == 'guest_hurt_delivered' and e['recipient'] == n]
        assert len(received) == 2 * len(hurts), 'Guest health/hit replication incomplete'
    captured = [(e['opcode'], e['digest']) for e in events if e['event'] == 'world_captured']
    delivered = [(e['opcode'], e['digest']) for e in events if e['event'] == 'world_delivered']
    assert captured == delivered, 'Shared world delivery mismatch'
    result = dict(pause_cases=4, guest_hits=len(hits), guest_kills=sum(e['after'] <= 0 for e in hits),
                  level=states[0]['level'], xp=states[0]['xp'], world_packets=len(delivered),
                  guest_incoming_hits=len(hurts), guest_health_lost=sum(e['before'] - e['after'] for e in hurts))
    print(json.dumps(result), flush=True)
    return result


if __name__ == '__main__':
    with (ROOT / 'analysis/coop-native-verification.jsonl').open('w', encoding='utf-8') as output:
        bridge = Verification(output)
        try:
            run(90, 2, bridge)
        finally:
            bridge.record(event='summary', pause_complete=bridge.finished, **bridge.counts)
            print(json.dumps(dict(pause_complete=bridge.finished, **bridge.counts)), flush=True)
        if not bridge.finished:
            raise SystemExit('Native pause matrix did not finish')
    verify_recording(ROOT / 'analysis/coop-native-verification.jsonl')
