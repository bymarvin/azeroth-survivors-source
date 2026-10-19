"""Live, disposable test of native lethal damage and teammate revival."""
import json
import struct
import time
import argparse

from native_probe import ROOT, HURT, game_field, BUILD, run
from verify_coop import Verification
from visibility_bridge import native_enemies


class RevivalVerification(Verification):
    updated_world_probe = True
    def __init__(self, output):
        super().__init__(output)
        self.killed, self.revived = [], []
        self.death_clocks = {}
        self.death_pause_step = 4
        self.death_pause_requested = False
        self.death_pause_observed = None

    def record(self, **event):
        if event.get('event') == 'player_revived':
            host = self.clients[1]
            clock = struct.unpack('<f', host.memory(host.server + 0x10 + game_field(0x85C), 4))[0]
            event['world_advanced'] = clock - self.death_clocks[event['player']]
            assert event['world_advanced'] > 0, 'Shared world froze during teammate death'
            self.revived.append(event['player'])
        super().record(**event)

    def before_batch(self, client, context):
        number = client.number
        if self.death_pause_step < 4:
            # A real level-up can interrupt the pause matrix during the death.
            # Spend its independent choices before continuing the control test.
            if any(state[0] == 2 for state in self.native_states.values()):
                self.death_pause_observed = None
                return super().before_batch(client, context)
            dead = self.killed[-1]
            source, paused = [(dead, True), (3 - dead, False),
                              (3 - dead, True), (dead, False)][self.death_pause_step]
            assert self.native_states[dead][0] == 4, 'Pause accidentally revived the character'
            if not self.death_pause_requested and number == source:
                from native_probe import PAUSE, RESUME
                self.death_pause_requested = True
                client.call_before(context, PAUSE if paused else RESUME,
                                   client.server + 0x10, request=True)
                return True
            if self.death_pause_requested and not self.pause_pending and self.router.paused == paused:
                host = self.clients[1]
                clock = struct.unpack('<f', host.memory(host.server + 0x10 + game_field(0x85C), 4))[0]
                if self.death_pause_observed is None:
                    self.death_pause_observed = time.monotonic(), clock
                elif time.monotonic() - self.death_pause_observed[0] >= .4:
                    delta = clock - self.death_pause_observed[1]
                    assert delta == 0 if paused else delta > 0, (paused, delta)
                    self.record(event='downed_pause_verified', dead=dead, player=source, paused=paused)
                    self.death_pause_step += 1
                    self.death_pause_requested = False
                    self.death_pause_observed = None
            return False
        if self.finished and len(self.killed) == len(self.revived) and len(self.killed) < 2:
            target = (2, 1)[len(self.killed)]
            if number == target and all(s[0] == 1 and s[1] >= 2 for s in self.native_states.values()):
                # Kill the host only when the guest has a real target to attack.
                if target == 1:
                    pose = self.router.players[0xFF0102].pose
                    if not any(hp > 0 and sum((a - b) ** 2 for a, b in zip(
                            position, (pose.x, pose.y, pose.z))) <= self.guest_stats[3] ** 2
                            for _, hp, position in native_enemies(client, client.server + 0x10)):
                        return super().before_batch(client, context)
                    self.next_guest_attack = 0
                self.killed.append(number)
                game = client.server + 0x10
                progress = struct.unpack('<II', client.memory(game + game_field(0x498), 8))
                def completed():
                    host = self.clients[1]
                    self.death_clocks[number] = struct.unpack('<f', host.memory(host.server + 0x10 + game_field(0x85C), 4))[0]
                    phase = client.memory(game + game_field(0x8BF), 1)[0]
                    self.record(event='diagnostic_lethal_hit', player=number, phase=phase, progress=progress)
                    assert phase == 4, 'Native lethal damage did not enter death state'
                    self.death_pause_step = 0
                client.call_before(context, HURT, game, next(iter(self.world_guids)), damage=100000, after=completed)
                return True
        return super().before_batch(client, context)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-combat', action='store_true')
    args = parser.parse_args()
    verification = RevivalVerification
    if args.native_combat:
        from native_guest_combat import NativeCombatBridge
        class NativeRevivalVerification(RevivalVerification, NativeCombatBridge):
            pass
        verification = NativeRevivalVerification
    path = ROOT / f'analysis/{BUILD}-revival-verification.jsonl'
    with path.open('w', encoding='utf-8') as output:
        bridge = verification(output)
        try:
            run(100, 2, bridge)
        finally:
            bridge.record(event='summary', killed=bridge.killed, revived=bridge.revived, **bridge.counts)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert bridge.killed == bridge.revived == [2, 1], (bridge.killed, bridge.revived)
    assert any(e['event'] in ('guest_damage', 'native_guest_damage_applied') and e.get('host_downed')
               for e in events), 'Guest could not fight while host was down'
    assert len([e for e in events if e['event'] == 'downed_pause_verified']) == 8
    assert [e['player'] for e in events if e['event'] == 'downed_ui_replaced'] == [2, 1]
    loaded = [i for i, e in enumerate(events) if e['event'] == 'client_loaded']
    started = [i for i, e in enumerate(events) if e['event'] == 'native_start']
    assert len(loaded) == 2 and min(started) > max(loaded), 'Started fighting before both clients loaded'
    for event in events:
        if event['event'] == 'player_revived':
            assert event['progress_before'][:2] == event['progress_after'], event
    assert bridge.counts['world_captured'] == bridge.counts['world_delivered']
    assert bridge.native_states[1][1:3] == bridge.native_states[2][1:3]
    print(json.dumps(dict(revived=bridge.revived, **bridge.counts)), flush=True)
