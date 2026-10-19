"""Bounded native pause/revival matrix across four independent TLS peers."""
import struct
import time
import json
import os
from pathlib import Path

from group_online import GroupOnlineBridge
from native_probe import PAUSE, RESUME, CHOOSE, HURT, WRITE, game_field, q, ROOT, EXECUTABLE, ACTIVE_HASH, UpdateCallTest
from updated_layout import field, rva as relocated
from world_packets import COMBAT
from verify_party_evidence import native_pending_field


class NetworkCoopVerification(GroupOnlineBridge):
    def __init__(self, output, number, channels):
        super().__init__(output, number, channels)
        if len(self.members) != 4:
            raise ValueError('Network co-op diagnostic requires four players')
        self.steps = [(n, paused) for source in self.members
                      for n, paused in ((source, True), (source % 4 + 1, False))]
        self.step = 0
        self.requested = set()
        self.observed = None
        self.saw_downed = False
        self.notifications = set()
        self.batch_attacks = []
        # Resolve diagnostic-only fields through the same typed native proof;
        # do not introduce unverified ability offsets into the active adapter.
        from build_hooks import UPDATED_HASH
        candidate = os.environ.get('COOP_CANDIDATE_PROFILE')
        self.progression = json.loads(Path(candidate).read_text()).get('progression_call_contract') if candidate else None
        if self.progression is None:
            from map_build_functions import structural_relocations
            from native_helper_contracts import discover_progression_call_contracts
            reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
            hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
            targets = [hooks[name]['reference_rva'] for name in ('AWARD_XP', 'CHOOSE')]
            self.progression = discover_progression_call_contracts(reference, EXECUTABLE,
                structural_relocations(reference, EXECUTABLE, targets))
        if (self.progression['sha256'] != ACTIVE_HASH or self.progression['reference_sha256'] != UPDATED_HASH
                or self.progression['entries']['CHOOSE']['entry'] != CHOOSE):
            raise ValueError('Talent diagnostic disagrees with active native adapter')

    def __call__(self, client, rva, context):
        self.batch_attacks = []
        result = super().__call__(client, rva, context)
        if (rva == WRITE and self.batch_attacks and client.number in self.buffers
                and q(context, 136) == self.buffers[client.number]
                and not self.attack_packets[client.number] and not self.notice_packets[client.number]):
            for opcode, body in self.batch_attacks:
                self.record(event='network_attack_written', recipient=client.number, opcode=opcode, body=body.hex())
        return result

    def decorate(self, peer, message):
        super().decorate(peer, message)
        if self.number == 1:
            message['diagnostic_step'] = self.step

    def receive_peer(self, peer, message):
        super().receive_peer(peer, message)
        if self.number != 1 and 'diagnostic_step' in message:
            step = message['diagnostic_step']
            if type(step) is not int or not self.step <= step <= 12:
                raise ValueError('Invalid diagnostic step')
            self.step = step
        # Inspect the actual received packet queue, including host-forwarded
        # third-party messages, rather than treating a local send as delivery.
        for opcode, body in self.notice_packets[self.number]:
            if opcode != 0x96:
                continue
            for target in self.members:
                if target == self.number:
                    continue
                for state in ('down', 'revived'):
                    needle = f'Player {target} is down.' if state == 'down' else f'Player {target} revived'
                    key = target, state
                    if needle.encode() in body and key not in self.notifications:
                        self.notifications.add(key)
                        self.record(event='network_revival_notice', player=self.number, target=target, state=state)

    def record(self, **event):
        if self.number == 1 and event.get('event') == 'native_guest_damage_applied':
            remaining = max(0, event['before'] - max(0, event['after']))
            for owner, amount in self.damage_owners.get(event['target'], {}).items():
                applied = min(remaining, amount)
                if applied > 0:
                    super().record(event='network_guest_hit_verified', player=owner, target=event['target'],
                                   before=event['before'], after=event['after'], applied=applied)
                remaining -= applied
        if event.get('event') == 'player_revived':
            if tuple(event['progress_before'][:2]) != tuple(event['progress_after']):
                raise AssertionError('Revival changed native level/XP')
        super().record(**event)

    def lethal_guard_buffs(self, client, game):
        """Active native HURT guard buffs of this player (47e4 family layout; read-only), else []."""
        from updated_layout import release_47e4
        if not release_47e4():
            return []
        pointer, count = struct.unpack('<QQ', client.memory(game + 0x2f8, 16))
        clock = struct.unpack('<f', client.memory(game + 0x8d4, 4))[0]
        rows = [struct.unpack_from('<I12xf', client.memory(pointer + 0x18 * i, 0x18)) for i in range(min(count, 64))]
        return [list(r) for r in rows if r[0] == 0xb and r[1] > clock]

    def lethal_diagnostics(self, client, game):
        """Read-only evidence around the diagnostic lethal HURT (no state is written)."""
        from updated_layout import release_47e4
        def diagnose(stage):
            event = dict(event='network_lethal_state', player=client.number, stage=stage,
                         health=struct.unpack('<f', client.memory(game + game_field(0x4A0), 4))[0],
                         phase=client.memory(game + game_field(0x8BF), 1)[0])
            if release_47e4():
                # HURT 0x5466930 early exits: byte [game+0x947] != 0, or a 24-byte buff with type 0xb whose
                # end time [+0x10] exceeds the clock [game+0x8d4] (vector cap/ptr/len at 0x2f0/0x2f8/0x300).
                pointer, count = struct.unpack('<QQ', client.memory(game + 0x2f8, 16))
                clock = struct.unpack('<f', client.memory(game + 0x8d4, 4))[0]
                rows = [struct.unpack_from('<I12xf', client.memory(pointer + 0x18 * i, 0x18)) for i in range(min(count, 64))]
                event.update(flag_947=client.memory(game + 0x947, 1)[0], clock=clock,
                             guard_buffs=[list(r) for r in rows if r[0] == 0xb and r[1] > clock])
            self.record(**event)
            return event
        return diagnose

    def advance(self):
        self.step += 1
        self.observed = None
        self.saw_downed = False
        self.last_network = 0

    def before_batch(self, client, context):
        if self.stop_requested or self.draining:
            return super().before_batch(client, context)
        self.batch_attacks = [(opcode, body) for opcode, body in
            self.attack_packets[client.number] + self.notice_packets[client.number] if opcode in COMBAT]
        game = client.server + 0x10
        phase = self.native_states[client.number][0]
        if phase == 2:
            return self.choose_independently(client, context, game)
        phases = [self.native_states.get(n, (0,))[0] for n in self.members]
        if phase == 1:
            # Keep unrelated enemies from interrupting the diagnostic; the
            # targeted native lethal hit below remains the real death path.
            client.put(game + game_field(0x4A0), struct.pack('<f', 1000))
            client.put(game + game_field(0x4F8), struct.pack('<f', 1000))
        if self.step < 8:
            source, paused = self.steps[self.step]
            if (client.number == source and self.step not in self.requested
                    and self.ready == set(self.members)
                    # XP replay can leave a pending talent on a paused player.
                    # Resume first so native code can open that player's chooser.
                    and (not paused or not any(state[3] for state in self.native_states.values()))
                    and phases == [1 if paused else 3] * 4):
                self.requested.add(self.step)
                client.call_before(context, PAUSE if paused else RESUME, game, request=True)
                return True
            if self.number == 1 and self.router.paused == paused and phases == [3 if paused else 1] * 4:
                now = time.monotonic()
                if self.observed is None:
                    self.observed = now, self.host_clock
                elif now - self.observed[0] >= 1:
                    delta = self.host_clock - self.observed[1]
                    if (paused and delta != 0) or (not paused and delta <= 0):
                        raise AssertionError('Native pause clock did not match party state')
                    self.record(event='network_pause_verified', player=source, paused=paused, clock_delta=delta)
                    self.advance()
            else:
                self.observed = None
        elif self.step < 12:
            target = (2, 3, 4, 1)[self.step - 8]
            if (client.number == target and self.step not in self.requested
                    and phases == [1] * 4 and self.enemy_snapshot):
                guards = self.lethal_guard_buffs(client, game)
                if guards:
                    # Native HURT ignores hits while a type-0xb guard buff lasts (0.92/0.93 grant one right after
                    # resuming). Injecting calls meanwhile can starve the host's frame, so let native time pass.
                    if getattr(self, 'lethal_waiting', None) != self.step:
                        self.lethal_waiting = self.step
                        self.record(event='network_lethal_wait', player=target, guard_buffs=guards)
                    return super().before_batch(client, context)
                self.requested.add(self.step)
                self.record(event='network_lethal_hit', player=target)
                diagnose = self.lethal_diagnostics(client, game)
                diagnose('before')
                step = self.step
                def completed():
                    # Native HURT ignores hits during a type-0xb guard buff (0.92.0 grants ~1 s right after
                    # resuming); a target that stayed in phase 1 gets the same native hit again next batch.
                    if diagnose('after')['phase'] == 1:
                        self.requested.discard(step)
                        self.record(event='network_lethal_retry', player=target)
                client.call_before(context, HURT, game, next(iter(self.enemy_snapshot)), damage=100000,
                                   after=completed)
                return True
            if self.number == 1:
                self.saw_downed |= phases[target - 1] == 4
                if self.saw_downed and phases == [1] * 4:
                    self.record(event='network_revival_verified', player=target)
                    self.advance()
        elif self.number == 1:
            if self.observed is None:
                self.observed = time.monotonic()
            elif time.monotonic() - self.observed >= 2:
                self.record(event='network_coop_complete')
                self.stop_requested = True
        return super().before_batch(client, context)

    def choose_independently(self, client, context, game):
        if q(client.memory(q(context, 152), 8)) != client.base + relocated(0x539FC26):
            return False  # Other native writes do not own this UI stack frame.
        state = UpdateCallTest.progression_state(self, client, game)
        if state['phase'] != 2:
            return False
        count, pointer = state['choices_count'], state['choices_pointer']
        if not 1 <= count <= 16 or not pointer:
            raise ValueError('Invalid native choices')
        before = UpdateCallTest.progression_abilities(self, client, state)
        # Read the actual native UI offer and match it against its current
        # String24 to reject repeated/stale menu batches.
        frame = q(context, 160)
        ui, length = (q(client.memory(frame + field('batch_frame', offset), 8)) for offset in (0x998, 0x9A0))
        if not 0 <= length <= 4096 or length and not ui:
            raise ValueError('Invalid diagnostic native UI vector')
        options = None
        for index in range(length):
            cap, address, size = struct.unpack('<QQQ', client.memory(ui + index*24, 24))
            if not 0 <= size <= cap <= 1048576 or size and not address:
                raise ValueError('Invalid diagnostic native UI string')
            if size > 65536:
                continue
            try:
                message = json.loads(client.memory(address, size))
            except (ValueError, UnicodeError):
                continue
            if isinstance(message, dict) and message.get('type') == 'choices':
                options = message.get('choices')
        if not isinstance(options, list) or len(options) != count:
            return False
        selected = (client.number - 1) % count
        offer = options[selected]
        row = client.memory(pointer + selected*self.progression['choice_stride'], self.progression['choice_stride'])
        cap, address, size = struct.unpack_from('<QQQ', row)
        if not 0 < size <= cap <= 1024 or not address:
            raise ValueError('Invalid native choice title')
        title = client.memory(address, size).decode('utf-8')
        if not isinstance(offer, dict) or title != offer.get('title'):
            return False
        expected, verified = dict(before), False
        if offer.get('kind') == 'new' and title.startswith('New: '):
            label = title[5:]
            if label in before:
                raise ValueError('Native new talent already exists')
            expected[label], verified = 1, True
        elif offer.get('kind') == 'upgrade':
            delta = self.progression['ability_contract']['upgrade_ui']['rank_delta_source']
            tags, tag_count, target = (q(row, delta[name]) for name in
                ('choice_pointer_offset', 'choice_count_offset', 'ability_index_offset'))
            if not tags or not 1 <= tag_count <= 32 or not tag_count <= q(row, delta['choice_capacity_offset']) < 2**63 or not 0 <= target < len(before):
                raise ValueError('Invalid native upgrade vector')
            label = list(before)[target]
            if title != f'{label} rank {before[label]+1}' or any(tag not in delta['allowed_tags'] for tag in client.memory(tags, tag_count)):
                raise ValueError('Native upgrade target or scalar tags disagree')
            expected[label], verified = before[label] + tag_count, True
        pending = native_pending_field(self.progression, state['choice_kind'])
        if pending is None or state[pending] < 1:
            raise ValueError('Native choice has no pending owner counter')
        def completed():
            after = UpdateCallTest.progression_state(self, client, game)
            abilities = UpdateCallTest.progression_abilities(self, client, after)
            if after[pending] != state[pending]-1 or verified and abilities != expected:
                raise ValueError('Independent native talent did not consume/apply the selected offer')
            self.record(event='network_talent_verified', player=client.number, selected=selected, title=title,
                        pending_before=state[pending], pending_after=after[pending], rank_verified=verified,
                        abilities_before=before, abilities_after=abilities)
        client.call_before(context, CHOOSE, game, selected, after=completed)
        return True
