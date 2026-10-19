"""One local EXE per peer; exchange bounded game snapshots over pinned TLS."""
import argparse
import base64
import io
import json
import math
import os
from pathlib import Path
import re
import socket
import struct
import time

# The map limit: 64 x 64 tiles of 533.33 units around the origin (world coordinates, as Elwynn's -9404/-633);
# beyond it a position is broken data (used for x, y and z).
MAX_POSITION = 32 * 1600 / 3

from coop_transport import accept, connect, create_pairing
from native_probe import ROOT, ACTIVE_HASH, IMAGE_SIZE, WRITE, MAX_ENEMY_DAMAGE, run
from play_limits import (MAX_CLOCK, MAX_COUNTER, MAX_DAMAGE_TOTAL, MAX_ENEMIES, MAX_ENEMY_HP, MAX_HIT_DAMAGE,
                         MAX_MULTIPLIER, MAX_NATIVE_OBJECTS, MAX_QUEUE)
from native_guest_combat import NativeCombatBridge, MAX_CLAIM_ITEMS
from sessions import MOVEMENT_OPCODES, Pose, LOGIN, HEARTBEAT, decode_ground_movement
from visibility_bridge import clone_player, frame, JUMP_DISTANCE, note_native_skip
from native_probe import game_field
from world_packets import validate_movement_packet, WORLD, UPDATE, objects


def binary(value):
    return base64.b64encode(value).decode('ascii')


def unbinary(value, maximum=1048576):
    if not isinstance(value, str) or len(value) > (maximum + 2) // 3 * 4:
        raise ValueError('Invalid binary co-op field')
    result = base64.b64decode(value, validate=True)
    if len(result) > maximum:
        raise ValueError('Co-op field exceeds bound')
    return result


def finite(value, low, high):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError('Invalid numeric co-op field')
    return value


# Enemy record (0xE0 bytes from +0x68; 0xF0 in build family 47e4) parts a guest mirror rewrites every
# tick: dead flag, health, start/end pose and movement timer. Changes there
# travel as packed hp/pose; the debuff spans travel separately (36 bytes).
from updated_layout import enemy_layout
from native_guest_combat import enemy_offset as _member
ENEMY_FLAT = enemy_layout()[0] - 0x68
ENEMY_VOLATILE = ((0, 4), (_member(0xE0) - 0x68, 4), (_member(0xFC) - 0x68, 0x20))
ENEMY_SPANS = tuple((_member(a) - 0x68, _member(b) - 0x68) for a, b in ((0x88, 0x98), (0x124, 0x128), (0x130, 0x140)))
ENEMY_SPAN_BYTES = sum(end - start for start, end in ENEMY_SPANS)


def _stable_mask():
    mask = bytearray(b'\xff' * ENEMY_FLAT)
    for start, size in ENEMY_VOLATILE:
        mask[start:start + size] = bytes(size)
    for start, end in ENEMY_SPANS:
        mask[start:end] = bytes(end - start)
    return int.from_bytes(mask, 'little')


ENEMY_STABLE_MASK = _stable_mask()


def enemy_parts(flat):
    """Split a record into (stable bytes, debuff spans); volatile parts are zeroed."""
    if len(flat) == ENEMY_FLAT:
        # Same bytes as the general path below, as one masked integer (~3x faster).
        (a, b), (c, d), (e, f) = ENEMY_SPANS
        return ((int.from_bytes(flat, 'little') & ENEMY_STABLE_MASK).to_bytes(ENEMY_FLAT, 'little'),
                bytes(flat[a:b]) + bytes(flat[c:d]) + bytes(flat[e:f]))
    stable = bytearray(flat)
    for start, size in ENEMY_VOLATILE:
        stable[start:start + size] = bytes(size)
    spans = b''.join(flat[start:end] for start, end in ENEMY_SPANS)
    for start, end in ENEMY_SPANS:
        stable[start:end] = bytes(end - start)
    return bytes(stable), spans


def with_spans(flat, spans):
    if len(spans) != ENEMY_SPAN_BYTES:
        raise ValueError('Invalid co-op enemy debuff span')
    flat, offset = bytearray(flat), 0
    for start, end in ENEMY_SPANS:
        flat[start:end] = spans[offset:offset + end - start]
        offset += end - start
    return bytes(flat)


def enemy_motion(hp, pose):
    """Exact hp/pose (interpolated doubles) in 32 bytes instead of ~80 JSON characters."""
    return struct.pack('<4d', hp, *pose)


# Protocol 3 enemy entries, concatenated into one binary blob per update:
#   <Q guid><B flags> [FULL: 0xE0 record [BOSS: <Q boss>]] [PATCH: <B runs> (<B start><B len> bytes)*]
#   [SPANS: 36 bytes] [MOTION: <4d hp x y z>]
# A patch carries only changed record bytes against the recipient's last
# applied state. GUID/definition bytes never patch: they need a full record.
ENEMY_FULL, ENEMY_PATCH, ENEMY_SPANS_SET, ENEMY_BOSS, ENEMY_MOTION = 1, 2, 4, 8, 16
ENEMY_IDENTITY = (_member(0x78) - 0x68, _member(0x80) - 0x68 + 8)  # guid + definition
_CHANGED_RUN = re.compile(rb'[^\x00](?:\x00{0,3}[^\x00])*', re.DOTALL)


def enemy_patch_runs(old_stable, new_stable):
    """Changed byte runs of two stable records; gaps under four bytes are merged."""
    diff = (int.from_bytes(old_stable, 'little') ^ int.from_bytes(new_stable, 'little')).to_bytes(ENEMY_FLAT, 'little')
    return [match.span() for match in _CHANGED_RUN.finditer(diff)]


def enemy_entry(guid, flags, flat, boss=None, runs=(), spans=b'', motion=b''):
    parts = [struct.pack('<QB', guid, flags)]
    if flags & ENEMY_FULL:
        parts.append(bytes(flat))
        if flags & ENEMY_BOSS:
            parts.append(struct.pack('<Q', boss))
    if flags & ENEMY_PATCH:
        parts.append(bytes((len(runs),)))
        for start, end in runs:
            parts.append(bytes((start, end - start)))
            parts.append(bytes(flat[start:end]))
    if flags & ENEMY_SPANS_SET:
        parts.append(spans)
    if flags & ENEMY_MOTION:
        parts.append(motion)
    return b''.join(parts)


def checked_enemy_flat(guid, flat, boss):
    if len(flat) != ENEMY_FLAT or struct.unpack_from('<Q', flat, ENEMY_IDENTITY[0])[0] != guid:
        raise ValueError('Invalid co-op enemy snapshot')
    definition = struct.unpack_from('<Q', flat, ENEMY_IDENTITY[0] + 8)[0]
    if not 0 <= definition < IMAGE_SIZE or (not definition and boss is None):
        raise ValueError('Invalid co-op enemy definition')
    if boss is not None and not 0 <= boss < IMAGE_SIZE - 0x58:
        raise ValueError('Invalid co-op boss definition')
    return flat


def validated_enemy(guid, encoded, boss):
    if type(guid) is not int:
        raise ValueError('Invalid enemy identity')
    flat = unbinary(encoded, ENEMY_FLAT)
    if len(flat) != ENEMY_FLAT or struct.unpack_from('<Q', flat, ENEMY_IDENTITY[0])[0] != guid:
        raise ValueError('Invalid co-op enemy snapshot')
    definition = struct.unpack_from('<Q', flat, ENEMY_IDENTITY[0] + 8)[0]
    if not 0 <= definition < IMAGE_SIZE or (not definition and boss is None):
        raise ValueError('Invalid co-op enemy definition')
    if boss is not None and (type(boss) is not int or not 0 <= boss < IMAGE_SIZE - 0x58):
        raise ValueError('Invalid co-op boss definition')
    return flat


class OnlineBridge(NativeCombatBridge):
    def __init__(self, output, number=None, channel=None, shared_world=True):
        super().__init__(output, shared_world=shared_world)
        number = number if number is not None else self.number
        channel = channel if channel is not None else self.channel
        self.number, self.other, self.channel = number, (2 if number == 1 else 1), channel
        self.trace_packets = os.environ.get('COOP_TRACE_PACKETS') == '1'
        if number != 1:
            self.raid_assignments = {}
        self.last_network = 0
        self.damage_sent, self.damage_acked, self.damage_done = {}, {}, {}
        self.enemy_seq, self.enemy_full_needed = 0, False  # Guest side of sequenced enemy deltas.
        self.controls = []
        self.claim_sent = None
        self.own_position = None    # Guest: (x, y, z, monotonic time) of his own game, sent with every state.
        self.live_positions = {}    # Host: guest -> (received, (x, y, z), (vx, vy), guest time); guest_position.
        self.remote_template_sent = False
        self.remote_restart = False
        self.peer_finished = self.stop_requested = False

    def record(self, **event):
        name = event.get('event')
        if name == 'shared_pause_requested' and hasattr(self, 'controls'):
            self.controls.append(dict(paused=event['paused']))
        if name in ('native_guest_damage_applied', 'guest_damage_target_already_dead') and self.number == 1:
            guid = event['target']
            self.damage_done[guid] = self.damage_done.get(guid, 0) + event['requested']
        super().record(**event)

    def __call__(self, client, rva, context):
        # All game state is consumed on the debugger thread. Network threads
        # only frame bytes and never touch a process or its native memory.
        self.poll_network()
        result = super().__call__(client, rva, context)
        self.poll_network()
        return result

    def poll_network(self):
        if self.peer_finished:
            return
        for message in self.channel.drain():
            self.receive_state(message)
        if self.peer_finished:
            return
        now = time.monotonic()
        if now - self.last_network >= .04 or self.restart_requested:
            self.send_state()
            self.last_network = now

    def before_batch(self, client, context):
        if self.number != 1 and client.number == self.number:
            self.capture_own_position(client)
        return super().before_batch(client, context)

    def capture_own_position(self, client):
        """Guest: his own game position for the host's pursuit and hit routing (0.0.22, guest_position)."""
        x, y, z = struct.unpack('<3f', client.memory(client.server + 0x10 + game_field(0x488), 12))
        if all(math.isfinite(v) and abs(v) <= MAX_POSITION for v in (x, y, z)):
            self.own_position = (x, y, z, time.monotonic())

    def receive_position(self, other, position):
        """Host: a guest's own position; velocity from his own clock, not the network's.

        Only a hint for pursuit and hit routing: an invalid one is dropped (logged once a minute) and the guest keeps
        his movement packet as position, the connection stays (mixed versions, damaged values)."""
        if (not isinstance(position, list) or len(position) != 4 or
                any(type(v) not in (int, float) or not math.isfinite(v) for v in position) or
                any(abs(v) > MAX_POSITION for v in position[:3]) or not 0 <= position[3] <= MAX_CLOCK):
            self.live_positions.pop(other, None)
            note_native_skip('guest_position_invalid', other, value=str(position)[:80])
            return
        x, y, z, sent = map(float, position)
        previous = self.live_positions.get(other)
        velocity, received = (0.0, 0.0), time.monotonic()
        if previous is not None:
            preceived, (px, py, _), (pvx, pvy), psent = previous
            dt = sent - psent
            if dt == 0:  # The same sample again: it keeps its velocity AND its age (a stalled guest goes stale).
                velocity, received = (pvx, pvy), preceived
            elif dt > 0 and math.hypot(x - px, y - py) <= JUMP_DISTANCE:  # No speed limit, but a jump is no run.
                velocity = (x - px) / dt, (y - py) / dt
            # dt < 0: the guest's clock restarted, no velocity.
        self.live_positions[other] = (received, (x, y, z), velocity, sent)

    def send_state(self):
        n, other = self.number, self.other
        message = dict(kind='state', ready=n in self.ready, loaded=n in self.loaded,
                       state=self.native_states.get(n), created=sorted(self.created.get(n, ())),
                       controls=[] if self.draining else self.controls, restart=self.restart_requested and not self.remote_restart)
        message['xp_multiplier'] = self.xp_multipliers.get(n, 1)
        if n != 1 and self.own_position is not None:
            message['position'] = [round(v, 3) for v in self.own_position[:3]] + [round(self.own_position[3], 4)]
        if n == 1:
            order = sorted((sequence, kind, clock)
                for kind in ('hits', 'areas')
                for sequence, _, clock in self.queued_hit_metadata(other, kind))
            message['hit_order'] = [[kind, clock] for _, kind, clock in order]
            message['powerups'] = self.powerups_pending[other][:]
            self.powerups_pending[other].clear()
        message['closing'] = self.draining
        if n == 1 and self.party_surrender:
            message['surrender'] = True  # Kept on every message; guests apply it once.
        if n == 1:
            message['raid_assignments'] = {str(n): icon for n, icon in self.raid_assignments.items()}
        if n in self.name_responses:
            message['name_response'] = binary(self.name_responses[n])
        message['world_received'] = self.counts['world_delivered'] if n != 1 else 0
        self.controls = []
        if n in self.templates and not self.remote_template_sent:
            message['template'] = binary(self.templates[n])
            self.remote_template_sent = True
        if n in self.latest_movement:
            opcode, body = self.latest_movement[n]
            message['movement'] = [opcode, binary(body)]
        packets = self.attack_packets[other] + self.hurt_packets[other] + self.notice_packets[other]
        message['packets'] = [[op, binary(body)] for op, body in packets]
        self.attack_packets[other].clear()
        self.hurt_packets[other].clear()
        self.notice_packets[other].clear()
        # Guests publish only requests (reserved) and completion (None); a local
        # shutdown refund is not a host answer and must not be echoed back. The host
        # answers each guest with that guest's own claim only.
        claim = self.claims.get(other if n == 1 else n)
        publish_claim = ((claim is None or claim['status'] == 'reserved') if n != 1 else
                         claim is None or claim['status'] != 'reserved')
        if publish_claim and claim != self.claim_sent:
            message['claim'] = claim
            self.claim_sent = dict(claim) if claim else None
        if n == 1:
            message['boss_rewards'] = list(self.boss_reward_events)
            message.update(clock=self.host_clock, boss=self.host_boss_hud, xp=self.xp_pending,
                gold=self.gold_pending, hits=self.guest_hits, areas=self.area_hits,
                world=[[op, binary(body)] for op, body in self.world_pending],
                # Party hosts send only changed receipts and loot (thin_snapshot);
                # copying every receipt of the run grew each send with play time.
                damage_done=[] if getattr(self, 'enemy_deltas', False) else list(self.damage_done.items()),
                chests=(lambda view: view if getattr(self, 'enemy_deltas', False) else list(view.items()))(
                    self.loot_view(other)))
            if not getattr(self, 'enemy_deltas', False):  # Party hosts send sequenced deltas instead.
                message['enemies'] = [[guid, binary(flat), hp, pose, self.boss_definitions.get(guid)]
                                      for guid, (flat, hp, pose) in self.enemy_snapshot.items()]
            self.xp_pending = self.gold_pending = 0
            self.guest_hits, self.area_hits = [], []
            for kind in ('hits', 'areas'):
                self.hit_metadata.pop((other, kind), None)
            self.world_pending = []
            self.world_bytes = 0
        else:
            message['boss_reward_ack'] = self.boss_reward_applied[n]
            damage = []
            for guid, pending in self.damage_pending.items():
                delta = pending - self.damage_sent.get(guid, 0)
                if delta > 0:
                    damage.append([guid, delta])
                    self.damage_sent[guid] = pending
            message.update(damage=damage,
                           effects=[[guid, binary(effect), spell] for guid, effect, spell in self.effects_pending])
            self.effects_pending = []
            if n in self.own_auras:
                auras = self.own_auras[n].take_changes()
                if auras:
                    message['auras'] = auras
                self.note_aura_drops()
            if self.self_surrendered:
                message['surrendered'] = True  # This guest gave up; it is leaving.
        self.channel.send(message)

    def receive_state(self, message):
        if message.get('kind') == 'goodbye':
            self.peer_finished = self.stop_requested = True
            return
        if message.get('kind') != 'state':
            raise ValueError('Unknown co-op message')
        other = self.other
        if 'raid_assignments' in message:
            if self.number == 1:
                raise ValueError('Only the host can assign raid icons')
            from party_markers import validate_assignments
            assignments = validate_assignments(message['raid_assignments'], self.members)
            if any(n in assignments and assignments[n] != icon for n, icon in self.raid_assignments.items()):
                raise ValueError('Raid assignment changed during a run')
            self.raid_assignments = assignments
        self.xp_multipliers[other] = finite(message.get('xp_multiplier', 1), 0, MAX_MULTIPLIER)
        if self.number != 1:
            powerups = message.get('powerups', [])
            if (not isinstance(powerups, list) or len(powerups) + len(self.powerups_pending[self.number]) > MAX_QUEUE
                    or any(type(k) is not int or k not in (3, 4, 5, 6) for k in powerups)):
                raise ValueError('Invalid shared powerup events')
            self.powerups_pending[self.number].extend(powerups)
        elif 'powerups' in message:
            raise ValueError('Only the host can publish powerups')
        if self.number == 1:
            ack = message.get('boss_reward_ack', 0)
            if type(ack) is not int or not self.boss_reward_applied[other] <= ack <= self.boss_reward_sequence:
                raise ValueError('Invalid boss reward acknowledgement')
            self.boss_reward_applied[other] = ack
            acknowledged = min(self.boss_reward_applied.values(), default=0)
            self.boss_reward_events[:] = [e for e in self.boss_reward_events if e['sequence'] > acknowledged]
        else:
            self.receive_boss_rewards(self.number, message.get('boss_rewards', []))
        if message.get('closing'):
            self.stop_requested = True
        if 'name_response' in message:
            self.set_name_response(other, unbinary(message['name_response'], 128))
        if 'template' in message:
            if other in self.templates:
                raise ValueError('Repeated co-op character template')
            body = unbinary(message['template'])
            pose = Pose(*struct.unpack_from('<4f', body, 20))
            guid = 0xFF0100 + other
            clone_player(body, guid, pose)
            self.templates[other] = body
            self.created[other] = set()
            self.router.add_player(guid, str(other), pose)
            self.router.attach_authenticated(str(other), str(other))
            self.router.receive(str(other), frame(LOGIN, struct.pack('<Q', guid)))
        for key, collection in (('ready', self.ready), ('loaded', self.loaded)):
            if type(message.get(key)) is not bool:
                raise ValueError('Invalid co-op readiness')
            if message[key]:
                collection.add(other)
        state = message.get('state')
        if state is not None:
            if len(state) != 4 or any(type(v) is not int or not 0 <= v <= MAX_COUNTER for v in state) or state[0] > 5:
                raise ValueError('Invalid co-op player state')
            self.native_states[other] = tuple(state)
        created = message.get('created', [])
        if not isinstance(created, list) or any(v not in self.members or v == other for v in created):
            raise ValueError('Invalid remote creation acknowledgement')
        if other in self.created:
            self.created[other] = set(created)
        if self.number == 1 and 'position' in message:
            self.receive_position(other, message['position'])
        if 'movement' in message and other in self.templates:
            opcode, encoded = message['movement']
            body = unbinary(encoded, 44)
            decode_ground_movement(body)
            self.router.receive(str(other), frame(opcode, body))
            self.latest_movement[other] = (opcode, body)
        controls = message.get('controls', [])
        if len(controls) > 32:
            raise ValueError('Too many co-op controls')
        for control in controls:
            paused = control.get('paused')
            if type(paused) is not bool:
                raise ValueError('Invalid co-op pause state')
            if not self.draining:
                self.router.paused = paused
                self.pause_pending[self.number] = paused
        if message.get('restart'):
            # The host fans a guest's Again decision out to the whole party;
            # guests suppress echoing a received host decision back to it.
            self.remote_restart = self.number != 1
            self.restart_requested = True
        packets = message.get('packets', [])
        if len(packets) > MAX_QUEUE:
            raise ValueError('Too many co-op packets')
        for opcode, encoded in packets:
            if opcode not in WORLD | MOVEMENT_OPCODES | {0x96}:
                raise ValueError('Unsupported peer combat packet')
            payload = unbinary(encoded)
            from party_markers import reject_remote_marker_packet
            reject_remote_marker_packet(opcode, payload)
            if opcode in MOVEMENT_OPCODES:
                validate_movement_packet(payload, self.members,
                                         other if self.number == 1 else None)
            self.receive_summon_packet(opcode, payload, other if self.number == 1 else None)
            if self.number == 1:  # The host checks guest avatars before anyone renders them.
                payload = self.sanitize_player_values(other, opcode, payload)
            if payload is not None:
                self.notice_packets[self.number].append((opcode, payload))
        if 'claim' in message:
            claim = message['claim']
            owner = self.other if self.number == 1 else self.number
            if claim is not None:
                expected = {'reserved'} if self.number == 1 else {'removed', 'refund', 'collected'}
                items = claim.get('items')
                chest = claim.get('chest', False)
                if (claim.get('status') not in expected or type(claim.get('guid')) is not int or
                        type(chest) is not bool or not isinstance(items, list) or
                        not 1 <= len(items) <= (1 if chest else MAX_CLAIM_ITEMS) or items[0] != claim['guid'] or
                        any(type(g) is not int for g in items) or len(set(items)) != len(items) or
                        claim.get('player', owner) != owner):
                    raise ValueError('Invalid co-op loot claim')
                for key, maximum in (('cost', MAX_COUNTER), ('range', 1000), ('multiplier', MAX_MULTIPLIER), ('xp_multiplier', MAX_MULTIPLIER)):
                    finite(claim[key], 0, maximum)
                if not chest and claim['cost'] != 0:
                    raise ValueError('Invalid co-op loot claim')
            # A late empty acknowledgement must not erase a newer reservation.
            current = self.claims.get(owner)
            if claim is not None or self.number == 1 or not current or current['status'] != 'reserved':
                if claim is None:
                    self.claims.pop(owner, None)
                else:
                    self.claims[owner] = claim
                self.claim_sent = dict(claim) if claim else None
        if self.number == 1:
            received = message.get('world_received')
            if type(received) is not int or not self.counts['world_delivered'] <= received <= self.counts['world_captured']:
                raise ValueError('Invalid co-op world acknowledgement')
            self.counts['world_delivered'] = received
            if 'auras' in message:
                self.receive_guest_auras(other, message['auras'])
            if 'surrender' in message and other not in self.surrender_rejected:
                # Only the host can end the run for the party.
                self.surrender_rejected.add(other)
                self.record(event='surrender_broadcast_rejected', player=other)
            if message.get('surrendered') is True and other not in self.surrendered:
                # The guest's own channel reports it; its closing drain then removes it.
                self.surrendered.add(other)
                self.record(event='guest_surrendered', player=other)
            for guid, damage in message.get('damage', []):
                if type(guid) is not int:
                    raise ValueError('Invalid enemy identity')
                self.damage_pending[guid] = self.damage_pending.get(guid, 0) + finite(damage, 0, MAX_ENEMY_DAMAGE)
                if self.damage_pending[guid] > MAX_ENEMY_DAMAGE:
                    raise ValueError('Pending damage exceeds bound')
            effects = message.get('effects', [])
            if len(effects) + len(self.effects_pending) > MAX_QUEUE:
                raise ValueError('Too many co-op effects')
            for guid, effect, spell in effects:
                self.effects_pending.append((guid, unbinary(effect, 12), spell))
        else:
            self.host_clock = finite(message['clock'], 0, MAX_CLOCK)
            if 'surrender' in message:
                if message['surrender'] is not True:
                    raise ValueError('Invalid party surrender')
                if not self.party_surrender:
                    self.party_surrender = True
                    self.surrendered.add(1)
                    self.record(event='party_surrender_received', player=self.number)
            self.host_boss_hud = message['boss']
            # Per message u32; the sums are applied in u32 parts (xp) or saturate (gold).
            self.xp_pending += int(finite(message['xp'], 0, MAX_COUNTER))
            self.gold_pending += int(finite(message['gold'], 0, MAX_COUNTER))
            for key, length in (('hits', 3), ('areas', 2)):
                if not isinstance(message[key], list) or len(message[key]) > MAX_QUEUE:
                    raise ValueError('Invalid incoming hit batch')
                for hit in message[key]:
                    if len(hit) != length or type(hit[0]) is not int:
                        raise ValueError('Invalid co-op incoming hit')
                    finite(hit[1], 0, MAX_HIT_DAMAGE)
                    if key == 'hits':
                        finite(hit[2], 0, MAX_CLOCK)
            # Preserve host production order across the two existing wire queues.
            # Older peers retain their previous area-first ordering.
            order = message.get('hit_order', [['areas', self.host_clock] for _ in message['areas']] +
                                [['hits', hit[2]] for hit in message['hits']])
            if not isinstance(order, list) or len(order) != len(message['hits']) + len(message['areas']):
                raise ValueError('Invalid incoming hit order')
            indices = dict(hits=0, areas=0)
            for entry in order:
                if not isinstance(entry, list) or len(entry) != 2 or entry[0] not in indices:
                    raise ValueError('Invalid incoming hit order')
                kind, clock = entry
                index = indices[kind]
                if index >= len(message[kind]):
                    raise ValueError('Repeated incoming hit index')
                self.queue_incoming_hit(self.number, kind, message[kind][index], finite(clock, 0, MAX_CLOCK))
                indices[kind] += 1
            # A protocol-3 party host sends enemy_update instead of a full list.
            enemies = message.get('enemies', ())
            if len(enemies) > MAX_ENEMIES:
                raise ValueError('Too many co-op enemies')
            snapshot, bosses = {}, {}
            for guid, encoded, hp, pose, boss in enemies:
                flat = validated_enemy(guid, encoded, boss)
                if len(pose) != 3:
                    raise ValueError('Invalid co-op enemy snapshot')
                if boss is not None:
                    bosses[guid] = boss
                snapshot[guid] = (flat, finite(hp, 0, MAX_ENEMY_HP), tuple(finite(v, -100000, 100000) for v in pose))
            if 'enemy_update' in message:
                self.apply_enemy_update(message['enemy_update'])
            for guid, done in message['damage_done']:
                if done == 0 and type(done) in (int, float):
                    # Protocol 5: the host forgot the receipt of a gone enemy (nothing in
                    # flight there). Forget its cumulative total; damage still in flight
                    # from here keeps its sent amount and is acknowledged from zero.
                    self.damage_acked.pop(guid, None)
                    if not self.damage_sent.get(guid) and guid not in self.damage_pending:
                        self.damage_sent.pop(guid, None)
                    continue
                previous = self.damage_acked.get(guid, 0)
                delta = finite(done, previous, MAX_DAMAGE_TOTAL) - previous
                if delta:
                    self.damage_pending[guid] = max(0, self.damage_pending.get(guid, 0) - delta)
                    self.damage_sent[guid] = max(0, self.damage_sent.get(guid, 0) - delta)
                    if not self.damage_pending[guid]:
                        del self.damage_pending[guid]
                        if not self.damage_sent[guid]:
                            del self.damage_sent[guid]  # Fully acknowledged.
                    self.damage_acked[guid] = done
            if 'enemies' in message:
                self.enemy_snapshot, self.boss_definitions = snapshot, bosses
            if 'chests' in message:  # Sent only when changed.
                if len(message['chests']) > MAX_NATIVE_OBJECTS:
                    raise ValueError('Too many co-op loot objects')
                self.chests = {guid: tuple(value) for guid, value in message['chests']}
            if 'chest_update' in message:  # Party hosts send only changed loot objects.
                update = message['chest_update']
                entries, drop = update.get('set'), update.get('drop', [])
                if (type(update.get('full')) is not bool or not isinstance(entries, list) or
                        not isinstance(drop, list) or len(entries) + len(drop) > 2 * MAX_NATIVE_OBJECTS):
                    raise ValueError('Invalid co-op loot update')
                chests = {} if update['full'] else dict(self.chests)
                for guid in drop:
                    chests.pop(guid, None)
                for guid, value in entries:
                    if type(guid) is not int or not isinstance(value, (list, tuple)):
                        raise ValueError('Invalid co-op loot object')
                    chests[guid] = tuple(value)
                if len(chests) > MAX_NATIVE_OBJECTS:
                    raise ValueError('Too many co-op loot objects')
                self.chests = chests
            for opcode, encoded in message['world']:
                if opcode not in WORLD:
                    raise ValueError('Unsupported co-op world packet')
                body = unbinary(encoded)
                self.world_pending.append((opcode, body))
                self.world_bytes += len(body) + 4
                self.counts['world_captured'] += 1
            if self.world_bytes > 524288:
                raise ValueError('Co-op renderer fell behind')
        if message.get('restart'):
            self.completed_transition(self.number, 6)

    def apply_enemy_update(self, update):
        """Apply a full or sequenced delta enemy snapshot from the host.

        A delta must build on the last applied sequence. Otherwise it is
        ignored and the next state message asks the host for a full snapshot.
        """
        seq, base, drop, blob = update.get('seq'), update.get('base'), update.get('drop', []), update.get('blob', '')
        if (type(seq) is not int or not 0 < seq <= 2 ** 53 or base is not None and type(base) is not int or
                not isinstance(drop, list) or len(drop) > MAX_ENEMIES):
            raise ValueError('Invalid co-op enemy update')
        current = getattr(self, 'enemy_seq', 0)
        if base is not None and base != current:
            self.enemy_full_needed = True
            return
        data = unbinary(blob, MAX_ENEMIES * 0x130)  # One decode; entries are parsed in place.
        if base is None:
            snapshot, bosses = {}, {}
        else:
            snapshot, bosses = dict(self.enemy_snapshot), dict(self.boss_definitions)
        for guid in drop:
            if type(guid) is not int:
                raise ValueError('Invalid enemy identity')
            snapshot.pop(guid, None)
            bosses.pop(guid, None)
        unpack, offset, size = struct.unpack_from, 0, len(data)
        try:
            while offset < size:
                guid, flags = unpack('<QB', data, offset)
                offset += 9
                if flags & ~0x1F or flags & ENEMY_BOSS and not flags & ENEMY_FULL or \
                        flags & ENEMY_FULL and flags & ENEMY_PATCH:
                    raise ValueError('Invalid co-op enemy entry')
                previous = snapshot.get(guid)
                if flags & ENEMY_FULL:
                    flat = data[offset:offset + ENEMY_FLAT]
                    offset += ENEMY_FLAT
                    boss = None
                    if flags & ENEMY_BOSS:
                        boss = unpack('<Q', data, offset)[0]
                        offset += 8
                    checked_enemy_flat(guid, flat, boss)
                    if boss is None:
                        bosses.pop(guid, None)
                    else:
                        bosses[guid] = boss
                elif previous is None:
                    self.enemy_full_needed = True  # A delta for an enemy this guest never saw.
                    return
                else:
                    flat = previous[0]
                if flags & ENEMY_PATCH:
                    patched = bytearray(flat)
                    runs = data[offset]
                    offset += 1
                    for _ in range(runs):
                        start, length = data[offset], data[offset + 1]
                        end = start + length
                        if not length or end > ENEMY_FLAT or start < ENEMY_IDENTITY[1] and end > ENEMY_IDENTITY[0]:
                            raise ValueError('Invalid co-op enemy patch')
                        chunk = data[offset + 2:offset + 2 + length]
                        if len(chunk) != length:
                            raise ValueError('Truncated co-op enemy update')
                        patched[start:end] = chunk
                        offset += 2 + length
                    flat = bytes(patched)
                if flags & ENEMY_SPANS_SET:
                    flat = with_spans(flat, data[offset:offset + ENEMY_SPAN_BYTES])
                    offset += ENEMY_SPAN_BYTES
                if flags & ENEMY_MOTION:
                    hp, *pose = unpack('<4d', data, offset)
                    offset += 32
                    hp, pose = finite(hp, 0, MAX_ENEMY_HP), tuple(finite(v, -100000, 100000) for v in pose)
                elif previous is None:
                    self.enemy_full_needed = True
                    return
                else:
                    hp, pose = previous[1], previous[2]
                snapshot[guid] = (flat, hp, pose)
        except (struct.error, IndexError):
            raise ValueError('Truncated co-op enemy update') from None
        if offset != size:
            raise ValueError('Truncated co-op enemy update')
        if len(snapshot) > MAX_ENEMIES:
            raise ValueError('Too many co-op enemies')
        self.enemy_snapshot, self.boss_definitions = snapshot, bosses
        self.enemy_seq, self.enemy_full_needed = seq, False
        self.note('enemy_full' if base is None else 'enemy_delta', len(snapshot), size)

    def finish_ready(self):
        if not self.peer_finished:
            self.send_state()
        return (super().finish_ready() and self.counts['world_captured'] == self.counts['world_delivered']
                and (self.number != 1 or not self.boss_reward_events))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('pair', 'host', 'join'))
    parser.add_argument('--pairing', type=Path, default=ROOT / '.coop-pairing')
    parser.add_argument('--address', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=47652)
    parser.add_argument('--seconds', type=int, default=3600)
    parser.add_argument('--verify-boss', action='store_true', help='Disposable diagnostic: automatic talents and protected boss fight')
    args = parser.parse_args()
    if args.mode == 'pair':
        create_pairing(args.pairing)
        print('Pairing created. Share only invite.json privately with your co-op partner.')
        return
    invite = json.loads((args.pairing / 'invite.json').read_text(encoding='utf-8'))
    if args.mode == 'host':
        with socket.create_server((args.address, args.port)) as listener:
            listener.settimeout(300)
            print('Waiting for the invited co-op partner.', flush=True)
            channel = accept(listener, args.pairing, invite, ACTIVE_HASH)
        number = 1
    else:
        channel = connect(args.address, args.port, invite, ACTIVE_HASH)
        number = 2
    try:
        with (ROOT / f'analysis/online-player-{number}.jsonl').open('w', encoding='utf-8') as output:
            if args.verify_boss:
                from verify_boss_visual import BossVerification
                class OnlineBossVerification(BossVerification, OnlineBridge):
                    def __init__(self, output):
                        self.number, self.channel = number, channel
                        super().__init__(output)
                bridge = OnlineBossVerification(output)
            else:
                bridge = OnlineBridge(output, number, channel)
            run(args.seconds, 1, bridge, player_numbers=[number])
            bridge.record(event='summary', **bridge.counts)
            if not bridge.peer_finished:
                channel.finish()
    finally:
        channel.close()


if __name__ == '__main__':
    main()
