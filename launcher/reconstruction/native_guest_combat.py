"""Development adapter: native guest player actions against owned enemy mirrors.

The host owns enemy HP/death/loot/XP. Guest native actions calculate damage and
produce their own combat packets. Enemy AI and loot stay on the host; the
guest retains native periodic-effect processing against its mirrors.
"""
import hashlib
import math
import json
import os
import struct
import time

from native_probe import TICK, AWARD_XP, SPAWN, SPAWN_BOSS, FIND_SPAWN, DAMAGE, HURT, REMOVE_LOOT, OFFER_CHOICES, APPLY_EFFECT, ENEMY_AOE, GROUND_AOE, ENEMY_TARGET, allocate, checked, q
from visibility_bridge import (Bridge, absolute_jump, guest_damage_patches, native_enemies, game_frame_code, validate_live_game,
                               native_enemy, native_enemy_array, parse_native_enemies, note_native_skip, finite_text)
from world_packets import COMBAT, UPDATE, DESTROY, MONSTER, SELF, object_packet, Reader, PROGRESSION, values_packet, remap_combat, objects, dynamic_object, dynamic_caster, DISPLAY_ID
from native_probe import HUD_DELIVER, game_field, IMAGE_SIZE, MAX_ENEMY_DAMAGE
from play_limits import (MAX_COUNTER, MAX_ENEMIES, MAX_LIVE_SUMMONS, MAX_MULTIPLIER, MAX_NATIVE_OBJECTS, MAX_QUEUE,
                         SUMMON_HISTORY, copper, u32_part)
from guest_auras import OwnAuras, AuraOverlay, validate_auras
from updated_layout import (reviewed_rva, reviewed_bytes, UPDATED, rva as relocated, phase_gate, expected_bytes, branch,
                            code_fields, field, release_0843, release_47e4, release_0931, release_7264, enemy_layout, family)


def enemy_offset(offset):
    """Native enemy record member (reviewed/0.84.3 offset in): build family 47e4 inserts 16 bytes before +0x70;
    0.93.1 (0931) also inserts 4 bytes before its 47e4 offset 0x13c (aligned 0x140->0x144 .. 0x154->0x158)."""
    if not release_47e4():
        return offset
    offset = offset + 0x10 if offset >= 0x70 else offset
    return offset + 4 if release_0931() and offset >= 0x13C else offset


# 0.95.0 "give up" (menu tag 10, case 0x5430eaf): surrender(Game) 0x546e540 acts in
# phases 1-3 only. Like a native death it sets phase 4, the defeat timer and end
# of run, and also clears Game+0x570, sets Game+0x94D=0xFF and the new byte
# Game+0x941=1 (death leaves 0x941 at 0 and sets health 0; surrender keeps it).
SURRENDER_ENTRY, SURRENDER_FLAG = 0x546E540, 0x941


# Player-owned units: native creature GUIDs (totems, companions) and pet GUIDs.
SUMMON_PREFIXES = (0xF130, 0xF140)


def owned_companion(block):
    """A native unit this player summoned or created (pets, water elemental, spirit wolves, treants)."""
    return any(k in block.fields and block.fields[k] | (block.fields.get(k + 1, 0) << 32) == SELF
               for k in (12, 14))


# Guest mirror writes: 'changed' (default) writes only differing records and
# dead flags; 'all' writes every record and retired flag each batch, to compare.
MIRROR_WRITE_ALL = os.environ.get('COOP_MIRROR_WRITE', 'changed') == 'all'
# Loot (0.0.19). A guest reserves up to MAX_CLAIM_ITEMS free objects (XP, gold, powerups) per round trip; a chest
# goes alone. Chests open once per player (variant B): only by contact (CHEST_CONTACT, native 0x545eb60), never by
# the pickup radius; the host keeps a chest book (opened_by/required per GUID) and filters chest DESTROYs per guest.
MAX_CLAIM_ITEMS = 8
CHEST_CONTACT = 3.0
HOST_CHECK_SLACK = 1.0  # The host sees a guest's last movement packet: accept that lag beyond the guest's exact check.
FREE_LOOT = (0, 1, 3, 4, 5, 6)


class _NativeCombatBridge(Bridge):
    @property
    def chest_claim(self):
        """A network guest's own open claim; on the host or in one local process the first open one."""
        number = getattr(self, 'number', None)
        if number not in (None, 1):
            return self.claims.get(number)
        return next(iter(self.claims.values()), None)

    @chest_claim.setter
    def chest_claim(self, claim):
        number = getattr(self, 'number', None)
        if number not in (None, 1):
            key = number
        elif claim is not None:
            key = claim.get('player', 2)
        else:
            self.claims.clear()
            return
        if claim is None:
            self.claims.pop(key, None)
        else:
            self.claims[key] = claim

    updated_world_probe = True  # Updated economy, combat, revival and boss regressions passed.

    def __init__(self, output, demo=False, shared_world=True):
        super().__init__(output, demo=demo, shared_world=shared_world)
        self.enemy_snapshot = {}
        self.ranged_targets = {}
        self.ranged_enemies = {}
        self.boss_definitions = {}
        self.host_boss_hud = None
        self.hud_buffer = 0
        self.provided_hp = {}
        self.provided_by_guest = {n: {} for n in self.guests if n != 2}
        self.damage_pending = {}
        self.effects_pending = []
        self.summon_maps = {n: {} for n in self.members}
        self.summons = {n: set() for n in self.members}
        self.dynamic_guids = {n: set() for n in self.members}  # Native ground-spell GUIDs per owner.
        self.unmapped_companions = set()  # Logged once each; bounded.
        self.own_auras = {n: OwnAuras() for n in self.members}  # Guest debuffs on own mirrors.
        self.aura_overlay = AuraOverlay()  # Host: guest debuffs in free enemy debuff slots.
        # Long-session state that hit its bound and dropped old entries instead of ending the session.
        self.bound_dropped, self.bound_logged, self.aura_drops_seen = {}, {}, 0
        # 0.95.0 menu "give up" (tag 10): players who gave up, the host's party-wide
        # surrender and the guests that already ran the native surrender for it.
        self.surrendered, self.surrender_applied = set(), set()
        self.party_surrender = self.self_surrendered = False
        self.surrender_rejected = set()
        self.area_hits = []
        self.areas_by_guest = {n: [] for n in self.guests if n != 2}
        self.next_guest_attack = float('inf')
        self.native_combat_packets = 0
        self.gold_counter = 0
        self.gold_seen = 0
        self.gold_pending = 0
        self.gold_by_guest = {n: 0 for n in self.guests if n != 2}
        self.pickup_xp_pending = 0
        self.chests = {}
        self.claims = {}      # player -> open loot claim (a guest process holds only its own)
        self.chest_book = {}  # host: chest guid -> position, value, opened_by, required, native
        self.powerups_pending = {n: [] for n in self.members}
        self.xp_multipliers = {}
        self.party_xp_buffer = 0
        self.extra_hooks += (SPAWN, FIND_SPAWN, APPLY_EFFECT, ENEMY_AOE, GROUND_AOE, ENEMY_TARGET, HUD_DELIVER)
        if UPDATED:
            self.extra_hooks += (REMOVE_LOOT,)
        self.spawn_counts = {n: 0 for n in self.members}
        self.spawn_turn = 0
        self.spawn_kind = 0
        self.spawn_debt = 0.0
        self.bonus_spawns = []
        self.spawning_bonus = False
        self.spawn_clone = self.spawn_option = self.spawn_scale = 0
        self.spawn_rng = None
        self.victory_requested = False
        self.victory_guests = set()
        self.hud_buffers = {}
        self.spawn_bonus_distance = float(os.environ.get('COOP_SPAWN_BONUS_DISTANCE', '100'))
        if not math.isfinite(self.spawn_bonus_distance) or self.spawn_bonus_distance <= 0:
            raise ValueError('Spawn bonus distance must be finite and positive')

    def note_bound(self, state, amount=1, **details):
        """Bounded long-session state dropped old entries: counted, logged at most once a minute per state."""
        self.bound_dropped[state] = self.bound_dropped.get(state, 0) + amount
        now = time.monotonic()
        if now >= self.bound_logged.get(state, 0):
            self.bound_logged[state] = now + 60
            self.record(event='bounded_state_dropped', state=state, dropped=self.bound_dropped[state], **details)

    def note_aura_drops(self):
        dropped = sum(o.dropped for o in self.own_auras.values()) + self.aura_overlay.dropped
        if dropped > self.aura_drops_seen:
            self.note_bound('guest_auras', dropped - self.aura_drops_seen,
                            guest_entries=sum(len(o.fields) for o in self.own_auras.values()),
                            host_entries=len(self.aura_overlay.guests))
            self.aura_drops_seen = dropped

    def spawn_bonus(self):
        living = [n for n in self.members if self.native_states.get(n, (0,))[0] in (1, 2, 3)]
        poses = [self.router.players[0xFF0100 + n].pose for n in living if 0xFF0100 + n in self.router.players]
        distance = max((math.hypot(a.x - b.x, a.y - b.y) for a in poses for b in poses), default=0)
        return .5 * min(1, distance / self.spawn_bonus_distance)

    def queue_gold(self, amount):
        if 2 in self.guests:
            self.gold_pending += amount
        for n in self.gold_by_guest:
            self.gold_by_guest[n] += amount

    def spawn_owner(self):
        living = [n for n in self.members if self.native_states.get(n, (0,))[0] in (1, 2, 3)]
        if not living:
            return None
        owner = living[self.spawn_turn % len(living)]
        if len(living) > 1:
            self.spawn_turn += 1
        return owner

    def party_xp_multiplier(self):
        # Add bonuses, not base multipliers; never write back into personal stats.
        return struct.unpack('<f', struct.pack('<f', max(0, 1 + sum(
            self.xp_multipliers.get(n, 1) - 1 for n in self.members))))[0]

    def __call__(self, client, rva, context):
        if rva == REMOVE_LOOT and client.number == 1:
            game, index = q(context, 128), q(context, 136)
            if game != client.server + 0x10:
                raise ValueError('Loot removal has no owned game')
            pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x5C8), 16))
            if not index < count <= MAX_NATIVE_OBJECTS:
                raise ValueError('Loot removal index exceeds owned array')
            kind = struct.unpack('<I', client.memory(pointer + index * 0x48 + 0x20, 4))[0]
            if kind in (3, 4, 5, 6):
                injected = (client.saved_context is not None and
                            q(client.memory(q(context, 152), 8)) == client.call_return)
                recipients = self.members if injected else self.guests
                for n in recipients:
                    if len(self.powerups_pending[n]) >= MAX_QUEUE:
                        raise ValueError('Shared powerup queue exceeds bound')
                    self.powerups_pending[n].append(kind)
                self.record(event='shared_powerup_collected', kind=kind, recipients=list(recipients))
            return
        if rva == HUD_DELIVER:
            payload = json.loads(client.memory(q(context, 136), q(context, 184)))
            if client.number == 1:
                self.host_boss_hud = payload.get('boss')
            else:
                # HUD receives a borrowed string; the caller still frees its
                # original native allocation. Never modify combat prediction.
                payload['boss'] = self.host_boss_hud
                body = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
                if len(body) > 1048576:
                    raise ValueError('Native HUD exceeds scratch buffer')
                buffer = self.hud_buffer if client.number == 2 else self.hud_buffers.get(client.number, 0)
                if not buffer:
                    buffer = checked(allocate(client.handle, None, 1048576, 0x3000, 4))
                    if client.number == 2:
                        self.hud_buffer = buffer
                    else:
                        self.hud_buffers[client.number] = buffer
                client.put(buffer, body)
                struct.pack_into('<Q', context, 136, buffer)
                struct.pack_into('<Q', context, 184, len(body))
            if self.trace_packets:
                self.record(event='boss_hud_delivered', player=client.number, boss=payload.get('boss'))
            # Emulate the exact indirect CALL [RAX+20], preserving its return.
            stack = q(context, 152) - 8
            client.put(stack, struct.pack('<Q', client.base + HUD_DELIVER + 3))
            struct.pack_into('<Q', context, 152, stack)
            struct.pack_into('<Q', context, 248, q(client.memory(q(context, 120) + 0x20, 8)))
            return
        if rva == ENEMY_TARGET:
            # 47e4 (0x54a1bc0): Game in RSI, interpolated enemy XY in XMM14, enemy cursor RCX.
            # 7264 (0x5484b3b): Game RSI and cursor RCX unchanged, enemy XY in XMM6 (movsldup xmm6,xmm1 ... addps xmm6,xmm0).
            game_register = 168 if release_47e4() else 184 if release_0843() else 192
            enemy_xmm = 6 if release_7264() else 14 if release_47e4() else 6 if release_0843() else 12
            validate_live_game(client, context, game_register, enemy_offset=128, enemy_frame=True)
            enemy_xy = struct.unpack_from('<ff', context, 416 + 16 * enemy_xmm)
            xy = client.memory(q(context, game_register) + game_field(0x488), 8)
            # NaN/inf (an enemy record being torn down): no guest choice, the native target (the host) stays.
            broken = not all(math.isfinite(v) for v in (*enemy_xy, *struct.unpack('<ff', xy)))
            if broken:
                note_native_skip('enemy_target_nonfinite', q(context, 136), enemy=finite_text(enemy_xy),
                                 player=finite_text(struct.unpack('<ff', xy)))
            owner = 1
            # Radial attacks are centered on the enemy. Their native distance
            # check must retain the host position; the guest is checked separately.
            if client.number == 1 and q(context, 136) != 3 and not broken:
                x, y = struct.unpack_from('<ff', context, 416 + 16 * enemy_xmm)
                hx, hy = struct.unpack('<ff', xy)
                closest = math.hypot(x - hx, y - hy) if self.native_states.get(1, (0,))[0] in (1, 2, 3) else float('inf')
                for number in self.guests:
                    if self.native_states.get(number, (0,))[0] not in (1, 2, 3):
                        continue
                    gx, gy, _ = self.guest_position(number)
                    distance = math.hypot(x - gx, y - gy)
                    if distance < closest:
                        closest = distance
                        xy, owner = struct.pack('<ff', gx, gy), number
            context[432:448] = xy + bytes(8)  # MOVSD memory clears the upper lane.
            struct.pack_into('<Q', context, 248, client.base + relocated(0x53E5580))
            if client.number == 1:
                self.record(event='native_enemy_ability_target', player=owner, owner_verified=True)
            return
        if rva in (ENEMY_AOE, GROUND_AOE):
            v47 = release_47e4()
            v7264 = release_7264()
            # 47e4: ENEMY_AOE (enemy function) Game RBX, radius XMM6, damage XMM7*XMM12, attacker R12;
            # GROUND_AOE (update) Game R14, ground XY XMM11, radius XMM10, damage XMM7.
            # 7264 ENEMY_AOE (jb 0x54855e3): Game RCX, ucomiss xmm9,xmm6 (radius XMM9), damage XMM8*XMM7, attacker R13;
            # GROUND_AOE unchanged (update function without register renames).
            if v47:
                validate_live_game(client, context, (128 if v7264 else 144) if rva == ENEMY_AOE else 232, enemy_frame=rva == ENEMY_AOE)
            else:
                validate_live_game(client, context, (136 if release_0843() else 176) if rva == ENEMY_AOE else 240)
            ground_xmm = 11 if v47 else 10
            # Emulate the displaced unsigned-below branch without changing flags.
            below = bool(struct.unpack_from('<I', context, 68)[0] & 1)
            destinations = (0x53E5430, 0x53E6069) if rva == ENEMY_AOE else (0x53E1898, 0x53E1883)
            struct.pack_into('<Q', context, 248, client.base + relocated(destinations[0 if below else 1]))
            if client.number == 1:
                radius_xmm = ((9 if v7264 else 6) if rva == ENEMY_AOE else 10) if v47 else 9
                radius = struct.unpack_from('<f', context, 416 + 16 * radius_xmm)[0]
                damage = struct.unpack_from('<f', context, 416 + 16 * (8 if v7264 and rva == ENEMY_AOE else 7))[0]
                if rva == ENEMY_AOE:
                    damage *= struct.unpack_from('<f', context, 416 + 16 * (7 if v7264 else 12 if v47 else 8))[0]
                    attacker = q(context, 224 if v7264 else 216 if UPDATED else 240)
                    found = native_enemy(client, client.server + 0x10, attacker)
                    enemy = found[1] if found is not None else None
                else:
                    attacker = q(client.memory(q(context, 160) + (field('game_update_frame', 0x3D0) if UPDATED else 0x3C0), 8))
                    enemy = struct.unpack_from('<ff', context, 416 + 16 * ground_xmm)
                    if not all(map(math.isfinite, enemy)):
                        note_native_skip('area_attack_nonfinite', attacker, position=finite_text(enemy))
                        enemy = None  # The native branch still runs; only the guest check is skipped.
                if not (math.isfinite(radius) and 0 <= radius <= 1000 and math.isfinite(damage) and 0 <= damage <= MAX_ENEMY_DAMAGE):
                    note_native_skip('area_attack_invalid', attacker, radius=finite_text([radius])[0],
                                     damage=finite_text([damage])[0])
                    return
                guest_hit = False
                if enemy and not self.draining and not self.router.paused:
                    for number in self.guests:
                        if self.native_states.get(number, (0,))[0] != 1:
                            continue
                        gx, gy, _ = self.guest_position(number)
                        hit = math.hypot(gx - enemy[0], gy - enemy[1]) <= radius
                        guest_hit |= hit
                        queue = self.area_hits if number == 2 else self.areas_by_guest[number]
                        if hit and damage > 0:
                            clock = struct.unpack('<f', client.memory(client.server + 0x10 + game_field(0x85C), 4))[0]
                            self.queue_incoming_hit(number, 'areas', (attacker, damage), clock)
                self.record(event='native_enemy_area', attacker=attacker, radius=radius,
                            damage=damage, host_hit=not below, guest_hit=guest_hit,
                            kind='radial' if rva == ENEMY_AOE else 'ground', owner_verified=True)
            return
        if rva == APPLY_EFFECT:
            if client.number != 1:
                effect = client.memory(q(context, 184), 12)
                if struct.unpack_from('<I', effect)[0] in (1, 2, 3, 4, 10):
                    if len(self.effects_pending) >= MAX_QUEUE:
                        raise ValueError('Guest effect queue exceeds bound')
                    spell = struct.unpack('<I', client.memory(q(context, 152) + 0x28, 4))[0]
                    self.effects_pending.append((q(context, 136), effect, spell))
            return
        if client.number == 1 and rva == SPAWN and 1 in self.ready and len(self.router.players) == len(self.members):
            self.spawn_kind = q(context, 136)
            if not 0 <= self.spawn_kind <= 11:
                raise ValueError('Unknown native enemy kind')
            # Both centers use the original annulus and native terrain validation.
            struct.pack_into('<Q', context, 184, self.spawn_option)
        if (client.number == 1 and rva == FIND_SPAWN and 1 in self.ready and
                q(client.memory(q(context, 152), 8)) == client.base + relocated(0x53FE9EC) and
                len(self.router.players) == len(self.members)):
            owner = self.spawn_owner()
            if owner is not None:
                self.spawn_counts[owner] += 1
                game = q(context, 136)
                clone = bytearray(client.memory(game, field('game_extent', 0x8D0) if UPDATED else 0x8C0))
                if self.spawn_rng is not None:
                    rng = game_field(0x808)
                    clone[rng:rng + 32] = client.memory(self.spawn_clone + rng, 32)
                self.spawn_rng = True
                pose = self.router.players[0xFF0100 + owner].pose
                struct.pack_into('<3f', clone, game_field(0x488), pose.x, pose.y, pose.z)
                client.put(self.spawn_clone, bytes(clone))
                struct.pack_into('<Q', context, 136, self.spawn_clone)
                bonus = self.spawn_bonus()
                if not self.spawning_bonus:
                    self.spawn_debt += bonus
                    if self.spawn_debt >= 1:
                        if len(self.bonus_spawns) >= MAX_QUEUE:
                            raise ValueError('Spawn bonus queue exceeds bound')
                        self.bonus_spawns.append(self.spawn_kind)
                        self.spawn_debt -= 1
                self.record(event='spawn_allocated', player=owner, bonus=self.spawning_bonus,
                            multiplier=1 + bonus, counts=dict(self.spawn_counts))
        if (client.number != 1 and rva == AWARD_XP and
                (client.saved_context is None or q(client.memory(q(context, 152), 8)) != client.call_return)):
            # Only our direct XP replay is authoritative. Native choice completion
            # can award mirror loot inside an injected CHOOSE call too.
            stack = q(context, 152)
            struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
            struct.pack_into('<Q', context, 152, stack + 8)
            self.record(event='mirror_xp_suppressed')
            return
        result = super().__call__(client, rva, context)
        if client.number == 1 and rva == TICK:
            self.spawn_clone = checked(allocate(client.handle, None,
                field('game_extent', 0x8D0) if UPDATED else 0x8C0, 0x3000, 4))
            self.spawn_option = checked(allocate(client.handle, None, 16, 0x3000, 4))
            self.spawn_scale = checked(allocate(client.handle, None, 8, 0x3000, 4))
            # The single-player arena-center clamp defeats split positioning.
            # Bypass it only for our borrowed spawn context, retaining terrain
            # and height checks and all ordinary native placement callers.
            if not release_47e4():
                # 47e4's spawn search (0x5496960) uses a per-map zone table instead of this
                # arena-center clamp; the bypass is not installed there (coop-lab/port-re/decisions.py).
                offset = relocated(0x53FF2DF)
                original = expected_bytes(0x53FF2DF, bytes.fromhex('f2410f108680000000 0f28ce 0f5cc8'))
                if client.memory(client.base + offset, len(original)) != original:
                    raise RuntimeError('Native arena clamp instructions changed')
                code = (b'\x50\x48\xb8' + struct.pack('<Q', self.spawn_clone) +
                        bytes.fromhex('4839c7 58 750e') + absolute_jump(client.base + relocated(0x53FF322)) +
                        original + absolute_jump(client.base + offset + len(original)))
                client.patch(client.base + offset, absolute_jump(client.executable_buffer(code)) + b'\x90')
            # Scale the native population limit by the same bounded Q16 bonus.
            offset = relocated(0x53FE96D)
            cap_load = bytes.fromhex('488b8ed8020000' if UPDATED else '488b8ec8020000')
            original = expected_bytes(0x53FE96D, bytes.fromhex('4839d1 0f839e060000') + cap_load)
            cap_load = original[9:]
            if client.memory(client.base + offset, len(original)) != original:
                raise RuntimeError('Native enemy cap instructions changed')
            code = (b'\x50\x41\x52\x49\xba' + struct.pack('<Q', self.spawn_scale) +
                    bytes.fromhex('4889d0 490faf02 48c1e810 4801c2 415a 58 4839d1 720e') +
                    absolute_jump(client.base + relocated(0x53FF014)) + cap_load +
                    absolute_jump(client.base + offset + len(original)))
            client.patch(client.base + offset, absolute_jump(client.executable_buffer(code)) + b'\x90' * 2)
            self.party_xp_buffer = checked(allocate(client.handle, None, 4, 0x3000, 4))
            client.put(self.party_xp_buffer, struct.pack('<f', 1))
            # Both world pickup paths round only after applying the party bonus.
            for site, raw in ((0x53F2416, 'f30f598624050000e8ec792900f3410f5fc5'),
                              (0x53F32A5, 'f30f598624050000e85d6b2900f3410f5fc2')) if UPDATED else ():
                original = reviewed_bytes(site, bytes.fromhex(raw))
                address = client.base + reviewed_rva(site)
                if client.memory(address, len(original)) != original:
                    raise RuntimeError('Native XP pickup instructions changed')
                clamp = original[-5:]
                if original[-9:-4] == bytes.fromhex('f30f5f05'):
                    # 47e4 path A: MAXSS XMM0,[RIP+disp] cannot be copied; use its absolute operand.
                    operand = address + len(original) + struct.unpack('<i', original[-4:])[0]
                    clamp = b'\x48\xb8' + struct.pack('<Q', operand) + bytes.fromhex('f30f5f00')
                code = (b'\x48\xb8' + struct.pack('<Q', self.party_xp_buffer) +
                        bytes.fromhex('f30f5900 48b8') +
                        struct.pack('<Q', client.base + reviewed_rva(0x5689E0F)) +
                        bytes.fromhex('ffd0') + clamp +
                        absolute_jump(address + len(original)))
                client.patch(address, absolute_jump(client.executable_buffer(code)) + b'\x90' * (len(original) - 14))
            self.gold_counter = checked(allocate(client.handle, None, 8, 0x3000, 4))
            # Count only world pickup credits. Chest spending and gold selected
            # as a private reward use different native instructions.
            gold_instructions = bytes.fromhex('8b8eb8040000 01c1 898eb8040000' if UPDATED else '8b8ea8040000 01c1 898ea8040000')
            for legacy_offset in (0x53E75EF, 0x53E7D9E, 0x53E7ED8):
                offset = relocated(legacy_offset)
                original = expected_bytes(legacy_offset, gold_instructions)
                if client.memory(client.base + offset, len(original)) != original:
                    raise RuntimeError('Native pickup gold instructions changed')
                prefix, suffix = b'\x9c\x52\x48\xba', b'\x48\x01\x02\x5a\x9d'
                if release_0843() and legacy_offset != 0x53E75EF:
                    prefix = bytes.fromhex('9c5048b8')
                    suffix = bytes.fromhex('480138589d' if legacy_offset == 0x53E7D9E else '480108589d')
                code = (prefix + struct.pack('<Q', self.gold_counter) +
                        suffix + original +
                        absolute_jump(client.base + offset + len(original)))
                client.patch(client.base + offset, absolute_jump(client.executable_buffer(code)))
        if client.number != 1 and rva == TICK:
            # The host already enforces the scaled population limit. Mirrors
            # have a separate MAX_ENEMIES adapter bound (play_limits), not a second world cap.
            cap_branch = expected_bytes(0x53FE970, bytes.fromhex('0f839e060000'))
            if client.memory(client.base + relocated(0x53FE970), 6) != cap_branch:
                raise RuntimeError('Native mirror cap branch changed')
            client.patch(client.base + relocated(0x53FE970), b'\x90' * 6)
            # Keep native DOT timers, damage, leech and temporary-vector cleanup.
            # Skip enemy AI per enemy, then skip loot/world spawning after cleanup.
            # The native victory branch needs these borrowed Vec addresses even
            # when our guest path skipped the single-player world/loot section.
            if not (release_0843() or release_47e4()):
                restore_game = client.executable_buffer(game_frame_code(code_fields(bytes.fromhex(
                    ('4c8bad e0030000 498d85 e8050000 488985 c8030000 '
                     '498d85 00060000 488985 80000000') if UPDATED else
                    ('4c8bad d0030000 498d85 d8050000 488985 a0030000 '
                     '498d85 f0050000 488985 80000000')), 'game', {'r13'})) + absolute_jump(client.base + relocated(0x53EA280)))
            if release_0843():
                restore_game = client.executable_buffer(game_frame_code(code_fields(bytes.fromhex(
                    '4c8ba5e0030000 498d8424e8050000 488985c8030000'), 'game', {'r12'})) +
                    absolute_jump(client.base + relocated(0x53EA280)))
            elif release_47e4():
                # 47e4: Game in R13; only the &Game.vec(0x5E8) slot is read first after 0x5480c07.
                restore_game = client.executable_buffer(game_frame_code(code_fields(bytes.fromhex(
                    '4c8bade0030000 498d85e8050000 488985c8030000'), 'game', {'r13'})) +
                    absolute_jump(client.base + relocated(0x53EA280)))
            patches = ((relocated(0x53E3381), expected_bytes(0x53E3381, bytes.fromhex('f30f10862c0100000f2ec70f868e000000')),
                        absolute_jump(client.base + relocated(0x53E2EB6)) + b'\x90' * 3),
                       (relocated(0x53E6B22), expected_bytes(0x53E6B22, bytes.fromhex('f20f10be980400008b86a0040000' if UPDATED else 'f20f10be880400008b8690040000')),
                        absolute_jump(restore_game)))
            for offset, expected, replacement in patches:
                if client.memory(client.base + offset, len(expected)) != expected:
                    raise RuntimeError('Guest effect/world boundary changed')
                client.patch(client.base + offset, replacement + b"\x90" * max(0, len(expected) - len(replacement)))
            client.patch(client.base + relocated(0x53DC9F5), phase_gate())
        return result

    def native_totem_guids(self, number):
        client = self.clients[number]
        pointer, count = struct.unpack('<QQ', client.memory(
            client.server + 0x10 + (field('game', 0x5C0) if UPDATED else 0x5B0), 16))
        if count > MAX_LIVE_SUMMONS or count and not pointer:
            raise ValueError('Native totem vector exceeds bound')
        # The verified totem update region owns 0x70-byte entries; +0x50
        # is the GUID sent by its native DESTROY path (47e4: 0x78-byte entries, GUID +0x58).
        stride, guid = (0x78, 0x58) if release_47e4() else (0x70, 0x50)
        return {q(client.memory(pointer + i * stride + guid, 8)) for i in range(count)}

    def receive_summon_packet(self, opcode, body, owner=None):
        """Track remote summon lifetime for departure, validating its namespace."""
        if opcode == UPDATE:
            for block in objects(body, remap=False):
                if block.kind in (2, 3) and block.object_type == 3:
                    number = ((block.guid & 0xFFFFFF) >> 22) + 1
                    # Totems name their owner in SUMMONEDBY and CREATEDBY; companions in at least one.
                    owners = [block.fields.get(k, 0) | (block.fields.get(k + 1, 0) << 32)
                              for k in (12, 14) if k in block.fields]
                    if (block.guid >> 48 not in SUMMON_PREFIXES or number not in self.guests or
                            owner is not None and number != owner or
                            block.fields.get(0, 0) | (block.fields.get(1, 0) << 32) != block.guid or
                            not owners or any(o != 0xFF0100 + number for o in owners)):
                        raise ValueError('Guest summon has an invalid owner or identity')
                    if len(self.summons[number]) >= MAX_LIVE_SUMMONS and block.guid not in self.summons[number]:
                        raise ValueError('Too many remote summons')
                    self.summons[number].add(block.guid)
                elif dynamic_object(block, native=False):
                    number = ((block.guid & 0xFFFFFF) >> 22) + 1
                    if (number not in self.guests or owner is not None and number != owner or
                            dynamic_caster(block) != 0xFF0100 + number):
                        raise ValueError('Guest ground spell has an invalid owner or identity')
                    if len(self.summons[number]) >= MAX_LIVE_SUMMONS and block.guid not in self.summons[number]:
                        raise ValueError('Too many remote summons')
                    self.summons[number].add(block.guid)
        elif opcode == DESTROY and len(body) == 8:
            guid = q(body)
            number = ((guid & 0xFFFFFF) >> 22) + 1
            if number in self.summons:
                if owner is not None and number != owner:
                    raise ValueError('Guest destroyed another owner summon')
                self.summons[number].discard(guid)

    def make_summon_room(self, number, limit=None):
        """Keep one guest's summon identities bounded: drop the oldest destroyed ones, never live ones."""
        limit = limit or SUMMON_HISTORY
        mapping, live = self.summon_maps[number], self.summons[number]
        if len(mapping) < limit:
            return
        drop = []
        for native, network in mapping.items():  # Oldest first.
            if network not in live:
                drop.append(native)
                if len(mapping) - len(drop) < limit * 3 // 4:
                    break
        for native in drop:
            del mapping[native]
            self.dynamic_guids[number].discard(native)
        self.note_bound('summon_identities', len(drop), player=number, kept=len(mapping))

    def filter_summons(self, number, opcode, body):
        mapping = self.summon_maps[number]
        if opcode == UPDATE:
            blocks = objects(body, remap=False)
            own = self.own_auras.get(number)
            if own is not None:
                for block in blocks:
                    if block.guid not in mapping and not owned_companion(block):
                        own.observe(block)  # Mirror enemies only (native creature GUIDs).
                self.publish_local_auras(number)
            candidates = [b for b in blocks if b.kind in (2, 3) and b.object_type == 3]
            owned = self.native_totem_guids(number) if candidates else set()
            for block in candidates:
                companion = block.guid not in owned and block.guid not in mapping and owned_companion(block)
                if companion and (block.guid >> 48 not in SUMMON_PREFIXES or block.guid & 0xC00000):
                    # Not representable in the reserved namespace: logged, stays hidden as before
                    # instead of ending the session.
                    if block.guid not in self.unmapped_companions:
                        if len(self.unmapped_companions) < 128:
                            self.unmapped_companions.add(block.guid)
                            self.record(event='guest_companion_unmapped', player=number, native_guid=block.guid)
                        else:
                            self.note_bound('unmapped_companions', player=number, native_guid=block.guid)
                    continue
                if companion:
                    if block.guid not in mapping:
                        self.make_summon_room(number)
                    mapping[block.guid] = block.guid | ((number - 1) << 22)
                    self.summons[number].add(mapping[block.guid])
                    self.record(event='guest_companion_created', player=number, native_guid=block.guid,
                                network_guid=mapping[block.guid], entry=block.fields.get(3))
                    continue
                if block.guid in owned:
                    if block.guid >> 48 != 0xF130 or block.guid & 0xC00000:
                        # Above four million native objects in one run the reserved owner
                        # bits are taken: like a companion, the totem stays hidden for the
                        # others (it still works for its owner) instead of ending the session.
                        if block.guid not in self.unmapped_companions and len(self.unmapped_companions) < 128:
                            self.unmapped_companions.add(block.guid)
                            self.record(event='guest_totem_unmapped', player=number, native_guid=block.guid)
                        else:
                            self.note_bound('unmapped_totems', player=number, native_guid=block.guid)
                        continue
                    if block.guid not in mapping:
                        self.make_summon_room(number)
                    mapping[block.guid] = block.guid | ((number - 1) << 22)
                    self.summons[number].add(mapping[block.guid])
                    self.record(event='guest_totem_created', player=number, native_guid=block.guid,
                                network_guid=mapping[block.guid], entry=block.fields.get(3))
            for block in blocks:
                # Own ground spells (Rain of Fire). Mirror-enemy casts stay hidden.
                if dynamic_object(block) and dynamic_caster(block) == SELF and block.guid not in mapping:
                    self.make_summon_room(number)
                    mapping[block.guid] = block.guid | ((number - 1) << 22)
                    self.summons[number].add(mapping[block.guid])
                    self.dynamic_guids[number].add(block.guid)
                    if self.trace_packets:
                        self.record(event='guest_ground_spell_created', player=number, native_guid=block.guid,
                                    network_guid=mapping[block.guid], spell=block.fields.get(9))
            selected = [b for b in blocks if b.guid in mapping]
            if not selected:
                return None
            for recipient in self.members:
                if recipient != number:
                    translated = dict(mapping)
                    translated[SELF] = 0xFF0100 + number
                    translated[0xFF0100 + recipient] = SELF
                    self.attack_packets[recipient].append((UPDATE, object_packet(objects(
                        object_packet(selected), guid_map=translated))))
            # Keep local player/inventory output as well as the owner's totems.
            allowed = [b for b in blocks if b.guid in mapping or b.guid == SELF or b.guid >> 48 == 0x4000]
            if any(b.guid == SELF and any(k in b.fields for k in PROGRESSION) for b in allowed):
                self.progress_sent.pop(number, None)
            return object_packet(objects(object_packet(allowed), guid_map={**mapping, SELF: SELF}))
        if opcode in (DESTROY, MONSTER):
            reader = Reader(body, remap_enabled=False)
            guid = reader.guid(packed=opcode != DESTROY)
            if guid not in mapping:
                if opcode == DESTROY and number in self.own_auras:
                    self.own_auras[number].destroy(guid)
                    self.publish_local_auras(number)
                return None
            for recipient in self.members:
                if recipient != number:
                    self.attack_packets[recipient].append((opcode, remap_combat(
                        opcode, body, player_guid=0xFF0100 + number,
                        local_guid=0xFF0100 + recipient, guid_map=mapping)))
            if opcode == DESTROY:
                self.summons[number].discard(mapping[guid])
                if guid in self.dynamic_guids[number]:
                    # Ground spells never reuse a GUID within one Game; keep the history bounded.
                    local = remap_combat(opcode, body, player_guid=SELF, local_guid=None, guid_map=mapping)
                    self.dynamic_guids[number].discard(guid)
                    del mapping[guid]
                    return local
                self.record(event='guest_totem_destroyed', player=number, network_guid=mapping[guid])
            return remap_combat(opcode, body, player_guid=SELF, local_guid=None, guid_map=mapping)
        return None

    def native_phase_changed(self, client, number, previous, state):
        if state[0] != 4 or (previous or (0,))[0] == 4 or not release_7264():
            return
        if client.memory(client.server + 0x10 + SURRENDER_FLAG, 1)[0] == 1:
            self.player_surrendered(number)

    def player_surrendered(self, number):
        """A native "give up" (tag 10) was confirmed by the game's own surrender flag."""
        if number in self.surrendered:
            return
        self.surrendered.add(number)
        if number == 1:
            # Ends the run for everyone: the guests run the same native surrender,
            # then the team defeat path shows every player the defeat.
            self.party_surrender = True
        elif not self.party_surrender and getattr(self, 'number', None) == number:
            # A guest who gave up leaves this party like a departing player; the
            # host and the others keep playing.
            self.self_surrendered = self.stop_requested = True
        self.record(event='player_surrendered', player=number, party=self.party_surrender)

    def apply_party_surrender(self, client, context):
        """Run the native surrender once on a guest after the host gave up."""
        number = client.number
        if number == 1 or not self.party_surrender or number in self.surrender_applied:
            return False
        self.surrender_applied.add(number)
        game = client.server + 0x10
        phase = self.native_states.get(number, (0,))[0]
        if phase not in (1, 2, 3) or client.memory(game, 4) == struct.pack('<I', 2):
            # Already down or out of a run: the native function would refuse.
            self.record(event='party_surrender_applied', player=number, native=False, phase=phase)
            return False
        if not release_7264():
            raise ValueError('Party surrender is bound to the 0.95.0 native function')
        code = b'\x48\xb8' + struct.pack('<Q', client.base + SURRENDER_ENTRY) + b'\xff\xe0'
        def completed():
            self.record(event='party_surrender_applied', player=number, native=True, phase=phase,
                        flag=client.memory(game + SURRENDER_FLAG, 1)[0])
        client.call_before(context, None, game, entry_code=code, after=completed)
        return True

    def publish_local_auras(self, number):
        # A network guest sends its changes in its state message; a process that
        # also runs the host game overlays them directly.
        if getattr(self, 'number', 1) == 1:
            self.receive_guest_auras(number, self.own_auras[number].take_changes())
        self.note_aura_drops()

    def receive_guest_auras(self, player, auras):
        # State only: the overlay is written with the next captured host world
        # block, where the world counters are the party totals (the group bridge
        # swaps them to one peer's while it receives).
        if player not in self.guests:
            raise ValueError('Guest auras from a non-guest')
        if auras:
            self.aura_overlay.guest_auras(player, validate_auras(auras))
            self.note_aura_drops()

    def drop_guest_auras(self, player):
        self.own_auras.pop(player, None)
        self.aura_overlay.drop_player(player)

    def world_observed(self, blocks, destroyed=None):
        for block in blocks:
            self.aura_overlay.host_block(block)
        if destroyed is not None:
            self.aura_overlay.destroy(destroyed)

    def capture_world(self, opcode, body):
        super().capture_world(opcode, body)
        if self.aura_overlay.dirty:
            # Only after this host block is queued: a host write to a shared packed
            # aura field must reach every client before our composed value.
            self.emit_aura_overlay()

    def emit_aura_overlay(self):
        for guid, fields in self.aura_overlay.updates(self.world_guids):
            packet = values_packet(guid, fields)
            # Guests: the same FIFO as the host world (delivered in order, held with it).
            # Host: its own client receives bridge packets after the native batch.
            for recipient in self.guests:
                (self.world_pending if recipient == 2 else self.world_queues[recipient]).append((UPDATE, packet))
                self.counts['world_captured'] += 1
                if self.trace_packets:  # Same evidence as host world: deliveries resolve to a capture.
                    self.record(event='world_captured', recipient=recipient, opcode=UPDATE,
                                digest=hashlib.sha256(packet).hexdigest(), body=packet.hex())
            self.notice_packets[1].append((UPDATE, packet))
            if self.trace_packets:
                self.record(event='guest_aura_overlay', target=guid, fields=fields)

    def route_enemy_hit(self, client, context):
        # 0.84.3's ordinary projectile impact ignores its stored victim GUID.
        # Other non-melee callers (ground/radial abilities) retain their own routing.
        stack = q(context, 152)
        # HURT return site in the native ordinary impact loop and the impact record's victim slot.
        impact_return, victim_slot = ((family('impact_return'), family('impact_victim_slot')) if release_47e4()
                                      else (0x5458E5E, 0x180))
        if ((release_0843() or release_47e4()) and not (q(context, 192) & 255) and
                q(client.memory(stack, 8)) == client.base + impact_return):
            victim = q(client.memory(q(context, 160) + victim_slot, 8))
            if victim != SELF:
                number = victim - 0xFF0100
                damage = struct.unpack_from('<f', context, 432)[0]
                if not math.isfinite(damage) or not 0 <= damage <= MAX_ENEMY_DAMAGE:
                    note_native_skip('projectile_damage_invalid', q(context, 184), damage=finite_text([damage])[0])
                elif number in self.guests and self.native_states.get(number, (0,))[0] == 1:
                    queue = self.area_hits if number == 2 else self.areas_by_guest[number]
                    clock = struct.unpack('<f', client.memory(client.server + 0x10 + game_field(0x85C), 4))[0]
                    self.queue_incoming_hit(number, 'areas', (q(context, 184), damage), clock)
                struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
                struct.pack_into('<Q', context, 152, stack + 8)
                self.record(event='ordinary_projectile_impact', player=number,
                            attacker=q(context, 184), damage=damage)
                return
        return super().route_enemy_hit(client, context)

    def route_projectile(self, opcode, body):
        if not (release_0843() or release_47e4()) or opcode not in (0x131, 0x132):
            return body
        reader = Reader(body, remap_enabled=False)
        attacker = reader.guid()
        reader.guid()
        spell = reader.integer(4)
        enemy = self.enemy_snapshot.get(attacker) or self.ranged_enemies.get(attacker)
        if enemy is None:
            return body
        definition = q(enemy[0], enemy_offset(0x80) - 0x68)
        client = self.clients[1]
        if not definition or struct.unpack('<II', client.memory(client.base + definition, 8)) != (1, spell):
            return body  # Ordinary ranged definitions only; bosses are separate.
        key = attacker, spell
        living = [n for n in self.members if self.native_states.get(n, (0,))[0] in (1, 2, 3)]
        if opcode == 0x131 or key not in self.ranged_targets:
            if key not in self.ranged_targets and len(self.ranged_targets) >= MAX_ENEMIES:
                # Casts whose enemy vanished without a DESTROY (run end): drop the oldest.
                del self.ranged_targets[next(iter(self.ranged_targets))]
                self.note_bound('ordinary_cast_targets')
            self.ranged_targets[key] = min(living, key=lambda n: sum((a - b) ** 2 for a, b in zip(
                enemy[2], (self.router.players[0xFF0100 + n].pose.x,
                           self.router.players[0xFF0100 + n].pose.y,
                           self.router.players[0xFF0100 + n].pose.z)))) if living else 1
        target = self.ranged_targets[key]
        if opcode == 0x132:
            self.ranged_targets.pop(key, None)
            game = client.server + 0x10
            # Pending ordinary impacts Vec (ptr,len); 47e4 moved it to Game+0x4F8.
            pointer, count = struct.unpack('<QQ', client.memory(game + (0x4F8 if release_47e4() else 0x5B8), 16))
            if count > MAX_NATIVE_OBJECTS:
                raise ValueError('Native pending impact count exceeds bound')
            # Match the newly appended ordinary impact, leaving earlier flights alone.
            for index in reversed(range(count)):
                address = pointer + index * 0x50
                row = client.memory(address, 0x50)
                if (q(row, 0x28) == attacker and q(row, 0x20) == SELF and
                        struct.unpack_from('<I', row, 0x40)[0] == spell and row[0x49] == 1):
                    client.put(address + 0x20, struct.pack('<Q', SELF if target == 1 else 0xFF0100 + target))
                    if target in self.guests:
                        pose = self.router.players[0xFF0100 + target].pose
                        # All ordinary ranged spells in the nine 0.84.3 maps;
                        # values verified against native speed helper 5497C50.
                        speed = {116: 28, 133: 24, 403: 20, 589: 0, 686: 20, 8092: 0, 11366: 24}[spell]
                        now = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
                        distance = math.hypot(enemy[2][0] - pose.x, enemy[2][1] - pose.y)
                        client.put(address + 0x3C, struct.pack('<f', now + (distance / speed if speed else 0)))
                    break
            else:
                raise RuntimeError('Ordinary cast has no matching native projectile')
        self.record(event='ordinary_projectile_target', attacker=attacker, spell=spell,
                    player=target, opcode=opcode)
        return remap_combat(opcode, body, player_guid=SELF, local_guid=None,
                            guid_map={SELF: SELF if target == 1 else 0xFF0100 + target})

    def filter_packet(self, number, opcode, body):
        if number == 1:
            body = self.route_projectile(opcode, body)
            if opcode == DESTROY and len(body) == 8:
                retired = q(body)
                self.ranged_enemies.pop(retired, None)
                for key in tuple(self.ranged_targets):
                    if key[0] == retired:
                        del self.ranged_targets[key]
        if opcode == UPDATE and self.native_states.get(number, (0,))[0] == 4:
            from world_packets import downed_player_values
            body = downed_player_values(body)
        if number != 1 and opcode == UPDATE:
            for block in objects(body, remap=False):
                if block.guid == SELF:
                    # These fields update this guest's remote avatar only. Native
                    # XP awards still come exclusively from the host. The display
                    # model carries druid forms.
                    vitals = {field: value for field, value in block.fields.items()
                              if 22 <= field <= 33 or field in PROGRESSION or field == DISPLAY_ID}
                    packet = vitals and self.sanitize_player_values(number, UPDATE, values_packet(0xFF0100 + number, vitals))
                    if packet:
                        for recipient in self.members:
                            if recipient != number:
                                self.notice_packets[recipient].append((UPDATE, packet))
        if number != 1 and opcode in (UPDATE, DESTROY, MONSTER):
            translated = self.filter_summons(number, opcode, body)
            if translated is not None:
                return translated
        if number != 1 and opcode in COMBAT:
            for recipient in self.members:
                if recipient != number:
                    self.attack_packets[recipient].append((opcode, remap_combat(opcode, body,
                        player_guid=0xFF0100 + number, local_guid=0xFF0100 + recipient,
                        guid_map=self.summon_maps[number])))
            self.native_combat_packets += 1
            self.record(event='native_guest_combat', player=number, opcode=opcode, body=body.hex())
            return remap_combat(opcode, body, player_guid=SELF, local_guid=None,
                                guid_map=self.summon_maps[number])
        return super().filter_packet(number, opcode, body)

    # The host captures the enemy vector every tick but needs the parsed
    # snapshot only for a send round or a guest effect. snapshot_enemies keeps
    # the raw bytes (one read while the game is halted) and the first access
    # parses exactly them, so the result equals an eager parse at capture time.
    @property
    def enemy_snapshot(self):
        if getattr(self, '_enemy_raw', None) is not None:
            self._parse_enemy_raw()
        return self._enemy_snapshot

    @enemy_snapshot.setter
    def enemy_snapshot(self, value):
        if getattr(self, '_enemy_raw', None) is not None:
            self._parse_enemy_raw()
        self._enemy_snapshot = value

    @property
    def boss_definitions(self):
        if getattr(self, '_enemy_raw', None) is not None:
            self._parse_enemy_raw()
        return self._boss_definitions

    @boss_definitions.setter
    def boss_definitions(self, value):
        if getattr(self, '_enemy_raw', None) is not None:
            self._parse_enemy_raw()
        self._boss_definitions = value

    def snapshot_enemies(self, client):
        data, now = native_enemy_array(client, client.server + 0x10)
        self._enemy_raw = (data, now, client.base)

    def _parse_enemy_raw(self):
        data, now, base = self._enemy_raw
        self._enemy_raw = None
        poses = {guid: (hp, position) for guid, hp, position in parse_native_enemies(data, now)}
        snapshot, bosses = {}, {}
        self._enemy_snapshot, self._boss_definitions = snapshot, bosses
        stride, guid_offset, _ = enemy_layout()
        definition_offset = enemy_offset(0x80) - 0x68
        bad = 0
        for offset in range(0, len(data), stride):
            guid = q(data, offset + guid_offset)
            if guid in poses:
                flat = bytearray(data[offset + 0x68:offset + stride])
                definition = q(flat, definition_offset)
                if definition:
                    definition -= base
                    if not 0 <= definition < IMAGE_SIZE:
                        # One record mid-teardown: skipped like an absent enemy.
                        bad += 1
                        note_native_skip('enemy_definition_invalid', guid)
                        continue
                else:
                    boss = q(data, offset + 0x30) - base
                    if q(data, offset + 0x18) == 0xFFFFFFFFFFFFFFFF or not 0 <= boss < IMAGE_SIZE - 0x58:
                        bad += 1
                        note_native_skip('boss_definition_invalid', guid)
                        continue
                    bosses[guid] = boss
                struct.pack_into('<Q', flat, definition_offset, definition)
                snapshot[guid] = (bytes(flat), *poses[guid])
                if definition:
                    # A queued GO can precede a death caused by injected guest
                    # damage. Retire cast metadata in packet order at DESTROY.
                    self.ranged_enemies[guid] = snapshot[guid]
        if bad and bad == len(poses) >= 5:
            # Every living enemy points outside the executable: a wrong layout, not a single broken entry.
            raise ValueError('Enemy definition is not in the verified executable')
        if len(self.ranged_enemies) > 2 * MAX_ENEMIES:
            # Enemies that left without a DESTROY (run end): keep the current ones, drop the oldest others.
            stale = [g for g in self.ranged_enemies if g not in snapshot][:len(self.ranged_enemies) - 3 * MAX_ENEMIES // 2]
            for guid in stale:
                del self.ranged_enemies[guid]
            self.note_bound('ordinary_enemy_metadata', len(stale), kept=len(self.ranged_enemies))

    def sync_mirrors(self, client, context, capture_only=False):
        provided = self.provided_hp if client.number == 2 else self.provided_by_guest.setdefault(client.number, {})
        game = client.server + 0x10
        pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x568), 16))
        if count > MAX_ENEMIES:
            raise ValueError('Enemy mirror count exceeds bound')
        S, _, _ = enemy_layout()
        E = enemy_offset
        data = bytearray(client.memory(pointer, count * S)) if count else bytearray()
        by_guid = {q(data, i * S + E(0x78)): i for i in range(count)}
        for guid, previous in provided.items():
            if guid in by_guid:
                health = struct.unpack_from('<f', data, by_guid[guid] * S + E(0xE0))[0]
                if not math.isfinite(health):
                    note_native_skip('mirror_health_nonfinite', guid, health=finite_text([health])[0])
                    continue
                dealt = previous - max(0, health)
                if dealt > 0 and guid in self.enemy_snapshot:
                    self.damage_pending[guid] = self.damage_pending.get(guid, 0) + dealt
                    self.record(event='native_guest_damage_computed', target=guid, damage=dealt)
        provided.clear()
        if len(self.damage_pending) > MAX_ENEMIES or any(v > MAX_ENEMY_DAMAGE for v in self.damage_pending.values()):
            raise ValueError('Guest damage queue exceeds bound')
        if capture_only:
            return False  # Final accepted native hits, without starting another mirror tick.
        retired = [i for guid, i in by_guid.items() if guid not in self.enemy_snapshot]
        missing = [guid for guid in self.enemy_snapshot if guid not in by_guid]
        # START's hidden local enemies are reusable owned allocations too.
        for guid in missing:
            boss = self.boss_definitions.get(guid)
            reusable = next((index for index in retired
                             if ((q(data, index * S + 0x18) != 0xFFFFFFFFFFFFFFFF) == (boss is not None)) and
                             (boss is None or q(data, index * S + 0x30) == client.base + boss)), None)
            if reusable is None:
                _, _, pose = self.enemy_snapshot[guid]
                before = count
                def completed():
                    after = q(client.memory(game + game_field(0x570), 8))
                    if after != before + 1:
                        raise RuntimeError('Native enemy mirror spawn was refused')
                    # Native local GUID counters can collide with an existing
                    # host GUID. Retire by slot before the next GUID lookup.
                    pointer = q(client.memory(game + game_field(0x568), 8))
                    client.put(pointer + before * S + E(0x78), bytes(8))
                    client.put(pointer + before * S + 0x68, struct.pack('<I', 1))
                self.note('mirror_spawn', 1)
                client.call_before(context, SPAWN if boss is None else SPAWN_BOSS, game,
                                   0 if boss is None else client.base + boss, position=pose, after=completed)
                return True
            index = reusable
            retired.remove(index)
            flat, _, _ = self.enemy_snapshot[guid]
            flat = bytearray(flat)
            definition_offset = E(0x80) - 0x68
            if q(flat, definition_offset):
                struct.pack_into('<Q', flat, definition_offset, q(flat, definition_offset) + client.base)
            address = pointer + index * S
            # Preserve native-owned vectors, retiring plain periodic-effect entries.
            client.put(address + 0x10, bytes(8))
            client.put(address + 0x68, bytes(flat))
            data[index * S + 0x68:(index + 1) * S] = flat
            by_guid[guid] = index
        retired_writes = written = 0
        for index in retired:
            # Retired slots keep their dead flag; rewriting it every batch made
            # native writes grow with every enemy that ever died (v11).
            if MIRROR_WRITE_ALL or struct.unpack_from('<I', data, index * S + 0x68)[0] != 1:
                client.put(pointer + index * S + 0x68, struct.pack('<I', 1))
                retired_writes += 1
        pending_effects = {guid for guid, _, _ in self.effects_pending}
        for guid, (flat, health, pose) in self.enemy_snapshot.items():
            address = pointer + by_guid[guid] * S
            health = max(0, health - self.damage_pending.get(guid, 0))
            # All game threads are suspended at this debugger event. Preserve
            # native-owned fields from this exact read and update one contiguous
            # span instead of seven WriteProcessMemory calls per enemy.
            start = by_guid[guid] * S + 0x68
            original = data[start:start + S - 0x68]
            updated = bytearray(original)
            struct.pack_into('<I', updated, 0, int(health == 0))
            struct.pack_into('<f', updated, E(0xE0) - 0x68, health)
            struct.pack_into('<6f', updated, E(0xFC) - 0x68, *pose, *pose)
            updated[E(0x114) - 0x68:E(0x11C) - 0x68] = bytes(8)
            if guid not in pending_effects:
                # Host debuffs also inform guest native conditional abilities.
                for start, end in ((0x88, 0x98), (0x124, 0x128), (0x130, 0x140)):
                    updated[E(start) - 0x68:E(end) - 0x68] = flat[E(start) - 0x68:E(end) - 0x68]
            if MIRROR_WRITE_ALL or updated != original:
                client.put(address + 0x68, bytes(updated))
                written += 1
            provided[guid] = health
        if written or retired_writes:
            self.note('mirror_writes', written, retired_writes)
        return False

    def apply_guest_damage(self, client, context):
        target = next(iter(self.damage_pending))
        damage = self.damage_pending[target]
        game = client.server + 0x10
        before = (native_enemy(client, game, target) or (0,))[0]
        if before <= 0:
            del self.damage_pending[target]
            self.record(event='guest_damage_target_already_dead', target=target, requested=damage)
            return False
        patches = list(guest_damage_patches())
        if self.native_states[1][0] == 4:
            patches.append((relocated(0x53FF52B), branch(0x53FF52B, 0x5402BF3, opcode=b'\x0f\x85', size=6), b'\x90' * 6))
        for offset, original, replacement in patches:
            if client.memory(client.base + offset, len(original)) != original:
                raise RuntimeError('Native raw damage instructions changed')
        for offset, original, replacement in patches:
            client.patch(client.base + offset, replacement)
        def completed():
            for offset, original, replacement in patches:
                client.patch(client.base + offset, original)
            after = (native_enemy(client, game, target) or (0,))[0]
            self.damage_pending[target] -= damage
            if self.damage_pending[target] <= 0:
                del self.damage_pending[target]
            self.snapshot_enemies(client)
            self.record(event='native_guest_damage_applied', target=target, before=before, after=after,
                        requested=damage, host_downed=self.native_states[1][0] == 4)
        client.call_before(context, DAMAGE, game, target, damage=damage, after=completed)
        return True

    def shared_victory(self, client):
        """Run the native victory path (save, root, result UI) on a guest, also one who was down at the victory."""
        game = client.server + 0x10
        # A guest who fell before the victory already had its run evaluated (without victory).
        self.rearm_result(client, 'shared_victory')
        client.put(game + game_field(0x7F0), struct.pack('<I', 1))
        client.put(game + game_field(0x8B5), b'\x00')
        client.put(game + game_field(0x8BF), b'\x01')
        self.victory_requested = True
        self.victory_guests.add(client.number)
        self.record(event='shared_victory_requested')

    def before_batch(self, client, context):
        self.next_guest_attack = float('inf')
        if client.number not in self.ready:
            return super().before_batch(client, context)
        if self.apply_party_surrender(client, context):
            return True
        if client.number == 1:
            # A boss death can collect coins and enter native victory in the
            # same tick. Publish those final credits before publishing phase 5.
            self.capture_pickup_gold(client)
        if self.native_states[client.number][0] == 5:
            if client.number != 1 and self.claims.get(client.number, {}).get('status') == 'refund':
                self.sync_chests(client, context)
            if self.powerups_pending[client.number]:
                self.record(event='shared_powerups_expired', player=client.number, reason='run_finished',
                            count=len(self.powerups_pending[client.number]))
                self.powerups_pending[client.number].clear()
            # Native victory tears down combat-owned storage. A stale peer
            # snapshot must never reconstruct mirrors into that completed run.
            if client.number == 1:
                self.enemy_snapshot.clear()
                self.boss_definitions.clear()
                self.damage_pending.clear()
                self.effects_pending.clear()
                self.bonus_spawns.clear()
            else:
                (self.provided_hp if client.number == 2 else self.provided_by_guest[client.number]).clear()
                self.damage_pending.clear()
                self.clear_incoming_hits(client.number, 'run_finished')
                self.apply_shared_gold(client)
            return False
        game = client.server + 0x10
        if client.number in self.guests:
            if self.native_states[client.number][0] == 4:
                # Native HURT ignores dead recipients; these hits cannot become
                # new attacks against the player's later revived life.
                self.clear_incoming_hits(client.number, 'recipient_dead')
            # Hits and other per-write work (mirrors, chests, rewards) alternate;
            # chained_hit bounds the hits per native queue write.
            due = self.hit_work_turn.get(client.number, True)
            self.hit_work_turn[client.number] = not due
            if due and self.chained_hit(client, context):
                return True
        multiplier = struct.unpack('<f', client.memory(game + game_field(0x514), 4))[0]
        if not math.isfinite(multiplier) or not 0 <= multiplier <= MAX_MULTIPLIER:
            note_native_skip('xp_multiplier_invalid', client.number, value=finite_text([multiplier])[0])
            multiplier = self.xp_multipliers.get(client.number, 1)  # Keeps the last valid value.
        self.xp_multipliers[client.number] = multiplier
        if client.number == 1:
            client.put(self.party_xp_buffer, struct.pack('<f', self.party_xp_multiplier()))
        if self.powerups_pending[client.number]:
            kind = self.powerups_pending[client.number].pop(0)
            if kind == 6:
                # Magnet acts on the single authoritative loot world. Its XP
                # and gold credits are already shared with every party member.
                if client.number == 1:
                    pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x5C8), 16))
                    if count > MAX_NATIVE_OBJECTS:
                        raise ValueError('Magnet loot count exceeds bound')
                    for i in range(count):
                        address = pointer + i * 0x48
                        loot_kind = struct.unpack('<I', client.memory(address + 0x20, 4))[0]
                        moving = struct.unpack('<I', client.memory(address + 0x18, 4))[0]
                        if loot_kind == 1 and moving == 0:
                            x, y = struct.unpack('<ff', client.memory(address + 0x34, 8))
                            hx, hy = struct.unpack('<ff', client.memory(game + game_field(0x488), 8))
                            arrival = self.host_clock + max(math.hypot(x - hx, y - hy) / 40.0, .15000000596046448)
                            client.put(address + 0x18, struct.pack('<If', 1, arrival))
                    code = b'\x48\xb8' + struct.pack('<Q', client.base + reviewed_rva(0x5412470)) + b'\xff\xe0'
                    client.call_before(context, None, game, entry_code=code,
                        after=lambda: self.record(event='shared_powerup_applied', player=1, kind=6))
                    return True
                self.record(event='shared_powerup_applied', player=client.number, kind=kind)
            else:
                # Native Speed/Berserking/Restoration owns timers, buff stacking,
                # recalculated stats, healing cap and the player's UI packets.
                code = b'\x48\xb8' + struct.pack('<Q', client.base + reviewed_rva(0x54135A0)) + b'\xff\xe0'
                def completed_powerup():
                    self.record(event='shared_powerup_applied', player=client.number, kind=kind)
                client.call_before(context, None, game, kind, entry_code=code, after=completed_powerup)
                return True
        if client.number == 1:
            client.put(self.spawn_scale, struct.pack('<Q', int(self.spawn_bonus() * 65536)))
            if self.sync_chests(client, context):
                return True
            if self.pickup_xp_pending:
                amount = u32_part(self.pickup_xp_pending)  # One native u32 award; the rest next batch.
                self.pickup_xp_pending -= amount
                client.call_before(context, AWARD_XP, client.server + 0x10, amount)
                return True
            self.snapshot_enemies(client)
            if self.effects_pending and not self.router.paused and self.native_states[1][0] in (1, 4):
                target, effect, spell = self.effects_pending.pop(0)
                if target in self.enemy_snapshot:
                    def completed():
                        self.snapshot_enemies(client)
                        self.record(event='guest_effect_applied', target=target,
                                    kind=struct.unpack_from('<I', effect)[0], spell=spell)
                    client.call_before(context, APPLY_EFFECT, client.server + 0x10, target,
                                       effect=effect, spell=spell, after=completed)
                    return True
            if self.damage_pending and not self.router.paused and self.native_states[1][0] in (1, 4):
                return self.apply_guest_damage(client, context)
            if self.bonus_spawns and not self.draining and not self.router.paused and self.native_states[1][0] in (1, 4):
                kind = self.bonus_spawns.pop(0)
                self.spawning_bonus = True
                def completed():
                    self.spawning_bonus = False
                client.call_before(context, SPAWN, client.server + 0x10, kind,
                                   position=(0, 0, 0), after=completed)
                return True
        elif client.number in self.ready:
            if self.native_states.get(1, (0,))[0] == 5 and client.number not in self.victory_guests:
                self.shared_victory(client)
            self.apply_shared_gold(client)
            if self.sync_chests(client, context):
                return True
            if self.draining:
                self.sync_mirrors(client, context, capture_only=True)
                self.drain_capture_complete = self.native_states[client.number][0] != 1
                return super().before_batch(client, context)
            if self.sync_mirrors(client, context):
                return True
        return super().before_batch(client, context)

    def capture_pickup_gold(self, client):
        if not self.gold_counter:
            return
        earned = q(client.memory(self.gold_counter, 8))
        delta = earned - self.gold_seen
        if not 0 <= delta <= MAX_COUNTER:
            raise ValueError('Shared pickup gold exceeds bound')
        self.queue_gold(delta)
        self.gold_seen = earned
        if delta:
            self.record(event='shared_gold_pickup', amount=delta)

    def apply_shared_gold(self, client):
        number = client.number
        pending = self.gold_pending if number == 2 else self.gold_by_guest.get(number, 0)
        if not pending:
            return
        game = client.server + 0x10
        gold = struct.unpack('<I', client.memory(game + game_field(0x4A8), 4))[0]
        earned = struct.unpack('<I', client.memory(game + game_field(0x6D0), 4))[0]
        amount = pending
        # Native u32 balances saturate; the copper display field saturates earlier (gold x 10000).
        balance, total = min(gold + amount, MAX_COUNTER), min(earned + amount, MAX_COUNTER)
        if balance - gold < amount:
            self.note_bound('gold_balance', amount - (balance - gold), player=number, balance=balance)
        client.put(game + game_field(0x4A8), struct.pack('<I', balance))
        client.put(game + game_field(0x6D0), struct.pack('<I', total))
        self.notice_packets[number].append((UPDATE, values_packet(SELF, {1176: copper(balance)})))
        if number == 2:
            self.gold_pending = 0
        else:
            self.gold_by_guest[number] = 0
        self.record(event='shared_gold_credited', player=number, amount=amount, balance=gold + amount)

    def sync_chests(self, client, context):
        game = client.server + 0x10
        if client.number == 1:
            pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x5C8), 16))
            if count > MAX_NATIVE_OBJECTS:
                raise ValueError('Native loot count exceeds bound')
            data = client.memory(pointer, count * 0x48) if count else b''
            # (index, position, kind, value, flying): +0x18 != 0 means the native pickup already pulls the
            # object to the host (magnet or pickup radius); guests never take those.
            self.chests = {q(data, i + 0x28): (i // 0x48, struct.unpack_from('<3f', data, i + 0x34),
                                             *struct.unpack_from('<II', data, i + 0x20),
                                             int(struct.unpack_from('<I', data, i + 0x18)[0] != 0))
                           for i in range(0, len(data), 0x48)
                           if struct.unpack_from('<I', data, i + 0x20)[0] in
                           ((0, 1, 2, 3, 4, 5, 6) if UPDATED else (0, 1, 2))}
            self.update_chest_book()
            # Claims in arrival order (deterministic); one native call per batch, always by GUID from this snapshot.
            for player, claim in list(self.claims.items()):
                if claim['status'] == 'reserved' and self.resolve_claim(client, context, game, player, claim):
                    return True
            return False
        claim = self.claims.get(client.number)
        phase = self.native_states[client.number][0]
        if claim and claim['status'] == 'collected':
            del self.claims[client.number]
            claim = None
        if claim and claim['status'] == 'refund':
            self.change_guest_gold(client, claim['cost'])
            self.record(event='guest_chest_refunded', **claim)
            del self.claims[client.number]
        elif claim and claim['status'] == 'removed' and phase == 1 and not self.router.paused:
            # Native chest purchase: next cost = trunc(float32(cost * 1.3) + 5).
            product = struct.unpack('<f', struct.pack('<f', claim['cost'] * 1.2999999523162842))[0]
            cost = int(struct.unpack('<f', struct.pack('<f', product + 5))[0])
            client.put(game + game_field(0x894), struct.pack('<I', cost))
            for offset in (0x6D4, 0x864):
                value = struct.unpack('<I', client.memory(game + game_field(offset), 4))[0]
                client.put(game + game_field(offset), struct.pack('<I', value + 1))
            del self.claims[client.number]
            self.record(event='guest_chest_awarded', guid=claim['guid'], cost=claim['cost'], player=client.number)
            client.call_before(context, OFFER_CHOICES, game, 1)
            return True
        if client.number in self.claims or self.draining or phase != 1 or self.router.paused:
            return False
        guest = self.router.players[0xFF0100 + client.number].pose
        host = self.router.players[0xFF0101].pose
        gold = struct.unpack('<I', client.memory(game + game_field(0x4A8), 4))[0]
        cost = struct.unpack('<I', client.memory(game + game_field(0x894), 4))[0]
        radius = struct.unpack('<f', client.memory(game + game_field(0x510), 4))[0]
        multiplier = struct.unpack('<f', client.memory(game + game_field(0x528), 4))[0]
        xp_multiplier = struct.unpack('<f', client.memory(game + game_field(0x514), 4))[0]
        if not (math.isfinite(radius) and 0 <= radius <= 1000 and
                math.isfinite(multiplier) and 0 <= multiplier <= 1000 and
                math.isfinite(xp_multiplier) and 0 <= xp_multiplier <= 1000):
            note_native_skip('pickup_profile_invalid', client.number,
                             values=finite_text([radius, multiplier, xp_multiplier]))
            return False  # Tried again on the next write.
        # A network guest holds its own view (host loot without chests it opened, plus chests only the host opened);
        # one local process derives the same view from the host snapshot.
        loot = self.chests if getattr(self, 'number', None) not in (None, 1) else self.loot_view(client.number)
        host_down = self.native_states[1][0] == 4
        free, chests = [], []
        for guid, (_, position, kind, _, flying) in loot.items():
            gd = sum((a - b) ** 2 for a, b in zip(position, (guest.x, guest.y, guest.z)))
            if kind == 2:
                if gd <= CHEST_CONTACT ** 2 and gold >= cost:
                    chests.append((gd, guid))
            elif not flying and gd <= radius ** 2:
                # Already flying objects belong to the host (0.0.17: orbs vanished mid-flight on the host).
                hd = sum((a - b) ** 2 for a, b in zip(position, (host.x, host.y, host.z)))
                if gd < hd or host_down:
                    free.append((gd, guid))
        if free:
            items = [guid for _, guid in sorted(free)[:MAX_CLAIM_ITEMS]]  # Nearest first, then by GUID.
            self.claims[client.number] = dict(guid=items[0], items=items, player=client.number, cost=0,
                                              status='reserved', range=radius, multiplier=multiplier,
                                              xp_multiplier=xp_multiplier)
            self.record(event='guest_loot_reserved', guid=items[0], items=len(items), cost=0, player=client.number)
        elif chests:
            guid = min(chests)[1]
            self.change_guest_gold(client, -cost)
            self.claims[client.number] = dict(guid=guid, items=[guid], chest=True, player=client.number, cost=cost,
                                              status='reserved', range=CHEST_CONTACT, multiplier=multiplier,
                                              xp_multiplier=xp_multiplier)
            self.record(event='guest_loot_reserved', guid=guid, items=1, cost=cost, kind=2, player=client.number)
        return False

    def resolve_claim(self, client, context, game, player, claim):
        """Host: settle one reserved claim; True when a native call was queued for this batch."""
        guest = self.router.players.get(0xFF0100 + player)
        if guest is None:
            claim['status'] = 'refund' if claim.get('chest') else 'collected'
            return False
        pose = (guest.pose.x, guest.pose.y, guest.pose.z)
        if claim.get('chest'):
            self.open_chest_for(player, claim, pose)
            return False
        items = claim['items']
        while claim.setdefault('next', 0) < len(items):
            guid = items[claim['next']]
            claim['next'] += 1
            entry = self.chests.get(guid)
            if entry is None or entry[2] not in FREE_LOOT:
                continue  # Taken meanwhile (host, earlier claim) or not free loot.
            if entry[4]:
                # It started flying to the host after the guest reserved it: the host gets it natively.
                self.record(event='guest_loot_released_flying', guid=guid, player=player)
                continue
            if sum((a - b) ** 2 for a, b in zip(entry[1], pose)) > (claim['range'] + HOST_CHECK_SLACK) ** 2:
                continue
            client.call_before(context, REMOVE_LOOT, game, entry[0],
                               after=lambda entry=entry, guid=guid: self.free_loot_taken(client, game, player, claim,
                                                                                          guid, entry))
            return True
        claim['status'] = 'collected'
        return False

    def free_loot_taken(self, client, game, player, claim, guid, entry):
        """Credit one free object a guest took (after its native REMOVE_LOOT)."""
        kind, value = entry[2], entry[3]
        if kind == 0:
            multiplier = self.party_xp_multiplier() if UPDATED else claim['xp_multiplier']
            product = struct.unpack('<f', struct.pack('<f', value * multiplier))[0]
            amount = max(1, math.floor(product + .5))
            if amount > MAX_COUNTER:
                raise ValueError('Guest pickup XP exceeds bound')
            self.pickup_xp_pending += amount
            self.record(event='guest_xp_pickup', amount=amount, guid=guid, player=player)
        elif kind == 1:
            product = struct.unpack('<f', struct.pack('<f', value * claim['multiplier']))[0]
            amount = math.floor(product + .5)  # Native CRT roundf, positive gold.
            if not 0 <= amount <= MAX_COUNTER:
                raise ValueError('Guest pickup gold exceeds bound')
            gold = struct.unpack('<I', client.memory(game + game_field(0x4A8), 4))[0]
            earned = struct.unpack('<I', client.memory(game + game_field(0x6D0), 4))[0]
            balance = min(gold + amount, MAX_COUNTER)  # u32 saturates, never ends the run.
            if balance - gold < amount:
                self.note_bound('gold_balance', amount - (balance - gold), player=1, balance=balance)
            client.put(game + game_field(0x4A8), struct.pack('<I', balance))
            client.put(game + game_field(0x6D0), struct.pack('<I', min(earned + amount, MAX_COUNTER)))
            self.notice_packets[1].append((UPDATE, values_packet(SELF, {1176: copper(balance)})))
            self.queue_gold(amount)
            self.record(event='shared_gold_pickup', amount=amount, picker=player)

    # ------------------------------------------------------------------ chests, variant B (once per player)

    def update_chest_book(self):
        """Host: book every native chest; a booked chest that left the host loot was opened natively by the host."""
        for guid, entry in self.chests.items():
            if entry[2] != 2:
                continue
            book = self.chest_book.get(guid)
            if book is None or not book['native']:
                # New (or a reused GUID after the host had opened the old one): every current member may open it.
                self.chest_book[guid] = dict(position=tuple(entry[1]), value=entry[3], opened_by=set(),
                                             required=set(self.members), native=True)
        for guid, book in list(self.chest_book.items()):
            if book['native'] and guid not in self.chests:
                book['native'] = False
                book['opened_by'].add(1)
                self.record(event='host_chest_opened', guid=guid, phantom_for=sorted(book['required'] - book['opened_by']))
                self.retire_chest(guid)

    def open_chest_for(self, player, claim, pose):
        """Host: a guest opens a booked chest once (no REMOVE_LOOT); the DESTROY goes only to him."""
        guid = claim['guid']
        book = self.chest_book.get(guid)
        reason = ('unknown' if book is None else 'already_opened' if player in book['opened_by'] else
                  'not_required' if player not in book['required'] else
                  'out_of_contact' if sum((a - b) ** 2 for a, b in zip(book['position'], pose)) >
                  (CHEST_CONTACT + HOST_CHECK_SLACK) ** 2
                  else None)
        if reason:
            claim['status'] = 'refund'
            self.record(event='guest_chest_refused', guid=guid, player=player, reason=reason)
            return
        book['opened_by'].add(player)
        claim['status'] = 'removed'
        if player in self.notice_packets:
            self.notice_packets[player].append((DESTROY, struct.pack('<Q', guid)))
        self.record(event='guest_chest_removed', guid=guid, player=player, phantom=not book['native'])
        self.retire_chest(guid)

    def retire_chest(self, guid):
        book = self.chest_book.get(guid)
        if book is not None and book['required'] <= book['opened_by'] and not book['native']:
            del self.chest_book[guid]

    def loot_view(self, player):
        """The host loot as one guest sees it: without chests he opened, plus chests only others opened."""
        view = {}
        for guid, entry in self.chests.items():
            book = self.chest_book.get(guid) if entry[2] == 2 else None
            if book is None or (player not in book['opened_by'] and player in book['required']):
                view[guid] = entry
        for guid, book in self.chest_book.items():
            if not book['native'] and player not in book['opened_by'] and player in book['required']:
                view[guid] = (-1, book['position'], 2, book['value'], 0)
        return view

    def hidden_world_objects(self, recipient):
        """Chests this guest opened stay out of his host-world updates."""
        return {guid for guid, book in self.chest_book.items() if recipient in book['opened_by']}

    def hides_world_destroy(self, guid):
        """A booked chest's native DESTROY (host opened it) never reaches guests: each gets his own on opening."""
        return guid in self.chest_book

    def drop_loot_member(self, number):
        """A player left: his claim ends and no chest waits for him any more."""
        self.claims.pop(number, None)
        for guid, book in list(self.chest_book.items()):
            book['required'].discard(number)
            book['opened_by'].discard(number)
            self.retire_chest(guid)

    def run_started(self):
        super().run_started()
        self.chest_book.clear()  # Next run / new hero: no phantoms from the last run.

    def change_guest_gold(self, client, amount):
        address = client.server + 0x10 + game_field(0x4A8)
        gold = struct.unpack('<I', client.memory(address, 4))[0] + amount
        if gold < 0:
            raise ValueError('Invalid chest payment balance')
        gold = min(gold, MAX_COUNTER)  # u32 saturates.
        client.put(address, struct.pack('<I', gold))
        self.notice_packets[client.number].append((UPDATE, values_packet(SELF, {1176: copper(gold)})))

    def finish_ready(self):
        host = getattr(self, 'number', 1) == 1
        if host and (self.damage_pending or self.effects_pending) and (
                self.router.paused or self.native_states.get(1, (0,))[0] not in (1, 4)):
            # Guest damage is applied only to a running, unpaused host game.
            # At shutdown it can no longer change the run; release the barrier.
            self.record(event='guest_combat_abandoned', damage=dict(self.damage_pending),
                        effects=len(self.effects_pending), paused=self.router.paused,
                        phase=self.native_states.get(1, (0,))[0])
            self.damage_pending.clear()
            self.effects_pending.clear()
        claim = self.chest_claim
        if not host and claim and claim.get('player', 2) == getattr(self, 'number', 2):
            if claim['status'] == 'removed' or (claim['status'] == 'reserved' and
                                                getattr(self, 'peer_finished', False)):
                # A shutdown cannot award the chest (phase 1 only) and a departed
                # host cannot answer a reservation: return the paid gold instead.
                self.record(event='guest_chest_refund_on_shutdown', **claim)
                claim['status'] = 'refund'
            if claim['status'] == 'refund' and getattr(self, 'number', 2) not in self.clients:
                self.record(event='guest_chest_refund_lost', reason='native_exited', **claim)
                self.chest_claim = None
        outbound = bool(self.damage_pending or self.effects_pending)
        if (any(self.powerups_pending[n] for n in self.members) or
                self.area_hits or any(self.areas_by_guest.values()) or self.gold_pending or
                any(self.gold_by_guest.values()) or self.claims or self.pickup_xp_pending or
                getattr(self, 'number', 1) == 1 and outbound):
            return False
        # Guests stop generating attacks before waiting for their final host ACK.
        # Hosts settle accepted damage while still running, then stop themselves.
        ready = super().finish_ready()
        return ready and not outbound


from boss_rewards import BossRewards


class NativeCombatBridge(BossRewards, _NativeCombatBridge):
    """Apply confirmed personal boss rewards before native victory/save."""
