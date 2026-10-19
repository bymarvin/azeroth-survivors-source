"""Authoritative boss notifications with independent native per-character gear rolls.

The wrapper reproduces updated DAMAGE's 540CB18..540CCB8 gear branch. It
calls the game's own class/map loot table and Vec allocator, uses each game's
RNG and difficulty/luck, and leaves persistence to the native result/save path.
"""
import struct

from play_limits import MAX_COUNTER, MAX_NATIVE_OBJECTS, MAX_QUEUE
from updated_layout import reviewed_rva, field, code_fields, release_0843, release_47e4


def guardian_counters():
    """Raw Game offsets of the guardian kill count and pending reward choices (exact releases)."""
    return (0x664, 0x8E4) if release_47e4() else (0x6E8, 0x888)

BOSS_DEATH = 0x540C39A
BOSS_SKIP = 0x540CF75
MAP_TABLE = 0x6636F60
LOOT_TABLE = 0x53D0380
DIFFICULTY = 0x53B1DD0
RESERVE_REWARDS = 0x568DE90
FREE = 0x21D0
REWARD_VECTOR = 0x648
BOSS_COUNT = 0x6DC
RNG = 0x818
GUARDIAN = -1  # Choice entitlement in the existing ordered encounter-reward stream.


def reward_code(base):
    """Windows x64 void(game*, (map_index << 8) | boss_index)."""
    code, labels, fixups = bytearray(), {}, []
    def emit(value):
        code.extend(bytes.fromhex(value))
    def call(rva):
        emit('48 b8'); code.extend(struct.pack('<Q', base + reviewed_rva(rva))); emit('ff d0')
    def branch(op, label):
        emit(op); fixups.append((len(code), label)); code.extend(bytes(4))
    def mark(label):
        labels[label] = len(code)

    # Seven nonvolatile pushes align RSP; 60h includes shadow space and locals.
    emit('53 56 57 41 54 41 55 41 56 41 57 48 83 ec 60')
    emit('0f 29 74 24 40 48 89 ce 49 89 d7')
    emit('ff 86 dc 06 00 00 80 be c9 08 00 00 00')
    branch('0f 85', 'done')  # Native run rule disables gear, but still counts kills.
    emit('48 8d 8e f8 02 00 00'); call(DIFFICULTY)
    emit('0f 28 f0 4d 89 f8 49 c1 e8 08 45 0f b6 cf')
    emit('0f b6 96 4c 03 00 00 48 8d 4c 24 20'); call(LOOT_TABLE)
    emit('48 8b 7c 24 28 4c 8b 74 24 30 4e 8d 34 f7')
    emit('4c 8d a6 48 06 00 00 c7 44 24 50 00 00 80 33')
    mark('loop')
    emit('4c 39 f7'); branch('0f 84', 'free')
    emit('44 8b 2f f3 0f 10 47 04')
    # Exact xoshiro256++ state transition and high-24-bit f32 conversion from
    # native 540CBEE..540CC50, using RSI=game. Never seed/copy host RNG here.
    emit('48 8b 86 30 08 00 00 48 8b 8e 18 08 00 00 48 8b 96 20 08 00 00')
    emit('4c 8d 04 08 49 c1 c0 17 49 01 c8 49 89 d1 49 c1 e1 11')
    emit('4c 8b 96 28 08 00 00 49 31 ca 48 31 d0 4c 31 d2')
    emit('48 89 96 20 08 00 00 48 31 c1 48 89 8e 18 08 00 00')
    emit('4d 31 ca 48 c1 c0 2d 49 c1 e8 28 0f 57 c9 f3 41 0f 2a c8')
    emit('4c 89 96 28 08 00 00 48 89 86 30 08 00 00')
    emit('f3 0f 58 86 d0 02 00 00 f3 0f 59 4c 24 50 f3 0f 59 c6 0f 2e c1')
    branch('0f 86', 'next')  # Native strictly-greater chance test, including NaN.
    emit('48 8b 9e 58 06 00 00 48 3b 9e 48 06 00 00')
    branch('0f 85', 'append')
    emit('4c 89 e1'); call(RESERVE_REWARDS)
    mark('append')
    emit('48 8b 86 50 06 00 00 44 89 2c 98 48 ff c3 48 89 9e 58 06 00 00')
    mark('next')
    emit('48 83 c7 08'); branch('e9', 'loop')
    mark('free')
    emit('48 8b 54 24 20 48 85 d2'); branch('0f 84', 'done')
    emit('48 c1 e2 03 48 8b 4c 24 28 41 b8 04 00 00 00'); call(FREE)
    mark('done')
    emit('0f 28 74 24 40 48 83 c4 60 41 5f 41 5e 41 5d 41 5c 5f 5e 5b c3')
    for offset, label in fixups:
        struct.pack_into('<i', code, offset, labels[label] - offset - 4)
    return code_fields(bytes(code), 'game', {'rsi'})


def native_map(client, game):
    """Return the actual native map index and its boss-array pointer."""
    q = lambda data, at=0: struct.unpack_from('<Q', data, at)[0]
    selected = client.memory(game + field('game', 0x2D8), 16)
    size = q(selected, 8)
    if not 1 <= size <= 32:
        raise ValueError('Invalid native boss map name')
    name = client.memory(q(selected), size)
    stride = field('map', 0xA0)
    name_pointer = field('map', 0)
    name_length = field('map', 8)
    boss_pointer = field('map', 0x40)
    for map_index in range(9):
        row = client.memory(client.base + reviewed_rva(MAP_TABLE) + map_index * stride, boss_pointer + 8)
        if q(row, name_length) == size and client.memory(q(row, name_pointer), size) == name:
            return map_index, q(row, boss_pointer)
    raise ValueError('Unknown native boss map')


def boss_identity(client, definition, game):
    """Require the confirmed native boss to belong to this game's actual map."""
    map_index, bosses = native_map(client, game)
    delta = definition - bosses
    if 0 <= delta < 5 * 0x58 and delta % 0x58 == 0:
        return map_index, delta // 0x58
    raise ValueError('Boss definition does not belong to the selected map')


def reward_items(client):
    game = client.server + 0x10
    capacity, pointer, count = struct.unpack('<QQQ', client.memory(game + field('game', REWARD_VECTOR), 24))
    if not 0 <= count <= capacity <= MAX_NATIVE_OBJECTS:
        raise ValueError('Invalid native gear reward vector')
    return list(struct.unpack('<' + 'I' * count, client.memory(pointer, count * 4))) if count else []


class BossRewards:
    """Mixin ahead of the native bridge. Network peers relay boss_reward_events."""
    def __init__(self, *args, **kwargs):
        from native_probe import BOSS_DEATH as resolved_boss_death
        from updated_layout import UPDATED
        super().__init__(*args, **kwargs)
        self.boss_death_hook = resolved_boss_death
        if UPDATED:
            self.extra_hooks += (self.boss_death_hook,)
        self.boss_reward_events = []
        self.boss_reward_sequence = 0
        self.boss_reward_pending = {n: [] for n in self.guests}
        self.boss_reward_seen = {n: 0 for n in self.guests}
        self.boss_reward_applied = {n: 0 for n in self.guests}
        self.guardian_count_seen = 0

    def publish_reward(self, map_index, boss):
        sequence = self.boss_reward_sequence + 1
        event = dict(sequence=sequence, map=map_index, boss=boss)
        if len(self.boss_reward_events) >= MAX_QUEUE:
            raise ValueError('Unacknowledged encounter reward history exceeds bound')
        self.boss_reward_events.append(event)
        self.boss_reward_sequence = sequence
        for number in self.guests:
            if number in self.clients:
                self.receive_boss_rewards(number, [event])
        self.record(event='authoritative_guardian_reward' if boss == GUARDIAN else 'authoritative_boss_reward', **event)

    def receive_boss_rewards(self, number, events):
        if number not in self.guests or not isinstance(events, list) or len(events) > MAX_QUEUE:
            raise ValueError('Invalid boss reward recipient or event count')
        for event in events:
            if (not isinstance(event, dict) or set(event) != {'sequence', 'map', 'boss'} or
                    any(type(event[k]) is not int for k in event) or
                    not 1 <= event['sequence'] <= 0xFFFFFFFF or
                    not 0 <= event['map'] < 9 or not GUARDIAN <= event['boss'] < 5):
                raise ValueError('Invalid boss reward event')
            sequence = event['sequence']
            if sequence <= self.boss_reward_seen[number]:
                continue
            if sequence != self.boss_reward_seen[number] + 1:
                raise ValueError('Out-of-order boss reward event')
            if len(self.boss_reward_pending[number]) >= MAX_QUEUE:
                raise ValueError('Boss reward queue exceeds bound')
            self.boss_reward_pending[number].append(dict(event))
            self.boss_reward_seen[number] = sequence

    def __call__(self, client, rva, context):
        if rva == self.boss_death_hook:
            if client.number == 1 and release_47e4():
                # 47e4 hook is INC DWORD [RSI+BOSS_COUNT] (Game in RSI, boss definition in RCX).
                game = struct.unpack_from('<Q', context, 168)[0]
                if game != client.server + 0x10:
                    raise ValueError('Boss death hook has no owned game')
                definition = struct.unpack_from('<Q', context, 128)[0]
                map_index, boss = boss_identity(client, definition, game)
                self.publish_reward(map_index, boss)
                counter = game + field('game', BOSS_COUNT)
                client.put(counter, struct.pack('<I', struct.unpack('<I', client.memory(counter, 4))[0] + 1))
                struct.pack_into('<Q', context, 248, client.base + self.boss_death_hook + 6)
            elif client.number == 1:
                rbp = struct.unpack_from('<Q', context, 160)[0]
                game = struct.unpack('<Q', client.memory(rbp + field('damage_frame', 0x178), 8))[0]
                definition = struct.unpack_from('<Q', context, 216 if release_0843() else 240)[0]
                map_index, boss = boss_identity(client, definition, game)
                self.publish_reward(map_index, boss)
                struct.pack_into('<Q', context, 120, game)
                struct.pack_into('<Q', context, 248, client.base + self.boss_death_hook + 7)
            else:
                # Prediction may kill/revive mirrors repeatedly before host death.
                # It must never roll gear or unlock a map speculatively.
                struct.pack_into('<Q', context, 248, client.base + reviewed_rva(BOSS_SKIP))
            return
        return super().__call__(client, rva, context)

    def before_batch(self, client, context):
        if (release_0843() or release_47e4()) and client.number == 1 and client.number in self.ready:
            # DAMAGE increments this native statistic only on a real guardian
            # death, even if a level-up defers the host's jewelry menu.
            count = struct.unpack('<I', client.memory(client.server + 0x10 + guardian_counters()[0], 4))[0]
            if not self.guardian_count_seen <= count <= self.guardian_count_seen + 128:
                raise ValueError('Native guardian count changed unexpectedly')
            if count > self.guardian_count_seen:
                map_index = native_map(client, client.server + 0x10)[0]
                for _ in range(count - self.guardian_count_seen):
                    self.publish_reward(map_index, GUARDIAN)
                self.guardian_count_seen = count
        pending = self.boss_reward_pending.get(client.number, [])
        if client.number in self.ready and pending:
            event = pending[0]
            if native_map(client, client.server + 0x10)[0] != event['map']:
                raise ValueError('Guest map differs from the authoritative boss reward map')
            if event['boss'] == GUARDIAN:
                if not (release_0843() or release_47e4()):
                    raise ValueError('Guardian choice requires the reviewed native layout')
                game = client.server + 0x10
                for offset in guardian_counters():
                    value = struct.unpack('<I', client.memory(game + offset, 4))[0]
                    if value >= MAX_COUNTER:
                        raise ValueError('Native guardian reward counter exceeds bound')
                    client.put(game + offset, struct.pack('<I', value + 1))
                pending.pop(0)
                self.boss_reward_applied[client.number] = event['sequence']
                self.record(event='independent_guardian_reward', player=client.number,
                            sequence=event['sequence'], phase=self.native_states[client.number][0])
                return False  # Entitlement persists in the native pending-choice counter.
            before = reward_items(client)
            def completed():
                after = reward_items(client)
                if after[:len(before)] != before:
                    raise RuntimeError('Native boss roll replaced existing rewards')
                pending.pop(0)
                self.boss_reward_applied[client.number] = event['sequence']
                self.record(event='independent_boss_reward', player=client.number,
                            sequence=event['sequence'], map=event['map'], boss=event['boss'],
                            items=after[len(before):])
            client.call_before(context, None, client.server + 0x10,
                               (event['map'] << 8) | event['boss'],
                               entry_code=reward_code(client.base), after=completed)
            return True
        if ((release_0843() or release_47e4()) and client.number in self.guests and client.number in self.ready and
                not self.draining and not self.router.paused and self.native_states[client.number][0] == 1):
            # Phase 1 only: OFFER_CHOICES sets phase 2 without checking, and over a paused
            # player's open menu RESUME (phase 3 only) can never close it again.
            game = client.server + 0x10
            if struct.unpack('<I', client.memory(game + guardian_counters()[1], 4))[0]:
                from native_probe import OFFER_CHOICES
                client.call_before(context, OFFER_CHOICES, game, 2)
                self.record(event='guardian_choice_offered', player=client.number)
                return True
        return super().before_batch(client, context)

    def finish_ready(self):
        if any(self.boss_reward_pending.get(number) for number in self.clients):
            return False
        return super().finish_ready()
