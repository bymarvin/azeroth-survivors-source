"""Guest debuffs (DoTs) on shared enemies, shown to every party member.

Only the host's native world reaches the clients, so a guest's own debuffs on
its enemy mirrors stayed invisible to everyone, the guest included. The guest
reads its native aura fields from the mirror updates it already suppresses and
sends the active debuffs; the host places them into debuff slots its own native
game does not use (from slot 47 downward; the native game fills from 32 up) and
writes sparse VALUES updates. Combat is unchanged: guest ticks still run on the
guest's mirrors and reach the host as damage.

Unit aura fields (vanilla layout, verified on captured host updates: Rend 772
in field 79, its flags in 99, its applications in 121):
UNIT_FIELD_AURA 47..94 (debuff slots 32..47 = fields 79..94), AURAFLAGS 95..100
(4 bits per slot), AURALEVELS 101..112 and AURAAPPLICATIONS 113..124 (1 byte).

State is bounded but never fatal over long sessions (new enemy GUIDs keep
coming): out-of-range and destroyed enemies are forgotten, and at MAX_ENEMIES
the least recently updated entry is dropped (inactive ones first); its debuff
only stops being shown. `dropped` counts this for the bridge's rate-limited log.
Wire input (validate_auras) stays strict.
"""
DEBUFF_SLOTS = range(32, 48)
from play_limits import MAX_ENEMIES

MAX_SPELL = 0xFFFFFFFF


def spell_field(slot):
    return 47 + slot


def packed(slot):
    """(field, shift, mask) of the slot's flags, level and applications."""
    return ((95 + slot // 8, slot % 8 * 4, 0xF), (101 + slot // 4, slot % 4 * 8, 0xFF),
            (113 + slot // 4, slot % 4 * 8, 0xFF))


PACKED = {slot: packed(slot) for slot in DEBUFF_SLOTS}  # Precomputed: overlay runs for every dirty enemy.
AURA_FIELDS = frozenset(spell_field(s) for s in DEBUFF_SLOTS) | frozenset(
    field for s in DEBUFF_SLOTS for field, _, _ in packed(s))


def enemy_guid(guid):
    return guid >> 48 == 0xF130


def slot_auras(fields):
    """Active debuffs {slot: (spell, flags, level, applications)} of one unit's aura fields."""
    result = {}
    for slot in DEBUFF_SLOTS:
        spell = fields.get(spell_field(slot), 0)
        if spell:
            result[slot] = (spell, *((fields.get(f, 0) >> shift) & mask for f, shift, mask in PACKED[slot]))
    return result


def validate_auras(auras):
    if not isinstance(auras, list) or len(auras) > MAX_ENEMIES:
        raise ValueError('Invalid guest aura batch')
    result = {}
    for entry in auras:
        if (not isinstance(entry, list) or len(entry) != 2 or type(entry[0]) is not int or
                not enemy_guid(entry[0]) or not isinstance(entry[1], list) or len(entry[1]) > len(DEBUFF_SLOTS)):
            raise ValueError('Invalid guest aura entry')
        debuffs = []
        for aura in entry[1]:
            if (not isinstance(aura, list) or len(aura) != 4 or any(type(v) is not int for v in aura) or
                    not 0 < aura[0] <= MAX_SPELL or not 0 <= aura[1] <= 0xF or
                    not 0 <= aura[2] <= 0xFF or not 0 <= aura[3] <= 0xFF):
                raise ValueError('Invalid guest aura')
            debuffs.append(tuple(aura))
        result[entry[0]] = debuffs
    return result


class OwnAuras:
    """Guest side: debuffs of this player's native mirrors, sent when they change."""

    def __init__(self, limit=MAX_ENEMIES):
        self.limit = limit
        self.fields = {}      # guid -> aura fields, least recently updated first
        self.inactive = {}    # guids in fields without active debuffs (ordered set, oldest first)
        self.sent = {}
        self.changed = set()
        self.dropped = 0

    def observe(self, block):
        if not enemy_guid(block.guid):
            return
        if block.kind == 4:  # OUT_OF_RANGE: the mirror is gone for this client.
            self.destroy(block.guid)
            return
        if block.kind in (2, 3) and self.forget(block.guid):
            self.changed.add(block.guid)  # A (re)created mirror starts from its create fields.
        if AURA_FIELDS.isdisjoint(block.fields):
            return
        state = self.fields.pop(block.guid, None)
        self.inactive.pop(block.guid, None)  # Re-evaluated by take_changes.
        if state is None:
            if len(self.fields) >= self.limit:
                self.drop_oldest()
            state = {}
        self.fields[block.guid] = state  # Most recently updated last.
        for field, value in block.fields.items():
            if field in AURA_FIELDS:
                state[field] = value
        self.changed.add(block.guid)

    def forget(self, guid):
        self.inactive.pop(guid, None)
        return self.fields.pop(guid, None) is not None

    def drop_oldest(self):
        guid = next(iter(self.inactive or self.fields))
        self.forget(guid)
        self.changed.add(guid)  # An active one is sent as removed; its debuff just stops being shown.
        self.dropped += 1

    def destroy(self, guid):
        if self.forget(guid) or guid in self.sent:
            self.changed.add(guid)

    def take_changes(self, limit=MAX_ENEMIES):
        """Changed enemies [[guid, debuffs]], at most `limit` (validate_auras' batch bound); the rest next time."""
        result = []
        for guid in sorted(self.changed):
            if len(result) >= limit:
                break
            self.changed.discard(guid)
            state = self.fields.get(guid)
            debuffs = [list(a) for _, a in sorted(slot_auras(state or {}).items())]
            if debuffs != self.sent.get(guid, []):
                result.append([guid, debuffs])
                if debuffs:
                    self.sent[guid] = debuffs
                else:
                    self.sent.pop(guid, None)
            if state is not None and not debuffs:
                if any(state.values()):
                    self.inactive[guid] = None  # Keeps packed flags a later spell write may rely on.
                else:
                    self.forget(guid)  # Nothing left to remember.
        return result


class AuraOverlay:
    """Host side: places guest debuffs into free debuff slots of the shared enemies."""

    def __init__(self, limit=MAX_ENEMIES):
        self.limit = limit
        self.dropped = 0
        self.host = {}      # guid -> host aura fields
        self.guests = {}    # guid -> {player: [(spell, flags, level, apps), ...]}, least recently changed first
        self.slots = {}     # guid -> {slot: (player, spell)}, stable assignment
        self.emitted = {}   # guid -> {field: value} as last written by the overlay
        self.dirty = set()

    def host_block(self, block):
        if not enemy_guid(block.guid):
            return
        if block.kind == 4:  # OUT_OF_RANGE: the clients forget the object.
            self.destroy(block.guid)
            return
        if block.kind in (2, 3):
            # A (re)created object starts without our overlay on every client.
            self.host.pop(block.guid, None)
            self.emitted.pop(block.guid, None)
            if block.guid in self.guests:
                self.dirty.add(block.guid)
        if AURA_FIELDS.isdisjoint(block.fields):
            return
        state = self.host.setdefault(block.guid, {})
        emitted = self.emitted.get(block.guid, {})
        for field, value in block.fields.items():
            if field in AURA_FIELDS:
                state[field] = value
                emitted.pop(field, None)  # The host's write replaced ours on every client.
        if block.guid in self.guests:
            self.dirty.add(block.guid)

    def destroy(self, guid):
        for mapping in (self.host, self.guests, self.slots, self.emitted):
            mapping.pop(guid, None)
        self.dirty.discard(guid)

    def guest_auras(self, player, auras):
        for guid, debuffs in auras.items():
            owners = self.guests.pop(guid, {})
            if debuffs:
                owners[player] = debuffs
            else:
                owners.pop(player, None)
            if owners:
                self.guests[guid] = owners  # Most recently changed last.
            self.dirty.add(guid)
        while len(self.guests) > self.limit:
            # Never fatal: the oldest guest debuffs stop being shown (the next overlay clears them).
            oldest = next(iter(self.guests))
            del self.guests[oldest]
            self.dirty.add(oldest)
            self.dropped += 1

    def drop_player(self, player):
        for guid in [g for g, owners in self.guests.items() if player in owners]:
            self.guest_auras(player, {guid: []})

    def updates(self, visible):
        """[(guid, {field: value})] to write for every dirty enemy the clients know."""
        result = []
        for guid in sorted(self.dirty):
            if guid not in visible:
                continue
            fields = self.overlay(guid)
            if fields:
                result.append((guid, fields))
        # Keep waiting only for enemies with guest debuffs; a gone enemy has nothing left to write.
        self.dirty = {g for g in self.dirty if g not in visible and g in self.guests}
        if len(self.host) > 4 * MAX_ENEMIES:  # Only enemies the clients still know.
            for guid in [g for g in self.host if g not in visible]:
                self.destroy(guid)
        return result

    def overlay(self, guid):
        host = self.host.get(guid, {})
        used = {s for s in DEBUFF_SLOTS if host.get(spell_field(s), 0)}
        host_spells = {host[spell_field(s)] for s in used}
        wanted = {}
        for player in sorted(self.guests.get(guid, {})):
            for aura in self.guests[guid][player]:
                if aura[0] not in host_spells and (player, aura[0]) not in wanted:
                    wanted[player, aura[0]] = aura
        previous = self.slots.get(guid, {})
        assigned = {s: key for s, key in previous.items() if s not in used and key in wanted}
        free = [s for s in reversed(DEBUFF_SLOTS) if s not in used and s not in assigned]
        for key in wanted:
            if key not in assigned.values() and free:
                assigned[free.pop(0)] = key
        if assigned:
            self.slots[guid] = assigned
        else:
            self.slots.pop(guid, None)
        desired = {}
        for slot in DEBUFF_SLOTS:
            if slot in used:
                continue
            aura = wanted[assigned[slot]] if slot in assigned else (0, 0, 0, 0)
            desired[spell_field(slot)] = aura[0]
            for (field, shift, mask), value in zip(PACKED[slot], aura[1:]):
                base = desired.get(field, host.get(field, 0))
                desired[field] = base & ~(mask << shift) | (value << shift)
        emitted = self.emitted.setdefault(guid, {})
        # Clients hold our last write, or the host's when it wrote the field since.
        fields = {f: v for f, v in desired.items() if emitted.get(f, host.get(f, 0)) != v}
        emitted.update(fields)
        return fields
