"""Bounded parser for the native world's object and combat replication packets.

Layouts checked against captured packets and the public Benilla protocol source.
Unknown movement layouts fail closed rather than guessing object boundaries.
"""
import struct
from dataclasses import dataclass

from play_limits import MAX_QUEUE

SELF = 0xFFFFFE
HOST = 0xFF0101
UPDATE, DESTROY, MONSTER = 0xA9, 0xAA, 0xDD
COMBAT = {0x143, 0x144, 0x14A, 0x250, 0x24E, 0x131, 0x132, 0x1F3}
WORLD = {UPDATE, DESTROY, MONSTER} | COMBAT
PROGRESSION = (34, 716, 717)  # UNIT_LEVEL, PLAYER_XP, PLAYER_NEXT_LEVEL_XP
# UNIT_FIELD_DISPLAYID: the native player-field builder (7264 0x544b6d9) sets the
# druid Cat/Dire Bear capstone form model here; there is no form byte or packet.
DISPLAY_ID = 131
# The only models it sets besides the race default (NATIVEDISPLAYID 132 stays the
# race/gender table, 0x544b7f3): Cat 892/8571 (tauren), Dire Bear 2281/2289 (tauren).
FORM_DISPLAYS = frozenset((892, 8571, 2281, 2289))
DYNAMIC_OBJECT = 6  # Ground spells (Rain of Fire): native create RVA 0x5496b20.


def values_packet(guid, fields):
    """Sparse VALUES update; writes only explicitly supplied native fields."""
    if not 0 < guid < 2**64 or not fields or any(
            type(k) is not int or not 0 <= k < 8160 or
            type(v) is not int or not 0 <= v <= 0xFFFFFFFF for k, v in fields.items()):
        raise ValueError('Invalid object values')
    raw = struct.pack('<Q', guid)
    packed = bytes([sum(1 << i for i, v in enumerate(raw) if v)]) + bytes(v for v in raw if v)
    count = max(fields) // 32 + 1
    mask = sum(1 << k for k in fields).to_bytes(count * 4, 'little')
    return (struct.pack('<IBB', 1, 0, 0) + packed + bytes([count]) + mask +
            b''.join(struct.pack('<I', fields[k]) for k in sorted(fields)))


class Reader:
    def __init__(self, body, remap_enabled=True, player_guid=HOST, local_guid=None, guid_map=None):
        self.body = bytearray(body)
        self.pos = 0
        self.remap_enabled = remap_enabled
        self.player_guid = player_guid
        self.local_guid = local_guid
        self.guid_map = guid_map or {}

    def take(self, size):
        if size < 0 or self.pos + size > len(self.body):
            raise ValueError('Truncated native world packet')
        start = self.pos
        self.pos += size
        return self.body[start:self.pos]

    def integer(self, size):
        return int.from_bytes(self.take(size), 'little')

    def guid(self, packed=True, remap=False):
        start = self.pos
        if packed:
            mask = self.integer(1)
            guid = sum(self.integer(1) << (i * 8) for i in range(8) if mask & (1 << i))
        else:
            guid = self.integer(8)
        if remap and self.remap_enabled:
            target = self.guid_map.get(guid, self.player_guid if guid == SELF else
                                       SELF if guid == self.local_guid else guid)
            if target != guid:
                raw = struct.pack('<Q', target)
                replacement = (bytes([sum(1 << i for i, v in enumerate(raw) if v)]) +
                               bytes(v for v in raw if v)) if packed else raw
                self.body[start:self.pos] = replacement
                self.pos = start + len(replacement)
        return guid

    def end(self):
        if self.pos != len(self.body):
            raise ValueError('Unparsed trailing world data')


def movement_block(reader):
    flags = reader.integer(1)
    if flags & 0x20:
        mode = reader.integer(4)
        if mode & 0x400000:
            raise ValueError('Create spline is not reconstructed')
        reader.take(20)  # time, xyz, facing
        if mode & 0x2000000:
            reader.take(24)
        if mode & 0x200000:
            reader.take(4)
        reader.take(4)
        if mode & 0x2000:
            reader.take(16)
        if mode & 0x4000000:
            reader.take(4)
        reader.take(24)  # six speeds
    elif flags & 0x40:
        reader.take(16)
    if flags & 8:
        reader.take(4)
    if flags & 0x10:
        reader.take(4)
    if flags & 4:
        reader.guid(remap=True)
    if flags & 2:
        reader.take(4)


@dataclass
class ObjectBlock:
    kind: int
    guid: int
    object_type: int | None
    data: bytes
    fields: dict


def objects(body, remap=True, guid_map=None):
    r = Reader(body, remap_enabled=remap, guid_map=guid_map)
    count = r.integer(4)
    if count > MAX_QUEUE or r.integer(1) != 0:
        raise ValueError('Unsupported world object count/transport')
    result = []
    for _ in range(count):
        start = r.pos
        kind = r.integer(1)
        if kind in (4, 5):
            size = r.integer(4)
            if size > MAX_QUEUE or len(result) + size > MAX_QUEUE:
                raise ValueError('World GUID list exceeds bound')
            for _ in range(size):
                begin = r.pos
                guid = r.guid(remap=True)
                data = bytes([kind]) + struct.pack('<I', 1) + bytes(r.body[begin:r.pos])
                result.append(ObjectBlock(kind, guid, None, data, {}))
            continue
        if kind not in (0, 1, 2, 3):
            raise ValueError(f'Unreconstructed update type {kind}')
        guid = r.guid(remap=True)
        object_type = r.integer(1) if kind in (2, 3) else None
        if kind in (1, 2, 3):
            movement_block(r)
        fields = {}
        if kind != 1:
            mask = r.integer(r.integer(1) * 4)
            offsets = {}
            for field in range(mask.bit_length()):
                if mask & (1 << field):
                    offsets[field] = r.pos
                    fields[field] = r.integer(4)
            # Object GUID and the standard unit GUID-valued fields only.
            for field in (0, 6, 8, 10, 12, 14, 16, 18, 20):
                if remap and field in fields:
                    original = fields[field] | (fields.get(field + 1, 0) << 32)
                    target = (guid_map or {}).get(original, HOST if original == SELF else original)
                    if target != original:
                        if field + 1 not in offsets and target >> 32:
                            raise ValueError('Remapped GUID needs its high field')
                        struct.pack_into('<I', r.body, offsets[field], target & 0xFFFFFFFF)
                        if field + 1 in offsets:
                            struct.pack_into('<I', r.body, offsets[field + 1], target >> 32)
        result.append(ObjectBlock(kind, guid, object_type, bytes(r.body[start:r.pos]), fields))
    r.end()
    return result


def dynamic_object(block, native=True):
    """True for a ground-spell create; malformed type-6 creates fail closed.

    The native writer uses GUID 0xF100000000000000 | Game+0x894 counter,
    OBJECT_FIELD_TYPE 0x41 and caster fields 6/7. The two counter bits
    22..23 are reserved for the guest owner, as with player summons, so a
    native counter must stay below them; relayed copies may carry them.
    """
    if block.kind not in (2, 3) or block.object_type != DYNAMIC_OBJECT:
        return False
    reserved = 0x0000FFFFFFC00000 if native else 0x0000FFFFFF000000
    if (block.guid >> 48 != 0xF100 or block.guid & reserved or
            block.fields.get(0, 0) | (block.fields.get(1, 0) << 32) != block.guid or
            block.fields.get(2) != 0x41 or 6 not in block.fields or 7 not in block.fields):
        raise ValueError('Native dynamic object exceeds reconstructed layout')
    return True


def dynamic_caster(block):
    return block.fields[6] | (block.fields[7] << 32)


def object_packet(blocks):
    return struct.pack('<IB', len(blocks), 0) + b''.join(b.data for b in blocks)


def downed_player_values(body):
    """Level-up healing must not make a still-downed avatar appear alive."""
    blocks = objects(body, remap=False)
    changed = False
    for index, block in enumerate(blocks):
        if block.guid == SELF and block.kind == 0 and block.fields.get(22, 0) != 0:
            fields = dict(block.fields)
            fields[22] = 0
            blocks[index] = objects(values_packet(SELF, fields), remap=False)[0]
            changed = True
    return object_packet(blocks) if changed else body


def remap_combat(opcode, body, player_guid=HOST, local_guid=0xFF0102, guid_map=None):
    """Rewrite actual GUID fields, never search-and-replace arbitrary bytes."""
    r = Reader(body, player_guid=player_guid, local_guid=local_guid, guid_map=guid_map)
    if opcode in (DESTROY, 0x1F3):
        r.guid(False, True)
        r.take(len(r.body) - r.pos)
    elif opcode == MONSTER:
        r.guid(remap=True)
        r.take(16)
        kind = r.integer(1)
        if kind == 3:
            r.guid(False, True)
        r.take(len(r.body) - r.pos)
    elif opcode == 0x143:
        r.guid(False, True)
        r.guid(False, True)
    elif opcode in (0x144, 0x250, 0x24E, 0x14A):
        if opcode == 0x14A:
            r.take(4)  # hit flags, then packed attacker and target
        r.guid(remap=True)
        r.guid(remap=True)
        r.take(len(r.body) - r.pos)
    elif opcode in (0x131, 0x132):
        r.guid(remap=True)
        r.guid(remap=True)
        r.take(4)
        flags = r.integer(2)
        if opcode == 0x131:
            r.take(4)
        else:
            for _ in range(r.integer(1)):
                r.guid(False, True)
            for _ in range(r.integer(1)):
                r.guid(False, True)
                if r.integer(1) == 11:  # reflect's outcome byte
                    r.take(1)
        mask = r.integer(2)
        if mask & (2 | 0x800 | 0x200 | 0x8000):
            r.guid(remap=True)
        if mask & (0x10 | 0x1000):
            r.guid(remap=True)
        if mask & 0x20:
            r.take(12)
        if mask & 0x40:
            r.take(12)
        if mask & 0x2000:
            while r.integer(1):
                pass
        if flags & 0x20:
            r.take(8)
    else:
        raise ValueError('Unreconstructed combat opcode')
    r.end()
    return bytes(r.body)


def validate_movement_packet(body, members, owner=None):
    from sessions import decode_ground_movement
    reader = Reader(body, remap_enabled=False)
    number = reader.guid() - 0xFF0100
    if number not in members or owner is not None and number != owner:
        raise ValueError('Movement packet belongs to another player')
    decode_ground_movement(body[reader.pos:])
    return number
