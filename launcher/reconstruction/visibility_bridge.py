"""Two real EXEs sharing player poses, optionally the host's world and combat.

Local lab adapter only. --demo drives remote avatars through a synthetic path
to test rendering without taking over keyboard input. Default relays real input.
--shared-world uses the host world and native guest combat adapter.
"""
import argparse
import json
import hashlib
import math
import os
import struct
import time
from collections import deque

from native_probe import ROOT, TICK, SERIALIZE, WRITE, PAUSE, RESUME, START, AWARD_XP, CHOOSE, DAMAGE, MOVE, HURT, DEFEAT_UI, UI_COMMAND, allocate, checked, q, run
from native_probe import CONNECTIONS, game_field
from play_limits import (MAX_CLASS_ENTRIES, MAX_COUNTER, MAX_ENEMIES, MAX_ENEMY_HP, MAX_NATIVE_OBJECTS, MAX_QUEUE,
                         MAX_WORLD_BACKLOG,
                         MAX_WORLD_OBJECTS, u32_part)
from play_limits import MAX_HIT_DAMAGE  # noqa: F401 (re-exported: queue folding and tests)
from updated_layout import (UPDATED, rva as relocated, phase_gate, reviewed_rva,
                            reviewed_bytes, expected_bytes, branch as native_branch, reviewed_branch,
                            field, code_fields, release_0843, release_47e4, release_7264, enemy_layout, family,
                            result_evaluation)
from sessions import ClientFrames, HeaderCipher, HEARTBEAT, LOGIN, MOVEMENT_OPCODES, Pose, ProtocolError, SessionRouter, decode_ground_movement
from world_packets import WORLD, UPDATE, DESTROY, MONSTER, objects, object_packet, remap_combat, SELF, PROGRESSION, values_packet, Reader, dynamic_object, DISPLAY_ID, HOST, FORM_DISPLAYS


HOST_AVATAR = bytes((0x07, 0x01, 0x01, 0xFF))  # Packed GUID 0xFF0101.


def native_progress_state(client, initialized):
    # Login serializes before Game construction finishes. MOVE is the existing
    # ownership/readiness barrier; loading peers publish no uninitialized data.
    if not initialized:
        return (0, 1, 0, 0)
    game = client.server + 0x10
    level, xp = struct.unpack('<II', client.memory(game + game_field(0x498), 8))
    phase = client.memory(game + game_field(0x8BF), 1)[0]
    pending = struct.unpack('<I', client.memory(game + game_field(0x860), 4))[0]
    return phase, level, xp, pending


def packed_guid(guid):
    raw = struct.pack('<Q', guid)
    return bytes([sum(1 << i for i, value in enumerate(raw) if value)]) + bytes(v for v in raw if v)


def absolute_jump(address):
    return b'\xff\x25\0\0\0\0' + struct.pack('<Q', address)


def dispatch_guard_code(base, contract):
    """Preserve a valid native dispatch; trap before an out-of-domain lookup."""
    kind = contract['kind']
    expected = bytes.fromhex(contract['expected'])
    if kind == 'cast_tag' and release_47e4():
        # 47e4: table register R8 (lea r8,[rip]); see coop-lab/port-re/decisions.py GUARDS.
        if (contract['maximum'] != 4 or len(expected) != 16
                or expected[:5] != bytes.fromhex('89d24c8d05')
                or expected[9:] != bytes.fromhex('496314904c01c2')
                or contract['rva']+9+struct.unpack_from('<i',expected,5)[0] != contract['table_rva']
                or contract['continuation_rva'] != contract['rva']+16):
            raise ValueError('Unrecognized guarded native cast dispatch')
        body = bytes.fromhex('89d2 49b8') + struct.pack('<Q', base + contract['table_rva'])
        body += expected[9:] + absolute_jump(base + contract['continuation_rva'])
        code = bytes.fromhex('83fa04 0f87') + struct.pack('<i', len(body)) + body
    elif kind == 'loot_tag' and release_47e4():
        # 47e4: index EBX, table R13 (12-byte site).
        if contract['maximum'] != 6 or expected != bytes.fromhex('89d8 4963448500 4c01e8 ffe0'):
            raise ValueError('Unrecognized guarded native loot dispatch')
        table_check = b'\x48\xb8' + struct.pack('<Q', base+contract['table_rva']) + bytes.fromhex('4939c5')
        code = bytes.fromhex('83fb06 0f87') + struct.pack('<i', len(table_check)+6+len(expected))
        code += table_check + bytes.fromhex('0f85') + struct.pack('<i', len(expected)) + expected
    elif kind == 'cast_tag':
        if (contract['maximum'] != 4 or len(expected) != 16
                or expected[:5] != bytes.fromhex('89d24c8d0d' if release_0843() else '89d24c8d15')
                or expected[9:] != bytes.fromhex('496314914c01ca' if release_0843() else '496314924c01d2')
                or contract['rva']+9+struct.unpack_from('<i',expected,5)[0] != contract['table_rva']
                or contract['continuation_rva'] != contract['rva']+16):
            raise ValueError('Unrecognized guarded native cast dispatch')
        table = base + contract['table_rva']
        body = bytes.fromhex('89d2 49b9' if release_0843() else '89d2 49ba') + struct.pack('<Q', table)
        body += expected[9:] + absolute_jump(base + contract['continuation_rva'])
        # ADD RDX,R10 overwrites the guard comparison flags on the valid path.
        code = bytes.fromhex('83fa04 0f87') + struct.pack('<i', len(body)) + body
    elif kind == 'loot_tag':
        if contract['maximum'] != 6 or expected != bytes.fromhex('89f8 49630484 4c01e0 ffe0' if release_0843() else '89f8 4963448500 4c01e8 ffe0'):
            raise ValueError('Unrecognized guarded native loot dispatch')
        table_check = b'\x48\xb8' + struct.pack('<Q', base+contract['table_rva']) + bytes.fromhex('4939c4' if release_0843() else '4939c5')
        # Original MOV EAX,EDI makes incoming RAX dead at this patch boundary.
        code = bytes.fromhex('83ff06 0f87') + struct.pack('<i', len(table_check)+6+len(expected))
        code += table_check + bytes.fromhex('0f85') + struct.pack('<i', len(expected)) + expected
    else:
        raise ValueError('Unknown native dispatch guard kind')
    return code + b'\x0f\x0b'  # A debugger-visible fatal invariant failure.


def install_dispatch_guards(client):
    """Install only hash-bound contracts admitted by the native profile owner."""
    contracts = getattr(client, 'dispatch_guard_contracts', ())
    installed = []
    for contract in contracts:
        if contract.get('mandatory_runtime_guard') is not True:
            raise ValueError('Native dispatch contract lacks mandatory guard')
        expected = bytes.fromhex(contract['expected'])
        site = client.base + contract['rva']
        if client.memory(site, len(expected)) != expected:
            raise ValueError('Native dispatch bytes changed before guard installation')
        code = dispatch_guard_code(client.base, contract)
        entry = client.executable_buffer(code, near=site) if len(expected) < 12 else client.executable_buffer(code)
        if contract['kind'] == 'cast_tag':
            replacement = absolute_jump(entry) + b'\x90' * (len(expected)-14)
        elif len(expected) < 12:
            replacement = b'\xe9' + struct.pack('<i', entry - site - 5) + b'\x90' * (len(expected) - 5)
        else:
            replacement = b'\x48\xb8' + struct.pack('<Q', entry) + b'\xff\xe0'
        client.patch(site, replacement)
        installed.append(dict(kind=contract['kind'], site=site, trap=entry+len(code)-2))
    client.dispatch_guard_traps = {item['trap']: item['kind'] for item in installed}
    return installed


def system_message(text):
    encoded = text.encode('utf-8')
    if len(encoded) > 4096 or b'\0' in encoded:
        raise ValueError('Invalid co-op notification')
    return 0x96, b'\x0a' + bytes(12) + struct.pack('<I', len(encoded) + 1) + encoded + b'\0\0'


def replace_downed_ui(client, pointer, count, replacement=b'{"type":"unpaused"}'):
    if count > MAX_QUEUE:
        raise ValueError('Native UI batch exceeds bound')
    replaced = 0
    for i in range(count):
        capacity, address, length = struct.unpack('<QQQ', client.memory(pointer + i * 24, 24))
        if length > capacity or length > 1048576:
            raise ValueError('Invalid native UI string')
        body = client.memory(address, length)
        if b'defeat' in body and json.loads(body).get('type') == 'defeat':
            if replacement is not None:
                if len(replacement) > capacity:
                    raise ValueError('Native UI allocation too small')
                client.put(address, replacement)
                client.put(pointer + i * 24 + 16, struct.pack('<Q', len(replacement)))
            replaced += 1
    return replaced


def game_frame_code(code):
    return code_fields(code, 'game_update_frame', {'rbp'})


def world_containers_code():
    if release_47e4():
        # Slots read first after the skipped region (liveness, validated on 0.84.3):
        # &Game.vec(0x5E8)->rbp+0x320, &Game.vec(0x840)->rbp+0x288, &Game.vec(0x818)->rbp+0x48 (47e4; per build in FAMILY).
        return b''.join(b'\x49\x8d\x85' + struct.pack('<I', field('game', member)) +
                        b'\x48\x89\x85' + struct.pack('<I', slot)
                        for member, slot in zip((0x5E8, 0x840, 0x818), family('world_slots')))
    fields = (((0x5E8, 0x3C8), (0x5A0, 0x120), (0x840, 0x188), (0x588, 0x2E8))
              if UPDATED else ((0x5D8, 0x3A0), (0x590, 0x100), (0x830, 0x160), (0x578, 0x168)))
    return b''.join((bytes.fromhex('498d8424') if release_0843() else b'\x49\x8d\x85') + struct.pack('<I', field('game', member) if UPDATED else member) +
                    b'\x48\x89\x85' + struct.pack('<I', field('game_update_frame', slot) if UPDATED else slot)
                    for member, slot in fields)


def native_constants_code(base):
    """Register constants normally loaded by the skipped native region."""
    if release_47e4():
        # 47e4 loads the same constant into XMM13 and zeroes XMM15 (0x547ad0e / 0x547acf8).
        return (b'\x48\xb8' + struct.pack('<Q', base + relocated(0x5809A24)) + bytes.fromhex('f3440f1028') +
                bytes.fromhex('450f57ff'))
    return b'\x48\xb8' + struct.pack('<Q', base + relocated(0x5809A24)) + bytes.fromhex('f3440f1038')


def downed_world_code(base, enabled):
    """Build-specific tick continuation: dead host skips only its player actions."""
    hud = absolute_jump(base + relocated(0x53EA3A8))
    clock = bytes.fromhex('f3410f10bd6c080000 f30f58bd40030000 f3410f11bd6c080000' if UPDATED
                         else 'f3410f10bd5c080000 f30f58bdc8020000 f3410f11bd5c080000')
    if release_0843():
        clock = bytes.fromhex('f3410f10bc246c080000 f30f58bd40030000 f3410f11bc246c080000')
    if release_47e4():
        # dt stays in XMM6 for the whole update (movaps xmm6,xmm1 at entry); no frame slot.
        clock = code_fields(bytes.fromhex('f3410f10bd6c080000 f30f58fe f3410f11bd6c080000'), 'game', {'r13'})
    else:
        clock = game_frame_code(code_fields(clock, 'game', {'r12'} if release_0843() else {'r13'}))
    # Normal path is selected from the original CMP phase,1 flags.
    normal = clock[:10 if release_0843() else 9] + absolute_jump(base + relocated(0x53DCA04))
    constant = native_constants_code(base)
    # These four borrowed container addresses normally come from player work.
    containers = world_containers_code()
    dead = (b'\x3c\x04\x74\x0e' + hud + b'\x48\xb8' + struct.pack('<Q', enabled) +
            b'\x80\x38\x01\x74\x0e' + hud + clock + constant + containers + absolute_jump(base + relocated(0x53E1254)))
    return b'\x0f\x84' + struct.pack('<i', len(dead)) + dead + normal


def downed_hazards_code(base):
    """Continue projectile/ground expiry while down, then skip owner-only totems."""
    original = bytes.fromhex('498d8588050000 488985e8020000' if UPDATED
                            else '498d8578050000 48898568010000')
    if release_47e4():
        # 16 position-independent bytes (movss xmm8,[r13+G]; lea rax,[r13+G]) from the profile.
        original = expected_bytes(0x53E1B4E, bytes.fromhex('498d8588050000 488985e8020000'))
    else:
        if release_0843():
            original = bytes.fromhex('498d842488050000 488985e8020000')
        original = game_frame_code(code_fields(original, 'game', {'r12'} if release_0843() else {'r13'}))
    normal = original + absolute_jump(base + relocated(0x53E1B5C))
    constant = native_constants_code(base)
    phase_test = code_fields(bytes.fromhex('4180bdcf08000004' if UPDATED else '4180bdbf08000004'), 'game', {'r13'})
    if release_0843():
        phase_test = code_fields(bytes.fromhex('4180bc24cf08000004'), 'game', {'r12'})
    return (phase_test + b'\x0f\x84' + struct.pack('<i', len(normal)) + normal +
            world_containers_code() + constant + absolute_jump(base + relocated(0x53E2C7B)))


def rbp_operand(prefix, reg, disp):
    """prefix + ModRM [rbp+disp] (disp8 when it fits, else disp32) for register field reg."""
    if -128 <= disp < 128:
        return prefix + bytes([0x45 | reg << 3]) + struct.pack('<b', disp)
    return prefix + bytes([0x85 | reg << 3]) + struct.pack('<i', disp)


def recycle_distance_original(position, scratch):
    """0.92 recycle filter test without its JA: movsd S,[r13]; subps P,S; mulps P,P; movshdup S,P; addss S,P;
    ucomiss S,xmm7 (P = enemy XY register, S = scratch)."""
    def rr(dst, src):
        return bytes([0xC0 | dst << 3 | src])
    return (bytes.fromhex('f2410f10') + bytes([0x45 | scratch << 3]) + b'\x00' + b'\x0f\x5c' + rr(position, scratch) +
            b'\x0f\x59' + rr(position, position) + b'\xf3\x0f\x16' + rr(scratch, position) +
            b'\xf3\x0f\x58' + rr(scratch, position) + b'\x0f\x2e' + rr(scratch, 7))


def recycle_distance_code(table, guests, position, scratch, temp, select, resume):
    """Squared XY distance from the enemy to the nearest of host ([r13]) and living guests; JA select else resume.

    The enemy XY register stays intact; scratch and temp are overwritten (both dead in the native code).
    """
    def rr(dst, src):
        return bytes([0xC0 | dst << 3 | src])
    def distance_into(dst):  # temp = (P - temp)^2 summed into lane 0
        return (b'\x0f\x5c' + rr(temp, position) + b'\x0f\x59' + rr(temp, temp) + b'\xf2\x0f\x7c' + rr(temp, temp) +
                (b'\x0f\x28' + rr(dst, temp) if dst == scratch else b'\xf3\x0f\x5d' + rr(scratch, temp)))
    code = bytearray(bytes.fromhex('f2410f10') + bytes([0x45 | temp << 3]) + b'\x00')  # movsd T,[r13] (host XY)
    code += distance_into(scratch)
    code += b'\x50\x48\xb8' + struct.pack('<Q', table)  # push rax; mov rax,table
    for index in range(guests):
        step = bytes([0xF2, 0x0F, 0x10, 0x40 | temp << 3, index * 16]) + distance_into(None)
        code += bytes([0x80, 0x78, index * 16 + 12, 0x01, 0x75, len(step)]) + step  # alive flag == 1
    code += b'\x58\x0f\x2e' + rr(scratch, 7)  # pop rax; ucomiss S,xmm7
    code += b'\x76\x0e' + absolute_jump(select) + absolute_jump(resume)
    return bytes(code)


def melee_packet(attacker, target, damage):
    """Exact noncritical 0x14a layout from native writer RVA 0x5443aa0."""
    damage = min(max(0, damage), 0xFFFFFFFF)  # A u32 field: saturates instead of ending the run.
    return (struct.pack('<I', 2) + packed_guid(attacker) + packed_guid(target) +
            struct.pack('<IBIf7I', damage, 1, 0, float(damage), damage, 0, 0, 1, 0, 0, 0))


PURSUIT_STICK = 2.0   # Units: an enemy keeps its player until another living one is this much nearer (sticky).
PURSUIT_TABLE = 4096  # Bytes of the sticky target table, one per enemy record (the guard allows at most 3000).


def pursuit_code(base, guest, guests=1, *, game=None, guard=None, sticky=None, stick=PURSUIT_STICK):
    """Choose the nearer living player at the native enemy's interpolated pose.

    Only the enemy loop's borrowed target coordinates change; player state stays
    untouched. XY distance matches the native pursuit calculation.
    sticky (0.0.22 candidate, COOP_PURSUIT_STICKY): a table of one byte per enemy record (index from the guard:
    0 host, 1 + n guest slot n, 0xFF none). An enemy keeps the player it chased last while he lives, until the
    nearest living player is more than `stick` units nearer; two players side by side otherwise flip its target
    (and the host-only path field) from frame to frame.
    """
    if sticky is not None and (guard is None or not UPDATED or not release_7264() or not 0 < guests < 0xFF):
        raise ValueError('Sticky pursuit needs the guarded 0.95 enemy loop')
    frame_size = 0x40 if sticky is not None else 0x30  # [rsp+0x30] enemy index, [rsp+0x38] chosen player.
    code = bytearray(bytes.fromhex('52 9c 50 4883ec') + bytes([frame_size]) +
                     bytes.fromhex('0f110424 0f114c2410 0f11542420'))
    branches = []
    def branch(opcode, label):
        code.extend(bytes.fromhex(opcode))
        branches.append((len(code), label))
        code.extend(bytes(4))
    if (game is None) != (guard is None):
        raise ValueError('Pursuit guard requires both Game and owned status storage')
    v47 = release_47e4()
    # 47e4: the enemy loop lives in its own function 0x549e650 with its own frame;
    # enemy cursor R15, interpolated enemy XY XMM12, time XMM6, +0.0 threshold XMM8.
    # 7264 (0x5482308): cursor R12, enemy XY XMM15; time XMM6 and threshold XMM8 unchanged.
    v7264 = release_7264()
    cursor_cmp_rax, cursor_cmp_rdx, cursor_to_rdx = (('4939c4', '4939d4', '4c89e2') if v7264 else
                                                      ('4939c7', '4939d7', '4c89fa') if v47 else ('4839c6', '4839d6', '4889f2'))
    xy_to_xmm1, xy_to_xmm0, xy_sub_xmm1 = (('410f28cf', '410f28c7', '410f5ccf') if v7264 or not v47 else
                                           ('410f28cc', '410f28c4', '410f5ccc'))
    frame_code = (lambda c: code_fields(c, 'enemy_frame', {'rbp'})) if v47 else game_frame_code
    stride = enemy_layout()[0]
    if guard is not None:
        # Validate ownership before reading Game, then validate the native Enemy
        # cursor without dereferencing it. Failure preserves the native path and
        # is reported on the next batch, before any further adapter mutation.
        code.extend(frame_code(bytes.fromhex('488b85e0030000' if UPDATED else '488b85d0030000')))
        code.extend(b'\x48\xba' + struct.pack('<Q', game) + bytes.fromhex('4839d0'))
        branch('0f85', 'guard_failed')
        code.extend(bytes.fromhex('660f7ef2' if v47 else '660f7efa') + b'\x3b\x90' + struct.pack('<I', game_field(0x85C)))
        branch('0f85', 'guard_failed')
        code.extend(bytes.fromhex('81e20000807f81fa0000807f'))
        branch('0f84', 'guard_failed')
        code.extend(bytes.fromhex('66440f7ec285d2' if v47 else '66440f7eea85d2' if release_0843() else '66440f7ef285d2'))  # Native interpolation threshold is +0.0 in XMM14.
        branch('0f85', 'guard_failed')
        pointer = game_field(0x568)
        code.extend(b'\x48\x8b\x90' + struct.pack('<I', pointer + 8) + bytes.fromhex('4881fab80b0000'))
        branch('0f87', 'guard_failed')
        code.extend(bytes.fromhex('4869d2') + struct.pack('<I', stride) + b'\x48\x8b\x80' + struct.pack('<I', pointer) +
                    bytes.fromhex(cursor_cmp_rax))
        branch('0f82', 'guard_failed')
        code.extend(bytes.fromhex('4801c2'))
        branch('0f82', 'guard_failed')
        code.extend(bytes.fromhex(cursor_cmp_rdx))
        branch('0f83', 'guard_failed')
        code.extend(bytes.fromhex(cursor_to_rdx + '4829c24889d031d251b9') + struct.pack('<I', stride) +
                    bytes.fromhex('48f7f1594885d2'))
        branch('0f85', 'guard_failed')
        if sticky is not None:
            code.extend(bytes.fromhex('4889442430'))  # mov [rsp+0x30], rax: the enemy's index.
        # Reject NaN/infinity in either native interpolated XY lane.
        code.extend(b'\x48\xb8' + struct.pack('<Q', 0x7F8000007F800000) +
                    bytes.fromhex('66480f6ec0' + xy_to_xmm1 + '0f54c8660f76c80f50d1f6c203'))
        branch('0f85', 'guard_failed')
        code.extend(b'\x48\xb8' + struct.pack('<Q', guard) + bytes.fromhex('48ff4008'))
    # Reset the loop's target to the host before selecting for this enemy.
    code.extend(frame_code(code_fields(bytes.fromhex('488b85e0030000 f20f108098040000 0f2985d0000000 f30f1080a0040000 f30f1185e4020000' if UPDATED
                             else '488b85d0030000 f20f108088040000 0f2985d0000000 f30f108090040000 f30f114578'), 'game', {'rax'})))
    code.extend(frame_code(bytes.fromhex('488b95e0030000' if UPDATED else '488b95d0030000')))
    code.extend(code_fields(bytes.fromhex('80bacf08000004' if UPDATED else '80babf08000004'), 'game', {'rdx'}))
    # Dead host contributes infinite distance; all living guests are compared.
    code.extend(frame_code(bytes.fromhex('7516 48b80000807f0000807f 66480f6ec0 0f2985d0000000')))
    if sticky is not None:
        code.extend(bytes.fromhex('c644243800'))  # The nearest so far: the host.
    labels = {}
    for index in range(guests):
        skip = f'next_{index}'
        code.extend(b'\x48\xb8' + struct.pack('<Q', guest + index * 16))
        code.extend(bytes.fromhex('80780c01'))
        branch('0f85', skip)
        code.extend(frame_code(bytes.fromhex(xy_to_xmm0 + '0f5c85d0000000 0f59c0 f30f16d0 f30f58c2')))
        code.extend(bytes.fromhex('f20f1008' + xy_sub_xmm1 + '0f59c9 f30f16d1 f30f58ca 0f2fc1'))
        branch('0f86', skip)
        code.extend(frame_code(bytes.fromhex('f20f1000 0f2985d0000000 f30f104008 f30f1185e4020000' if UPDATED
                                 else 'f20f1000 0f2985d0000000 f30f104008 f30f114578')))
        if sticky is not None:
            code.extend(bytes.fromhex('c6442438') + bytes([index + 1]))
        labels[skip] = len(code)
    if sticky is not None:
        guest_set = frame_code(bytes.fromhex('f20f1000 0f2985d0000000 f30f104008 f30f1185e4020000'))
        host_set = frame_code(code_fields(bytes.fromhex(
            '488b85e0030000 f20f108098040000 0f2985d0000000 f30f1080a0040000 f30f1185e4020000'), 'game', {'rax'}))
        # prev = table[index]; the same as the nearest, or none yet: keep the nearest.
        code.extend(bytes.fromhex('488b442430 48ba') + struct.pack('<Q', sticky) + bytes.fromhex('0fb60402 3a442438'))
        branch('0f84', 'sticky_store')
        code.extend(bytes.fromhex('3cff'))
        branch('0f84', 'sticky_store')
        # XMM0 = distance to the nearest (the target the loop chose).
        code.extend(frame_code(bytes.fromhex(xy_to_xmm0 + '0f5c85d0000000 0f59c0 f30f16d0 f30f58c2')) +
                    bytes.fromhex('f30f51c0 84c0'))
        branch('0f85', 'sticky_prev_guest')
        # The host chased before: alive? (state 4 = dead) XMM1 = his XY.
        code.extend(frame_code(bytes.fromhex('488b95e0030000')) + code_fields(bytes.fromhex('80bacf08000004'), 'game', {'rdx'}))
        branch('0f84', 'sticky_store')
        code.extend(code_fields(bytes.fromhex('f20f108a98040000'), 'game', {'rdx'}))
        branch('e9', 'sticky_have_prev')
        labels['sticky_prev_guest'] = len(code)
        # A guest slot chased before: in range and alive? XMM1 = his XY.
        code.extend(bytes.fromhex('3c') + bytes([guests]))
        branch('0f87', 'sticky_store')
        code.extend(bytes.fromhex('0fb6c0 48ba') + struct.pack('<Q', guest - 16) + bytes.fromhex('48c1e004 4801c2 48c1e804 807a0c01'))
        branch('0f85', 'sticky_store')
        code.extend(bytes.fromhex('f20f100a'))
        labels['sticky_have_prev'] = len(code)
        # XMM1 = distance to him; switch only when the nearest is more than `stick` nearer.
        code.extend(bytes.fromhex(xy_sub_xmm1 + '0f59c9 f30f16d1 f30f58ca f30f51c9 ba') + struct.pack('<f', stick) +
                    bytes.fromhex('660f6ed2 f30f58c2 0f2fc8'))
        branch('0f87', 'sticky_store')
        code.extend(bytes.fromhex('88442438 84c0'))  # He stays the target.
        branch('0f85', 'sticky_set_guest')
        code.extend(host_set)
        branch('e9', 'sticky_store')
        labels['sticky_set_guest'] = len(code)
        code.extend(b'\x48\xba' + struct.pack('<Q', guest - 16) + bytes.fromhex('48c1e004 4801c2 4889d0') + guest_set)
        labels['sticky_store'] = len(code)
        code.extend(bytes.fromhex('488b442430 48ba') + struct.pack('<Q', sticky) + bytes.fromhex('4801c2 8a442438 8802'))
    if guard is not None:
        branch('e9', 'done')
        labels['guard_failed'] = len(code)
        code.extend(b'\x48\xb8' + struct.pack('<Q', guard) + bytes.fromhex('48c70001000000'))
    labels['done'] = len(code)
    code.extend(bytes.fromhex('0f100424 0f104c2410 0f10542420 4883c4') + bytes([frame_size]) + bytes.fromhex('58 9d 5a'))
    original = (expected_bytes(0x53E370A, bytes.fromhex('450f28cf 440f5c8dd0000000 f3450f16e9'))
                if release_0843() or v47 else game_frame_code(bytes.fromhex('450f28cf 440f5c8dd0000000 f3450f16e9')))
    code.extend(original + absolute_jump(base + relocated(0x53E371B)))
    for offset, label in branches:
        struct.pack_into('<i', code, offset, labels[label] - offset - 4)
    return bytes(code)


def validate_live_game(client, context, register_offset, *, enemy_offset=None, enemy_frame=False):
    """Check actual native owners before interpreting interior hook operands.

    enemy_frame: the hook sits in the separate enemy function of build family 47e4.
    """
    game = client.server + 0x10
    frame = q(context, 160)
    slot = (field('enemy_frame', 0x3E0) if enemy_frame and release_47e4() else
            field('game_update_frame', 0x3E0) if UPDATED else 0x3D0)
    if q(context, register_offset) != game or q(client.memory(frame + slot, 8)) != game:
        raise ValueError('Interior native Game ownership changed')
    if enemy_offset is not None:
        pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x568), 16))
        enemy = q(context, enemy_offset)
        stride = enemy_layout()[0]
        if not 0 < count <= MAX_ENEMIES or not pointer <= enemy < pointer + count * stride or (enemy-pointer) % stride:
            raise ValueError('Interior native Enemy ownership changed')
    return game


def retarget_monster(body, host, guest, host_alive, guest_alive, guest_guid=0xFF0102):
    """Keep spline facing-target GUID consistent with native two-player pursuit."""
    reader = Reader(body)
    reader.guid()
    x, y, _, _ = struct.unpack('<3fI', reader.take(16))
    if reader.integer(1) != 3 or not guest_alive:
        return body
    offset = reader.pos
    if reader.guid(False) != SELF:
        return body
    if not host_alive or (x - guest.x) ** 2 + (y - guest.y) ** 2 < (x - host.x) ** 2 + (y - host.y) ** 2:
        reader.body[offset:offset + 8] = struct.pack('<Q', guest_guid)
    return bytes(reader.body)


def guest_damage_patches():
    """Apply guest damage without the host's conditional bonuses/healing/procs.

    Native enemy death, world loot, and shared XP still execute normally.
    Patches exist only during the injected call under the host's game lock.
    """
    def jump(source, target, size):
        return reviewed_branch(source, target, size=size)
    if release_47e4():
        # 47e4 DAMAGE (evidence: coop-lab/port-re/decisions.py, out/damage-diff.txt).
        patches = (
            # Personal meter is the call 0x54c4900 with a borrowed label: skip only that call.
            (0x540B73A, bytes.fromhex('4c8ba6800600004889b578010000'), jump(0x540B741, 0x540B79D, 5)),
            (0x540B15F, bytes.fromhex('f3440f59de'), bytes.fromhex('440f28c690')),
            # Class heal/leech factor (pure helper 0x5486ef0) and heal: XMM12 = 0, continue at its JBE target.
            (0x540BA5C, bytes.fromhex('0fb6824c03000004fe'), bytes.fromhex('450f57e4') + jump(0x540BA60, 0x540BDD7, 5)),
            (0x540C2C7, bytes.fromhex('f30f108844050000'), bytes.fromhex('450f57e4')),
            (0x540CFAC, bytes.fromhex('488b8660030000488b8e68030000'), jump(0x540CFAC, 0x540E318, 5)),
        )
        # The family added a second meter call before the boss meter: the run meter
        # (Game+0x5C8) counted injected guest hits on the host's meter as "Melee".
        start, resume, meter = family('run_meter')
        run_meter = bytes.fromhex('488d8ec80500004c89fa0f28d7e8') + struct.pack('<i', meter - resume)
        if len(run_meter) != resume - start:
            raise ValueError('Run meter call span changed')
        return tuple((reviewed_rva(address), reviewed_bytes(address, original),
                      replacement + b'\x90' * (len(reviewed_bytes(address, original)) - len(replacement)))
                     for address, original, replacement in patches) + (
            (start, run_meter, b'\xeb' + bytes([resume - start - 2]) + b'\x90' * (resume - start - 2)),)
    if UPDATED:
        # The updated class/healing block initializes XMM12 internally. Restore
        # that zero explicitly before bypassing the host's private modifiers.
        patches = (
            # Injected remote damage must not enter the host's personal meter.
            # Retain the owned label cleanup; enemy HP/death still run below.
            (0x540B73A, bytes.fromhex('4c8ba6800600004889b578010000'),
             bytes.fromhex('4889b578010000') + jump(0x540B741, 0x540B79D, 7)),
            (0x540B15F, bytes.fromhex('f3440f59de'), bytes.fromhex('440f28de90')),
            (0x540BA5C, bytes.fromhex('0fb6824c03000004fe'),
             bytes.fromhex('450f57e4') + jump(0x540BA60, 0x540BDD7, 5)),
            (0x540C2C7, bytes.fromhex('f30f108844050000'), bytes.fromhex('0f57c9') + b'\x90' * 5),
            (0x540CFAC, bytes.fromhex('488b8660030000488b8e68030000'), jump(0x540CFAC, 0x540E318, 14)),
        )
        return tuple((reviewed_rva(address), reviewed_bytes(address, original),
                      replacement + b'\x90' * (len(reviewed_bytes(address, original)) - len(replacement)))
                     for address, original, replacement in patches)
    return (
        (0x53FF9CF, bytes.fromhex('f3440f59de'), bytes.fromhex('440f28de90')),
        (0x54002C8, bytes.fromhex('0fb6863c03000004fe'), jump(0x54002C8, 0x5400637, 9)),
        (0x5400B40, bytes.fromhex('f30f108e34050000'), bytes.fromhex('0f57c9') + b'\x90' * 5),
        (0x540173C, bytes.fromhex('488b8650030000488b8e58030000'), jump(0x540173C, 0x5402A59, 14)),
    )


# One unpack per enemy record (from +0x68): dead flag, guid (+0x78), hp (+0xE0),
# start/end pose (+0xFC/+0x108), movement start and duration (+0x114).
ENEMY_RECORD = struct.Struct('<I12xQ96xf24x3f3fff')


def enemy_record():
    stride, guid_offset, layout = enemy_layout()
    return stride, guid_offset, struct.Struct(layout)


def native_enemy_array(client, game):
    """The native enemy vector as one read: (records, game time). The game is halted."""
    pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x568), 16))
    if count > MAX_ENEMIES:
        raise ValueError('Native enemy vector exceeds diagnostic bound')
    data = client.memory(pointer, count * enemy_layout()[0]) if count else b''
    now = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
    return data, now


# Single broken entries in game memory (an enemy record with NaN/inf while it dies or its slot is reused, a
# nonfinite value in one hit) are skipped and logged, never the end of the run (user: "no limit, play as far as
# you can"). Wrong layouts or changed instructions still stop; peer (wire) input stays strict.
NATIVE_SKIPS = dict(report=None, last={})


def finite_text(values):
    """Floats for the JSON log: NaN/inf as text (json would write invalid NaN tokens)."""
    return [v if not isinstance(v, float) or math.isfinite(v) else repr(v) for v in values]


def note_native_skip(event, key=None, **details):
    """Log a skipped native entry once per (event, key) and minute; the bridge sets the reporter (record)."""
    now, last = time.monotonic(), NATIVE_SKIPS['last']
    if now - last.get((event, key), float('-inf')) < 60:
        return
    if len(last) >= 4096:
        for old in [k for k, t in last.items() if now - t >= 60]:
            del last[old]
    last[(event, key)] = now
    report = NATIVE_SKIPS['report']
    if report is not None:
        report(event=event, key=key, **details)


def enemy_pose(fields, now, guid=None):
    """(hp, interpolated pose) of one living record, or None if it holds NaN/inf (skipped, logged)."""
    hp, x0, y0, z0, x1, y1, z1, began, duration = fields
    if not all(map(math.isfinite, (now, *fields))):
        note_native_skip('enemy_state_nonfinite', guid, clock=finite_text([now])[0], fields=finite_text(fields))
        return None
    t = min(1, max(0, (now - began) / duration)) if duration > 0 else 1
    return hp, (x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, z0 + (z1 - z0) * t)


def parse_native_enemies(data, now):
    stride, _, record = enemy_record()
    unpack = record.unpack_from
    result = []
    for offset in range(0x68, len(data), stride):
        dead, guid, *fields = unpack(data, offset)
        if dead == 1:
            continue
        pose = enemy_pose(fields, now, guid)
        if pose is not None:  # A record with NaN/inf is treated as not there.
            result.append((guid, *pose))
    return result


def native_enemies(client, game):
    return parse_native_enemies(*native_enemy_array(client, game))


def native_enemy(client, game, guid):
    """(hp, pose) of the first living record with this guid, else None.

    Same result as scanning native_enemies(), but only the matching record is
    unpacked (the guid is searched in C); used once per guest hit or area attack.
    """
    data, now = native_enemy_array(client, game)
    needle = struct.pack('<Q', guid)
    stride, guid_offset, record = enemy_record()
    found = data.find(needle)
    while found >= 0:
        offset = found - guid_offset
        if offset % stride == 0:
            dead, _, *fields = record.unpack_from(data, offset + 0x68)
            if dead != 1:
                return enemy_pose(fields, now, guid)  # None for NaN/inf: as if not there.
        found = data.find(needle, found + 1)
    return None


# Melee reach of an enemy record: 0.95 compares the XY distance to its target with [record+0x104]
# (0x54825f7 movss/ucomiss, jb = out of reach); that is the guid slot + 0x7c in every layout (0x78 -> 0xF4, 0x88 -> 0x104).
MELEE_REACH_FROM_GUID = 0x7C
GUEST_REACH_MARGIN = 3.0  # A guest's pose is his last movement packet (heartbeat + latency behind).
# Where a guest is (0.0.22). A running client sends a movement heartbeat only about every 0.5 s, so on the host his
# last packet trails him by several units, and enemies chased (and hit) that ghost instead of the players. Guests
# put their own game position into every state message (25 Hz); the host moves it on by the guest's velocity for its
# age plus the one-way latency, at most EXTRAPOLATE_SECONDS. There is no top speed (user, 17.10.2026: whoever cheats
# has the problem himself), so neither the velocity nor the distance to the movement packet is bounded; only broken
# data is dropped (online_bridge.receive_position) and a jump gives no velocity (JUMP_DISTANCE).
LIVE_POSITION_AGE = 1.0      # Older than this: the last movement packet again (guest paused, link stalled).
EXTRAPOLATE_SECONDS = .25
# Two samples farther apart than this are a teleport, blink (20 units) or respawn: no velocity from them, the new
# position is taken as it is. Samples come every 40 ms: a run of 7 units/s moves 0.28 between them, 5 units would
# take 125 units/s.
JUMP_DISTANCE = 5.0


def native_enemy_melee(client, game, guid):
    """(hp, pose, melee reach) of the first living record with this guid, else None (also for NaN/inf)."""
    data, now = native_enemy_array(client, game)
    needle = struct.pack('<Q', guid)
    stride, guid_offset, record = enemy_record()
    found = data.find(needle)
    while found >= 0:
        offset = found - guid_offset
        if offset % stride == 0:
            dead, _, *fields = record.unpack_from(data, offset + 0x68)
            if dead != 1:
                pose = enemy_pose(fields, now, guid)
                reach = struct.unpack_from('<f', data, offset + guid_offset + MELEE_REACH_FROM_GUID)[0]
                if pose is None:
                    return None
                if not math.isfinite(reach) or not 0 <= reach <= 1000:
                    note_native_skip('enemy_reach_invalid', guid, reach=finite_text([reach])[0])
                    return None
                return (*pose, reach)
        found = data.find(needle, found + 1)
    return None


def native_melee_stats(client, game, phase):
    """Class profile and scalar melee modifiers used by this build's game.tick."""
    klass = client.memory(game + game_field(0x33C), 1)[0]
    profile = (q(client.memory(client.base + relocated(0x6623E50) + (klass - 2) * 8, 8))
               if 2 <= klass <= 11 else client.base + relocated(0x65F6848))
    enabled, damage, interval, radius = struct.unpack('<I3f', client.memory(profile, 16))
    if not enabled & 1:
        return None  # Ranged/spell classes require their own ability reconstruction.
    multiplier, speed = struct.unpack('<ff', client.memory(game + game_field(0x4FC), 8))
    pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x730), 16))
    if count > 256:
        raise ValueError('Unexpected guest modifier count')
    modifiers = client.memory(pointer, count * 8) if count else b''
    bonus = sum(struct.unpack_from('<f', modifiers, i + 4)[0]
                for i in range(0, len(modifiers), 8) if modifiers[i] == 0x10)
    if not all(math.isfinite(v) and 0 < v <= 1000 for v in (damage, interval, radius, multiplier, speed, 1 + bonus)):
        raise ValueError('Invalid native guest melee profile')
    return phase, damage * 1.5 * multiplier * (1 + bonus), interval * 1.2 * math.sqrt(speed), radius


def frame(opcode, body):
    return struct.pack('>H', len(body) + 4) + struct.pack('<I', opcode) + body


def movement(pose, timestamp):
    return struct.pack('<IIffffI', 0, timestamp & 0xFFFFFFFF, pose.x, pose.y, pose.z, pose.facing, 0)


def character_name(body):
    """Validate the captured 0x51 reply: GUID, name, empty realm, race/sex/class."""
    end = body.find(b'\0', 8)
    if not 9 <= end <= 104 or len(body) != end + 14 or body[end + 1] != 0:
        raise ValueError('Invalid native character name response')
    name = body[8:end].decode('utf-8')
    race, gender, class_id = struct.unpack_from('<III', body, end + 2)
    if (not name.isprintable() or not 1 <= race <= 255 or gender > 2
            or not 1 <= class_id <= 255):
        raise ValueError('Invalid native character identity')
    return name


def clone_player(body, guid, pose):
    """Only the captured build's single, stationary, local-player create shape."""
    if len(body) < 73 or body[:12] != bytes.fromhex('01000000000307feffff0471'):
        raise ValueError('Not the verified local-player creation shape')
    if struct.unpack_from('<I', body, 12)[0] != 0:
        raise ValueError('Unsupported initial movement flags')
    result = bytearray(body)
    # This lab reserves 0xff0101 and 0xff0102, both three nonzero GUID bytes.
    encoded = packed_guid(guid)
    if len(encoded) != 4:
        raise ValueError('Replacement GUID must retain packed width')
    result[6:10] = encoded
    result[11] &= ~1  # Clear SELF; the recipient keeps its own native avatar.
    struct.pack_into('<ffff', result, 20, pose.x, pose.y, pose.z, pose.facing)
    count = result[68]
    start = 69 + count * 4
    mask = int.from_bytes(result[69:start], 'little')
    if mask & 3 != 3 or len(result) != start + mask.bit_count() * 4:
        raise ValueError('Unexpected object field mask')
    if q(result, start) != 0xFFFFFE:
        raise ValueError('Object field GUID does not match local player')
    struct.pack_into('<Q', result, start, guid)
    return bytes(result)


def encrypt_packets(packets, key, index, previous):
    if len(key) != 40 or not 0 <= index < 40:
        raise ValueError('Invalid native server cipher state')
    result = bytearray()
    for opcode, body in packets:
        header = struct.pack('>H', len(body) + 2) + struct.pack('<H', opcode)
        for value in header:
            previous = ((value ^ key[index]) + previous) & 255
            index = (index + 1) % 40
            result.append(previous)
        result.extend(body)
    return bytes(result), index, previous


def decrypt_batch(data, key, index, previous):
    """Native queue writes contain complete serialized server packets."""
    if len(data) > 1048576 or not 0 <= index < 40:
        raise ValueError('Invalid server batch')
    cipher = HeaderCipher(key)
    cipher.index, cipher.previous = index, previous
    packets, offset = [], 0
    while offset < len(data):
        if offset + 4 > len(data):
            raise ValueError('Truncated server header')
        header = cipher.decrypt(data[offset:offset + 4])
        size = struct.unpack_from('>H', header)[0]
        if size < 2 or offset + size + 2 > len(data):
            raise ValueError('Truncated server body')
        packets.append((struct.unpack_from('<H', header, 2)[0], data[offset + 4:offset + size + 2]))
        offset += size + 2
    return packets, cipher.index, cipher.previous


# Waiting incoming hits applied within ONE native queue write. Every hit is a
# complete native HURT call on the stopped server thread (game lock held, full
# register context restored at the queue writer, no nesting), exactly like the
# retried START/XP/pause calls; the bound only limits how long one write waits.
HITS_PER_BATCH = 24
HIT_CHAIN_SECONDS = .008  # Wall time per write after the first hit (frame budget).
# MAX_HIT_DAMAGE (play_limits): native HURT argument bound (call_before) and wire bound.
QUEUE_LIMIT = 128

class Bridge:
    def __init__(self, output, demo=False, shared_world=False):
        count = int(os.environ.get('COOP_PLAYERS', '2'))
        if not 1 <= count <= 4:
            raise ValueError('Co-op rooms support one to four players')
        self.members = tuple(range(1, count + 1))
        self.guests = self.members[1:]
        self.pursuit_guests = self.guests  # Native target-array slots stay fixed after a departure.
        self.output, self.demo = output, demo
        self.trace_packets = True  # Disposable verifiers keep full packet evidence.
        self.shared_world = shared_world
        self.autostart = not shared_world
        self.loaded, self.loading_offsets = set(), {}
        self.loading_check = 0
        self.extra_hooks = (PAUSE, RESUME, START, AWARD_XP, CHOOSE, MOVE, HURT, UI_COMMAND) if shared_world else ()
        self.restart_requested = False
        self.end_action = None
        self.end_pending = {}
        self.menu_players = set()
        self.command_buffers = {}
        self.router = SessionRouter()
        self.clients, self.templates, self.created, self.parsers = {}, {}, {}, {}
        self.name_responses = {}
        self.name_queries = {n: set() for n in self.members}
        self.buffers, self.last_sent = {}, {}
        self.latest_movement = {}
        self.world_pending, self.world_guids = [], set()
        self.world_queues = {n: [] for n in self.guests if n != 2}
        self.xp_queues = {n: 0 for n in self.guests}
        self.world_bytes = 0
        self.progress_fields, self.progress_sent = {}, {}
        self.remote_display = {}  # Latest relayed display model (druid form) per remote player GUID.
        self.remote_display_seen = {}  # (recipient, GUID) -> display last delivered, for the record.
        self.template_displays, self.displays_rejected = {}, set()  # Login models; peers logged once.
        self.server_states = {}
        self.connection_keys = {}  # Cipher keys of each mirrored player's server connection.
        self.pause_pending = {}
        self.host_started, self.xp_pending = False, 0
        self.native_states = {}
        self.ready = set()
        self.guest_stats = None
        self.next_guest_attack = 0.0
        self.attack_packets = {n: [] for n in self.members}
        self.hurt_packets = {n: [] for n in self.members}
        self.notice_packets = {n: [] for n in self.members}
        self.guest_hits = []
        self.hit_queues = {n: [] for n in self.guests if n != 2}
        self.hit_turn = 0
        self.hit_metadata = {}
        self.hit_metrics = {}
        self.hit_sequence = 0
        self.hit_work_turn = {}
        self.hit_chain = {}  # player -> (hits in the current queue write, first hit time)
        self.hit_batch_stats = {}  # player -> [writes with hits, hits, max, since]
        self.completed_players = set()
        self.draining = False
        self.talent_paused = set()
        self.revive_progress = {}
        self.revive_status = {}
        self.downed = set()
        self.result_xp = {}  # player -> class XP of its account at run start (no credit of this run in it)
        self.result_open = {}  # player -> (class, fall credit taken back at a revival, not yet re-earned)
        self.result_notes = set()
        self.raid_assignments = {n: n - 1 for n in self.members}
        self.raid_sent, self.minimap_sent = {}, {}
        self.team_defeat = set()
        self.world_enable = None
        self.guest_target = None
        self.host_clock = 0.0
        self.started = time.monotonic()
        NATIVE_SKIPS['report'] = self.record  # Skipped native entries are logged through this bridge.
        self.counts = dict(created=0, relayed=0, native_moves=0, unsupported_moves=0)
        self.counts.update(world_captured=0, world_delivered=0, guest_suppressed=0)
        self.counts.update(serializer_stops=0, batch_reads=0)

    def record(self, **event):
        log_queue = getattr(self, 'log_queue', None)
        if log_queue is not None:
            log_queue.put(event)  # The game is halted during hooks; the writer thread serializes.
            return
        self.output.write(json.dumps(event) + '\n')

    def native_connection_replaced(self, number, connection):
        """A new native world/connection for a player this session already mirrors.

        Its cipher keys no longer match the parsers and batch states of this
        run. Stop mirroring that client and end the session cleanly; a new
        run needs a new room (no crash report, clear launcher status).
        """
        keys = bytes(connection[0x31:0x59]) + bytes(connection[0x5B:0x83])
        known = self.connection_keys.setdefault(number, keys)
        if known == keys:
            return False
        self.menu_players.add(number)
        self.stop_requested = True
        self.record(event='native_world_restarted', player=number)
        self.record(event='party_restart_requires_lobby', player=number)
        return True

    def start_log_writer(self):
        """Serialize and write gameplay events on a background thread, in order."""
        import queue
        import threading
        self.log_queue = queue.SimpleQueue()

        def write():
            while True:
                event = self.log_queue.get()
                if event is None:
                    return
                try:
                    line = json.dumps(event)
                except (TypeError, ValueError, RuntimeError) as error:
                    line = json.dumps(dict(event='log_event_unserializable', name=str(event.get('event')),
                                           error=type(error).__name__))
                self.output.write(line + '\n')
        self.log_thread = threading.Thread(target=write, name='coop-gameplay-log', daemon=True)
        self.log_thread.start()

    def stop_log_writer(self):
        """Write every queued event, then return to direct writes (before closing the log)."""
        thread = getattr(self, 'log_thread', None)
        if thread is None:
            return
        self.log_queue.put(None)
        thread.join(30)
        self.log_queue = self.log_thread = None

    def note(self, kind, *values):
        """Recent native-side actions for frame_hitch diagnostics (bounded, cheap)."""
        notes = getattr(self, 'recent_actions', None)
        if notes is None:
            import collections
            notes = self.recent_actions = collections.deque(maxlen=64)
        notes.append((time.perf_counter(), kind, values))

    def incoming_queue(self, number, kind):
        selected = getattr(self, 'selected_guest_saved', None)
        if number == 2 and selected is not None:
            return selected[3 if kind == 'hits' else 4]
        if kind == 'hits':
            return self.guest_hits if number == 2 else self.hit_queues[number]
        return self.area_hits if number == 2 else self.areas_by_guest[number]

    def queued_hit_metadata(self, number, kind):
        queue = self.incoming_queue(number, kind)
        metadata = self.hit_metadata.setdefault((number, kind), deque())
        # Older test fixtures and peers can supply the existing plain lists.
        while len(metadata) < len(queue):
            self.hit_sequence += 1
            hit = queue[len(metadata)]
            metadata.append((self.hit_sequence, time.monotonic(), hit[2] if kind == 'hits' else self.host_clock))
        return metadata

    def merge_waiting_hit(self, number, kind, queue, metadata, metrics):
        """Free one slot without losing damage: fold the oldest mergeable pair.

        Two waiting hits of the same attacker in the same queue become one hit
        with their summed damage at the older hit's place, sequence and clock
        (bounded by the native HURT maximum). Returns False if no pair fits.
        """
        first = {}
        for index, hit in enumerate(queue):
            attacker, damage = hit[0], hit[1]
            if attacker in first:
                older = first[attacker]
                total = queue[older][1] + damage
                if total <= MAX_HIT_DAMAGE:
                    queue[older] = (attacker, total, *queue[older][2:])
                    del queue[index]
                    del metadata[index]
                    metrics['merged'] = metrics.get('merged', 0) + 1
                    metrics['merged_damage'] = metrics.get('merged_damage', 0) + damage
                    pending = self.hit_merge_pending.setdefault((number, kind), [0, 0.0, 0.0])
                    pending[0] += 1
                    pending[1] += damage
                    now = time.monotonic()
                    if now - pending[2] >= 1:  # Aggregated: at most one record per second.
                        self.record(event='hit_queue_merged', player=number, queue=kind,
                                    merged=pending[0], damage=round(pending[1], 3), length=len(queue))
                        self.hit_merge_pending[(number, kind)] = [0, 0.0, now]
                    return True
                if damage < MAX_HIT_DAMAGE:
                    first[attacker] = index  # The older one is too big: try the newer one.
            elif damage < MAX_HIT_DAMAGE:
                first[attacker] = index
        return False

    def queue_incoming_hit(self, number, kind, hit, clock=None):
        queue = self.incoming_queue(number, kind)
        metadata = self.queued_hit_metadata(number, kind)
        metrics = self.hit_metrics.setdefault((number, kind), dict(incoming=0, applied=0, obsolete=0, high_water=0))
        if not hasattr(self, 'hit_merge_pending'):
            self.hit_merge_pending = {}
        if len(queue) >= QUEUE_LIMIT and not self.merge_waiting_hit(number, kind, queue, metadata, metrics):
            # Last resort only when no two waiting hits share an attacker: a stopped
            # game is worse than losing the oldest waiting hit (decision 15.10.2026).
            self.record(event='hit_queue_overflow', player=number, queue=kind, dropped=1,
                        attempted_length=len(queue) + 1, diagnostics=self.diagnostic_summary())
            queue.pop(0)
            metadata.popleft()
            metrics['obsolete'] += 1
        self.hit_sequence += 1
        metadata.append((self.hit_sequence, time.monotonic(),
                         clock if clock is not None else hit[2] if kind == 'hits' else self.host_clock))
        queue.append(tuple(hit))
        metrics['incoming'] += 1
        metrics['high_water'] = max(metrics['high_water'], len(queue))

    def clear_incoming_hits(self, number, reason):
        for kind in (('hits', 'areas') if hasattr(self, 'area_hits') else ('hits',)):
            queue = self.incoming_queue(number, kind)
            if queue:
                metrics = self.hit_metrics.setdefault((number, kind), dict(incoming=0, applied=0, obsolete=0, high_water=0))
                metadata = self.queued_hit_metadata(number, kind)
                if metadata:
                    metrics['max_wait'] = max(metrics.get('max_wait', 0), time.monotonic() - metadata[0][1])
                metrics['obsolete'] += len(queue)
                self.record(event='incoming_hits_obsolete', player=number, queue=kind,
                            count=len(queue), reason=reason)
            queue.clear()
            self.hit_metadata.pop((number, kind), None)

    def diagnostic_summary(self):
        now = time.monotonic()
        elapsed = max(.001, now - self.started)
        queues = []
        for number in self.guests:
            for kind in ('hits', 'areas'):
                if kind == 'areas' and not hasattr(self, 'area_hits'):
                    continue
                pending = self.incoming_queue(number, kind)
                metadata = self.queued_hit_metadata(number, kind)
                metrics = self.hit_metrics.get((number, kind), {})
                oldest = max(0, now - metadata[0][1]) if metadata else 0
                sample_at, sample_in, sample_applied = metrics.get('sample', (self.started, 0, 0))
                interval = max(.001, now - sample_at)
                recent_in = (metrics.get('incoming', 0) - sample_in) / interval
                recent_applied = (metrics.get('applied', 0) - sample_applied) / interval
                if interval >= 5 and metrics:
                    metrics['sample'] = now, metrics['incoming'], metrics['applied']
                queues.append(dict(player=number, queue=kind, length=len(pending),
                    direction='incoming' if getattr(self, 'number', number) == number else 'outgoing',
                    high_water=metrics.get('high_water', len(pending)),
                    oldest_seconds=round(oldest, 3),
                    max_wait_seconds=round(max(oldest, metrics.get('max_wait', 0)), 3),
                    incoming=metrics.get('incoming', 0), applied=metrics.get('applied', 0),
                    obsolete=metrics.get('obsolete', 0),
                    incoming_per_second=round(metrics.get('incoming', 0) / elapsed, 3),
                    applied_per_second=round(metrics.get('applied', 0) / elapsed, 3),
                    recent_incoming_per_second=round(recent_in, 3),
                    recent_applied_per_second=round(recent_applied, 3),
                    phase=self.native_states.get(number, (0,))[0]))
        return dict(elapsed_seconds=round(elapsed, 3), game_seconds=self.host_clock,
                    paused=self.router.paused, draining=self.draining,
                    states=dict(self.native_states), counters=dict(self.counts), incoming_hits=queues)

    def completed_transition(self, number, command, phase=None):
        if command not in (6, 9) or number in self.completed_players:
            return
        phase = self.native_states.get(number, (0,))[0] if phase is None else phase
        ended = phase == 5 or phase == 4 and all(self.native_states.get(n, (0,))[0] == 4 for n in self.members)
        if not ended:
            return
        if number in self.guests:
            # New Hero hands this server back to native menu ownership, so no
            # later game batch can retire these already-obsolete combat hits.
            self.clear_incoming_hits(number, 'run_transition')
        self.completed_players.add(number)
        self.record(event='completed_run_transition', player=number,
                    action='again' if command == 6 else 'new_hero', phase=phase,
                    duration_seconds=self.host_clock, diagnostics=self.diagnostic_summary())

    def request_victory_action(self, command):
        if command not in (8, 9):
            raise ValueError('Unsupported victory choice')
        if 1 in self.end_pending:
            return  # Repeated requests cannot replace the host's pending decision.
        sequence = self.end_action['sequence'] + 1 if self.end_action else 1
        self.end_action = dict(sequence=sequence, command=command)
        self.end_pending.update({n: command for n in self.members})
        self.record(event='host_victory_action', **self.end_action)

    def finish_ready(self):
        """Stop simulation and drain accepted replication before a timed exit."""
        if not self.shared_world:
            return True
        self.draining = True
        # Accepted damage cannot disappear because a recipient changed phase
        # before delivery. Keep draining, or fail the bounded shutdown explicitly.
        if self.guest_hits or any(self.hit_queues.values()):
            return False
        self.router.paused = True
        # Closing is monotonic, including resumes queued before closing began.
        self.pause_pending.update({n: True for n in self.clients
                                   if self.pause_pending.get(n) is False or
                                   self.native_states.get(n, (0,))[0] == 1})
        for number in tuple(self.pause_pending):
            if number in self.clients and self.native_states.get(number, (0,))[0] == 2:
                # A final accepted XP award can open a talent menu during drain.
                # That native phase is already quiescent; Pause cannot act on it.
                del self.pause_pending[number]
                self.record(event='drain_menu_quiescent', player=number)
        # Remote snapshots cannot confirm local shutdown after a connection ends.
        stopped = all(self.native_states.get(n, (0,))[0] != 1 for n in self.clients)
        return (stopped and not any(n in self.pause_pending for n in self.clients) and not self.world_pending and not any(self.world_queues.values()) and not any(self.attack_packets.values()) and
                not any(self.hurt_packets.values()) and
                all(c.saved_context is None for c in self.clients.values()))

    def pose(self, number):
        pose = self.router.players[0xFF0100 + number].pose
        if self.demo:
            elapsed = time.monotonic() - self.started
            return Pose(-9396 + 3 * math.sin(elapsed * .5 + number),
                        -633 + 3 * math.cos(elapsed * .5 + number), pose.z, elapsed * .5)
        return pose

    def __call__(self, client, rva, context):
        number = client.number
        if rva == WRITE and number == 1 and getattr(self, 'pursuit_guard', 0):
            failed, checks = struct.unpack('<QQ', client.memory(self.pursuit_guard, 16))
            if failed:
                raise ValueError('Native pursuit owner/vector/SIMD guard failed')
            if checks and not getattr(self, 'pursuit_guard_observed', False):
                self.pursuit_guard_observed = True
                self.record(event='native_pursuit_guard', checks=checks)
        self.clients[number] = client
        if number in self.menu_players:
            return  # Native character-selection lifecycle owns this server again.
        if rva == UI_COMMAND:
            command = struct.unpack('<I', client.memory(q(context, 136), 4))[0]
            phase = (client.memory(q(context, 128) + 0x10 + game_field(0x8BF), 1)[0]
                     if command in (6, 8, 9) else self.native_states.get(number, (0,))[0])
            if command == 9 and phase != 5:
                self.completed_transition(number, command, phase)
            if command in (8, 9) and (client.saved_context is None or getattr(client, 'call_is_request', False)):
                if phase == 5:
                    if number == 1:
                        self.request_victory_action(command)
                    else:
                        self.notice_packets[number].append(system_message('The host chooses whether the party keeps fighting or returns to character selection.'))
                    stack = q(context, 152)
                    struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
                    struct.pack_into('<Q', context, 152, stack + 8)
                    return
            if command == 6:  # Native Again command has no owned payload.
                self.completed_transition(number, command, phase)
                self.restart_requested = True
                stack = q(context, 152)
                struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
                struct.pack_into('<Q', context, 152, stack + 8)
                self.record(event='shared_restart_requested', player=number)
            return
        if rva == HURT:
            if number == 1 and client.saved_context is None:
                self.route_enemy_hit(client, context)
            return
        if rva == MOVE:
            # Login sends its first batch before finishing construction of game.
            # Native movement dispatch proves that initialization has completed.
            if q(context, 128) != client.server + 0x10:
                raise RuntimeError('Unexpected native movement game object')
            self.ready.add(number)
            client.disable_hooks.add(MOVE)
            self.record(event='native_ready', player=number)
            return
        if rva == START:
            if self.shared_world and len(self.loaded) != len(self.members):
                stack = q(context, 152)
                struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
                struct.pack_into('<Q', context, 152, stack + 8)
                return  # Defer native start until both clients finish loading.
            if number == 1:
                self.host_started = True
                self.run_started()
            self.record(event='native_start', player=number)
            return
        if rva == AWARD_XP:
            amount = q(context, 136) & 0xFFFFFFFF
            if number == 1:
                if 2 in self.guests:
                    self.xp_pending += amount
                for guest in self.guests:
                    if guest != 2:
                        self.xp_queues[guest] += amount
                self.record(event='native_xp_award', amount=amount)
            return
        if rva == CHOOSE:
            self.record(event='native_talent_choice', player=number, slot=q(context, 136))
            return
        if rva in (PAUSE, RESUME):
            if self.draining:
                # The native call still returns normally; repair a late Resume
                # through the existing owned Pause call at the next batch.
                self.router.paused = True
                if rva == RESUME:
                    self.pause_pending[number] = True
                return
            # Calls mirrored by us must not feed back as fresh player requests.
            if (client.saved_context is None or getattr(client, 'call_is_request', False)) and str(number) in self.router.sessions:
                phase = client.memory(q(context, 128) + game_field(0x8BF), 1)[0]
                if phase == (1 if rva == PAUSE else 3) or phase == 4:
                    self.router.set_paused(str(number), rva == PAUSE)
                    self.pause_pending.update({n: self.router.paused for n in self.clients})
                    self.record(event='shared_pause_requested', player=number, paused=self.router.paused)
            return
        if rva == TICK:
            client.server = q(context, 128)
            self.record(event='native_server', player=number)
            if not getattr(client, 'dispatch_guards_installed', False):
                installed = install_dispatch_guards(client)
                client.dispatch_guards_installed = True
                if installed:
                    self.record(event='native_dispatch_guards', player=number, guards=installed)
            if self.shared_world and number == 1:
                expected = phase_gate() + code_fields(bytes.fromhex('f3410f10bd6c080000' if UPDATED else 'f3410f10bd5c080000'), 'game', {'r13'})
                address = client.base + relocated(0x53DC9F5)
                if release_0843():
                    expected = phase_gate() + code_fields(bytes.fromhex('f3410f10bc246c080000'), 'game', {'r12'})
                if client.memory(address, len(expected)) != expected:
                    raise RuntimeError('Host tick phase gate does not match verified build')
                self.world_enable = checked(allocate(client.handle, None, 1, 0x3000, 4))
                code = client.executable_buffer(downed_world_code(client.base, self.world_enable))
                client.patch(address, absolute_jump(code) + b'\x90' * (len(expected) - 14))
                address = client.base + relocated(0x53E1B4E)
                expected = expected_bytes(0x53E1B4E, bytes.fromhex(
                    '498d8588050000 488985e8020000' if UPDATED else '498d8578050000 48898568010000'))
                if client.memory(address, len(expected)) != expected:
                    raise RuntimeError('Native hazard/totem boundary changed')
                client.patch(address, absolute_jump(client.executable_buffer(downed_hazards_code(client.base))) + b'\x90' * (len(expected) - 14))
                self.guest_target = checked(allocate(client.handle, None, max(1, len(self.guests)) * 16, 0x3000, 4))
                self.pursuit_guard = checked(allocate(client.handle, None, 16, 0x3000, 4))
                address = client.base + relocated(0x53E370A)
                expected = expected_bytes(0x53E370A, bytes.fromhex('450f28cf 440f5c8dd0000000 f3450f16e9'))
                if client.memory(address, len(expected)) != expected:
                    raise RuntimeError('Enemy pursuit instructions changed')
                sticky = None
                if os.environ.get('COOP_PURSUIT_STICKY') == '1' and release_7264():
                    # Candidate (17.10.2026): enemies keep their player, see pursuit_code / PURSUIT_STICK.
                    sticky = checked(allocate(client.handle, None, PURSUIT_TABLE, 0x3000, 4))
                    client.put(sticky, b'\xff' * PURSUIT_TABLE)
                    self.record(event='native_pursuit_sticky', stick=PURSUIT_STICK)
                code = client.executable_buffer(pursuit_code(client.base, self.guest_target, len(self.guests),
                    game=client.server + 0x10, guard=self.pursuit_guard, sticky=sticky))
                client.patch(address, absolute_jump(code) + b'\x90' * (len(expected) - 14))
                if release_47e4():
                    # 0.92 steers approaching enemies through a path field that the enemy function rebuilds
                    # around the host only (call 0x5504340 from [rbp+0x50] at frame start; query 0x5504930).
                    # An enemy whose pursuit target is a guest would follow it back to the host, so the
                    # field query runs only while the target equals the host position (Game+0x3e8; Game slot
                    # [rbp+0x260] set at 0x549eb0d). Guest-bound enemies keep the 0.84.3 direct approach with
                    # the native wall raycast. Original: cmp qword [rbp+0x60],-1; je 0x54a0278; mov rdx,[rbp+0x78].
                    site, resume, skip = family('path_field')
                    walls, path, game_slot, target = family('path_field_slots')
                    address = client.base + site
                    # cmp qword [rbp+walls],-1 ; je skip ; mov rdx,[rbp+path]
                    head = rbp_operand(bytes.fromhex('4883'), 7, walls) + bytes.fromhex('ff')
                    expected = (head + bytes.fromhex('0f84') + struct.pack('<i', skip - (site + len(head) + 6)) +
                                rbp_operand(bytes.fromhex('488b'), 2, path))
                    if client.memory(address, len(expected)) != expected:
                        raise RuntimeError('Enemy path-field query instructions changed')
                    # mov rdx,[rbp+path]; push rax; mov rax,[rbp+Game]; mov rax,[rax+host XY]; cmp rax,[rbp+target];
                    # pop rax; jne skip; jmp resume (native test rdx,rdx / je stay) ; skip: jmp skip
                    body = (rbp_operand(bytes.fromhex('488b'), 2, path) + bytes.fromhex('50') +
                            rbp_operand(bytes.fromhex('488b'), 0, game_slot) +
                            bytes.fromhex('488b80') + struct.pack('<I', game_field(0x488)) +
                            rbp_operand(bytes.fromhex('483b'), 0, target) + bytes.fromhex('58750e') +
                            absolute_jump(client.base + resume))
                    code = head + bytes.fromhex('74') + bytes([len(body)]) + body + absolute_jump(client.base + skip)
                    client.patch(address, absolute_jump(client.executable_buffer(code)) + bytes.fromhex('90') * (len(expected) - 14))
                    self.record(event='native_path_field_guard', rva=site)
                    # 0.92 recycles every ordinary enemy farther than 55 (3025 squared) from the host to a new
                    # spot around the host (Update 0x547dcb3 -> filter 0x54e6430 -> search 0x5496960, at most four
                    # per frame; 0.93.1 the same at 0x54ff4a0). Enemies spawned around a guest would be pulled back
                    # at once, so the filter's two distance tests use the nearest living player instead.
                    for (site, after, select), regs in zip(family('recycle'), ((1, 2, 3), (0, 1, 3))):
                        address = client.base + site
                        expected = (recycle_distance_original(*regs[:2]) + bytes.fromhex('0f87') +
                                    struct.pack('<i', select - (site + 29)))
                        if client.memory(address, len(expected)) != expected:
                            raise RuntimeError('Enemy recycle distance instructions changed')
                        code = recycle_distance_code(self.guest_target, len(self.guests), *regs,
                                                     client.base + select, client.base + after)
                        client.patch(address, absolute_jump(client.executable_buffer(code)) + bytes.fromhex('90') * 15)
                    self.record(event='native_recycle_guard', sites=[sites[0] for sites in family('recycle')])
            if self.shared_world and number != 1:
                # Keep the native status/buff update tail, skipping independent world simulation.
                address = client.base + relocated(0x53DC9F5)
                expected = phase_gate()
                if client.memory(address, 6) != expected:
                    raise RuntimeError('Guest simulation gate does not match verified build')
                client.patch(address, native_branch(0x53DC9F5, 0x53EA3A8, size=6))
                self.record(event='guest_simulation_paused', player=number)
            return
        if rva == SERIALIZE:
            self.counts['serializer_stops'] += 1
            if number in self.server_states:
                # Once bootstrap is delivered, inspect whole queue batches instead.
                client.disable_hooks.add(SERIALIZE)
                return
            packet = client.memory(q(context, 136), 32)
            size, opcode = q(packet, 16), struct.unpack_from('<H', packet, 24)[0]
            if opcode == 0xA9 and number not in self.templates:
                body = client.memory(q(packet, 8), size)
                if body[:12] == bytes.fromhex('01000000000307feffff0471'):
                    pose = Pose(*struct.unpack_from('<ffff', body, 20))
                    guid = 0xFF0100 + number
                    clone_player(body, guid, pose)  # Validate before registering.
                    self.templates[number] = body
                    if not self.shared_world:
                        client.disable_hooks.add(SERIALIZE)
                    self.created[number] = set()
                    self.router.add_player(guid, str(number), pose)
                    # Identity is bound to the process we launched, not a network claim.
                    self.router.attach_authenticated(str(number), str(number))
                    self.router.receive(str(number), frame(LOGIN, struct.pack('<Q', guid)))
                    self.record(event='player_registered', player=number, guid=guid)
                    self.record(event='native_player_create', player=number, body=body.hex())
            if self.shared_world and (opcode in WORLD or opcode == 0x51):
                body = client.memory(q(packet, 8), size)
                filtered = self.filter_packet(number, opcode, body)
                if filtered is None:
                    stack = q(context, 152)
                    struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
                    struct.pack_into('<Q', context, 152, stack + 8)
                elif filtered != body:
                    if len(filtered) > q(packet):
                        raise ValueError('Filtered bootstrap exceeds native allocation')
                    client.put(q(packet, 8), filtered)
                    client.put(q(context, 136) + 16, struct.pack('<Q', len(filtered)))
            return
        if rva != WRITE or not client.server:
            return
        pointer, count = struct.unpack('<QQ', client.memory(client.server + CONNECTIONS, 16))
        if count != 1:
            return
        connection = client.memory(pointer, 0xB0)
        if connection[0x30] != 1:
            return
        if self.native_connection_replaced(number, connection):
            return
        queue = q(context, 128)
        if queue == q(connection, 0x88) + 0x10:
            if number not in self.parsers:
                parser = ClientFrames(connection[0x5B:0x83])
                parser.cipher.index, parser.cipher.previous = connection[0x83:0x85]
                self.parsers[number] = parser
            data = client.memory(q(context, 136), q(context, 184))
            for opcode, body in self.parsers[number].feed(data):
                if opcode in MOVEMENT_OPCODES and number in self.templates:
                    try:
                        # Reject unsupported modes before touching the session parser.
                        decode_ground_movement(body)
                    except ProtocolError:
                        self.counts['unsupported_moves'] += 1
                        if self.counts['unsupported_moves'] <= 5:
                            self.record(event='unsupported_movement', player=number, opcode=opcode,
                                        length=len(body), flags=body[:4].hex())
                        continue
                    self.router.receive(str(number), frame(opcode, body))
                    self.latest_movement[number] = (opcode, body)
                    # Preserve every transition: a later heartbeat must not
                    # overwrite jump/landing before the next network batch.
                    for recipient in self.members:
                        if recipient != number:
                            if len(self.notice_packets[recipient]) >= MAX_QUEUE:
                                raise ValueError('Movement notice queue exceeds bound')
                            self.notice_packets[recipient].append((opcode, packed_guid(0xFF0100 + number) + body))
                    self.counts['native_moves'] += 1
                    self.record(event='native_movement', player=number, opcode=opcode, body=body.hex())
            return
        if queue != q(connection, 0x90) + 0x10 or number not in self.templates:
            return
        if number in self.end_pending and q(client.memory(q(context, 152), 8)) == client.base + relocated(0x539FC26):
            command = self.end_pending[number]
            if self.native_states.get(number, (0,))[0] == 5 and not getattr(self, 'boss_reward_pending', {}).get(number):
                self.completed_transition(number, command)
                if number not in self.command_buffers:
                    self.command_buffers[number] = checked(allocate(client.handle, None, 0xE8, 0x3000, 4))
                client.put(self.command_buffers[number], struct.pack('<I', command) + bytes(0xE4))
                del self.end_pending[number]
                if command == 9:
                    self.menu_players.add(number)
                client.call_before(context, UI_COMMAND, client.server, self.command_buffers[number])
                self.record(event='victory_action_applied', player=number, command=command)
                return
        if self.shared_world and q(client.memory(q(context, 152), 8)) == client.base + relocated(0x539FC26):
            # This native batch owns a separate UI-string vector, not chat packets.
            stack_frame = q(context, 160)
            ui_pointer = q(client.memory(stack_frame + (field('batch_frame', 0x998) if UPDATED else 0x988), 8))
            ui_count = q(client.memory(stack_frame + (field('batch_frame', 0x9A0) if UPDATED else 0x990), 8))
            if any(self.native_states.get(n, (4,))[0] != 4 for n in self.members if n != number) and replace_downed_ui(client, ui_pointer, ui_count):
                self.record(event='downed_ui_replaced', player=number)
            elif number in self.team_defeat and replace_downed_ui(client, ui_pointer, ui_count, None):
                self.record(event='team_defeat_delivered', player=number)
        if self.shared_world:
            game = client.server + 0x10
            self.check_loading()
            state = native_progress_state(client, number in self.ready)
            phase, level, xp, pending = state
            if self.draining and number in self.result_open:
                self.keep_open_result(client)  # The run ends here without another evaluation of it.
            if number == 1 and number in self.ready:
                self.host_clock = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
            elif number in self.ready:
                client.put(game + game_field(0x85C), struct.pack('<f', self.host_clock))
            if number == 2 and number in self.ready:
                self.guest_stats = native_melee_stats(client, game, phase)
            if number == 1:
                enabled = (not self.draining and not self.router.paused and
                           any(self.native_states.get(n, (0,))[0] == 1 for n in self.guests))
                client.put(self.world_enable, bytes([enabled]))
                # Choosing/paused players remain alive targets; do not trigger enemy leashing.
                for index, guest_number in enumerate(self.pursuit_guests):
                    if 0xFF0100 + guest_number in self.router.players:
                        # Pursuit chases where the guest is now, not his last movement packet (0.0.22).
                        client.put(self.guest_target + index * 16, struct.pack('<3fI', *self.guest_position(guest_number),
                                   int(self.native_states.get(guest_number, (0,))[0] in (1, 2, 3))))
                    else:
                        client.put(self.guest_target + index * 16, bytes(16))
            if self.native_states.get(number) != state:
                previous = self.native_states.get(number)
                if previous and previous[3] > pending:
                    self.record(event='native_talent_spent', player=number, count=previous[3] - pending,
                                remaining=pending, level=level)
                self.native_states[number] = state
                if phase in (1, 2, 3) and (previous is None or previous[0] in (0, 5)):
                    self.remember_result_xp(client)  # Run start, or playing on after a victory.
                self.record(event='native_state', player=number, phase=phase, level=level, xp=xp, talents_due=pending)
                self.native_phase_changed(client, number, previous, state)
            if len(self.loaded) == len(self.members) and number in self.ready and phase == 0:
                client.call_before(context, START, game)
                return
            if self.mirror_xp(client, context, phase):
                return
        if number in self.pause_pending and number in self.ready:
            paused = self.pause_pending[number]
            phase = client.memory(client.server + 0x10 + game_field(0x8BF), 1)[0]
            if phase == 4:
                del self.pause_pending[number]
                client.call_before(context, PAUSE if paused else RESUME, client.server + 0x10, ui_only=True)
                self.record(event='shared_pause_applied', recipient=number, paused=paused, downed=True)
                return
            if phase in (1, 3):
                if phase != (3 if paused else 1):
                    client.call_before(context, PAUSE if paused else RESUME, client.server + 0x10)
                    return  # Retry this exact queue write after the native call.
                del self.pause_pending[number]
                self.record(event='shared_pause_applied', recipient=number, paused=paused)
        if self.shared_world and number in self.ready and (self.sync_revival(client, context) or self.sync_talents(client, context) or self.before_batch(client, context)):
            return
        self.hit_batch_written(number)  # This write now proceeds: its hit chain ends here.
        original = client.memory(q(context, 136), q(context, 184))
        batch_start = self.server_states.get(number)
        native_packets = None
        if batch_start is not None:
            self.counts['batch_reads'] += 1
            decoded, end_index, end_previous = decrypt_batch(original, connection[0x31:0x59], *batch_start)
            if (end_index, end_previous) != tuple(connection[0x59:0x5B]):
                raise RuntimeError('Native server batch cipher boundary changed')
            native_packets = []
            for opcode, body in decoded:
                if number == 1 and opcode == MONSTER and len(self.router.players) == len(self.members):
                    reader = Reader(body)
                    reader.guid()
                    x, y = struct.unpack('<ff', reader.take(8))
                    living = [n for n in self.guests if self.native_states.get(n, (0,))[0] in (1, 2, 3)]
                    if living:
                        nearest = min(living, key=lambda n: (self.router.players[0xFF0100 + n].pose.x - x) ** 2 +
                                      (self.router.players[0xFF0100 + n].pose.y - y) ** 2)
                        body = retarget_monster(body, self.router.players[0xFF0101].pose,
                            self.router.players[0xFF0100 + nearest].pose, phase != 4, True, 0xFF0100 + nearest)
                filtered = self.filter_packet(number, opcode, body)
                if filtered is not None:
                    native_packets.append((opcode, filtered))
        packets = []
        created_packets = []
        named_packets = []
        for other in sorted(self.name_queries[number]):
            if other in self.name_responses:
                body = struct.pack('<Q', 0xFF0100 + other) + self.name_responses[other][8:]
                packets.append((0x51, body))
                named_packets.append((other, body))
        for other in self.templates:
            if other == number:
                continue
            guid, pose = 0xFF0100 + other, self.pose(other)
            if other not in self.created[number]:
                packets.append((0xA9, clone_player(self.templates[other], guid, pose)))
                created_packets.append((other, packets[-1][1]))
                if guid in self.remote_display:
                    # The login template predates a form learned since.
                    packets.append((UPDATE, values_packet(guid, {DISPLAY_ID: self.remote_display[guid]})))
                self.created[number].add(other)
                self.progress_sent.pop(number, None)
                self.counts['created'] += 1
                self.record(event='remote_create', recipient=number, player=other, guid=guid)
            now = time.monotonic()
            source = self.latest_movement.get(other)
            signature = source if not self.demo else int(now * 10)
            if self.demo and signature != self.last_sent.get((number, other), 'unset'):
                opcode, body = source if source and not self.demo else (HEARTBEAT, movement(pose, int(now * 1000)))
                packets.append((opcode, packed_guid(guid) + body))
                self.last_sent[number, other] = signature
                self.counts['relayed'] += 1
                self.record(event='remote_pose', recipient=number, player=other,
                            pose=list(pose.__dict__.values()), synthetic=self.demo)
        if self.shared_world and number != 1 and 1 in self.created[number]:
            pending_world = self.world_pending if number == 2 else self.world_queues[number]
            packets.extend(pending_world)
            for opcode, body in pending_world:
                if opcode == UPDATE and HOST_AVATAR in body:  # Cheap scan before parsing.
                    self.observe_host_display(number, body)
            if self.trace_packets:
                for opcode, body in pending_world:
                    self.record(event='world_delivered', opcode=opcode, digest=hashlib.sha256(body).hexdigest())
            self.counts['world_delivered'] += len(pending_world)
            pending_world.clear()
            self.world_bytes = 0
        if self.shared_world and self.router.progress is not None:
            # Also repair a guest bootstrap that arrived after the host snapshot.
            if self.progress_sent.get(number) != self.router.progress:
                fields = dict(zip(PROGRESSION, self.router.progress))
                for guid in (SELF, *(0xFF0100 + other for other in self.created[number])):
                    packets.append((UPDATE, values_packet(guid, fields)))
                self.progress_sent[number] = self.router.progress
                self.record(event='shared_progress', recipient=number, progress=self.router.progress)
        packets.extend(self.attack_packets[number])
        for opcode, body in self.attack_packets[number]:
            self.record(event='guest_attack_delivered', recipient=number, opcode=opcode, body=body.hex())
        self.attack_packets[number].clear()
        packets.extend(self.hurt_packets[number])
        for opcode, body in self.hurt_packets[number]:
            self.record(event='guest_hurt_delivered', recipient=number, opcode=opcode, body=body.hex())
        self.hurt_packets[number].clear()
        packets.extend(self.notice_packets[number])
        for op, payload in self.notice_packets[number]:
            if op == UPDATE:
                self.observe_remote_display(payload, number)
            if op in MOVEMENT_OPCODES:
                reader = Reader(payload, remap_enabled=False)
                owner = reader.guid() - 0xFF0100
                pose = decode_ground_movement(payload[reader.pos:])
                self.counts['relayed'] += 1
                self.record(event='remote_pose', recipient=number, player=owner,
                            pose=list(pose.__dict__.values()), synthetic=False,
                            opcode=op, body=payload[reader.pos:].hex())
        self.notice_packets[number].clear()
        from native_probe import ACTIVE_HASH
        from party_markers import SUPPORTED_HASHES, append_markers
        if self.shared_world and ACTIVE_HASH in SUPPORTED_HASHES:
            append_markers(self, number, packets)
        if native_packets is not None:
            data, index, previous = encrypt_packets(native_packets + packets, connection[0x31:0x59], *batch_start)
        else:
            extra, index, previous = encrypt_packets(packets, connection[0x31:0x59], connection[0x59], connection[0x5A])
            data = original + extra
        if self.shared_world:
            self.server_states[number] = (index, previous)
        if data == original:
            return
        if len(data) > 1048576:
            raise ValueError('Bridge output exceeds scratch buffer')
        if number not in self.buffers:
            self.buffers[number] = checked(allocate(client.handle, None, 1048576, 0x3000, 4))
        address = self.buffers[number]
        client.put(address, data)
        client.put(pointer + 0x59, bytes((index, previous)))
        struct.pack_into('<Q', context, 136, address)
        struct.pack_into('<Q', context, 184, len(data))
        for other, body in created_packets:
            self.record(event='remote_player_create_written', recipient=number, player=other, body=body.hex())
        for other, body in named_packets:
            self.name_queries[number].discard(other)
            self.record(event='remote_character_name_written', recipient=number, player=other,
                        name=character_name(body), body=body.hex())

    def check_loading(self):
        now = time.monotonic()
        if len(self.loaded) == len(self.members) or now < self.loading_check:
            return
        self.loading_check = now + 1
        for number, client in self.clients.items():
            if number in self.loaded:
                continue
            with (client.folder / 'stderr.log').open('rb') as log:
                log.seek(self.loading_offsets.get(number, 0))
                data = log.read(1048576)
                # Retain enough overlap if a log line is still being written.
                self.loading_offsets[number] = max(0, log.tell() - 128)
            if b'loading screen: cleared (' in data:
                self.loaded.add(number)
                self.record(event='client_loaded', player=number)

    def sync_talents(self, client, context):
        number = client.number
        if number not in self.ready or self.router.paused or self.draining:
            return False
        phase, _, _, pending = self.native_states[number]
        game = client.server + 0x10
        if pending and phase == 1:
            # Zero XP invokes the native chooser without awarding another point.
            client.call_before(context, AWARD_XP, game, 0)
            self.record(event='talents_opened', player=number, pending=pending)
            return True
        waiting = any(state[0] == 2 or (state[0] in (1, 3) and state[3] > 0)
                      for state in self.native_states.values())
        if not (phase == 3 and number in self.talent_paused or waiting and phase == 1):
            return False
        # Open chest/guardian choices count like level-ups: native OFFER_CHOICES opens
        # phase 2 without checking the phase, and RESUME only leaves phase 3, so a player
        # who owes a choice resumes first and is never paused (level 99 guardian kill).
        owed = pending + self.choices_owed(client)
        if phase == 3 and number in self.talent_paused and (owed or not waiting):
            self.talent_paused.discard(number)
            client.call_before(context, RESUME, game)
            self.record(event='talent_wait_ended', player=number, owed=owed)
            return True
        if waiting and phase == 1 and not owed:
            self.talent_paused.add(number)
            client.call_before(context, PAUSE, game)
            self.record(event='talent_wait_started', player=number)
            return True
        return False

    def choices_owed(self, client):
        """Open chest (Game 0x864) and guardian choices of this player; level-ups are its state[3]."""
        game = client.server + 0x10
        owed = struct.unpack('<I', client.memory(game + game_field(0x864), 4))[0]
        if release_0843() or release_47e4():
            from boss_rewards import guardian_counters
            owed += struct.unpack('<I', client.memory(game + guardian_counters()[1], 4))[0]
        return owed

    def mirror_xp(self, client, context, phase):
        """The host's run XP on a guest, also while it is down (phase 4): revived, it is on the team's level."""
        number = client.number
        pending_xp = self.xp_pending if number == 2 else self.xp_queues.get(number, 0)
        if number == 1 or phase not in (1, 2, 3, 4) or not pending_xp:
            return False
        amount = u32_part(pending_xp)  # One native u32 award; the rest next batch.
        if number == 2:
            self.xp_pending -= amount
        else:
            self.xp_queues[number] -= amount
        client.call_before(context, AWARD_XP, client.server + 0x10, amount)
        self.record(event='native_xp_mirrored', amount=amount)
        return True

    def class_xp(self, client, layout):
        """{class: (entry address, xp)} of the account's class XP table, or None if it does not look valid."""
        account = client.server + layout['account']
        entries, count = struct.unpack('<QQ', client.memory(account + 0x68, 16))
        if not 0 <= count <= MAX_CLASS_ENTRIES or count and not entries:
            return None
        table = client.memory(entries, count * 32) if count else b''
        return {table[i * 32 + 4]: (entries + i * 32, struct.unpack_from('<I', table, i * 32)[0]) for i in range(count)}

    def remember_result_xp(self, client):
        """Class XP at run start or after a finished (won) evaluation: no credit of this run is open in it."""
        layout = result_evaluation()
        table = self.class_xp(client, layout) if layout else None
        self.result_open.pop(client.number, None)
        if table is not None:
            self.result_xp[client.number] = {cls: xp for cls, (_, xp) in table.items()}

    def result_note(self, client, reason, **details):
        """Log a kept credit once per player and reason (rearm runs at every revival)."""
        key = client.number, reason
        if key not in self.result_notes:
            self.result_notes.add(key)
            self.record(event='result_xp_kept', player=client.number, reason=reason, **details)

    def rearm_result(self, client, reason):
        """Let the run evaluation run once more, for a fallen player who plays on (revival, shared victory).

        Native single-player ends the run at a fall, so its evaluation runs once per run: the once lock in front
        of the map unlock stays set and the class XP of the whole run so far is credited. Here the fall is not the
        end. The lock always opens again (map unlock at the victory). The class XP of the fall evaluation is taken
        back, and the last evaluated phase cleared so that the real end (victory or team defeat) is evaluated and
        credits the whole run once, like for a player who never fell; only if nothing but that fall evaluation
        changed the account since the snapshot, otherwise nothing is written and it is logged once.

        Revival is the exception (2-PC test 2, 18.10.2026): the evaluation after a revival counts only what happened
        since the revival (guest log: 170 XP at the fall, then 5 XP; with the 170 taken back a new hero got no level).
        So for reason 'revival' the fall credit STAYS on the account, the lock and the last phase are reopened and the
        snapshot moves up; the next evaluation is added to it. Assumption (one logged round so far): the evaluation
        parts (time survived, kills) restart at a revival; every later fall logs result_credit_kept with the credit
        of its own evaluation, which shows whether it holds. Shared victory has no revival: still taken back.
        """
        layout = result_evaluation()
        number = client.number
        if layout is None:
            self.result_note(client, 'unsupported_build')
            return
        server = client.server
        lock, last = client.memory(server + layout['lock'], 1)[0], client.memory(server + layout['last_phase'], 1)[0]
        client.put(server + layout['lock'], b'\x00')
        details = dict(player=number, reason=reason, was_locked=lock, last_phase=last)
        if not lock:
            self.record(event='result_rearmed', xp_taken_back=0, **details)  # No evaluation since the last rearm.
            return
        baseline, table = self.result_xp.get(number), self.class_xp(client, layout)
        cls = client.memory(server + layout['class_id'], 1)[0]
        victory = struct.unpack('<I', client.memory(server + layout['victory'], 4))[0]
        if baseline is None or table is None:
            self.result_note(client, 'no_snapshot' if baseline is None else 'invalid_table')
        elif last != 4 or victory:
            self.result_note(client, 'not_a_fall_evaluation', last_phase=last, victory=victory)
        elif any(xp != baseline.get(c) for c, (_, xp) in table.items() if c != cls) or \
                any(c not in table for c in baseline) or table.get(cls, (0, 0))[1] < baseline.get(cls, 0):
            self.result_note(client, 'account_changed_otherwise', cls=cls)
        else:
            address, xp = table.get(cls, (None, baseline.get(cls, 0)))
            credited = xp - baseline.get(cls, 0)
            if reason == 'revival':
                client.put(server + layout['last_phase'], b'\x00')
                self.result_xp[number][cls] = xp
                self.record(event='result_credit_kept', player=number, cls=cls, credited=credited, reason=reason)
                self.record(event='result_rearmed', xp_taken_back=0, cls=cls, **details)
                return
            if credited:
                client.put(address, struct.pack('<I', baseline.get(cls, 0)))
            client.put(server + layout['last_phase'], b'\x00')
            self.result_open[number] = cls, credited
            self.record(event='result_rearmed', xp_taken_back=credited, cls=cls, **details)
            return
        self.record(event='result_rearmed', xp_taken_back=0, **details)

    def keep_open_result(self, client):
        """A run that ends without another evaluation (left after a revival) keeps the fall credit, once."""
        if client.number not in self.result_open:
            return
        cls, credited = self.result_open.pop(client.number)
        layout = result_evaluation()
        if client.memory(client.server + layout['lock'], 1)[0]:
            return  # A later evaluation credited the whole run already.
        table = self.class_xp(client, layout)
        baseline = (self.result_xp.get(client.number) or {}).get(cls, 0)
        if table is None or cls not in table or table[cls][1] != baseline:
            self.result_note(client, 'open_credit_not_restored', cls=cls, credited=credited)
            return
        client.put(table[cls][0], struct.pack('<I', baseline + credited))
        self.record(event='result_open_credit_kept', player=client.number, cls=cls, credited=credited)

    def sync_revival(self, client, context):
        number = client.number
        teammates = [n for n in self.members if n != number]
        living = [n for n in teammates if self.native_states.get(n, (0,))[0] == 1]
        fallen_pose = self.router.players.get(0xFF0100 + number)
        other = min(living, key=lambda n: sum((a - b) ** 2 for a, b in zip(
            (fallen_pose.pose.x, fallen_pose.pose.y, fallen_pose.pose.z),
            (self.router.players[0xFF0100 + n].pose.x, self.router.players[0xFF0100 + n].pose.y,
             self.router.players[0xFF0100 + n].pose.z)))) if living and fallen_pose else (teammates[0] if teammates else number)
        phase = self.native_states[number][0]
        if phase != 4:
            self.revive_progress.pop(number, None)
            self.revive_status.pop(number, None)
            return False
        if all(self.native_states.get(n, (0,))[0] == 4 for n in teammates) and number not in self.team_defeat:
            self.team_defeat.add(number)
            client.call_before(context, DEFEAT_UI, client.server + 0x10)
            self.record(event='team_defeat_shown', player=number)
            return True
        if number in getattr(self, 'surrendered', ()):
            return False  # A player who gave up is never revived.
        if number not in self.downed:
            self.downed.add(number)
            self.record(event='player_downed', player=number)
            for packets in self.notice_packets.values():
                packets.append(system_message(f'Player {number} is down. Stand within 5 yards for 3 seconds to revive.'))
        def status(reason, **details):
            if self.revive_status.get(number) != reason:
                self.revive_status[number] = reason
                self.record(event='revival_progress', player=number, reason=reason, **details)
        # Use shared game time: menus/pauses never spend or erase earned progress.
        now = self.host_clock
        elapsed, previous = self.revive_progress.get(number, (0.0, now))
        if (self.draining or self.router.paused or any(s[0] in (2, 3) for s in self.native_states.values())):
            self.revive_progress[number] = elapsed, now
            status('suspended', elapsed=elapsed)
            return False
        if self.native_states.get(other, (0,))[0] != 1:
            self.revive_progress.pop(number, None)
            status('no_survivor')
            return False
        fallen = self.router.players[0xFF0100 + number].pose
        survivor = self.router.players[0xFF0100 + other].pose
        distance = sum((a - b) ** 2 for a, b in zip(
            (fallen.x, fallen.y, fallen.z), (survivor.x, survivor.y, survivor.z)))
        if distance > 25:
            self.revive_progress.pop(number, None)
            status('outside_radius', distance=math.sqrt(distance), elapsed=elapsed)
            return False
        if self.revive_status.get(number) == 'in_range':
            elapsed += max(0, now - previous)
        self.revive_progress[number] = elapsed, now
        status('in_range', by=other, elapsed=elapsed, distance=math.sqrt(distance))
        if elapsed < 3:
            return False
        game = client.server + 0x10
        maximum = struct.unpack('<f', client.memory(game + game_field(0x4F8), 4))[0]
        if not math.isfinite(maximum) or not 1 <= maximum <= MAX_ENEMY_HP:
            note_native_skip('revival_health_invalid', number, maximum=finite_text([maximum])[0])
            return False  # Tried again next batch.
        health = max(1, maximum * .5)
        before = self.native_states[number][1:]
        client.put(game + game_field(0x4A0), struct.pack('<f', health))
        client.put(game + game_field(0x7F8), struct.pack('<II', 0, 0))
        self.rearm_result(client, 'revival')  # The fall already ran the once-per-run evaluation.
        # Native resume sends unroot + resume UI without resetting world/build/XP.
        client.put(game + game_field(0x8BF), b'\x03')
        def completed():
            restored = client.memory(game + game_field(0x8BF), 1)[0]
            if restored != 1:
                raise RuntimeError('Native revival resume failed')
            self.downed.discard(number)
            self.revive_progress.pop(number, None)
            status('completed', by=other, elapsed=elapsed)
            for packets in self.notice_packets.values():
                packets.append(system_message(f'Player {number} revived with 50% health.'))
            for recipient in self.members:
                guid = SELF if recipient == number else 0xFF0100 + number
                self.hurt_packets[recipient].append((UPDATE, values_packet(guid, {22: int(health)})))
            self.record(event='player_revived', player=number, by=other, health=health,
                        progress_before=before, progress_after=list(struct.unpack('<II', client.memory(game + game_field(0x498), 8))))
        client.call_before(context, RESUME, game, after=completed)
        return True

    def chained_hit(self, client, context):
        """Apply the next waiting hit if this queue write still has room (count and time)."""
        number = client.number
        count, started = self.hit_chain.get(number, (0, None))
        now = time.perf_counter()
        if count >= HITS_PER_BATCH or started is not None and now - started >= HIT_CHAIN_SECONDS:
            return False  # The rest waits for the next write; nothing is dropped.
        if not self.apply_incoming_hit(client, context):
            return False
        self.hit_chain[number] = (count + 1, now if started is None else started)
        return True

    def hit_batch_written(self, number):
        """The native queue write proceeds: close this write's hit chain and count it."""
        count, _ = self.hit_chain.pop(number, (0, None))
        if not count:
            return
        now = time.monotonic()
        stats = self.hit_batch_stats.setdefault(number, [0, 0, 0, now])
        stats[0] += 1
        stats[1] += count
        stats[2] = max(stats[2], count)
        if now - stats[3] >= 10:
            self.record(event='hits_applied_per_batch', player=number, writes=stats[0], hits=stats[1],
                        max=stats[2], mean=round(stats[1] / stats[0], 2), limit=HITS_PER_BATCH)
            self.hit_batch_stats[number] = [0, 0, 0, now]

    def apply_incoming_hit(self, client, context):
        number = client.number
        if number == 1 or self.native_states[number][0] != 1 or self.router.paused:
            return False
        kinds = ('hits', 'areas') if hasattr(self, 'area_hits') else ('hits',)
        waiting = [(self.queued_hit_metadata(number, kind)[0][0], kind)
                   for kind in kinds if self.incoming_queue(number, kind)]
        if waiting:
            _, kind = min(waiting)
            _, arrived, clock = self.queued_hit_metadata(number, kind).popleft()
            hit = self.incoming_queue(number, kind).pop(0)
            attacker, damage = hit[:2]
            game = client.server + 0x10
            before = struct.unpack('<f', client.memory(game + game_field(0x4A0), 4))[0]
            current_clock = client.memory(game + game_field(0x85C), 4)
            client.put(game + game_field(0x85C), struct.pack('<f', clock))
            def completed_hit():
                after = struct.unpack('<f', client.memory(game + game_field(0x4A0), 4))[0]
                phase = client.memory(game + game_field(0x8BF), 1)[0]
                client.put(game + game_field(0x85C), current_clock)
                if not math.isfinite(after):
                    note_native_skip('guest_health_nonfinite', number, before=finite_text([before])[0])
                    return
                metrics = self.hit_metrics.setdefault((number, kind), dict(incoming=0, applied=0, obsolete=0, high_water=0))
                metrics['applied'] += 1
                metrics['max_wait'] = max(metrics.get('max_wait', 0), time.monotonic() - arrived)
                dealt = max(0, before - after)
                for recipient in self.members:
                    victim = SELF if recipient == client.number else 0xFF0100 + client.number
                    if kind == 'hits':
                        self.hurt_packets[recipient].append((0x14A, melee_packet(attacker, victim, int(dealt))))
                    self.hurt_packets[recipient].append((UPDATE, values_packet(victim, {22: int(max(0, after))})))
                self.record(event='guest_hurt' if kind == 'hits' else 'guest_area_hurt',
                            player=number, attacker=attacker, before=before, after=after, phase=phase,
                            requested=damage, queued_seconds=round(time.monotonic() - arrived, 3))
            client.call_before(context, HURT, game, attacker, damage=damage, melee=kind == 'hits', after=completed_hit)
            return True
        return False

    def before_batch(self, client, context):
        if self.chained_hit(client, context):
            return True
        if (client.number != 1 or self.draining or self.router.paused or self.pause_pending or
                not self.guest_stats or self.guest_stats[0] != 1 or
                self.native_states[1][0] not in (1, 4) or 2 not in self.created.get(1, ()) or
                1 not in self.created.get(2, ())):
            return False
        game = client.server + 0x10
        now = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
        if now < self.next_guest_attack:
            return False
        self.next_guest_attack = now + .1  # Bound scans when no enemy is in range.
        enemies = native_enemies(client, game)
        pose = self.router.players[0xFF0102].pose
        targets = []
        for guid, hp, position in enemies:
            distance = sum((a - b) ** 2 for a, b in zip(position, (pose.x, pose.y, pose.z)))
            if hp > 0 and distance <= self.guest_stats[3] ** 2:
                targets.append((distance, guid, hp))
        if not targets:
            return False
        _, target, before = min(targets)
        _, damage, interval, _ = self.guest_stats
        downed = self.native_states[1][0] == 4
        damage_gate = client.base + relocated(0x53FF52B)
        original_gate = native_branch(0x53FF52B, 0x5402BF3, opcode=b'\x0f\x85', size=6)
        if downed:
            if client.memory(damage_gate, 6) != original_gate:
                raise RuntimeError('Native damage phase gate changed')
            client.patch(damage_gate, b'\x90' * 6)
        patches = guest_damage_patches()
        for offset, original, replacement in patches:
            if client.memory(client.base + offset, len(original)) != original:
                raise RuntimeError('Guest damage isolation instructions changed')
        for offset, original, replacement in patches:
            client.patch(client.base + offset, replacement)
        host_health = struct.unpack('<f', client.memory(game + game_field(0x4A0), 4))[0]
        # ponytail: basic melee only; reconstruct guest abilities before full talent combat.
        self.next_guest_attack = now + max(.2, interval)
        def completed():
            for offset, original, replacement in patches:
                client.patch(client.base + offset, original)
            if downed:
                client.patch(damage_gate, original_gate)
            remaining = next((hp for guid, hp, _ in native_enemies(client, game) if guid == target), 0)
            dealt = before - remaining
            if not math.isfinite(dealt) or dealt <= 0:
                # The target died, vanished or holds NaN meanwhile: nothing to show for this swing.
                note_native_skip('guest_attack_without_effect', target, before=finite_text([before])[0],
                                 after=finite_text([remaining])[0])
                return
            for recipient, attacker in ((1, 0xFF0102), (2, SELF)):
                self.attack_packets[recipient].append((0x14A, melee_packet(attacker, target, int(dealt))))
            self.record(event='guest_damage', target=target, before=before, after=remaining, damage=dealt,
                        requested_damage=damage, host_downed=downed, host_health_before=host_health,
                        host_health_after=struct.unpack('<f', client.memory(game + game_field(0x4A0), 4))[0])
        client.call_before(context, DAMAGE, game, target, damage=damage, after=completed)
        return True

    def one_way_latency(self, number):
        channels = getattr(self, 'channels', None)
        channel = channels.get(number) if isinstance(channels, dict) else getattr(self, 'channel', None)
        latency = getattr(channel, 'latency_ms', None)
        value = latency() if callable(latency) else None
        return min(value / 2000, EXTRAPOLATE_SECONDS) if isinstance(value, (int, float)) and value >= 0 else 0.0

    def guest_position(self, number):
        """(x, y, z) of a guest now as far as the host can tell (see LIVE_POSITION_AGE)."""
        pose = self.router.players[0xFF0100 + number].pose
        live = getattr(self, 'live_positions', {}).get(number)
        if live is None:
            return pose.x, pose.y, pose.z
        received, (x, y, z), (vx, vy) = live[:3]
        age = time.monotonic() - received
        if not 0 <= age <= LIVE_POSITION_AGE:
            return pose.x, pose.y, pose.z
        ahead = min(age + self.one_way_latency(number), EXTRAPOLATE_SECONDS)
        return x + vx * ahead, y + vy * ahead, z

    def route_enemy_hit(self, client, context):
        """Give a native melee hit (victim always the host) to the player the enemy chased and reached.

        The target is chosen as pursuit_code chooses it for the enemy loop: the nearest living player in XY, the host
        by his game position (Game+0x488 slot, what the native check used this frame), guests by their last movement
        packet (0.0.22: guest_position); on a tie the host. 0.0.17 used the host's router pose, which movement packets update only about every
        0.5 s while running: hits that had reached a running host went to a guest next to him ("enemies only hit me
        while I stand still"). 0.0.19 kept every hit with a host in reach, which starved a guest standing beside
        him (enemy-pressure: 11 instead of 32 guest hits per minute). A guest gets the hit only within his melee
        reach + GUEST_REACH_MARGIN; otherwise the native hit stays with the host.
        """
        if self.draining or self.router.paused or q(context, 192) & 255 != 1:
            return
        game, attacker = q(context, 128), q(context, 184)
        found = native_enemy_melee(client, game, attacker)
        if found is None or found[0] <= 0:
            return
        _, enemy, reach = found
        states = {n: self.native_states.get(n, (1 if n == 1 else 0,))[0] for n in self.members}
        distances = {}
        if states.get(1) == 1:
            host = struct.unpack('<3f', client.memory(game + game_field(0x488), 12))
            if not all(map(math.isfinite, host)):
                note_native_skip('host_position_nonfinite', 1, position=finite_text(host))
                return  # The native hit stays with the host.
            distances[1] = math.hypot(enemy[0] - host[0], enemy[1] - host[1])
        for number in self.members:
            if number != 1 and states[number] == 1 and 0xFF0100 + number in self.router.players:
                gx, gy, _ = self.guest_position(number)
                distances[number] = math.hypot(enemy[0] - gx, enemy[1] - gy)  # XY like the native check.
        if not distances:
            return
        nearest = min(distances.values())
        tied = [n for n in distances if abs(distances[n] - nearest) < .01]
        if 1 in tied:
            if self.guests:  # Party evidence (melee-run acceptance): the native hit stays with the host.
                self.record(event='enemy_hit_kept', attacker=attacker, distance=round(nearest, 2), reach=round(reach, 2))
            return
        if nearest > reach + GUEST_REACH_MARGIN:
            # Nobody the enemy could have reached: the native hit (on the host) stays as it is.
            self.record(event='enemy_hit_kept', attacker=attacker, distance=round(distances.get(1, nearest), 2),
                        reach=round(reach, 2), reason='no_guest_in_reach')
            return
        self.hit_turn += 1
        target = tied[self.hit_turn % len(tied)]
        if target not in self.created.get(1, ()) or 1 not in self.created.get(target, ()):
            return
        queue = self.guest_hits if target == 2 else self.hit_queues[target]
        pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x5E0), 16))
        if not 1 <= count <= MAX_NATIVE_OBJECTS:
            return
        packet = client.memory(pointer + (count - 1) * 32, 32)
        if struct.unpack_from('<H', packet, 24)[0] != 0x14A:
            return
        body = client.memory(q(packet, 8), q(packet, 16))
        reader = Reader(body)
        reader.take(4)
        if reader.guid() != attacker:
            return
        start = reader.pos
        if reader.guid() != SELF or reader.pos - start != 4:
            return
        damage = struct.unpack_from('<f', context, 432)[0]
        if not math.isfinite(damage) or not 0 < damage <= MAX_HIT_DAMAGE:
            note_native_skip('enemy_hit_invalid', attacker, damage=finite_text([damage])[0])
            return  # The native hit stays with the host.
        # Mark only the victim GUID; batch filtering removes this old host hit.
        client.put(q(packet, 8) + start, packed_guid(0xFF0100 + target))
        clock = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
        self.queue_incoming_hit(target, 'hits', (attacker, damage, clock))
        stack = q(context, 152)
        struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
        struct.pack_into('<Q', context, 152, stack + 8)
        self.record(event='enemy_hit_redirected', attacker=attacker, damage=damage, player=target,
                    distance=round(nearest, 2), reach=round(reach, 2))

    def set_name_response(self, number, body):
        name = character_name(body)
        if number not in self.members or q(body) != SELF:
            raise ValueError('Character name does not belong to its authenticated player')
        previous = self.name_responses.get(number)
        if previous is not None and previous != body:
            raise ValueError('Character identity changed during the session')
        if previous is None:
            self.name_responses[number] = body
            self.record(event='character_name_registered', player=number, name=name, body=body.hex())

    def filter_packet(self, number, opcode, body):
        if opcode == 0x51:
            character_name(body)
            guid = q(body)
            if guid == SELF:
                self.set_name_response(number, body)
            elif 0xFF0101 <= guid <= 0xFF0104:
                other = guid - 0xFF0100
                if other in self.members and other != number:
                    self.name_queries[number].add(other)
                return None  # Native single-player reply contains the local name.
        if number == 1 and opcode == 0x14A:
            reader = Reader(body)
            reader.take(4)
            reader.guid()
            if reader.guid() in {0xFF0100 + n for n in self.guests}:
                return None  # Replaced after guest's own native defenses apply.
        if opcode not in WORLD:
            return body
        if number == 1:
            self.capture_world(opcode, body)
            return body
        if opcode == UPDATE:
            blocks = objects(body, remap=False)
            allowed = [b for b in blocks if b.guid == SELF or b.guid >> 48 == 0x4000]
            if allowed:
                if any(b.guid == SELF and any(k in b.fields for k in PROGRESSION) for b in allowed):
                    self.progress_sent.pop(number, None)
                return body if len(allowed) == len(blocks) else object_packet(allowed)
        self.counts['guest_suppressed'] += 1
        return None

    def native_phase_changed(self, client, number, previous, state):
        """A local player's native progress state changed (native combat detects "give up")."""

    def world_observed(self, blocks, destroyed=None):
        """Host world blocks before replication (native combat overlays guest debuffs)."""

    def observe_remote_display(self, payload, recipient=None):
        # Only the single-player VALUES shape the bridge writes for 0xFF0101..04.
        if payload[:6] != b'\x01\0\0\0\0\0' or payload[6] != 0x07 or payload[8:10] != b'\x01\xff':
            return
        block, = objects(payload, remap=False)
        if DISPLAY_ID in block.fields and 0xFF0101 <= block.guid <= 0xFF0104:
            self.remote_display_changed(recipient, block.guid, block.fields[DISPLAY_ID])

    def observe_host_display(self, recipient, body):
        # Host world: the host's own player block arrives under the host avatar GUID.
        for block in objects(body, remap=False):
            if block.guid == HOST and DISPLAY_ID in block.fields:
                self.remote_display_changed(recipient, HOST, block.fields[DISPLAY_ID])

    def display_allowed(self, number, display):
        """A player's model is its login model or a native druid form model."""
        if display in FORM_DISPLAYS:
            return True
        if number not in self.template_displays and number in self.templates:
            block, = objects(self.templates[number], remap=False)
            self.template_displays[number] = block.fields.get(DISPLAY_ID)
        return display == self.template_displays.get(number)

    def sanitize_player_values(self, peer, opcode, payload):
        """Drop an unexpected display model from a peer's avatar update (logged once), keep the rest."""
        if (opcode != UPDATE or payload[:6] != b'\x01\0\0\0\0\0' or payload[6] != 0x07 or
                payload[8:10] != b'\x01\xff'):
            return payload
        block, = objects(payload, remap=False)
        display = block.fields.get(DISPLAY_ID)
        if display is None or self.display_allowed(block.guid - 0xFF0100, display):
            return payload
        if peer not in self.displays_rejected:
            self.displays_rejected.add(peer)
            self.record(event='guest_display_rejected', player=peer, avatar=block.guid - 0xFF0100, display=display)
        fields = {k: v for k, v in block.fields.items() if k != DISPLAY_ID}
        return values_packet(block.guid, fields) if fields else None

    def remote_display_changed(self, recipient, guid, display):
        self.remote_display[guid] = display
        if recipient is not None and self.remote_display_seen.get((recipient, guid)) != display:
            self.remote_display_seen[recipient, guid] = display
            self.record(event='remote_display_delivered', recipient=recipient, player=guid - 0xFF0100, display=display)

    def run_started(self):
        """Host: a run begins (native START); loot-owning subclasses reset their per-run books."""

    def hidden_world_objects(self, recipient):
        return ()

    def hides_world_destroy(self, guid):
        return False

    def capture_world(self, opcode, body):
        selected = None
        if opcode == DESTROY:
            destroyed = Reader(body, remap_enabled=False).guid(False)
            self.world_guids.discard(destroyed)
            self.world_observed((), destroyed)
            if self.hides_world_destroy(destroyed):
                return  # A chest the host opened stays for guests until each opens it (they get their own DESTROY).
        if opcode == UPDATE:
            blocks = objects(body)
            self.world_observed(blocks)
            selected = []
            for block in blocks:
                if block.guid == SELF:
                    self.progress_fields.update({k: v for k, v in block.fields.items() if k in PROGRESSION})
                    if all(k in self.progress_fields for k in PROGRESSION):
                        self.router.set_host_progress(*(self.progress_fields[k] for k in PROGRESSION))
                # Host ground spells (Rain of Fire) keep the native GUID; guest
                # copies use the reserved owner bits, so they cannot collide.
                if block.object_type in (3, 5) or dynamic_object(block):
                    if block.guid not in self.world_guids and len(self.world_guids) >= MAX_WORLD_OBJECTS:
                        raise RuntimeError(f'Host world active-object limit exceeded ({MAX_WORLD_OBJECTS} objects)')
                    self.world_guids.add(block.guid)
                if block.guid in self.world_guids or (block.guid == SELF and block.kind == 0):
                    selected.append(block)
                if block.kind == 4:  # OUT_OF_RANGE retires visibility; kind 5 is NEAR_OBJECTS.
                    self.world_guids.discard(block.guid)
            if not selected:
                return
            body = object_packet(selected)
        if not self.guests:
            # Solo hosts still track progression, but have no replication backlog.
            self.world_bytes = 0
            return
        self.world_bytes += len(body) + 4
        if self.world_bytes > MAX_WORLD_BACKLOG:
            raise RuntimeError(f'Host-world queue backlog exceeded {MAX_WORLD_BACKLOG} bytes')
        for recipient in self.guests:
            delivered_body = body if opcode == UPDATE else remap_combat(opcode, body, local_guid=0xFF0100 + recipient)
            hidden = self.hidden_world_objects(recipient) if selected else ()
            if hidden and any(block.guid in hidden for block in selected):
                kept = [block for block in selected if block.guid not in hidden]
                if not kept:
                    continue
                delivered_body = object_packet(kept)
            queue = self.world_pending if recipient == 2 else self.world_queues[recipient]
            if sum(len(data) + 4 for _, data in queue) + len(delivered_body) + 4 > MAX_WORLD_BACKLOG:
                raise RuntimeError(f'Guest {recipient} world-queue backlog exceeded {MAX_WORLD_BACKLOG} bytes')
            queue.append((opcode, delivered_body))
            self.counts['world_captured'] += 1
            if self.trace_packets:
                self.record(event='world_captured', recipient=recipient, opcode=opcode, digest=hashlib.sha256(delivered_body).hexdigest(), body=delivered_body.hex())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=90, choices=range(15, 3601))
    parser.add_argument('--demo', action='store_true', help='synthetic remote movement for rendering validation')
    parser.add_argument('--shared-world', action='store_true', help='shared host world with native guest combat')
    args = parser.parse_args()
    adapter = Bridge
    if args.shared_world:
        from native_guest_combat import NativeCombatBridge
        adapter = NativeCombatBridge
    with (ROOT / 'analysis/visibility-bridge.jsonl').open('w', encoding='utf-8') as output:
        remaining = args.seconds
        while remaining > 0:
            bridge = adapter(output, args.demo, args.shared_world)
            began = time.monotonic()
            try:
                run(remaining, 2, bridge)
            finally:
                bridge.record(event='summary', **bridge.counts, synthetic=args.demo, shared_world=args.shared_world)
                print(json.dumps(bridge.counts), flush=True)
            if not bridge.restart_requested:
                break
            # ponytail: restart both isolated processes; native in-place reset needs
            # separate cipher/bootstrap reconstruction before it can avoid reloading.
            remaining -= time.monotonic() - began


if __name__ == '__main__':
    main()
