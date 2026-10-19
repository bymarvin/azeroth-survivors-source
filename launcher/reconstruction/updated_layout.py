"""Legacy-to-reviewed locations followed by a verified runtime address map."""
import os

UPDATED = os.environ.get('COOP_BUILD', 'updated') == 'updated'
_runtime = None
ADDRESSES = {
    0x53FCC02: 0x5408372, 0x65EFA08: 0x6631EA0,
    0x539FC26: 0x53C2246, 0x53A0160: 0x53C2780,
    0x53DC9F5: 0x53E7625,
    0x53DCA04: 0x53E7634, 0x53E1254: 0x53EC644,
    0x53E1B4E: 0x53ECF3E, 0x53E1B5C: 0x53ECF4C,
    0x53E2C7B: 0x53EE06B, 0x53E370A: 0x53EEB1E,
    0x53E371B: 0x53EEB2F, 0x53EA3A8: 0x53F5808,
    0x53F186E: 0x53FCCB7, 0x53F5FDB: 0x5401557,
    0x566ED90: 0x568AC10, 0x6622698: 0x6663360,
    0x5809A24: 0x581C4AC, 0x65F6848: 0x6638CE0,
    0x6623E50: 0x6664B18,
    0x53FF52B: 0x540ACBB, 0x53FF531: 0x540ACC1,
    0x5402BF3: 0x540E4CD,
    0x53E5580: 0x53F09C0,
    0x53E5430: 0x53F0870,
    0x53E6069: 0x53F14A9,
    0x53E1898: 0x53ECC88,
    0x53E1883: 0x53ECC73,
    0x53FE9EC: 0x540A17C,
    0x53FF2DF: 0x540AA6F,
    0x53FF322: 0x540AAB2,
    0x53FE96D: 0x540A0FD,
    0x53FF014: 0x540A7A4,
    0x53E75EF: 0x53F2A2F,
    0x53E7D9E: 0x53F31DE,
    0x53E7ED8: 0x53F3318,
    0x53FE970: 0x540A100,
    0x53EA280: 0x53F56E0,
    0x53E3381: 0x53EE781,
    0x53E2EB6: 0x53EE2A8,
    0x53E6B22: 0x53F1F62,
}


def configure(runtime):
    """Called after profile verification, before importing native adapter users."""
    global _runtime
    if runtime is not None and not runtime.profile.get('runtime_equivalent'):
        from runtime_addresses import RuntimeAddresses
        if (not isinstance(runtime, RuntimeAddresses)
                or runtime.profile.get('adapter_contracts_verified') is not True
                or not hasattr(runtime, 'exact_addresses')):
            raise ValueError('Runtime address translation requires a verified profile')
    _runtime = runtime


def release_0843():
    return bool(UPDATED and _runtime is not None and _runtime.profile.get('release_version') == '0.84.3')


def build_variant():
    """Native code-shape family of the verified profile: '0843', '47e4' or 'reviewed'.

    Each family pins the register/stack-slot roles of the generated patch code.
    Evidence for '47e4' lives in coop-lab/port-re (decisions.py, FRAGMENTS-47e4.md).
    """
    if not UPDATED or _runtime is None:
        return 'reviewed'
    version = str(_runtime.profile.get('release_version'))
    return ('0843' if version == '0.84.3' else '47e4' if version.startswith('47e4ab65') else
            '0931' if version.startswith('0315cf38') else '7264' if version.startswith('7264d50b') else 'reviewed')


def release_47e4():
    """Build family 47e4 (0.92.0) and its successors 0931 (0.93.1) and 7264 (0.95.0): same code paths, literals from FAMILY."""
    return build_variant() in ('47e4', '0931', '7264')


def release_0931():
    """0.93.1 data layout (enemy record +4 from 0x13c); 0.95.0 keeps it."""
    return build_variant() in ('0931', '7264')


def release_7264():
    """0.95.0 (7264d50b): enemy function with new register allocation (coop-lab/port-7264/WORKLIST.md)."""
    return build_variant() == '7264'


# Raw native addresses and frame slots of the 47e4 family that are not adapter-profile entries.
# 0931 values: coop-lab/port-0931 (map_0931.py instruction alignment, pairwin.py, decisions_0931.py).
FAMILY = {
    '47e4': dict(
        impact_return=0x547A52E, impact_victim_slot=0xB0, world_slots=(0x320, 0x288, 0x48),
        path_field=(0x54A01AA, 0x54A01B9, 0x54A0278), path_field_slots=(0x60, 0x78, 0x260, 0x50),
        recycle=((0x54E64E2, 0x54E64FF, 0x54E659E), (0x54E6612, 0x54E662F, 0x54E66B9)),
        # DAMAGE's run meter call (Game+0x5C8, AZS_METER): lea rcx; mov rdx,r15; movaps xmm2,xmm7; call meter.
        run_meter=(0x549888C, 0x549889E, 0x54C4900)),
    '0931': dict(
        # world_slots: update-frame votes 0x320->0x330 (66), 0x288->0x298 (20); [rbp+0x48] unchanged (aligned text)
        impact_return=0x547C5BE, impact_victim_slot=0xB0, world_slots=(0x330, 0x298, 0x48),
        path_field=(0x54A228D, 0x54A229F, 0x54A235E), path_field_slots=(0x70, 0x88, 0x270, -0x20),
        recycle=((0x54FF552, 0x54FF56F, 0x54FF60E), (0x54FF682, 0x54FF69F, 0x54FF729)),
        run_meter=(0x549A90C, 0x549A91E, 0x54C6E00)),
    '7264': dict(
        # coop-lab/port-7264 (map_7264.py): update frame unchanged (0x330 66, 0x298 20, 0x48 9, 0xb0 18 votes);
        # enemy frame +0x20 (0x70->0x90 5, 0x88->0xa8 4, 0x270->0x290 30), target slot [rbp] (frame start 0x5481564).
        impact_return=0x545CCCE, impact_victim_slot=0xB0, world_slots=(0x330, 0x298, 0x48),
        path_field=(0x5483125, 0x548313A, 0x54831FC), path_field_slots=(0x90, 0xA8, 0x290, 0x0),
        recycle=((0x550ACF2, 0x550AD0F, 0x550ADAE), (0x550AE22, 0x550AE3F, 0x550AEC9)),
        run_meter=(0x547B6AC, 0x547B6BE, 0x54A7FA0)),
}


def family(key):
    return FAMILY[build_variant()][key]


# The native run evaluation (TICK calls it once per new phase 4/5, i.e. also when a co-op player falls), server
# offsets: lock = once-per-run lock in front of the map unlock, last_phase = last evaluated phase (TICK evaluates
# only a phase different from it), account = account whose class XP table (+0x68 entries of 32 B: u32 xp, u8 class
# at +4; +0x70 count) it credits on every call, class_id = the run's class byte, victory = victory flag (u32);
# sites = the lock's check and set (RVA) for the static check. Pattern scan of each build: cmp byte [r13+lock],0 ..
# mov byte [r13+lock],1 in the result function, and/cl,6 cmp cl,4 cmp [rsi+last_phase],al in TICK, the function's
# movzx [rcx+class_id] / mov [rcx+victory] and lea [r13+account] / [r13+account+0x68].
RESULT_EVALUATION = {
    '0843': dict(lock=0xDFA, last_phase=0xDFC, account=0x940, class_id=0x35C, victory=0x820, sites=(0x53E6438, 0x53E6461)),
    '47e4': dict(lock=0xFA2, last_phase=0xFA4, account=0x9A8, class_id=0x294, victory=0x868, sites=(0x53F12E8, 0x53F1311)),
    '0931': dict(lock=0xFBA, last_phase=0xFBC, account=0x9A8, class_id=0x294, victory=0x868, sites=(0x53F0E88, 0x53F0EB1)),
    '7264': dict(lock=0xFBA, last_phase=0xFBC, account=0x9A8, class_id=0x294, victory=0x868, sites=(0x542E3F8, 0x542E421)),
    'reviewed': None,  # Reference build 20d4ce5f: no executable to verify against, so not supported.
}


def result_evaluation():
    """Offsets of the native run evaluation for this build, or None where they are not verified."""
    return RESULT_EVALUATION.get(build_variant())


# Native sub-object layouts that are not adapter fields (records inside native vectors).
ENEMY_LAYOUTS = {
    # stride, guid offset, struct from +0x68: dead, guid, hp, start pose, end pose, began, duration
    'reviewed': (0x148, 0x78, '<I12xQ96xf24x3f3fff'),
    '0843': (0x148, 0x78, '<I12xQ96xf24x3f3fff'),
    '47e4': (0x158, 0x88, '<I28xQ96xf24x3f3fff'),
    # 0.93.1: fields below 0x13c unchanged, 0x13c.. +4, stride 0x160 (imul/add 0x158->0x160, 45+34 aligned sites).
    '0931': (0x160, 0x88, '<I28xQ96xf24x3f3fff'),
    # 0.95.0: no struct displacement change in the enemy record (map_7264.py).
    '7264': (0x160, 0x88, '<I28xQ96xf24x3f3fff'),
}


def enemy_layout():
    return ENEMY_LAYOUTS[build_variant()]


def reviewed_rva(address):
    """Translate an explicit current-reviewed RVA, never an object-field offset."""
    return _runtime.rva(address) if UPDATED and _runtime is not None else address


def field(domain, reviewed_offset):
    """Translate one typed native field; missing candidate evidence is fatal."""
    if not isinstance(domain, str) or not domain or type(reviewed_offset) is not int or reviewed_offset < 0:
        raise ValueError('Invalid native field contract')
    if UPDATED and _runtime is not None:
        resolver = getattr(_runtime, 'field', None)
        if resolver is None:
            # The existing complete-image equivalence proof permits no layout
            # change. New candidate profiles must supply explicit field evidence.
            if _runtime.profile.get('runtime_equivalent') is True:
                return reviewed_offset
            raise ValueError(f'Unresolved native field {domain}+{reviewed_offset:x}')
        translated = resolver(domain, reviewed_offset)
        if type(translated) is not int or (translated < 0 and not domain.endswith('_frame')):
            raise ValueError(f'Unresolved native field {domain}+{reviewed_offset:x}')  # rbp slots may be negative
        return translated
    return reviewed_offset


def code_fields(code, domain, registers):
    """Translate displacements only on explicitly owned structure registers.

    Input must be complete instructions, before embedding inline jump addresses.
    Registers describe the whole snippet; no register ownership is inferred.
    """
    if not UPDATED or _runtime is None:
        return code
    import capstone
    from build_hooks import displacement_size
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    result, consumed = bytearray(code), 0
    for instruction in decoder.disasm(code, 0):
        consumed += instruction.size
        for operand in instruction.operands:
            if operand.type != capstone.x86.X86_OP_MEM or instruction.reg_name(operand.mem.base) not in registers:
                continue
            if operand.mem.index:
                raise ValueError('Indexed native field needs a separate array contract')
            before = operand.mem.disp
            after = field(domain, before)
            if after == before:
                continue
            width = displacement_size(instruction)
            if width not in (1, 4) or not -(1 << (8 * width - 1)) <= after < (1 << (8 * width - 1)):
                raise ValueError('Native field relocation needs a different instruction encoding')
            offset = instruction.address + instruction.disp_offset
            result[offset:offset + width] = after.to_bytes(width, 'little', signed=True)
    if consumed != len(code):
        raise ValueError('Native field snippet contains undecodable bytes')
    return bytes(result)


def _reviewed(legacy):
    if not UPDATED:
        return legacy
    try:
        return ADDRESSES[legacy]
    except KeyError:
        raise ValueError(f'Updated relocation not reviewed: {legacy:x}') from None


def rva(legacy):
    return reviewed_rva(_reviewed(legacy))


def reviewed_bytes(address, expected):
    return _runtime.expected_bytes(address, expected) if UPDATED and _runtime is not None else expected


def expected_bytes(legacy, expected):
    return reviewed_bytes(_reviewed(legacy), expected)


def branch_bytes(source, target, *, opcode=b'\xe9', size=5):
    """Encode an already-translated branch; never truncate an out-of-range jump."""
    short = len(opcode) == 1 and (opcode == b'\xeb' or 0x70 <= opcode[0] <= 0x7F)
    long = opcode in (b'\xe8', b'\xe9') or len(opcode) == 2 and opcode[0] == 0x0F and 0x80 <= opcode[1] <= 0x8F
    width = 1 if short else 4
    if not (short or long) or size < len(opcode) + width:
        raise ValueError('Unsupported generated branch encoding')
    operand = target - source - len(opcode) - width
    if not -(1 << (width * 8 - 1)) <= operand < 1 << (width * 8 - 1):
        raise ValueError('Relocated branch is out of range; a reviewed trampoline is required')
    return opcode + operand.to_bytes(width, 'little', signed=True) + b'\x90' * (size - len(opcode) - width)


def reviewed_branch(source, target, *, opcode=b'\xe9', size=5):
    if UPDATED and _runtime is not None:
        return _runtime.relative_branch(source, target, opcode=opcode, size=size)
    return branch_bytes(source, target, opcode=opcode, size=size)


def branch(legacy_source, legacy_target, *, opcode=b'\xe9', size=5):
    return reviewed_branch(_reviewed(legacy_source), _reviewed(legacy_target), opcode=opcode, size=size)


def phase_gate():
    return expected_bytes(0x53DC9F5, bytes.fromhex('0f85dde10000' if UPDATED else '0f85add90000'))
