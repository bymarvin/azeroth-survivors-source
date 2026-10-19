"""Validate whole-image relocations or typed, dependency-complete adapter profiles.

Changed builds require independently proved code, layouts and patch contracts,
then source-bound native acceptance before activation. Signatures alone cannot
authorize gameplay; unknown semantics or ownership remain unresolved.
"""
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

from build_hooks import ROOT, UPDATED_HASH, canonical_runtime_image
sys.path.insert(0, str(ROOT / 'analysis'))
from map_build_functions import function_references, verify_function_relocation


# Generated from the hash-verified development reference, reviewed with this source.
REFERENCE_METADATA_SHA256 = 'b63b4628386500daba0c74f062b16016733cce1975a52c80b8df8de1a4f247b9'


class ReferenceMetadata:
    """Only the reviewed PE bounds and exact patch bytes needed at launch."""
    def __init__(self, path):
        with Path(path).open('rb') as source:
            data = source.read(65537)
        if len(data) > 65536 or hashlib.sha256(data).hexdigest() != REFERENCE_METADATA_SHA256:
            raise ValueError('Reference compatibility metadata changed; install a verified co-op package')
        record = json.loads(data)
        if (record.get('format') != 1 or record.get('reference_sha256') != UPDATED_HASH
                or record.get('machine') != 0x8664 or record.get('magic') != 0x20b
                or type(record.get('image_size')) is not int
                or not 0 < record['image_size'] <= 256 * 1024 * 1024):
            raise ValueError('Invalid reference compatibility metadata')
        self.FILE_HEADER = SimpleNamespace(Machine=record['machine'])
        self.OPTIONAL_HEADER = SimpleNamespace(Magic=record['magic'], SizeOfImage=record['image_size'])
        self.patches = {}
        occupied = {}
        for row in record['patches']:
            address, raw = row['rva'], row['bytes']
            expected = bytes.fromhex(raw)
            key = address, len(expected)
            if (type(address) is not int or not expected or raw != expected.hex()
                    or address < 0 or address + len(expected) > record['image_size']
                    or key in self.patches):
                raise ValueError('Invalid or duplicate reference patch')
            for offset, value in enumerate(expected, address):
                if occupied.setdefault(offset, value) != value:
                    raise ValueError('Contradictory reference patches')
            self.patches[key] = expected
        if not self.patches:
            raise ValueError('Missing reference patches')

    def get_data(self, address, size):
        try:
            return self.patches[address, size]
        except KeyError:
            raise ValueError(f'Unresolved reference patch at {address:x}') from None


class AddressMap:
    def __init__(self, moves):
        # A move is [reviewed RVA, candidate RVA, byte length, 'code' or 'data'].
        self.moves = sorted(tuple(move) for move in moves)
        self.reverse = sorted((new, old, size, kind) for old, new, size, kind in self.moves)
        for spans in (self.moves, self.reverse):
            end = 0
            for start, destination, size, kind in spans:
                if start < end or start < 0 or destination < 0 or size <= 0 or kind not in ('code', 'data'):
                    raise ValueError('Invalid or overlapping address moves')
                end = start + size
        self.starts = [move[0] for move in self.moves]
        self.reverse_starts = [move[0] for move in self.reverse]

    def translate(self, address, *, inverse=False, end=False):
        spans, starts = (self.reverse, self.reverse_starts) if inverse else (self.moves, self.starts)
        index = (bisect.bisect_left(starts, address) if end else bisect.bisect_right(starts, address)) - 1
        if index >= 0:
            start, destination, size, _ = spans[index]
            if address < start + size or end and address == start + size:
                return destination + address - start
        return address


def game_field_candidates(functions, requested):
    """Map only observed Game* operands; never infer a structure-wide delta.

    This is layout evidence, not a calling-convention/ownership certificate.
    An address-only operand proves its base, not neighboring structure bytes.
    """
    rows = {}
    for offset in sorted(set(requested)):
        if type(offset) is not int or offset < 0:
            raise ValueError('Invalid requested Game field')
        matches = []
        for function, row in functions.items():
            contract = row.get('game_field_evidence', row.get('candidate_game_field_evidence', {}))
            for use in contract.get('fields', ()):
                start = use['old_offset']
                # Exact offsets work with older reports. Spans require explicit
                # load/store evidence, rather than assuming LEA reads memory.
                access = use.get('memory_access') is True or (use.get('address_only') is False and bool(use.get('access')))
                extent = use['width'] if access else 1
                if start <= offset < start + extent:
                    matches.append(dict(candidate=use['new_offset'] + offset - start,
                        function=function, method=contract.get('method'),
                        old_site=use['old_rva'], new_site=use['new_rva']))
        values = sorted({row['candidate'] for row in matches})
        rows[hex(offset)] = dict(candidates=values, unique=len(values) == 1,
                                 evidence=matches)
    return rows


def observed_game_field_candidates(functions, requested, observation):
    """Add only exact paired operands whose Game ownership was observed.

    The caller binds the observation to executable and adapter source hashes.
    This is field-layout evidence, never a full gameplay/activation certificate.
    """
    admitted = dict(functions)
    if observation.get('status') != 'passed':
        return game_field_candidates(admitted, requested)
    for function, row in functions.items():
        conditional = list(row.get('reload_game_field_candidates', ()))
        conditional += list(row.get('conditional_pointer_immediates', ()))
        conditional += list(row.get('conditional_game_accesses', ()))
        fields = []
        for use in conditional:
            keys = ('old_rva', 'new_rva', 'old_offset', 'new_offset', 'width', 'address_only')
            if any(event.get('owner_verified') is True and all(event.get(key) == use.get(key) for key in keys)
                   for event in observation.get('field_observations', ())):
                fields.append(dict(use, memory_access=use.get('address_only') is False))
        if fields:
            admitted['observed:' + function] = dict(game_field_evidence=dict(
                method='paired native operand with observed Game ownership', fields=fields))
    return game_field_candidates(admitted, requested)


def scoped_game_field_candidates(rows, contracts, candidate_hash):
    """Merge explicitly typed scalar fields from independently proved calls.

    These are exact declared fields, not inferred neighbors of a pointer/LEA.
    Preserve conflicting evidence so a disagreement cannot become a mapping.
    """
    import copy
    result = copy.deepcopy(rows)
    for name, contract in contracts.items():
        if (contract.get('reference_sha256') != UPDATED_HASH
                or contract.get('sha256') != candidate_hash or not contract.get('entries')):
            raise ValueError('Scoped field contract identity or native entry proof is missing')
        for member, value in contract.get('fields', {}).items():
            old, new, width = (value.get(key) for key in ('reviewed_offset', 'offset', 'width'))
            if any(type(v) is not int for v in (old, new, width)) or min(old, new) < 0 or width <= 0:
                raise ValueError('Scoped field contract has an invalid typed extent')
            key = hex(old)
            if key not in result:
                continue
            row = result[key]
            row['candidates'] = sorted(set(row['candidates']) | {new})
            row['unique'] = len(row['candidates']) == 1
            row['evidence'].append(dict(candidate=new, contract=name, member=member,
                width=width, method='exact typed native call field'))
    return result


def bootstrap_adapter_inputs(reference, candidate, structural, required_addresses, required_patches):
    """Compile entry-only interception contracts; native bodies are not replaced.

    Heap ownership is a mandatory per-hit guard, not inferred from signatures.
    Only these entry prefixes and the exact HUD CALL are admitted as patches.
    """
    import json
    before, after = Path(reference).read_bytes(), Path(candidate).read_bytes()
    if hashlib.sha256(before).hexdigest() != UPDATED_HASH:
        raise ValueError('Bootstrap reference is not the reviewed executable')
    old, _ = canonical_runtime_image(before)
    new, _ = canonical_runtime_image(after)
    hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
    tick = structural[hex(hooks['TICK']['reference_rva'])]
    def unique(rows, flag=None):
        rows = [row for row in rows if flag is None or row.get(flag) is True]
        if len(rows) != 1:
            raise ValueError('Bootstrap ownership contract is missing or ambiguous')
        return rows[0]
    entry = unique(tick['entry_contract_candidates'], 'verified_header')
    original_entry = tick['reference_entry_contract']
    if any(entry.get(k) != original_entry.get(k) for k in ('server_argument', 'time_argument')):
        raise ValueError('Native server entry argument roles changed')
    pairs = {}
    live = {}
    fields = []
    points = {hooks['TICK']['reference_rva']: int(entry['rva'], 16)}
    patch_sites = {hooks['TICK']['reference_rva']: b'\x55'}
    for name in ('SERIALIZE', 'WRITE'):
        address = hooks[name]['reference_rva']
        match = unique(structural[hex(address)]['candidates'], 'structure_equivalent')
        if match.get('field_changes'):
            raise ValueError(f'{name} consumed native record fields changed without a typed layout proof')
        points[address] = int(match['rva'], 16)
        patch_sites[address] = b'\x41\x57' if name == 'SERIALIZE' else b'\x55'
    for key, flag in (('hud', 'local_abi_roles'), ('batch', 'local_batch_contract'),
                      ('connection', 'local_vector_contract'), ('game', None)):
        suffix = 'vectors' if key == 'connection' else 'contracts'
        a = unique(tick['reference_' + key + '_' + suffix], flag)
        b = unique(tick[key + '_' + suffix], flag)
        pairs[key] = (a, b)
        live[key] = b
    a, b = pairs['hud']
    if any(a[k] != b[k] for k in ('buffer_register', 'length_register', 'callback_slot')) or b['callback_slot'] != 32:
        raise ValueError('HUD call argument or vtable slot contract changed')
    points[int(a['rva'], 16)] = int(b['rva'], 16)
    patch_sites[int(a['rva'], 16)] = bytes.fromhex('ff5020')
    a, b = pairs['batch']
    if any(a[k] != b[k] for k in ('queue_field', 'queue_offset')) or a['ui_vector']['element_size'] != b['ui_vector']['element_size']:
        raise ValueError('Native batch element/queue contract changed')
    if a['ui_vector']['stack_register'] != 'rbp' or b['ui_vector']['stack_register'] != 'rbp':
        raise ValueError('Adapter batch UI consumer requires the native RBP frame')
    points[int(a['return_rva'], 16)] = int(b['return_rva'], 16)
    for key in ('pointer', 'count'):
        fields.append(dict(domain='batch_frame', reference=a['ui_vector'][key], candidate=b['ui_vector'][key]))
    a, b = pairs['connection']
    if any(a[k] != b[k] for k in ('element_size', 'receive_queue_field', 'queue_offset')):
        raise ValueError('Connection record layout changed')
    if any(row['count_field'] != row['pointer_field'] + 8 for row in (a, b)):
        raise ValueError('Adapter connection count is not adjacent to its pointer')
    fields.append(dict(domain='server', reference=a['pointer_field'], candidate=b['pointer_field']))
    a, b = pairs['game']
    if a['argument'] != b['argument'] or a['argument'] != 'rcx' or a['frame_slot_writes'] != b['frame_slot_writes'] or b['frame_slot_writes'] != 1:
        raise ValueError('Embedded Game ownership derivation changed')
    if a['game_offset'] != 0x10 or b['game_offset'] != 0x10:
        raise ValueError('Adapter Game consumers require the reviewed embedded offset')
    fields.append(dict(domain='server', reference=a['game_offset'], candidate=b['game_offset']))
    if not all(row['game_extent']['tight_aligned_extent'] for row in (a, b)):
        raise ValueError('Native Game clone extent is not tightly bounded')
    fields.append(dict(domain='game_extent', reference=a['game_extent']['aligned_access_extent'], candidate=b['game_extent']['aligned_access_extent']))
    patches = []
    for address, expected in required_patches:
        expected = bytes.fromhex(expected) if isinstance(expected, str) else expected
        if address not in patch_sites:
            continue
        if expected != patch_sites[address] or old.get_data(address, len(expected)) != expected or new.get_data(points[address], len(expected)) != expected:
            raise ValueError('Native bootstrap interception instruction changed')
        patches.append(dict(reference=address, expected=expected.hex(), candidate_bytes=expected.hex()))
    return dict(reference_sha256=UPDATED_HASH, sha256=hashlib.sha256(after).hexdigest(),
        addresses=[dict(reference=a, candidate=b, contracts=['bootstrap-entry-and-live-owner'])
                   for a, b in points.items() if a in required_addresses], patches=patches, fields=fields,
        mandatory_live_contracts=live, automatic_activation_allowed=False)


def dynamic_input_coverage(inputs):
    """Reviewed finite expressions; new dynamic consumers remain unresolved.

    These are source-bound by the inventory identity, and their finite values
    are also checked against the captured inputs. This is not branch coverage.
    """
    from updated_layout import ADDRESSES
    if not isinstance(inputs.get('dynamic_source_inputs'), list):
        raise ValueError('Adapter inventory omitted dynamic source coverage')
    addresses, fields = set(inputs['addresses']), set(map(tuple, inputs['fields']))
    catalog = set(ADDRESSES.values())
    rules = {
        ('native_probe.py', 'game_field', "field('game', legacy_offset + 0x10)"): 'typed-game-wrapper',
        ('native_probe.py', 'defeat_ui_code', "field('game', offset)"): 'executed-defeat-generator',
        ('native_probe.py', 'call_before', 'relocated(0x53F186E if rva == PAUSE else 0x53F5FDB)'): 'complete-address-catalog',
        ('visibility_bridge.py', 'guest_damage_patches', 'reviewed_rva(address)'): 'executed-damage-generator',
        ('visibility_bridge.py', 'world_containers_code', "field('game_update_frame', slot)"): 'executed-container-generator',
        ('visibility_bridge.py', 'world_containers_code', "field('game', member)"): 'executed-container-generator',
        ('native_guest_combat.py', '__call__', 'reviewed_rva(site)'): 'finite-xp-pickup-patches',
        ('native_guest_combat.py', '__call__', 'relocated(legacy_offset)'): 'complete-address-catalog',
        ('native_guest_combat.py', '__call__', 'relocated(destinations[0 if below else 1])'): 'complete-address-catalog',
        ('native_guest_combat.py', 'sync_chests', 'game_field(offset)'): 'finite-chest-counters',
        ('boss_rewards.py', 'call', 'reviewed_rva(rva)'): 'executed-reward-generator',
    }
    rows, unresolved = [], []
    for row in inputs.get('dynamic_source_inputs', ()):
        rule = rules.get((row['file'], row.get('function'), row['expression']))
        valid = rule is not None
        if rule == 'complete-address-catalog':
            valid = catalog <= addresses
        elif rule == 'finite-xp-pickup-patches':
            valid = {0x53F2416, 0x53F32A5} <= addresses
        elif rule == 'finite-chest-counters':
            valid = {('game', 0x6e4), ('game', 0x874)} <= fields
        elif rule == 'typed-game-wrapper':
            # Parse the wrapper's actual reject-unknown allowlist instead of
            # assuming future edits keep the same fields.
            import ast
            tree = ast.parse((ROOT / 'reconstruction/native_probe.py').read_text(encoding='utf-8'))
            function = next(v for v in tree.body if isinstance(v, ast.FunctionDef) and v.name == 'game_field')
            bounds = [v for v in ast.walk(function) if isinstance(v, ast.Compare)
                      and isinstance(v.left, ast.Name) and v.left.id == 'legacy_offset'
                      and len(v.ops) == 1 and isinstance(v.ops[0], ast.NotIn)]
            valid = len(bounds) == 1 and {('game', v + 0x10) for v in ast.literal_eval(bounds[0].comparators[0])} <= fields
        rows.append(dict(row, coverage=rule, covered=valid))
        if not valid:
            unresolved.append(f"Unclassified dynamic adapter input {row['file']}:{row['line']} {row['expression']}")
    return rows, unresolved


def scalar_gap_is_unused(start, size, accesses):
    return not any(not row.get('address_only') and row['new_offset'] < start + size
                   and row['new_offset'] + row['width'] > start for row in accesses)


def caller_conditions_discharged(row, damage_guard, effect_guard=None):
    """Every incoming site needs its scalar proof or the exact persistent guard."""
    proofs = row.get('caller_condition_proofs', ())
    for condition in row.get('caller_enum_obligations', ()):
        if condition.get('kind') == 'native_effect_enum_bound':
            guard = effect_guard or {}
            if not (guard.get('mandatory') is True and guard.get('base') == condition.get('register') == 'r8'
                    and guard.get('width') == condition.get('width') == 4
                    and guard.get('maximum') == condition.get('maximum') == 10
                    and guard.get('borrowed_size') == condition.get('borrowed_size') == 12
                    and guard.get('rva') == int(condition.get('new_rva', '0'), 16)):
                return False
            continue
        if condition.get('kind') == 'game_unsigned_bound':
            guard = damage_guard or {}
            if not (guard.get('mandatory') is True and condition.get('width') == 1
                    and guard.get('width') == condition['width']
                    and guard.get('maximum') == condition.get('maximum') == 3
                    and guard.get('offset') == condition.get('new_offset')
                    and guard.get('base') == condition.get('register')
                    and guard.get('rva') == int(condition.get('new_rva', '0'), 16)):
                return False
            continue
        if not row.get('calls'):
            return False
        for call in row['calls']:
            matches = [p for p in proofs if p.get('condition') == condition and p.get('call') == call]
            if (len(matches) != 1 or matches[0].get('statically_discharged') is not True
                    or not matches[0].get('values')
                    or any(not condition.get('minimum', 0) <= v <= condition['maximum']
                           for v in matches[0]['values'])):
                return False
    return True


def compile_adapter_profile(reference, candidate, structural, contracts, inputs):
    """Join fresh typed proofs into one exact adapter profile, retaining gaps."""
    from build_hooks import probe_identity
    from enemy_contracts import conditional_update_regions
    from native_helper_contracts import collect_helper_inputs, discover_region_call_contracts
    identity = probe_identity(candidate)
    if inputs.get('identity') != probe_identity(reference):
        raise ValueError('Adapter input inventory belongs to different source bytes')
    for report in contracts.values():
        if report.get('sha256') != identity['sha256'] or report.get('reference_sha256') != UPDATED_HASH:
            raise ValueError('Adapter contract belongs to different executable bytes')
    required_addresses, required_patches = inputs['addresses'], inputs['patches']
    update = conditional_update_regions(reference, candidate, structural, required_addresses, required_patches)
    calls = discover_region_call_contracts(reference, candidate, update['native_call_audit'], update['call_arguments'])
    reports = dict(contracts, update_calls=calls, update_complete_calls=dict(
        reference_sha256=update['reference_sha256'], sha256=update['sha256'],
        verified=update['native_call_audit']['verified']))
    helpers = collect_helper_inputs(reference, candidate, reports, required_addresses, required_patches)
    bootstrap = bootstrap_adapter_inputs(reference, candidate, structural, required_addresses, required_patches)
    addresses, patches, fields = {}, {}, {}
    dynamic_coverage, unresolved = dynamic_input_coverage(inputs)
    def add(table, key, value, label):
        if key in table and table[key] != value:
            raise ValueError(f'Ambiguous typed adapter {label}: {key}')
        table[key] = value
    for report in (helpers, bootstrap, update['exact_inputs']):
        for row in report['addresses']:
            add(addresses, row['reference'], row['candidate'], 'address')
        for row in report['patches']:
            add(patches, (row['reference'], row['expected']), row['candidate_bytes'], 'patch')
    superseded = helpers.get('superseded_menu_inputs', {})
    excluded = set(superseded.get('addresses', ()))
    if excluded and not any(report.get('variant') == superseded['required_variant']
                            and report.get('menu_contract_verified') is True for report in contracts.values()):
        raise ValueError('Obsolete menu inputs lack their verified replacement route')
    required_addresses = sorted(set(required_addresses) - excluded)
    for point in required_addresses:
        if point not in addresses:
            unresolved.append(f'Unresolved adapter address {point:x}')
    for point, expected in required_patches:
        if (point, expected) not in patches:
            unresolved.append(f'Unresolved adapter patch {point:x}/{expected}')
    # Call proofs expose paired owner-verified Game operands. Include immutable
    # fields as well as changed ones; exact offsets never imply a global delta.
    sources = dict(structural)
    def collect_fields(value, path):
        if isinstance(value, dict):
            rows = value.get('game_accesses', ())
            if rows:
                sources[path] = dict(game_field_evidence=dict(method='typed helper Game accesses', fields=rows))
            for key, child in value.items():
                if isinstance(child, (dict, list)):
                    collect_fields(child, path + '/' + key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                collect_fields(child, path + '/' + str(index))
    collect_fields(reports, 'contracts')
    collect_fields(update['enemy'], 'enemy')
    for key, row in structural.items():
        if row.get('guarded_game_field_evidence'):
            sources['guarded:' + key] = dict(game_field_evidence=row['guarded_game_field_evidence'])
    game_offsets = [offset for domain, offset in inputs['fields'] if domain == 'game']
    game = game_field_candidates(sources, game_offsets)
    game = scoped_game_field_candidates(game, {key: value for key, value in contracts.items()
        if value.get('entries') and value.get('fields')}, identity['sha256'])
    for offset in game_offsets:
        row = game[hex(offset)]
        if row['unique']:
            add(fields, ('game', offset), row['candidates'][0], 'field')
    for row in bootstrap['fields'] + helpers.get('fields', []):
        add(fields, (row['domain'], row['reference']), row['candidate'], 'field')
    for row in update['frame_fields']:
        if row['base'] == 'rbp':
            add(fields, ('game_update_frame', row['old_offset']), row['new_offset'], 'frame')
    # BOSS_DEATH's exact paired MOV identifies the borrowed saved-Game slot.
    import json
    hook = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']['BOSS_DEATH']['reference_rva']
    expected = '488b8578010000'
    if (hook, expected) in patches:
        actual = bytes.fromhex(patches[hook, expected])
        if len(actual) == 7 and actual[:3] == bytes.fromhex('488b85'):
            add(fields, ('damage_frame', int.from_bytes(bytes.fromhex(expected)[3:], 'little')),
                int.from_bytes(actual[3:], 'little'), 'frame')
    for key in map(tuple, inputs['fields']):
        if key not in fields:
            unresolved.append(f'Unresolved adapter field {key[0]}+{key[1]:x}')
    for row in calls['unresolved']:
        unresolved.append(f"Native update callee {row['reference']:x}: {row.get('reason', row.get('error'))}")
    obligations = helpers.get('unresolved_runtime_obligations', [])
    damage_guard = next((r['guard_instruction'] for r in contracts.values() if 'guard_instruction' in r), None)
    effect_rows = [row['proof'] for row in calls['verified']
                   if row.get('proof', {}).get('native_effect_contract_verified') is True]
    effect_guard = effect_rows[0]['guard_instruction'] if len(effect_rows) == 1 else None
    if effect_guard is None:
        unresolved.append('Native effect paths lack one complete persistent guard contract')
    independent_sources = {key: row for key, row in sources.items() if not key.startswith('contracts/')}
    access_spans = [row for source in sources.values()
                    for row in source.get('game_field_evidence', {}).get('fields', ())
                    if not row.get('address_only')]
    for proof in effect_rows:
        for condition in proof.get('new_scalar_layout_obligations', ()):
            offset = condition['reference_position']
            position = game_field_candidates(independent_sources, [offset])[hex(offset)]
            if (not position['unique'] or condition['candidate_gap_size'] != 8
                    or condition['candidate_gap_start'] + condition['candidate_gap_size'] != position['candidates'][0]
                    or any(condition['candidate_gap_start'] <= value < condition['candidate_gap_start'] + condition['candidate_gap_size']
                           for (domain, _), value in fields.items() if domain == 'game')
                    or not scalar_gap_is_unused(condition['candidate_gap_start'], condition['candidate_gap_size'], access_spans)):
                unresolved.append('Native shield scalar gap lacks an independent position layout proof')
    # These conditions must be compiled into guards or proved at every caller;
    # passing a single smoke test is not enough to erase them.
    for row in calls['verified']:
        if not caller_conditions_discharged(row, damage_guard, effect_guard):
            unresolved.append(f"Native caller enum conditions at {row['reference']:x}")
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
    for obligation in obligations:
        address = obligation['reference']
        for condition in obligation.get('preconditions', ()):
            recognized = False
            if address == manifest['DAMAGE']['reference_rva'] and condition.get('kind') == 'game_unsigned_bound':
                recognized = caller_conditions_discharged(dict(caller_enum_obligations=[condition]), damage_guard)
            elif address == manifest['OFFER_CHOICES']['reference_rva']:
                recognized = (condition.get('register') == 'dl' and condition.get('width') == 1
                              and condition.get('minimum') == 0 and condition.get('maximum') == 2)
            elif address == manifest['SPAWN_LOOT']['reference_rva']:
                recognized = (condition.get('register') == 'edx' and condition.get('width') == 4
                              and condition.get('minimum') == 0 and condition.get('maximum') == 6
                              and condition.get('adapter_allowed_values') == [0, 1, 2])
            elif address == manifest['APPLY_EFFECT']['reference_rva']:
                recognized = (condition.get('effect_pointer_register') == 'r8'
                              and condition.get('effect_size') == 12
                              and condition.get('allowed_tags') == [1, 2, 3, 4, 10])
            if not recognized or condition.get('mandatory_before_every_adapter_call') is not True:
                unresolved.append(f'Unrecognized adapter native-call precondition at {address:x}')
    dispatch = update['mandatory_dispatch_guards']
    if (update.get('static_verified') is not True
            or update['enemy'].get('conditional_enemy_tail_verified') is not True
            or not update['conditionally_admitted_regions']
            or any(row.get('admitted') is not True for row in update['conditionally_admitted_regions'])
            or len(dispatch) != 2 or {row['kind'] for row in dispatch} != {'cast_tag', 'loot_tag'}
            or any(row.get('mandatory_runtime_guard') is not True for row in dispatch)):
        unresolved.append('Native controlled regions lack their complete guarded ownership contracts')
    if probe_identity(candidate) != identity:
        raise ValueError('Game or resolver sources changed during adapter compilation')
    return dict(reference_sha256=UPDATED_HASH, sha256=identity['sha256'], identity=identity,
        runtime_equivalent=False, adapter_contracts_verified=not unresolved,
        addresses=[dict(reference=a, candidate=addresses[a]) for a in required_addresses if a in addresses],
        patches=[dict(reference=a, expected=b, candidate_bytes=patches[a, b])
                 for a, b in required_patches if (a, b) in patches],
        fields=[dict(domain=d, reference=a, candidate=fields[d, a])
                for d, a in inputs['fields'] if (d, a) in fields],
        required_inputs=dict(addresses=required_addresses, patches=required_patches, fields=inputs['fields']),
        native_live_contracts=bootstrap['mandatory_live_contracts'],
        dispatch_guards=update['mandatory_dispatch_guards'],
        damage_guard=damage_guard,
        effect_guard=effect_guard,
        update_contract=update, update_call_contracts=calls, runtime_obligations=obligations,
        dynamic_input_coverage=dynamic_coverage,
        superseded_menu_inputs=superseded, unresolved_contracts=unresolved,
        automatic_activation_allowed=False)


def _runtime_functions(image, mapped):
    directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    start, size = directory.VirtualAddress, directory.Size
    if size % 12 or start + size > len(mapped):
        raise ValueError('Invalid exception directory')
    rows = list(struct.iter_unpack('<III', mapped[start:start + size]))
    if any(not 0 < begin < end <= len(mapped) or unwind >= len(mapped) for begin, end, unwind in rows):
        raise ValueError('Invalid native function range')
    return start, size, rows


def _relocation_sites(image, mapped):
    directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    cursor, end = directory.VirtualAddress, directory.VirtualAddress + directory.Size
    # canonical_runtime_image already validates directory bounds, types and overlap.
    while cursor < end:
        page, size = struct.unpack_from('<II', mapped, cursor)
        for (entry,) in struct.iter_unpack('<H', mapped[cursor + 8:cursor + size]):
            if entry >> 12:
                yield page + (entry & 0xFFF)
        cursor += size


def verify_runtime_moves(reference_data, candidate_data, moves, *, reviewed_data_spans=()):
    """Validate a complete candidate runtime, not just the supplied addresses.

    Supports permutations of code/data spans without changes to section layout.
    Span padding must be included when functions of different sizes are reordered.
    All other bytes, including imports/resources/unwind programs, remain exact.
    """
    addresses = AddressMap(moves)
    old_pe, before = canonical_runtime_image(reference_data)
    new_pe, after = canonical_runtime_image(candidate_data)
    if len(before) != len(after):
        raise ValueError('Mapped image size changed')
    def covered(spans):
        result = []
        for start, _, size, _ in spans:
            if result and result[-1][1] == start:
                result[-1] = (result[-1][0], start + size)
            else:
                result.append((start, start + size))
        return result
    if covered(addresses.moves) != covered(addresses.reverse):
        raise ValueError('Moved spans do not cover the same image regions')
    for old, new, size, kind in addresses.moves:
        if kind == 'data' and (old, size) not in reviewed_data_spans:
            raise ValueError('Data move lacks reviewed complete-object extent')
        a, b = old_pe.get_section_by_rva(old), new_pe.get_section_by_rva(new)
        if (a is None or b is None or a.Characteristics != b.Characteristics
                or old + size > a.VirtualAddress + a.Misc_VirtualSize
                or new + size > b.VirtualAddress + b.Misc_VirtualSize
                or bool(a.Characteristics & 0x20000000) != (kind == 'code')):
            raise ValueError('Move crosses section boundaries or changes permissions')
        # Loader-owned tables have their own typed normalization below.
        for image in (old_pe, new_pe):
            for index in (3, 5):
                directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[index]
                if old < directory.VirtualAddress + directory.Size and old + size > directory.VirtualAddress:
                    raise ValueError('Move overlaps loader metadata')

    canonical = bytearray(after)
    old_sites = list(_relocation_sites(old_pe, before))
    new_sites = list(_relocation_sites(new_pe, after))
    if sorted(addresses.translate(site, inverse=True) for site in new_sites) != sorted(old_sites):
        raise ValueError('Loader relocation sites changed')
    for site in old_sites:
        if addresses.translate(site + 7) != addresses.translate(site) + 7:
            raise ValueError('Move splits a loader pointer')
    for site in new_sites:
        value = struct.unpack_from('<Q', canonical, site)[0]
        struct.pack_into('<Q', canonical, site, addresses.translate(value, inverse=True))
    old_reloc, new_reloc = (image.OPTIONAL_HEADER.DATA_DIRECTORY[5] for image in (old_pe, new_pe))
    if (old_reloc.VirtualAddress, old_reloc.Size) != (new_reloc.VirtualAddress, new_reloc.Size):
        raise ValueError('Relocation-directory allocation changed')
    start, size = old_reloc.VirtualAddress, old_reloc.Size
    canonical[start:start + size] = before[start:start + size]

    old_start, old_size, old_functions = _runtime_functions(old_pe, before)
    new_start, new_size, new_functions = _runtime_functions(new_pe, after)
    if (old_start, old_size) != (new_start, new_size):
        raise ValueError('Exception directory layout changed')
    canonical_functions = sorted((addresses.translate(begin, inverse=True),
                                  addresses.translate(end, inverse=True, end=True),
                                  addresses.translate(unwind, inverse=True))
                                 for begin, end, unwind in new_functions)
    if canonical_functions != old_functions:
        raise ValueError('Function bounds or unwind program changed')
    for index, row in enumerate(canonical_functions):
        struct.pack_into('<III', canonical, old_start + index * 12, *row)

    # Verify all changed functions, including unchanged-address callers whose
    # relative call operands now point to a moved callee.
    verified = []
    boundaries = sorted({boundary for old, _, size, _ in addresses.moves for boundary in (old, old + size)})
    for begin, end, _ in old_functions:
        boundary = bisect.bisect_right(boundaries, begin)
        if boundary < len(boundaries) and boundaries[boundary] < end:
            raise ValueError('Move splits a native function')
        destination = addresses.translate(begin)
        original = bytes(before[begin:end])
        candidate = bytes(canonical[destination:destination + end - begin])
        if destination != begin or original != candidate:
            references = function_references(original, begin)[1]
            mapping = {target: addresses.translate(target) for _, _, _, target in references}
            mapping[end] = addresses.translate(end)
            proof = verify_function_relocation(original, begin, candidate, destination, mapping)
            if not proof['instructions_equivalent'] or not proof['references_verified']:
                raise ValueError(f'Changed function semantics or dependency at {begin:x}')
            verified.append((begin, end, destination))

    # Restore declared blocks first, then validated instruction bytes. A leaf
    # without exception metadata is checked as a complete explicit code span.
    restored = bytearray(canonical)
    function_starts = {begin for begin, _, _ in old_functions}
    for old, new, size, kind in addresses.moves:
        block = bytes(canonical[new:new + size])
        if kind == 'code' and old not in function_starts:
            original = bytes(before[old:old + size])
            references = function_references(original, old)[1]
            mapping = {target: addresses.translate(target) for _, _, _, target in references}
            mapping[old + size] = addresses.translate(old + size)
            proof = verify_function_relocation(original, old, block, new, mapping)
            if not proof['instructions_equivalent'] or not proof['references_verified']:
                raise ValueError(f'Changed leaf function at {old:x}')
            block = original
        restored[old:old + size] = block
    for begin, end, _ in verified:
        restored[begin:end] = before[begin:end]

    entry = new_pe.OPTIONAL_HEADER.get_field_absolute_offset('AddressOfEntryPoint')
    struct.pack_into('<I', restored, entry,
                     addresses.translate(new_pe.OPTIONAL_HEADER.AddressOfEntryPoint, inverse=True))
    if restored != before:
        first = next(i for i, (left, right) in enumerate(zip(before, restored)) if left != right)
        raise ValueError(f'Unverified mapped-runtime change at RVA {first:x}')
    return dict(reference_sha256=hashlib.sha256(reference_data).hexdigest(),
                sha256=hashlib.sha256(candidate_data).hexdigest(), moves=addresses.moves,
                verified_functions=len(verified), runtime_equivalent=True,
                adapter_translation_required=any(old != new for old, new, _, _ in addresses.moves))


class RuntimeAddresses:
    """Runtime integration API; constructing it revalidates both byte snapshots."""
    def __init__(self, reference, candidate, moves, *, reviewed_data_spans=()):
        reference_data, candidate_data = Path(reference).read_bytes(), Path(candidate).read_bytes()
        if hashlib.sha256(reference_data).hexdigest() != UPDATED_HASH:
            raise ValueError('Runtime translation requires the reviewed baseline')
        self.profile = verify_runtime_moves(reference_data, candidate_data, moves,
                                            reviewed_data_spans=reviewed_data_spans)
        self.addresses = AddressMap(moves)
        self.reference, _ = canonical_runtime_image(reference_data)
        self.candidate, _ = canonical_runtime_image(candidate_data)

    @classmethod
    def from_adapter_profile(cls, reference, candidate, profile, *, isolated=False):
        """Consume a complete typed adapter proof, without whole-image equivalence.

        The launch-time resolver owns proof construction and native acceptance.
        This path has no identity fallback for omitted addresses or fields.
        """
        from build_hooks import probe_identity
        import pefile
        if Path(reference).suffix == '.json':
            reference_image = ReferenceMetadata(reference)
        else:
            before = Path(reference).read_bytes()
            if hashlib.sha256(before).hexdigest() != UPDATED_HASH:
                raise ValueError('Adapter proof belongs to different executable or source bytes')
            reference_image = pefile.PE(data=before, fast_load=True)
        after = Path(candidate).read_bytes()
        if (profile.get('reference_sha256') != UPDATED_HASH
                or profile.get('identity') != probe_identity(candidate)
                or profile.get('sha256') != hashlib.sha256(after).hexdigest()):
            raise ValueError('Adapter proof belongs to different executable or source bytes')
        if (profile.get('adapter_contracts_verified') is not True
                or profile.get('runtime_equivalent') is not False
                or profile.get('unresolved_contracts') != []):
            raise ValueError('Typed adapter dependency proof is incomplete')
        if not isolated:
            acceptance = profile.get('native_acceptance', {})
            required = {'concurrent_menus', 'class_gear_selection', 'host_map', 'four_player_movement', 'four_player_combat',
                        'bosses', 'shared_xp', 'shared_gold', 'independent_talents', 'independent_loot',
                        'pause_resume', 'revival', 'saves', 'guest_departure', 'host_shutdown',
                        'victory_keep_fighting', 'victory_new_hero', 'map_progression', 'fall_revival_unlock',
                        'lan_mode', 'lan_offline',
                        'next_run', 'next_run_after_defeat',
                        'next_run_relay', 'victory_new_hero_relay', 'host_melee_while_running'}
            if acceptance.get('identity') != profile['identity']:
                raise ValueError('Source-bound native party acceptance is missing or stale; rerun compatibility testing')
            if (acceptance.get('failures') != [] or not acceptance.get('runs') or
                    any(run.get('passed') is not True for run in acceptance['runs'])):
                raise ValueError('Native party acceptance contains failed or missing test runs')
            missing = sorted(name for name in required if acceptance.get('cases', {}).get(name) != 'passed')
            if missing:
                raise ValueError('Incomplete native party acceptance: ' + ', '.join(missing))
        result = cls.__new__(cls)
        # Typed admission reads only exact file-backed dependencies; allocating
        # two complete virtual images here adds no evidence and is costly when
        # four isolated peers start together.
        import pefile
        result.reference = reference_image
        result.candidate = pefile.PE(data=after, fast_load=True)
        for image in (result.reference, result.candidate):
            if (image.FILE_HEADER.Machine != 0x8664 or image.OPTIONAL_HEADER.Magic != 0x20b
                    or not 0 < image.OPTIONAL_HEADER.SizeOfImage <= 256 * 1024 * 1024):
                raise ValueError('Typed adapter requires a bounded Windows x64 image')
        result.profile = dict(profile, isolated_candidate=isolated)
        result.exact_addresses, result.typed_fields, result.patch_preconditions = {}, {}, {}
        for row in profile.get('addresses', ()):
            old, new = row['reference'], row['candidate']
            if (type(old) is not int or type(new) is not int
                    or not 0 <= old < result.reference.OPTIONAL_HEADER.SizeOfImage
                    or not 0 <= new < result.candidate.OPTIONAL_HEADER.SizeOfImage
                    or old in result.exact_addresses):
                raise ValueError('Invalid or ambiguous adapter address')
            result.exact_addresses[old] = new
        for row in profile.get('fields', ()):
            domain, old, new = row['domain'], row['reference'], row['candidate']
            if (not isinstance(domain, str) or not domain or type(old) is not int or type(new) is not int
                    or old < 0 or (new < 0 and not domain.endswith('_frame'))  # rbp-relative slots may be negative
                    or (domain, old) in result.typed_fields):
                raise ValueError('Invalid or ambiguous typed adapter field')
            result.typed_fields[domain, old] = new
        for row in profile.get('patches', ()):
            old = row['reference']
            expected, actual = bytes.fromhex(row['expected']), bytes.fromhex(row['candidate_bytes'])
            key = old, expected
            if (not expected or not actual or key in result.patch_preconditions
                    or result.reference.get_data(old, len(expected)) != expected
                    or result.candidate.get_data(result.rva(old), len(actual)) != actual):
                raise ValueError('Adapter patch precondition does not match both executable snapshots')
            result.patch_preconditions[key] = actual
        required = profile.get('required_inputs')
        if (not isinstance(required, dict) or not result.exact_addresses or not result.typed_fields
                or not result.patch_preconditions
                or set(required.get('addresses', ())) != set(result.exact_addresses)
                or {tuple(v) for v in required.get('fields', ())} != set(result.typed_fields)
                or {(v[0], bytes.fromhex(v[1])) for v in required.get('patches', ())} != set(result.patch_preconditions)):
            raise ValueError('Adapter input inventory is incomplete or disagrees with its proof')
        return result

    def rva(self, reviewed_rva):
        if not 0 <= reviewed_rva < self.reference.OPTIONAL_HEADER.SizeOfImage:
            raise ValueError('Address outside reviewed image')
        if hasattr(self, 'exact_addresses'):
            if reviewed_rva not in self.exact_addresses:
                raise ValueError(f'Unresolved adapter address {reviewed_rva:x}')
            return self.exact_addresses[reviewed_rva]
        return self.addresses.translate(reviewed_rva)

    def field(self, domain, reviewed_offset):
        if self.profile.get('runtime_equivalent') is True:
            return reviewed_offset
        try:
            return self.typed_fields[domain, reviewed_offset]
        except KeyError:
            raise ValueError(f'Unresolved adapter field {domain}+{reviewed_offset:x}') from None

    def expected_bytes(self, reviewed_rva, expected):
        """Translate a patch precondition without accepting changed instructions."""
        if self.reference.get_data(reviewed_rva, len(expected)) != expected:
            raise ValueError('Patch precondition does not match reviewed executable')
        if hasattr(self, 'patch_preconditions'):
            try:
                return self.patch_preconditions[reviewed_rva, expected]
            except KeyError:
                raise ValueError(f'Unresolved adapter patch at {reviewed_rva:x}') from None
        actual = self.candidate.get_data(self.rva(reviewed_rva), len(expected))
        if len(actual) != len(expected):
            raise ValueError('Truncated relocated patch')
        return actual

    def pointer(self, image_base, reviewed_rva):
        """An explicit native address operand for generated machine code."""
        return struct.pack('<Q', image_base + self.rva(reviewed_rva))

    def relative_branch(self, reviewed_source, reviewed_target, *, opcode=b'\xe9', size=5):
        """Rebuild a generated rel8/rel32 using both translated endpoints."""
        from updated_layout import branch_bytes
        return branch_bytes(self.rva(reviewed_source), self.rva(reviewed_target), opcode=opcode, size=size)


def candidate_profile(reference, candidate, dependencies):
    """Promote unique function candidates only after whole-image validation."""
    before, after = Path(reference).read_bytes(), Path(candidate).read_bytes()
    if (hashlib.sha256(before).hexdigest() != UPDATED_HASH
            or dependencies.get('reference_sha256') != UPDATED_HASH
            or dependencies.get('sha256') != hashlib.sha256(after).hexdigest()):
        raise ValueError('Dependency evidence belongs to a different executable')
    image, mapped = canonical_runtime_image(before)
    functions = {start: end for start, end, _ in _runtime_functions(image, mapped)[2]}
    moves = {}
    for key, row in dependencies['dependencies'].items():
        original = int(key, 16)
        start = row.get('function')
        if start not in functions or len(row['candidates']) != 1:
            continue
        destination = row['candidates'][0] - original + start
        if destination != start:
            move = (start, destination, functions[start] - start, 'code')
            if start in moves and moves[start] != move:
                raise ValueError('Conflicting function relocation evidence')
            moves[start] = move
    return verify_runtime_moves(before, after, list(moves.values()))
