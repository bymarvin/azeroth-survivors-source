"""Discover hooks and activate only a provably equivalent reviewed runtime."""
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.tools/python'))
import pefile
import capstone

UPDATED_HASH = '20d4ce5fb1232dac64bc00a4d8c9f2bcae43fb8373ea3fa95350ab8c4f20d618'
# Exact game releases with a reviewed adapter profile: sha256 -> (release file, display name).
# Activation still requires the source-bound native acceptance stored in analysis/active-hooks.json.
REVIEWED_RELEASES = {
    'dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306': ('release-0.84.3.json', '0.84.3'),
    '47e4ab65c1ad7366e554171a6a28b0272141664010a50795371129b203111bf2': ('release-47e4ab65.json', '47e4ab65'),
    '0315cf387f4f807512ac965763ed81ae58e7f20dd94547a7541ee8eae3135f66': ('release-0315cf38.json', '0315cf38'),
    '7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30': ('release-7264d50b.json', '7264d50b'),
}
# Reviewed against disassembly and the updated two-client movement smoke test.
# No RVA is needed here. Unknown builds still need gameplay-layout validation.
SIGNATURES = {
    'TICK': bytes.fromhex('554157415641554154565753b8e8200000e8dad12c004829c4488dac2480000000440f29bd50200000440f29b5402000'),
    'SERIALIZE': bytes.fromhex('4157415641554154565755534883ec284c89c6488b7a108d6f0266c1c5084189ee41c1ee08440fb77a184589fc41c1ec'),
    'WRITE': bytes.fromhex('5541565657534883ec40488d6c244048c745f8feffffff4989ceb10131c0f0410fb00e7526488b354c84ec01488b0648'),
}


def unique_entry(sections, signature):
    if len(signature) < 32:
        raise ValueError('Hook signature is too short')
    matches = []
    for rva, data in sections:
        start = 0
        while (offset := data.find(signature, start)) >= 0:
            matches.append(rva + offset)
            start = offset + 1
    if len(matches) != 1:
        raise ValueError(f'Hook needs one exact executable match, found {len(matches)}')
    return matches[0]


def resolve_updated_hooks(binary):
    data = Path(binary).read_bytes()
    if hashlib.sha256(data).hexdigest() != UPDATED_HASH:
        raise ValueError('Unreviewed build; refusing automatic hook activation')
    pe = pefile.PE(data=data, fast_load=True)
    sections = [(s.VirtualAddress, s.get_data()) for s in pe.sections
                if s.Characteristics & 0x20000000]
    return {name: unique_entry(sections, signature) for name, signature in SIGNATURES.items()}


def displacement_size(ins):
    """Use x86 ModRM encoding where Capstone confuses SSE operand-size prefixes.

    A 66 prefix changes SIMD operand width, not its address displacement width.
    Capstone can report disp16 for an encoded RIP-relative disp32 in this case.
    """
    if ins.disp_offset and ins.modrm_offset and ins.addr_size in (4, 8):
        mode, rm = ins.modrm >> 6, ins.modrm & 7
        if mode == 1:
            return 1
        if mode == 2 or mode == 0 and (rm == 5 or rm == 4 and ins.sib & 7 == 5):
            return 4
    return ins.disp_size


def instruction_signature(data, address):
    """Mask relocation operands only; retain registers, field offsets and opcodes."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    pattern, mask = bytearray(), bytearray()
    for ins in decoder.disasm(data, address):
        start = len(pattern)
        pattern.extend(ins.bytes)
        mask.extend(b'\xff' * ins.size)
        spans = []
        if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL):
            if ins.imm_size:
                spans.append((ins.imm_offset, ins.imm_size))
        if any(op.type == capstone.x86.X86_OP_MEM and
               op.mem.base == capstone.x86.X86_REG_RIP for op in ins.operands):
            spans.append((ins.disp_offset, displacement_size(ins)))
        for offset, size in spans:
            mask[start + offset:start + offset + size] = bytes(size)
        if len(pattern) >= 192:
            break
    if sum(bool(v) for v in mask) < 48:
        raise ValueError('Insufficient fixed instruction bytes')
    return bytes(pattern), bytes(mask)


def signature_candidates(sections, pattern, mask):
    if (len(pattern) != len(mask) or len(pattern) > 256
            or any(v not in (0, 255) for v in mask) or sum(bool(v) for v in mask) < 48):
        raise ValueError('Invalid masked signature')
    # Search the longest fixed run first; verify every other fixed byte too.
    runs = list(re.finditer(b'\xff+', mask))
    anchor = max(runs, key=lambda m: m.end() - m.start())
    needle = pattern[anchor.start():anchor.end()]
    result = []
    for rva, data in sections:
        cursor = 0
        while (hit := data.find(needle, cursor)) >= 0:
            cursor = hit + 1
            start = hit - anchor.start()
            if start >= 0 and start + len(pattern) <= len(data) and all(
                    not keep or data[start + i] == pattern[i] for i, keep in enumerate(mask)):
                result.append(rva + start)
    return result


def discover_manifest(binary, manifest, *, data=None):
    if data is None:
        data = Path(binary).read_bytes()
    pe = pefile.PE(data=data, fast_load=True)
    sections = [(s.VirtualAddress, s.get_data()) for s in pe.sections
                if s.Characteristics & 0x20000000]
    rows = {}
    for name, entry in manifest['hooks'].items():
        matches = signature_candidates(sections, bytes.fromhex(entry['pattern']), bytes.fromhex(entry['mask']))
        rows[name] = dict(candidates=matches, unique=len(matches) == 1)
    return dict(sha256=hashlib.sha256(data).hexdigest(), hooks=rows,
                automatic_activation_allowed=False,
                reason='Instruction matches do not verify gameplay layouts or calling conventions')


def canonical_runtime_image(data):
    """Permit packaging/rebase updates: every normalized mapped byte is identical.

    COFF timestamp, optional-header checksum and the certificate-directory entry
    do not describe game logic. All code, resources, data, unwind tables, imports,
    relocations, image layout and remaining header bytes stay in the digest.
    Normalize the preferred image base and loader relocation values together:
    a correctly rebased executable has the same runtime at a given load address.
    The relocation table itself remains in the digest, as do all RVA layouts.
    The unmapped overlay (including Authenticode certificates) is excluded.
    """
    pe = pefile.PE(data=data, fast_load=True)
    if (pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B
            or not 0 < pe.OPTIONAL_HEADER.SizeOfImage <= 256 * 1024 * 1024):
        raise ValueError('Unsupported executable format or image size')
    mapped = bytearray(pe.get_memory_mapped_image(max_virtual_address=256 * 1024 * 1024))
    # Parse only the loader's base-relocation directory. Do not mask arbitrary
    # absolute-looking numbers: they could be changed gameplay constants.
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    cursor, end = directory.VirtualAddress, directory.VirtualAddress + directory.Size
    if end > len(mapped):
        raise ValueError('Truncated loader relocation directory')
    relocations = []
    while cursor < end:
        if cursor + 8 > end:
            raise ValueError('Truncated loader relocation block')
        page, size = struct.unpack_from('<II', mapped, cursor)
        if size < 8 or size % 2 or cursor + size > end:
            raise ValueError('Invalid loader relocation block size')
        for (entry,) in struct.iter_unpack('<H', mapped[cursor + 8:cursor + size]):
            kind, offset = entry >> 12, page + (entry & 0xFFF)
            if kind == 0:  # IMAGE_REL_BASED_ABSOLUTE is alignment padding.
                continue
            if kind != 10:  # The reviewed x64 image uses DIR64 only.
                raise ValueError('Unsupported loader relocation type')
            relocations.append(offset)
        cursor += size
    previous_end = pe.OPTIONAL_HEADER.SizeOfHeaders
    for offset in sorted(relocations):
        if (offset < previous_end or offset + 8 > len(mapped)
                or offset < end and offset + 8 > directory.VirtualAddress):
            raise ValueError('Invalid or overlapping loader relocation')
        previous_end = offset + 8
        value = struct.unpack_from('<Q', mapped, offset)[0]
        struct.pack_into('<Q', mapped, offset, (value - pe.OPTIONAL_HEADER.ImageBase) & 0xFFFFFFFFFFFFFFFF)
    fields = [(pe.FILE_HEADER.get_field_absolute_offset('TimeDateStamp'), 4),
              (pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'), 4),
              (pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(), 8),
              (pe.OPTIONAL_HEADER.get_field_absolute_offset('ImageBase'), 8)]
    for offset, size in fields:
        mapped[offset:offset + size] = bytes(size)
    return pe, mapped


def runtime_fingerprint(data):
    return hashlib.sha256(canonical_runtime_image(data)[1]).hexdigest()


def compatibility_report(binary, manifest):
    if manifest['reference_sha256'] != UPDATED_HASH:
        raise ValueError('Unexpected hook reference build')
    data = Path(binary).read_bytes()
    report = discover_manifest(binary, manifest, data=data)
    report['runtime_fingerprint'] = runtime_fingerprint(data)
    equivalent = report['runtime_fingerprint'] == manifest.get('runtime_fingerprint')
    # A hook that moved while the rest of the image allegedly stayed equivalent
    # is inconsistent: embedded patch/data RVAs are part of this adapter too.
    exact = report['hooks'].keys() == manifest['hooks'].keys() and all(
                row['candidates'] == [manifest['hooks'][name]['reference_rva']]
                for name, row in report['hooks'].items())
    allowed = bool(report['hooks']) and exact and (report['sha256'] == UPDATED_HASH or equivalent)
    report.update(automatic_activation_allowed=allowed,
                  status=('reviewed' if report['sha256'] == UPDATED_HASH else 'runtime_equivalent')
                  if allowed else 'verification_required',
                  reason=('All hooks and mapped gameplay bytes match the reviewed runtime'
                          if allowed else 'Code/layout changes or ambiguous hooks require a verified adapter update'))
    return report


def write_report(path, report):
    """Concurrent clients never see half-written activation/discovery metadata."""
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    try:
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        first_error = None
        for attempt in range(6):
            try:
                temporary.replace(path)
                break
            except PermissionError as error:
                # Windows readers/OneDrive can briefly deny atomic replacement
                # when several peers publish the same verified profile at once.
                if first_error is None:
                    first_error = error
                if attempt == 5:
                    raise first_error
                time.sleep(min(0.05 * 2 ** attempt, 0.5))
    finally:
        temporary.unlink(missing_ok=True)


# A player's check of a reviewed build takes seconds; another window holding the lock longer is hung or stuck.
RESOLVER_WAIT_SECONDS = 120
# progress(stage, detail) for callers without their own (the hook import and run() inside a game session):
# the launcher sets it so a wait for another window is visible instead of a frozen status (0.0.24).
WAIT_PROGRESS = None


def resolve_reviewed_profile(binary, *, allow_runtime_relocation=False, report_directory=None, progress=None, developer_discovery=False):
    """Serialize discovery, native acceptance and publication across launchers."""
    try:
        if not __debug__:
            raise RuntimeError('Compatibility checks require assertions; restart Python without -O or PYTHONOPTIMIZE')
        binary = Path(binary).resolve()
        directory = Path(report_directory).resolve() if report_directory is not None else ROOT / 'analysis'
        # ponytail: serialize per workspace while analysis outputs are shared;
        # split locks only after every discovery output is isolated per attempt.
        lock_directory = ROOT / 'analysis'
        lock_directory.mkdir(parents=True, exist_ok=True)
        requested_at = time.time_ns()
        identity = probe_identity(binary)
        if not developer_discovery and identity['sha256'] not in (UPDATED_HASH,
                '72b51b222171059029eb762ce800c97614ea94f88de7c14543c5236a6fc34743', *REVIEWED_RELEASES):
            raise ValueError('This game build needs a matching co-op update. Install the co-op release for this executable.')
        request = dict(binary=str(binary), report_directory=str(directory),
                       allow_runtime_relocation=allow_runtime_relocation, developer_discovery=developer_discovery, identity=identity)
        outcome_path = lock_directory / 'resolver-attempt.json'
        from coop_lock import FolderLock
        waited = False
        report = progress if progress is not None else WAIT_PROGRESS

        def waiting(text):
            nonlocal waited
            waited = True
            if report is not None:
                report('waiting', text)
        lock = FolderLock(lock_directory / 'compatibility-resolver.lock', 'compatibility check')
        lock.acquire(timeout=7200 if developer_discovery else RESOLVER_WAIT_SECONDS, progress=waiting,
                     waiting_text='Waiting for {owner} in this folder to finish its compatibility check ({seconds} s)… '
                                  'If nothing else is running, close all co-op windows and start again.',
                     busy_text='The compatibility check waited {seconds} s: {path} is held by {owner}. Close all co-op '
                               'windows and start again; if none is open, end the leftover "python.exe" of Azeroth '
                               'Survivors Together in Task Manager.')
        try:
            if probe_identity(binary) != identity:
                raise ValueError('Game or resolver changed while waiting for compatibility; retry with the current files')
            if waited:
                try:
                    outcome = json.loads(outcome_path.read_text())
                except (OSError, ValueError):
                    outcome = {}
                # Only clients which actually waited for this same attempt
                # share its failure. A later explicit retry runs normally.
                if (outcome.get('request') == request and outcome.get('status') == 'failed'
                        and outcome.get('finished_at', 0) >= requested_at):
                    raise ValueError('The concurrent compatibility check failed: ' + outcome.get('error', 'Unknown failure'))
            try:
                # Re-read and fully validate active-hooks after acquiring
                # the lock; never return another process's unvalidated data.
                result = _resolve_reviewed_profile(binary, allow_runtime_relocation=allow_runtime_relocation,
                    report_directory=directory, progress=progress)
                if probe_identity(binary) != identity:
                    raise ValueError('Game or resolver changed during compatibility verification; retry')
            except Exception as error:
                try:
                    write_report(outcome_path, dict(request=request, status='failed', finished_at=time.time_ns(), error=str(error)))
                except OSError:
                    pass  # Preserve the real verification error if reporting also fails.
                raise
            write_report(outcome_path, dict(request=request, status='passed', finished_at=time.time_ns()))
            return result
        finally:
            lock.release()
    except Exception as error:
        if progress is not None:
            progress('failure', str(error))
        raise


def _resolve_reviewed_profile(binary, *, allow_runtime_relocation=False, report_directory=None, progress=None):
    def notify(stage, detail):
        if progress is not None:
            progress(stage, detail)
    notify('checking', 'Checking the game against verified co-op profiles.')
    report_directory = Path(report_directory) if report_directory is not None else ROOT / 'analysis'
    report_directory.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    report = compatibility_report(binary, manifest)
    if report.get('sha256') == '72b51b222171059029eb762ce800c97614ea94f88de7c14543c5236a6fc34743':
        try:
            previous = json.loads((report_directory / 'active-hooks.json').read_text())
        except (OSError, ValueError):
            raise ValueError('Install the matching verified co-op update for game 0.77.6') from None
        return adapter_launch_profile(binary, previous, isolated=False)
    if report.get('sha256') in REVIEWED_RELEASES:
        release_file, release_name = REVIEWED_RELEASES[report['sha256']]
        reviewed = json.loads((ROOT / 'reconstruction' / release_file).read_text())
        try:
            active = json.loads((report_directory / 'active-hooks.json').read_text())['adapter_profile']
        except (OSError, ValueError, KeyError):
            raise ValueError(f'Install the matching verified co-op update for game {release_name}') from None
        profile = reviewed['adapter_profile']
        if {k: v for k, v in active.items() if k not in ('identity', 'native_acceptance')} != profile:
            raise ValueError(f'The installed {release_name} co-op profile does not match its reviewed release')
        profile.update(identity=active.get('identity'), native_acceptance=active.get('native_acceptance'))
        result = adapter_launch_profile(binary, reviewed, isolated=False)
        notify('ready', f'Verified co-op profile is ready for game {release_name}.')
        return result
    if not report['automatic_activation_allowed']:
        try:
            cached = json.loads((report_directory / 'active-hooks.json').read_text())
            if cached.get('status') == 'verified_adapter':
                # Keep discovery metadata; a cache hit is not a new activation.
                report = dict(cached, **adapter_launch_profile(binary, cached, isolated=False))
        except (OSError, ValueError, KeyError) as error:
            report['cached_adapter_error'] = str(error)
    write_report(report_directory / 'updated-hook-discovery.json', report)
    if not report['automatic_activation_allowed']:
        notify('discovering', 'Looking for verified hook and dependency matches in the changed game.')
        baseline = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        if baseline.is_file():
            # Offline evidence only. Even completely matched function bodies do
            # not certify referenced data tables or generated machine-code patches.
            sys.path.insert(0, str(ROOT / 'analysis'))
            from check_build_hooks import embedded_references
            from map_build_functions import dependency_relocations
            image = pefile.PE(str(binary), fast_load=True)
            targets = [int(row['rva'], 16) for row in embedded_references(ROOT / 'reconstruction', image)]
            try:
                dependencies = dependency_relocations(baseline, binary, targets)
                dependency_path = report_directory / 'dependency-relocations.json'
                write_report(dependency_path, dependencies)
                report['dependency_report'] = os.path.relpath(dependency_path, ROOT)
                from runtime_addresses import AddressMap, candidate_profile
                proof = candidate_profile(baseline, binary, dependencies)
                if proof['sha256'] != report['sha256']:
                    raise ValueError('Executable changed while checking relocation profile')
                report['relocation_profile'] = proof
                if allow_runtime_relocation:
                    addresses = AddressMap(proof['moves'])
                    for name, entry in manifest['hooks'].items():
                        rva = addresses.translate(entry['reference_rva'])
                        row = report['hooks'][name]
                        if rva not in row['candidates']:
                            raise ValueError('Verified relocation is missing its reviewed hook signature')
                        row['discovered_candidates'] = row['candidates']
                        row.update(candidates=[rva], unique=True)
                    report.update(automatic_activation_allowed=True, status='verified_runtime_relocation',
                                  reason='Whole mapped image equivalent under verified runtime address translation')
                else:
                    report['reason'] = 'Runtime relocation verified; adapter address translation is not enabled'
            except (ValueError, OSError) as error:
                report['dependency_error'] = str(error)
            if not report['automatic_activation_allowed']:
                from map_build_functions import structural_profile
                evidence = structural_profile(baseline, binary)
                if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != report['sha256']:
                    raise ValueError('Executable changed during structural discovery')
                candidate_path = report_directory / 'candidate-compatibility.json'
                candidate = dict(sha256=report['sha256'], reference_sha256=UPDATED_HASH,
                    automatic_activation_allowed=False, status='dependency_verification_pending',
                    functions=evidence,
                    adapter_inputs={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in sorted((ROOT / 'reconstruction').glob('*.py'))},
                    unresolved_contracts=['Complete code/data dependency closure',
                        'Interior patch live registers and stack ownership',
                        'Typed structure member spans and native ownership',
                        'Isolated four-player gameplay acceptance'])
                from runtime_addresses import game_field_candidates
                contracts = json.loads((ROOT / 'analysis/native-contract-baseline.json').read_text())
                if contracts['reference_sha256'] != UPDATED_HASH:
                    raise ValueError('Native contract baseline belongs to a different executable')
                requested = [int(row[0], 16) for name, row in contracts['structures']['game'].items()
                             if isinstance(row, list) and not name.endswith('_size')]
                candidate['game_fields'] = game_field_candidates(evidence, requested)
                # A changed menu is a separate native contract, not permission
                # to waive the remaining combat/ownership dependencies.
                from menu_contracts import discover_menu_contract
                try:
                    candidate['menu_contract'] = discover_menu_contract(baseline, binary, evidence)
                except ValueError as error:
                    candidate['menu_contract_error'] = str(error)
                from native_helper_contracts import discover_helper_contracts
                try:
                    candidate['helper_contracts'] = discover_helper_contracts(
                        baseline, binary, evidence, menu=candidate.get('menu_contract'))
                except ValueError as error:
                    candidate['helper_contract_error'] = str(error)
                from effect_contracts import discover_effect_contract
                try:
                    candidate['effect_contract'] = discover_effect_contract(baseline, binary, evidence)
                except ValueError as error:
                    candidate['effect_contract_error'] = str(error)
                from enemy_contracts import discover_enemy_contract
                try:
                    candidate['enemy_contract'] = discover_enemy_contract(baseline, binary, evidence)
                except ValueError as error:
                    candidate['enemy_contract_error'] = str(error)
                from native_helper_contracts import discover_pause_call_contracts
                try:
                    candidate['pause_call_contract'] = discover_pause_call_contracts(baseline, binary, evidence)
                except ValueError as error:
                    candidate['pause_call_contract_error'] = str(error)
                from native_helper_contracts import discover_callable_contracts
                try:
                    candidate['callable_contracts'] = discover_callable_contracts(baseline, binary, evidence)
                    progression = candidate['callable_contracts'].get('scoped_progression', {})
                    if progression.get('sha256') == report['sha256'] and progression.get('entries'):
                        candidate['progression_call_contract'] = progression
                except ValueError as error:
                    candidate['callable_contract_error'] = str(error)
                from native_helper_contracts import discover_boss_call_contract
                try:
                    candidate['boss_call_contract'] = discover_boss_call_contract(baseline, binary, evidence)
                except ValueError as error:
                    candidate['boss_call_contract_error'] = str(error)
                from native_helper_contracts import discover_damage_call_contract
                try:
                    candidate['damage_call_contract'] = discover_damage_call_contract(baseline, binary, evidence)
                except ValueError as error:
                    candidate['damage_call_contract_error'] = str(error)
                from native_helper_contracts import discover_state_call_contracts
                try:
                    candidate['state_call_contract'] = discover_state_call_contracts(baseline, binary, evidence)
                except ValueError as error:
                    candidate['state_call_contract_error'] = str(error)
                candidate['hook_discovery'] = structural_hook_summary(manifest, evidence,
                                                                     menu=candidate.get('menu_contract'))
                report['structural_hook_discovery'] = candidate['hook_discovery']
                from runtime_addresses import compile_adapter_profile
                try:
                    command = ('import sys,json;sys.path.insert(0,' + repr(str(ROOT / 'analysis')) + ');'
                               'from inventory_native_contracts import runtime_inputs;print(json.dumps(runtime_inputs()))')
                    inventory_run = subprocess.run([sys.executable, '-c', command], cwd=ROOT,
                        capture_output=True, text=True, timeout=60, check=True,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                    inputs = json.loads(inventory_run.stdout)
                    contract_names = ('menu_contract', 'helper_contracts', 'effect_contract', 'pause_call_contract',
                                      'progression_call_contract', 'boss_call_contract', 'damage_call_contract',
                                      'state_call_contract', 'callable_contracts')
                    candidate['adapter_profile'] = compile_adapter_profile(baseline, binary, evidence,
                        {name: candidate[name] for name in contract_names if name in candidate}, inputs)
                except (ValueError, subprocess.SubprocessError) as error:
                    candidate['adapter_compile_error'] = str(error)
                notify('testing', 'Testing discovered entry hooks in a temporary game profile. Gameplay checks follow only after their contracts are verified.')
                candidate['native_observation'] = test_observation_candidate(
                    binary, report_directory, candidate_calls='pause_call_contract' in candidate,
                    progression_calls='pause_call_contract' in candidate and 'progression_call_contract' in candidate,
                    boss_calls=all(name in candidate for name in ('pause_call_contract', 'progression_call_contract', 'boss_call_contract')),
                    damage_calls=all(name in candidate for name in ('pause_call_contract', 'progression_call_contract', 'boss_call_contract', 'damage_call_contract')))
                from runtime_addresses import observed_game_field_candidates, scoped_game_field_candidates
                field_sources = dict(evidence)
                progression = candidate.get('progression_call_contract', {})
                entries = dict(progression.get('entries', {}), choice_consumption=progression.get('choice_consumption', {}))
                for key in ('boss_call_contract', 'damage_call_contract', 'state_call_contract'):
                    entries.update(candidate.get(key, {}).get('entries', {}))
                for name, proof in entries.items():
                    fields = [row for row in proof.get('game_fields', ()) if row.get('alias_proven')]
                    if fields:
                        field_sources['call:' + name] = dict(game_field_evidence=dict(
                            method='scoped native helper with proved Game aliases', fields=fields))
                candidate['game_fields'] = observed_game_field_candidates(field_sources, requested, candidate['native_observation'])
                candidate['game_fields'] = scoped_game_field_candidates(candidate['game_fields'],
                    {key: candidate[key] for key in ('progression_call_contract', 'boss_call_contract', 'damage_call_contract')
                     if key in candidate}, report['sha256'])
                write_report(candidate_path, candidate)
                if (candidate.get('adapter_profile', {}).get('adapter_contracts_verified') is True
                        and candidate['native_observation'].get('status') == 'passed'):
                    candidate['native_acceptance'] = test_adapter_candidate(
                        binary, candidate_path, report_directory, progress=notify)
                    candidate['adapter_profile']['native_acceptance'] = candidate['native_acceptance']
                    write_report(candidate_path, candidate)
                    try:
                        report = adapter_launch_profile(binary, candidate, isolated=False)
                    except ValueError as error:
                        candidate['unresolved_contracts'] = [str(error), *candidate['native_acceptance'].get('failures', ())]
                        write_report(candidate_path, candidate)
                report['candidate_profile'] = os.path.relpath(candidate_path, ROOT)
                report['structurally_matched_functions'] = sum(row['unique_structure'] for row in evidence.values())
                report['static_adapter_verified'] = candidate.get('adapter_profile', {}).get('adapter_contracts_verified') is True
                if report['static_adapter_verified'] and not report['automatic_activation_allowed']:
                    report['reason'] = 'Static compatibility verified; native co-op acceptance is incomplete'
                report['contract_failures'] = candidate_failures(candidate)
    write_report(report_directory / 'updated-hook-discovery.json', report)
    if not report['automatic_activation_allowed']:
        unresolved = [name for name, row in report.get('structural_hook_discovery', report.get('hooks', {})).items()
                      if len(row.get('candidates', ())) != 1]
        details = [report.get('reason', 'Gameplay compatibility needs verification')]
        if unresolved:
            details.append('Unresolved hooks: ' + ', '.join(sorted(unresolved)))
        if report.get('dependency_error') and not report.get('static_adapter_verified'):
            details.append('Dependency verification: ' + report['dependency_error'])
        if report.get('contract_failures'):
            details.append('Adapter contracts: ' + '; '.join(report['contract_failures']))
        if not (ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe').is_file():
            details.append('Install a matching verified co-op update; new-build analysis requires the development reference')
        raise ValueError('Build not activated. ' + '; '.join(details))
    active = report_directory / 'active-hooks.json'
    try:
        previous = json.loads(active.read_text())
    except (OSError, ValueError):
        previous = None
    if (isinstance(previous, dict) and previous.get('automatic_activation_allowed') is True
            and previous != report):
        write_report(report_directory / 'previous-verified-hooks.json', previous)
    write_report(active, report)
    notify('ready', 'Verified co-op hooks are ready for this game build.')
    # This is the activated local profile, not permission for a different hash.
    # Re-evaluate the executable and manifest on every process launch.
    return report


def load_isolated_adapter_profile(binary, path, *, with_runtime=False):
    """Load a source-bound candidate for disposable acceptance, never activate it."""
    return adapter_launch_profile(binary, json.loads(Path(path).read_text()), isolated=True,
                                  with_runtime=with_runtime)


def adapter_launch_profile(binary, candidate, *, isolated, with_runtime=False):
    """Revalidate byte snapshots, exact mappings and acceptance on each launch."""
    from runtime_addresses import RuntimeAddresses
    profile = candidate['adapter_profile']
    runtime = RuntimeAddresses.from_adapter_profile(
        ROOT / 'reconstruction/reference-metadata.json', binary, profile, isolated=isolated)
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    hooks = {name: dict(candidates=[runtime.rva(row['reference_rva'])], unique=True)
             for name, row in manifest['hooks'].items()}
    menu = candidate.get('menu_contract')
    if (not menu or menu.get('sha256') != profile['sha256']
            or menu.get('reference_sha256') != UPDATED_HASH or not menu.get('menu_contract_verified')):
        raise ValueError('Candidate party menus lack a matching verified contract')
    report = dict(sha256=profile['sha256'], status='isolated_adapter_candidate' if isolated else 'verified_adapter',
                image_size=runtime.candidate.OPTIONAL_HEADER.SizeOfImage,
                hooks=hooks, adapter_profile=profile, menu_contract=menu,
                automatic_activation_allowed=not isolated)
    return (report, runtime) if with_runtime else report


def earned_gear_fixture(home):
    """Reuse a real native award, never manufacture an equipment inventory."""
    for number in range(2, 5):
        events = [json.loads(line) for line in (home / f'group-online-{number}.jsonl').read_text().splitlines()]
        save = home / f'player-{number}/characters.txt'
        if save.is_file() and any(row.get('event') == 'independent_boss_reward'
                and row.get('class_id') == 1 and 101800 in row.get('items', []) for row in events):
            return save
    raise ValueError('No Warrior weapon was awarded by native loot rolls; retry compatibility testing to obtain an equipment fixture.')


def test_adapter_candidate(binary, path, directory, *, progress=None):
    """Run existing native party diagnostics against a fully admitted candidate.

    Only assertions actually made by each diagnostic contribute acceptance.
    Missing scenarios remain pending and cannot activate a profile.
    """
    import msvcrt
    import shutil
    from native_test_process import run_verifier
    from coop_transport import create_pairing
    load_isolated_adapter_profile(binary, path)
    identity = probe_identity(binary)
    directory = Path(directory)
    result = dict(identity=identity, cases={}, runs=[], failures=[])
    destination = directory / 'native-adapter-acceptance.json'
    parent = ROOT / 'coop-lab/compatibility-tests'
    parent.mkdir(parents=True, exist_ok=True)
    with (directory / 'native-adapter.lock').open('a+b') as lock:
        if lock.seek(0, 2) == 0:
            lock.write(b'0')
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise RuntimeError('Another four-player compatibility test is running') from None
        try:
            suites = (
                ('pause-revival', 'verify_group_online.py', ['--verify-coop'],
                 ('pause_resume', 'revival', 'shared_xp', 'four_player_combat', 'independent_talents')),
                ('boss-rewards', 'verify_network_boss.py', [], ('bosses', 'independent_loot', 'map_progression', 'saves')),
                ('room-menus', 'verify_room_launch.py', ['--players', '4', '--automatic-menus',
                 '--expect-classes', '1', '8', '3', '4', '--expect-map', 'duskwood',
                 '--guest-request-map', 'elwynn', '--observe-gear'], ('concurrent_menus', 'host_map')),
                ('room-gear', 'verify_room_launch.py', ['--players', '4', '--automatic-gear'], ('class_gear_selection',)),
                ('menu-departure', 'verify_room_departure.py', ['--players', '4', '--automatic'],
                 ('guest_departure', 'host_shutdown')),
                ('movement', 'verify_group_online.py', ['--require-movement'], ('four_player_movement',)),
                ('economy', 'verify_group_online.py', ['--verify-economy'], ('shared_gold',)),
                ('victory-continue', 'verify_network_boss.py', ['--victory-command', '8'], ('victory_keep_fighting',)),
                ('victory-new-hero', 'verify_network_boss.py', ['--victory-command', '9'], ('victory_new_hero',)),
                ('fall-unlock', 'verify_network_boss.py', ['--fall-before-victory'], ('fall_revival_unlock',)),
                ('lan', 'verify_next_run.py', ['--lan'], ('lan_mode', 'lan_offline')),
                ('next-run', 'verify_next_run.py', [], ('next_run',)),
                ('next-run-defeat', 'verify_next_run.py', ['--defeat'], ('next_run_after_defeat',)),
                ('next-run-relay', 'verify_next_run.py', ['--relay'], ('next_run_relay', 'victory_new_hero_relay')),
                ('melee-run', 'verify_group_online.py', ['--verify-melee-run'], ('host_melee_while_running',)),
            )
            boss_home = None
            for name, script, arguments, cases in suites:
                if probe_identity(binary) != identity:
                    raise ValueError('Game or adapter sources changed during party acceptance')
                home = Path(tempfile.mkdtemp(prefix=name + '-', dir=parent))
                create_pairing(home / 'pairing')
                snapshot = home / 'candidate-profile.json'
                shutil.copyfile(path, snapshot)
                if progress:
                    progress('testing', f'Testing four-player {name} with disposable saves.')
                environment = dict(os.environ, COOP_EXECUTABLE=str(Path(binary).resolve()), COOP_BUILD='updated',
                    COOP_CANDIDATE_PROFILE=str(snapshot), COOP_CANDIDATE_HOME=str(home),
                    COOP_TEST_WINDOW_CORNERS='1')
                if name == 'movement':
                    # Native client diagnostic input; only received, changing
                    # client packets can satisfy the movement assertion.
                    environment['WOW_ROGUE_KEY'] = 'w@3'
                    environment['COOP_VERIFY_NATIVE_MOVEMENT'] = '1'
                log = home / 'verification.log'
                timed_out = False
                with log.open('w', encoding='utf-8') as output:
                    try:
                        if name in ('room-menus', 'room-gear') and boss_home is None:
                            output.write('Host-map test needs a verified native boss victory save; boss acceptance failed.\n')
                            passed = False
                        else:
                            if name == 'room-menus':
                                arguments = [*arguments, '--profile-save', f'1:{boss_home / "player-1/characters.txt"}']
                            elif name == 'room-gear':
                                fixture = earned_gear_fixture(boss_home)
                                # Reusing earned inventory tests independent equipment choices;
                                # it is not counted as four new loot awards.
                                arguments = [*arguments, *[value for n in range(1, 5)
                                    for value in ('--profile-save', f'{n}:{fixture}')]]
                            tested = run_verifier([str(ROOT / 'reconstruction' / script), *arguments],
                                cwd=ROOT, env=environment, stdout=output,
                                timeout=1200 if name in ('boss-rewards', 'fall-unlock') else
                                1800 if name.startswith('next-run') or name == 'lan' else
                                720 if name == 'melee-run' else 420)
                            passed = tested.returncode == 0
                    except subprocess.TimeoutExpired:
                        passed = False
                        timed_out = True
                    except ValueError as error:
                        output.write(str(error) + '\n')
                        passed = False
                patterns = (('room-player-*.jsonl',) if script.startswith(('verify_room_', 'verify_next_run')) else
                            ('group-online-*.jsonl', 'network-boss-*.txt' if script == 'verify_network_boss.py'
                             else 'group-network-*.txt'))
                for pattern in patterns:
                    for source in (ROOT / 'analysis').glob(pattern):
                        shutil.copyfile(source, home / source.name)
                result['runs'].append(dict(name=name, passed=passed, evidence=str(home.relative_to(ROOT))))
                if not passed:
                    result['failures'].append(f'{name} failed; see {log.relative_to(ROOT)}')
                else:
                    result['cases'].update(dict.fromkeys(cases, 'passed'))
                    if name == 'boss-rewards':
                        boss_home = home
                result['status'] = 'failed' if result['failures'] else 'partial'
                write_report(destination, result)
                # A timed-out child may still own native processes. Do not
                # overlap another suite; ordinary assertion failures are safe
                # to continue and collect the remaining independent evidence.
                if timed_out:
                    break
            if probe_identity(binary) != identity:
                raise ValueError('Game or adapter sources changed during party acceptance')
            result['status'] = 'failed' if result['failures'] else 'partial'
            write_report(destination, result)
            return result
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def resolve_reviewed_hooks(binary):
    report = resolve_reviewed_profile(binary)
    return {name: row['candidates'][0] for name, row in report['hooks'].items()}


def structural_hook_summary(manifest, functions, *, menu=None):
    """Separate address discovery from compatibility; neither implies the other."""
    result = {}
    for name, hook in manifest['hooks'].items():
        target = hex(hook['reference_rva'])
        owner = next((row for row in functions.values() if target in row['targets']), None)
        candidates, kind = [], 'unresolved'
        if owner:
            interior = owner.get('interior_candidates', {}).get(target, {})
            candidates = interior.get('candidates', [])
            if owner.get('unique_structure'):
                kind = 'matching_function_structure'
            elif candidates:
                kind = 'matching_local_instructions_only'
            if name == 'TICK' and owner.get('unique_entry_contract'):
                candidates = [row['rva'] for row in owner['entry_contract_candidates'] if row['verified_header']]
                kind = 'server_header_only'
            if name == 'HUD_DELIVER':
                hud = [row for row in owner.get('hud_contracts', ()) if row.get('local_abi_roles')]
                if len(hud) == 1:
                    candidates = [hud[0]['rva']]
                    kind = 'hud_call_with_runtime_owner_guard'
        if name == 'UI_COMMAND' and menu and menu.get('menu_contract_verified'):
            candidates = [hex(menu['ui_command'])]
            kind = 'scoped_native_menu_contract'
        result[name] = dict(candidates=candidates, evidence=kind, gameplay_verified=False)
    return result


def candidate_failures(candidate):
    """Name the missing evidence rather than asking users to bless offsets."""
    if candidate.get('adapter_profile', {}).get('adapter_contracts_verified') is True:
        observation = candidate.get('native_observation', {})
        if observation.get('status') != 'passed':
            return [observation.get('reason', 'Isolated native call verification is pending')]
        acceptance = candidate.get('native_acceptance', {})
        return acceptance.get('failures') or ['Complete four-player native acceptance is still required']
    failures = []
    missing = [name for name, row in candidate['game_fields'].items() if not row['unique']]
    if missing:
        failures.append('Game members without a unique typed mapping: ' + ', '.join(missing))
    changed = [name for name, row in candidate['hook_discovery'].items()
               if row['evidence'] != 'matching_function_structure']
    if changed:
        failures.append('Changed function/interior contracts still need proof: ' + ', '.join(changed))
    if candidate.get('menu_contract_error'):
        failures.append('Menu: ' + candidate['menu_contract_error'])
    for failure in candidate.get('helper_contracts', {}).get('unresolved', ()):
        failures.append('Native helper: ' + str(failure))
    if candidate.get('helper_contract_error'):
        failures.append('Native helper: ' + candidate['helper_contract_error'])
    if candidate.get('effect_contract_error'):
        failures.append('Guest effects: ' + candidate['effect_contract_error'])
    if candidate.get('callable_contract_error'):
        failures.append('Native calls: ' + candidate['callable_contract_error'])
    if candidate.get('state_call_contract_error'):
        failures.append('Character/reward state: ' + candidate['state_call_contract_error'])
    failures.extend('Character/reward state ' + row['function'] + ': ' + row['reason']
                    for row in candidate.get('state_call_contract', {}).get('unresolved', ()))
    if candidate.get('adapter_compile_error'):
        failures.append('Adapter preparation: ' + candidate['adapter_compile_error'])
    failures.extend(candidate.get('adapter_profile', {}).get('unresolved_contracts', ()))
    for name, row in candidate.get('callable_contracts', {}).get('callables', {}).items():
        if not row.get('verified_unique'):
            reasons = sorted({value.get('reason', 'No unique dependency proof')
                              for value in row.get('candidates', ()) if not value.get('verified')})
            failures.append(f'Native {name}: ' + '; '.join(reasons or ['Missing or ambiguous callable proof']))
    if candidate.get('enemy_contract_error'):
        failures.append('Enemy ownership: ' + candidate['enemy_contract_error'])
    for failure in candidate.get('enemy_contract', {}).get('unresolved', ()):
        failures.append('Enemy ownership: ' + str(failure))
    observation = candidate.get('native_observation')
    if observation and observation['status'] != 'passed':
        failures.append('Isolated entry test: ' + observation['reason'])
    failures.extend(candidate['unresolved_contracts'])
    return failures


def probe_identity(binary):
    sources = sorted((ROOT / 'reconstruction').glob('*.py')) + sorted((ROOT / 'analysis').glob('*.py'))
    sources += [ROOT / 'relay' / name for name in ('routing.py', 'client.py', 'server.py')]
    sources += [path for path in (ROOT / 'reconstruction/reviewed-hooks.json',
                ROOT / 'analysis/native-contract-baseline.json') if path.is_file()]
    sources.append(ROOT / 'reconstruction/reference-metadata.json')
    sources += sorted((ROOT / 'reconstruction').glob('release-*.json'))
    return dict(sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                reference_sha256=UPDATED_HASH, python=sys.version,
                disassembler=capstone.__version__, pe_parser=pefile.__version__,
                sources={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})


def test_observation_candidate(binary, report_directory, *, candidate_calls=False, progression_calls=False, boss_calls=False, damage_calls=False):
    """Automatically test only the statically admitted bootstrap in isolation.

    This evidence never certifies gameplay and cannot activate a profile. The
    OS file lock prevents simultaneous launchers running duplicate native tests.
    """
    import msvcrt
    if damage_calls and not boss_calls:
        raise ValueError('Damage test requires the native boss test')
    if boss_calls and not progression_calls:
        raise ValueError('Boss test requires the native progression test')
    if progression_calls and not candidate_calls:
        raise ValueError('Progression test requires the native call test')
    binary, directory = Path(binary).resolve(), Path(report_directory)
    def identity():
        return dict(probe_identity(binary), candidate_calls=candidate_calls, progression_calls=progression_calls,
                    boss_calls=boss_calls, damage_calls=damage_calls)
    before = identity()
    with (directory / 'native-observation.lock').open('a+b') as lock:
        if lock.seek(0, 2) == 0:
            lock.write(b'0')
            lock.flush()
        deadline = time.monotonic() + 240
        while True:
            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('Another compatibility test is still running. Retry after it finishes.')
                time.sleep(.25)
        try:
            if identity() != before:
                raise ValueError('Game or resolver changed while waiting for native verification; retry')
            destination = directory / 'native-observation-result.json'
            try:
                cached = json.loads(destination.read_text())
            except (OSError, ValueError):
                cached = {}
            if cached.get('identity') == before and cached.get('status') == 'passed':
                return cached
            result = dict(identity=before, status='failed', gameplay_verified=False,
                          automatic_activation_allowed=False)
            with tempfile.TemporaryDirectory(prefix='coop-observation-evidence-') as temporary:
                log = Path(temporary) / 'events.jsonl'
                environment = dict(os.environ, COOP_EXECUTABLE=str(binary), COOP_BUILD='updated')
                try:
                    mode = ['--test-update-calls', '--bounded-cleanup'] if candidate_calls else ['--observe-update']
                    if progression_calls:
                        mode = ['--test-update-progression', '--bounded-cleanup']
                    if boss_calls:
                        mode = ['--test-update-boss', '--bounded-cleanup']
                    if damage_calls:
                        mode = ['--test-update-damage', '--bounded-cleanup']
                    run = subprocess.run([sys.executable, str(ROOT / 'reconstruction/native_probe.py'),
                        *mode, '--seconds', '60', '--observation-report', str(log)],
                        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=180,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                    rows = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                    starts = [row for row in rows if row.get('event') == 'observation_start']
                    summaries = [row for row in rows if row.get('event') == 'observation_summary']
                    required = {'TICK', 'SERIALIZE', 'WRITE', 'HUD_DELIVER'}
                    passed = (run.returncode == 0 and len(starts) == len(summaries) == 1
                              and starts[0].get('sha256') == before['sha256']
                              and required <= summaries[0].get('hits', {}).keys()
                              and all(summaries[0]['hits'][name] > 0 for name in required)
                              and any(row.get('event') == 'observation_hud_owner'
                                      and row.get('server_matches') and row.get('fields_match') for row in rows)
                              and summaries[0].get('batch_hits', 0) > 0
                              and any(row.get('event') == 'observation_batch_layout'
                                      and all(row.get(key) for key in ('server_matches', 'connection_matches',
                                          'packet_arguments_match', 'ui_bounds_valid')) for row in rows)
                              and not any(row.get('event') == 'native_crash' for row in rows))
                    calls = [row for row in rows if row.get('event') == 'candidate_call_test_summary']
                    if candidate_calls:
                        passed = passed and len(calls) == 1 and all(
                            set(calls[0].get(key, ())) == {'PAUSE', 'RESUME'} for key in ('returned', 'messages'))
                        passed = passed and calls[0].get('identity_unchanged') is True
                    if progression_calls:
                        passed = passed and calls[0].get('progression_complete') is True
                    if boss_calls:
                        passed = passed and calls[0].get('boss_complete') is True
                    if damage_calls:
                        passed = passed and calls[0].get('damage_complete') is True
                    if passed:
                        result.update(status='passed', hits=summaries[0]['hits'], batch_hits=summaries[0]['batch_hits'],
                                      field_observations=[row for row in rows if row.get('event') == 'observation_game_field'],
                                      unobserved_sites=summaries[0].get('unobserved_sites', []),
                                      scope='Entry ABI, HUD/connection ownership, batch frame and sampled Game operands only; bounded cleanup, not normal quit')
                        if candidate_calls:
                            result.update(pause_resume_verified=True, native_call_results=calls[0],
                                          scope=result['scope'] + '; native pause/resume phases, returns and serialized menu messages verified')
                        if progression_calls:
                            result.update(progression_verified=True,
                                scope=result['scope'] + '; native XP, level increase and offered ability name/rank consumption verified')
                        if boss_calls:
                            result.update(boss_spawn_verified=True,
                                scope=result['scope'] + '; native boss spawn, matching model/health packet and boss announcement verified')
                        if damage_calls:
                            result.update(damage_verified=True,
                                scope=result['scope'] + '; dispatch-guarded native boss damage/death and matching world/UI outputs verified')
                    else:
                        result['reason'] = ('Required native observations were not completed. '
                                            'See native-observation-events.json for the last stage.')
                        errors = [line.strip() for line in getattr(run, 'stderr', '').splitlines()
                                  if line.startswith(('ValueError:', 'RuntimeError:', 'OSError:', 'TimeoutError:'))]
                        if errors:
                            result['reason'] = errors[-1][:800]
                        result['process_exit_code'] = run.returncode
                    write_report(directory / 'native-observation-events.json', rows)
                except subprocess.TimeoutExpired:
                    result['reason'] = 'Temporary game test exceeded three minutes; close any stalled test window and retry.'
            if identity() != before:
                raise ValueError('Game or resolver changed during native verification; retry with stable files')
            write_report(destination, result)
            return result
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def discover_observation_profile(binary, *, candidate_calls=False, progression_calls=False, boss_calls=False, damage_calls=False):
    if damage_calls and not boss_calls:
        raise ValueError('Damage observation requires isolated boss calls')
    if boss_calls and not progression_calls:
        raise ValueError('Boss observation requires isolated progression calls')
    if progression_calls and not candidate_calls:
        raise ValueError('Progression observation requires isolated candidate calls')
    """Resolve entry breakpoints for read-only diagnostics, never gameplay calls."""
    sys.path.insert(0, str(ROOT / 'analysis'))
    from map_build_functions import (structural_relocations, tick_entry_contract, unwind_ranges,
                                    hud_delivery_contracts, batch_write_contracts, server_vector_contracts)
    reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
    before_data, after_data = reference.read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(before_data).hexdigest() != UPDATED_HASH:
        raise ValueError('Observation reference changed')
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    targets = {name: manifest['hooks'][name]['reference_rva'] for name in ('TICK', 'SERIALIZE', 'WRITE')}
    rows = structural_relocations(reference, binary, targets.values())
    before, after = pefile.PE(data=before_data, fast_load=True), pefile.PE(data=after_data, fast_load=True)
    old_ends, new_ends = dict(unwind_ranges(before)), dict(unwind_ranges(after))
    hooks = {}
    for name in ('SERIALIZE', 'WRITE'):
        row = rows[hex(targets[name])]
        matches = [c for c in row['candidates'] if c['structure_equivalent']]
        if len(matches) != 1:
            raise ValueError(f'Observation hook {name} is missing or ambiguous')
        hooks[name] = int(matches[0]['rva'], 16)
    tick = targets['TICK']
    original = tick_entry_contract(before.get_data(tick, old_ends[tick] - tick), tick)
    candidates = set()
    row = rows[hex(tick)]
    candidates.update(int(c['rva'], 16) for c in row['candidates'] if c['structure_equivalent'])
    candidates.update(int(c['rva'], 16) for c in row.get('call_graph_candidates', ()) if c['distinct_anchors'] >= 2)
    contracts = {address: tick_entry_contract(after.get_data(address, new_ends[address] - address), address)
                 for address in candidates}
    valid = [address for address, contract in contracts.items() if contract['verified_header']]
    if not original['verified_header'] or len(valid) != 1:
        raise ValueError('Observation server/time entry contract is missing or ambiguous')
    hooks['TICK'] = valid[0]
    for name, address in hooks.items():
        prefix = b'\x41\x57' if name == 'SERIALIZE' else b'\x55'
        if address not in new_ends or after.get_data(address, len(prefix)) != prefix:
            raise ValueError(f'Observation {name} entry cannot be emulated safely')
    hud = None
    if 'HUD_DELIVER' in manifest['hooks']:
        old_hud = hud_delivery_contracts(before.get_data(tick, old_ends[tick] - tick), tick)
        new_hud = hud_delivery_contracts(after.get_data(valid[0], new_ends[valid[0]] - valid[0]), valid[0])
        if (len(old_hud) != 1 or len(new_hud) != 1
                or int(old_hud[0]['rva'], 16) != manifest['hooks']['HUD_DELIVER']['reference_rva']):
            raise ValueError('Observation HUD callback contract is missing or ambiguous')
        hud = new_hud[0]
        hooks['HUD_DELIVER'] = int(hud['rva'], 16)
        if after.get_data(hooks['HUD_DELIVER'], 3) != b'\xff\x50\x20':
            raise ValueError('Observation HUD callback encoding changed')
    digest = hashlib.sha256(after_data).hexdigest()
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != digest:
        raise ValueError('Game changed during observation discovery')
    report = dict(sha256=digest, reference_sha256=UPDATED_HASH, status='observation_only',
                  image_size=after.OPTIONAL_HEADER.SizeOfImage,
                  automatic_activation_allowed=False, hooks={name: dict(candidates=[address]) for name, address in hooks.items()},
                  entry_contract=contracts[valid[0]], restrictions='Entry/register observation only; no gameplay calls or activation')
    if hud is not None:
        report['hud_contract'] = hud
        batches, vectors = [], []
        for pe, address, ends, serialize, write in ((before, tick, old_ends, targets['SERIALIZE'], targets['WRITE']),
                (after, valid[0], new_ends, hooks['SERIALIZE'], hooks['WRITE'])):
            code = pe.get_data(address, ends[address] - address)
            batch = batch_write_contracts(code, address, serialize, write)
            vector = server_vector_contracts(code, address)
            if len(batch) != 1 or len(vector) != 1:
                raise ValueError('Observation batch/connection contract is missing or ambiguous')
            batches.append(batch[0])
            vectors.append(vector[0])
        if (batches[0]['ui_vector']['element_size'] != batches[1]['ui_vector']['element_size']
                or vectors[0]['element_size'] != vectors[1]['element_size']):
            raise ValueError('Observation native container element layout changed')
        report.update(batch_contract=batches[1], connection_contract=vectors[1])
        if 'ENEMY_TARGET' in manifest['hooks']:
            from map_build_functions import structural_profile
            structure = structural_profile(reference, binary)
            game_calls = structure[hex(tick)].get('game_contracts', [])
            if len(game_calls) != 1:
                raise ValueError('Observation embedded Game ownership is missing or ambiguous')
            game = game_calls[0]
            entry = int(game['update_rva'], 16)
            if after.get_data(entry, 1) != b'\x55':
                raise ValueError('Observation Game entry instruction changed')
            sites = {hex(entry): dict(kind='game_entry', expected='55')}
            owner = next((row for row in structure.values()
                          if any(c['rva'] == hex(entry) for c in row.get('candidates', ()))), None)
            frames = owner.get('saved_game_frames', []) if owner else []
            if len(frames) != 1:
                raise ValueError('Observation saved Game frame is missing or ambiguous')
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            decoder.detail = True
            for use in owner.get('reload_game_field_candidates', ()):
                address = int(use['new_rva'], 16)
                instruction = next(decoder.disasm(after.get_data(address, 15), address), None)
                if instruction is None or not any(op.type == capstone.x86.X86_OP_MEM
                        and instruction.reg_name(op.mem.base) == use['base'] and not op.mem.index
                        and op.mem.disp == use['new_offset'] for op in instruction.operands):
                    raise ValueError('Observation field operand no longer matches its candidate')
                site = dict(kind='game_field', expected=instruction.bytes.hex(), **use)
                if hex(address) in sites and sites[hex(address)] != site:
                    raise ValueError('Conflicting observation field sites')
                sites[hex(address)] = site
            damage = structure.get(hex(manifest['hooks']['DAMAGE']['reference_rva']), {})
            pointer_uses = list(damage.get('conditional_pointer_immediates', ()))
            pointer_uses += list(owner.get('conditional_pointer_immediates', ()))
            for use in pointer_uses:
                address = int(use['new_rva'], 16)
                if after.get_data(address, len(bytes.fromhex(use['expected']))).hex() != use['expected']:
                    raise ValueError('Observation pointer instruction changed')
                if hex(address) in sites:
                    raise ValueError('Conflicting observation pointer sites')
                sites[hex(address)] = dict(kind='game_pointer', base=use['register'], **use)
            from runtime_addresses import game_field_candidates
            baseline_fields = json.loads((ROOT / 'analysis/native-contract-baseline.json').read_text())
            requested = [int(value[0], 16) for name, value in baseline_fields['structures']['game'].items()
                         if isinstance(value, list) and not name.endswith('_size')]
            missing = {int(key, 16) for key, value in game_field_candidates(structure, requested).items()
                       if not value['unique']}
            for row in (owner, damage):
                for use in row.get('conditional_game_accesses', ()):
                    if use['old_offset'] not in missing or use['new_rva'] in sites:
                        continue
                    address = int(use['new_rva'], 16)
                    if after.get_data(address, len(bytes.fromhex(use['expected']))).hex() != use['expected']:
                        raise ValueError('Conditional Game observation instruction changed')
                    sites[use['new_rva']] = dict(kind='game_candidate_field', base=use['register'], **use)
            if len(sites) > 512:
                raise ValueError('Observation site count exceeds its bound')
            report.update(game_contract=game, game_frame=frames[0], observation_sites=sites)
            if candidate_calls:
                from native_helper_contracts import discover_pause_call_contracts
                contract = discover_pause_call_contracts(reference, binary, structure)
                if contract['sha256'] != digest or not contract.get('isolated_candidate_calls_only'):
                    raise ValueError('Candidate call contract belongs to a different executable')
                report['candidate_call_contract'] = contract
                if progression_calls:
                    from native_helper_contracts import discover_progression_call_contracts
                    progression = discover_progression_call_contracts(reference, binary, structure)
                    if progression['sha256'] != digest or not progression.get('isolated_candidate_calls_only'):
                        raise ValueError('Progression call contract belongs to a different executable')
                    report['progression_call_contract'] = progression
                    contract['entries'].update(progression['entries'])
                if boss_calls:
                    from native_helper_contracts import discover_boss_call_contract
                    boss = discover_boss_call_contract(reference, binary, structure)
                    if boss['sha256'] != digest or not boss.get('isolated_candidate_calls_only'):
                        raise ValueError('Boss call contract belongs to a different executable')
                    report['boss_call_contract'] = boss
                    contract['entries'].update(boss['entries'])
                if damage_calls:
                    from native_helper_contracts import discover_damage_call_contract
                    damage = discover_damage_call_contract(reference, binary, structure)
                    if damage['sha256'] != digest or not damage.get('isolated_candidate_calls_only'):
                        raise ValueError('Damage call contract belongs to a different executable')
                    report['damage_call_contract'] = damage
                    contract['entries'].update(damage['entries'])
                for name, entry in contract['entries'].items():
                    report['hooks'][name] = dict(candidates=[entry['entry']], unique=True)
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != digest:
        raise ValueError('Game changed during observation contract discovery')
    write_report(ROOT / 'analysis/observation-candidate.json', report)
    return report
