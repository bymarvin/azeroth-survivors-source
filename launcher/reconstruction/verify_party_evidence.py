"""Evidence checks for real native party traffic; synthetic poses never count."""
import math

from sessions import decode_ground_movement
from world_packets import UPDATE, HOST, Reader, objects, remap_combat


def native_pending_field(contract, kind):
    mapping = contract['pending_by_choice_kind']
    return mapping.get(kind, mapping.get(str(kind)))


def attack_actor(opcode, body):
    reader = Reader(body, remap_enabled=False)
    if opcode == 0x143:
        return reader.guid(False)
    if opcode == 0x14A:
        reader.take(4)
        return reader.guid()
    if opcode in (0x131, 0x132):
        return reader.guid()
    return None


def verify_party_combat(recordings):
    host = recordings[0]
    for recipient in (2, 3, 4):
        received = {(r['opcode'], r['digest']) for r in recordings[recipient-1]
                    if r['event'] == 'world_delivered'}
        assert any(r['event'] == 'world_captured' and r['recipient'] == recipient
                   and (r['opcode'], r['digest']) in received
                   and attack_actor(r['opcode'], bytes.fromhex(r['body'])) == HOST for r in host), \
            (recipient, 'native host attack missing')
    delivered = [{(r['opcode'], r['body']) for r in rows
                  if r['event'] == 'network_attack_written'} for rows in recordings]
    for source in (2, 3, 4):
        native = [r for r in recordings[source-1] if r['event'] == 'native_guest_combat']
        computed = {r['target'] for r in recordings[source-1]
                    if r['event'] == 'native_guest_damage_computed' and r['damage'] > 0}
        hits = [r for r in host if r['event'] == 'network_guest_hit_verified'
                and r['player'] == source and r['target'] in computed and r['applied'] > 0]
        assert hits, f'Guest {source} has no native damage applied to a living host enemy'
        for recipient in range(1, 5):
            if recipient == source:
                continue
            assert any((r['opcode'], remap_combat(r['opcode'], bytes.fromhex(r['body']),
                       player_guid=0xFF0100+source, local_guid=0xFF0100+recipient).hex())
                       in delivered[recipient-1] for r in native), (source, recipient, 'native attack missing')
        # Host-captured health update must actually reach every guest, rather
        # than being inferred from local mirror damage or a transport ACK.
        for recipient in (2, 3, 4):
            received = {r['digest'] for r in recordings[recipient-1] if r['event'] == 'world_delivered'}
            shared = False
            for packet in host:
                if (packet['event'] != 'world_captured' or packet['recipient'] != recipient
                        or packet['opcode'] != UPDATE or packet['digest'] not in received):
                    continue
                for block in objects(bytes.fromhex(packet['body']), remap=False):
                    if any(block.guid == hit['target'] and 22 in block.fields
                           and block.fields[22] <= math.ceil(max(0, hit['after'])) for hit in hits):
                        shared = True
            assert shared, (source, recipient, 'shared native enemy HP missing')
    return {'host_native_combat': True, 'guest_native_combat': True, 'shared_enemy_health': True, 'attack_packets': True}


def verify_independent_talents(recordings):
    selections = []
    for number, rows in enumerate(recordings, 1):
        choices = [r for r in rows if r['event'] == 'network_talent_verified'
                   and r['player'] == number and r['rank_verified']]
        assert choices, f'Player {number} has no independently verified native ability choice'
        assert all(r['pending_before'] - r['pending_after'] == 1 for r in choices)
        assert any(r['event'] == 'native_talent_spent' and r['player'] == number for r in rows)
        selections.append([(r['selected'], r['title']) for r in choices])
    # Selection is performed separately against each peer's actual offer;
    # identical lucky rolls are valid and need not be artificially changed.
    return {'independent_native_talents': True, 'selections': selections}


def verify_real_movement(recordings, minimum_distance=.25):
    diagnostic = any(r['event'] == 'native_input_test_installed' for rows in recordings for r in rows)
    for source, rows in enumerate(recordings, 1):
        packets = [r for r in rows if r['event'] == 'native_movement' and r['player'] == source]
        if diagnostic:
            presses = [r for r in rows if r['event'] == 'native_input_ready_press' and r['player'] == source]
            releases = [r for r in rows if r['event'] == 'native_input_test_path'
                        and r['player'] == source and r['stage'] == 'release']
            assert len(presses) == len(releases) == 1, (source, 'missing gated native input pair')
            press, release = presses[0], releases[0]
            assert press['phase'] == 1 and set(press['ready']) == set(press['loaded']) == {1,2,3,4}
            start, end = press['monotonic'], release['monotonic']
            assert math.isfinite(start) and math.isfinite(end) and 0 < end-start <= 10
            assert all(math.isfinite(r.get('monotonic', float('nan'))) for r in packets)
            before = [r for r in packets if r['monotonic'] < start]
            # Retain one genuine baseline, then only packets during the native
            # hold or its bounded delivery allowance. Late unrelated input is
            # real movement but cannot satisfy this automatic diagnostic.
            packets = before[-1:] + [r for r in packets if start <= r['monotonic'] <= end+1]
        poses = [decode_ground_movement(bytes.fromhex(r['body'])) for r in packets]
        changing = [(a, b) for a, b in zip(poses, poses[1:])
                    if sum((x-y)**2 for x, y in zip((a.x,a.y,a.z), (b.x,b.y,b.z))) >= minimum_distance**2]
        # Small continuous steps also count once their accumulated displacement
        # from the first real client packet crosses the threshold.
        if poses:
            changing += [(poses[0], b) for b in poses[1:] if sum((x-y)**2 for x, y in
                zip((poses[0].x,poses[0].y,poses[0].z), (b.x,b.y,b.z))) >= minimum_distance**2]
        assert changing, f'Player {source} has no real native movement; operator input is still required'
        for recipient in range(1, 5):
            if recipient == source:
                continue
            remote = {tuple(r['pose']) for r in recordings[recipient-1]
                      if r['event'] == 'remote_pose' and r['player'] == source and not r.get('synthetic', True)}
            assert any(tuple(a.__dict__.values()) in remote and tuple(b.__dict__.values()) in remote
                       for a, b in changing), (source, recipient, 'native movement not delivered')
    return {'real_native_movement': True, 'source': 'native client packets', 'gated_native_input': diagnostic}
