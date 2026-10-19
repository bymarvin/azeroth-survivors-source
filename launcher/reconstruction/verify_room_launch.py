"""Four local processes join a directory room and launch only after host Start."""
import json
import argparse
import multiprocessing as mp
import os
import socket
import struct
import sys
from pathlib import Path
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def menu_build():
    """'47e4' for the 0.92.0 executable (moved Armory button), else the 0.84.3 menu."""
    import hashlib
    executable = Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe'))
    return '47e4' if hashlib.sha256(executable.read_bytes()).hexdigest().startswith(('47e4ab65', '0315cf38', '7264d50b')) else '0843'


def native_menu_taps(class_id, guest=False, zone='elwynn', equip_claymore=False, build=None):
    # Observed native 1100x700 menu coordinates. Native output assertions below
    # are mandatory: coordinates alone never establish the selected class.
    position = {1: '135,190', 8: '135,319', 3: '248,190', 4: '135,254'}[class_id]
    if equip_claymore and class_id != 1:
        raise ValueError('Observed Worn Claymore equipment route requires Warrior')
    map_position = {'elwynn': '908,220', 'duskwood': '908,329'}[zone]
    # Readiness/cadence are gated on the native producer, not a fixed startup
    # delay. A finite native Enter tail retries until the server acknowledges.
    selection = ([position, map_position, position] if guest else [position, map_position])
    if equip_claymore:
        # Native UI observed on a genuinely awarded Warrior save: Armory,
        # Collection, Worn Claymore, Equip, Done. No item values are written.
        # 0.92.0 (build 47e4): Armory button moved to 378..547 x 370..410; Collection, item, Equip and Done
        # unchanged (frames coop-lab/port-re/out/frames-roomgear3 of a passed room-gear run).
        armory = '462,390' if (build or menu_build()) == '47e4' else '464,353'
        selection[1:1] = [armory, '510,80', '773,185', '874,239', '1046,79']
    return ';'.join(selection + ['605,605'] * 20)


def gear_record(data, schema):
    assert len(data) == schema['size']
    appearances = []
    for slot in range(schema['slots']):
        offset = slot * schema['appearance_stride']
        tag = struct.unpack_from('<I', data, offset + schema['appearance_tag'])[0]
        assert tag in (0, 1), 'Invalid native appearance option'
        appearances.append(struct.unpack_from('<I', data, offset + schema['appearance_id'])[0] if tag else None)
    return dict(class_id=data[schema['class_id']], appearances=appearances,
                items=list(struct.unpack_from('<' + 'I' * schema['slots'], data, schema['items'])))


def verify_selected_gear(recordings, expected, require_baseline=False):
    assert {n for n, slot, item in expected} == set(range(1, len(recordings) + 1)), \
        'Every player needs an explicit gear expectation'
    for number, rows in enumerate(recordings, 1):
        entered = [r for r in rows if r['event'] == 'native_enter_gear']
        loaded = [r['gear'] for r in rows if r['event'] == 'native_login_gear']
        assert entered and len(loaded) == 1, (number, 'Native Enter/login gear observation missing')
        selected = entered[-1]['gear']
        if selected is None:
            assert entered[-1].get('absent_record') is True
            assert loaded[0]['class_id'] == entered[-1]['class_id']
            assert loaded[0]['items'] == [0] * 19 and loaded[0]['appearances'] == [None] * 19, \
                (number, 'Native absent-class default gear changed')
        else:
            assert selected == loaded[0], (number, 'Native selected gear changed on login')
        if require_baseline:
            baseline = [(i, r) for i, r in enumerate(rows) if r['event'] == 'native_initial_gear'
                        and r['player'] == number and r['before_enter']]
            assert len(baseline) == 1, (number, 'Initial native equipment observation missing')
            index, initial = baseline[0]
            assert initial['class_id'] == loaded[0]['class_id'] == 1
            if initial['gear'] is None:
                assert initial.get('absent_record') is True
            else:
                assert initial['gear']['class_id'] == 1 and initial['gear']['items'] == [0] * 19, \
                    (number, 'Fixture was already equipped')
            first_enter = next(i for i, r in enumerate(rows) if r['event'] == 'native_enter_gear')
            assert index < first_enter, (number, 'Equipment baseline was captured too late')
            assert initial['time_ns'] < entered[0]['time_ns'], (number, 'Invalid equipment observation times')
        for player, slot, item in expected:
            if player == number:
                if item == 0:
                    assert slot is None and loaded[0]['items'] == [0] * 19, (number, 'Player should remain unequipped')
                else:
                    matched = (loaded[0]['items'].count(item) == 1 if slot is None else
                               loaded[0]['items'][slot] == item)
                    assert item > 0 and matched, (number, slot, 'Expected gear was not selected')
    return dict(gear_selection_verified=True)


def verify_player_fields(recordings):
    from world_packets import objects, SELF
    sources = {}
    for number, rows in enumerate(recordings, 1):
        captured = [r for r in rows if r['event'] == 'native_player_create' and r['player'] == number]
        assert len(captured) == 1, (number, 'Missing native character creation')
        blocks = objects(bytes.fromhex(captured[0]['body']), remap=False)
        assert len(blocks) == 1 and blocks[0].guid == SELF and blocks[0].object_type == 4
        sources[number] = {k: v for k, v in blocks[0].fields.items() if k not in (0, 1)}
    for recipient, rows in enumerate(recordings, 1):
        for source in sources.keys() - {recipient}:
            writes = [r for r in rows if r['event'] == 'remote_player_create_written'
                      and r['recipient'] == recipient and r['player'] == source]
            assert writes, (source, recipient, 'Character was never written to native output')
            for write in writes:
                blocks = objects(bytes.fromhex(write['body']), remap=False)
                assert len(blocks) == 1 and blocks[0].guid == 0xFF0100 + source and blocks[0].object_type == 4
                actual = {k: v for k, v in blocks[0].fields.items() if k not in (0, 1)}
                assert actual == sources[source], (source, recipient, 'Native character fields changed')
    return dict(gear_replication_verified=True, native_character_fields_preserved=True)


def verify_menu_selection(recordings, zone=None, classes=None, guest_request=None):
    loaded = []
    routes = {}
    for number, rows in enumerate(recordings, 1):
        maps = [r for r in rows if r['event'] == 'party_map_loaded' and r['player'] == number]
        assert maps, (number, 'Native world was not loaded')
        assert len({(r['zone'], r['class_id']) for r in maps}) == 1, (number, 'Loaded map/class changed')
        loaded.append(maps[0])
        if classes:
            assert maps[0]['class_id'] == classes[number-1], (number, 'Personal class selection was lost')
        if guest_request and number != 1:
            host_zone = maps[0]['zone']
            assert guest_request != host_zone, 'Conflicting-map acceptance requires different maps'
            selected_class = maps[0]['class_id']
            logins = [(i, r) for i, r in enumerate(rows) if r['event'] == 'guest_login_map_verified'
                      and r.get('player') == number]
            assert logins and all(r['zone'] == host_zone for i, r in logins), (number, 'Host map not verified at native login')
            login = logins[0][0]
            assert login < rows.index(maps[0]), (number, 'Loaded world preceded verified login')
            enters = [(i, r) for i, r in enumerate(rows[:login]) if r['event'] == 'diagnostic_menu_selection'
                      and r.get('player') == number and r['enter']]
            assert enters, (number, 'Native Enter observation missing')
            enter, selection = enters[-1]
            assert selection['class_id'] == selected_class, (number, 'Class changed between Enter and login')
            enforced = [i for i, r in enumerate(rows[:login]) if r['event'] == 'guest_map_enforced'
                        and r.get('player') == number and r['zone'] == host_zone]
            assert enforced, (number, 'Host map enforcement missing before login')
            if selection['zone'] == guest_request:
                routes[number] = 'conflicting-enter-enforced'
            else:
                assert selection['zone'] == host_zone, (number, 'Unexpected guest Enter map')
                previews = [i for i, r in enumerate(rows[:enter]) if r['event'] == 'diagnostic_menu_selection'
                            and r.get('player') == number and not r['enter'] and r['zone'] == guest_request
                            and r['class_id'] == selected_class]
                assert any(preview < enforce < enter for preview in previews for enforce in enforced), \
                    (number, 'No ordered conflicting preview, host preset and Enter evidence')
                routes[number] = 'preset-before-enter'
    assert len({r['zone'] for r in loaded}) == 1, loaded
    if zone:
        assert loaded[0]['zone'] == zone, loaded
        assert any(r['event'] == 'host_map_selected' and r['zone'] == zone for r in recordings[0]), \
            'Host native map selection missing'
    return dict(host_map=loaded[0]['zone'], native_classes=[r['class_id'] for r in loaded],
                conflicting_guest_selection_verified=bool(guest_request), guest_map_routes=routes,
                gear_selection_verified=False)


def verify_character_names(recordings):
    identities = {}
    for number, rows in enumerate(recordings, 1):
        own = [r for r in rows if r['event'] == 'character_name_registered' and r['player'] == number]
        assert len(own) == 1, (number, 'Native character identity missing')
        identities[number] = own[0]
    for number, rows in enumerate(recordings, 1):
        replies = [r for r in rows if r['event'] == 'remote_character_name_written']
        assert {r['player'] for r in replies} == set(identities) - {number}, (number, replies)
        for reply in replies:
            source = identities[reply['player']]
            expected = struct.pack('<Q', 0xFF0100 + reply['player']) + bytes.fromhex(source['body'])[8:]
            assert reply['recipient'] == number and bytes.fromhex(reply['body']) == expected
            assert reply['name'] == source['name']
    return dict(native_character_names_verified=True)


def verify_concurrent_menus(recordings):
    previews, enters = [], []
    for number, rows in enumerate(recordings, 1):
        events = [r for r in rows if r['event'] == 'diagnostic_menu_selection' and r['player'] == number]
        preview = [r['time_ns'] for r in events if not r['enter']]
        enter = [r['time_ns'] for r in events if r['enter']]
        assert preview and enter, (number, 'Native menu preview and Enter observations required')
        previews.append(min(preview))
        enters.append(min(enter))
    assert max(previews) < min(enters), 'Not all native menus were available before first Enter'
    return dict(concurrent_native_menus_verified=True)


def member(url, number, pipe, menus, observe_gear=False, menu_taps=None, profile_save=None):
    from room_client import RoomClient
    import native_probe
    import struct
    original_run = native_probe.run

    def bounded_run(seconds, players, bridge, **kwargs):
        folder = (native_probe._candidate_home / f'player-{number}' if native_probe._candidate_home else
                  ROOT / f'coop-lab/bridge-updated-player-{number}')
        if profile_save:
            original = Path(profile_save).read_bytes()
            if not original.startswith(b'RSE1:'):
                raise ValueError('Native menu fixture must be an encrypted game save')
            folder = ((native_probe._candidate_home or ROOT / 'coop-lab') /
                      f'room-menu-{uuid.uuid4().hex[:10]}-player-{number}')
            folder.mkdir()
            (folder / 'characters.txt').write_bytes(original)
            bridge.profile_folder = folder
            bridge.record(event='diagnostic_save_staged', player=number, folder=str(folder))
        if menu_taps:
            os.environ['WOW_ROGUE_TAPS'] = menu_taps
            bridge.autostart = False
            if folder.exists():
                native_probe.ensure_windowed(folder)
            if (folder / 'config.toml').exists():
                import re
                config = (folder / 'config.toml').read_text()
                resolution = re.findall(r'(?m)^gxResolution\s*=\s*"([^"]+)"', config)
                if resolution != ['1100x700']:
                    raise ValueError('Automatic native menu taps require the observed 1100x700 viewport')
            if number == 1:
                original_poll = bridge.poll_network
                def bounded_menu_play():
                    original_poll()
                    if (bridge.ready == set(bridge.members) and bridge.host_clock is not None
                            and bridge.host_clock >= 10):
                        bridge.stop_requested = True
                bridge.poll_network = bounded_menu_play
        gear = None
        if observe_gear:
            sys.path.insert(0, str(ROOT / 'analysis'))
            from menu_contracts import discover_gear_observation
            from build_hooks import UPDATED_HASH
            if bridge.menu_contract is None:
                raise ValueError('Gear observation requires a discovered current native menu contract')
            gear = discover_gear_observation(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe',
                                            native_probe.EXECUTABLE, bridge.menu_contract)
        original_call = type(bridge).__call__
        def observed_menu(self, client, rva, context):
            if gear and rva == native_probe.TICK:
                site = client.base + gear['login']['rva']
                expected = bytes.fromhex(gear['login']['expected'])
                if client.memory(site, len(expected)) != expected:
                    raise ValueError('Native gear observation instruction changed')
                client.breakpoints[site] = expected
                client.patch(site, b'\xcc')
            if gear and rva == gear['login']['rva']:
                client.disable_hooks.add(rva)
                pointer = native_probe.q(context, 160) + gear['login']['output_offset']
                stack = native_probe.q(context, 152)
                if not stack <= pointer <= stack + gear['login']['frame_size'] - gear['schema']['size']:
                    raise ValueError('Gear observation left the native caller stack')
                self.record(event='native_login_gear', player=number,
                            gear=gear_record(client.memory(pointer, gear['schema']['size']), gear['schema']))
                return
            if rva == native_probe.MAP_SELECT:
                from updated_layout import reviewed_rva
                config = native_probe.q(context, 184)
                pointer, size = struct.unpack('<QQ', client.memory(config + 0x20, 16))
                if not 1 <= size <= 16:
                    raise ValueError('Invalid native menu map')
                enter = native_probe.q(client.memory(native_probe.q(context, 152), 8)) - client.base == (
                    self.menu_contract['host_map_return'] if self.menu_contract else reviewed_rva(0x53cb7fe))
                self.record(event='diagnostic_menu_selection', player=number,
                            zone=client.memory(pointer, size).decode('ascii'),
                            class_id=client.memory(config + 0x38, 1)[0],
                            enter=enter, time_ns=time.monotonic_ns())
                if enter:
                    self._menu_enter_observed = True
                class_id = client.memory(config + 0x38, 1)[0]
                initial = gear and not enter and class_id == 1 and not getattr(self, '_gear_baseline_recorded', False)
                if gear and (enter or initial):
                    schema, account = gear['schema'], native_probe.q(context, 136)
                    pointer = native_probe.q(client.memory(account + schema['account_pointer'], 8))
                    count = native_probe.q(client.memory(account + schema['account_count'], 8))
                    if count > 32:
                        raise ValueError('Native per-class gear array exceeds bound')
                    records = [gear_record(client.memory(pointer + i * schema['size'], schema['size']), schema)
                               for i in range(count)]
                    matches = [r for r in records if r['class_id'] == class_id]
                    if len(matches) > 1:
                        raise ValueError('Duplicate native class gear records')
                    selected = matches[0] if matches else None
                    if initial:
                        self._gear_baseline_recorded = True
                        self.record(event='native_initial_gear', player=number, before_enter=True,
                                    class_id=class_id, gear=selected, absent_record=not matches,
                                    time_ns=time.monotonic_ns())
                    if enter:
                        self.record(event='native_enter_gear', player=number, class_id=class_id,
                                    gear=selected, absent_record=not matches, time_ns=time.monotonic_ns())
            return original_call(self, client, rva, context)
        type(bridge).__call__ = observed_menu
        original_batch = bridge.before_batch
        def batch(client, context):
            if bridge.native_states[client.number][0] == 2:
                game = client.server + 0x10
                if client.memory(game + native_probe.game_field(0x8BF), 1)[0] != 2:
                    return original_batch(client, context)
                count = struct.unpack('<Q', client.memory(game + native_probe.game_field(0x618), 8))[0]
                assert 1 <= count <= 16
                client.call_before(context, native_probe.CHOOSE, game, (number - 1) % count)
                return True
            return original_batch(client, context)
        bridge.before_batch = batch
        duration = 300 if menus else 110
        callback = bridge
        if menu_taps:
            from verify_native_input import NativeMenuDiagnostic
            callback = NativeMenuDiagnostic(bridge, menu_taps)
        return original_run(duration if number == 1 else duration + 60, players, callback, **kwargs)

    native_probe.run = bounded_run
    client = RoomClient(url, diagnostic_autostart=not menus, isolated_profile=True)
    try:
        if number == 1:
            with socket.create_server(('127.0.0.1', 0)) as available:
                port = available.getsockname()[1]
            client.create('Native room test', 'Host', False, '127.0.0.1', port)
            pipe.send(client.room['id'])
            assert pipe.recv() == 'start'
            client.action('start')
        else:
            client.join(f'Guest {number}', pipe.recv())
            pipe.send('joined')
        threading.Thread(target=client.heartbeat, daemon=True).start()
        deadline = time.monotonic() + (420 if menus else 200)
        while not client.launched and not client.error and time.monotonic() < deadline:
            time.sleep(.1)
        while client.worker and client.worker.is_alive() and time.monotonic() < deadline:
            time.sleep(.2)
        assert client.launched and client.worker and not client.worker.is_alive(), 'Room launch timed out'
        assert client.error is None, client.error
        pipe.send('passed')
    except Exception as error:
        pipe.send(str(error))
        raise
    finally:
        client.stopped.set()
        client.cancel.set()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--players', type=int, choices=(2, 3, 4), default=4)
    parser.add_argument('--menus', action='store_true')
    parser.add_argument('--automatic-menus', action='store_true', help='Use native touch diagnostics to choose four different classes')
    parser.add_argument('--automatic-gear', action='store_true',
                        help='Equip real earned Warrior Worn Claymore through the observed native armory UI')
    parser.add_argument('--expect-map', choices=('elwynn', 'duskwood', 'wsg', 'ab', 'feralas', 'arena', 'av', 'brm', 'aq'))
    parser.add_argument('--expect-classes', type=int, nargs='+')
    parser.add_argument('--guest-request-map', help='Require evidence that guests selected this conflicting map')
    parser.add_argument('--expect-gear', action='append', metavar='PLAYER:SLOT:ITEM', default=[],
                        help='Require an actual native nondefault item choice for every player')
    parser.add_argument('--observe-gear', action='store_true', help='Record native selected/login gear without claiming nondefault selection')
    parser.add_argument('--profile-save', action='append', default=[], metavar='PLAYER:PATH',
                        help='Copy an existing encrypted save into a new disposable native menu profile')
    args = parser.parse_args()
    if args.automatic_gear:
        args.automatic_menus = True
        args.expect_classes = args.expect_classes or [1] * args.players
        if args.expect_classes != [1] * args.players or args.expect_gear:
            parser.error('--automatic-gear requires all Warriors and supplies its own nondefault item expectations')
    if args.automatic_menus:
        args.menus = True
        args.expect_classes = args.expect_classes or [1, 8, 3, 4][:args.players]
        if any(c not in (1, 8, 3, 4) for c in args.expect_classes):
            parser.error('Automatic menu coordinates are verified only for Warrior, Mage, Hunter and Rogue')
        if args.expect_map not in (None, 'elwynn', 'duskwood'):
            parser.error('Automatic native menu taps currently cover Elwynn and Duskwood')
        args.expect_map = args.expect_map or 'elwynn'
        if args.guest_request_map not in (None, 'elwynn', 'duskwood'):
            parser.error('Automatic guest map taps currently cover Elwynn and Duskwood')
    fixtures = {}
    try:
        for item in args.profile_save:
            player, path = item.split(':', 1)
            player = int(player)
            assert 1 <= player <= args.players and player not in fixtures
            fixtures[player] = str(Path(path).resolve(strict=True))
    except (ValueError, AssertionError, OSError):
        parser.error('--profile-save requires a unique PLAYER:PATH to an existing native save')
    if args.automatic_gear and set(fixtures) != set(range(1, args.players + 1)):
        parser.error('--automatic-gear requires an actual earned native save fixture for every player')
    if args.expect_classes and len(args.expect_classes) != args.players:
        parser.error('--expect-classes requires one native class ID per player')
    try:
        expected_gear = [tuple(map(int, entry.split(':'))) for entry in args.expect_gear]
        assert all(len(v) == 3 and 1 <= v[0] <= args.players and 0 <= v[1] < 19 and v[2] > 0 for v in expected_gear)
    except (ValueError, AssertionError):
        parser.error('--expect-gear requires PLAYER:SLOT:ITEM with a positive item ID and slot0..18')
    if args.automatic_gear:
        expected_gear = [(number, None, 101800 if number % 2 else 0) for number in range(1, args.players + 1)]
    if (args.expect_map or args.expect_classes or args.guest_request_map or expected_gear or args.observe_gear) and not args.menus:
        parser.error('Explicit menu acceptance requires --menus')
    from lobby_server import server
    app = server(('127.0.0.1', 0))
    threading.Thread(target=app.serve_forever, daemon=True).start()
    processes, pipes = [], []
    try:
        url = f'http://127.0.0.1:{app.server_port}'
        for number in range(1, args.players + 1):
            parent, child = mp.Pipe()
            taps = native_menu_taps(args.expect_classes[number-1], number != 1,
                args.expect_map if number == 1 else args.guest_request_map or 'elwynn',
                equip_claymore=args.automatic_gear and number % 2 == 1) if args.automatic_menus else None
            process = mp.Process(target=member, args=(url, number, child, args.menus,
                bool(expected_gear or args.observe_gear), taps, fixtures.get(number)))
            process.start()
            processes.append(process)
            pipes.append(parent)
            if number == 1:
                assert parent.poll(30), 'Host did not create room'
                room_id = parent.recv()
            else:
                parent.send(room_id)
                assert parent.poll(30) and parent.recv() == 'joined'
        assert app.rooms.rooms[room_id]['phase'] == 'lobby'
        assert len(app.rooms.rooms[room_id]['players']) == args.players
        pipes[0].send('start')
        results = []
        for pipe in pipes:
            assert pipe.poll(430 if args.menus else 210), 'Room worker timed out'
            results.append(pipe.recv())
        assert results == ['passed'] * args.players, results
        for process in processes:
            process.join(10)
            assert process.exitcode == 0
        summaries = []
        maps = []
        progress = []
        recordings = []
        for number in range(1, args.players + 1):
            rows = [json.loads(line) for line in (ROOT / f'analysis/room-player-{number}.jsonl').read_text().splitlines()]
            recordings.append(rows)
            summaries.append(next(row for row in reversed(rows) if row['event'] == 'summary'))
            maps.append(next(row for row in rows if row['event'] == 'party_map_loaded'))
            state = next(row for row in reversed(rows) if row['event'] == 'native_state' and row['player'] == number)
            progress.append((state['level'], state['xp']))
        assert len({row['zone'] for row in maps}) == 1, maps
        assert len(set(progress)) == 1, progress
        host = summaries[0]
        assert host['world_captured'] > 0 and host['world_delivered'] == host['world_captured'], host
        assert sum(s['world_delivered'] for s in summaries[1:]) == host['world_delivered']
        assert [s['created'] for s in summaries] == [args.players - 1] * args.players
        menu = verify_menu_selection(recordings, args.expect_map, args.expect_classes, args.guest_request_map)
        if expected_gear:
            menu.update(verify_selected_gear(recordings, expected_gear, require_baseline=args.automatic_gear))
        if args.automatic_menus:
            menu.update(verify_concurrent_menus(recordings))
        print(json.dumps(dict(room_launch='passed', world_deliveries=host['world_delivered'],
                              **menu, **verify_player_fields(recordings), **verify_character_names(recordings))))
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(10)
        app.shutdown()
        app.server_close()


if __name__ == '__main__':
    main()
