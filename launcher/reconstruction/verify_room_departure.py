"""Manual X/menu quit acceptance in isolated native profiles; host quits last."""
import argparse
import json
import multiprocessing as mp
import os
from pathlib import Path
import threading


def verify_departures(logs, departed, players):
    """Only native process-exit events count; bounded teardown cannot pass."""
    expected = set(departed)
    assert expected and expected < set(range(2, players + 1)), 'Leave a guest connected when host closes'
    host = logs[0]
    actual = {r['player'] for r in host if r['event'] == 'guest_departed'}
    continued = {r['player'] for r in host if r['event'] == 'departure_world_continued'}
    assert actual == expected and continued == expected, (expected, actual, continued)
    for number in expected | {1}:
        assert any(r['event'] == 'native_exit' and r['player'] == number and r['code'] == 0
                   for r in logs[number - 1]), (number, 'No normal native close')
    for number in set(range(2, players + 1)) - expected:
        assert any(r['event'] == 'host_departed' for r in logs[number - 1]), \
            (number, 'Surviving guest did not receive host departure')
    assert not any(r['event'] in ('native_crash', 'native_contract_failure') for rows in logs for r in rows)
    return dict(departure_test='passed', departed=sorted(expected), continued=sorted(continued),
                host_closed_with_survivors=True)


def member(url, number, pipe, automatic=False):
    if automatic:
        if number in (1, 2):
            os.environ['WOW_ROGUE_KEY'] = 'escape@0'
            os.environ['WOW_ROGUE_TAPS'] = '549,521'
        else:
            os.environ.pop('WOW_ROGUE_KEY', None)
            os.environ.pop('WOW_ROGUE_TAPS', None)
    import native_probe
    from verify_room_launch import member as launch
    run = native_probe.run
    def bounded(seconds, players, bridge, **kwargs):
        bridge.autostart, bridge.host_map = True, 'elwynn'
        bridge.character_names = {number: 'Hero' if native_probe._candidate_home else f'Coop{number}'}
        poll = bridge.poll_network
        observed = {}
        def check():
            poll()
            if number == 1:
                for left in bridge.departed:
                    if left not in observed:
                        observed[left] = bridge.host_clock
                    elif observed[left] is not None and bridge.host_clock > observed[left] + 2:
                        bridge.record(event='departure_world_continued', player=left,
                                      clock=bridge.host_clock, members=bridge.members)
                        observed[left] = None
        bridge.poll_network = check
        callback = bridge
        if automatic and number in (1, 2):
            from verify_native_input import NativeDepartureDiagnostic
            def ready():
                if bridge.native_states.get(number, (None,))[0] != 1:
                    return False
                if number == 1:
                    return observed.get(2, False) is None
                return bridge.ready == set(bridge.members) and bridge.host_clock >= 3
            callback = NativeDepartureDiagnostic(bridge, ready)
        return run(300 if number == 1 else 360, players, callback, **kwargs)
    native_probe.run = bounded
    launch(url, number, pipe, True)  # Existing lifecycle assertions and isolated profiles.


def main():
    from lobby_server import server
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--players', type=int, choices=(3, 4), default=4)
    parser.add_argument('--automatic', action='store_true', help='Use gated native Escape and Quit input in disposable candidate profiles')
    parser.add_argument('--departed', type=int, nargs='+', default=[2],
                        help='Guests to close normally before the host; leave at least one connected')
    args = parser.parse_args()
    if args.automatic and args.departed != [2]:
        parser.error('--automatic currently verifies guest2 then host menu Quit')
    if not set(args.departed) < set(range(2, args.players + 1)) or not args.departed:
        parser.error('--departed must leave at least one guest connected')
    app = server(('127.0.0.1', 0))
    threading.Thread(target=app.serve_forever, daemon=True).start()
    processes, pipes = [], []
    try:
        for number in range(1, args.players + 1):
            parent, child = mp.Pipe()
            process = mp.Process(target=member, args=(f'http://127.0.0.1:{app.server_port}', number, child, args.automatic))
            process.start()
            processes.append(process)
            pipes.append(parent)
            if number == 1:
                assert parent.poll(30)
                room_id = parent.recv()
            else:
                parent.send(room_id)
                assert parent.poll(30) and parent.recv() == 'joined'
        pipes[0].send('start')
        print('Automatic native menu Quit: guest2 first, host after surviving world advances.' if args.automatic else
              f'Enter Elwynn in every window. Close guests {args.departed} using X/menu, wait for '
              'departure_world_continued in the host log, then close the host with the other guests still connected.', flush=True)
        for pipe in pipes:
            assert pipe.poll(420) and pipe.recv() == 'passed', 'Native session did not close cleanly'
        for process in processes:
            process.join(10)
            assert process.exitcode == 0
        root = Path(__file__).resolve().parents[1]
        logs = [[json.loads(line) for line in (root / f'analysis/room-player-{n}.jsonl').read_text().splitlines()]
                for n in range(1, args.players + 1)]
        result = verify_departures(logs, args.departed, args.players)
        if args.automatic:
            for number in (1, 2):
                for event in ('departure_native_escape', 'departure_native_quit_tap'):
                    assert any(row['event'] == event and row['player'] == number for row in logs[number - 1]), (number, event)
            result['native_menu_quit_verified'] = True
        assert not app.rooms.rooms, 'Finished room still listed'
        print(json.dumps(result))
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(10)
        app.shutdown()
        app.server_close()


if __name__ == '__main__':
    main()
