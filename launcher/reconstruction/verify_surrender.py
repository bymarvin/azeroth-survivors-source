"""Menu "give up" (0.95.0 tag 10) on four separate native peers.

Guest 4 gives up first: only it leaves (the host removes it like a departing
player) while the host and guests 2 and 3 keep playing. Then the host gives
up: guests 2 and 3 run the same native surrender once, and the team defeat
path shows the defeat to the host and both guests. Both are requested through
the native menu command itself (disposable saves); nobody is revived.
"""
import argparse
import json
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'reconstruction'))

GIVE_UP = 10  # 0.95.0 menu command tag (Enter moved to 11).
GUEST_AT, HOST_AT = 12.0, 28.0  # Game seconds after the run starts.
LEAVER = 4


def events(rows, name, **match):
    return [r for r in rows if r['event'] == name and all(r.get(k) == v for k, v in match.items())]


def verify(recordings):
    host, *guests = recordings
    leaver = recordings[LEAVER - 1]
    assert events(leaver, 'surrender_requested', player=LEAVER), 'Guest 4 did not give up'
    assert events(leaver, 'player_surrendered', player=LEAVER, party=False), 'Guest 4 surrender not detected'
    assert not events(leaver, 'party_surrender_received'), 'Guest 4 left before the host gave up'
    order = [r['event'] for r in host if r['event'] in ('guest_surrendered', 'guest_departed', 'player_surrendered')]
    assert order[:3] == ['guest_surrendered', 'guest_departed', 'player_surrendered'], order
    assert events(host, 'guest_departed', player=LEAVER), 'Host kept the guest who gave up'
    assert events(host, 'player_surrendered', player=1, party=True), 'Host surrender not detected'
    for number in (2, 3):
        rows = recordings[number - 1]
        assert events(rows, 'party_surrender_received'), (number, 'No party surrender from the host')
        applied = events(rows, 'party_surrender_applied', player=number)
        assert len(applied) == 1, (number, applied)
    for number in (1, 2, 3):
        rows = recordings[number - 1]
        assert events(rows, 'team_defeat_shown', player=number), (number, 'No defeat after the host gave up')
        assert not events(rows, 'player_revived'), (number, 'A player who gave up was revived')
    return dict(leaver=LEAVER, defeated=[1, 2, 3],
                native_guest_surrender=[r['native'] for n in (2, 3)
                                        for r in events(recordings[n - 1], 'party_surrender_applied', player=n)])


def adapter(base):
    from native_probe import CHOOSE, UI_COMMAND, allocate, checked, game_field

    class SurrenderVerification(base):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.give_up_at = HOST_AT if self.number == 1 else GUEST_AT if self.number == LEAVER else None
            self.run_start = None

        def before_batch(self, client, context):
            game = client.server + 0x10
            phase = self.native_states[client.number][0]
            if phase == 2:
                count = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
                if not 1 <= count <= 16:
                    raise ValueError('Invalid native choices')
                client.call_before(context, CHOOSE, game, (client.number - 1) % count)
                return True
            if self.give_up_at is not None and phase == 1 and not self.router.paused:
                now = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
                if self.run_start is None:
                    self.run_start = now
                ready = client.number != 1 or LEAVER in getattr(self, 'departed', ())
                if now - self.run_start >= self.give_up_at and ready:
                    self.give_up_at = None
                    buffer = checked(allocate(client.handle, None, 0xE8, 0x3000, 4))
                    client.put(buffer, struct.pack('<I', GIVE_UP) + bytes(0xE4))
                    self.record(event='surrender_requested', player=client.number, clock=now)
                    client.call_before(context, UI_COMMAND, client.server, buffer, request=True)
                    return True
            return super().before_batch(client, context)

    return SurrenderVerification


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    t0 = time.time()
    print('[ .... ] Aufgeben: 4 Peers starten', flush=True)
    processes, outputs = [], []
    try:
        for number in range(1, 5):
            output = (ROOT / f'analysis/group-network-{number}.txt').open('w')
            outputs.append(output)
            args = [sys.executable, str(ROOT / 'reconstruction/group_online.py'),
                    'host' if number == 1 else 'join', '--players', '4', '--seconds', '75', '--verify-surrender']
            if number != 1:
                args += ['--slot', str(number)]
            processes.append(subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT))
            if number == 1:
                time.sleep(2)
        for process in processes:
            process.wait(timeout=360)
        codes = [p.returncode for p in processes]
        assert codes == [0] * 4, codes
        recordings = [[json.loads(line) for line in (ROOT / f'analysis/group-online-{n}.jsonl').read_text().splitlines()]
                      for n in range(1, 5)]
        result = verify(recordings)
        print(f'[  OK  ] Aufgeben ({time.time() - t0:.0f} s, {json.dumps(result)})', flush=True)
    except Exception as error:
        print(f'[FAILED] Aufgeben: {type(error).__name__}: {error}', flush=True)
        raise
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
        for output in outputs:
            output.close()


if __name__ == '__main__':
    main()
