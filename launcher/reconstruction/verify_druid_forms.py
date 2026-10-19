"""Druid forms on four separate native peers: the host fights in Cat Form, guest 2
in Dire Bear Form, guest 3 in its own model; every other client must create each
avatar with that model.

The 0.95.0 Cat/Dire Bear capstones come from the persistent talent tree ("You
start every run with ..."). The native player-field builder (7264 0x544aa10,
form scan 0x544b6d9) runs only when a world is built (Enter 0x543188c and
0x542a061), so the display model (UNIT_FIELD_DISPLAYID 131) is fixed for the
whole run and travels in the player's login create block, from which the
bridge creates every remote avatar. A form cannot change within a run; a new
run is a new session with a new create block. The driver forces the model at
the builder before the world is built (disposable saves), so the run needs no
druid capstone. Replication and native rendering are unchanged.
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

CAT, BEAR = 892, 2281  # Night elf Cat/Dire Bear models chosen by the native builder.
SITE, RESUME = 0x544B6AD, 0x544B756  # Talent scan -> display field insert (7264).
ORIGINAL = bytes.fromhex('488b8700070000 4885c0 7460')
FORMS = {1: CAT, 2: BEAR}  # Players 3 and 4 keep their native model.
ACTORS = tuple(FORMS)


def form_patch(model):
    """mov r8d, model; jmp RESUME (the builder inserts field 131 with r8d there)."""
    code = bytes.fromhex('41b8') + struct.pack('<I', model) + bytes.fromhex('e9') + struct.pack('<i', RESUME - (SITE + 11))
    return code + bytes.fromhex('90') * (len(ORIGINAL) - len(code))


def created_display(body):
    from world_packets import objects, DISPLAY_ID
    block, = objects(bytes.fromhex(body), remap=False)
    return block.fields.get(DISPLAY_ID)


def verify(recordings):
    """Every player's own model is the model every other client created its avatar with."""
    result = {}
    for player, rows in enumerate(recordings, 1):
        own = [r['display'] for r in rows if r['event'] == 'own_display']
        assert own, (player, 'No native display model')
        expected = FORMS.get(player, own[0])
        assert own[0] == expected and expected not in (None, 0), (player, own)
        if player not in FORMS:
            assert expected not in (CAT, BEAR), (player, own)
        for recipient, other in enumerate(recordings, 1):
            if recipient == player:
                continue
            created = [created_display(r['body']) for r in other
                       if r['event'] == 'remote_player_create_written' and r['player'] == player]
            assert created and all(d == expected for d in created), (player, recipient, created)
        result[player] = expected
    return result


def adapter(base):
    from native_probe import CHOOSE, game_field
    from updated_layout import release_7264
    from world_packets import objects, UPDATE, SELF, DISPLAY_ID

    class DruidFormVerification(base):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.form_patched = self.number not in FORMS

        def __call__(self, client, rva, context):
            if not self.form_patched:
                # Before the world (and its login create block) is built.
                if not release_7264():
                    raise ValueError('Druid form driver is bound to the 0.95.0 builder')
                address = client.base + SITE
                if client.memory(address, len(ORIGINAL)) != ORIGINAL:
                    raise RuntimeError('Native display builder changed')
                client.patch(address, form_patch(FORMS[self.number]))
                self.form_patched = True
                self.record(event='druid_form_set', player=client.number, display=FORMS[self.number])
            return super().__call__(client, rva, context)

        def filter_packet(self, number, opcode, body):
            if opcode == UPDATE:
                for block in objects(body, remap=False):
                    if block.guid == SELF and DISPLAY_ID in block.fields:
                        self.record(event='own_display', player=number, display=block.fields[DISPLAY_ID])
            return super().filter_packet(number, opcode, body)

        def before_batch(self, client, context):
            game = client.server + 0x10
            if self.native_states[client.number][0] == 2:
                count = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
                if not 1 <= count <= 16:
                    raise ValueError('Invalid native choices')
                client.call_before(context, CHOOSE, game, (client.number - 1) % count)
                return True
            return super().before_batch(client, context)

    return DruidFormVerification


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    t0 = time.time()
    print('[ .... ] Druiden-Gestalten: 4 Peers starten', flush=True)
    processes, outputs = [], []
    try:
        for number in range(1, 5):
            output = (ROOT / f'analysis/group-network-{number}.txt').open('w')
            outputs.append(output)
            args = [sys.executable, str(ROOT / 'reconstruction/group_online.py'),
                    'host' if number == 1 else 'join', '--players', '4', '--seconds', '60', '--verify-forms']
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
        print(f'[  OK  ] Druiden-Gestalten ({time.time() - t0:.0f} s, {json.dumps(result)})', flush=True)
    except Exception as error:
        print(f'[FAILED] Druiden-Gestalten: {type(error).__name__}: {error}', flush=True)
        raise
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
        for output in outputs:
            output.close()


if __name__ == '__main__':
    main()
