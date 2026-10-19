"""Run four separate native peers locally and check delivery and progression."""
import json
import argparse
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-coop', action='store_true', help='Also verify all four pause/resume and revival paths')
    parser.add_argument('--verify-economy', action='store_true', help='Verify native contested chest and guest-four gold pickup')
    parser.add_argument('--require-movement', action='store_true', help='Require real operator-driven movement from all four native clients')
    parser.add_argument('--verify-melee-run', action='store_true',
                        help='Host and guest side by side, standing then running: the host keeps his melee hits')
    options = parser.parse_args()
    processes, outputs = [], []
    try:
        for number in range(1, 5):
            output = (ROOT / f'analysis/group-network-{number}.txt').open('w')
            outputs.append(output)
            args = [sys.executable, str(ROOT / 'reconstruction/group_online.py'),
                    'host' if number == 1 else 'join', '--players', '4', '--seconds',
                    '330' if options.verify_melee_run else  # Two passes 15 + 4 x 60 s plus start-up; guests +30 = 360 cap.
                    '300' if options.verify_coop or options.verify_economy else '120',
                    '--verify-melee-run' if options.verify_melee_run else
                    '--verify-economy' if options.verify_economy else '--verify-coop' if options.verify_coop else '--verify']
            if number != 1:
                args += ['--slot', str(number)]
            processes.append(subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT))
            if number == 1:
                time.sleep(2)
        for process in processes:
            process.wait(timeout=600 if options.verify_melee_run else 360)
        codes = [p.returncode for p in processes]
        assert codes == [0] * 4, codes
        summaries = []
        recordings = []
        for number in range(1, 5):
            rows = [json.loads(line) for line in (ROOT / f'analysis/group-online-{number}.jsonl').read_text().splitlines()]
            recordings.append(rows)
            summaries.append(next(row for row in reversed(rows) if row['event'] == 'summary'))
        host = summaries[0]
        assert host['world_captured'] > 0 and host['world_captured'] == host['world_delivered'], host
        assert sum(s['world_delivered'] for s in summaries[1:]) == host['world_delivered'], summaries
        own_states = [s['states'][str(n)][1:3] for n, s in enumerate(summaries, 1)]
        assert all(state == own_states[0] for state in own_states), own_states
        assert [s['created'] for s in summaries] == [3] * 4, summaries
        if options.verify_coop:
            expected = [(source, paused) for n in range(1, 5) for source, paused in ((n, True), (n % 4 + 1, False))]
            assert [(r['player'], r['paused']) for r in recordings[0] if r['event'] == 'network_pause_verified'] == expected
            assert [r['player'] for r in recordings[0] if r['event'] == 'network_revival_verified'] == [2, 3, 4, 1]
            for number, rows in enumerate(recordings, 1):
                revivals = [r for r in rows if r['event'] == 'player_revived']
                assert len(revivals) == 1 and revivals[0]['player'] == number, revivals
                assert revivals[0]['progress_before'][:2] == revivals[0]['progress_after'], revivals
                notices = {(r['target'], r['state']) for r in rows if r['event'] == 'network_revival_notice'}
                assert notices == {(n, state) for n in range(1, 5) if n != number for state in ('down', 'revived')}, notices
            assert any(r['event'] == 'network_coop_complete' for r in recordings[0])
            from verify_party_evidence import verify_party_combat, verify_independent_talents
            print(json.dumps(dict(party_combat=verify_party_combat(recordings),
                                  party_talents=verify_independent_talents(recordings))), flush=True)
        if options.require_movement:
            from verify_party_evidence import verify_real_movement
            print(json.dumps(verify_real_movement(recordings)), flush=True)
        if options.verify_melee_run:
            verified = [r for r in recordings[0] if r['event'] == 'network_melee_run_verified']
            assert len(verified) == 1, 'Melee hits of the running host were not verified'
            print(json.dumps(dict(melee_run=verified[0])), flush=True)
        if options.verify_economy:
            assert any(r['event'] == 'network_chest_contention_verified' for r in recordings[0])
            assert any(r['event'] == 'network_guest_four_gold_verified' for r in recordings[0])
            rain = [r for r in recordings[0] if r['event'] == 'network_orb_rain_verified']
            assert len(rain) == 1, 'Orb rain next to the host was not verified'
            print(json.dumps(dict(orb_rain=rain[0])), flush=True)
            assert any(r['event'] == 'network_host_first_chest_verified' for r in recordings[0])
            # Variant B: every guest opened both chests once (fixture, then the one the host opened first).
            awards = sorted(r['player'] for rows in recordings for r in rows if r['event'] == 'guest_chest_awarded')
            assert awards == [2, 2, 3, 3, 4, 4], awards
        print(json.dumps(dict(deliveries=host['world_delivered'], progression=own_states, exits=codes)))
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        for output in outputs:
            output.close()


if __name__ == '__main__':
    main()
