"""Diagnostic: enemy pressure on the host, alone vs. with one guest (user approval 17.10.2026).

  verify_enemy_pressure.py [--variants solo,duo-0.0.17,duo] [--seconds 180] [--pattern circle|line|stand|apart|native]
  (defaults also from COOP_PRESSURE_VARIANTS, COOP_PRESSURE_SECONDS, COOP_PRESSURE_PATTERN for run_acceptance)

Every variant is its own native session with the same scripted movement, written into the game (the host's router
pose follows only like his movement heartbeat, as when a player runs):
  solo        the host alone (as room_client plays a one-player room)
  duo-0.0.17  host + guest 2 one unit beside him, melee hits routed as in 0.0.17 (host router pose)
  duo         the same with the 0.0.19 routing (host game position and melee reach)
Measured for --seconds after WARMUP: host HURT per minute (melee / other), hits per minute queued for the guest
(melee / area), enemy_hit_redirected, the share of living enemies nearest to each player, living enemies and enemies
within 15 of each player (sampled every second). Every player keeps 1000 health. Results go to
analysis/enemy-pressure-<variant>.json and analysis/enemy-pressure.json; a table is printed at the end.
Pattern apart (17.10.2026): both stand, the guest APART units from the host, so the enemies around the host have no
second target next to him (does a target that flips between two players 1 unit apart cost hits?). hits_per_near_min:
melee hits on all players per minute and per enemy within NEAR of any player (solo ~21 in circle, duo ~9).
Pattern native (17.10.2026, closer to real play): no position is written for the guest; he holds the game's own
diagnostic W key (native press repeat as verify_split_spawns, up to NATIVE_HOLD_MAX seconds) and runs with his real
movement and heartbeats, while the host stands. Use --seconds 90 or less, the hold ends after that.
Every second while measuring the host records pressure_target: host spot, the guest's router pose (heartbeat), his
last live sample (age, velocity), the estimate guest_position() makes and the guest_target the pursuit reads, enemies
near (NEAR) and far of that target and how the enemies that chase it moved over the last second (at the target,
toward it, elsewhere). The estimate is checked against where the guest really was: his later live samples carry his
own clock, the same monotonic clock as the host's on one machine (all peers of a suite run on one PC), so the error
of the estimate and of the heartbeat at the same instant come out in target_error_* / heartbeat_error_* (median, max).
Run it like a suite (run_acceptance.py --suites enemy-pressure): disposable candidate saves only.
"""
import collections
import argparse
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
WARMUP = 15
RADIUS = 8.0
SPEED = 3.0
HEARTBEAT_SECONDS = .5
# Guests' movement reaches the host at a real client's cadence (0.0.22; COOP_GUEST_HEARTBEAT=0: every batch as before).
GUEST_HEARTBEAT_SECONDS = float(os.environ.get('COOP_GUEST_HEARTBEAT', HEARTBEAT_SECONDS))
GUEST_OFFSET = 1.0
APART = 25.0              # Pattern apart: the guest this far from the host (beyond the near range of either).
NEAR = 15.0
VARIANTS = ('solo', 'duo-0.0.17', 'duo')
PATTERNS = ('circle', 'line', 'stand', 'apart', 'native')
NATIVE_HOLD_MAX = 120     # The native key hold (verify_split_spawns allows 2..120 s).
AT_TARGET = 3.0           # An enemy this close to its target attacks rather than chases.
FOLLOW_COS = .5           # A chaser moved within 60 degrees of the direction to its target.
MOVED = .2                # Units per second below which an enemy counts as standing.
INTERPOLATE_GAP = .25     # Live samples further apart than this do not give a true position.


def median(values):
    ordered = sorted(values)
    if not ordered:
        return None
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def true_position(samples, when):
    """Where the guest was at `when` (his clock) from his own samples [(sent, x, y)], or None without a pair."""
    later = next((i for i, (sent, _, _) in enumerate(samples) if sent >= when), None)
    if later is None or later == 0:
        return None
    (s0, x0, y0), (s1, x1, y1) = samples[later - 1], samples[later]
    if s1 - s0 > INTERPOLATE_GAP:
        return None
    f = (when - s0) / (s1 - s0) if s1 > s0 else 0.0
    return x0 + (x1 - x0) * f, y0 + (y1 - y0) * f


def pose_at(pattern, center, elapsed):
    """Host position on the scripted path: a circle around center, back and forth through it, or standing still."""
    cx, cy, cz = center
    if pattern in ('stand', 'apart', 'native'):
        return cx + RADIUS, cy, cz
    if pattern == 'line':
        span = 4 * RADIUS
        phase = (SPEED * elapsed) % (2 * span)
        offset = phase if phase <= span else 2 * span - phase
        return cx + RADIUS - offset, cy, cz
    angle = SPEED / RADIUS * elapsed
    return cx + RADIUS * math.cos(angle), cy + RADIUS * math.sin(angle), cz


def legacy_route_enemy_hit(self, client, context):
    """The 0.0.17 melee routing (nearest player by router pose, host included), for the comparison only."""
    from play_limits import MAX_HIT_DAMAGE, MAX_NATIVE_OBJECTS
    from native_probe import game_field, q
    from visibility_bridge import native_enemies, packed_guid
    from world_packets import Reader, SELF
    if self.draining or self.router.paused or q(context, 192) & 255 != 1:
        return
    game, attacker = q(context, 128), q(context, 184)
    enemy = next((p for guid, hp, p in native_enemies(client, game) if guid == attacker and hp > 0), None)
    if enemy is None:
        return
    living = [n for n in self.members if self.native_states.get(n, (1 if n == 1 else 0,))[0] == 1
              and 0xFF0100 + n in self.router.players]
    if not living:
        return
    distances = {}
    for number in living:
        pose = self.router.players[0xFF0100 + number].pose
        distances[number] = sum((a - b) ** 2 for a, b in zip(enemy, (pose.x, pose.y, pose.z)))
    nearest = min(distances.values())
    tied = [n for n in living if abs(distances[n] - nearest) < .01]
    self.hit_turn += 1
    target = tied[self.hit_turn % len(tied)]
    if target == 1 or target not in self.created.get(1, ()) or 1 not in self.created.get(target, ()):
        return
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
        return
    client.put(q(packet, 8) + start, packed_guid(0xFF0100 + target))
    clock = struct.unpack('<f', client.memory(game + game_field(0x85C), 4))[0]
    self.queue_incoming_hit(target, 'hits', (attacker, damage, clock))
    stack = q(context, 152)
    struct.pack_into('<Q', context, 248, q(client.memory(stack, 8)))
    struct.pack_into('<Q', context, 152, stack + 8)
    self.record(event='enemy_hit_redirected', attacker=attacker, damage=damage, player=target)


def adapter(parent, routing='fix', label='duo', seconds=180, pattern='circle'):
    """The measuring bridge for one variant (parent: NativeCombatBridge solo, GroupOnlineBridge duo)."""
    from native_probe import CHOOSE, game_field, q
    from sessions import HEARTBEAT, Pose
    from visibility_bridge import native_enemies

    class Pressure(parent):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.p_stage, self.p_started, self.p_center, self.p_spot = 'wait', None, None, None
            self.p_beat = self.p_sample = 0.0
            self.p = dict(host_melee=0, host_other=0, redirected=0, guest_melee=0, guest_area=0, samples=0,
                          alive=0, nearest_host=0, nearest_guest=0, near_host=0, near_guest=0, near_any=0,
                          chasers_at=0, chasers_toward=0, chasers_elsewhere=0, chasers_standing=0)
            if pattern == 'native' and getattr(self, 'input_contract', None) is not None:
                hold = min(NATIVE_HOLD_MAX, WARMUP + seconds + 15)
                self.input_contract = dict(self.input_contract, hold_seconds=hold)
            self.p_live = collections.deque(maxlen=2000)       # The guest's own samples (his clock, x, y).
            self.p_pending = collections.deque()               # (host clock, estimate, heartbeat) to check.
            self.p_errors, self.p_heartbeat_errors = [], []
            self.p_enemies = {}                                # guid -> (x, y) at the last sample.

        def decorate(self, peer, message):
            super().decorate(peer, message)
            if getattr(self, 'number', 1) == 1:
                message['pressure'] = [self.p_stage, self.p_center, self.p_spot]

        def receive_peer(self, peer, message):
            super().receive_peer(peer, message)
            if getattr(self, 'number', 1) != 1 and 'pressure' in message:
                self.p_stage, self.p_center, self.p_spot = message['pressure']

        def record(self, **event):
            if self.p_stage == 'measure' and event.get('event') == 'enemy_hit_redirected':
                self.p['redirected'] += 1
            super().record(**event)

        def route_enemy_hit(self, client, context):
            stack, melee = q(context, 152), q(context, 192) & 255 == 1
            if routing == '0.0.17' and melee:
                legacy_route_enemy_hit(self, client, context)
            else:
                super().route_enemy_hit(client, context)
            if self.p_stage == 'measure' and q(context, 152) == stack:  # The native HURT on the host runs.
                self.p['host_melee' if melee else 'host_other'] += 1

        def receive_position(self, other, position):
            super().receive_position(other, position)
            live = self.live_positions.get(other)
            if other == 2 and live is not None and (not self.p_live or live[3] > self.p_live[-1][0]):
                self.p_live.append((live[3], live[1][0], live[1][1]))

        def queue_incoming_hit(self, number, kind, hit, clock=None):
            if self.p_stage == 'measure' and number != 1:
                self.p['guest_melee' if kind == 'hits' else 'guest_area'] += 1
            return super().queue_incoming_hit(number, kind, hit, clock)

        def place(self, client, game, number, x, y, z, router=True):
            client.put(game + game_field(0x488), struct.pack('<4f', x, y, z, 0))
            if router and 0xFF0100 + number in self.router.players:
                self.router.players[0xFF0100 + number].pose = Pose(x, y, z, 0)
                if hasattr(self, 'latest_movement'):
                    moving = int(self.p_stage in ('warmup', 'measure') and pattern not in ('stand', 'apart'))
                    self.latest_movement[number] = (HEARTBEAT, struct.pack('<II4fI', moving, 0, x, y, z, 0, 0))

        def before_batch(self, client, context):
            game = client.server + 0x10
            phase = self.native_states[client.number][0]
            if phase == 2:
                count = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
                if not 1 <= count <= 16:
                    raise ValueError('Invalid native choices')
                client.call_before(context, CHOOSE, game, (client.number - 1) % count)
                return True
            if phase == 1:
                client.put(game + game_field(0x4A0), struct.pack('<f', 1000))
                client.put(game + game_field(0x4F8), struct.pack('<f', 1000))
                if client.number == 1:
                    self.drive_host(client, game)
                elif self.p_spot is not None and self.p_center is not None and pattern != 'native':
                    hx, hy, hz = self.p_spot
                    dx, dy = hx - self.p_center[0], hy - self.p_center[1]
                    length = math.hypot(dx, dy) or 1
                    if pattern == 'line':
                        dx, dy, length = 0, 1, 1  # Beside the host, across the line.
                    offset = GUEST_OFFSET
                    if pattern == 'apart':
                        dx, dy, length, offset = 0, 1, 1, APART
                    now = time.monotonic()
                    beat = now - getattr(self, 'guest_beat', 0.0) >= GUEST_HEARTBEAT_SECONDS
                    if beat:
                        self.guest_beat = now
                    self.place(client, game, client.number, hx + dx / length * offset,
                               hy + dy / length * offset, hz, router=beat)
            return super().before_batch(client, context)

        def drive_host(self, client, game):
            now = time.monotonic()
            if self.p_center is None:
                if self.ready != set(self.members):
                    return
                x, y, z = struct.unpack('<3f', client.memory(game + game_field(0x488), 12))
                self.p_center = [x - RADIUS, y, z]
                self.p_stage, self.p_started = 'warmup', now
                self.record(event='pressure_started', variant=label, routing=routing, pattern=pattern,
                            players=len(self.members), center=self.p_center)
            elapsed = now - self.p_started
            if self.p_stage == 'warmup' and elapsed >= WARMUP:
                self.p_stage = 'measure'
            if self.p_stage == 'measure' and elapsed >= WARMUP + seconds:
                self.finish()
                return
            if self.p_stage == 'done':
                return
            x, y, z = pose_at(pattern, self.p_center, elapsed)
            self.p_spot = [x, y, z]
            beat = now - self.p_beat >= HEARTBEAT_SECONDS
            if beat:
                self.p_beat = now
            self.place(client, game, 1, x, y, z, router=beat)
            if self.p_stage == 'measure' and now - self.p_sample >= 1:
                self.p_sample = now
                self.sample(client, game, (x, y))

        def sample(self, client, game, host):
            guest = self.router.players.get(0xFF0102) if len(self.members) > 1 else None
            living = [(guid, p) for guid, hp, p in native_enemies(client, game) if hp > 0]
            enemies = [p for _, p in living]
            if guest is not None and hasattr(self, 'guest_position'):
                self.sample_target(client, host, guest.pose, living)
            self.p['samples'] += 1
            self.p['alive'] += len(enemies)
            for ex, ey, _ in enemies:
                dh = math.hypot(ex - host[0], ey - host[1])
                dg = math.hypot(ex - guest.pose.x, ey - guest.pose.y) if guest else float('inf')
                self.p['nearest_host' if dh <= dg else 'nearest_guest'] += 1
                self.p['near_host'] += dh <= NEAR
                self.p['near_guest'] += dg <= NEAR
                self.p['near_any'] += min(dh, dg) <= NEAR

        def sample_target(self, client, host, pose, living):
            """pressure_target: where the pursuit chases the guest, how far that is from him and who follows it."""
            now = time.monotonic()
            estimate = self.guest_position(2)
            written = None
            if getattr(self, 'guest_target', None) and 2 in self.pursuit_guests:
                wx, wy, _, alive = struct.unpack('<3fI', client.memory(
                    self.guest_target + self.pursuit_guests.index(2) * 16, 16))
                written = [round(wx, 2), round(wy, 2), alive]
            live = self.live_positions.get(2)
            sample = None
            if live is not None:
                received, (lx, ly, _), (vx, vy), _ = live
                sample = [round(lx, 2), round(ly, 2), round(now - received, 3), round(vx, 2), round(vy, 2)]
            self.p_pending.append((now, estimate[:2], (pose.x, pose.y)))
            error = heartbeat = None
            while self.p_pending and self.p_live and self.p_pending[0][0] <= self.p_live[-1][0]:
                when, (ex, ey), (rx, ry) = self.p_pending.popleft()
                truth = true_position(self.p_live, when)
                if truth is not None:
                    error = math.hypot(ex - truth[0], ey - truth[1])
                    heartbeat = math.hypot(rx - truth[0], ry - truth[1])
                    self.p_errors.append(error)
                    self.p_heartbeat_errors.append(heartbeat)
            tx, ty = estimate[0], estimate[1]
            counts = dict(near=0, far=0, at=0, toward=0, elsewhere=0, standing=0)
            seen = {}
            for guid, (ex, ey, _) in living:
                seen[guid] = (ex, ey)
                to_target = math.hypot(tx - ex, ty - ey)
                counts['near' if to_target <= NEAR else 'far'] += 1
                if to_target > NEAR or math.hypot(host[0] - ex, host[1] - ey) < to_target:
                    continue  # Not near, or the host is its nearer target.
                if to_target <= AT_TARGET:
                    counts['at'] += 1
                    continue
                previous = self.p_enemies.get(guid)
                if previous is None:
                    continue
                dx, dy = ex - previous[0], ey - previous[1]
                moved = math.hypot(dx, dy)
                if moved <= MOVED:
                    counts['standing'] += 1
                elif (dx * (tx - ex) + dy * (ty - ey)) / (moved * to_target) >= FOLLOW_COS:
                    counts['toward'] += 1
                else:
                    counts['elsewhere'] += 1
            self.p_enemies = seen
            for key in ('at', 'toward', 'elsewhere', 'standing'):
                self.p['chasers_' + key] += counts[key]
            self.record(event='pressure_target', elapsed=round(now - self.p_started, 1),
                        host=[round(host[0], 2), round(host[1], 2)], router=[round(pose.x, 2), round(pose.y, 2)],
                        live=sample, estimate=[round(tx, 2), round(ty, 2)], written=written,
                        error=None if error is None else round(error, 2),
                        heartbeat_error=None if heartbeat is None else round(heartbeat, 2), **counts)

        def finish(self):
            self.p_stage = 'done'
            minutes = seconds / 60
            samples = max(1, self.p['samples'])
            enemies = max(1, self.p['nearest_host'] + self.p['nearest_guest'])
            summary = dict(variant=label, routing=routing, pattern=pattern, players=len(self.members),
                           seconds=seconds,
                           host_hurt_per_min=round((self.p['host_melee'] + self.p['host_other']) / minutes, 1),
                           host_melee_per_min=round(self.p['host_melee'] / minutes, 1),
                           guest_hits_per_min=round((self.p['guest_melee'] + self.p['guest_area']) / minutes, 1),
                           guest_melee_per_min=round(self.p['guest_melee'] / minutes, 1),
                           redirected_per_min=round(self.p['redirected'] / minutes, 1),
                           target_share_host=round(self.p['nearest_host'] / enemies, 3),
                           target_share_guest=round(self.p['nearest_guest'] / enemies, 3),
                           alive_enemies=round(self.p['alive'] / samples, 1),
                           near_host=round(self.p['near_host'] / samples, 1),
                           near_guest=round(self.p['near_guest'] / samples, 1), counts=dict(self.p))
            chasers = sum(self.p['chasers_' + k] for k in ('at', 'toward', 'elsewhere', 'standing'))
            summary.update(
                target_samples=len(self.p_errors),
                target_error_median=None if not self.p_errors else round(median(self.p_errors), 2),
                target_error_max=None if not self.p_errors else round(max(self.p_errors), 2),
                heartbeat_error_median=None if not self.p_errors else round(median(self.p_heartbeat_errors), 2),
                heartbeat_error_max=None if not self.p_errors else round(max(self.p_heartbeat_errors), 2),
                chasers_following=None if not chasers else
                round((self.p['chasers_at'] + self.p['chasers_toward']) / chasers, 3),
                chasers_elsewhere=None if not chasers else round(self.p['chasers_elsewhere'] / chasers, 3))
            near_any = self.p['near_any'] / samples
            hits = (self.p['host_melee'] + self.p['guest_melee']) / minutes
            summary.update(near_any=round(near_any, 1),
                           hits_per_near_min=round(hits / near_any, 1) if near_any else None)
            self.record(event='pressure_summary', **summary)
            (ROOT / f'analysis/enemy-pressure-{label}.json').write_text(json.dumps(summary, indent=1), encoding='utf-8')
            self.stop_requested = True

    return Pressure


def session_solo(seconds, pattern):
    """One native client alone, as room_client plays a one-player room."""
    os.environ['COOP_PLAYERS'] = '1'
    from native_guest_combat import NativeCombatBridge
    from native_probe import run
    with (ROOT / 'analysis/enemy-pressure-solo.jsonl').open('w', encoding='utf-8') as output:
        bridge = adapter(NativeCombatBridge, 'fix', 'solo', seconds, pattern)(output)
        bridge.autostart = True
        try:
            run(WARMUP + seconds + 30, 1, bridge, player_numbers=[1])
        finally:
            bridge.record(event='summary', states=bridge.native_states, **bridge.counts)


def session_duo(label, seconds, pattern):
    routing = '0.0.17' if label == 'duo-0.0.17' else 'fix'
    processes, outputs = [], []
    total = WARMUP + seconds + 60
    try:
        for number in (1, 2):
            output = (ROOT / f'analysis/group-network-{number}.txt').open('w')
            outputs.append(output)
            args = [sys.executable, str(ROOT / 'reconstruction/group_online.py'), 'host' if number == 1 else 'join',
                    '--players', '2', '--seconds', str(WARMUP + seconds + 60), '--verify-pressure', routing,
                    '--pressure-seconds', str(seconds), '--pressure-pattern', pattern, '--pressure-label', label]
            env = {k: v for k, v in os.environ.items() if k not in ('WOW_ROGUE_KEY', 'COOP_VERIFY_NATIVE_MOVEMENT')}
            if number != 1:
                args += ['--slot', '2']
                if pattern == 'native':  # The guest runs with the game's own W key, as in verify_split_spawns.
                    env.update(WOW_ROGUE_KEY='w@3', COOP_VERIFY_NATIVE_MOVEMENT='1')
            processes.append(subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT, env=env))
            if number == 1:
                time.sleep(2)
        started = time.time()
        deadline = started + WARMUP + seconds + 240
        while any(p.poll() is None for p in processes):
            if time.time() > deadline:
                raise subprocess.TimeoutExpired(args, WARMUP + seconds + 240)
            elapsed = time.time() - started
            log(f'{min(99, int(100 * elapsed / total)):3d} %', f'{time.strftime("%H:%M:%S")} {label} ({pattern}): '
                                                              f'{elapsed:.0f}/{total} s')
            time.sleep(1)  # Progress every second (user rule, 17.10.2026).
        return [p.returncode for p in processes]
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        for output in outputs:
            output.close()


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--variants', default=os.environ.get('COOP_PRESSURE_VARIANTS', ','.join(VARIANTS)))
    parser.add_argument('--seconds', type=int, default=int(os.environ.get('COOP_PRESSURE_SECONDS', 180)))
    parser.add_argument('--pattern', choices=PATTERNS, default=os.environ.get('COOP_PRESSURE_PATTERN', 'circle'))
    parser.add_argument('--session', choices=('solo',), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.pattern == 'native' and args.variants != 'duo':
        parser.error('pattern native: only the variant duo (the guest runs)')
    if args.session == 'solo':
        session_solo(args.seconds, args.pattern)
        return 0
    variants = args.variants.split(',')
    if any(v not in VARIANTS for v in variants):
        parser.error(f'variants: {", ".join(VARIANTS)}')
    results, t0 = {}, time.time()
    for label in variants:
        started = time.time()
        log(' .... ', f'{label}: {args.seconds} s Messung ({args.pattern}) + {WARMUP} s Vorlauf')
        target = ROOT / f'analysis/enemy-pressure-{label}.json'
        target.unlink(missing_ok=True)
        if label == 'solo':
            code = subprocess.call([sys.executable, str(Path(__file__)), '--session', 'solo', '--seconds',
                                    str(args.seconds), '--pattern', args.pattern], timeout=WARMUP + args.seconds + 240)
            codes = [code]
        else:
            codes = session_duo(label, args.seconds, args.pattern)
        if not target.is_file():
            log('FAILED', f'{label}: keine Messung (Exit {codes})')
            continue
        results[label] = json.loads(target.read_text(encoding='utf-8'))
        r = results[label]
        log('  OK  ', f'{label} ({time.time() - started:.0f} s, Host-HURT {r["host_hurt_per_min"]}/min, '
                      f'Gast {r["guest_hits_per_min"]}/min, umgeleitet {r["redirected_per_min"]}/min, '
                      f'Ziele Host {r["target_share_host"]:.0%}, Gegner {r["alive_enemies"]}, nah {r.get("near_any")}, '
                      f'Treffer je nahem Gegner {r.get("hits_per_near_min")}/min)')
        if r.get('target_samples'):
            log(' INFO ', f'{label}: Ziel vom Gast entfernt Median {r["target_error_median"]} / Max '
                          f'{r["target_error_max"]} (Heartbeat {r["heartbeat_error_median"]} / '
                          f'{r["heartbeat_error_max"]}, {r["target_samples"]} Proben), Verfolger folgen '
                          f'{r["chasers_following"]}, laufen woanders hin {r["chasers_elsewhere"]}')
    columns = ('host_hurt_per_min', 'host_melee_per_min', 'guest_hits_per_min', 'guest_melee_per_min',
               'redirected_per_min', 'target_share_host', 'target_share_guest', 'alive_enemies', 'near_host',
               'near_guest')
    print('\n' + 'variant'.ljust(12) + ''.join(c[:18].rjust(20) for c in columns), flush=True)
    for label, r in results.items():
        print(label.ljust(12) + ''.join(str(r[c]).rjust(20) for c in columns), flush=True)
    (ROOT / 'analysis/enemy-pressure.json').write_text(json.dumps(results, indent=1), encoding='utf-8')
    log(' INFO ', f'Zusammenfassung: {len(results)}/{len(variants)} Varianten gemessen ({time.time() - t0:.0f} s)')
    return 0 if len(results) == len(variants) else 1


if __name__ == '__main__':
    sys.exit(main())
