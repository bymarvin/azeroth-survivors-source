"""0.0.22 acceptance: enemies hit the players while they run, not only while they stand (user: "enemies only hit
me while I stand still"), for the host and for a guest alike.

Four native peers (verify_group_online.py --verify-melee-run), all four as one group on the corners of a square
(SPACING apart, outward along the line to the circle's center and along the running direction). Two passes, each
first STAND_SECONDS still, then RUN_SECONDS running on a circle (RADIUS, SPEED units/s; slower than the enemies, so
they keep up). Enemies chase a running group from behind, so the rear corners meet them first:
  pass A (stand, run):   the host runs at the inner rear corner, guest 2 at the outer rear, guests 3/4 in front;
  pass B (stand2, run2): guest 3 runs at that same inner rear corner, guest 4 at the outer rear, host/guest 2 in front.
The group stays where pass A ended. Between the passes (reset, RESET_SECONDS, not counted) the enemies near the group
drop to RELEASE_HP once and are not held, so the group kills the crowd that chased it in pass A and pass B starts with
enemies as spread as pass A after the warm-up (17.10.2026 without it: 1774 of 1814 standing hits on guest 4, who stood
in that crowd, guest 3 at the rear corner 37, against 248 for the host at the same corner in pass A). Positions are written into the native games; the host's router pose follows only
every HEARTBEAT_SECONDS, the guests report their movement at a real client's cadence (GUEST_HEARTBEAT_SECONDS), so the
host knows running guests only from heartbeats unless their live position reaches him (0.0.22). Every enemy melee hit
on a player is counted on the host (natively every enemy strikes the host, the mod passes it on): the host keeps it
(enemy_hit_kept) or a guest gets it (enemy_hit_redirected, by player).
Passed when, in each pass, all players are hit at least MIN_HITS times standing and while running at least
RUN_RATIO of their standing rate, and the player at the inner rear corner (host in A, guest 3 in B) is hit at least
MIN_REAR_STAND times standing and keeps while running at least REAR_RATIO of his standing hit rate (hits per second)
and MIN_REAR_RUN hits (a rough floor: the crowd behind the group takes most hits on the outer rear guest, so the
rate of the inner one scatters, 0.44 to 1.01 on 17.10.2026); the objective running verdict is where the host
places the running guests: every TARGET_SAMPLE_SECONDS the host's guest_position() (what pursuit and hit routing
use) is compared with where the guest really was at that instant (from his later own samples, one machine and
clock): median <= TARGET_MEDIAN and 95th percentile <= TARGET_P95 per pass (the movement heartbeat alone: ~1 / 2); over both passes every player is hit at least MIN_STAND times standing (nobody hidden). The
players in front are not checked while running: pursuers reach them last. Not per pass: in pass B the enemies stay
on the guests at the rear from pass A (17.10.2026: host 0, guest 2 3 hits in stand2, 248 and 398 in stand).
Overrides for tuning: COOP_MELEE_RUN_SPEED, COOP_MELEE_RUN_RADIUS, COOP_GUEST_HEARTBEAT.
History: in a line (0.0.19/0.0.20) the player in the middle was hidden; with guests 3/4 far away the pair got a share
of the spawns only; the group killed nearly everything before it struck, so while the run is measured enemies within
HOLD_RANGE keep at least HOLD_HP health (written into their record each batch, as the players' 1000).
Disposable candidate saves only; every player has 1000 health throughout.
"""
import collections
import math
import os
import struct
import time

from group_online import GroupOnlineBridge
from native_probe import CHOOSE, game_field
from play_limits import MAX_ENEMIES
from sessions import HEARTBEAT, Pose
from updated_layout import enemy_layout
from verify_enemy_pressure import true_position

WARMUP_SECONDS = 15      # Enemies gather around the group first.
# Two passes fit into the bound candidate session cap (native_probe: 360 s incl. the guests' 30 s): 15 + 4 x 60 + 15 s.
STAND_SECONDS = 60
RUN_SECONDS = 60
RESET_SECONDS = 15       # Between the passes: the group kills the crowd from pass A (not counted).
SPEED = float(os.environ.get('COOP_MELEE_RUN_SPEED', 2))     # Below the enemies' chase speed (3 was too fast).
RADIUS = float(os.environ.get('COOP_MELEE_RUN_RADIUS', 8))
HEARTBEAT_SECONDS = .5   # Native movement heartbeat while running (sessions.py).
# Guests' movement reaches the host at the same cadence as from a real client (0.0.22; 0 = every batch as before):
# between two heartbeats the host knows a running guest only where he was (the lag pursuit and routing see).
GUEST_HEARTBEAT_SECONDS = float(os.environ.get('COOP_GUEST_HEARTBEAT', HEARTBEAT_SECONDS))
SPACING = 1.5
# Offsets of the guests from the host: (outward, along the running direction). The host's own spot is the corner
# (0, 0); the inner rear corner is the one closest to the center and last in the running direction.
FORMATIONS = {
    'A': {2: (SPACING, 0.0), 3: (0.0, SPACING), 4: (SPACING, SPACING)},      # Host and guest 2 at the rear.
    'B': {2: (SPACING, 0.0), 3: (0.0, -SPACING), 4: (SPACING, -SPACING)},    # Guests 3 and 4 at the rear.
}
GUESTS = (2, 3, 4)
PASSES = {'A': ('stand', 'run', 'host'), 'B': ('stand2', 'run2', 'guest 3')}  # Stages and the player at the rear.
STAGES = ('warmup', 'stand', 'run', 'reset', 'stand2', 'run2')
MIN_HITS = 25            # Enemy melee hits on the players per phase.
RUN_RATIO = .25          # Running: all players together, a rough floor too (17.10.2026 pass B after the reset: 0.38,
                         # pass A 1.24; the crowd behind a running group decides, the target distance is the verdict).
# The player at the inner rear corner, running vs standing hit rate. 17.10.2026 with the live position (e381e6d):
# host 1.01 (pass A), guest 3 0.97 (pass B); without it (47ab49a, heartbeat cadence) the host had 0.30.
REAR_RATIO = .35          # Rough floor only (main session 17.10.2026); the target distance decides.
MIN_REAR_STAND = 15      # Enough standing hits for the ratio to mean something (guest 3 had 37 in pass B).
MIN_REAR_RUN = 10
MIN_STAND = 2            # Every player is hit standing over both passes (a never hit player hides a broken route).
TARGET_SAMPLE_SECONDS = .25
TARGET_MEDIAN = .5       # Units between the host's estimate of a running guest and where he was (main, 17.10.2026).
TARGET_P95 = 1.5
MIN_TARGET_SAMPLES = 100  # Per pass: three guests, 60 s, 4 per second, minus the first and the last.
HOLD_HP = 300.0          # Enemies near the group cannot die during the measurement (test only).
HOLD_RANGE = 30.0
RELEASE_HP = 1.0         # Reset: the held crowd near the group dies to the players' next strikes.
HP_FROM_GUID = 0x68      # Enemy record: guid, 96 bytes, then health (all layouts: 0x78 -> 0xE0, 0x88 -> 0xF0).


def formation(stage):
    return 'B' if stage in ('reset', 'stand2', 'run2') else 'A'


def guest_spot(center, host, number, which='A'):
    """Where a guest stands in the square: outward from the circle's center and along the running direction."""
    hx, hy, hz = host
    dx, dy = hx - center[0], hy - center[1]
    length = math.hypot(dx, dy) or 1
    outward, along = FORMATIONS[which][number]
    ox, oy = dx / length, dy / length  # Outward; the running direction (counterclockwise) is (-oy, ox).
    return hx + ox * outward - oy * along, hy + oy * outward + ox * along, hz


class MeleeRunVerification(GroupOnlineBridge):
    def __init__(self, output, number, channels):
        super().__init__(output, number, channels)
        self.center = None         # Circle center (host start minus RADIUS on x).
        self.stage = 'wait'        # wait -> warmup -> stand -> run -> reset -> stand2 -> run2 -> done
        self.stage_started = None
        self.angle = self.angle_start = 0.0
        self.host_spot = None      # Host position this batch, sent to the guests.
        self.last_heartbeat = 0.0
        self.hits = {stage: dict(kept=0, redirected=0, guests={}) for stage in STAGES}
        self.durations = {}
        self.target_live = {n: collections.deque(maxlen=4000) for n in GUESTS}   # His own samples (clock, x, y).
        self.target_pending = collections.deque()      # (stage, guest, host clock, estimate, heartbeat)
        self.target_errors = {s: [] for s in STAGES}
        self.heartbeat_errors = {s: [] for s in STAGES}
        self.target_sampled = 0.0

    def decorate(self, peer, message):
        super().decorate(peer, message)
        if self.number == 1:
            message['melee_run'] = [self.stage, self.center, self.host_spot]

    def receive_peer(self, peer, message):
        super().receive_peer(peer, message)
        if self.number != 1 and 'melee_run' in message:
            self.stage, self.center, self.host_spot = message['melee_run']

    def record(self, **event):
        if self.number == 1 and self.stage in self.hits:
            if event.get('event') == 'enemy_hit_kept':
                self.hits[self.stage]['kept'] += 1
            elif event.get('event') == 'enemy_hit_redirected':
                self.hits[self.stage]['redirected'] += 1
                guests = self.hits[self.stage].setdefault('guests', {})
                player = str(event.get('player'))
                guests[player] = guests.get(player, 0) + 1
        super().record(**event)

    def receive_position(self, other, position):
        super().receive_position(other, position)
        live = self.live_positions.get(other)
        samples = self.target_live.get(other)
        if live is not None and samples is not None and (not samples or live[3] > samples[-1][0]):
            samples.append((live[3], live[1][0], live[1][1]))

    def sample_targets(self, now):
        """Where the host places each running guest (guest_position) against where he was then."""
        if self.stage in ('run', 'run2') and now - self.target_sampled >= TARGET_SAMPLE_SECONDS:
            self.target_sampled = now
            for n in GUESTS:
                if 0xFF0100 + n in self.router.players:
                    pose = self.router.players[0xFF0100 + n].pose
                    self.target_pending.append((self.stage, n, now, self.guest_position(n)[:2], (pose.x, pose.y)))
        while self.target_pending:
            stage, n, when, (ex, ey), (rx, ry) = self.target_pending[0]
            samples = self.target_live[n]
            if samples and samples[-1][0] < when and now - when < 2:
                break  # His later samples are still to come.
            self.target_pending.popleft()
            truth = true_position(samples, when)
            if truth is not None:
                self.target_errors[stage].append(math.hypot(ex - truth[0], ey - truth[1]))
                self.heartbeat_errors[stage].append(math.hypot(rx - truth[0], ry - truth[1]))

    def target_summary(self, stage):
        errors, heartbeat = sorted(self.target_errors[stage]), sorted(self.heartbeat_errors[stage])
        if not errors:
            return dict(samples=0)
        at = lambda values, q: values[min(len(values) - 1, max(0, math.ceil(q * len(values)) - 1))]
        return dict(samples=len(errors), median=round(at(errors, .5), 3), p95=round(at(errors, .95), 3),
                    max=round(errors[-1], 3), heartbeat_median=round(at(heartbeat, .5), 3),
                    heartbeat_p95=round(at(heartbeat, .95), 3))

    def place(self, client, game, x, y, z, router=True):
        client.put(game + game_field(0x488), struct.pack('<4f', x, y, z, 0))
        if router:
            self.router.players[0xFF0100 + self.number].pose = Pose(x, y, z, 0)
            moving = 1 if self.stage in ('run', 'run2') else 0  # MOVE_FORWARD while running, like a real heartbeat.
            self.latest_movement[self.number] = (HEARTBEAT, struct.pack('<II4fI', moving, 0, x, y, z, 0, 0))

    def before_batch(self, client, context):
        game = client.server + 0x10
        phase = self.native_states[client.number][0]
        if phase == 2:
            count = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
            if not 1 <= count <= 16:
                raise ValueError('Invalid native choices')
            client.call_before(context, CHOOSE, game, (client.number - 1) % count)
            return True
        if phase != 1:
            return super().before_batch(client, context)
        client.put(game + game_field(0x4A0), struct.pack('<f', 1000))
        client.put(game + game_field(0x4F8), struct.pack('<f', 1000))
        now = time.monotonic()
        if self.number == 1:
            self.host_batch(client, game, now)
        elif self.center is not None and self.host_spot is not None:
            beat = now - getattr(self, 'guest_beat', 0.0) >= GUEST_HEARTBEAT_SECONDS
            if beat:
                self.guest_beat = now
            self.place(client, game, *guest_spot(self.center, self.host_spot, self.number, formation(self.stage)),
                       router=beat)
        return super().before_batch(client, context)

    def host_batch(self, client, game, now):
        if self.stage == 'done':
            return  # Verdict written; the shutdown drain still delivers batches (0.0.22 acceptance: KeyError 'done').
        if self.center is None:
            if self.ready != set(self.members):
                return
            x, y, z = struct.unpack('<3f', client.memory(game + game_field(0x488), 12))
            self.center = [x - RADIUS, y, z]
            self.stage, self.stage_started = 'warmup', now
            self.record(event='melee_run_started', center=self.center, speed=SPEED, radius=RADIUS,
                        guest_heartbeat=GUEST_HEARTBEAT_SECONDS)
        elapsed = now - self.stage_started
        following = {'warmup': ('stand', WARMUP_SECONDS), 'stand': ('run', STAND_SECONDS),
                     'run': ('reset', RUN_SECONDS), 'reset': ('stand2', RESET_SECONDS),
                     'stand2': ('run2', STAND_SECONDS), 'run2': (None, RUN_SECONDS)}
        nxt, length = following[self.stage]
        if elapsed >= length:
            if self.stage != 'warmup':
                self.durations[self.stage] = elapsed
            if nxt is None:
                self.finish()
                return
            self.stage, self.stage_started, elapsed = nxt, now, 0
            self.angle_start = self.angle  # Pass B starts where pass A stopped.
            if nxt == 'reset':
                self.released = self.release_enemies(client, game, self.host_spot[:2])
        if self.stage in ('run', 'run2'):
            self.angle = self.angle_start + SPEED / RADIUS * elapsed
        cx, cy, cz = self.center
        x, y = cx + RADIUS * math.cos(self.angle), cy + RADIUS * math.sin(self.angle)
        self.host_spot = [x, y, cz]
        # The router pose of the host follows like his movement heartbeat: exact while standing, lagging while running.
        heartbeat = now - self.last_heartbeat >= HEARTBEAT_SECONDS
        if heartbeat:
            self.last_heartbeat = now
        self.place(client, game, x, y, cz, router=heartbeat)
        self.sample_targets(now)
        if self.stage != 'reset':
            self.hold_enemies(client, game, (x, y))

    def near_enemies(self, client, game, host):
        """(health address, health) of the living enemies within HOLD_RANGE of the host."""
        pointer, count = struct.unpack('<QQ', client.memory(game + game_field(0x568), 16))
        if not 0 < count <= MAX_ENEMIES:
            return []
        stride, guid_offset, layout = enemy_layout()
        record = struct.Struct(layout)
        data = client.memory(pointer, count * stride)
        near = []
        for index in range(count):
            dead, _, hp, *_, x, y, _, _, _ = record.unpack_from(data, index * stride + 0x68)
            if dead == 1 or not math.isfinite(hp) or hp <= 0 or math.hypot(x - host[0], y - host[1]) > HOLD_RANGE:
                continue
            near.append((pointer + index * stride + guid_offset + HP_FROM_GUID, hp))
        return near

    def hold_enemies(self, client, game, host):
        """Living enemies near the group keep HOLD_HP health, so they reach the players and strike."""
        near = self.near_enemies(client, game, host)
        for address, hp in near:
            if hp < HOLD_HP:
                client.put(address, struct.pack('<f', HOLD_HP))
        self.held = max(getattr(self, 'held', 0), len(near))
        return len(near)

    def release_enemies(self, client, game, host):
        """Reset: the crowd near the group drops to RELEASE_HP once, the players' strikes finish it."""
        near = self.near_enemies(client, game, host)
        for address, hp in near:
            if hp > RELEASE_HP:
                client.put(address, struct.pack('<f', RELEASE_HP))
        self.record(event='melee_run_reset', released=len(near))
        return len(near)

    def roles(self):
        """Hits and rates (per second) per role and stage: players, host, guests, guest 2/3/4."""
        seconds = {s: self.durations.get(s, STAND_SECONDS if s.startswith('stand') else RUN_SECONDS)
                   for s in STAGES if s != 'warmup'}
        roles = {'players': {s: self.hits[s]['kept'] + self.hits[s]['redirected'] for s in seconds},
                 'host': {s: self.hits[s]['kept'] for s in seconds},
                 'guests': {s: self.hits[s]['redirected'] for s in seconds}}
        for number in GUESTS:
            roles[f'guest {number}'] = {s: self.hits[s].get('guests', {}).get(str(number), 0) for s in seconds}
        rates = {role: {s: round(count[s] / max(seconds[s], 1e-3), 3) for s in seconds} for role, count in roles.items()}
        return roles, rates, seconds

    def finish(self):
        self.stage = 'done'
        roles, rates, seconds = self.roles()
        targets = {run: self.target_summary(run) for _, run, _ in PASSES.values()}
        self.record(event='melee_run_counts', hits=self.hits, roles=roles, rates=rates, seconds=seconds,
                    most_enemies_held=getattr(self, 'held', 0), released=getattr(self, 'released', None),
                    targets=targets)
        for name, (stand, run, rear) in PASSES.items():
            assert roles['players'][stand] >= MIN_HITS, \
                f'Pass {name}: too few enemy melee hits on the standing players: {roles["players"]} (enemies could not reach them)'
            assert roles['players'][run] >= MIN_HITS and rates['players'][run] >= RUN_RATIO * rates['players'][stand], \
                f'Pass {name}: enemies hardly hit the running players: {roles["players"]} {rates["players"]}'
            assert roles[rear][stand] >= MIN_REAR_STAND, \
                f'Pass {name}: too few hits on the standing {rear} at the rear corner: {roles[rear][stand]} {roles}'
            assert (roles[rear][run] >= MIN_REAR_RUN and rates[rear][run] >= REAR_RATIO * rates[rear][stand]), \
                (f'Pass {name}: enemies hardly hit the running {rear} at the rear corner: {roles[rear][run]} hits '
                 f'running ({rates[rear][run]}/s) vs {roles[rear][stand]} standing ({rates[rear][stand]}/s) {roles}')
            target = targets[run]
            assert target['samples'] >= MIN_TARGET_SAMPLES, f'Pass {name}: too few running guest samples: {target}'
            assert target['median'] <= TARGET_MEDIAN and target['p95'] <= TARGET_P95, \
                f'Pass {name}: the host places running guests away from where they are: {target}'
        for role in ('host', *(f'guest {n}' for n in GUESTS)):
            standing = sum(roles[role][stand] for stand, _, _ in PASSES.values())
            assert standing >= MIN_STAND, f'enemies never hit standing {role}: {roles}'
        self.record(event='network_melee_run_verified', roles=roles, rates=rates, targets=targets)
        self.stop_requested = True
