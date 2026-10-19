"""Disposable four-peer chests once per player, guest-four coin pickup and the orb rain next to the host.

Step 1 (0.0.19, chests variant B): one chest at the fixture, every guest opens it once (own cost 20, own choice), the
host never reaches it. Step 1.5: a chest lands on the host, who opens it natively at once; every guest then opens the
same chest (phantom on the host) once at his own next cost (31). Step 2: guest four picks up a coin shared by all.

Step 3 (0.0.18): guest 2 stands next to the host while RAIN_ORBS XP orbs of RAIN_VALUE land around them, some
inside the host's pickup radius (the native pickup pulls them: +0x18 != 0), some only inside the guest's. No guest
may take an orb that was ever seen flying to the host (0.0.17 bug); every orb ends exactly once, flying to the host
(native pickup) or taken by a guest (credited RAIN_VALUE once, with every personal XP multiplier at 1); the XP
awarded meanwhile is at least RAIN_VALUE per orb (the native pickup and the guest credits award several orbs in one
AWARD_XP, and native kill orbs add to it); every orb is gone in time.
"""
import math
import struct
import time

from group_online import GroupOnlineBridge
from native_probe import CHOOSE, SPAWN_LOOT, game_field
from sessions import HEARTBEAT, Pose


RAIN_VALUE = 37     # Unusual XP value: identifies the test orbs among native drops.
RAIN_ORBS = 10      # Half inside the host's pickup radius, half only inside the guest's (when the radii allow).
RAIN_SECONDS = 60   # Every orb must be gone this long after the first one landed.


def loot_clear(center, chests):
    # Keep both the contested pickup and later waiting positions clear of map loot.
    return all(sum((a - b) ** 2 for a, b in zip(position, (center[0] + waiting, *center[1:]))) > 100
               for _, position, *_ in chests.values() for waiting in (0, 20))


def clear_loot_center(pose, chests):
    for offset in range(30, 151, 10):
        center = [pose.x + offset, pose.y, pose.z]
        if loot_clear(center, chests):
            return center
    raise ValueError('No clear native economy test location near the host')


class NetworkEconomyVerification(GroupOnlineBridge):
    def __init__(self, output, number, channels):
        super().__init__(output, number, channels)
        self.step = 0
        self.center = None
        self.prepared = False
        self.snapshots = {}
        self.reservations = set()
        self.spawned_steps = set()
        self.baseline = None
        self.coin_seen = False
        self.host_opened = False
        self.settled = None
        # The native start loot appears with the first running frame. Choose
        # the fixture only from a host loot snapshot taken in phase 1.
        self.loot_fresh = False
        self.host_chest = None      # Where the host-first chest landed (step 1.5).
        self.rain = None            # Host position of the orb rain (step 3).
        self.rain_spots = None
        self.rain_spawned = 0
        self.rain_started = None
        self.orbs = {}              # guid -> ever seen flying to the host
        self.guest_orbs, self.stolen, self.guest_credits = set(), [], []
        self.rain_awards = 0        # XP awarded on the host while the rain runs (sum of AWARD_XP).
        self.rain_done = False      # Verified once; later batches until the stop do nothing (0.0.20: 6 records).

    def decorate(self, peer, message):
        super().decorate(peer, message)
        if self.number == 1:
            message['economy_diagnostic'] = [self.step, self.center, self.rain, self.host_chest]
        if self.number in self.snapshots:
            message['economy_snapshot'] = self.snapshots[self.number]

    def receive_peer(self, peer, message):
        if self.number == 1 and (message.get('claim') or {}).get('status') == 'reserved':
            self.reservations.add(peer)
        super().receive_peer(peer, message)
        if self.number != 1 and 'economy_diagnostic' in message:
            self.step, self.center, self.rain, self.host_chest = message['economy_diagnostic']
        if 'economy_snapshot' in message:
            self.snapshots[peer] = message['economy_snapshot']

    def record(self, **event):
        if event.get('event') == 'shared_gold_pickup' and event.get('picker') == 4:
            self.coin_seen = True
        if event.get('event') == 'host_chest_opened' and self.step == 1.5:
            self.host_opened = True
        if self.number == 1 and self.step == 3:
            if event.get('event') == 'guest_xp_pickup' and event.get('guid') in self.orbs:
                self.guest_orbs.add(event['guid'])
                self.guest_credits.append((event['guid'], event.get('amount')))
                if self.orbs[event['guid']]:
                    self.stolen.append(event['guid'])  # Taken from the host while flying to him.
            if event.get('event') == 'native_xp_award' and self.rain_started:
                self.rain_awards += event.get('amount', 0)
        super().record(**event)

    def sync_chests(self, client, context):
        # Let all three native clients reserve before the host resolves the
        # contested object. Only the diagnostic delays this arbitration.
        if client.number == 1 and self.step == 1 and self.chest_claim and len(self.reservations) < 3:
            return False
        result = super().sync_chests(client, context)
        if client.number == 1 and self.native_states[1][0] == 1:
            self.loot_fresh = True
        if client.number == 1 and self.step == 3:
            for guid, (_, _, kind, value, flying) in self.chests.items():
                if kind == 0 and value == RAIN_VALUE:
                    self.orbs[guid] = self.orbs.get(guid, False) or bool(flying)
        return result

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
        if self.step == 3:
            client.put(game + game_field(0x514), struct.pack('<f', 1))  # Party XP multiplier 1: an orb = its value.
        if self.number == 1 and self.center is None and self.ready == set(self.members) and self.loot_fresh:
            pose = self.router.players[0xFF0101].pose
            self.center = clear_loot_center(pose, self.chests)
            self.record(event='network_economy_center', center=self.center, loot=len(self.chests))
        if self.center is None:
            return super().before_batch(client, context)
        if not self.prepared:
            self.prepared = True
            for offset, value in ((0x4A8, 100), (0x6D0, 100), (0x6D4, 0), (0x894, 20)):
                client.put(game + game_field(offset), struct.pack('<I', value))
        if self.number != 1:
            x, y, z = self.center
            if self.step >= 2 and self.number != 4:
                x += 20
            if self.step == 1.5 and self.host_chest:
                # Around the chest the host opened (contact 3), one per guest.
                x, y, z = self.host_chest[0] + .8 * (self.number - 3), self.host_chest[1] + 1, self.host_chest[2]
            if self.step == 3 and self.number == 2 and self.rain:
                x, y, z = self.rain[0] + 1, self.rain[1], self.rain[2]  # Right next to the host.
            pose = Pose(x, y, z, 0)
            client.put(game + game_field(0x488), struct.pack('<4f', x, y, z, 0))
            self.router.players[0xFF0100 + self.number].pose = pose
            self.latest_movement[self.number] = (HEARTBEAT, struct.pack('<II4fI', 0, 0, x, y, z, 0, 0))
        gold = struct.unpack('<I', client.memory(game + game_field(0x4A8), 4))[0]
        earned, opened = struct.unpack('<II', client.memory(game + game_field(0x6D0), 8))
        radius = struct.unpack('<f', client.memory(game + game_field(0x510), 4))[0]
        self.snapshots[self.number] = [gold, earned, opened, self.step, bool(self.chest_claim), radius]
        if self.number == 1 and len(self.snapshots) == 4:
            current = [self.snapshots[n] for n in self.members]
            if self.step == 0:
                self.step = 1
            if self.step == 1 and [s[2] for s in current] == [0, 1, 1, 1] and not any(s[4] for s in current):
                assert self.reservations == {2, 3, 4}, self.reservations
                spending = [s[1] - s[0] for s in current]
                assert spending == [0, 20, 20, 20], spending  # Each guest at his own cost; the host did not open.
                self.record(event='network_chest_contention_verified', openers=[2, 3, 4], snapshots=current)
                self.step = 1.5
                self.host_chest = list(struct.unpack('<3f', client.memory(game + game_field(0x488), 12)))
            if self.step == 1.5 and [s[2] for s in current] == [1, 2, 2, 2] and not any(s[4] for s in current):
                spending = [s[1] - s[0] for s in current]
                # Host 20 natively; every guest 20 + 31 (trunc(float32(20 * 1.3) + 5)) for the phantom chest.
                assert spending == [20, 51, 51, 51], spending
                assert self.host_opened, 'The host did not open the chest natively first'
                self.record(event='network_host_first_chest_verified', snapshots=current)
                self.baseline = [s[:3] for s in current]
                self.step = 2
            if self.step in (1, 1.5, 2) and self.step not in self.spawned_steps:
                if self.step == 1 and not loot_clear(self.center, self.chests):
                    # Native loot landed on the fixture before the contested chest.
                    if any(s[2] for s in current) or any(s[4] for s in current):
                        raise AssertionError(f'Native loot reached the economy fixture: {current}')
                    self.center = clear_loot_center(self.router.players[0xFF0101].pose, self.chests)
                    self.record(event='network_economy_center', center=self.center, loot=len(self.chests))
                    return super().before_batch(client, context)
                if self.step == 1.5:
                    if all(s[3] == 1.5 for s in current[1:]):
                        self.spawned_steps.add(self.step)
                        client.call_before(context, SPAWN_LOOT, game, 2, amount=1, position=self.host_chest)
                        return True
                elif self.step == 1 or all(s[3] == 2 for s in current[1:]):
                    self.spawned_steps.add(self.step)
                    client.call_before(context, SPAWN_LOOT, game, 2 if self.step == 1 else 1,
                                       amount=1 if self.step == 1 else 40, position=self.center)
                    return True
            if self.step == 2 and self.coin_seen:
                deltas = [s[0] - old[0] for s, old in zip(current, self.baseline)]
                if min(deltas) >= 40 and len(set(deltas)) == 1 and not any(s[4] for s in current):
                    assert all(s[2] == old[2] and s[1] - old[1] == delta
                               for s, old, delta in zip(current, self.baseline, deltas))
                    if self.settled is None:
                        self.settled = time.monotonic()
                    elif time.monotonic() - self.settled > 2:
                        self.record(event='network_guest_four_gold_verified', amount=deltas[0], snapshots=current)
                        self.step = 3
                        self.rain = list(struct.unpack('<3f', client.memory(game + game_field(0x488), 12)))
                        self.record(event='network_orb_rain_started', host=self.rain)
            if self.step == 3 and self.rain_orbs(client, context, game, current):
                return True
        return super().before_batch(client, context)

    def rain_orbs(self, client, context, game, current):
        """Host: spawn the orbs one per batch once guest 2 stands next to him, then check every orb's fate."""
        if self.rain_done:
            return False
        hx, hy, hz = self.rain
        guest = self.router.players[0xFF0102].pose
        if self.rain_spots is None:
            if current[1][3] != 3 or math.hypot(guest.x - hx - 1, guest.y - hy) > .5:
                return False  # Guest 2 is not next to the host yet.
            host_radius, guest_radius = current[0][5], current[1][5]
            assert all(math.isfinite(r) and 0 < r <= 100 for r in (host_radius, guest_radius)), current
            inner = [(hx + .6 + .1 * i, hy + .3 * (i - 2)) for i in range(RAIN_ORBS // 2)]
            # Outside the host's radius, inside the guest's (standing 1 to the right of the host).
            outer = [(hx + host_radius + .5, hy + dy) for dy in (0, .3, -.3, .6, -.6)[:RAIN_ORBS - len(inner)]
                     if math.hypot(host_radius + .5 - 1, dy) < guest_radius - .2]
            self.rain_spots = inner + outer
            self.rain_outer = len(outer)
            self.record(event='network_orb_rain_spots', host_radius=host_radius, guest_radius=guest_radius,
                        inner=len(inner), outer=len(outer))
        if self.rain_spawned < len(self.rain_spots):
            x, y = self.rain_spots[self.rain_spawned]
            self.rain_spawned += 1
            self.rain_started = self.rain_started or time.monotonic()
            client.call_before(context, SPAWN_LOOT, game, 0, amount=RAIN_VALUE, position=[x, y, hz])
            return True
        gone = [g for g in self.orbs if g not in self.chests]
        elapsed = time.monotonic() - self.rain_started
        if len(self.orbs) == len(gone) == len(self.rain_spots) and not self.chest_claim:
            flying = sum(self.orbs.values())
            assert not self.stolen, f'Guests took orbs that flew to the host: {self.stolen}'
            assert flying >= 1, 'No test orb flew to the host'
            assert len(self.guest_orbs) >= (1 if self.rain_outer else 0), (self.guest_orbs, self.rain_outer)
            flew = {guid for guid, seen in self.orbs.items() if seen}
            assert not flew & self.guest_orbs and len(flew) + len(self.guest_orbs) == len(self.rain_spots),                 f'an orb ended twice or not at all: {len(flew)} to the host, {len(self.guest_orbs)} to guests'
            assert len(self.guest_credits) == len(self.guest_orbs), f'a guest orb was credited twice: {self.guest_credits}'
            assert all(amount == RAIN_VALUE for _, amount in self.guest_credits), self.guest_credits
            assert self.rain_awards >= RAIN_VALUE * len(self.rain_spots), (self.rain_awards, len(self.rain_spots))
            self.record(event='network_orb_rain_verified', orbs=len(self.rain_spots), flying_to_host=flying,
                        guest_pickups=len(self.guest_orbs), awards=self.rain_awards, seconds=round(elapsed, 1))
            self.rain_done = True
            self.stop_requested = True
            return False
        if elapsed > RAIN_SECONDS:
            raise AssertionError(f'Orb rain incomplete after {RAIN_SECONDS} s: seen {len(self.orbs)}, gone {len(gone)}, '
                                 f'spots {len(self.rain_spots)}, awards {self.rain_awards}, claim {self.chest_claim}')
        return False
