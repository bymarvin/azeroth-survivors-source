"""Launcher-owned routes over the existing pinned game channel and relay tunnel."""
import asyncio
import concurrent.futures
import queue
import socket
import threading
import time

from .client import connect as relay_connect
from .server import tunnel
from coop_transport import accept, connect


class Helper:
    """One cancellable relay link; credentials stay in memory."""
    def __init__(self, membership, game_port, peer, server, port):
        self.membership, self.game_port, self.peer = membership, game_port, peer
        self.server, self.port = server, port
        self.loop = asyncio.new_event_loop()
        self.ready = concurrent.futures.Future()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    async def link(self):
        while True:
            remote = local = None
            try:
                remote = await relay_connect(self.server, self.port, self.membership, self.peer)
                if self.peer != 1:
                    local = await asyncio.open_connection('127.0.0.1', self.game_port)
                    await tunnel(remote, local)
                else:
                    connected = self.loop.create_future()
                    def guest(reader, writer):
                        if connected.done():
                            writer.close()
                        else:
                            connected.set_result((reader, writer))
                    async with await asyncio.start_server(guest, '127.0.0.1', 0) as listener:
                        self.ready.set_result(listener.sockets[0].getsockname()[1])
                        local = await asyncio.wait_for(connected, 10)
                        await tunnel(local, remote)
                    return
            except (OSError, ValueError, TimeoutError) as error:
                if self.peer == 1:
                    if not self.ready.done():
                        self.ready.set_exception(ConnectionError('Relay connection failed'))
                    return
            finally:
                for stream in (remote, local):
                    if stream:
                        stream[1].close()
            await asyncio.sleep(.5)

    def run(self):
        asyncio.set_event_loop(self.loop)
        self.task = self.loop.create_task(self.link())
        try:
            self.loop.run_until_complete(self.task)
        except asyncio.CancelledError:
            pass
        finally:
            if not self.ready.done():
                self.ready.set_exception(ConnectionError('Relay connection stopped'))
            self.loop.close()

    def close(self):
        if self.thread.is_alive():
            try:
                self.loop.call_soon_threadsafe(lambda: self.task.cancel())
            except RuntimeError:
                pass
            self.thread.join(2)


def message(channel, stop, timeout=10):
    deadline = time.monotonic() + timeout
    while not stop.is_set() and time.monotonic() < deadline:
        try:
            return channel.incoming.get(timeout=.02)
        except queue.Empty:
            channel.check()
    raise TimeoutError('Party connection timed out')


DIRECT_TIMEOUT = 3  # Seconds for the direct attempt before the relay takes over.
LAN_TIMEOUT = 8     # LAN/VPN mode: direct only, so a slow VPN gets more time.
WAIT_HINT_SECONDS = 30  # prepare(): from then on the waiting status says what to check.
LOOPBACK = ('127.0.0.1', '::1', 'localhost')


class Routes:
    def __init__(self, room, token, pairing, build, server='dash2812.de', port=47771, log=None, relay=True,
                 direct_address=None, unreachable=None):
        """relay=False (LAN/VPN mode): no relay helpers; guests connect directly to direct_address (the
        address they reached the host's lobby at) and report `unreachable` (a firewall hint) on failure."""
        self.room, self.pairing, self.build = room, pairing, build
        self.relay, self.direct_address, self.unreachable = relay, direct_address, unreachable
        self.log = log or (lambda **event: None)  # Route diagnostics; never tickets or tokens.
        self.membership = dict(room=room['id'], token=token)
        self.server, self.port = server, port
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.channels, self.helpers, self.labels = {}, {}, {}
        self.handed_off = False
        self.listener = None
        self.error = None
        self.generation = 0
        if room['slot'] == 1:
            self.listener = socket.create_server(('0.0.0.0', room['connection']['port']))
            self.listener.settimeout(.25)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def drop(self, slot):
        channel = self.channels.pop(slot, None)
        if channel:
            channel.close()
        helper = self.helpers.pop(slot, None)
        if helper:
            helper.close()
        self.labels.pop(slot, None)

    def update(self, room):
        with self.lock:
            if self.room['run'] != room['run'] or self.room['slot'] != room['slot']:
                self.generation += 1
                for slot in set(self.channels) | set(self.helpers):
                    self.drop(slot)
                self.labels.clear()
            elif room['slot'] == 1:
                for slot in set(self.channels) | set(self.helpers):
                    if room['tickets'].get(str(slot)) != self.room['tickets'].get(str(slot)):
                        self.drop(slot)
            self.room = room

    def run(self):
        while not self.stop.is_set():
            try:
                if self.listener:
                    self.host()
                else:
                    self.guest()
            except (OSError, ValueError, ConnectionError, TimeoutError) as error:
                self.error = str(error)
            self.stop.wait(.1)

    def host(self):
        with self.lock:
            if self.stop.is_set() or self.handed_off:
                return
            room, generation = self.room, self.generation
            members = {int(n): ticket for n, ticket in room['tickets'].items()}
            for slot in members:
                channel = self.channels.get(slot)
                if channel and (channel.closed or channel.error) and not self.handed_off:
                    self.drop(slot)
                if self.relay and slot not in self.helpers and slot not in self.channels:
                    self.helpers[slot] = Helper(self.membership, room['connection']['port'], slot,
                                                self.server, self.port)
                    self.labels[slot] = 'Checking connection…'
                elif not self.relay and slot not in self.channels:
                    self.labels.setdefault(slot, 'Waiting for a direct connection…')
        channel = None
        try:
            def current_members(slot, ticket):
                deadline = time.monotonic() + 1
                while not self.stop.is_set():
                    with self.lock:
                        members.clear()
                        members.update({int(n): ticket for n, ticket in self.room['tickets'].items()})
                    if members.get(slot) == ticket or time.monotonic() >= deadline:
                        break
                    self.stop.wait(.02)
                return members
            slot, channel = accept(self.listener, self.pairing, {}, self.build, current_members, timeout=2)
            hello = message(channel, self.stop, 3)
            if (hello.get('kind') != 'route' or
                    hello.get('route') not in ('Direct', 'Relay')):
                raise ValueError('Invalid route handshake')
            with self.lock:
                if (self.stop.is_set() or hello.get('run') != self.room['run'] or
                        self.handed_off or slot in self.channels):
                    raise ValueError('Party connection changed')
                if self.room['tickets'].get(str(slot)) != members.get(slot):
                    raise ValueError('Player left the party')
                channel.send(dict(kind='route', run=self.room['run'], slot=slot))
                self.channels[slot], self.labels[slot] = channel, hello['route']
                self.log(event='guest_route', slot=slot, route=hello['route'])
                if hello['route'] == 'Direct':
                    helper = self.helpers.pop(slot, None)
                    if helper:
                        helper.close()
                channel = None
                self.error = None
        except socket.timeout:
            pass
        finally:
            if channel:
                channel.close()

    def guest(self):
        with self.lock:
            if self.stop.is_set() or self.handed_off:
                return
            room, generation = self.room, self.generation
            channel = self.channels.get(1)
            if channel and not (channel.closed or channel.error):
                return
            self.drop(1)
            self.labels[room['slot']] = 'Testing direct connection…'
        connection = room.get('connection')
        if not connection:
            return
        invite = dict(fingerprint=connection['fingerprint'], token=room['ticket'])
        channel = helper = None
        try:
            route = 'Direct'
            if not self.relay:
                # LAN/VPN mode: first the address this guest reached the host's lobby at, then the address the host
                # published (its first LAN/VPN candidate); no relay to fall back to.
                addresses = list(dict.fromkeys(a for a in (self.direct_address, connection.get('address'))
                                               if a and (a not in LOOPBACK or self.direct_address in LOOPBACK)))
                started, failure = time.monotonic(), None
                for address in addresses:
                    with self.lock:
                        if generation == self.generation:
                            self.labels[room['slot']] = f'Trying the host at {address}:{connection["port"]}…'
                    try:
                        channel = connect(address, connection['port'], invite, self.build, room['slot'],
                                          timeout=LAN_TIMEOUT)
                        break
                    except (OSError, ValueError) as error:
                        failure = error
                        self.log(event='direct_failed', slot=room['slot'], route='none', reason=type(error).__name__)
                if channel is None:
                    with self.lock:
                        if generation == self.generation:
                            self.labels[room['slot']] = 'Host not reachable; retrying…'
                    self.stop.wait(2)
                    tried = ' or '.join(f'{a}:{connection["port"]}' for a in addresses) or 'no address'
                    raise ConnectionError(f'Cannot reach the host at {tried} (its room list answered, the game '
                                          'connection does not). ' + (self.unreachable or '')) from failure
                self.log(event='direct_connected', slot=room['slot'], seconds=round(time.monotonic() - started, 2))
            else:
                try:
                    address = connection.get('address')
                    if not address or address in LOOPBACK and self.server not in LOOPBACK:
                        # The host has no reachable port (placeholder 127.0.0.1 on a remote
                        # directory, e.g. no UPnP/NAT-PMP or CGNAT): relay only. A local test
                        # directory keeps the direct loopback connection.
                        raise ConnectionError('no_direct_offer')
                    # Guests behind the host's own router also use the public address
                    # (hairpin NAT); routers without hairpin fall back to the relay.
                    started = time.monotonic()
                    channel = connect(address, connection['port'], invite, self.build,
                                      room['slot'], timeout=DIRECT_TIMEOUT)
                    self.log(event='direct_connected', slot=room['slot'],
                             seconds=round(time.monotonic() - started, 2))
                except (OSError, ValueError) as error:
                    self.log(event='direct_failed', slot=room['slot'], route='relay',
                             reason=str(error) if str(error) == 'no_direct_offer' else type(error).__name__)
                    route = 'Relay'
                    with self.lock:
                        if self.stop.is_set() or generation != self.generation:
                            return
                        self.labels[room['slot']] = 'Direct unavailable; connecting through relay…'
                        helper = Helper(self.membership, 0, 1, self.server, self.port)
                        self.helpers[1] = helper
                    local_port = helper.ready.result(timeout=40)
                    channel = connect('127.0.0.1', local_port, invite, self.build, room['slot'])
                    self.log(event='relay_connected', slot=room['slot'])
            channel.send(dict(kind='route', run=room['run'], route=route))
            if message(channel, self.stop, 5) != dict(kind='route', run=room['run'], slot=room['slot']):
                raise ValueError('Host rejected party route')
            with self.lock:
                if self.stop.is_set() or generation != self.generation:
                    return
                self.channels[1] = channel
                self.labels[room['slot']] = route
                channel = None
                self.error = None
        finally:
            if channel:
                channel.close()
            with self.lock:
                if helper and self.channels.get(1) is None:
                    if self.helpers.get(1) is helper:
                        self.helpers.pop(1)
                    helper.close()

    def waiting_text(self, room, wanted, waited):
        """What prepare() waits for, for the launcher status (once a second), with a hint after 30 s."""
        with self.lock:
            missing = sorted(wanted - set(self.channels))
            labels, error = dict(self.labels), self.error
        if room['slot'] == 1:
            who = ', '.join(f'player {slot} ({labels.get(slot) or "not connected"})' for slot in missing) or 'the final check'
            text = f'Waiting for {who} to connect… ({int(waited)} s)'
        else:
            address = self.direct_address or (room.get('connection') or {}).get('address')  # what the guest dials
            port = (room.get('connection') or {}).get('port')
            target = f' at {address}:{port}' if address else ''
            text = f'Connecting to the host{target}… ({int(waited)} s, {labels.get(room["slot"]) or "connecting"})'
        if waited >= WAIT_HINT_SECONDS:
            hint = error or (self.unreachable if room['slot'] == 1 else None)  # host: e.g. a Public VPN network
            text += (f' {hint}' if hint else
                     (' Still waiting: check that every player has joined this room and is not stuck on an error, '
                      'that all PCs are on the same network (or VPN), and that Windows Firewall allows co-op '
                      '(Private network). The start gives up after 2 minutes.'))
        return text

    def prepare(self, room, cancel, timeout=120, progress=None):
        """Revalidate the final roster and every authenticated channel before launch.

        progress(text), if given, gets a status line about once a second while channels are missing.
        """
        expected = {p['slot'] for p in room['players']} - {1}
        wanted = expected if room['slot'] == 1 else {1}
        started = time.monotonic()
        deadline = started + timeout
        shown = None
        while not cancel.is_set() and not self.stop.is_set() and time.monotonic() < deadline:
            waited = time.monotonic() - started
            if progress is not None and (shown is None or waited - shown >= 1):
                shown = waited
                try:
                    progress(self.waiting_text(room, wanted, waited))
                except Exception:
                    pass  # A status line must never stop the launch.
            with self.lock:
                if (self.room['run'] != room['run'] or
                        self.room['players'] != room['players'] or self.room['slot'] != room['slot']):
                    raise ValueError('Party changed before launch. Form a new room to try again.')
                if set(self.channels) == wanted:
                    for channel in self.channels.values():
                        channel.check()
                    self.handed_off = True
                    channels = dict(self.channels)
                    break
            cancel.wait(.05)
        else:
            raise TimeoutError('Party did not connect within 2 minutes. ' + self.waiting_text(room, wanted, timeout))
        count = len(room['players'])
        check = dict(kind='prepare', run=room['run'], players=count)
        if room['slot'] == 1:
            for channel in channels.values():
                channel.send(check)
            for channel in channels.values():
                if message(channel, cancel, max(.1, deadline - time.monotonic())) != check:
                    raise ValueError('Guest did not confirm the final party')
            for channel in channels.values():
                channel.send(dict(kind='start', players=count, routes=self.labels))
        else:
            channel = channels[1]
            if message(channel, cancel, max(.1, deadline - time.monotonic())) != check:
                raise ValueError('Host changed the final party')
            channel.send(check)
            start = message(channel, cancel, max(.1, deadline - time.monotonic()))
            if start.get('kind') != 'start' or start.get('players') != count:
                raise ValueError('Invalid room launch')
            with self.lock:
                self.labels = {int(k): v for k, v in start['routes'].items()}
        return channels

    def close(self):
        self.stop.set()
        if self.listener:
            self.listener.close()
        with self.lock:
            for slot in set(self.channels) | set(self.helpers):
                self.drop(slot)
        self.thread.join(12)
