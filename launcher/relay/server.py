"""Lobby-authenticated, bounded byte tunnels; no game protocol interpretation."""
import argparse
import asyncio
import json
import ssl
import time
import urllib.request

MAX_CONNECTIONS = 128
WAIT_SECONDS = 30
IDLE_SECONDS = 30
AUTH_SECONDS = 15
BYTES_PER_SECOND = 8 * 1024 * 1024


async def copy(reader, writer):
    start, count = time.monotonic(), 0
    while True:
        data = await asyncio.wait_for(reader.read(65536), IDLE_SECONDS)
        if not data:
            return
        now = time.monotonic()
        if now - start >= 1:
            start, count = now, 0
        count += len(data)
        if count > BYTES_PER_SECOND:
            raise ValueError('Traffic limit exceeded')
        writer.write(data)
        await asyncio.wait_for(writer.drain(), 10)


async def tunnel(a, b, monitor=None):
    tasks = [asyncio.create_task(copy(a[0], b[1])), asyncio.create_task(copy(b[0], a[1]))]
    if monitor is not None:
        tasks.append(asyncio.create_task(monitor))
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        a[1].close()
        b[1].close()


class Relay:
    def __init__(self, directory):
        self.directory = directory
        self.connections = 0
        self.pairs = {}

    async def member(self, room, token):
        def poll():
            request = urllib.request.Request(self.directory + '/poll',
                data=json.dumps({'room': room}).encode(),
                headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read(16384))
        return await asyncio.to_thread(poll)

    async def monitor(self, endpoints):
        while True:
            await asyncio.sleep(AUTH_SECONDS)
            for endpoint in endpoints:
                state = await self.member(endpoint['room'], endpoint['token'])
                if state['slot'] != endpoint['slot'] or state['phase'] not in ('lobby', 'playing', 'victory'):
                    return

    async def handle(self, reader, writer):
        key = endpoint = None
        self.connections += 1
        try:
            if self.connections > MAX_CONNECTIONS:
                return
            line = await asyncio.wait_for(reader.readline(), 5)
            if len(line) > 2048 or not line.endswith(b'\n'):
                raise ValueError('Invalid handshake')
            hello = json.loads(line)
            if not isinstance(hello, dict) or hello.get('version') != 1:
                raise ValueError('Invalid protocol')
            room, token, peer = hello.get('room'), hello.get('token'), hello.get('peer')
            if (not isinstance(room, str) or len(room) != 24 or
                    any(c not in '0123456789abcdef' for c in room) or
                    not isinstance(token, str) or not 20 <= len(token) <= 128 or
                    any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in token) or
                    type(peer) is not int or peer not in (1, 2, 3, 4)):
                raise ValueError('Invalid credentials')
            state = await self.member(room, token)
            slot = state['slot']
            if state['phase'] not in ('lobby', 'playing', 'victory'):
                raise ValueError('Room is not active')
            if not ((slot == 1 and peer in (2, 3, 4)) or (slot in (2, 3, 4) and peer == 1)):
                raise ValueError('Only host-guest links are allowed')
            if peer not in [p['slot'] for p in state['players']]:
                raise ValueError('Peer is absent')
            key = (room, max(slot, peer))
            pair = self.pairs.setdefault(key, {})
            if slot in pair:
                raise ValueError('Duplicate endpoint')
            endpoint = dict(room=room, token=token, slot=slot, stream=(reader, writer), ready=asyncio.Event(), done=asyncio.Event())
            pair[slot] = endpoint
            if len(pair) == 1:
                deadline = time.monotonic() + WAIT_SECONDS
                while not endpoint['ready'].is_set():
                    # A launcher replaces waiting links after Start compacts slots.
                    # Retire closed endpoints promptly instead of blocking the new link.
                    if reader.at_eof() or time.monotonic() >= deadline:
                        return
                    try:
                        await asyncio.wait_for(endpoint['ready'].wait(), .1)
                    except TimeoutError:
                        pass
                await endpoint['done'].wait()
            else:
                endpoints = list(pair.values())
                # Recheck the waiting endpoint before exposing either byte stream.
                for item in endpoints:
                    current = await self.member(room, item['token'])
                    if (current['slot'] != item['slot'] or
                            current['phase'] not in ('lobby', 'playing', 'victory') or
                            not {slot, peer} <= {p['slot'] for p in current['players']}):
                        raise ValueError('Membership changed')
                for item in endpoints:
                    item['stream'][1].write(b'{"paired":true}\n')
                    await item['stream'][1].drain()
                # The waiting handler must not time out during an active tunnel.
                endpoints[0]['ready'].set()
                await tunnel(endpoints[0]['stream'], endpoints[1]['stream'], self.monitor(endpoints))
        except (ValueError, KeyError, TypeError, OSError, TimeoutError, asyncio.IncompleteReadError):
            pass  # Credentials and payloads are never logged.
        finally:
            self.connections -= 1
            if key is not None and endpoint is not None:
                pair = self.pairs.get(key, {})
                if pair.get(endpoint['slot']) is endpoint:
                    for item in pair.values():
                        item['stream'][1].close()
                        item['done'].set()
                        item['ready'].set()
                    self.pairs.pop(key, None)
            writer.close()


async def serve(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    relay = Relay(args.directory)
    async with await asyncio.start_server(relay.handle, args.bind, args.port, ssl=context,
            ssl_handshake_timeout=5, limit=2048, backlog=64) as server:
        print('Relay listening', flush=True)
        await server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=47771)
    parser.add_argument('--directory', default='http://127.0.0.1:47770')
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    asyncio.run(serve(parser.parse_args()))
