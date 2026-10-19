"""Outbound relay tunnel. Credentials are read from a private JSON file, not argv."""
import argparse
import asyncio
import json
from pathlib import Path
import ssl

if __package__:
    from .server import tunnel
else:
    from server import tunnel


async def connect(host, port, membership, peer):
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port,
        ssl=ssl.create_default_context(), server_hostname=host, ssl_handshake_timeout=5), 10)
    try:
        hello = dict(version=1, room=membership['room'], token=membership['token'], peer=peer)
        writer.write(json.dumps(hello).encode() + b'\n')
        await writer.drain()
        response = await asyncio.wait_for(reader.readline(), 35)
        if response != b'{"paired":true}\n':
            raise ConnectionError('Relay rejected membership or peer did not connect')
        return reader, writer
    except BaseException:
        writer.close()
        raise


async def run(args):
    membership = json.loads(Path(args.membership).read_text())
    if args.role == 'host':
        async def link(peer):
            while True:
                remote = None
                try:
                    remote = await connect(args.server, args.port, membership, peer)
                    local = await asyncio.open_connection('127.0.0.1', args.game_port)
                    await tunnel(remote, local)
                except (OSError, ValueError, TimeoutError):
                    if remote:
                        remote[1].close()
                await asyncio.sleep(2)
        await asyncio.gather(*(link(peer) for peer in (2, 3, 4)))
    else:
        busy = False
        async def guest(reader, writer):
            nonlocal busy
            if busy:
                writer.close()
                return
            busy = True
            try:
                remote = await connect(args.server, args.port, membership, 1)
                await tunnel((reader, writer), remote)
            except (OSError, ValueError, TimeoutError):
                writer.close()
            finally:
                busy = False
        async with await asyncio.start_server(guest, '127.0.0.1', args.game_port) as listener:
            print('Local relay tunnel ready', flush=True)
            await listener.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=('host', 'guest'))
    parser.add_argument('--membership', required=True)
    parser.add_argument('--server', default='dash2812.de')
    parser.add_argument('--port', type=int, default=47771)
    parser.add_argument('--game-port', type=int, default=47773)
    asyncio.run(run(parser.parse_args()))
