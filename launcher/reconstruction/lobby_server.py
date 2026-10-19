"""Bounded room directory API; loopback by default, TLS required for remote use."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
from urllib.parse import urlsplit

from lobby import Rejected, Rooms

GENERIC = 'Request rejected; check room state, membership and game build'  # All older clients ever read.
# A request the directory cannot parse (missing field, wrong type): no internal detail, but actionable.
MALFORMED = 'This launcher sent a request the room directory cannot read; update the co-op launcher and try again'
from crash_reports import CrashReports, MAX_REPORT

# Why requests are refused in practice: one boot-log line per refusal (category and endpoint only, never a
# name, room, invite, token or address): journalctl -u azsurvivors-lobby | grep 'reason=' | awk '{print $4}' | sort | uniq -c
CATEGORIES = (('This room is gone', 'room_gone_or_invite'), ('This room has already', 'started_or_full'),
              ('Your game', 'build_mismatch_guest'), ("A player's game differs", 'build_mismatch_start'),
              ('You are no longer', 'membership_lost'), ('Select a supported host region', 'region_missing'),
              ('Use a name', 'name'), ('Use a message', 'chat_text'), ('Wait a second', 'chat_rate'),
              ('Room directory is full', 'directory_full'), ('Only the', 'not_host'), ('Action is unavailable', 'action_state'),
              ('Room changed', 'room_changed'), ('Invalid', 'invalid'))


def category(text):
    return next((name for prefix, name in CATEGORIES if text.startswith(prefix)), 'other')


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass  # Never log invitations or membership credentials.

    def reply(self, status, value):
        body = json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.rooms.expire()
        if self.path == '/rooms':
            self.reply(200, dict(rooms=self.server.rooms.listing()))
        else:
            self.reply(404, dict(error='Unknown endpoint'))

    def do_POST(self):
        try:
            origin = self.headers.get('Origin')
            if origin and urlsplit(origin).netloc != self.headers.get('Host'):
                raise ValueError('Cross-origin requests are unavailable')
            if self.headers.get_content_type() != 'application/json' or self.headers.get('Transfer-Encoding'):
                raise ValueError('Use a bounded JSON request')
            length = int(self.headers.get('Content-Length', '0'))
            crash = self.path in ('/crash-report', '/completed-report')
            metadata = self.server.reports.authorize(self.headers.get('Authorization', '')) if crash else None
            if not 1 <= length <= (MAX_REPORT if crash else 8192):
                raise ValueError('Request exceeds size limit')
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError('Incomplete request')
            request = json.loads(body)
            if not isinstance(request, dict):
                raise ValueError('Expected a JSON object')
            rooms = self.server.rooms
            rooms.expire()
            if crash:
                result = self.server.reports.collect(metadata, request, completed=self.path == '/completed-report')
            elif self.path == '/create':
                result = rooms.create(request['name'], request['player'], request['private'], request['build'], request.get('region'), request.get('version'))
            elif self.path == '/join':
                result = rooms.join(request['room'], request['player'], request['build'], request.get('invite'),
                                    request.get('version'))
            elif self.path in ('/poll', '/action', '/connection', '/chat'):
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer '):
                    raise ValueError('Membership is required')
                if self.path == '/chat':
                    result = rooms.chat(request['room'], auth[7:], request['text'])
                elif self.path == '/connection':
                    result = rooms.connection(request['room'], auth[7:], request['address'], request['port'], request['fingerprint'])
                elif self.path == '/poll':
                    result = rooms.poll(request['room'], auth[7:])
                else:
                    result = rooms.action(request['room'], auth[7:], request['action'], request['revision'], request.get('build'))
            else:
                self.reply(404, dict(error='Unknown endpoint'))
                return
            if self.path in ('/create', '/join', '/poll'):
                room = result['room'] if 'room' in result else result
                room['crash_upload_permit'] = self.server.reports.permit(room)
            self.reply(200, result)
        except Rejected as error:
            # 0.0.20: the reason a player can act on (lobby.py texts only); older clients ignore it.
            code = category(str(error))
            print(f'[ INFO ] 400 reason={code} endpoint={self.path.split("?")[0][:16]}', flush=True)
            # 0.0.23: 'code' is the same category as the log line, so a player's message maps to it.
            self.reply(400, dict(error=GENERIC, reason=str(error), code=code))
        except (ValueError, KeyError, TypeError, TimeoutError):
            print(f'[ INFO ] 400 reason=malformed_request endpoint={self.path.split("?")[0][:16]}', flush=True)
            self.reply(400, dict(error=GENERIC, reason=MALFORMED, code='malformed_request'))
        except OSError:
            self.reply(503, dict(error='Report storage unavailable; keep the local report'))


class DirectoryServer(ThreadingHTTPServer):
    # Caddy opens one connection per request. The stdlib backlog of 5 overflowed under bursts and
    # under CPU throttling, so Caddy answered 502 (dial timeout / connection reset).
    request_queue_size = 1024


class ExclusiveDirectoryServer(DirectoryServer):
    """The LAN lobby on a player's PC: on Windows SO_REUSEADDR would let a second program or co-op launcher bind
    the same port and receive part of the connections, so the port is claimed exclusively (0.0.24)."""
    allow_reuse_address = not hasattr(socket, 'SO_EXCLUSIVEADDRUSE')

    def server_bind(self):
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def server(address, *, collected_logs='collected-logs', exclusive=False, rooms=None):
    result = (ExclusiveDirectoryServer if exclusive else DirectoryServer)(address, Handler)
    result.daemon_threads = True
    result.rooms = rooms if rooms is not None else Rooms()
    result.reports = CrashReports(collected_logs)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=47770)
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--collected-logs', default='collected-logs')
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key) or (args.bind not in ('127.0.0.1', 'localhost') and not args.cert):
        parser.error('Remote room directories require --cert and --key')
    with server((args.bind, args.port), collected_logs=args.collected_logs) as app:
        if args.cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.cert, args.key)
            app.socket = context.wrap_socket(app.socket, server_side=True)
        print('Room directory started', flush=True)
        app.serve_forever()


if __name__ == '__main__':
    main()
