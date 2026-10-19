"""Local room-browser controller and native game launcher. No third-party services."""
import argparse
import hashlib
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import ssl
import sys
import threading
from collections import deque
import time
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
try:
    from launcher_profile import LauncherProfile, game_version
except ImportError as _missing:  # The first co-op module this process needs: say how to repair (0.0.23).
    print(f'[FAILED] A co-op file is missing or damaged: Python module {_missing.name!r}. Close the game and run '
          'Azeroth-Survivors-Together-Updater.exe in the co-op folder to repair it.', file=sys.stderr, flush=True)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def rejection_reason(error):
    """The directory's reason for a 400 (lobby_server.py 0.0.20+), or None for older directories."""
    if not hasattr(error, 'coop_reason'):
        reason = code = None
        try:
            body = json.loads(error.read(4096) or b'{}')
            text = body.get('reason') if isinstance(body, dict) else None
            if isinstance(text, str) and 1 <= len(text) <= 300 and all(c.isprintable() for c in text):
                reason = text
            value = body.get('code') if isinstance(body, dict) else None
            if isinstance(value, str) and 1 <= len(value) <= 32 and all(c.islower() or c == '_' for c in value):
                code = value  # 0.0.23+: the category the directory logs, e.g. build_mismatch_guest.
        except (OSError, ValueError, AttributeError):
            pass
        error.coop_reason, error.coop_code = reason, code
    return error.coop_reason


UPDATER_HINT = 'Close the game and run Azeroth-Survivors-Together-Updater.exe in the co-op folder to repair it'


def error_log(error):
    """Full traceback to coop-lab/logs/launcher-error-<UTC time>.log (for the player to send); None if not writable."""
    import traceback
    now = datetime.now(timezone.utc)
    path = ROOT / 'coop-lab' / 'logs' / f'launcher-error-{now:%Y%m%dT%H%M%S%fZ}.log'
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'{now.isoformat()} | co-op {coop_version()}\n' +
                        ''.join(traceback.format_exception(type(error), error, error.__traceback__)), encoding='utf-8')
    except OSError:
        return None
    return path


def coop_version():
    try:
        return (ROOT / 'COOP-VERSION.txt').read_text(encoding='utf-8').strip()
    except OSError:
        return 'unknown'


def package_file(error):
    """The missing or damaged part of the co-op package behind an ImportError/FileNotFoundError, else None."""
    if isinstance(error, ImportError):
        name = error.name or str(error)
        return f"Python module '{name}'" + (f' ({Path(error.path).name})' if getattr(error, 'path', None) else '')
    if isinstance(error, FileNotFoundError) and error.filename:
        try:
            relative = Path(error.filename).resolve().relative_to(ROOT.resolve())
        except (ValueError, OSError):
            return None  # Not a file of the co-op folder (for example a missing save elsewhere).
        return f'file {relative.as_posix()}'
    return None


CHANNEL_SWITCHED = 3  # exit code: the co-op channel changed, the launcher restarts the room client (WP4)


def failure_description(error, directory):
    """Share actionable diagnostics without exposing request URLs, bodies or tokens."""
    missing = package_file(error)
    if missing:
        # 0.0.23: a player saw only "Unexpected launcher error [ModuleNotFoundError]" (antivirus quarantine or an
        # interrupted copy had removed part of the package). Name it, say how to repair, keep the traceback.
        log = error_log(error)
        return (f'A co-op file is missing or damaged: {missing}. {UPDATER_HINT}.'
                + (f' Full report: {log}' if log else ''))
    target = urlsplit(directory)
    endpoint = f'{target.scheme}://{target.netloc.rsplit("@", 1)[-1]}'
    cause = error.reason if isinstance(error, URLError) and not isinstance(error, HTTPError) else error
    if isinstance(cause, ssl.SSLCertVerificationError):
        code = getattr(cause, 'verify_code', None)
        detail = {10: 'The TLS certificate has expired.', 9: 'The TLS certificate is not yet valid.',
                  18: 'The TLS certificate is self-signed.', 19: 'The TLS certificate chain is self-signed.',
                  20: 'The TLS certificate issuer is not trusted.',
                  62: 'The TLS certificate does not match the server name.'}.get(code, 'TLS certificate verification failed.')
        detail += (f' [SSLCertVerificationError; verify code {code}]. '
                   'Check Windows date, time and time zone. If correct, report this to the server administrator; '
                   'a VPN, proxy or antivirus HTTPS filter can also present a different certificate. '
                   f'PC time (UTC): {datetime.now(timezone.utc).isoformat(timespec="seconds")}.')
    elif isinstance(error, HTTPError):
        try:
            status = HTTPStatus(error.code).phrase
        except ValueError:
            status = 'Unknown status'
        reason = rejection_reason(error) if error.code == 400 else None
        if reason:
            code = getattr(error, 'coop_code', None)
            # The directory's own words; the endpoint adds nothing for the player, the code helps support.
            return f'{reason}. [HTTP 400, {code}]' if code else f'{reason}. [HTTP 400]'
        detail = f'HTTP {error.code} {status}. '
        detail += ('The directory service is unavailable; retry shortly.' if error.code >= 500 else
                   'The directory rejected the request; refresh the lobby and check your room details.')
    elif isinstance(cause, (TimeoutError, socket.timeout)):
        detail = 'The directory request timed out. Check your connection, VPN/proxy and firewall, then retry.'
    elif isinstance(cause, socket.gaierror):
        detail = 'DNS lookup failed. Check your Internet connection and DNS settings.'
    elif isinstance(cause, ConnectionRefusedError):
        detail = 'Connection refused. The service may be offline or blocked by a firewall.'
    elif isinstance(cause, ssl.SSLError):
        detail = f'TLS handshake failed [{getattr(cause, "reason", None) or "SSLError"}]. Check your VPN/proxy or HTTPS filtering and contact the administrator.'
    elif isinstance(error, json.JSONDecodeError):
        detail = 'The directory returned invalid JSON. A proxy, captive portal or server error may be returning another page.'
    elif isinstance(error, OSError) and not isinstance(error, URLError):
        code = getattr(error, 'winerror', None) or error.errno
        if code in (98, 10048):
            detail = 'The local host port is already in use. Close the other host session or choose another port in Connection settings.'
        elif isinstance(error, PermissionError):
            detail = 'Access denied. Check game-folder write permissions and security software blocking the local host connection.'
        else:
            detail = 'Local system operation failed. Check the game folder and local connection settings.'
        return f'{detail} [{type(error).__name__}; code {code}]'
    elif isinstance(error, URLError):
        detail = f'Network request failed [{type(cause).__name__}; code {getattr(cause, "winerror", None) or getattr(cause, "errno", None)}]. Check your connection, VPN/proxy and firewall.'
    elif isinstance(error, ValueError):
        return str(error)
    else:
        log = error_log(error)
        # Only the type name: the message can carry addresses or tokens; the local report keeps the full traceback.
        return (f'Unexpected launcher error [{type(error).__name__}]. If it repeats: {UPDATER_HINT}, '
                'then report this message' + (f' and send {log}' if log else '') + ' to the co-op maintainer.')
    return f'Directory {endpoint}: {detail}'


# Published when the host has no reachable port. Every directory version accepts
# it and earlier clients sent it too; guests then use the relay.
NO_DIRECT_OFFER = '127.0.0.1'
# LAN guest: seconds of failed room-list polls before the host counts as gone (a VPN drops polls now and then).
LAN_POLL_GRACE = 60
# "Next run": seconds the host waits for confirmations before closing the game, and for the
# confirmed guests to rejoin before it starts without the missing ones.
NEXT_RUN_CONFIRM = 10
# The link to the host closed after this player's run had ended (host left, or the line/relay dropped).
AFTER_RUN_STATUS = 'Run finished; the connection to the host closed. Your progress is saved.'
NEXT_RUN_WAIT = 120
# Repeats of a read-only directory request after a transient failure, and the waits before them (s).
DIRECTORY_RETRIES = 2
DIRECTORY_BACKOFF = (0.5, 1.5)


def next_run_closing(bridge, next_room, now):
    """Host game thread: close the game for the next run once every guest confirmed, or after NEXT_RUN_CONFIRM s.

    Guests that never confirm (left, hung, or a 0.0.15 launcher that ignores the invitation) are not waited for.
    """
    if not next_room or not bridge.next_run_offer or next_room['expected'] is not None:
        return False
    guests = {n for n in bridge.members if n != 1} - bridge.departed
    if not bridge.next_run_acks >= guests and now - next_room['offered'] <= NEXT_RUN_CONFIRM:
        return False
    next_room['expected'] = sorted(bridge.next_run_acks & guests)
    bridge.record(event='next_run_closing', confirmed=next_room['expected'], missing=sorted(guests - bridge.next_run_acks))
    return True


class RoomClient:
    def __init__(self, directory, *, diagnostic_autostart=False, isolated_profile=False, profile_folder=None, lan=None):
        """lan: LAN/VPN mode settings (dict: hosts, lobby_port, discovery_port, bind, discovery_targets) or None.

        In LAN mode there is no Internet directory: hosting starts this launcher's own LAN lobby
        (lan_mode.LanLobby), joining talks to a discovered or typed-in host's lobby over pinned TLS.
        """
        self.lan = None if lan is None else dict(dict(hosts=(), lobby_port=None, discovery_port=None, bind='0.0.0.0',
                                                      discovery_targets=None), **lan)
        if self.lan is not None:
            directory = 'https://lan.invalid'  # Replaced by the chosen host's lobby (PinnedDirectory.url).
        parsed = urlsplit(directory)
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost')):
            raise ValueError('Remote room directories require HTTPS')
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Invalid directory URL')
        self.directory = directory.rstrip('/')
        self.lan_lobby = self.lan_directory = None  # Hosting: own lobby; the current pinned lobby (host or guest).
        self.lan_known = {}      # (address, port) -> PinnedDirectory of every LAN lobby seen (pins persist).
        self.lan_hosts, self.lan_rooms, self.lan_errors = [], [], {}
        self.lan_address = self.lan_name = self.lan_browser = None
        self.lan_waiting_since = None
        self.diagnostic_autostart = diagnostic_autostart
        self.isolated_profile = isolated_profile or diagnostic_autostart
        self.profile = LauncherProfile(profile_folder or ROOT / 'coop-lab' /
            ('launcher-' + secrets.token_hex(8) if self.isolated_profile else 'launcher'))
        self.membership = self.room = self.pairing = None
        self.next_room = None    # host: the following room (membership, confirmed guests, waiting since)
        self.next_invite = None  # guest: the host's invitation, joined once the current game has closed
        self.status, self.error = 'Choose a room or host your own.', None
        self.events, self.commands = queue.Queue(32), queue.Queue(32)
        self.bridge = None
        self.launched = False
        self.room_detached = False
        self.worker = None
        self.routes = None
        self.mapper = None  # Host port mapping (UPnP/PCP/NAT-PMP) of the open room.
        self.cancel = threading.Event()
        self.stopped = threading.Event()
        self.lock = threading.RLock()
        self.build = hashlib.sha256(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')).read_bytes()).hexdigest()
        self.version = game_version(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')), self.build)

    def request(self, path, data=None, authenticated=False, token=None):
        headers = {'Content-Type': 'application/json'}
        if authenticated or token:
            headers['Authorization'] = 'Bearer ' + (token or self.membership['token'])
        if getattr(self, 'lan', None) is not None:
            if self.lan_directory is None:
                raise ValueError('Choose a LAN host first.')
            return json.loads(self.lan_directory.request('GET' if data is None else 'POST', path,
                                                         None if data is None else json.dumps(data).encode(), headers))
        body = None if data is None else json.dumps(data).encode()
        # Reads (room list, membership poll) are safe to repeat: a brief directory hiccup (502/503/504,
        # reset, timeout) is retried twice before the player sees an error. Changes are never repeated.
        retries = DIRECTORY_RETRIES if data is None or path == '/poll' else 0
        for attempt in range(retries + 1):
            try:
                return self.directory_request(urllib.request.Request(self.directory + path, body, headers))
            except HTTPError as error:
                if error.code not in (502, 503, 504) or attempt == retries:
                    raise
            except (URLError, TimeoutError, ConnectionError):
                if attempt == retries:
                    raise
            time.sleep(DIRECTORY_BACKOFF[attempt])

    @staticmethod
    def directory_request(request):
        with urllib.request.urlopen(request, timeout=20) as response:
            if int(response.headers.get('Content-Length', '0')) > 1048576:
                raise ValueError('Directory response exceeds bound')
            data = response.read(1048577)
            if len(data) > 1048576:
                raise ValueError('Directory response exceeds bound')
            return json.loads(data)

    def network_event(self, **event):
        """Connection diagnostics (port mapping, route); never invitations, tickets or tokens."""
        event['time'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
        self.last_network_event = event
        if (event.get('event') == 'guest_route' and event.get('route') == 'Relay'
                and (self.room or {}).get('connection', {}).get('address') not in (None, NO_DIRECT_OFFER)):
            # A direct offer existed but the guest could not reach it: most often
            # Windows Firewall blocking inbound TCP for the launcher. No rule is
            # created automatically; the player decides.
            port = self.room['connection'].get('port')
            hint = (f'Player {event.get("slot")} could not reach you directly and uses the relay. '
                    f'If Windows Firewall asked about co-op, allow it, or allow inbound TCP port {port}.')
            self.firewall_hint = hint
            self.write_network_event(dict(event='firewall_hint', level='WARN', slot=event.get('slot'),
                                          port=port, time=event['time']))
        self.write_network_event(event)

    def write_network_event(self, event):
        try:
            folder = self.profile.folder / 'logs'
            folder.mkdir(parents=True, exist_ok=True)
            with (folder / f'network-{datetime.now(timezone.utc):%Y%m%d}.jsonl').open('a', encoding='utf-8') as log:
                log.write(json.dumps(event) + '\n')
        except OSError:
            pass  # Diagnostics never block hosting.

    def direct_endpoint(self, address, port):
        """Address guests may try directly, or None: guests then use the relay."""
        address = (address or '').strip()
        if getattr(self, 'lan', None) is not None:
            # LAN/VPN: informational only (guests use the address they reached the lobby at); no router mapping.
            from lan_mode import candidates, interfaces, parse_target
            if address and address.lower() != 'auto':
                address = parse_target(address)[0]
            else:
                found = candidates(interfaces())
                address = found[0].address if found else '127.0.0.1'
            self.lan_address = address
            self.network_event(event='direct_offer', source='lan', port=port)
            return address
        if urlsplit(self.directory).hostname in ('127.0.0.1', 'localhost'):
            return address if address and address.lower() != 'auto' else '127.0.0.1'  # Local test directory.
        if address and address.lower() != 'auto':
            # Typed in by the player (forwarded port, or a LAN address for players at
            # home): published unchanged as in earlier versions, no router mapping.
            from port_mapping import public_address
            self.network_event(event='direct_offer', source='manual', port=port,
                               scope='public' if public_address(address) else 'other')
            return address
        if os.environ.get('COOP_UPNP') == '0':
            self.network_event(event='upnp_failed', reason='disabled')
            return None
        from port_mapping import PortMapper
        self.status = 'Opening the game port on your router (UPnP)…'
        mapper = PortMapper(port, self.network_event)
        mapped = mapper.open()
        if not mapped:
            return None
        self.mapper = mapper
        import atexit
        atexit.register(mapper.close)  # Normal exit; a crash is covered by the lease.
        return mapped[0]

    def release_mapping(self):
        mapper, self.mapper = self.mapper, None
        if mapper:
            mapper.close()

    def create(self, name, player, private, address, port, region=None):
        from coop_transport import create_pairing
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError('Choose a game port between 1024 and 65535 in Connection settings.')
        with self.lock:
            if self.membership or self.worker and self.worker.is_alive() or getattr(self, 'hosting', False):
                raise ValueError('Leave the current room first')
            self.reset_session()
            self.hosting = True  # Blocks a second create/join while the router is asked.
        try:
            if getattr(self, 'lan', None) is not None:
                self.start_lan_lobby(name)
            # Router discovery and mapping take seconds: never under the lock, so the
            # room browser keeps answering (and shows the status) meanwhile.
            direct = self.direct_endpoint(address, port)
            with self.lock:
                if self.stopped.is_set() or self.membership or self.worker and self.worker.is_alive():
                    self.release_mapping()  # Browser closed or a room appeared meanwhile.
                    raise ValueError('Room creation was cancelled.')
                self.publish_room(name, player, private, port, region, direct, create_pairing)
        finally:
            self.hosting = False

    def publish_room(self, name, player, private, port, region, direct, create_pairing):
        """Create the listing and publish the endpoint; runs under the lock."""
        pairing = ROOT / '.coop-rooms' / secrets.token_hex(12)
        invite = create_pairing(pairing)
        try:
            self.membership = self.request('/create', dict(name=name, player=player, private=private, build=self.build, region=region, version=self.version))
        except Exception:
            self.release_mapping()
            raise
        self.room = self.membership['room']
        self.pairing = pairing
        try:
            # Same request as every earlier client: the unchanged directory accepts it.
            self.room = self.request('/connection', dict(room=self.room['id'],
                address=direct or NO_DIRECT_OFFER, port=port, fingerprint=invite['fingerprint']), True)
            self.start_routes()
        except Exception:
            self.leave_membership(self.room['id'], 'Could not open the host connection.')
            raise
        self.status = ('Waiting for players on your LAN/VPN.' if getattr(self, 'lan', None) is not None else
                       'Waiting for players. Guests can connect directly.' if direct else
                       'Waiting for players. Guests connect through the relay.')
        self.lan_waiting_since = time.monotonic()
        self.profile.save(player=player, region=region, name=name)

    def join(self, player, room_id=None, code=None, region=None, lan_host=None):
        with self.lock:
            if self.membership or self.worker and self.worker.is_alive() or getattr(self, 'hosting', False):
                raise ValueError('Leave the current room first')
            self.reset_session()
            invite = None
            if code:
                code = code.strip()
                if getattr(self, 'lan', None) is not None and '@' in code:
                    code, target = code.split('@', 1)  # LAN invite: room:invite@address[:port][#LAN code]
                    self.lan_directory = self.lan_target(target)
                room_id, invite = code.split(':', 1)
            elif getattr(self, 'lan', None) is not None and lan_host:
                key = (lan_host.get('address'), lan_host.get('port'))
                if key not in self.lan_known:
                    raise ValueError('That LAN host is no longer listed. Refresh and try again.')
                self.lan_directory = self.lan_known[key]
            if getattr(self, 'lan', None) is not None:
                if self.lan_directory is None:
                    raise ValueError('Choose a LAN host first.')
                self.directory = self.lan_directory.url
            self.membership = self.request('/join', dict(room=room_id, player=player, build=self.build, invite=invite,
                                                         version=self.version))  # Older directories ignore it.
            self.room = self.membership['room']
            self.start_routes()
            self.status = 'Joined. Checking the connection to the host…'
            self.profile.save(player=player, region=region)

    def start_routes(self):
        from relay.routing import Routes
        if self.room.get('connection'):
            options = {}
            if getattr(self, 'lan', None) is not None:
                from lan_mode import firewall_hint
                hint = firewall_hint(self.room['connection']['port'])
                if self.room['slot'] == 1 and self.lan_public_hint():
                    hint = self.lan_public_hint() + ' ' + hint  # The likely cause on a VPN, named first.
                options = dict(relay=False, unreachable=hint,
                               direct_address=None if self.room['slot'] == 1 else self.lan_directory.host)
            self.routes = Routes(dict(self.room), self.membership['token'], self.pairing, self.build,
                                 server=urlsplit(self.directory).hostname, log=self.network_event, **options)

    def reset_session(self):
        self.build = hashlib.sha256(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')).read_bytes()).hexdigest()
        self.version = game_version(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')), self.build)
        self.cancel.clear()
        self.launched = self.room_detached = False
        self.error = None
        self.commands, self.events = queue.Queue(32), queue.Queue(32)

    def action(self, action):
        with self.lock:
            if not self.room:
                raise ValueError('Join a room first')
            if action == 'leave':
                self.cancel.set()
                self.next_invite = None  # A guest who leaves between runs stays out of the next one.
                self.drop_next_room()
                self.leave_membership(self.room['id'], 'Left the room.')
                return
            if action == 'next_run':
                self.next_run()
                return
            if action == 'start':
                current = hashlib.sha256(Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe')).read_bytes()).hexdigest()
                if current != self.build or self.room.get('build', self.build) != current:
                    raise ValueError('Game build changed or differs from the host. Leave and rejoin with the matching executable.')
            if (self.room_detached and action == 'keep_fighting') or action == 'new_hero':
                # The decision travels over the game channel (host_action), which is what guests apply.
                # New hero is never told to the directory: its "menu" phase makes the relay close every
                # tunnel within 15 s (relay/server.py monitor), cutting relay guests off after the run
                # and before Next run. The listing stays in "victory", which the relay keeps open.
                if not self.bridge:
                    raise ValueError('The game has already ended.')
                self.queue_game_command(8 if action == 'keep_fighting' else 9)
                return
            fresh = self.request('/poll', dict(room=self.room['id']), True)
            result = self.request('/action', dict(room=fresh['id'], action=action, revision=fresh['revision'], build=self.build), True)
            if action in ('keep_fighting', 'new_hero') and self.bridge:
                self.queue_game_command(8 if action == 'keep_fighting' else 9)
            self.room = result
            if self.routes:
                self.routes.update(dict(self.room))

    def next_run(self):
        """Host: open the following room and invite the party over the running game's channels.

        The directory is unchanged: a new private room (same name and region) with the same host
        connection and pairing, so guests can verify it is this host's room. The game closes once every
        guest confirmed (at most NEXT_RUN_CONFIRM s); the launcher then switches to the new room.
        """
        bridge = self.bridge
        if self.room['slot'] != 1:
            raise ValueError('Only the host starts the next run.')
        if self.next_room:
            raise ValueError('The next run is already being prepared.')
        if bridge is None or not hasattr(bridge, 'offer_next_run') or not bridge.run_over():
            raise ValueError('Finish the current run first (victory, defeat or give up).')
        connection = self.room.get('connection') or {}
        host = next(p['name'] for p in self.room['players'] if p['slot'] == 1)
        membership = self.request('/create', dict(name=self.room['name'], player=host, private=True, build=self.build,
                                                  region=self.room.get('region'), version=self.version))
        try:
            membership['room'] = self.request('/connection', dict(room=membership['room']['id'],
                address=connection['address'], port=connection['port'], fingerprint=connection['fingerprint']),
                token=membership['token'])
        except Exception:
            self.drop_next_room(membership)
            raise
        self.next_room = dict(membership=membership, offered=time.monotonic(), expected=None, since=None, polled=0)
        bridge.offer_next_run(membership['room']['id'], membership['room']['invite'])
        self.status = 'Next run: inviting the party…'

    def drop_next_room(self, membership=None):
        """Close a prepared next room (host leaves or the old game failed); best effort."""
        membership = membership or (self.next_room or {}).get('membership')
        self.next_room = None
        if membership:
            try:
                self.request('/action', dict(room=membership['room']['id'], action='leave',
                                             revision=membership['room']['revision']), token=membership['token'])
            except Exception:
                pass  # It expires without polls anyway.

    def switch_to_next_room(self, next_room):
        """Host, after the old game closed: the prepared room becomes the current one."""
        with self.lock:
            self.reset_session()
            self.membership = next_room['membership']
            self.room = self.membership['room']
            self.start_routes()
            next_room['since'] = time.monotonic()
            self.next_room = next_room
            count = len(next_room['expected'])
            self.status = (f'Next run: waiting for {count} player{"s" if count != 1 else ""} to rejoin…' if count else
                           'Next run: nobody confirmed. Start alone or wait for players to join with the invite.')

    def invited(self, offer, room):
        """Guest game thread: the host's invitation (pinned channel, peer 1); joined after this game closes."""
        if self.cancel.is_set():
            return  # Leaving: never rejoin.
        me = next(p['name'] for p in room['players'] if p['slot'] == room['slot'])
        self.next_invite = dict(offer, player=me, region=room.get('region'), fingerprint=room['connection']['fingerprint'])
        self.status = 'The host started the next run. You rejoin automatically when this game closes (or Leave).'

    def join_next_run(self):
        """Guest, once the previous game has closed: join the host's next room, only if it is this host's."""
        offer, self.next_invite = self.next_invite, None
        try:
            self.join(offer['player'], code=f'{offer["room"]}:{offer["invite"]}', region=offer['region'])
        except Exception as error:
            self.status = 'Could not join the next run. Choose a room or host your own.'
            self.error = 'Next run: ' + failure_description(error, self.directory)
            return
        if (self.room.get('connection') or {}).get('fingerprint') != offer['fingerprint']:
            self.leave_membership(self.room['id'], 'Not joined: the next-run room does not belong to your host.')
            self.error = 'The invitation did not lead to your host\'s room; nothing was joined.'
            return
        self.status = 'Rejoined the party for the next run. Waiting for the host to start.'

    def next_run_due(self):
        """Host heartbeat: keep the prepared room alive; start once the confirmed guests are back."""
        next_room, now = self.next_room, time.monotonic()
        if next_room['since'] is None:
            if now - next_room['polled'] >= 10:  # The directory retires members silent for 60 s.
                next_room['polled'] = now
                membership = next_room['membership']
                membership['room'] = self.request('/poll', dict(room=membership['room']['id']), token=membership['token'])
            return
        if self.room['id'] != next_room['membership']['room']['id'] or self.room['phase'] != 'lobby':
            self.next_room = None
            return
        expected = next_room['expected']
        names = {p['slot']: p['name'] for p in self.room['players']}
        if not expected or len(names) - 1 < len(expected) and now - next_room['since'] < NEXT_RUN_WAIT:
            return
        self.next_room = None
        if len(names) == 1:
            self.status = 'Nobody rejoined in time. Start alone, or share the invite and start when the party is back.'
            return
        self.room = self.request('/action', dict(room=self.room['id'], action='start', revision=self.room['revision'],
                                                 build=self.build), True)
        missing = len(expected) - (len(names) - 1)
        self.status = ('Next run started.' if missing <= 0 else
                       f'Next run started without {missing} player{"s" if missing != 1 else ""} who did not rejoin in time.')

    def queue_game_command(self, command):
        try:
            self.commands.put_nowait(command)
        except queue.Full:
            raise ValueError('The game is busy; try the choice again in a moment.') from None

    def game_event(self, event):
        """Called on the game thread: never block or raise for directory bookkeeping."""
        if self.room_detached:
            return  # No listing left to update; the game channel carries the decision.
        try:
            self.events.put_nowait(event)
        except queue.Full:
            self.dropped_events = getattr(self, 'dropped_events', 0) + 1

    def chat(self, text):
        with self.lock:
            if not self.room:
                raise ValueError('Join a room first')
            self.room = self.request('/chat', dict(room=self.room['id'], text=text), True)

    def leave_membership(self, room_id, status, keep_mapping=False):
        """Retire this session only; never clear a subsequently joined room."""
        with self.lock:
            if not self.membership or not self.room or self.room['id'] != room_id:
                return
            try:
                self.request('/action', dict(room=room_id, action='leave', revision=self.room['revision']), True)
            except HTTPError as error:
                if error.code != 400:  # Already-closed rooms need no further cleanup.
                    message = 'The directory could not confirm leaving; membership will expire automatically.'
                    self.error = f'{self.error}\n{message}' if self.error else message
            except OSError:
                # LAN: the host's own lobby closes with its launcher (e.g. right after the run): nothing left to leave.
                if getattr(self, 'lan', None) is None or self.room.get('slot') == 1:
                    message = 'The directory could not confirm leaving; membership will expire automatically.'
                    self.error = f'{self.error}\n{message}' if self.error else message
            except Exception:
                message = 'The directory could not confirm leaving; membership will expire automatically.'
                self.error = f'{self.error}\n{message}' if self.error else message
            finally:
                try:
                    if self.routes:
                        self.routes.close()
                finally:
                    self.routes = None
                    self.membership = self.room = None
                    self.status = status
                    if not keep_mapping:  # The next room keeps the host's port and router mapping.
                        self.release_mapping()

    def poll_room(self):
        """Only a rejected membership poll means the room has disappeared."""
        lan_guest = getattr(self, 'lan', None) is not None and self.room['slot'] != 1
        try:
            self.room = self.request('/poll', dict(room=self.room['id']), True)
            self.lan_poll_failed_since = None
        except HTTPError as error:
            if error.code != 400:
                raise
            if lan_guest and (rejection_reason(error) or '').startswith('You are no longer'):
                host = getattr(self.lan_directory, 'host', 'the host')
                return self.room_gone(f'You lost contact with the host\'s room list at {host}: your polls did not '
                                      'reach it for several minutes, so the host dropped you. Check the VPN connection '
                                      'and Windows Firewall on both PCs, then join again.')
            return self.room_gone()
        except OSError:
            if not lan_guest:
                raise
            # LAN: one lost poll over a VPN is no reason to leave; only a host that stays silent has gone
            # (it left, or the PC is off) - 0.0.24 VPN report.
            now = time.monotonic()
            since = getattr(self, 'lan_poll_failed_since', None) or now
            self.lan_poll_failed_since = since
            if now - since < LAN_POLL_GRACE:
                host = getattr(self.lan_directory, 'host', 'the host')
                self.status = (f'No reply from the host\'s room list at {host} for {int(now - since)} s; retrying… '
                               '(VPN or Wi-Fi hiccup, or the host closed its launcher)')
                return True
            return self.room_gone('The host closed the LAN room list (the host left, the PC is off, or the network '
                                  f'between you failed for {LAN_POLL_GRACE} s).')
        if not self.routes:
            self.start_routes()
        if self.routes:
            self.routes.update(dict(self.room))
        return True

    def party_changed_text(self, room):
        """Instead of "Party changed before launch": who is missing and, on a LAN lobby, why (0.0.24)."""
        before = {p['slot'] for p in room.get('players', ())}
        now = {p['slot'] for p in (self.room or {}).get('players', ())}
        missing = sorted(before - now)
        if not missing:
            return 'The party changed during the start (a player joined or left). Form the party again and press Start.'
        who = ', '.join(f'Player {slot}' for slot in missing)
        text = f'{who} left or lost contact with the room list during the start.'
        expired = None
        if getattr(self, 'lan_lobby', None) is not None:
            try:
                expired = self.lan_lobby.http.rooms.last_expired(room.get('id'))
            except AttributeError:
                expired = None
        if expired:
            text += (f' Player {expired["slot"]}\'s launcher sent no room-list poll for {expired["seconds"]} s: check the VPN '
                     'connection and Windows Firewall on that PC (and on this one).')
        return text + ' Form the party again and press Start.'

    def room_gone(self, guest_status='The host ended the room.'):
        """The listing is gone: a running game continues over its channels; otherwise the room closes."""
        if self.bridge is not None:
            # The directory only matches players. A running game owns its
            # authenticated channels and ends through them, not the listing.
            self.room_detached = True
            self.status = ('The room listing expired; the game continues over the existing connection. '
                           'Victory choices still work in the game window.')
            return False
        guest = self.room['slot'] != 1
        self.cancel.set()
        if self.routes:
            self.routes.close()
            self.routes = None
        self.release_mapping()
        self.membership = self.room = None
        self.status = guest_status if guest else 'The room has closed.'
        return False

    # ----- LAN / VPN mode -----------------------------------------------------------------------

    def lan_option(self, key, default):
        value = self.lan.get(key)
        return default if value is None else value

    def start_lan_lobby(self, name):
        """Host: this launcher's own LAN lobby (once per launcher; Next run and new rooms reuse it)."""
        from lan_mode import DISCOVERY_PORT, LOBBY_PORT, LanLobby
        self.lan_name = name
        if self.lan_lobby is None:
            try:
                self.lan_lobby = LanLobby(self.profile.folder, self.lan_announcement,
                                          bind=self.lan_option('bind', '0.0.0.0'),
                                          port=self.lan_option('lobby_port', LOBBY_PORT),
                                          discovery_port=self.lan_option('discovery_port', DISCOVERY_PORT),
                                          log=self.network_event)
            except OSError as error:
                raise ValueError(str(error.strerror or error)) from error
            self.network_event(event='lan_lobby_started', port=self.lan_lobby.port,
                               discovery=bool(self.lan_lobby.responder))
        self.lan_directory = self.lan_lobby.directory()
        self.directory = self.lan_directory.url

    def report_permit(self, room):
        """Crash/completion upload permit; LAN mode: none, reports stay on this PC (the LAN lobby is another
        player's PC, not the maintainer's)."""
        return None if getattr(self, 'lan', None) is not None else room.get('crash_upload_permit')

    def lan_announcement(self):
        return dict(name=(self.lan_name or 'Co-op host')[:48], version=str(self.version)[:32], build=self.build)

    def lan_target(self, text):
        """A typed host ('192.168.1.20', with ':port' and/or '#LAN code'): its pinned lobby, reused if known.

        With a LAN code the pin must match it (a host already pinned by discovery is upgraded to 'code').
        """
        from lan_mode import LOBBY_PORT, LanPinError, PinnedDirectory, lan_code, parse_target
        address, port, code = parse_target(text, self.lan_option('lobby_port', LOBBY_PORT))
        known = self.lan_known.get((address, port))
        if known is not None and known.fingerprint:
            if code:
                if lan_code(known.fingerprint) != code:
                    raise LanPinError(f'The LAN code does not match the host at {address}. Check the code shown '
                                      "in the host's room browser.")
                known.trusted_by = 'code'
            return known
        known = PinnedDirectory(address, port, code=code, timeout=8)  # LAN: a silent host is not a slow server.
        self.lan_known[(address, port)] = known
        return known

    def lan_connect(self, text):
        """Room browser: add a host by address (VPNs without broadcast); checks that it answers now."""
        target = self.lan_target(text)
        try:
            target.request('GET', '/rooms')  # Pins on first use, or checks the LAN code.
        except Exception:
            if not target.fingerprint:
                self.lan_known.pop((target.host, target.port), None)
            raise
        self.lan_refresh(discover_hosts=False)

    def lan_refresh(self, discover_hosts=True):
        """Discovered and typed-in hosts with their open rooms (parallel, each bounded to a few seconds)."""
        from lan_mode import DISCOVERY_PORT, PinnedDirectory, discover, lan_code
        found = discover(timeout=1.0, port=self.lan_option('discovery_port', DISCOVERY_PORT),
                         targets=self.lan_option('discovery_targets', None)) if discover_hosts else []
        own = self.lan_lobby.fingerprint if self.lan_lobby else None
        hosts = {}
        for answer in found:
            if answer['fingerprint'] == own:
                continue
            key = (answer['address'], answer['port'])
            known = self.lan_known.get(key)
            if known is None:
                known = self.lan_known[key] = PinnedDirectory(*key, fingerprint=answer['fingerprint'])
                known.trusted_by = 'discovery'
            hosts[key] = dict(answer, conflict=bool(known.fingerprint and known.fingerprint != answer['fingerprint']))
        for key, known in list(self.lan_known.items()):
            if key not in hosts and known.fingerprint != own:
                hosts[key] = dict(name=key[0], address=key[0], port=key[1], typed=True, duplicate_name=False,
                                  conflict=False, code=lan_code(known.fingerprint) if known.fingerprint else None)
        rooms, errors = [], {}

        def fetch(key, host):
            known = self.lan_known[key]
            probe = PinnedDirectory(known.host, known.port, fingerprint=known.fingerprint, timeout=3)
            try:
                listing = json.loads(probe.request('GET', '/rooms'))['rooms'][:64]
            except Exception as error:
                errors[f'{key[0]}:{key[1]}'] = failure_description(error, probe.url)
                return
            for room in listing:
                if isinstance(room, dict):
                    room['lan_host'] = dict(address=key[0], port=key[1], name=host['name'], code=host.get('code'),
                                            trusted_by=known.trusted_by, duplicate_name=host['duplicate_name'])
                    rooms.append(room)
        workers = [threading.Thread(target=fetch, args=item, daemon=True) for item in hosts.items()
                   if not item[1]['conflict']]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(5)
        self.lan_hosts = sorted(hosts.values(), key=lambda h: (h['name'], h['address']))
        self.lan_rooms, self.lan_errors = list(rooms), errors

    def lan_browse(self):
        """Background refresh while browsing (discovery every few seconds; never on the UI thread)."""
        for text in self.lan_option('hosts', ()):
            try:
                self.lan_connect(text)
            except Exception as error:
                self.lan_errors[text] = failure_description(error, 'https://' + text.split('#')[0])
        while not self.stopped.wait(0 if not self.lan_hosts and not self.lan_rooms else 3):
            if self.membership:
                continue
            try:
                self.lan_refresh()
            except Exception as error:
                self.lan_errors['discovery'] = failure_description(error, 'https://lan.invalid')
            self.stopped.wait(3)

    def rooms(self):
        """The room browser's list: the directory's rooms, or in LAN mode the rooms of every LAN host found."""
        if getattr(self, 'lan', None) is None:
            return self.request('/rooms')
        with self.lock:
            if self.lan_browser is None:
                self.lan_browser = threading.Thread(target=self.lan_browse, name='lan-browse', daemon=True)
                self.lan_browser.start()
        return dict(rooms=list(self.lan_rooms))

    def lan_public_hint(self):
        """Host: the Public-network hint for this PC's LAN/VPN adapters (checked once per launcher), or None."""
        if not hasattr(self, '_lan_public_hint'):
            try:
                from lan_mode import interfaces, network_categories, public_network_hint
                self._lan_public_hint = public_network_hint(interfaces(), network_categories())
            except Exception:
                self._lan_public_hint = None
        return self._lan_public_hint

    def lan_state(self, room):
        from lan_mode import LOBBY_PORT, candidates, firewall_hint, interfaces
        hosting = bool(self.lan_lobby and room and room.get('slot') == 1)
        state = dict(hosting=hosting, crash_reports='local',
                     hosts=[{k: h.get(k) for k in ('name', 'address', 'port', 'code', 'duplicate_name', 'conflict',
                                                   'typed', 'version')} for h in self.lan_hosts],
                     errors=dict(self.lan_errors))
        if hosting:
            port = (room.get('connection') or {}).get('port') or 47771
            state.update(code=self.lan_lobby.code, address=self.lan_address, lobby_port=self.lan_lobby.port)
            if self.lan_public_hint():
                state['firewall'] = self.lan_public_hint()  # Shown at once: nobody can join until it is fixed.
            if (len(room.get('players', ())) == 1 and self.lan_waiting_since
                    and time.monotonic() - self.lan_waiting_since > 20):
                state['firewall'] = ('Nobody has joined yet. ' + (self.lan_public_hint() + ' ' if self.lan_public_hint() else '')
                                     + firewall_hint(port, self.lan_lobby.port))
        elif not room:
            try:
                state['candidates'] = [i.label() for i in candidates(interfaces())]
            except Exception:
                state['candidates'] = []
        return state

    def lan_invite(self, room):
        """Host: the invite with this lobby's address and LAN code, so the guest can pin it."""
        port = '' if self.lan_lobby.port == 47770 else f':{self.lan_lobby.port}'
        return f'{room["id"]}:{room["invite"]}@{self.lan_address}{port}#{self.lan_lobby.code}'

    def heartbeat(self):
        while not self.stopped.wait(.5):
            try:
                with self.lock:
                    if (getattr(self, 'next_invite', None) and not self.membership
                            and not (self.worker and self.worker.is_alive())):
                        self.join_next_run()
                    if getattr(self, 'next_room', None):
                        self.next_run_due()
                    if not self.membership or getattr(self, 'room_detached', False):
                        continue
                    if not self.poll_room():
                        continue
                    while not self.events.empty():
                        event = self.events.get_nowait()
                        if self.room['slot'] != 1:
                            continue
                        if event == 9:
                            continue  # New hero stays off the directory (see action): the relay keeps the tunnels.
                        desired = 'victory' if event == 'victory' else 'keep_fighting'
                        required = 'playing' if event == 'victory' else 'victory'
                        if self.room['phase'] == required:
                            try:
                                self.room = self.request('/action', dict(room=self.room['id'], action=desired,
                                    revision=self.room['revision']), True)
                            except HTTPError as error:
                                if error.code != 400:
                                    raise
                                # Another guest may have left since the poll.
                                # Retry the native decision after refreshing.
                                self.events.put_nowait(event)
                                break
                    if self.room['phase'] == 'playing' and not self.launched:
                        self.launched = True
                        self.worker = threading.Thread(target=self.play, args=(dict(self.room),), daemon=True)
                        self.worker.start()
            except Exception as error:
                self.error = 'Room connection failed: ' + failure_description(error, self.directory)

    def check_compatibility(self):
        from build_hooks import resolve_reviewed_profile
        binary = Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe'))
        current = hashlib.sha256(binary.read_bytes()).hexdigest()
        if current != self.build:
            raise ValueError('The game changed after joining this room. Leave and join a room using the updated game.')
        candidate = os.environ.get('COOP_CANDIDATE_PROFILE')
        if candidate:
            if not self.isolated_profile:
                raise ValueError('Candidate compatibility profiles are restricted to isolated acceptance tests')
            home = Path(os.environ.get('COOP_CANDIDATE_HOME', '')).resolve()
            parent = (ROOT / 'coop-lab/compatibility-tests').resolve()
            if parent not in home.parents or not home.is_dir():
                raise ValueError('Candidate acceptance requires a disposable compatibility-test directory')
            from build_hooks import load_isolated_adapter_profile
            profile = load_isolated_adapter_profile(binary, candidate)
            if hashlib.sha256(binary.read_bytes()).hexdigest() != current or profile.get('sha256') != current:
                raise ValueError('The game changed during isolated compatibility checking')
            self.status = 'Isolated compatibility check ready. Connecting the test party…'
            return profile
        def progress(stage, detail):
            self.status = {
                'checking': 'Checking game compatibility…',
                'discovering': 'Update detected → checking compatibility…',
                'ready': 'Compatibility ready. Connecting the party…',
                'failure': 'Compatibility check stopped. See the details below.',
            }.get(stage, detail)
        profile = resolve_reviewed_profile(binary, allow_runtime_relocation=True, progress=progress,
            report_directory=ROOT / 'analysis/diagnostic-hooks' if os.environ.get('COOP_EXECUTABLE') else None)
        after = hashlib.sha256(binary.read_bytes()).hexdigest()
        if after != current or profile.get('sha256') != current or after != self.build:
            raise ValueError('The game changed during compatibility checking. Leave and join a room using the updated game.')
        return profile

    def play(self, room):
        channels = {}
        save = None
        crash_log = None
        after_run = None  # A link lost after the finished run: reported, never shown as an error.
        gameplay_log = None
        bridge = None
        diagnostic_events = deque(maxlen=96)
        completed_room = {k: room.get(k) for k in ('id', 'run', 'slot', 'build', 'version')}
        completed_room['build'] = completed_room['build'] or self.build
        completed_room['version'] = completed_room['version'] or self.version
        try:
            framework = (ROOT / 'COOP-VERSION.txt').read_text(encoding='utf-8').strip()
        except OSError:
            framework = 'unknown'
        upload_permit = self.report_permit(room)
        private_values = [room.get('invite'), room.get('ticket'), upload_permit,
                          (self.membership or {}).get('token'),
                          *room.get('tickets', {}).values()]
        try:
            if room.get('build', self.build) != self.build:
                raise ValueError('Host and local executable SHA-256 hashes differ; session start refused')
            profile = self.check_compatibility()
            # Loading the hooks verifies the game once more (a few seconds; waits if another launcher in this
            # folder is checking): say so instead of leaving "Compatibility ready" on screen (0.0.24, LAN report).
            self.status = 'Loading the co-op hooks for this game…'
            import build_hooks
            build_hooks.WAIT_PROGRESS = lambda stage, detail: setattr(self, 'status', detail) if stage == 'waiting' else None
            from group_online import GroupOnlineBridge
            from native_guest_combat import NativeCombatBridge
            from party_menu import PartyMenu
            from native_probe import ACTIVE_HASH, run
            if ACTIVE_HASH != profile['sha256']:
                raise ValueError('The game changed while this launcher was open. Restart the launcher to load its verified adapter.')
            binary = Path(os.environ.get('COOP_EXECUTABLE', ROOT / 'AzerothSurvivors.exe'))
            if (hashlib.sha256(binary.read_bytes()).hexdigest() != profile['sha256'] or
                    profile['sha256'] != self.build):
                raise ValueError('The game changed before party connection. Leave and join a room using the updated game.')
            number, count = room['slot'], len(room['players'])
            os.environ['COOP_PLAYERS'] = str(count)
            connection = room['connection']
            if not connection:
                raise ValueError('The host has not published its connection')
            self.status = 'Rechecking the final party connections…'
            with self.lock:
                if not self.poll_room() or self.room['players'] != room['players'] or self.room['slot'] != number:
                    raise ValueError('Party changed before launch. Form a new room to try again.')
                routes = self.routes
            if count > 1:
                if routes is None:
                    raise ValueError('Party connection is unavailable')
                def waiting(text):
                    self.status = text
                channels = routes.prepare(room, self.cancel, progress=waiting)
                self.status = 'Party connected. Starting the game…'
            with self.lock:
                if self.cancel.is_set() or self.stopped.is_set():
                    return
                if not self.poll_room() or self.room['players'] != room['players']:
                    raise ValueError('Party changed before launch. Form a new room to try again.')
                for channel in channels.values():
                    channel.check()
            owner = self
            parent = GroupOnlineBridge if channels else NativeCombatBridge
            class Game(PartyMenu, parent):
                def record(self, **event):
                    name = event.get('event')
                    if name == 'native_crash' and event.get('player', number) == number:
                        owner.native_crash = event  # The DLL core reports its crash as data, not as an exception.
                    if name in ('native_state', 'revival_progress', 'network_health', 'transport_failure',
                                'hit_queue_overflow', 'incoming_hits_obsolete', 'completed_run_transition',
                                'guest_departed', 'host_departed'):
                        row = json.dumps(event)
                        if len(row) <= 8192:
                            diagnostic_events.append(row)
                    if name == 'completed_run_transition' and event['player'] == number:
                        try:
                            from crash_reports import upload_completed
                            upload_completed(owner.directory, upload_permit, completed_room,
                                event['action'], event['duration_seconds'], framework,
                                '\n'.join(diagnostic_events), event['diagnostics'],
                                owner.profile.folder / 'logs', private_values)
                        except Exception as error:
                            print(f'Completion diagnostics could not be saved ({type(error).__name__}); gameplay continues.',
                                  file=sys.stderr, flush=True)
                    if event.get('event') == 'host_departed':
                        owner.status = (AFTER_RUN_STATUS if event.get('after_run') else 'The host ended the game.')
                    if event.get('event') == 'guest_departed':
                        owner.status = f'Player {event.get("player")} left. The remaining party can keep playing.'
                    if event.get('event') == 'party_restart_requires_lobby':
                        owner.status = ('Press Next run in the room browser to play the next map with this party.'
                                        if number == 1 else 'Waiting for the host to start the next run (or Leave).')
                    if event.get('event') == 'party_waiting_for_map':
                        owner.status = 'Choose your class and gear. Enter the game after the host confirms the map.'
                    if (event.get('event') == 'native_state' and event.get('player') == number
                            and not owner.cancel.is_set() and not owner.room_detached
                            and not owner.status.startswith(('The host ended', AFTER_RUN_STATUS))):
                        owner.status = 'Playing.' if event.get('phase') == 1 else 'Game connected.'
                    if event.get('event') == 'native_state' and event.get('player') == 1 and event.get('phase') == 5:
                        owner.game_event('victory')
                    if event.get('event') == 'host_victory_action':
                        owner.game_event(event['command'])
                    super().record(**event)

                def next_run_offered(self, offer):
                    owner.invited(offer, room)

                def poll_network(self):
                    if owner.cancel.is_set() or owner.stopped.is_set():
                        self.stop_requested = True
                        return
                    if number == 1 and next_run_closing(self, owner.next_room, time.monotonic()):
                        self.stop_requested = True  # Normal drain and save; the launcher switches rooms.
                    if owner.room_detached and not getattr(self, 'room_listing_logged', False):
                        self.room_listing_logged = True  # Logged on the game thread only.
                        self.record(event='room_listing_lost', room=room['id'])
                    while not owner.commands.empty():
                        command = owner.commands.get_nowait()
                        if command == 'stop':
                            self.stop_requested = True
                        elif number == 1 and self.native_states.get(1, (0,))[0] == 5:
                            self.request_victory_action(command)
                    if channels:
                        previous_map = self.host_map
                        super().poll_network()
                        if number != 1 and previous_map is None and self.host_map is not None:
                            owner.status = 'Host map confirmed. Finish your class and gear, then enter the game.'

            # Acceptance of several runs in a row (next run) keeps each run's log: log_suffix per run.
            with (ROOT / f'analysis/room-player-{number}{getattr(self, "log_suffix", "")}.jsonl').open('w') as output:
                gameplay_log = Path(output.name)
                bridge = Game(output, number, channels) if channels else Game(output)
                if self.diagnostic_autostart:
                    bridge.autostart = True
                    bridge.host_map = 'elwynn'
                self.bridge = bridge
                self.status = 'Loading the game in a window…'
                if not self.isolated_profile:
                    from personal_save import PersonalSave
                    import save_mode
                    save = PersonalSave(save_mode.profile_folder(ROOT), mode=save_mode.read_mode(ROOT))  # channel profile (0.0.24)
                    bridge.profile_folder = save.folder
                    if getattr(save, "notice", None):  # Repair done or save kept apart: tell the player.
                        self.status = save.notice
                # Event serialization and file writes leave the debugger thread:
                # every hook halts the game until it returns.
                getattr(bridge, 'start_log_writer', lambda: None)()
                try:
                    try:
                        self.native_crash = None
                        run(86400, 1, bridge, player_numbers=[number])
                        if self.native_crash is not None:
                            # A core that crashed returns normally: report it like a native exception (schema 2 line is
                            # already in the gameplay log), so the crash upload runs.
                            from crash_modules import summary
                            raise RuntimeError(summary(number, self.native_crash))
                        failure = getattr(bridge, 'connection_failure', None)
                        if failure is not None and getattr(bridge, 'connection_after_run', False):
                            after_run = failure
                        elif failure is not None:
                            raise ConnectionError('Co-op host connection lost; local cleanup completed') from failure
                    except TimeoutError as error:
                        # The game has already closed and shutdown_drain_finished holds
                        # the leftover work; ending a played session is not a crash.
                        if not str(error).startswith('Co-op shutdown did not drain'):
                            raise
                        bridge.record(event='shutdown_drain_abandoned', error=str(error))
                    bridge.record(event='summary', **bridge.counts)
                    for peer, channel in list(channels.items()):
                        if not channel.closed:
                            try:
                                channel.finish()
                            except ConnectionError:
                                if not (channel.closed or channel.peer_goodbye.is_set()
                                        or peer in getattr(bridge, 'departed', ())
                                        or getattr(bridge, 'peer_finished', False)):
                                    raise
                finally:
                    getattr(bridge, 'stop_log_writer', lambda: None)()  # Before the log file closes.
        except Exception as error:
            log = self.profile.log_exception(error, room.get('slot', 1))
            crash_log = log
            if not self.cancel.is_set():
                cause = error.__cause__
                self.error = f'Game session failed: {error}' + (f' ({cause})' if cause else '')
                if str(error).startswith('Party changed before launch'):
                    self.error = 'Game session failed: ' + self.party_changed_text(room)
                missing = package_file(error)
                if missing:  # A quarantined or half-copied package file: say how to repair (0.0.23).
                    self.error = f'Game session failed: a co-op file is missing or damaged: {missing}. {UPDATER_HINT}.'
                if log:
                    self.error += f' Full traceback: {log}'
        finally:
            if save:
                try:
                    # Native run has closed its processes, including on disconnect.
                    # Preserve any completed native save on every exit path.
                    save.commit()
                except Exception as error:
                    log = self.profile.log_exception(error, room.get('slot', 1), 'saving progress')
                    message = f'Progress could not be copied to single-player: {error}' + (f' Full traceback: {log}' if log else '')
                    self.error = f'{self.error}\n{message}' if self.error else message
                finally:
                    try:
                        save.close()
                    except Exception as error:
                        self.profile.log_exception(error, room.get('slot', 1), 'save cleanup')
            for channel in list(channels.values()):
                if not channel.closed:
                    try:
                        channel.close()
                    except Exception as error:
                        self.profile.log_exception(error, room.get('slot', 1), 'connection cleanup')
            self.bridge = None
            if after_run is not None and not crash_log:
                try:
                    raise ConnectionError('Co-op connection lost after the finished run; progress saved') from after_run
                except ConnectionError as error:
                    crash_log = self.profile.log_exception(error, room.get('slot', 1), 'after the run', quiet=True)
            if crash_log:
                from crash_reports import upload_report
                diagnostics = bridge.diagnostic_summary() if bridge is not None else None
                if after_run is not None:
                    diagnostics = dict(diagnostics or {}, after_run=True)  # Marked: the run had already ended.
                try:
                    report_status = upload_report(self.directory, upload_permit, crash_log,
                        gameplay_log, framework, private_values, diagnostics=diagnostics)
                except Exception as error:
                    report_status = f'Crash report upload failed ({type(error).__name__}); local logs retained.'
                if after_run is None:  # After the run: reported quietly, no error look for the player.
                    print(report_status, file=sys.stderr, flush=True)
                if self.error:
                    self.error += ' ' + report_status
            next_room = self.next_room if room.get('slot') == 1 else None
            if next_room and (next_room['expected'] is None or crash_log or self.stopped.is_set()):
                self.drop_next_room()  # The old game did not close for the next run.
                next_room = None
            status = (self.status if self.status.startswith(('The host ended', AFTER_RUN_STATUS)) or self.next_invite else
                      'The game session ended. Join or create a room to play again.')
            try:
                self.leave_membership(room['id'], status, keep_mapping=bool(next_room))
            except Exception as error:
                self.profile.log_exception(error, room.get('slot', 1), 'room cleanup')
            if next_room:
                try:
                    self.switch_to_next_room(next_room)
                except Exception as error:
                    self.profile.log_exception(error, 1, 'next run')
                    self.error = 'Next run could not open the new room: ' + failure_description(error, self.directory)
                    self.drop_next_room(next_room['membership'])
                    self.release_mapping()

    def state(self):
        with self.lock:
            room = None if self.room is None else {k: v for k, v in self.room.items()
                if k not in ('ticket', 'tickets', 'connection', 'crash_upload_permit')}
            if room and 'invite' in room:
                room['invite'] = (self.lan_invite(room) if getattr(self, 'lan', None) is not None and self.lan_lobby and room['slot'] == 1
                                  else room['id'] + ':' + room['invite'])
            entry = None
            bridge = self.bridge
            if (room and room['slot'] != 1 and room['phase'] == 'playing'
                    and not self.error and not self.cancel.is_set()):
                if bridge:
                    if room['slot'] not in bridge.ready and room['slot'] not in bridge.menu_players:
                        entry = dict(ready=bridge.host_map is not None, map=bridge.host_map)
                elif not self.launched or self.worker and self.worker.is_alive():
                    entry = dict(ready=False, map=None, starting=True)
            routes, latency = {}, {}
            if self.routes:
                with self.routes.lock:
                    routes = dict(self.routes.labels)
                    if room:
                        latency = {(peer if room['slot'] == 1 else room['slot']): channel.latency_ms()
                                   for peer, channel in self.routes.channels.items()}
            status = self.status + (' ' + self.profile.warning if self.profile.warning else '')
            if getattr(self, 'firewall_hint', None) and room and room.get('slot') == 1:
                status += ' ' + self.firewall_hint
            next_run = dict(available=bool(room and room['slot'] == 1 and bridge is not None and not self.next_room
                                           and hasattr(bridge, 'offer_next_run') and bridge.run_over()),
                            preparing=bool(self.next_room), invited=bool(self.next_invite),
                            run_over=bool(bridge is not None and hasattr(bridge, 'run_finished_here') and bridge.run_finished_here()))
            return dict(room=room, status=status, error=self.error, guest_entry=entry, routes=routes, latency=latency,
                        connection_error=self.routes.error if self.routes else None, next_run=next_run,
                        lan=self.lan_state(room) if getattr(self, 'lan', None) is not None else None)

    def shutdown(self):
        self.stopped.set()
        self.cancel.set()
        if self.worker and self.worker.is_alive():
            self.worker.join(15)
        with self.lock:
            if self.room:
                self.leave_membership(self.room['id'], 'Room browser closed.')
            self.release_mapping()
            if getattr(self, 'lan_lobby', None):
                self.lan_lobby.close()  # Guests then see that the host closed the LAN room list.
                self.lan_lobby = None


# A browser tab closed or reloaded while the room browser answered: harmless, never an error for the player
# (player report 0.0.21: long "Exception occurred during processing of request" tracebacks, WinError 10053).
TAB_GONE = (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)


class UIServer(ThreadingHTTPServer):
    """The local room-browser server: a dropped browser request ends quietly, anything else is still reported."""

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], TAB_GONE):
            return
        super().handle_error(request, client_address)


class UI(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass

    def tab_gone(self):
        """The browser dropped this request: one INFO line, no error page to a closed socket."""
        if not getattr(self, 'gone', False):
            self.gone = True
            print(f'[ INFO ] The browser tab dropped a request ({self.command} {self.path.split("?")[0]}); '
                  'nothing to do.', flush=True)

    def reply(self, status, body, content='application/json'):
        if getattr(self, 'gone', False):
            return
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        try:
            self.send_response(status)
            self.send_header('Content-Type', content + '; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)
        except TAB_GONE:
            self.tab_gone()

    def do_GET(self):
        if self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}':
            self.reply(403, dict(error='Invalid local host'))
            return
        try:
            if self.path == '/':
                page = (ROOT / 'reconstruction/lobby.html').read_text(encoding='utf-8').replace('__CLIENT_SECRET__', self.server.secret)
                defaults = json.dumps(self.server.client.profile.preferences, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
                page = page.replace('__LAUNCHER_DEFAULTS__', defaults)
                self.reply(200, page.encode(), 'text/html')
            elif self.path == '/state':
                self.reply(200, self.server.client.state())
            elif self.path == '/rooms':
                client = self.server.client
                listing = client.rooms() if getattr(client, 'lan', None) is not None else client.request('/rooms')
                self.reply(200, dict(listing, local_build=client.build, local_version=client.version))
            else:
                self.reply(404, dict(error='Not found'))
        except TAB_GONE:
            self.tab_gone()
        except Exception as error:
            self.reply(503, dict(error=failure_description(error, self.server.client.directory)))

    def do_POST(self):
        if self.headers.get('X-Coop-Client') != self.server.secret or self.headers.get_content_type() != 'application/json':
            self.reply(403, dict(error='Invalid local request'))
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 1 <= size <= 8192:
                raise ValueError('Request is too large')
            data = json.loads(self.rfile.read(size))
            client = self.server.client
            if self.path == '/channel':  # Co-op channel panel (0.0.24): 0.95.0 or the 0.99.0 DLL beta
                import channel_panel
                if client.isolated_profile:
                    raise channel_panel.Refused('This launcher uses a disposable test profile; switch the co-op channel in the normal launcher.')
                coop_running = bool(client.membership or client.worker and client.worker.is_alive() or getattr(client, 'hosting', False))
                restart = os.environ.get('COOP_CHANNEL_RESTART') == '1'  # the launcher restarts us on exit code 3 (WP4)
                if data.get('op') == 'restart':
                    if not restart or coop_running:
                        raise channel_panel.Refused('Close the co-op and start Start-Coop.cmd again to use the new channel.', 'restart_manual')
                    self.reply(200, dict(restarting=True))
                    self.server.exit_code = CHANNEL_SWITCHED
                    threading.Thread(target=self.server.shutdown, daemon=True, name='channel-restart').start()
                    return
                result = channel_panel.panel_request(ROOT, data, coop_running=coop_running,
                                                     local=(getattr(client, 'version', None), getattr(client, 'build', None)))
                if data.get('op') == 'status':
                    result = dict(result, restart_supported=restart)
                self.reply(200, result)
                return
            if self.path == '/saves':  # Saves panel (0.0.23): mode, import, repair, open folder
                import save_mode
                if client.isolated_profile:
                    raise save_mode.Refused('This launcher uses a disposable test profile; manage saves in the normal launcher.')
                self.reply(200, save_mode.panel_request(ROOT, data))
                return
            if self.path == '/create':
                client.create(data['name'], data['player'], data['private'], data['address'], data['port'], data.get('region'))
            elif self.path == '/join':
                lan_host = data.get('lan_host')
                client.join(data['player'], data.get('room'), data.get('code'), data.get('region'),
                            lan_host=(dict(address=str(lan_host.get('address')), port=int(lan_host.get('port')))
                                      if isinstance(lan_host, dict) else None))
            elif self.path == '/lan/connect':
                if client.lan is None:
                    raise ValueError('LAN mode is off')
                client.lan_connect(str(data['address'])[:80])
            elif self.path == '/chat':
                client.chat(data['text'])
            elif self.path == '/action':
                client.action(data['action'])
            else:
                raise ValueError('Unknown action')
            self.reply(200, client.state())
        except TAB_GONE:
            self.tab_gone()
        except Exception as error:
            if type(error).__name__ == 'Refused':  # save_mode / channel_panel Refused: a plain message for the player
                self.reply(400, dict(error=getattr(error, 'text', None) or str(error), **({'code': error.code} if getattr(error, 'code', None) else {})))
                return
            self.reply(400, dict(error=failure_description(error, self.server.client.directory)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', default='http://127.0.0.1:47770')
    parser.add_argument('--port', type=int, default=47772)
    parser.add_argument('--local-directory', action='store_true')
    parser.add_argument('--lan', action='store_true', help='LAN/VPN mode: no Internet directory, hosts are found on '
                        'this network (UDP 47773) or typed in; the host runs its own room list on TCP 47770')
    parser.add_argument('--lan-host', action='append', default=[],
                        help='LAN host to add at start: address[:port][#LAN code] (VPNs without broadcast)')
    parser.add_argument('--open-browser', action='store_true')
    parser.add_argument('--profile', type=Path, help='Independent launcher settings/log folder; use a different folder per local client')
    parser.add_argument('--isolated-profile', action='store_true',
                        help='Use disposable characters for multiple local test clients')
    args = parser.parse_args()
    directory = None
    if args.local_directory:
        from lobby_server import server
        directory = server(('127.0.0.1', 47770))
        threading.Thread(target=directory.serve_forever, daemon=True).start()
    client = RoomClient(args.directory, isolated_profile=args.isolated_profile, profile_folder=args.profile,
                        lan=dict(hosts=tuple(args.lan_host)) if args.lan else None)
    threading.Thread(target=client.heartbeat, daemon=True).start()
    with UIServer(('127.0.0.1', args.port), UI) as app:
        app.client, app.secret = client, secrets.token_hex(32)
        print(f'Room browser: http://127.0.0.1:{args.port}', flush=True)
        if args.open_browser:
            import webbrowser
            webbrowser.open(f'http://127.0.0.1:{args.port}')
        try:
            app.serve_forever()
        finally:
            client.shutdown()
            if directory:
                directory.shutdown()
                directory.server_close()
    if getattr(app, 'exit_code', 0):
        raise SystemExit(app.exit_code)  # CHANNEL_SWITCHED: the launcher starts the room browser again


if __name__ == '__main__':
    main()
