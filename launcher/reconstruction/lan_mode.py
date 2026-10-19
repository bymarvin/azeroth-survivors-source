"""LAN / VPN mode (0.0.22): the host's own room directory on the local network, no Internet.

The host's launcher runs the unchanged lobby_server in its own process on 0.0.0.0:47770 with TLS
(a self-signed certificate made once per installation). Guests pin its SHA-256 fingerprint:
  - from the host's LAN code (the first 40 bits, e.g. K7QF-2M3D): real pinning;
  - from a discovery answer or the first contact with a typed-in address: trust on first use.
Discovery is a bounded, rate-limited UDP broadcast on 47773, answered only for local peers.
Game traffic goes directly to the host (relay.routing.Routes with relay=False).
"""
import base64
import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import socket
import ssl
import threading
import time
from pathlib import Path
from urllib.error import HTTPError

LOBBY_PORT = 47770
DISCOVERY_PORT = 47773
PROTOCOL = 1
QUERY_KIND, ANSWER_KIND = 'azs-lan-discover', 'azs-lan-host'
MAX_QUERY = 256
MAX_ANSWER = 1024
MAX_HOSTS = 32
MAX_RESPONSE = 1048576
CERT_FILE, KEY_FILE = 'lan-lobby-cert.pem', 'lan-lobby-key.pem'

PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
CGNAT = ipaddress.ip_network('100.64.0.0/10')  # Tailscale and other VPNs.
LINK_LOCAL = ipaddress.ip_network('169.254.0.0/16')
LOOPBACK = ipaddress.ip_network('127.0.0.0/8')
# Adapter names/descriptions that are not a network to other PCs (Hyper-V/WSL/Docker/VM host-only).
VIRTUAL = ('vethernet', 'hyper-v', 'wsl', 'docker', 'virtualbox', 'vmware', 'vmnet', 'loopback', 'bluetooth',
           'npcap', 'pseudo-interface', 'default switch')
VPN = ('tailscale', 'zerotier', 'hamachi', 'wireguard', 'openvpn', 'tap-windows', 'wintun', 'nordlynx', 'radmin',
       'netbird')

FIREWALL_HINT = ('Allow co-op in Windows Firewall on the host PC (python.exe of this game folder; on a VPN adapter '
                 'also for "Public" networks): TCP {lobby} (room list), TCP {game} (game), UDP {discovery} (finding '
                 'hosts). Both PCs must be in the same network; guest Wi-Fi often isolates devices.')


CATEGORIES = {0: 'Public', 1: 'Private', 2: 'Domain'}


def network_categories(timeout=3):
    """{adapter name: 'Public' | 'Private' | 'Domain'} from Windows (Get-NetConnectionProfile); {} if unknown."""
    if os.name != 'nt':
        return {}
    import json
    import subprocess
    try:
        out = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                              'Get-NetConnectionProfile | Select-Object InterfaceAlias,NetworkCategory | ConvertTo-Json -Compress'],
                             capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout
        rows = json.loads(out or '[]')
        rows = rows if isinstance(rows, list) else [rows]
        return {str(r.get('InterfaceAlias')): CATEGORIES.get(r.get('NetworkCategory'), str(r.get('NetworkCategory')))
                for r in rows if isinstance(r, dict)}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}


def public_network_hint(items, categories):
    """A concrete hint when an adapter guests can use (LAN or VPN such as ZeroTier, Radmin, Hamachi) is a Public
    network: Windows' first-run prompt only allows python.exe on Private networks, so co-op is blocked there."""
    public = [i for i in candidates(items) if categories.get(i.name) == 'Public']
    if not public:
        return None
    names = ', '.join(f'"{i.name}" ({i.address}{", VPN" if i.kind == "vpn" else ""})' for i in public)
    return (f'Windows counts {names} as a Public network: Windows Firewall blocks co-op there unless python.exe of '
            'this game folder is allowed on Public networks. Allow it (Windows Security > Firewall > Allow an app) or '
            'set that network to Private.')


def firewall_hint(game_port, lobby_port=LOBBY_PORT, discovery_port=DISCOVERY_PORT):
    return FIREWALL_HINT.format(lobby=lobby_port, game=game_port, discovery=discovery_port)


class LanPinError(ValueError):
    """The LAN host's certificate does not match the pinned fingerprint or LAN code."""


# ---------------------------------------------------------------------------------------------
# Network adapters
# ---------------------------------------------------------------------------------------------

class Interface(tuple):
    """(name, description, address, prefix, kind); kind: lan, vpn, virtual, link-local, loopback, public."""
    __slots__ = ()

    def __new__(cls, name, description, address, prefix, kind=None):
        return super().__new__(cls, (name, description, address, prefix,
                                     kind or classify(name, description, address)))

    name, description, address, prefix, kind = (property(lambda self, i=i: self[i]) for i in range(5))

    @property
    def network(self):
        return ipaddress.ip_network(f'{self.address}/{self.prefix}', strict=False)

    def label(self):
        kind = 'VPN' if self.kind == 'vpn' else 'LAN'
        return f'{self.address} ({kind}: {self.name})'


def classify(name, description, address):
    ip = ipaddress.ip_address(address)
    text = f'{name} {description}'.lower()
    if ip in LOOPBACK:
        return 'loopback'
    if ip in LINK_LOCAL:
        return 'link-local'
    if any(word in text for word in VIRTUAL):
        return 'virtual'
    if any(word in text for word in VPN) or ip in CGNAT:
        return 'vpn'
    if any(ip in network for network in PRIVATE):
        return 'lan'
    return 'public'  # A public address straight on the adapter: never offered automatically.


def candidates(items):
    """Addresses other PCs can reach: physical LAN first, then VPNs; order is stable."""
    order = {'lan': 0, 'vpn': 1}
    return sorted((i for i in items if i.kind in order), key=lambda i: (order[i.kind], i.name, i.address))


def interfaces():
    """IPv4 adapters that are up. Windows: GetAdaptersAddresses; elsewhere a best-effort fallback."""
    if os.name == 'nt':
        try:
            return _windows_interfaces()
        except (OSError, AttributeError, ValueError):
            pass
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = info[4][0]
            if address not in (i.address for i in found):
                found.append(Interface('adapter', '', address, 24))
    except OSError:
        pass
    return found


def _windows_interfaces():
    import ctypes
    from ctypes import wintypes

    class SocketAddress(ctypes.Structure):
        _fields_ = [('lpSockaddr', ctypes.c_void_p), ('iSockaddrLength', ctypes.c_int)]

    class Unicast(ctypes.Structure):
        pass
    Unicast._fields_ = [('Length', wintypes.ULONG), ('Flags', wintypes.DWORD), ('Next', ctypes.POINTER(Unicast)),
                        ('Address', SocketAddress), ('PrefixOrigin', ctypes.c_int), ('SuffixOrigin', ctypes.c_int),
                        ('DadState', ctypes.c_int), ('ValidLifetime', wintypes.ULONG),
                        ('PreferredLifetime', wintypes.ULONG), ('LeaseLifetime', wintypes.ULONG),
                        ('OnLinkPrefixLength', ctypes.c_ubyte)]

    class Adapter(ctypes.Structure):
        pass
    Adapter._fields_ = [('Length', wintypes.ULONG), ('IfIndex', wintypes.DWORD), ('Next', ctypes.POINTER(Adapter)),
                        ('AdapterName', ctypes.c_char_p), ('FirstUnicastAddress', ctypes.POINTER(Unicast)),
                        ('FirstAnycastAddress', ctypes.c_void_p), ('FirstMulticastAddress', ctypes.c_void_p),
                        ('FirstDnsServerAddress', ctypes.c_void_p), ('DnsSuffix', ctypes.c_wchar_p),
                        ('Description', ctypes.c_wchar_p), ('FriendlyName', ctypes.c_wchar_p),
                        ('PhysicalAddress', ctypes.c_ubyte * 8), ('PhysicalAddressLength', wintypes.ULONG),
                        ('Flags', wintypes.DWORD), ('Mtu', wintypes.ULONG), ('IfType', wintypes.DWORD),
                        ('OperStatus', ctypes.c_int)]

    get = ctypes.windll.iphlpapi.GetAdaptersAddresses
    get.argtypes = [wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG)]
    size = wintypes.ULONG(16384)
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value)
        result = get(socket.AF_INET, 0x2 | 0x4 | 0x8, None, buffer, ctypes.byref(size))  # Skip any/multi/DNS.
        if result != 111:  # ERROR_BUFFER_OVERFLOW: size holds the required length.
            break
    if result != 0:
        raise OSError(f'GetAdaptersAddresses failed ({result})')
    found = []
    adapter = ctypes.cast(buffer, ctypes.POINTER(Adapter))
    while adapter and len(found) < 64:
        item = adapter.contents
        if item.OperStatus == 1:  # IfOperStatusUp
            unicast = item.FirstUnicastAddress
            while unicast:
                entry = unicast.contents
                raw = ctypes.string_at(entry.Address.lpSockaddr, 8)
                if int.from_bytes(raw[:2], 'little') == socket.AF_INET:
                    address = socket.inet_ntoa(raw[4:8])
                    prefix = entry.OnLinkPrefixLength if entry.OnLinkPrefixLength <= 32 else 24
                    kind = 'loopback' if item.IfType == 24 else None
                    found.append(Interface(item.FriendlyName or '', item.Description or '', address, prefix, kind))
                unicast = entry.Next
        adapter = item.Next
    return found


def peer_allowed(address, own=None):
    """Lobby and discovery answer only local peers: private, CGNAT, loopback or on one of our networks."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    if ip in LOOPBACK or ip in CGNAT or any(ip in network for network in PRIVATE):
        return True
    return any(ip in i.network for i in (own if own is not None else interfaces())
               if i.kind in ('lan', 'vpn') and i.prefix >= 8)


def broadcast_targets(items):
    """Limited broadcast plus each candidate network's directed broadcast (VPNs often drop the former)."""
    targets = ['255.255.255.255']
    for item in candidates(items):
        if 8 <= item.prefix <= 30:
            address = str(item.network.broadcast_address)
            if address not in targets:
                targets.append(address)
    return targets


# ---------------------------------------------------------------------------------------------
# Lobby certificate, LAN code and pinned HTTPS
# ---------------------------------------------------------------------------------------------

def lobby_identity(folder):
    """(cert path, key path, fingerprint) of this installation's LAN lobby; created on first use."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    folder = Path(folder)
    cert_path, key_path = folder / CERT_FILE, folder / KEY_FILE
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        serialization.load_pem_private_key(key_path.read_bytes(), None)
        return cert_path, key_path, cert.fingerprint(hashes.SHA256()).hex()
    except (OSError, ValueError):
        pass  # Missing or damaged: a new identity (guests with the old LAN code then refuse it).
    folder.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Azeroth co-op LAN lobby')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650)).sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path, cert.fingerprint(hashes.SHA256()).hex()


def lan_code(fingerprint):
    """The first 40 bits of the fingerprint as 8 base32 characters, e.g. K7QF-2M3D."""
    text = base64.b32encode(bytes.fromhex(fingerprint)[:5]).decode('ascii')
    return f'{text[:4]}-{text[4:]}'


def normalize_code(code):
    """A typed LAN code: case, spaces and dashes do not matter; 0/1/8 read as O/I/B."""
    text = ''.join(c for c in str(code or '').upper() if c not in ' -')
    text = text.translate(str.maketrans('018', 'OIB'))
    if len(text) != 8 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in text):
        raise ValueError('A LAN code has 8 letters and digits, e.g. K7QF-2M3D.')
    return f'{text[:4]}-{text[4:]}'


def valid_fingerprint(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


class PinnedDirectory:
    """HTTPS to one LAN lobby, pinned to its certificate fingerprint (or LAN code, or first use)."""

    def __init__(self, host, port=LOBBY_PORT, fingerprint=None, code=None, timeout=20):
        ipaddress.ip_address(host)  # Addresses only: no DNS in LAN mode.
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Invalid LAN lobby port')
        if fingerprint is not None and not valid_fingerprint(fingerprint):
            raise ValueError('Invalid LAN lobby fingerprint')
        self.host, self.port, self.timeout = host, port, timeout
        self.fingerprint = fingerprint
        self.code = normalize_code(code) if code else None
        self.trusted_by = 'fingerprint' if fingerprint else 'code' if code else 'first use'
        self.lock = threading.Lock()

    @property
    def url(self):
        return f'https://{self.host}:{self.port}'

    def context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Self-signed: the fingerprint check below is the trust decision.
        return context

    def check(self, certificate):
        actual = hashlib.sha256(certificate or b'').hexdigest()
        with self.lock:
            if self.fingerprint:
                if not hmac.compare_digest(actual, self.fingerprint):
                    raise LanPinError(f'The LAN host {self.host} presented a different certificate than before. '
                                      'Ask the host for the LAN code and enter it.')
            elif self.code:
                if lan_code(actual) != self.code:
                    raise LanPinError(f'The LAN code does not match the host at {self.host}. Check the code '
                                      'shown in the host\'s room browser.')
                self.fingerprint = actual
            else:
                self.fingerprint = actual  # Trust on first use: as trustworthy as the network itself.

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context())
        try:
            connection.connect()
            self.check(connection.sock.getpeercert(binary_form=True))
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            if int(response.headers.get('Content-Length', '0')) > MAX_RESPONSE:
                raise ValueError('Directory response exceeds bound')
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise ValueError('Directory response exceeds bound')
            if response.status >= 400:
                raise HTTPError(self.url + path, response.status, response.reason, response.headers, None)
            return data
        finally:
            connection.close()


def parse_target(text, port=LOBBY_PORT):
    """'192.168.1.20', '192.168.1.20:47770' or with a LAN code '100.101.1.2#K7QF-2M3D' -> (ip, port, code)."""
    text = (text or '').strip()
    text, _, code = text.partition('#')
    host, _, typed_port = text.strip().partition(':')
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError('Enter the host PC\'s IP address, e.g. 192.168.1.20 or 100.101.1.2.') from None
    if ip.version != 4 or ip.is_multicast or ip.is_unspecified or str(ip) == '255.255.255.255':
        raise ValueError('Enter the host PC\'s IPv4 address, e.g. 192.168.1.20.')
    if typed_port:
        if not typed_port.isdecimal() or not 1 <= int(typed_port) <= 65535:
            raise ValueError('Invalid LAN lobby port')
        port = int(typed_port)
    return str(ip), port, normalize_code(code) if code.strip() else None


# ---------------------------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------------------------

QUERY = json.dumps(dict(kind=QUERY_KIND, v=PROTOCOL), separators=(',', ':')).encode()


def printable(value, limit):
    return isinstance(value, str) and 1 <= len(value) <= limit and value.isprintable()


def parse_query(data):
    if not 1 <= len(data) <= MAX_QUERY:
        return False
    try:
        query = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(query, dict) and query.get('kind') == QUERY_KIND and query.get('v') == PROTOCOL


def parse_answer(data, source):
    """A validated host announcement (dict) or None. The address is the sender's, never a claimed one."""
    if not 1 <= len(data) <= MAX_ANSWER:
        return None
    try:
        answer = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(answer, dict) or answer.get('kind') != ANSWER_KIND or answer.get('v') != PROTOCOL:
        return None
    name, port, version = answer.get('name'), answer.get('port'), answer.get('version')
    build, fingerprint, rooms = answer.get('build'), answer.get('fingerprint'), answer.get('rooms')
    if (not printable(name, 48) or type(port) is not int or not 1024 <= port <= 65535
            or not printable(version, 32) or not valid_fingerprint(build) or not valid_fingerprint(fingerprint)
            or type(rooms) is not int or not 0 <= rooms <= 64):
        return None
    return dict(name=name, address=source, port=port, version=version, build=build, fingerprint=fingerprint,
                rooms=rooms, code=lan_code(fingerprint))


class RateLimit:
    """Token buckets: per source and in total (answers are small, but never an amplifier)."""

    def __init__(self, per_source=2.0, burst=4, total=40.0, clock=time.monotonic):
        self.per_source, self.burst, self.total, self.clock = per_source, burst, total, clock
        self.sources = {}
        self.all = [total, clock()]

    def allow(self, source):
        now = self.clock()
        tokens, last = self.all
        tokens = min(self.total, tokens + (now - last) * self.total)
        self.all = [tokens, now]
        bucket = self.sources.get(source, [self.burst, now])
        bucket[0] = min(self.burst, bucket[0] + (now - bucket[1]) * self.per_source)
        bucket[1] = now
        if len(self.sources) > 256:
            self.sources = {k: v for k, v in self.sources.items() if now - v[1] < 10}
        self.sources[source] = bucket
        if tokens < 1 or bucket[0] < 1:
            return False
        bucket[0] -= 1
        self.all[0] -= 1
        return True


class Responder:
    """Answers discovery queries for the hosting launcher (bounded, rate-limited, local peers only)."""

    def __init__(self, announce, port=DISCOVERY_PORT, bind='0.0.0.0', log=None, own=None):
        self.announce, self.log = announce, log or (lambda **event: None)
        self.own = own  # Our adapters for the on-link check; None = read them per answer.
        self.limit = RateLimit()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if os.name == 'nt':
            self.sock.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_EXCLUSIVEADDRUSE', 4), 1)
        self.sock.bind((bind, port))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(.5)
        self.stopped = threading.Event()
        self.answered = self.refused = 0
        self.thread = threading.Thread(target=self.run, name='lan-discovery', daemon=True)
        self.thread.start()

    def answer(self, data, source):
        """The reply datagram for one query, or None (counted as refused)."""
        if not parse_query(data) or not peer_allowed(source, self.own) or not self.limit.allow(source):
            return None
        body = json.dumps(dict(kind=ANSWER_KIND, v=PROTOCOL, **self.announce()), separators=(',', ':')).encode()
        return body if len(body) <= MAX_ANSWER else None

    def run(self):
        while not self.stopped.is_set():
            try:
                data, (source, port) = self.sock.recvfrom(MAX_QUERY + 1)
            except socket.timeout:
                continue
            except OSError:
                if self.stopped.is_set():
                    return
                continue  # Windows reports ICMP port unreachable of an earlier answer here.
            try:
                reply = self.answer(data, source)
            except Exception:
                reply = None
            if reply is None:
                self.refused += 1
                continue
            try:
                self.sock.sendto(reply, (source, port))
                self.answered += 1
            except OSError:
                pass

    def close(self):
        self.stopped.set()
        self.sock.close()
        self.thread.join(2)


def discover(timeout=1.2, targets=None, port=DISCOVERY_PORT, items=None):
    """Hosts that answered within `timeout` (at most MAX_HOSTS), deduplicated by address and fingerprint.

    A name announced by two different certificates is marked: someone may be impersonating a host.
    """
    targets = targets if targets is not None else broadcast_targets(items if items is not None else interfaces()) + ['127.0.0.1']
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', 0))
        for target in targets:
            try:
                sock.sendto(QUERY, (target, port))
            except OSError:
                pass  # No route for that network.
        deadline = time.monotonic() + timeout
        while len(found) < MAX_HOSTS:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, (source, _) = sock.recvfrom(MAX_ANSWER + 1)
            except socket.timeout:
                break
            except OSError:
                continue
            answer = parse_answer(data, source)
            if answer:
                found.setdefault((answer['address'], answer['port'], answer['fingerprint']), answer)
    hosts = sorted(found.values(), key=lambda h: (h['name'], h['address']))
    names = {}
    for host in hosts:
        names.setdefault(host['name'], set()).add(host['fingerprint'])
    for host in hosts:
        host['duplicate_name'] = len(names[host['name']]) > 1
    return hosts


# ---------------------------------------------------------------------------------------------
# The host's LAN lobby
# ---------------------------------------------------------------------------------------------

LAN_MEMBER_TTL = 180    # s without a poll before a LAN member is dropped (the public directory: 60 s)
LAN_START_GRACE = 180   # s after Start in which nobody is dropped: the party handshake is running


def lan_rooms():
    """Rooms for the host's own LAN lobby: tolerant of a lossy VPN, never drops a member during the start
    handshake, and keeps (and logs) why a member was dropped so the host can say it (0.0.24 VPN report)."""
    import time
    from lobby import Rooms

    class LanRooms(Rooms):
        def __init__(self):
            super().__init__()
            self.started_at, self.expired = {}, []

        def expire(self, now=None):
            with self.lock:
                now = time.monotonic() if now is None else now
                for key, room in list(self.rooms.items()):
                    if room['phase'] != 'lobby':
                        self.started_at.setdefault((key, room['run']), now)
                        if now - self.started_at[(key, room['run'])] < LAN_START_GRACE:
                            continue
                    stale = [(token, member) for token, member in room['players'].items()
                             if now - member['seen'] > LAN_MEMBER_TTL]
                    for token, member in stale:
                        age = round(now - member['seen'])
                        self.expired.append(dict(room=key, slot=member['slot'], seconds=age, at=now))
                        print(f'[ INFO ] LAN member expired slot={member["slot"]} no poll for {age} s '
                              f'(limit {LAN_MEMBER_TTL} s)', flush=True)
                    del self.expired[:-16]
                    if any(member['slot'] == 1 for _, member in stale):
                        del self.rooms[key]
                    elif stale:
                        for token, _ in stale:
                            del room['players'][token]
                        room['revision'] += 1

        def last_expired(self, room_id):
            with self.lock:
                return next((e for e in reversed(self.expired) if e['room'] == room_id), None)
    return LanRooms()


class LanLobby:
    """lobby_server in this process on 0.0.0.0 with TLS, plus the discovery responder."""

    def __init__(self, folder, announce, bind='0.0.0.0', port=LOBBY_PORT, discovery_port=DISCOVERY_PORT,
                 log=None, own=None):
        from lobby_server import server
        self.cert, self.key, self.fingerprint = lobby_identity(folder)
        self.code = lan_code(self.fingerprint)
        self.own = own
        try:
            self.http = server((bind, port), collected_logs=Path(folder) / 'lan-collected-logs', exclusive=True,
                               rooms=lan_rooms())
        except OSError as error:
            raise OSError(error.errno, f'The LAN room list port {port} is in use by another program or co-op '
                                       'launcher on this PC. Close the other host launcher (or the program using '
                                       f'TCP port {port}) and host again.') from error
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert, self.key)
        # The handshake runs in the request thread (5 s socket timeout): a silent peer cannot stall accept().
        self.http.socket = context.wrap_socket(self.http.socket, server_side=True, do_handshake_on_connect=False)
        self.http.verify_request = lambda request, address: peer_allowed(address[0], self.own)
        self.http.handle_error = lambda request, address: None  # Failed TLS (plain HTTP, scans): no traceback.
        self.port = self.http.server_address[1]
        self.thread = threading.Thread(target=self.http.serve_forever, name='lan-lobby', daemon=True)
        self.thread.start()
        self.announce = announce
        try:
            self.responder = Responder(lambda: dict(announce(), port=self.port, fingerprint=self.fingerprint,
                                                    rooms=len(self.http.rooms.listing())),
                                       port=discovery_port, log=log, own=own)
        except OSError:
            self.responder = None  # Discovery port taken: guests can still type the address.
            (log or (lambda **e: None))(event='lan_discovery_unavailable', port=discovery_port)

    def directory(self):
        """The host's own client view of its lobby (loopback, pinned to its own certificate)."""
        return PinnedDirectory('127.0.0.1', self.port, fingerprint=self.fingerprint)

    def close(self):
        if self.responder:
            self.responder.close()
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(2)
