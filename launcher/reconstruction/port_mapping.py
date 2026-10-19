"""Automatic host port forwarding: UPnP-IGD first, then PCP, then NAT-PMP.

Standard library only. The mapper talks exclusively to the gateway of the
default route, maps only the host's own TCP game port (external == internal),
never touches other rules, bounds every response and refuses XML with DOCTYPE
or ENTITY declarations before parsing. Mappings carry a lease that is renewed
while the room is open and removed on close; a crashed launcher is covered by
the lease running out.
"""
import ipaddress
import os
import socket
import struct
import threading
import time
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

MAX_BODY = 65536
SSDP_GROUP = ('239.255.255.250', 1900)
PMP_PORT = 5351
LEASE_SECONDS = 3600
DESCRIPTION = 'Azeroth Survivors co-op'
SEARCH_TARGETS = ('urn:schemas-upnp-org:device:InternetGatewayDevice:2',
                  'urn:schemas-upnp-org:device:InternetGatewayDevice:1')
# Preference order: IGDv2 IP connection, IGDv1 IP connection, PPPoE connection.
SERVICES = ('urn:schemas-upnp-org:service:WANIPConnection:2',
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            'urn:schemas-upnp-org:service:WANPPPConnection:1')


class MappingError(Exception):
    """A mapping attempt failed; reason is a short machine-readable code."""
    def __init__(self, reason, detail=''):
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason, self.detail = reason, detail


class SoapError(MappingError):
    def __init__(self, code, detail=''):
        super().__init__(f'upnp_error_{code}', detail)
        self.code = code


def public_address(text):
    """True only for a literal, globally routable IP address (never a hostname, CGNAT or LAN)."""
    if not isinstance(text, str) or not 2 <= len(text) <= 45:
        return False
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    shared = ipaddress.ip_network('100.64.0.0/10')  # RFC 6598 carrier-grade NAT.
    return address.is_global and not (address.version == 4 and address in shared)


def default_route():
    """(gateway, local address) of the IPv4 default route; ValueError if none."""
    local = None
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(('192.0.2.1', 9))  # TEST-NET-1; connect() sends nothing.
        local = probe.getsockname()[0]
    except OSError as error:
        raise MappingError('no_route', str(error)) from None
    finally:
        probe.close()
    gateway = _windows_gateway() if os.name == 'nt' else _proc_gateway()
    if not gateway:
        raise MappingError('no_gateway')
    for value in (gateway, local):
        address = ipaddress.ip_address(value)
        if not address.is_private or address.is_loopback:
            raise MappingError('gateway_not_lan', value)
    return gateway, local


def _windows_gateway():
    import ctypes
    from ctypes import wintypes

    class Row(ctypes.Structure):  # MIB_IPFORWARDROW
        _fields_ = [(name, wintypes.DWORD) for name in (
            'dest', 'mask', 'policy', 'next_hop', 'if_index', 'type', 'proto', 'age',
            'next_hop_as', 'metric1', 'metric2', 'metric3', 'metric4', 'metric5')]
    row = Row()
    target = struct.unpack('<I', socket.inet_aton('192.0.2.1'))[0]
    if ctypes.WinDLL('iphlpapi').GetBestRoute(target, 0, ctypes.byref(row)) != 0:
        return None
    hop = socket.inet_ntoa(struct.pack('<I', row.next_hop))
    return None if hop == '0.0.0.0' else hop


def _proc_gateway():
    try:
        with open('/proc/net/route') as table:
            for line in table.readlines()[1:]:
                fields = line.split()
                if len(fields) > 3 and fields[1] == '00000000' and int(fields[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack('<I', int(fields[2], 16)))
    except OSError:
        return None
    return None


def safe_xml(data):
    """Parse a bounded XML document; DOCTYPE/ENTITY declarations are refused outright."""
    if len(data) > MAX_BODY:
        raise MappingError('response_too_large')
    if b'<!' in data:
        raise MappingError('xml_declarations_refused')
    try:
        return ElementTree.fromstring(data)
    except ElementTree.ParseError as error:
        raise MappingError('xml_invalid', str(error)) from None


def local_name(tag):
    return tag.rsplit('}', 1)[-1]


def child_text(element, name):
    for child in element:
        if local_name(child.tag) == name:
            return (child.text or '').strip()
    return None


def gateway_request(url, gateway, method='GET', body=None, headers=None, timeout=3.0):
    """HTTP request to the gateway only; returns (status, bounded body)."""
    import http.client
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.hostname != gateway:
        raise MappingError('foreign_gateway_url', parts.hostname or '')
    connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        path = parts.path or '/'
        if parts.query:
            path += '?' + parts.query
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read(MAX_BODY + 1)
        if len(data) > MAX_BODY:
            raise MappingError('response_too_large')
        return response.status, data
    except (OSError, http.client.HTTPException) as error:
        raise MappingError('gateway_http', type(error).__name__) from None
    finally:
        connection.close()


class UpnpGateway:
    """One IGD WAN connection service on the default gateway."""
    def __init__(self, gateway, local, *, timeout=2.0, ssdp=SSDP_GROUP):
        self.gateway, self.local, self.timeout, self.ssdp = gateway, local, timeout, ssdp
        self.service = self.control = None

    def discover(self):
        location = self.search()
        status, data = gateway_request(location, self.gateway, timeout=self.timeout + 1)
        if status != 200:
            raise MappingError('description_http', str(status))
        root = safe_xml(data)
        base = next((e.text.strip() for e in root.iter() if local_name(e.tag) == 'URLBase' and e.text), location)
        found = {}
        for element in root.iter():
            if local_name(element.tag) == 'service':
                kind, control = child_text(element, 'serviceType'), child_text(element, 'controlURL')
                if kind in SERVICES and control:
                    found.setdefault(kind, urljoin(base, control))
        for kind in SERVICES:
            if kind in found:
                control = found[kind]
                if urlsplit(control).hostname != self.gateway:
                    raise MappingError('foreign_gateway_url', urlsplit(control).hostname or '')
                self.service, self.control = kind, control
                return kind
        raise MappingError('no_wan_service')

    def search(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.bind((self.local, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)  # LAN only.
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.local))
            for target in SEARCH_TARGETS:
                request = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
                           'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ' + target + '\r\n\r\n').encode()
                sock.sendto(request, self.ssdp)
                # Unicast to the gateway as well: some routers ignore multicast from Wi-Fi bridges.
                sock.sendto(request, (self.gateway, self.ssdp[1]))
            deadline = time.monotonic() + self.timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise MappingError('no_upnp')
                sock.settimeout(left)
                try:
                    data, (sender, _) = sock.recvfrom(4096)
                except socket.timeout:
                    raise MappingError('no_upnp') from None
                except ConnectionResetError:
                    continue  # Windows: ICMP unreachable for the unicast probe; keep listening.
                if sender != self.gateway:
                    continue  # Only the default gateway may answer.
                headers = {}
                for line in data.decode('latin-1').split('\r\n')[1:]:
                    key, _, value = line.partition(':')
                    headers[key.strip().lower()] = value.strip()
                location = headers.get('location', '')
                if urlsplit(location).hostname == self.gateway and urlsplit(location).scheme == 'http':
                    return location
        finally:
            sock.close()

    def soap(self, action, arguments=()):
        body = ''.join(f'<{k}>{v}</{k}>' for k, v in arguments)
        envelope = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                    f'<u:{action} xmlns:u="{self.service}">{body}</u:{action}></s:Body></s:Envelope>').encode()
        status, data = gateway_request(self.control, self.gateway, 'POST', envelope, {
            'Content-Type': 'text/xml; charset="utf-8"', 'SOAPAction': f'"{self.service}#{action}"'},
            timeout=self.timeout + 1)
        root = safe_xml(data)
        if status != 200:
            code = next((e.text.strip() for e in root.iter() if local_name(e.tag) == 'errorCode' and e.text), '')
            raise SoapError(code or str(status), action)
        values = {}
        for element in root.iter():
            if local_name(element.tag) == action + 'Response':
                for child in element:
                    values[local_name(child.tag)] = (child.text or '').strip()
        return values

    def external_address(self):
        return self.soap('GetExternalIPAddress').get('NewExternalIPAddress', '')

    def existing(self, port):
        try:
            return self.soap('GetSpecificPortMappingEntry', (
                ('NewRemoteHost', ''), ('NewExternalPort', port), ('NewProtocol', 'TCP')))
        except SoapError as error:
            if error.code in ('714', '402'):  # NoSuchEntryInArray / invalid args on some IGDv1.
                return None
            raise

    def stale_permanent(self, keep_port, limit=128):
        """External ports of our own permanent rules (same description, this PC) except keep_port."""
        found = []
        for index in range(limit):
            try:
                entry = self.soap('GetGenericPortMappingEntry', (('NewPortMappingIndex', index),))
            except SoapError as error:
                if error.code in ('713', '714', '402'):  # End of the table.
                    break
                raise
            if (entry.get('NewPortMappingDescription') == DESCRIPTION and entry.get('NewInternalClient') == self.local
                    and entry.get('NewProtocol') == 'TCP' and entry.get('NewLeaseDuration') == '0'
                    and entry.get('NewExternalPort', '').isdigit() and int(entry['NewExternalPort']) != keep_port):
                found.append(int(entry['NewExternalPort']))
        return found

    def add(self, port, lease):
        self.soap('AddPortMapping', (
            ('NewRemoteHost', ''), ('NewExternalPort', port), ('NewProtocol', 'TCP'),
            ('NewInternalPort', port), ('NewInternalClient', self.local), ('NewEnabled', 1),
            ('NewPortMappingDescription', DESCRIPTION), ('NewLeaseDuration', lease)))

    def delete(self, port):
        self.soap('DeletePortMapping', (('NewRemoteHost', ''), ('NewExternalPort', port), ('NewProtocol', 'TCP')))


def _pmp_exchange(gateway, request, size, timeout, port=PMP_PORT, check=None):
    """One UDP request to the gateway; retries per RFC 6886 (250 ms doubling)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        wait, deadline = .25, time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.sendto(request, (gateway, port))
            sock.settimeout(min(wait, max(.01, deadline - time.monotonic())))
            try:
                while True:
                    data, (sender, sender_port) = sock.recvfrom(1100)
                    if sender == gateway and sender_port == port and len(data) >= 4 and (check is None or check(data)):
                        return data
            except socket.timeout:
                wait *= 2
            except ConnectionResetError:
                # Windows reports the gateway's ICMP port-unreachable here: no PCP/NAT-PMP service.
                raise MappingError('no_response') from None
        raise MappingError('no_response')
    finally:
        sock.close()


class NatPmp:
    method = 'nat-pmp'

    def __init__(self, gateway, local, *, timeout=2.0, port=PMP_PORT):
        self.gateway, self.local, self.timeout, self.port = gateway, local, timeout, port

    def external_address(self):
        data = _pmp_exchange(self.gateway, b'\x00\x00', 12, self.timeout, self.port,
                             lambda d: d[:2] == b'\x00\x80')
        if len(data) < 12 or struct.unpack('!H', data[2:4])[0] != 0:
            raise MappingError('nat_pmp_refused', str(struct.unpack('!H', data[2:4])[0]))
        return socket.inet_ntoa(data[8:12])

    def map(self, port, lease):
        request = struct.pack('!BBHHHI', 0, 2, 0, port, port, lease)
        data = _pmp_exchange(self.gateway, request, 16, self.timeout, self.port,
                             lambda d: d[:2] == b'\x00\x82' and len(d) >= 16 and struct.unpack('!H', d[8:10])[0] == port)
        result = struct.unpack('!H', data[2:4])[0]
        if result:
            raise MappingError('nat_pmp_refused', str(result))
        external, lifetime = struct.unpack('!HI', data[10:16])
        return external, lifetime

    def delete(self, port):
        self.map(port, 0)


class Pcp:
    """PCP MAP (RFC 6887) for TCP over IPv4."""
    method = 'pcp'

    def __init__(self, gateway, local, *, timeout=2.0, port=PMP_PORT):
        self.gateway, self.local, self.timeout, self.port = gateway, local, timeout, port
        self.nonce = os.urandom(12)
        self.external = None

    def map(self, port, lease):
        client = b'\x00' * 10 + b'\xff\xff' + socket.inet_aton(self.local)
        request = (struct.pack('!BBHI', 2, 1, 0, lease) + client + self.nonce +
                   struct.pack('!B3xHH', 6, port, port) + b'\x00' * 10 + b'\xff\xff' + b'\x00' * 4)
        def matches(data):
            return data[0] == 0 or (len(data) >= 60 and data[1] == 0x81 and data[24:36] == self.nonce)
        data = _pmp_exchange(self.gateway, request, 60, self.timeout, self.port, matches)
        if data[0] == 0:
            raise MappingError('pcp_unsupported')  # A NAT-PMP-only gateway answered.
        result = data[3]
        if result:
            raise MappingError('pcp_refused', str(result))
        lifetime = struct.unpack('!I', data[4:8])[0]
        external_port = struct.unpack('!H', data[42:44])[0]
        address = ipaddress.ip_address(data[44:60])
        self.external = str(address.ipv4_mapped or address)
        return external_port, lifetime

    def external_address(self):
        return self.external

    def delete(self, port):
        self.map(port, 0)


class PortMapper:
    """Owns at most one TCP mapping of the host game port; thread-safe."""
    def __init__(self, port, log=lambda **event: None, *, route=default_route, lease=LEASE_SECONDS,
                 timeout=2.0, ssdp=SSDP_GROUP, pmp_port=PMP_PORT, min_renew=30.0):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError('Invalid host game port')
        self.port, self.log, self.route, self.lease = port, log, route, lease
        self.timeout, self.ssdp, self.pmp_port, self.min_renew = timeout, ssdp, pmp_port, min_renew
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.backend = self.method = self.address = None
        self.renewer = None
        self.renewals = 0

    def open(self):
        """Map the port; returns (public address, port) or None (relay only)."""
        with self.lock:
            try:
                gateway, local = self.route()
            except MappingError as error:
                self.log(event='upnp_failed', reason=error.reason, method='route')
                return None
            reasons = {}
            for method in ('upnp', 'pcp', 'nat-pmp'):
                try:
                    address, lifetime = self._try(method, gateway, local)
                except MappingError as error:
                    reasons[method] = error.reason
                    self._release()  # A half-made mapping never outlives a failed attempt.
                    continue
                if not public_address(address):
                    # CGNAT or a double NAT: an opened router port is still unreachable.
                    self._release()
                    self.log(event='upnp_failed', reason='not_public', method=method,
                             external='cgnat' if address and ipaddress.ip_address(address) in
                             ipaddress.ip_network('100.64.0.0/10') else 'private')
                    return None
                self.address = address
                self.log(event='upnp_mapped', method=method, port=self.port, lease=lifetime,
                         external=address)
                if lifetime:
                    self.renewer = threading.Thread(target=self._renew, args=(lifetime,), daemon=True)
                    self.renewer.start()
                return address, self.port
            self.log(event='upnp_failed', reason=reasons.get('upnp', 'unknown'), attempts=reasons)
            return None

    def _try(self, method, gateway, local):
        if method == 'upnp':
            backend = UpnpGateway(gateway, local, timeout=self.timeout, ssdp=self.ssdp)
            backend.discover()
            self._remove_stale(backend)
            current = backend.existing(self.port)
            if current is not None:
                owner = current.get('NewInternalClient')
                if owner != local or current.get('NewInternalPort') not in (str(self.port), None):
                    raise MappingError('conflict')  # Another device's rule stays untouched.
            lease = self.lease
            try:
                backend.add(self.port, lease)
            except SoapError as error:
                if error.code == '725':  # OnlyPermanentLeasesSupported.
                    lease = 0
                    backend.add(self.port, 0)
                    # Removed on close, and on the next hosting if this launcher crashed.
                    self.log(event='upnp_permanent_lease', port=self.port, level='WARN')
                elif error.code == '718':
                    raise MappingError('conflict') from None
                else:
                    raise
            self.backend, self.method = backend, method
            return backend.external_address(), lease
        # Fallbacks wait less: a router without any mapping support should not stall hosting.
        backend = (Pcp if method == 'pcp' else NatPmp)(gateway, local, timeout=self.timeout / 2, port=self.pmp_port)
        external_port, lifetime = backend.map(self.port, self.lease)
        self.backend, self.method = backend, method
        if external_port != self.port:
            self._release()
            raise MappingError('port_changed', str(external_port))
        return backend.external_address(), lifetime

    def _remove_stale(self, backend):
        """Delete our own permanent rules left by a crashed launcher (only on routers without leases)."""
        try:
            ports = backend.stale_permanent(self.port)
        except MappingError as error:
            self.log(event='upnp_stale_check_failed', reason=error.reason)
            return
        removed = []
        for port in ports:
            try:
                backend.delete(port)
                removed.append(port)
            except MappingError as error:
                self.log(event='upnp_release_failed', method='upnp', reason=error.reason, port=port)
        if removed:
            self.log(event='upnp_stale_removed', ports=removed, level='WARN')

    def _renew(self, lifetime):
        while not self.stop.wait(max(self.min_renew, lifetime / 2)):
            with self.lock:
                if self.backend is None:
                    return
                try:
                    if self.method == 'upnp':
                        self.backend.add(self.port, self.lease)
                    else:
                        _, lifetime = self.backend.map(self.port, self.lease)
                    self.renewals += 1
                    self.log(event='upnp_renewed', method=self.method, port=self.port)
                except MappingError as error:
                    self.log(event='upnp_renew_failed', method=self.method, reason=error.reason)

    def _release(self):
        backend, self.backend = self.backend, None
        if backend is not None:
            try:
                backend.delete(self.port)
                return True
            except MappingError as error:
                self.log(event='upnp_release_failed', method=self.method, reason=error.reason)
        return False

    def close(self):
        """Remove the mapping; safe to call repeatedly and from any thread."""
        self.stop.set()
        with self.lock:
            method = self.method
            if self._release():
                self.log(event='upnp_released', method=method, port=self.port)
            self.address = None
        if self.renewer and self.renewer is not threading.current_thread():
            self.renewer.join(2)
