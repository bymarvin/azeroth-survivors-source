"""Bounded authenticated TLS channel. Carries game data, never process commands."""
import datetime
import hashlib
import hmac
import json
from pathlib import Path
import queue
import secrets
import select
import socket
import ssl
import struct
import threading
import time
import zlib

from play_limits import MAX_MESSAGE  # noqa: E402 (a full MAX_ENEMIES snapshot fits)
MAX_BACKLOG = 2 * MAX_MESSAGE  # Queued outgoing bytes before the channel reports congestion.
# Protocol 2 compresses gameplay frames. Both players need the same co-op
# hotfix; a different version is refused with a named reason in the handshake.
# 3: enemy updates as binary record patches (v11).
# 4: guest companions (owner-field units, F140 pets), guest debuff overlay
#    ('auras') and guest display models; a protocol-3 host would end the session
#    on a guest pet, so mixed versions are refused at the handshake.
PROTOCOL = 5  # 5: 0.0.12 play limits (larger values and messages than protocol 4 peers accept)
COMPRESS_FROM = 512  # Smaller frames (keepalives, acknowledgments) stay plain JSON.
_DNS_SLOTS = threading.BoundedSemaphore(4)


class VersionMismatch(ValueError):
    """The peer runs a different co-op protocol; the player must update."""


def frame_bytes(sequence, payload, control=b''):
    """One length-prefixed gameplay frame: plain JSON or b'Z' + zlib(JSON)."""
    body = b'{"seq":' + str(sequence).encode() + b',"payload":' + payload + (b',' + control if control else b'') + b'}'
    if len(body) >= COMPRESS_FROM:
        packed = b'Z' + zlib.compress(body, 6)
        if len(packed) < len(body):
            body = packed
    return struct.pack('!I', len(body)) + body


def frame_payload(body):
    """Decode one received frame body, bounding the decompressed size."""
    if body[:1] == b'Z':
        inflater = zlib.decompressobj()
        try:
            body = inflater.decompress(body[1:], MAX_MESSAGE + 1)
        except zlib.error as error:
            raise ValueError('Corrupt compressed co-op message') from error
        if len(body) > MAX_MESSAGE or inflater.unconsumed_tail:
            raise ValueError('Decompressed co-op message exceeds size limit')
        if not inflater.eof or inflater.unused_data:
            raise ValueError('Truncated compressed co-op message')
    elif body[:1] != b'{':
        raise ValueError('Unknown co-op frame encoding')
    return json.loads(body, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def mismatch_message(local, remote):
    return (f'Co-op version mismatch: this player uses protocol {local}, the other uses '
            f'{remote}. Both players need the same co-op hotfix.')

def failure_details(error):
    """Bounded error chain without payloads, addresses or authentication material."""
    result = []
    while error is not None and len(result) < 4:
        message = str(error)
        result.append(dict(type=type(error).__name__, errno=getattr(error, 'errno', None),
                           winerror=getattr(error, 'winerror', None), reason=getattr(error, 'reason', None),
                           library=getattr(error, 'library', None),
                           message=message[:240] if message.startswith('Co-op ') else None))
        error = error.__cause__ or error.__context__
    return result


def create_pairing(folder):
    """Create disposable host credentials using the installed crypto library."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    if any((folder / n).exists() for n in ('host-key.pem', 'host-cert.pem', 'invite.json')):
        raise FileExistsError('Pairing already exists; use another directory to rotate credentials')
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Azeroth co-op')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    (folder / 'host-key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (folder / 'host-cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    invite = dict(protocol=PROTOCOL, fingerprint=cert.fingerprint(hashes.SHA256()).hex(), token=secrets.token_hex(32))
    (folder / 'invite.json').write_text(json.dumps(invite), encoding='utf-8')
    return invite


def read_exact(sock, size, deadline=None):
    result = bytearray()
    while len(result) < size:
        if deadline is not None:
            sock.settimeout(remaining(deadline))
        data = sock.recv(size - len(result))
        if not data:
            raise ConnectionError('Co-op peer disconnected')
        result.extend(data)
    return bytes(result)


def receive(sock, deadline=None):
    size = struct.unpack('!I', read_exact(sock, 4, deadline))[0]
    if not 1 <= size <= MAX_MESSAGE:
        raise ValueError('Co-op message exceeds size limit')
    message = json.loads(read_exact(sock, size, deadline), parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    if not isinstance(message, dict):
        raise ValueError('Co-op message must be an object')
    return message


def encode(message):
    body = json.dumps(message, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if not 1 <= len(body) <= MAX_MESSAGE:
        raise ValueError('Co-op message exceeds size limit')
    return struct.pack('!I', len(body)) + body


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError('Co-op connection timed out')
    return seconds


def open_socket(host, port, deadline):
    # getaddrinfo has no timeout. Bound both the caller's wait and DNS workers;
    # a late result cannot create a socket or retain session credentials.
    result = queue.Queue(1)
    if not _DNS_SLOTS.acquire(timeout=remaining(deadline)):
        raise TimeoutError('Host lookup timed out')
    def resolve():
        try:
            result.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as error:
            result.put(error)
        finally:
            _DNS_SLOTS.release()
    threading.Thread(target=resolve, daemon=True).start()
    try:
        addresses = result.get(timeout=remaining(deadline))
    except queue.Empty:
        raise TimeoutError('Host lookup timed out') from None
    if isinstance(addresses, Exception):
        raise addresses
    error = OSError('Host has no TCP addresses')
    for family, kind, protocol, _, address in addresses:
        sock = socket.socket(family, kind, protocol)
        try:
            no_delay(sock)
            sock.settimeout(remaining(deadline))
            sock.connect(address)
            return sock
        except OSError as failure:
            error = failure
            sock.close()
    raise error


POLL_SECONDS = .02  # I/O poll interval without a wake-up pair (the behaviour before 0.0.23).
_pair_warned = False


def wake_pair():
    """A non-blocking socket pair that wakes the I/O thread, or (None, None) if this system refuses one.

    On Windows/Wine socketpair is a loopback TCP connection; security software that blocks loopback would
    otherwise end every co-op session at its start. Without a pair the channel polls every 20 ms as before.
    One [ WARN ] line per process.
    """
    global _pair_warned
    reader = writer = None
    try:
        reader, writer = socket.socketpair()
        reader.setblocking(False)
        writer.setblocking(False)
        return reader, writer
    except Exception as error:  # noqa: BLE001 - any refusal falls back to polling
        for end in (reader, writer):
            if end is not None:
                try:
                    end.close()
                except OSError:
                    pass
        if not _pair_warned:
            _pair_warned = True
            print(f'[ WARN ] Co-op transport: no local wake-up pair ({type(error).__name__}: {error}); '
                  f'polling every {round(POLL_SECONDS * 1000)} ms instead', flush=True)
        return None, None


def no_delay(sock):
    """Small game frames go out at once: Nagle held them until the previous frame was acknowledged,
    which a delayed ACK (Windows: up to 200 ms) turned into visible ping on direct connections."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass  # Not a TCP socket (tests) or an exotic stack: keep the default.


def connect(host, port, invite, build, slot=None, timeout=10):
    deadline = time.monotonic() + timeout
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Exact certificate pin below, before sending the token.
    raw = open_socket(host, port, deadline)
    sock = None
    try:
        sock = context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
        sock.settimeout(remaining(deadline))
        sock.do_handshake()
        fingerprint = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(fingerprint, invite['fingerprint']):
            raise ValueError('Host certificate does not match the invitation')
        hello = dict(protocol=PROTOCOL, build=build, token=invite['token'])
        expected = dict(accepted=True, protocol=PROTOCOL, build=build)
        if slot is not None:
            hello['slot'] = expected['slot'] = slot
        sock.settimeout(remaining(deadline))
        sock.sendall(encode(hello))
        try:
            reply = receive(sock, deadline)
        except ConnectionError as error:
            # Protocol-1 hosts close silently on any mismatch.
            raise ValueError('Host closed the co-op handshake: the invitation, game build '
                             'or co-op version differs') from error
        if reply.get('reason') == 'protocol':
            raise VersionMismatch(mismatch_message(PROTOCOL, reply.get('protocol')))
        if reply != expected:
            raise ValueError('Host rejected co-op handshake')
        return Channel(sock)
    except BaseException:
        (sock or raw).close()
        raise


def accept(listener, folder, invite, build, members=None, timeout=10):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(Path(folder) / 'host-cert.pem'), str(Path(folder) / 'host-key.pem'))
    raw, _ = listener.accept()
    no_delay(raw)
    deadline = time.monotonic() + timeout
    raw.settimeout(timeout)
    sock = None
    try:
        sock = context.wrap_socket(raw, server_side=True)
        hello = receive(sock, deadline)
        if hello.get('protocol') != PROTOCOL:
            # Name the reason before any credential check; it reveals nothing.
            sock.settimeout(remaining(deadline))
            sock.sendall(encode(dict(accepted=False, reason='protocol', protocol=PROTOCOL)))
            raise VersionMismatch(mismatch_message(PROTOCOL, hello.get('protocol')))
        slot = hello.get('slot')
        if callable(members):
            if type(slot) is not int or slot not in (2, 3, 4) or not isinstance(hello.get('token'), str):
                raise ValueError('Invalid co-op invitation or player slot')
            members = members(slot, hello.get('token'))
        token = invite['token'] if members is None else members.get(slot) if type(slot) is int else None
        if (hello.get('protocol') != PROTOCOL or hello.get('build') != build or
                not isinstance(hello.get('token'), str) or not isinstance(token, str) or
                not hmac.compare_digest(hello['token'], token)):
            raise ValueError('Invalid co-op invitation or game build')
        reply = dict(accepted=True, protocol=PROTOCOL, build=build)
        if members is not None:
            reply['slot'] = slot
        sock.settimeout(remaining(deadline))
        sock.sendall(encode(reply))
        return Channel(sock) if members is None else (slot, Channel(sock))
    except BaseException:
        (sock or raw).close()
        raise


class Channel:
    def __init__(self, sock):
        self.socket = sock
        # The debugger thread never waits for network I/O. Bounded queues turn
        # an unresponsive peer into a disconnect, not unbounded memory growth.
        # About ten seconds at the bridge's 25 Hz, still capped at 16 MiB.
        self.incoming, self.outgoing = queue.Queue(16), queue.Queue(256)
        self.queued_bytes = 0
        self.queue_lock = threading.Lock()
        self.error = None
        self.closed = False
        self.peer_goodbye = threading.Event()
        self.sent = 0
        self.payload_bytes = self.wire_bytes = 0  # Uncompressed vs written, for diagnostics.
        self.io_wakeups = 0

        self.received = self.sent_bytes = self.received_bytes = 0
        self.buffered_bytes = self.inflight_bytes = 0
        self.last_received = self.last_frame = self.last_sent = time.monotonic()
        self.receive_full_since = None
        self.latency_sample = None
        self.close_lock = threading.Lock()
        self.close_done = False
        # The I/O thread sleeps in select() until the socket or this pair wakes it: no 20 ms polling.
        # socket.socketpair is a loopback TCP pair on Windows (and Wine/Proton), a UNIX pair elsewhere.
        self.wake_reader, self.wake_writer = wake_pair()
        self.worker = threading.Thread(target=self._guard, args=(self._io,), daemon=True)
        self.worker.start()

    def _guard(self, fn):
        try:
            fn()
        except Exception as error:
            if not self.closed and self.error is None:
                self.error = error

    def wake(self):
        """Any thread: make the I/O thread look at its queues now (one byte; a full pair is already awake)."""
        writer = self.wake_writer
        if writer is None:
            return  # No pair (fallback) or closed: the I/O thread polls every 20 ms as before 0.0.23.
        try:
            writer.send(b'\0')
        except OSError:
            pass  # BlockingIOError: wake-ups already pending; closed: the worker is gone.

    def latency_ms(self):
        sample = self.latency_sample
        if self.closed or self.error or sample is None or time.monotonic() - sample[1] > 10:
            return None
        return round(sample[0] * 1000)

    def diagnostics(self):
        full_since = self.receive_full_since
        now = time.monotonic()
        return dict(incoming_messages=self.incoming.qsize(), outgoing_messages=self.outgoing.qsize(),
                    queued_bytes=self.queued_bytes, inflight_bytes=self.inflight_bytes,
                    buffered_bytes=self.buffered_bytes, received_messages=self.received,
                    sent_messages=self.sent, received_bytes=self.received_bytes, sent_bytes=self.sent_bytes,
                    last_receive_seconds=round(now - self.last_received, 3),
                    last_frame_seconds=round(now - self.last_frame, 3),
                    last_send_seconds=round(now - self.last_sent, 3),
                    receive_full_seconds=round(now - full_since, 3) if full_since is not None else 0,
                    closed=self.closed, errors=failure_details(self.error))

    def _io(self):
        # One owner for the SSL object: concurrent SSL_read/SSL_write is unsafe.
        self.socket.setblocking(False)
        expected, incoming, outgoing = 0, bytearray(), b''
        last_sent = last_received = time.monotonic()
        probe_id, probe_started, next_probe = 0, None, last_sent
        pong = None
        last_pong = last_sent - 1
        woken = False
        while not self.closed:
            if woken:
                # Drain before looking at the queues: a byte written after this belongs to an item we see now
                # or wakes the next select, so no queued message waits for a timeout.
                try:
                    while self.wake_reader is not None and self.wake_reader.recv(4096):
                        pass
                except OSError:
                    pass
                woken = False
            if not outgoing:
                now = time.monotonic()
                pong_due = pong is not None and now - last_pong >= .1
                probe_due = now >= next_probe and (probe_started is None or now - probe_started > 10)
                if pong_due or probe_due:
                    # Ping and pong ride alone, ahead of queued payloads: the ping measures the link, not the
                    # time to transmit a world snapshot. Payload order and sequence numbers are unchanged.
                    item = b'null'
                else:
                    try:
                        item = self.outgoing.get_nowait()
                    except queue.Empty:
                        item = b'null' if now - last_sent >= 1 else False
                if item is None:
                    return
                if isinstance(item, threading.Event):
                    item.set()
                elif item is not False:
                    if item != b'null':
                        with self.queue_lock:
                            self.queued_bytes -= len(item)
                    # Older peers ignore optional metadata. Probes never enter
                    # gameplay queues or the prepare/start handshake.
                    now = time.monotonic()
                    control = {}
                    if len(item) + 128 <= MAX_MESSAGE and now >= next_probe and (probe_started is None or now - probe_started > 10):
                        probe_id += 1
                        probe_started = now
                        next_probe = now + 2
                        control['ping'] = probe_id
                    if len(item) + 128 <= MAX_MESSAGE and pong is not None and now - last_pong >= .1:
                        control['pong'] = pong
                        pong = None
                        last_pong = now
                    extra = json.dumps(control, separators=(',', ':')).encode()[1:-1]
                    # Compression runs here, on the I/O thread, never the game thread.
                    outgoing = frame_bytes(self.sent, item, extra)
                    self.sent += 1
                    self.payload_bytes += len(item)
                    self.wire_bytes += len(outgoing)
            can_read = not self.incoming.full()
            self.receive_full_since = (None if can_read else
                                       self.receive_full_since if self.receive_full_since is not None else time.monotonic())
            self.inflight_bytes = len(outgoing)
            now = time.monotonic()
            if outgoing or (can_read and self.socket.pending()):
                timeout = 0 if not outgoing else .25
            else:
                due = min(last_sent + 1, last_received + 10, next_probe if probe_started is None else probe_started + 10,
                          last_pong + .1 if pong is not None else now + .25)
                timeout = min(.25, max(0, due - now))
            wake_reader = self.wake_reader
            if wake_reader is None:
                timeout = min(timeout, POLL_SECONDS)  # Fallback without a pair: nothing else would wake us.
            readers = ([self.socket] if can_read else []) + ([wake_reader] if wake_reader is not None else [])
            writers = [self.socket] if outgoing else []
            if readers or writers:
                readable, writable, _ = select.select(readers, writers, [], timeout)
            else:
                time.sleep(timeout)  # Windows select rejects three empty sets (receive paused, no pair).
                readable, writable = [], []
            self.io_wakeups += 1  # Diagnostics: an idle channel wakes ~4x/s (keepalive, probes), not 50x/s.
            if wake_reader is not None and wake_reader in readable:
                woken = True
                readable = [r for r in readable if r is not wake_reader]
            if writable:
                try:
                    sent = self.socket.send(outgoing)
                    if sent == 0:
                        raise ConnectionError('Co-op peer disconnected')
                    outgoing = outgoing[sent:]
                    last_sent = time.monotonic()
                    self.last_sent = last_sent
                    self.sent_bytes += sent
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
            if can_read and (readable or self.socket.pending()):
                try:
                    data = self.socket.recv(65536)
                    if not data:
                        raise ConnectionError('Co-op peer disconnected')
                    incoming.extend(data)
                    last_received = time.monotonic()
                    self.last_received = last_received
                    self.received_bytes += len(data)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
            while len(incoming) >= 4 and not self.incoming.full():
                size = struct.unpack_from('!I', incoming)[0]
                if not 1 <= size <= MAX_MESSAGE:
                    raise ValueError('Co-op message exceeds size limit')
                if len(incoming) < size + 4:
                    break
                item = frame_payload(bytes(incoming[4:size + 4]))
                del incoming[:size + 4]
                if not isinstance(item, dict) or item.pop('seq', None) != expected:
                    raise ValueError('Out-of-order co-op message')
                expected += 1
                self.received = expected
                self.last_frame = time.monotonic()
                now = time.monotonic()
                ping = item.get('ping')
                if type(ping) is int and 0 < ping <= 9007199254740991:
                    pong = ping
                if type(item.get('pong')) is int and item['pong'] == probe_id and probe_started is not None:
                    elapsed = now - probe_started
                    previous = self.latency_sample
                    self.latency_sample = (elapsed if previous is None else previous[0] * .75 + elapsed * .25, now)
                    probe_started = None
                payload = item.get('payload')
                if payload is not None:
                    if not isinstance(payload, dict):
                        raise ValueError('Invalid co-op payload')
                    self.incoming.put_nowait(payload)
                    if payload.get('kind') == 'goodbye':
                        self.peer_goodbye.set()
                        return
            self.buffered_bytes = len(incoming)
            if time.monotonic() - last_received > 10:
                if self.receive_full_since is not None:
                    raise TimeoutError('Co-op receive timeout with local incoming queue full')
                raise TimeoutError('Co-op peer stopped responding')

    def send(self, message):
        self.check()
        body = encode(message)[4:]
        if len(body) + 64 > MAX_MESSAGE:
            raise ValueError('Co-op envelope exceeds size limit')
        with self.queue_lock:
            if self.queued_bytes + len(body) > MAX_BACKLOG:
                raise TimeoutError(f'Co-op outgoing backlog exceeded {MAX_BACKLOG >> 20} MiB')
            try:
                self.outgoing.put_nowait(body)
            except queue.Full:
                raise TimeoutError('Co-op outgoing backlog exceeded 256 messages') from None
            self.queued_bytes += len(body)
        self.wake()

    def drain(self):
        if self.incoming.empty():
            self.check()
        paused = self.receive_full_since is not None  # The I/O thread stopped reading; resume it now.
        result = []
        while True:
            try:
                result.append(self.incoming.get_nowait())
            except queue.Empty:
                if paused and result:
                    self.wake()
                return result

    def flush(self):
        barrier = threading.Event()
        self.outgoing.put(barrier, timeout=2)
        self.wake()
        if not barrier.wait(2):
            raise ConnectionError('Co-op writer did not drain')

    def check(self):
        if self.error:
            raise ConnectionError('Co-op connection failed') from self.error
        if self.closed:
            raise ConnectionError('Co-op connection closed')

    def finish(self):
        if self.peer_goodbye.is_set():
            return
        try:
            self.send(dict(kind='goodbye'))
            self.flush()
        except ConnectionError:
            if not self.peer_goodbye.is_set():
                raise

    def close(self):
        """Idempotent and safe from any thread; always releases the socket and the wake-up pair."""
        with self.close_lock:
            if self.close_done:
                return
            self.close_done = True
        self.closed = True
        self.wake()
        if self.worker is not threading.current_thread():
            self.worker.join(timeout=1)
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()
        try:
            self.outgoing.put_nowait(None)
        except queue.Full:
            pass
        # A worker still inside select() gets an error on the closed sockets and ends (closed: not recorded).
        reader, writer = self.wake_reader, self.wake_writer
        self.wake_reader = self.wake_writer = None
        for end in (reader, writer):
            if end is not None:
                try:
                    end.close()
                except OSError:
                    pass
