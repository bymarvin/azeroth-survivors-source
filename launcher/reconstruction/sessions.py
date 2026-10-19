"""Executable-informed reference model, NOT recovered Rust or an EXE plugin.

Packet framing/header cipher follow native function 0x1453c9b30 in build
900f6ea6...0413a5. Per-session ownership/routing below is NEW co-op design.
Only authenticated, ground/jump movement sessions are modeled. No network listener.
"""
from dataclasses import dataclass
import math
import struct

LOGIN = 0x003D
HEARTBEAT = 0x00EE
MOVEMENT_OPCODES = (set(range(0xB5, 0xCC)) - {0xC7}) | {0xDA, 0xDB, HEARTBEAT}
MAX_FRAME = 65537  # u16 big-endian size plus its two-byte prefix


class ProtocolError(ValueError):
    pass


class HeaderCipher:
    """One direction's rolling 40-byte-key header state; not authentication."""
    def __init__(self, key: bytes):
        if len(key) != 40:
            raise ProtocolError('Expected a verified 40-byte session key')
        self.key = bytes(key)
        self.index = self.previous = 0

    def decrypt(self, header: bytes) -> bytes:
        output = bytearray()
        for value in header:
            output.append(((value - self.previous) & 255) ^ self.key[self.index])
            self.previous = value
            self.index = (self.index + 1) % 40
        return bytes(output)


class ClientFrames:
    """Incremental client frames. Attach only AFTER the authentication boundary.

    None means plaintext test input. Cipher state is consumed once per header,
    even when its payload arrives in a later read. Bodies are not encrypted.
    """
    def __init__(self, key: bytes | None = None):
        self.cipher = HeaderCipher(key) if key is not None else None
        self.buffer = bytearray()
        self.pending = None

    def feed(self, chunk: bytes) -> list[tuple[int, bytes]]:
        # ponytail: bounded read batches; a socket adapter must feed <=64 KiB reads.
        if len(chunk) > MAX_FRAME or len(self.buffer) + len(chunk) > 2 * MAX_FRAME:
            raise ProtocolError('Input batch exceeds the bounded decoder buffer')
        self.buffer.extend(chunk)
        packets = []
        while True:
            if self.pending is None:
                if len(self.buffer) < 6:
                    break
                header = bytes(self.buffer[:6])
                del self.buffer[:6]
                if self.cipher:
                    header = self.cipher.decrypt(header)
                size = struct.unpack_from('>H', header)[0]
                if size < 4:
                    raise ProtocolError('Client frame length excludes its opcode')
                self.pending = (struct.unpack_from('<I', header, 2)[0], size - 4)
            opcode, length = self.pending
            if len(self.buffer) < length:
                break
            packets.append((opcode, bytes(self.buffer[:length])))
            del self.buffer[:length]
            self.pending = None
        return packets


@dataclass(frozen=True)
class Pose:
    x: float
    y: float
    z: float
    facing: float


def decode_ground_movement(body: bytes) -> Pose:
    """Validated ground/falling movement, including the native jump tail.

    Transport, swimming and flight remain unsupported. Client time is never
    used as the authoritative simulation clock.
    """
    if len(body) < 28:
        raise ProtocolError('Truncated movement body')
    flags, _time, x, y, z, facing, _fall = struct.unpack_from('<IIffffI', body)
    if flags & ~0x71FF:
        raise ProtocolError('Movement flags require an unimplemented mode')
    expected = 44 if flags & 0x2000 else 28
    if len(body) != expected:
        raise ProtocolError('Invalid ground/jump movement length')
    values = (x, y, z, facing)
    if flags & 0x2000:
        values += struct.unpack_from('<4f', body, 28)
    if not all(math.isfinite(v) for v in values):
        raise ProtocolError('Non-finite movement')
    return Pose(x, y, z, facing)


@dataclass
class Player:
    account: str
    pose: Pose


@dataclass
class Session:
    account: str
    frames: ClientFrames
    player_id: int | None = None


class SessionRouter:
    """Proposed co-op seam: one selected character per authenticated connection.

    Authentication, map/collision/speed authority and game packets are NOT
    implemented. This model must not be exposed as a production game server.
    """
    def __init__(self):
        self.players: dict[int, Player] = {}
        self.sessions: dict[str, Session] = {}
        # One run owns progression and pause; characters never accrue separate XP.
        self.progress = None  # (level, XP within level, XP required for next level)
        self.paused = False

    def set_host_progress(self, level: int, xp: int, next_xp: int):
        """Trusted host adapter only; copy absolute values, never count replicas."""
        if any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF
               for v in (level, xp, next_xp)) or level == 0:
            raise ValueError('Invalid host progression')
        self.progress = (level, xp, next_xp)

    def set_paused(self, connection: str, paused: bool):
        session = self.sessions.get(connection)
        if session is None or session.player_id is None or type(paused) is not bool:
            raise ProtocolError('Pause requires a selected authenticated player and boolean state')
        # Explicit state, not a toggle or per-player hold: either player can resume.
        self.paused = paused

    def add_player(self, player_id: int, account: str, pose: Pose):
        if not 0 < player_id < 2**64 or player_id in self.players or not account:
            raise ValueError('Player ID must be unique and owned by an account')
        if not all(math.isfinite(v) for v in (pose.x, pose.y, pose.z, pose.facing)):
            raise ValueError('Invalid initial pose')
        self.players[player_id] = Player(account, pose)

    def attach_authenticated(self, connection: str, account: str, key: bytes | None = None):
        """Trusted adapter entry only: caller must already have verified identity."""
        if not connection or not account or connection in self.sessions:
            raise ValueError('Connection must be unique and authenticated')
        self.sessions[connection] = Session(account, ClientFrames(key))

    def receive(self, connection: str, data: bytes) -> list[tuple[int, Pose]]:
        session = self.sessions[connection]
        updates = []
        try:
            for opcode, body in session.frames.feed(data):
                if opcode == LOGIN:
                    if len(body) != 8 or session.player_id is not None:
                        raise ProtocolError('Invalid or repeated player login')
                    player_id = struct.unpack('<Q', body)[0]
                    player = self.players.get(player_id)
                    if player is None or player.account != session.account:
                        raise ProtocolError('Character does not belong to this account')
                    if any(s.player_id == player_id for s in self.sessions.values()):
                        raise ProtocolError('Character is already connected')
                    session.player_id = player_id
                elif opcode in MOVEMENT_OPCODES:
                    if session.player_id is None:
                        raise ProtocolError('Movement before player login')
                    pose = decode_ground_movement(body)
                    self.players[session.player_id].pose = pose
                    updates.append((session.player_id, pose))
                else:
                    raise ProtocolError(f'Unreconstructed opcode {opcode:#x}')
        except ProtocolError:
            self.disconnect(connection)  # Do not reuse a failed cipher/parser state.
            raise
        return updates

    def snapshot(self) -> dict[int, Pose]:
        # ponytail: single-threaded reference; serialize events in a future host loop.
        return {s.player_id: self.players[s.player_id].pose
                for s in self.sessions.values() if s.player_id is not None}

    def disconnect(self, connection: str):
        self.sessions.pop(connection, None)
