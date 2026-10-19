"""Four-slot room state. Authentication identifies members, never client-sent slots."""
from collections import deque
import secrets
import re
import threading
import time

VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9.+-]{0,31}')


class Rejected(ValueError):
    """A reason the player can act on; lobby_server.py sends its text (never tokens or internals)."""


class Rooms:
    def __init__(self):
        self.rooms = {}
        self.lock = threading.RLock()

    def view(self, room, member=None):
        result = {key: room[key] for key in ('id', 'name', 'private', 'phase', 'revision', 'run', 'build', 'version')}
        result['players'] = [{'slot': p['slot'], 'name': p['name']} for p in room['players'].values()]
        result['capacity'] = 4
        result['region'] = room.get('region')
        if member:
            result['chat'] = list(room['chat'])
            result['slot'] = member['slot']
            result['ticket'] = member['ticket']
            result['connection'] = room.get('connection')
            if member['slot'] == 1:
                result['invite'] = room['invite']
                result['tickets'] = {str(p['slot']): p['ticket'] for p in room['players'].values() if p['slot'] != 1}
        return result

    @staticmethod
    def name(value):
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= 48 or any(ord(c) < 32 for c in value):
            raise Rejected('Use a name between 1 and 48 characters')
        return value.strip()

    def listing(self):
        with self.lock:
            return [self.view(room) for room in self.rooms.values()
                    if not room['private'] and room['phase'] == 'lobby' and len(room['players']) < 4]

    def create(self, name, player, private, build, region=None, version=None):
        name, player = self.name(name), self.name(player)
        if version is None:
            version = 'Unknown'
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            raise Rejected('Invalid display version')
        if type(private) is not bool or not isinstance(build, str) or len(build) != 64 or any(c not in '0123456789abcdef' for c in build):
            raise Rejected('Invalid room settings or game build')
        if region is not None and (not isinstance(region, str) or region not in ('eu', 'na', 'sa', 'as', 'oc', 'af')):
            raise Rejected('Select a supported host region (EU, NA, SA, AS, OC or AF)')
        with self.lock:
            if len(self.rooms) >= 256:
                raise Rejected('Room directory is full')
            room = dict(id=secrets.token_hex(12), name=name, private=private, build=build, region=region, version=version,
                        invite=secrets.token_urlsafe(18), phase='lobby', revision=1, run=0, players={},
                        chat=deque(maxlen=100), chat_sequence=0)
            self.rooms[room['id']] = room
            return self._add(room, player, build)

    def _add(self, room, name, build):
        token = secrets.token_urlsafe(32)
        used = {p['slot'] for p in room['players'].values()}
        member = dict(slot=next(n for n in range(1, 5) if n not in used), name=name, build=build,
                      ticket=secrets.token_urlsafe(32), seen=time.monotonic())
        room['players'][token] = member
        room['revision'] += 1
        return dict(token=token, room=self.view(room, member))

    def join(self, room_id, player, build, invite=None, version=None):
        player = self.name(player)
        with self.lock:
            room = self.rooms.get(room_id)
            if room is None or (room['private'] and
                    (not isinstance(invite, str) or not secrets.compare_digest(invite, room['invite']))):
                raise Rejected('This room is gone or the invite code is wrong; refresh the room list')
            if room['phase'] != 'lobby' or len(room['players']) >= 4:
                raise Rejected('This room has already started or is full')
            if build != room['build']:
                yours = version if isinstance(version, str) and VERSION.fullmatch(version) else None
                raise Rejected(f'Your game ({yours or "another version"}) differs from the room\'s game '
                               f'({room["version"]}): everyone needs the same game. Update or repair your game '
                               'files (Start-Coop.cmd does it), then join again')
            return self._add(room, player, build)

    def member(self, room_id, token):
        room = self.rooms.get(room_id)
        if room is None or not isinstance(token, str) or token not in room['players']:
            raise Rejected('You are no longer in this room (it closed or your connection timed out); join it again')
        member = room['players'][token]
        member['seen'] = time.monotonic()
        return room, member

    def poll(self, room_id, token):
        with self.lock:
            room, member = self.member(room_id, token)
            return self.view(room, member)

    def chat(self, room_id, token, text):
        if (not isinstance(text, str) or not 1 <= len(text.strip()) <= 500 or
                any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in text)):
            raise Rejected('Use a message between 1 and 500 characters without control characters')
        with self.lock:
            room, member = self.member(room_id, token)
            now = time.monotonic()
            if now - member.get('last_chat', float('-inf')) < 1:
                raise Rejected('Wait a second before sending another message')
            member['last_chat'] = now
            room['chat_sequence'] += 1
            room['chat'].append(dict(id=room['chat_sequence'], name=member['name'],
                                     text=text.strip(), time=time.time()))
            return self.view(room, member)

    def connection(self, room_id, token, address, port, fingerprint):
        if (not isinstance(address, str) or not 1 <= len(address) <= 253 or
                any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:' for c in address) or
                type(port) is not int or not 1 <= port <= 65535 or
                not isinstance(fingerprint, str) or len(fingerprint) != 64 or
                any(c not in '0123456789abcdef' for c in fingerprint)):
            raise Rejected('Invalid game endpoint')
        with self.lock:
            room, member = self.member(room_id, token)
            if member['slot'] != 1 or room['phase'] != 'lobby':
                raise Rejected('Only the waiting host can publish the connection')
            room['connection'] = dict(address=address, port=port, fingerprint=fingerprint)
            room['revision'] += 1
            return self.view(room, member)

    def action(self, room_id, token, action, revision, build=None):
        with self.lock:
            room, member = self.member(room_id, token)
            # Leaving never mutates another member or a run decision. A roster
            # change must not strand a departing guest behind a stale revision.
            if action != 'leave' and (type(revision) is not int or revision != room['revision']):
                raise Rejected('Room changed; refresh before trying again')
            if action == 'leave':
                if member['slot'] == 1:
                    del self.rooms[room_id]  # Host departure closes the entire room.
                    return dict(closed=True)
                del room['players'][token]
            else:
                if member['slot'] != 1:
                    raise Rejected('Only the host can control the run')
                transitions = {('lobby', 'start'): 'playing', ('playing', 'victory'): 'victory',
                               ('victory', 'keep_fighting'): 'playing', ('victory', 'new_hero'): 'menu'}
                phase = transitions.get((room['phase'], action))
                if phase is None:
                    raise Rejected('Action is unavailable in this state')
                if action == 'start' and ((build is not None and build != room['build']) or
                        any(player['build'] != room['build'] for player in room['players'].values())):
                    raise Rejected('A player\'s game differs from the host\'s; everyone needs the same game files '
                                   'before starting (Start-Coop.cmd repairs changed files)')
                room['phase'] = phase
                if action == 'start':
                    # Waiting-room departures may leave a hole; freeze a compact
                    # roster before publishing the launch to any native client.
                    for slot, player in enumerate(sorted(room['players'].values(), key=lambda p: p['slot']), 1):
                        player['slot'] = slot
                    room['run'] += 1
            room['revision'] += 1
            return self.view(room, member)

    def expire(self, now=None):
        with self.lock:
            now = time.monotonic() if now is None else now
            for key, room in list(self.rooms.items()):
                stale = [token for token, member in room['players'].items() if now - member['seen'] > 60]
                if any(room['players'][token]['slot'] == 1 for token in stale):
                    del self.rooms[key]
                elif stale:
                    for token in stale:
                        del room['players'][token]
                    room['revision'] += 1
