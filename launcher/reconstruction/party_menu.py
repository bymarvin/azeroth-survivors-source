"""Native class/gear menus with a host-authoritative, unlocked zone."""
import struct
import time

from native_probe import BUILD, MAP_SELECT, MOVE, UI_COMMAND, q
from visibility_bridge import absolute_jump
from updated_layout import reviewed_rva, reviewed_bytes, reviewed_branch, field

ZONES = ('elwynn', 'duskwood', 'wsg', 'ab', 'feralas', 'arena', 'av', 'brm', 'aq')


def host_zone(client, account, config):
    """Mirror the reviewed native per-class unlock clamp, without writing saves."""
    pointer, length = struct.unpack('<QQ', client.memory(config + 0x20, 16))
    if not 1 <= length <= 16:
        raise ValueError('Invalid native zone name')
    selected = client.memory(pointer, length).decode('ascii')
    if selected not in ZONES:
        raise ValueError('Unknown native zone')
    class_id = client.memory(config + 0x38, 1)[0]
    pointer, count = struct.unpack('<QQ', client.memory(account + 0x20, 16))
    if count > 32:
        raise ValueError('Invalid native class unlocks')
    entries = client.memory(pointer, count * 16) if count else b''
    unlocked = next((q(entries, i + 8) for i in range(0, len(entries), 16)
                     if entries[i] == class_id), 1)
    unlocked = max(1, min(9, unlocked))
    return ZONES[min(ZONES.index(selected), unlocked - 1)]


class PartyMenu:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if BUILD != 'updated':
            raise ValueError('Native room menus require the reviewed updated game')
        self.extra_hooks += (MAP_SELECT,)
        self.autostart = False
        self.host_map = None
        import native_probe
        self.menu_contract = getattr(native_probe, 'MENU_CONTRACT', None)
        self.menu_login = getattr(native_probe, 'MENU_LOGIN', None)
        if self.menu_contract is not None:
            contract = self.menu_contract
            if (contract.get('variant') != 'borrowed_map_predicate'
                    or contract.get('menu_contract_verified') is not True
                    or contract.get('sha256') != native_probe.ACTIVE_HASH
                    or contract.get('ui_command') != UI_COMMAND or contract.get('map_select') != MAP_SELECT):
                raise ValueError('Candidate menu contract does not match the verified native adapter')
            login = contract['login']
            original = bytes.fromhex(login['expected'])
            if (self.menu_login != login['branch'] or len(original) != 2 or original[0] != 0x75
                    or login['branch'] + 2 + int.from_bytes(original[1:], 'little', signed=True) != login['continuation']
                    or login.get('requested_map_register') != 'r15'
                    or type(login.get('requested_length_stack')) is not int):
                raise ValueError('Candidate login branch contract is inconsistent')
            self.extra_hooks += (self.menu_login,)

    def __call__(self, client, rva, context):
        if self.menu_contract is not None and rva == self.menu_login:
            login = self.menu_contract['login']
            if client.number != 1:
                if self.host_map not in ZONES:
                    raise ValueError('Guest login has no confirmed host map')
                size = q(client.memory(q(context, 160) + login['requested_length_stack'], 8))
                if not 1 <= size <= 16:
                    raise ValueError('Invalid borrowed login map length')
                name = client.memory(q(context, 240), size).decode('ascii')
                if name != self.host_map:
                    raise ValueError('Guest requested a different login map from the host')
                destination = login['continuation']
                self.record(event='guest_login_map_verified', player=client.number, zone=name)
            else:
                # Defensive emulation if a host ever reaches this guest-only hook.
                zero = bool(struct.unpack_from('<I', context, 68)[0] & 0x40)
                destination = rva + 2 if zero else login['continuation']
            struct.pack_into('<Q', context, 248, client.base + destination)
            return
        if rva == UI_COMMAND:
            command = struct.unpack('<I', client.memory(q(context, 136), 4))[0]
            # Native Enter tag: 10 up to 0.93.1, 11 in 0.95.0 (new command at 10; release menu_contract.enter_tag).
            enter = (self.menu_contract or {}).get('enter_tag', 10)
            # A player who already entered this session's world (native MOVE seen)
            # cannot enter a second one from the menu: after a victory (new hero)
            # or a team defeat the native client builds a fresh world and server
            # connection that this session's state does not describe (crash v11).
            finished = client.number in self.menu_players or client.number in getattr(self, 'ready', ())
            waiting = client.number != 1 and self.host_map is None
            if command == enter and waiting and not finished:
                if getattr(self, 'number', None) != client.number or not callable(getattr(self, 'poll_network', None)):
                    raise ValueError('Waiting for a host map requires a per-player network bridge')
                # Retain the native command and its owned strings on the paused
                # thread; dropping it leaves the client UI stuck in Entering.
                self.record(event='party_waiting_for_map', player=client.number)
                deadline = time.monotonic() + 300
                while self.host_map is None:
                    for poll in (False, True):
                        if poll:
                            self.poll_network()
                        if any(getattr(self, name, False) for name in
                               ('stop_requested', 'restart_requested', 'peer_finished', 'host_closing')):
                            raise ConnectionError('Party closed while waiting for the host map')
                    if self.host_map is None:
                        if time.monotonic() >= deadline:
                            raise TimeoutError('The host did not select a map within five minutes')
                        time.sleep(.01)
                if self.host_map not in ZONES:
                    raise ValueError('Invalid confirmed host map')
                self.record(event='party_enter_resumed', player=client.number, zone=self.host_map)
            if command == enter and finished:
                # Keep character setup native, but do not construct a world
                # before its map is known or reuse a finished world's patches.
                # Enter owns two native strings. Tail-call the command's native
                # destructor instead of leaking them when rejecting the request.
                destructor = self.menu_contract['command_destructor'] if self.menu_contract else None
                drop = client.base + (destructor['entry'] if destructor else reviewed_rva(0x546f050))
                expected = (bytes.fromhex(destructor['expected']) if destructor else
                            reviewed_bytes(0x546f050, bytes.fromhex('41565657534883ec28')))
                if client.memory(drop, len(expected)) != expected:
                    raise ValueError('Native menu command destructor changed')
                struct.pack_into('<Q', context, 128, q(context, 136))
                struct.pack_into('<Q', context, 248, drop)
                self.record(event='party_restart_requires_lobby',
                            player=client.number)
                return
        if rva == MOVE:
            game = client.server + 0x10
            pointer, length = struct.unpack('<QQ', client.memory(game + field('game', 0x2d8), 16))
            if not 1 <= length <= 16:
                raise ValueError('Invalid loaded party map')
            zone = client.memory(pointer, length).decode('ascii')
            if zone != self.host_map:
                raise ValueError('The native client loaded a different map from the host')
            self.record(event='party_map_loaded', player=client.number, zone=zone,
                        class_id=client.memory(game + field('game', 0x34c), 1)[0])
        if rva == MAP_SELECT and client.number != 1 and not getattr(client, 'party_map_patched', False):
            if self.host_map is None:
                # Startup/menu previews may run before the host confirms a map.
                # UI_COMMAND holds Enter above; class and equipment stay usable.
                return
            if self.host_map not in ZONES:
                raise ValueError('Guest cannot load before the host chooses a map')
            # Use the native allocation/copy/free path, preserving Rust string
            # ownership. Only replace its zone index; class/gear stay private.
            clamp = self.menu_contract['map_clamp'] if self.menu_contract else None
            site = client.base + (clamp['site'] if clamp else reviewed_rva(0x539a6b9))
            expected = (bytes.fromhex(clamp['expected']) if clamp else
                        reviewed_bytes(0x539a6b9, bytes.fromhex('488b4b20488b532848c1e2044531c00f1f8400')))
            if client.memory(site, len(expected)) != expected:
                raise ValueError('Native zone clamp changed')
            map_patch = b'\xb8' + struct.pack('<I', ZONES.index(self.host_map)) + absolute_jump(
                client.base + (clamp['allocation_path'] if clamp else reviewed_rva(0x539a750)))
            if self.menu_contract:
                client.patch(site, map_patch)
                client.party_map_patched = True
                self.record(event='guest_map_enforced', player=client.number, zone=self.host_map)
                return
            client.patch(site, map_patch)
            # Login has its own inline unlock clamp, independent of the picker.
            # Select the host's table entry before native world construction.
            # Reuse its borrowed-string path; never change account unlocks.
            login = client.base + reviewed_rva(0x53be2ba)
            expected_login = reviewed_bytes(0x53be2ba, bytes.fromhex('4981fcffffff0048898d801f0000488995081f00000f8475080000'))
            if client.memory(login, len(expected_login)) != expected_login:
                raise ValueError('Native login zone clamp changed')
            if client.memory(client.base + reviewed_rva(0x53bead1), 2) != reviewed_bytes(0x53bead1, b'\x74\x2d'):
                raise ValueError('Native login zone fallback changed')
            client.patch(login, b'\xb8' + struct.pack('<I', ZONES.index(self.host_map)) +
                         absolute_jump(client.base + reviewed_rva(0x53beaa8)) + b'\x90' * 8)
            client.patch(client.base + reviewed_rva(0x53bead1), reviewed_branch(0x53bead1, 0x53beb4a, opcode=b'\xeb', size=2))
            client.party_map_patched = True
            self.record(event='guest_map_enforced', player=client.number, zone=self.host_map)
        if rva == MAP_SELECT:
            # Only the explicit native Enter selection publishes the host map;
            # the startup/default config must not release waiting guests.
            caller = q(client.memory(q(context, 152), 8)) - client.base
            host_return = (self.menu_contract['host_map_return'] if self.menu_contract else reviewed_rva(0x53cb7fe))
            if client.number == 1 and caller == host_return:
                selected = host_zone(client, q(context, 136), q(context, 184))
                if self.host_map is not None and selected != self.host_map:
                    raise ValueError('Start a new room to change the party map')
                self.host_map = selected
                self.record(event='host_map_selected', zone=selected)
            return
        return super().__call__(client, rva, context)
