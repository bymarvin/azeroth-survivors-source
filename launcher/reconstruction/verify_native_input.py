"""Disposable native-input substitution; never enabled by ordinary co-op."""
import os
import struct
import time
import math
from pathlib import Path


class NativeMenuDiagnostic:
    """Observe/gate original native taps; never rewind its index or invent events."""
    def __init__(self, bridge, sequence, *, allow_early_enter=False):
        from native_probe import ROOT, EXECUTABLE, ACTIVE_HASH
        from build_hooks import UPDATED_HASH
        from native_input_contracts import discover_native_key_diagnostic
        self.bridge = bridge
        self.allow_early_enter = allow_early_enter
        self.home = Path(os.environ.get('COOP_CANDIDATE_HOME', '')).resolve()
        if (not os.environ.get('COOP_CANDIDATE_PROFILE') or
                (ROOT / 'coop-lab/compatibility-tests').resolve() not in self.home.parents or
                not self.home.is_dir() or os.environ.get('WOW_ROGUE_TAPS') != sequence):
            raise ValueError('Native menu taps require the isolated exact input request')
        self.points = [tuple(map(float, point.split(','))) for point in sequence.split(';')]
        if not 1 <= len(self.points) <= 96 or any(len(p) != 2 or not all(math.isfinite(v) for v in p) for p in self.points):
            raise ValueError('Invalid bounded native tap sequence')
        self.contract = discover_native_key_diagnostic(
            ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe', EXECUTABLE)
        if self.contract['sha256'] != ACTIVE_HASH:
            raise ValueError('Native menu input proof does not match executable')
        self.installed = self.ui_ready = False
        self.last_tap = self.next_readiness_check = 0.0
        self.last_index = -1
        self.enter_attempts = 0
        self.exhausted_at = None
        self.wait_reason = None
        self.pending_touch = None

    def __getattr__(self, name):
        return getattr(self.bridge, name)

    def poll_network(self):
        self.bridge.poll_network()
        if (self.exhausted_at is not None and not getattr(self.bridge, '_menu_enter_observed', False)
                and time.monotonic() > self.exhausted_at + 8):
            raise ValueError('Native menu Enter retry limit exhausted without acknowledgment')

    def release_touch(self, client, context, event_name='menu_native_touch_release'):
        from native_probe import q
        release, gate = self.contract['touch_release'], self.contract['tap_gate']
        state, tag = q(context, 240), q(context, 120)
        if q(client.memory(state, 8)) != tag:
            raise ValueError('Native touch state differs from its loaded tag')
        if tag == release['pending_tag']:
            point = struct.unpack('<ff', client.memory(state + release['coordinates'], 8))
            finger = q(client.memory(state + release['finger_id'], 8))
            pending = self.pending_touch
            if (pending is None or state != pending['state'] or point != pending['point']
                    or struct.unpack_from('<ff', context, 544) != point
                    or finger != pending['finger'] or q(context, 144) != finger):
                raise ValueError('Native touch release does not match its original press')
            now = time.monotonic()
            if now < pending['at'] + release['hold_seconds']:
                # Preserve the pending native touch and let native owned
                # temporary strings/vectors take their usual cleanup path.
                struct.pack_into('<Q', context, 248, client.base + gate['cleanup'])
                return
            self.record(event=event_name, player=client.number, index=pending['index'],
                        x=point[0], y=point[1], finger_id=finger, held_seconds=now-pending['at'])
            self.pending_touch = None
        # Exactly emulate the displaced native MOV [R15],0. No index,
        # coordinate, finger ID or queue contents are changed by the test.
        client.put(state, bytes(8))
        struct.pack_into('<Q', context, 248, client.base + release['next'])
        return

    def __call__(self, client, rva, context):
        from native_probe import TICK, UI_COMMAND, q
        gate = self.contract['tap_gate']
        release = self.contract['touch_release']
        if self.installed and rva == release['rva']:
            return self.release_touch(client, context)
        if self.installed and rva == gate['rva']:
            if getattr(self.bridge, '_menu_enter_observed', False):
                if self.wait_reason != 'acknowledged':
                    self.record(event='menu_native_tap_wait', player=client.number, reason='acknowledged')
                self.wait_reason = 'acknowledged'
                struct.pack_into('<Q', context, 248, client.base + gate['cleanup'])
                return
            now = time.monotonic()
            index = q(context, 120)
            frame = q(context, 160)
            count = q(client.memory(frame + gate['count_stack'], 8))
            pointer = q(client.memory(frame + gate['points_stack'], 8))
            if count != len(self.points) or not 0 <= index < count:
                raise ValueError('Native tap index/count differs from requested sequence')
            point = struct.unpack('<ff', client.memory(pointer + index * gate['point_stride'], 8))
            if point != self.points[index] or index < self.last_index or index > self.last_index + 1:
                raise ValueError('Native tap coordinates/order differ from requested sequence')
            elapsed = struct.unpack_from('<f', context, 416 + gate['elapsed_xmm'] * 16)[0]
            scheduled = struct.unpack_from('<f', context, 416 + gate['scheduled_xmm'] * 16)[0]
            if not math.isfinite(elapsed) or not math.isfinite(scheduled):
                raise ValueError('Invalid native tap scheduling time')
            if not self.ui_ready and now >= self.next_readiness_check:
                self.next_readiness_check = now + .25
                # Native client-side character-selection initialization, read
                # only from this owned process's log. Roster server output is
                # insufficient: it can precede the actual picker UI.
                self.ui_ready = b'char select: lastCharacterIndex selects row' in (client.folder / 'stderr.log').read_bytes()
            reason = ('native-picker' if not self.ui_ready else
                      'host-map' if point == (605.0, 605.0) and client.number != 1 and self.bridge.host_map is None and not self.allow_early_enter else
                      'cadence' if now < self.last_tap + 2 or elapsed < scheduled else None)
            if reason is not None:
                if reason != self.wait_reason and reason != 'cadence':
                    self.record(event='menu_native_tap_wait', player=client.number, index=index, reason=reason)
                self.wait_reason = reason
                struct.pack_into('<Q', context, 248, client.base + gate['cleanup'])
                return
            self.wait_reason = None
            self.last_tap, self.last_index = now, index
            if self.pending_touch is not None:
                raise ValueError('Native menu press arrived before its matched release')
            self.pending_touch = dict(index=index, point=point, finger=index+7, at=now, state=q(context, 240))
            if point == (605.0, 605.0):
                self.enter_attempts += 1
            if index == count - 1:
                self.exhausted_at = now
            self.record(event='menu_native_tap', player=client.number, index=index, x=point[0], y=point[1],
                        enter_attempt=self.enter_attempts, native_picker_ready=self.ui_ready,
                        host_map=self.bridge.host_map, finger_id=index+7)
            # UCOMISS/JAE only select this producer or cleanup. Each target
            # sets flags before consuming them; native code owns index advance
            # and the following press/release pair without adapter writes.
            struct.pack_into('<Q', context, 248, client.base + gate['producer'])
            return
        if rva == TICK and not self.installed:
            if self.home not in client.folder.resolve().parents:
                raise ValueError('Native menu input cannot touch personal saves')
            import re
            config = (client.folder / 'config.toml').read_text()
            if re.findall(r'(?m)^gxResolution\s*=\s*"([^"]+)"', config) != ['1100x700']:
                raise ValueError('Native menu coordinates require observed 1100x700 viewport')
            for address, expected in ((gate['cleanup'], gate['cleanup_expected']),
                                      (gate['producer'], gate['producer_expected']),
                                      (gate['rva'], gate['expected']),
                                      (release['rva'], release['expected'])):
                data = bytes.fromhex(expected)
                if client.memory(client.base + address, len(data)) != data:
                    raise ValueError('Native menu input live instruction changed')
            for row in (gate, release):
                site = client.base + row['rva']
                if site in client.breakpoints:
                    raise ValueError('Native menu tap gate overlaps another hook')
                client.breakpoints[site] = bytes.fromhex(row['expected'])
                client.patch(site, b'\xcc')
            self.installed = True
            self.record(event='menu_native_input_installed', player=client.number, taps=len(self.points))
        enter = (getattr(__import__('native_probe'), 'MENU_CONTRACT', None) or {}).get('enter_tag', 10)
        if rva == UI_COMMAND and struct.unpack('<I', client.memory(q(context, 136), 4))[0] == enter:
            self.record(event='menu_native_enter_request', player=client.number,
                        host_map=self.bridge.host_map, attempts=self.enter_attempts)
        return self.bridge(client, rva, context)


class NativeDepartureDiagnostic:
    """Gate native Escape and a real native Quit tap in disposable sessions."""
    def __init__(self, bridge, ready):
        from native_probe import ROOT, EXECUTABLE, ACTIVE_HASH
        from build_hooks import UPDATED_HASH
        from native_input_contracts import discover_native_key_diagnostic
        self.bridge, self.departure_ready = bridge, ready
        self.home = Path(os.environ.get('COOP_CANDIDATE_HOME', '')).resolve()
        if (not os.environ.get('COOP_CANDIDATE_PROFILE') or
                (ROOT / 'coop-lab/compatibility-tests').resolve() not in self.home.parents or
                not self.home.is_dir() or os.environ.get('WOW_ROGUE_KEY') != 'escape@0' or
                os.environ.get('WOW_ROGUE_TAPS') != '549,521'):
            raise ValueError('Automatic native departure requires the isolated exact input request')
        self.contract = discover_native_key_diagnostic(
            ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe', EXECUTABLE)
        if self.contract['sha256'] != ACTIVE_HASH:
            raise ValueError('Native departure input proof does not match executable')
        self.installed, self.escaped_at = False, None
        self.pending_touch = None

    def __getattr__(self, name):
        return getattr(self.bridge, name)

    def __call__(self, client, rva, context):
        from native_probe import TICK, q
        press, tap = self.contract['repeat_press'], self.contract['tap_gate']
        release = self.contract['touch_release']
        if self.installed and rva == release['rva']:
            return NativeMenuDiagnostic.release_touch(self, client, context, 'departure_native_touch_release')
        if self.installed and rva == press['rva']:
            if not self.departure_ready():
                struct.pack_into('<Q', context, 248, client.base + self.contract['release_cleanup']['rva'])
                return
            self.escaped_at = time.monotonic()
            self.record(event='departure_native_escape', player=client.number)
            client.disable_hooks.add(rva)
            return
        if self.installed and rva == tap['rva']:
            phase = self.bridge.native_states.get(client.number, (None,))[0]
            if self.escaped_at is None or phase != 3 or time.monotonic() < self.escaped_at + 0.5:
                struct.pack_into('<Q', context, 248, client.base + tap['cleanup'])
                return
            index, frame = q(context, 120), q(context, 160)
            count = q(client.memory(frame + tap['count_stack'], 8))
            pointer = q(client.memory(frame + tap['points_stack'], 8))
            if index != 0 or count != 1:
                raise ValueError('Native Quit tap differs from its single original token')
            point = struct.unpack('<ff', client.memory(pointer, 8))
            if point != (549.0, 521.0) or self.pending_touch is not None:
                raise ValueError('Native Quit coordinates or pending touch changed')
            elapsed = struct.unpack_from('<f', context, 416 + tap['elapsed_xmm'] * 16)[0]
            scheduled = struct.unpack_from('<f', context, 416 + tap['scheduled_xmm'] * 16)[0]
            if not math.isfinite(elapsed) or not math.isfinite(scheduled):
                raise ValueError('Invalid native Quit scheduling time')
            if elapsed < scheduled:
                struct.pack_into('<Q', context, 248, client.base + tap['cleanup'])
                return
            self.pending_touch = dict(index=index, point=point, finger=index+7,
                                      at=time.monotonic(), state=q(context, 240))
            self.record(event='departure_native_quit_tap', player=client.number, phase=phase,
                        index=index, x=point[0], y=point[1], finger_id=index+7)
            struct.pack_into('<Q', context, 248, client.base + tap['producer'])
            return
        if rva == TICK and not self.installed:
            if self.home not in client.folder.resolve().parents:
                raise ValueError('Native departure cannot touch personal saves')
            import re
            config = (client.folder / 'config.toml').read_text()
            if re.findall(r'(?m)^gxResolution\s*=\s*"([^"]+)"', config) != ['1100x700']:
                raise ValueError('Native Quit coordinate requires observed 1100x700 viewport')
            for address, expected in (
                    (self.contract['release_cleanup']['rva'], self.contract['release_cleanup']['expected']),
                    (tap['cleanup'], tap['cleanup_expected']),
                    (tap['producer'], tap['producer_expected'])):
                data = bytes.fromhex(expected)
                if client.memory(client.base + address, len(data)) != data:
                    raise ValueError('Native departure cleanup live instruction changed')
            for site in (press, tap, release):
                address, expected = client.base + site['rva'], bytes.fromhex(site['expected'])
                if address in client.breakpoints or client.memory(address, len(expected)) != expected:
                    raise ValueError('Native departure gate live instruction changed')
                client.breakpoints[address] = expected
                client.patch(address, b'\xcc')
            self.installed = True
            self.record(event='departure_native_input_installed', player=client.number)
        return self.bridge(client, rva, context)


class NativeMovementDiagnostic:
    def __init__(self, *args, **kwargs):
        from native_probe import ROOT, EXECUTABLE, ACTIVE_HASH
        from build_hooks import UPDATED_HASH
        from native_input_contracts import discover_native_key_diagnostic
        home = Path(os.environ.get('COOP_CANDIDATE_HOME', '')).resolve()
        if (not os.environ.get('COOP_CANDIDATE_PROFILE') or
                (ROOT / 'coop-lab/compatibility-tests').resolve() not in home.parents or not home.is_dir() or
                os.environ.get('WOW_ROGUE_KEY') != 'w@3'):
            raise ValueError('Native movement input requires an isolated profile and exact w@3 request')
        self.input_home = home
        self.input_contract = discover_native_key_diagnostic(
            ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe', EXECUTABLE)
        if self.input_contract['sha256'] != ACTIVE_HASH:
            raise ValueError('Native input proof does not match the running build')
        self.input_installed = set()
        self.input_pressed = set()
        self.input_waiting = {}
        self.input_release_deadlines = {}
        self.input_probes = {row['rva']: (name, row) for name, row in self.input_contract['probes'].items()}
        super().__init__(*args, **kwargs)

    def record(self, **event):
        if event.get('event') == 'native_movement':
            event['monotonic'] = time.monotonic()
        return super().record(**event)

    def __call__(self, client, rva, context):
        from native_probe import TICK
        if rva in self.input_probes:
            name, _ = self.input_probes[rva]
            if name == 'press':
                phase = self.native_states.get(client.number, (None,))[0]
                state = (tuple(sorted(self.ready)), tuple(sorted(self.loaded)), phase)
                evidence = dict(monotonic=time.monotonic(), ready=list(state[0]),
                                loaded=list(state[1]), phase=phase)
                if not (set(self.members) <= self.ready and set(self.members) <= self.loaded and phase == 1):
                    if self.input_waiting.get(client.number) != state:
                        self.record(event='native_input_wait', player=client.number, **evidence)
                        self.input_waiting[client.number] = state
                    struct.pack_into('<Q', context, 248,
                                     client.base + self.input_contract['release_cleanup']['rva'])
                    return
                self.record(event='native_input_ready_press', player=client.number, **evidence)
                self.input_pressed.add(client.number)
            elif name == 'release':
                if client.number not in self.input_pressed:
                    raise ValueError('Native key release arrived before the observed press')
                now = time.monotonic()
                if client.number not in self.input_release_deadlines:
                    producer = self.input_contract['repeat_press']
                    expected = bytes.fromhex(producer['expected'])
                    if client.memory(client.base + producer['rva'], len(expected)) != expected:
                        raise ValueError('Native key press producer live instruction changed')
                    self.input_release_deadlines[client.number] = now + self.input_contract['hold_seconds']
                    self.record(event='native_input_test_hold', player=client.number, seconds=2.0,
                                mode='native_press_repeat')
                if now < self.input_release_deadlines[client.number]:
                    # Repeat the game's own key-press event while held. A raw
                    # event may precede the next physical-input update; another
                    # native press can then reach held-key binding consumers.
                    struct.pack_into('<Q', context, 248, client.base + self.input_contract['repeat_press']['rva'])
                    return
            self.record(event='native_input_test_path', player=client.number, stage=name,
                        monotonic=now if name == 'release' else time.monotonic())
            # Restore and run the original full instruction. No register,
            # object-state or timing assumptions are needed for this evidence.
            client.disable_hooks.add(rva)
            return
        if rva == TICK and client.number not in self.input_installed:
            if self.input_home not in client.folder.resolve().parents:
                raise ValueError('Native input substitution cannot touch personal saves')
            contract = self.input_contract
            address = client.base + contract['rva']
            expected = bytes.fromhex(contract['expected'])
            if client.memory(address, len(expected)) != expected:
                raise ValueError('Native key diagnostic live instruction changed')
            cleanup = contract['release_cleanup']
            cleanup_bytes = bytes.fromhex(cleanup['expected'])
            if client.memory(client.base + cleanup['rva'], len(cleanup_bytes)) != cleanup_bytes:
                raise ValueError('Native key cleanup live instruction changed')
            client.patch(address, bytes.fromhex(contract['replacement']))
            for probe_rva, (_, probe) in self.input_probes.items():
                site = client.base + probe_rva
                original = bytes.fromhex(probe['expected'])
                if site in client.breakpoints or client.memory(site, len(original)) != original:
                    raise ValueError('Native input observation instruction changed or overlaps another hook')
                client.breakpoints[site] = original
                client.patch(site, b'\xcc')
            self.input_installed.add(client.number)
            self.record(event='native_input_test_installed', player=client.number,
                        rva=contract['rva'], input=contract['key_spec'])
            # This changes only an owned disposable process. Its native lifetime
            # ends with this test; the executable on disk is never modified.
        return super().__call__(client, rva, context)
