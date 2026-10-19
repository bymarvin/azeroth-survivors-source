"""Section timing for the debugger loop (native_probe.run), written into the gameplay log.

The game is halted from a debug event until ContinueDebugEvent, so every
millisecond spent there is a game stall. Every 10 s the debugger thread writes
`loop_profile`; debug_overhead at the end carries the whole-run summary and
`loop_profile_final` the full tables. Fields (times in ms):
  events     per event (p<player>:<hook name> or kind<debug event>): [sum, max, count],
             wait() return -> ContinueDebugEvent
  sections   inclusive [sum, max, count] per section on the debugger thread;
             poll_network is split into (loop) = top of run() and (hook) = inside a hook
  loop_gap   ContinueDebugEvent -> next wait() call (nobody takes the next event)
  stall      per event the upper bound of the game hold: if wait() returned at once
             (event already pending), time since the previous continue, plus handling;
             stall_over_ms counts events above 5/16/50/100/250 ms
  frame_gap  per hook the largest interval between two hits (a game-side hitch)
  worst      the longest stall with its section breakdown
  io         channel I/O thread (zlib framing): [sum, max, count]
  cpu        debugger-thread and process CPU seconds
Diagnostics only: nothing here changes game state or the wire protocol.
Set COOP_LOOP_PROFILE=0 to disable.
"""
import os
import struct
import threading
import time
from collections import defaultdict

perf = time.perf_counter
WINDOW = 10.0
HITCH_SECONDS = .08  # frame_hitch: interval between two WRITE hooks of one game
BUCKETS = (5, 16, 50, 100, 250)


class Stats:
    def __init__(self):
        self.sections = defaultdict(lambda: [0.0, 0.0, 0])  # sum, max, count
        self.events = defaultdict(lambda: [0.0, 0.0, 0])
        self.loop_gap = [0.0, 0.0, 0]
        self.stall = [0.0, 0.0, 0]
        self.buckets = [0] * len(BUCKETS)
        self.frame_gap = defaultdict(float)
        self.worst = None
        self.io = defaultdict(lambda: [0.0, 0.0, 0])

    @staticmethod
    def add(slot, value):
        slot[0] += value
        if value > slot[1]:
            slot[1] = value
        slot[2] += 1

    def payload(self, seconds):
        ms = lambda s: [round(s[0] * 1000, 1), round(s[1] * 1000, 2), s[2]]
        order = lambda d: dict(sorted(((k, ms(v)) for k, v in list(d.items())), key=lambda i: -i[1][0]))
        return dict(seconds=round(seconds, 1), events=order(self.events), sections=order(self.sections),
                    loop_gap=ms(self.loop_gap), stall=ms(self.stall),
                    stall_over_ms={str(b): n for b, n in zip(BUCKETS, self.buckets)},
                    frame_gap_ms={k: round(v * 1000, 1) for k, v in
                                  sorted(self.frame_gap.items(), key=lambda i: -i[1])[:8]},
                    worst=self.worst, io=order(self.io))


class Profiler:
    def __init__(self, callback, wait, cont):
        self.callback = callback
        self._wait, self._cont = wait, cont
        self.thread = threading.get_ident()
        self.lock = threading.Lock()
        self.window, self.total = Stats(), Stats()
        self.window_start = self.run_start = perf()
        self.cpu = (time.thread_time(), time.process_time())
        self.in_event = False
        self.event_start = self.handling_start = self.last_cont = None
        self.event_name = None
        self.event_sections = None
        self.last_hit = {}
        self.handled_at_hit, self.handled_total = {}, 0.0
        self.emitting = False

    # -- sections -------------------------------------------------------
    def section(self, name, elapsed):
        if threading.get_ident() != self.thread:
            with self.lock:
                Stats.add(self.window.io[name], elapsed)
                Stats.add(self.total.io[name], elapsed)
            return
        Stats.add(self.window.sections[name], elapsed)
        Stats.add(self.total.sections[name], elapsed)
        if self.event_sections is not None:
            self.event_sections[name] = self.event_sections.get(name, 0.0) + elapsed

    # -- debugger loop --------------------------------------------------
    def wait(self, event, milliseconds):
        called = perf()
        if self.last_cont is not None:
            gap = called - self.last_cont
            Stats.add(self.window.loop_gap, gap)
            Stats.add(self.total.loop_gap, gap)
        self.maybe_emit(called)
        result = self._wait(event, milliseconds)
        returned = perf()
        if result:
            # An event that was already pending waited since the previous continue.
            pending = returned - called < .0002 and self.last_cont is not None
            self.event_start = self.last_cont if pending else returned
            self.handling_start = returned
            self.in_event = True
            self.event_name = f'kind{struct.unpack_from("<I", event)[0]}'
            self.event_sections = {}
        return result

    def cont(self, pid, tid, status):
        result = self._cont(pid, tid, status)
        now = perf()
        if self.in_event:
            handled = now - self.handling_start
            stall = now - self.event_start
            self.handled_total += stall
            for stats in (self.window, self.total):
                Stats.add(stats.events[self.event_name], handled)
                Stats.add(stats.stall, stall)
                for index, bucket in enumerate(BUCKETS):
                    if stall * 1000 > bucket:
                        stats.buckets[index] += 1
                if stats.worst is None or stall * 1000 > stats.worst['stall_ms']:
                    stats.worst = dict(stall_ms=round(stall * 1000, 2), handled_ms=round(handled * 1000, 2),
                                       event=self.event_name, at_s=round(now - self.run_start, 1),
                                       sections={k: round(v * 1000, 2) for k, v in
                                                 sorted(self.event_sections.items(), key=lambda i: -i[1])[:10]})
        self.in_event = False
        self.event_sections = None
        self.last_cont = now
        return result

    def hook(self, client, rva):
        key = f'p{client.number}:{NAMES.get(rva, format(rva, "x"))}'
        self.event_name = key
        now = perf()
        last = self.last_hit.get(key)
        if last is not None:
            gap = now - last
            for stats in (self.window, self.total):
                if gap > stats.frame_gap[key]:
                    stats.frame_gap[key] = gap
            if gap > HITCH_SECONDS and key.endswith(':WRITE') and not self.emitting:
                self.report_hitch(key, gap, last, now)
        self.last_hit[key] = now
        self.handled_at_hit[key] = self.handled_total

    def report_hitch(self, key, gap, last, now):
        """A long interval between two frames: our handling inside it vs the game's own time."""
        ours = self.handled_total - self.handled_at_hit.get(key, self.handled_total)
        actions = [[round((at - last) * 1000, 1), kind, *values]
                   for at, kind, values in list(getattr(self.callback, 'recent_actions', ()))
                   if at >= last - .3]
        self.record(event='frame_hitch', hook=key, gap_ms=round(gap * 1000, 1), ours_ms=round(ours * 1000, 1),
                    at_s=round(now - self.run_start, 2), monotonic=round(time.monotonic(), 3),
                    actions=actions[-24:])

    # -- reporting ------------------------------------------------------
    def cpu_delta(self):
        thread, process = time.thread_time(), time.process_time()
        delta = dict(debugger_thread_s=round(thread - self.cpu[0], 2), process_s=round(process - self.cpu[1], 2))
        self.cpu = (thread, process)
        return delta

    def record(self, **event):
        record = getattr(self.callback, 'record', None)
        if record is None:
            return
        self.emitting = True
        try:
            record(player=getattr(self.callback, 'number', None), **event)
        finally:
            self.emitting = False

    def maybe_emit(self, now):
        if now - self.window_start < WINDOW or self.emitting:
            return
        with self.lock:
            window, self.window = self.window, Stats()
        payload = window.payload(now - self.window_start)
        payload['cpu'] = self.cpu_delta()
        payload['enemies'] = len(getattr(self.callback, '_enemy_snapshot', None) or ())
        payload['host_clock'] = getattr(self.callback, 'host_clock', None)
        self.window_start = now
        self.record(event='loop_profile', **payload)

    def summary(self):
        """Whole-run values for debug_overhead; writes loop_profile_final once."""
        with self.lock:
            payload = self.total.payload(perf() - self.run_start)
        self.record(event='loop_profile_final', **payload)
        return dict(stall_max_ms=payload['stall'][1], stall_over_ms=payload['stall_over_ms'],
                    loop_gap_max_ms=payload['loop_gap'][1], worst_stall=payload['worst'],
                    top_sections=dict(list(payload['sections'].items())[:8]))


NAMES = {}
ACTIVE = None
_INSTALLED = False


def timed(label, original, split_hook=False):
    def wrapper(*args, **kwargs):
        profiler = ACTIVE
        if profiler is None:
            return original(*args, **kwargs)
        started = perf()
        try:
            return original(*args, **kwargs)
        finally:
            name = f'{label}({"hook" if profiler.in_event else "loop"})' if split_hook else label
            profiler.section(name, perf() - started)
    wrapper.__wrapped__ = original
    wrapper.__name__ = getattr(original, '__name__', label)
    wrapper.__doc__ = getattr(original, '__doc__', None)
    return wrapper


def _install_wrappers():
    """Wrap the loop sections once per process; inactive wrappers cost one global read."""
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True
    import native_probe
    import coop_transport
    import visibility_bridge
    import native_guest_combat
    import online_bridge
    import group_online
    NAMES.update({value: name for name, value in vars(native_probe).items()
                  if name.isupper() and type(value) is int and 0x1000000 <= value < 0x8000000})

    def wrap(owner, attribute, name=None, split_hook=False):
        original = owner.__dict__.get(attribute) if isinstance(owner, type) else getattr(owner, attribute, None)
        if original is None:
            return
        setattr(owner, attribute, timed(name or attribute, original, split_hook))

    wrap(group_online.GroupOnlineBridge, 'poll_network', split_hook=True)
    wrap(group_online.GroupOnlineBridge, 'decorate')
    wrap(group_online.GroupOnlineBridge, 'thin_snapshot')
    wrap(group_online.GroupOnlineBridge, 'enemy_update')
    wrap(group_online.GroupOnlineBridge, 'enemy_wire_view')
    wrap(group_online.GroupOnlineBridge, 'receive_peer')
    wrap(online_bridge.OnlineBridge, 'poll_network', 'poll_network_pair', split_hook=True)
    wrap(online_bridge.OnlineBridge, 'send_state')
    wrap(online_bridge.OnlineBridge, 'receive_state')
    wrap(online_bridge.OnlineBridge, 'apply_enemy_update')
    wrap(online_bridge.OnlineBridge, '__call__', 'hook_callback')
    wrap(visibility_bridge.Bridge, '__call__', 'bridge_call')
    wrap(visibility_bridge.Bridge, 'capture_world')
    wrap(visibility_bridge.Bridge, 'before_batch', 'before_batch(base)')
    wrap(visibility_bridge.Bridge, 'record')
    wrap(native_guest_combat._NativeCombatBridge, '__call__', 'combat_call')
    wrap(native_guest_combat._NativeCombatBridge, 'before_batch')
    wrap(native_guest_combat._NativeCombatBridge, 'snapshot_enemies')
    wrap(native_guest_combat._NativeCombatBridge, '_parse_enemy_raw', 'parse_enemies')
    wrap(native_guest_combat._NativeCombatBridge, 'sync_mirrors')
    wrap(native_guest_combat._NativeCombatBridge, 'sync_chests')
    wrap(native_guest_combat._NativeCombatBridge, 'apply_guest_damage')
    for module in (native_guest_combat, visibility_bridge):
        wrap(module, 'native_enemies')
        wrap(module, 'native_enemy')
    wrap(native_probe.Native, 'memory', 'native_read')
    wrap(native_probe.Native, 'put', 'native_write')
    wrap(native_probe.Native, 'context', 'get_context')
    wrap(coop_transport, 'encode', 'json_encode')
    wrap(coop_transport.Channel, 'send', 'channel_send')
    wrap(coop_transport.Channel, 'drain', 'channel_drain')
    wrap(coop_transport, 'frame_bytes', 'frame_bytes_zlib')    # I/O thread
    wrap(coop_transport, 'frame_payload', 'frame_payload_zlib')  # I/O thread


def start(callback, wait, cont):
    """Profiler for one run() or None; run() calls its wait/cont/hook/summary."""
    global ACTIVE
    if os.environ.get('COOP_LOOP_PROFILE') == '0' or not hasattr(callback, 'record'):
        return None
    _install_wrappers()
    ACTIVE = Profiler(callback, wait, cont)
    return ACTIVE


def stop(profiler):
    global ACTIVE
    if ACTIVE is profiler:
        ACTIVE = None
