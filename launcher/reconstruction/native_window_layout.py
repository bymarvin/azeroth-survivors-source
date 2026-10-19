"""Opt-in placement of launcher-owned disposable local test windows."""
import ctypes as C
from ctypes import wintypes as W
import time

# Asynchronous is required: the debugger may have stopped the game's UI thread.
FLAGS = 0x4000 | 0x0010 | 0x0004 | 0x0001  # ASYNC, NOACTIVATE, NOZORDER, NOSIZE


def corner_position(slot, work, size):
    if slot not in (1, 2, 3, 4):
        raise ValueError('Invalid local test slot')
    left, top, right, bottom = work
    width, height = size
    if right <= left or bottom <= top or width <= 0 or height <= 0:
        raise ValueError('Invalid desktop/window dimensions')
    return (left if slot in (1, 3) else max(left, right-width),
            top if slot in (1, 2) else max(top, bottom-height))


class TestWindowPlacement:
    def __init__(self, pid, slot, viewport):
        self.pid, self.slot = pid, slot
        self.viewport = tuple(int(value) for value in viewport.split('x'))
        if len(self.viewport) != 2 or any(not 100 <= value <= 16384 for value in self.viewport):
            raise ValueError('Invalid configured test viewport')
        self.ready_window = None
        self.next_poll, self.done, self.request = 0, False, None
        self.until = time.monotonic() + 120
        self.api = C.WinDLL('user32', use_last_error=True)
        self.callback_type = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
        for name, args, result in (
            ('EnumWindows', [self.callback_type, W.LPARAM], W.BOOL),
            ('GetWindowThreadProcessId', [W.HWND, C.POINTER(W.DWORD)], W.DWORD),
            ('IsWindowVisible', [W.HWND], W.BOOL),
            ('GetWindow', [W.HWND, W.UINT], W.HWND),
            ('GetWindowRect', [W.HWND, C.POINTER(W.RECT)], W.BOOL),
            ('GetClientRect', [W.HWND, C.POINTER(W.RECT)], W.BOOL),
            ('SystemParametersInfoW', [W.UINT, W.UINT, C.c_void_p, W.UINT], W.BOOL),
            ('SetThreadDpiAwarenessContext', [C.c_void_p], C.c_void_p),
            ('SetWindowPos', [W.HWND, W.HWND, C.c_int, C.c_int, C.c_int, C.c_int, W.UINT], W.BOOL)):
            fn = getattr(self.api, name)
            fn.argtypes, fn.restype = args, result

    def poll(self):
        now = time.monotonic()
        if self.done or now < self.next_poll:
            return None
        self.next_poll = now + .25
        if now > self.until:
            raise TimeoutError('Owned local test window could not be placed: ' +
                               getattr(self, 'wait_reason', 'placement not confirmed'))
        previous = self.api.SetThreadDpiAwarenessContext(C.c_void_p(-4))
        if not previous:
            raise C.WinError(C.get_last_error())
        try:
            matches = []
            @self.callback_type
            def visit(window, _):
                pid = W.DWORD()
                self.api.GetWindowThreadProcessId(window, C.byref(pid))
                if pid.value == self.pid and self.api.IsWindowVisible(window) and not self.api.GetWindow(window, 4):
                    client = W.RECT()
                    if self.api.GetClientRect(window, C.byref(client)):
                        viewport = client.right-client.left, client.bottom-client.top
                        if viewport == self.viewport:
                            matches.append(window)
                return True
            if not self.api.EnumWindows(visit, 0):
                raise C.WinError(C.get_last_error())
            if len(matches) != 1:
                self.wait_reason = ('ambiguous configured viewport windows: ' + str(len(matches))
                                    if matches else 'configured viewport not ready')
                self.ready_window = self.request = None
                return None  # Startup auxiliary windows may appear/disappear.
            self.wait_reason = 'placement not confirmed'
            window, rect, work = matches[0], W.RECT(), W.RECT()
            signature = window, self.viewport
            if self.ready_window != signature:
                self.ready_window, self.request = signature, None
                return None  # Require configured viewport on two separate polls.
            if not self.api.GetWindowRect(window, C.byref(rect)) or not self.api.SystemParametersInfoW(0x30, 0, C.byref(work), 0):
                raise C.WinError(C.get_last_error())
            size = rect.right-rect.left, rect.bottom-rect.top
            target = corner_position(self.slot, (work.left, work.top, work.right, work.bottom), size)
            if (rect.left, rect.top) == target:
                self.done = True
                return dict(player=self.slot, pid=self.pid, position=target, outer_size=size)
            if self.request != (window, target, size):
                if not self.api.SetWindowPos(window, None, *target, 0, 0, FLAGS):
                    raise C.WinError(C.get_last_error())
                self.request = (window, target, size)
            return None  # Confirm asynchronous placement on a later debugger loop.
        finally:
            self.api.SetThreadDpiAwarenessContext(previous)
