"""The room browser's "Co-op channel" panel (0.0.24, WP3): 0.95.0 (default) or 0.99.0 (DLL beta).

A thin layer over game_channel (WP2, DLL chat): no channel logic here, only the page's requests and the slow
search kept in a background thread so the page can poll. The page asks the player; every call here is checked again
by game_channel (running game or co-op round, build, free space, server switch).
"""
import threading
from pathlib import Path

CHANNELS = ('0.95.0', '0.99.0')


class Refused(Exception):
    """A request the player cannot make now; `text` is shown as it is, `code` for tests and logs."""

    def __init__(self, text, code='refused'):
        super().__init__(text)
        self.text, self.code = text, code


_search_lock = threading.Lock()
_search = dict(state='idle', results=[], error=None)


def _module(root):
    """game_channel ships in <root>/dllshim (not in reconstruction/, whose .py files are the launcher's identity)."""
    import sys
    shim = str(Path(root) / 'dllshim')
    if shim not in sys.path:
        sys.path.append(shim)
    try:
        import game_channel
    except ImportError:
        return None
    return game_channel


def _call(fn, *args, **kwargs):
    """game_channel.Refused -> Refused with the player text and code."""
    try:
        return fn(*args, **kwargs)
    except Exception as error:
        if type(error).__name__ == 'Refused':
            raise Refused(getattr(error, 'text', None) or str(error), getattr(error, 'code', 'refused')) from None
        raise


def _run_search(gc, root):
    try:
        results = _call(gc.locate, root)
        with _search_lock:
            _search.update(state='done', results=list(results), error=None)
    except Refused as error:
        with _search_lock:
            _search.update(state='failed', results=[], error=error.text)
    except Exception as error:  # a search that crashed is shown, never raised into the page
        with _search_lock:
            _search.update(state='failed', results=[], error='The search failed: %s' % error)


def search_state():
    with _search_lock:
        return dict(_search, results=list(_search['results']))


def panel_request(root, data, coop_running=False, local=None, module=None):
    """One request of the panel: {'op': 'status'|'locate'|'locate_folder'|'copy_start'|'copy_progress'|'copy_cancel'|
    'set_active', ...}. `local` = (version, build) the running launcher plays."""
    gc = module if module is not None else _module(root)
    op = data.get('op')
    if gc is None:
        if op == 'status':
            return dict(available=False, active='0.95.0', local_version=(local or (None, None))[0], local_build=(local or (None, None))[1])
        raise Refused('This launcher has no 0.99.0 beta yet.', 'unavailable')
    if op == 'status':
        status = dict(_call(gc.channel_status, root, coop_running=coop_running))
        status.update(available=True, local_version=(local or (None, None))[0], local_build=(local or (None, None))[1],
                      search=search_state(), copy=_call(gc.copy_progress, root))
        return status
    if op == 'locate':
        with _search_lock:
            if _search['state'] == 'searching':
                return dict(_search, results=[])
            _search.update(state='searching', results=[], error=None)
        threading.Thread(target=_run_search, args=(gc, root), daemon=True, name='channel-locate').start()
        return search_state()
    if op == 'search':
        return search_state()
    if op == 'locate_folder':
        path = str(data.get('path') or '').strip()
        if not path:
            raise Refused('Enter the folder of your Azeroth Survivors 0.99.0 game.', 'not_found')
        return _call(gc.locate_folder, root, path[:400])
    if op == 'copy_start':
        if data.get('confirm') is not True:
            raise Refused('Copy not confirmed; nothing changed.', 'not_confirmed')
        return _call(gc.copy_start, root, str(data.get('path') or '')[:400])
    if op == 'copy_progress':
        return _call(gc.copy_progress, root)
    if op == 'copy_cancel':
        return _call(gc.copy_cancel, root)
    if op == 'set_active':
        channel = str(data.get('channel'))
        if channel not in CHANNELS:
            raise Refused('Unknown co-op channel.', 'unknown')
        if channel == '0.99.0' and data.get('confirm') is not True:
            raise Refused('Switch not confirmed; nothing changed.', 'not_confirmed')
        return _call(gc.set_active, root, channel, coop_running=coop_running)
    raise Refused('Unknown action.', 'unknown')
