"""Start the room browser with an EU, US, OCE or SA room directory or in LAN/VPN mode (asked at start, remembered)."""
import argparse
import os
from pathlib import Path
import subprocess
import socket
import sys
import threading
import time
from urllib.parse import urlsplit

# Order = menu numbers [1], [2], ... (LAN follows last); LETTERS gives each choice's letter key.
# Every directory runs on our own servers (EU Central since 0.0.19, EU Southwest since 0.0.20).
REGIONS = {
    'eu': ('EU Central', 'https://lobby.azsurvivors-eu.duckdns.org'),
    'eusw': ('EU Southwest', 'https://lobby.azsurvivors-eusw.duckdns.org'),  # Madrid.
    'us': ('US', 'https://lobby.azsurvivors.duckdns.org'),
    'oce': ('OCE', 'https://lobby.azsurvivors-oce.duckdns.org'),
    'sa': ('SA East (Sao Paulo)', 'https://lobby.azsurvivors-naeast.duckdns.org'),  # Since 0.0.24; ASCII: consoles/pipes (cp437).
}
LAN = 'lan'  # No Internet directory: hosts run their own room list on this network (room_client --lan).
LETTERS = {'eu': 'e', 'eusw': 'w', 'us': 'u', 'oce': 'o', 'sa': 's', LAN: 'l'}  # 'e' stays EU Central (eu and eusw share it).
ALIASES = {'naeast': 'sa'}  # The server's DNS name says naeast; it stands in Sao Paulo.
REGION_FILE = 'coop-region.txt'  # Last choice; not part of any release, so updates keep it.
CHOICE_SECONDS = 5


def check_for_update(root, wait=3.0):
    """Ask GitHub for a newer signed release; offline or slow: start as usual, say nothing."""
    if os.environ.get('COOP_UPDATE_CHECKED') == '1':
        return  # Start-Coop.cmd already asked (coop_autoupdate.py) a moment ago.
    def ask():
        try:
            sys.path.insert(0, str(root / 'reconstruction'))
            import self_update
            status, latest = self_update.check(root, timeout=wait)
        except Exception:
            return
        if status == 'newer':
            updater = root / self_update.UPDATER_ASSET
            how = (f'close the game and run {updater.name} in this folder' if updater.is_file() else
                   'download Azeroth-Survivors-Together-Updater.exe from '
                   'https://github.com/bymarvin/azeroth-survivors-together/releases/latest, '
                   'put it into this folder and run it')
            print(f'[ INFO ] Update available: co-op {latest}. To install it, {how}.', flush=True)
    worker = threading.Thread(target=ask, daemon=True)
    worker.start()
    worker.join(wait)


def region_of(value):
    """'eu'/'eusw'/'us'/'oce'/'sa'/'lan' (any case, 'naeast' = 'sa') for a region name, None otherwise."""
    value = (value or '').strip().lower()
    value = ALIASES.get(value, value)
    return value if value in REGIONS or value == LAN else None


def remembered_region(root):
    try:
        return region_of((root / REGION_FILE).read_text(encoding='utf-8')) or 'eu'
    except (OSError, UnicodeError):
        return 'eu'


def remember_region(root, region):
    try:
        (root / REGION_FILE).write_text(region + '\n', encoding='utf-8')
    except OSError:
        pass  # A read-only folder only means the question shows the default next time.


def latency_ms(url, timeout=1.5, attempts=3, resolve=socket.getaddrinfo):
    """Best TCP connect time to the directory's HTTPS port in ms, None if it does not answer.

    The name is resolved first and not timed (a cold DuckDNS lookup took over 150 ms); then only the
    connect to that address counts, best of `attempts`, everything within `timeout` seconds.
    """
    parts = urlsplit(url)
    deadline = time.monotonic() + timeout
    try:
        address = resolve(parts.hostname, parts.port or 443, 0, socket.SOCK_STREAM)[0][4][:2]
    except (OSError, ValueError, UnicodeError, IndexError):
        return None
    best = None
    for _ in range(attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        started = time.perf_counter()
        try:
            with socket.create_connection(address, remaining):
                ms = round((time.perf_counter() - started) * 1000)
        except (OSError, ValueError):
            continue
        best = ms if best is None else min(best, ms)
    return best


def latencies(timeout=1.5):
    """All regions measured in parallel (at most `timeout` seconds in total)."""
    results = {}
    def measure(key):
        results[key] = latency_ms(REGIONS[key][1], timeout)
    workers = [threading.Thread(target=measure, args=(key,), daemon=True) for key in REGIONS]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout + .5)
    return results


def console_key():
    """A key pressed in this console window, or None (never blocks)."""
    import msvcrt
    return msvcrt.getwch() if msvcrt.kbhit() else None


def choose_region(default, read_key, *, measured=None, seconds=CHOICE_SECONDS, now=time.monotonic,
                  sleep=time.sleep, write=print):
    """Ask for a region or LAN; Enter or no key within `seconds` keeps `default`. Returns (region, how)."""
    measured = measured or {}
    order = [*REGIONS, LAN]  # Number keys follow this order; LETTERS adds a letter per choice.
    shortcuts = {str(number): key for number, key in enumerate(order, 1)}
    shortcuts.update({LETTERS.get(key, key[0]): key for key in order})
    names = dict({key: REGIONS[key][0] for key in REGIONS}, **{LAN: 'LAN / VPN'})
    width = max(len(REGIONS[key][0]) for key in REGIONS)
    def label(key):
        if key == LAN:
            return f'  [{order.index(key) + 1}] {"LAN":<{width}}  {"this network or VPN only, no Internet":<36}'
        name, url = REGIONS[key]
        ms = measured.get(key)
        speed = f'{ms} ms' if ms is not None else ('not reachable' if key in measured else '')
        return f'  [{order.index(key) + 1}] {name:<{width}}  {urlsplit(url).hostname:<36} {speed}'
    numbers = ', '.join(str(n) for n in range(1, len(order))) + f' or {len(order)}'
    write('Co-op region (room list and relay):')
    for key in order:
        write(label(key) + ('   <- last choice' if key == default else ''))
    write(f'Press {numbers}, Enter = {names[default]} (starts automatically in {seconds} s).')
    deadline = now() + seconds
    while True:
        key = read_key()
        if key is None:
            if now() >= deadline:
                return default, 'timeout'
            sleep(.05)
            continue
        key = key.lower()
        if key in ('\r', '\n'):
            return default, 'enter'
        if key in shortcuts:
            return shortcuts[key], 'key'
        write('[ WARN ] Press ' + ', '.join(f'{n} ({names[k]})' for n, k in enumerate(order, 1)) + ' or Enter.')


def resolve_directory(argument, region_option, root, *, interactive, read_key=console_key, measure=latencies,
                      environment=os.environ, write=print, **choice):
    """Directory URL to use, plus how it was chosen.

    Order: an explicit URL (tests, private directories) > a region argument or --region >
    COOP_REGION > the question at start (remembered choice preselected; without a console
    the remembered choice is used at once).
    """
    if argument and region_of(argument) is None:
        return argument, None, 'url'
    region = region_of(argument) or region_of(region_option) or region_of(environment.get('COOP_REGION'))
    how = 'argument' if region else None
    if region is None:
        default = remembered_region(root)
        if interactive:
            region, how = choose_region(default, read_key, measured=measure(), write=write, **choice)
        else:
            region, how = default, 'remembered'
    remember_region(root, region)
    return (LAN if region == LAN else REGIONS[region][1]), region, how


def room_client_command(root, directory, region, ui_port, *, lan_host=None, isolated_profile=False, profile=None):
    """The room browser process; LAN mode passes --lan (and a typed host) instead of a directory."""
    command = [sys.executable, str(root / 'reconstruction' / 'room_client.py')]
    if region == LAN:
        command += ['--lan', *(['--lan-host', lan_host] if lan_host else [])]
    else:
        command += ['--directory', directory]
    command += ['--port', str(ui_port), '--open-browser']
    if isolated_profile:
        command.append('--isolated-profile')
    if profile:
        command += ['--profile', str(Path(profile).resolve())]
    return command


def prepare_channel(root):
    """Before the save setup: the co-op profile of the channel this start uses (COOP_PROFILE_FOLDER for the 0.99.0 beta, its own
    heroes). Without dllshim/ nothing changes."""
    starter = Path(root) / 'dllshim' / 'channel_start.py'
    if not starter.is_file():
        return '0.95.0'
    if str(starter.parent) not in sys.path:
        sys.path.insert(0, str(starter.parent))
    import channel_start
    return channel_start.prepare_launcher(root)


def start_room_browser(root, command, call=subprocess.call):
    """The room browser of the active co-op channel (dllshim/channel_start.py: 0.95.0 default, the 0.99.0 DLL beta, the restart after a
    channel switch with the same --port). Without dllshim/ the launcher starts its room client as before."""
    starter = Path(root) / 'dllshim' / 'channel_start.py'
    if not starter.is_file():
        return call(command)
    if str(starter.parent) not in sys.path:
        sys.path.insert(0, str(starter.parent))
    import channel_start
    return channel_start.run(root, command, call=call)


def save_setup(root, args, interactive, ask=input, say=lambda text: print(text, flush=True)):
    """Save mode (separate by default, shared only with the confirmation word), the one-time NOTICE for old
    installs, the optional import of the single-player heroes and the status line."""
    reconstruction = str(root / 'reconstruction')
    if reconstruction not in sys.path:
        sys.path.insert(0, reconstruction)
    import save_mode
    notice = save_mode.first_start_notice(root)
    if notice:
        say('[ INFO ] ' + notice)
    prompt = ask if interactive else (lambda question: '')
    if args.save_mode == save_mode.SHARED and save_mode.read_mode(root) != save_mode.SHARED:
        if args.confirm == save_mode.CONFIRM_WORD:
            save_mode.write_mode(root, save_mode.SHARED)
            say('[  OK  ] Saves are now shared with the single-player save. Undo: Start-Coop.cmd --save-mode separate')
        elif interactive:
            save_mode.choose_shared(root, prompt, say)
        else:
            say('[ WARN ] Shared saves need a confirmation: run Start-Coop.cmd --save-mode shared in a console window. '
                'Saves stay ' + save_mode.read_mode(root) + '.')
    elif args.save_mode == save_mode.SEPARATE and save_mode.read_mode(root) != save_mode.SEPARATE:
        save_mode.write_mode(root, save_mode.SEPARATE)
        say('[  OK  ] Saves are separate again; the single-player save is no longer touched.')
    if args.import_heroes:
        confirmed = args.confirm == 'IMPORT' or (interactive and prompt(save_mode.IMPORT_WARNING).strip().lower() in ('y', 'yes'))
        if confirmed:
            try:
                backup, note = save_mode.import_single_player(root)
                say('[  OK  ] Single-player heroes copied into the co-op (' + note + ')'
                    + (', previous co-op heroes kept as ' + backup.name if backup else '') + '.')
            except (OSError, KeyError, ValueError) as error:
                say('[FAILED] Copying the single-player heroes: ' + str(error) + '. The co-op heroes are unchanged.')
        else:
            say('[ INFO ] Import not confirmed; the co-op heroes are unchanged.')
    elif save_mode.channel_profile(root):
        # Native engine (0.0.25): no first-start question for new players; existing players are asked ONCE whether their co-op
        # heroes come along (one-way copy, never overwrites). Without a console the room browser asks.
        if save_mode.heroes_question_due(root) and interactive:
            answer = prompt(save_mode.HEROES_QUESTION).strip().lower()
            try:
                result = save_mode.answer_heroes_question(root, answer in ('', 'y', 'yes'))
                say('[  OK  ] ' + {'copied': 'Your co-op heroes were copied to the Native engine (the Classic heroes stay).',
                                   'declined': 'The Native engine starts with new heroes (your Classic heroes stay).',
                                   'kept': 'The Native engine already has heroes; nothing was copied.'}[result['answer']])
            except save_mode.Refused as error:
                say('[ WARN ] ' + str(error))
    elif save_mode.read_mode(root) == save_mode.SEPARATE and save_mode.profile_is_empty(root) and interactive:
        save_mode.first_start(root, prompt, say)
    say(save_mode.status_line(root))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', nargs='?', help='eu, eusw, us, oce, sa (or naeast), lan or a room directory URL (skips the region question)')
    parser.add_argument('lan_host', nargs='?', help='with lan: the host PC\'s address, e.g. 100.101.1.2 or '
                        '100.101.1.2#K7QF-2M3D (VPNs without broadcast such as Tailscale)')
    parser.add_argument('--region', choices=sorted((*REGIONS, LAN)), help='Use this region without asking')
    parser.add_argument('--profile', type=Path, help='Independent launcher settings/log folder')
    parser.add_argument('--isolated-profile', action='store_true', help='Use a disposable native save for another local client')
    parser.add_argument('--save-mode', choices=('separate', 'shared'),
                        help='separate (default): the co-op keeps its own heroes; shared: link with the single-player '
                             'save (asks for confirmation)')
    parser.add_argument('--import-heroes', action='store_true',
                        help='copy the single-player heroes into the co-op once (replaces the co-op heroes, backup kept)')
    parser.add_argument('--confirm', help=argparse.SUPPRESS)  # scripted confirmation (SHARE / IMPORT), for tests
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    # Use a fresh UI port so another install's old launcher cannot receive this session.
    # If the port is taken during handoff, room_client fails binding before opening a browser.
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        ui_port = reservation.getsockname()[1]
    try:
        version = Path(__file__).with_name('COOP-VERSION.txt').read_text(encoding='utf-8').strip() or 'unknown'
    except (OSError, UnicodeError):
        version = 'unknown'
    print('Co-op framework version: ' + version, flush=True)
    print('Co-op game folder: ' + str(root), flush=True)
    check_for_update(root)
    interactive = sys.stdin is not None and sys.stdin.isatty() and os.name == 'nt'
    if not args.isolated_profile:
        prepare_channel(root)  # the 0.99.0 beta keeps its own co-op heroes (COOP_PROFILE_FOLDER)
        save_setup(root, args, interactive)
    directory, region, how = resolve_directory(args.directory, args.region, root, interactive=interactive)
    if region == LAN:
        print(f'[  OK  ] LAN / VPN mode ({how}): no Internet; hosts on this network are found automatically'
              + (f', plus {args.lan_host}' if args.lan_host else '') + '. Change it next time with the number keys '
              f'at start, or start with "Start-Coop.cmd {"|".join((*REGIONS, LAN))}".', flush=True)
    elif region:
        print(f'[  OK  ] Region {REGIONS[region][0]} ({urlsplit(directory).hostname}, {how}). '
              f'Change it next time with the number keys at start, or start with '
              f'"Start-Coop.cmd {"|".join((*REGIONS, LAN))}".', flush=True)
    raise SystemExit(start_room_browser(root, room_client_command(
        root, directory, region, ui_port, lan_host=args.lan_host if region == LAN else None,
        isolated_profile=args.isolated_profile, profile=args.profile)))
