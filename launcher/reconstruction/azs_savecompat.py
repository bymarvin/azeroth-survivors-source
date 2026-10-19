"""Keeps a single-player save of a newer game safe while the co-op runs on game 0.95.0.

Problem: the co-op hands the single-player save to game 0.95.0 and writes the result back.
0.95.0 only knows `unlock|class|n` (first n zones of its 9-zone list). From 0.96 the game stores
`open|class|zone_id` instead and knows 12 zones. 0.95.0 skips `open` lines and unknown zones, so
every class falls back to Elwynn Forest, and the write-back overwrites the newer save.

This module (plaintext level; see azs_rse1 for the container):
  * newer_format_reasons(text)  -> why a save is newer than 0.95.0 (empty list = 0.95-compatible)
  * compat_view(text)           -> the save as 0.95.0 understands it (newer data mapped or left out)
  * merge(original, given, result) -> original + only what the co-op session changed
  * damage_report(current, backup) -> zones a co-op write-back already lost, with a repaired text
The rules are documented in MERGE-RULES.md.
"""

# Zone order of the `unlock` format (0.95.0 and earlier). An unlock count n means these first n.
LEGACY_ZONES = ('elwynn', 'duskwood', 'wsg', 'ab', 'feralas', 'arena', 'av', 'brm', 'aq')

# Zone order of 0.97.1 (12 zones). Only used to place zones that 0.95.0 does not know between
# the old ones; `zone_order` can be passed in (e.g. read from the player's exe) for later builds.
ZONES_0971 = ('elwynn', 'duskwood', 'wsg', 'ungoro', 'ab', 'feralas', 'arena', 'sm', 'av', 'brm', 'aq', 'naxx')

# Records 0.95.0 reads. Anything else is newer data and is never handed to 0.95.0.
KINDS_095 = ('pick', 'unlock', 'items', 'equip', 'look', 'talent', 'seen', 'ach', 'achat', 'stat',
             'beat', 'perk', 'tabard', 'pets', 'resets', 'hero')

# Order in which the game writes records (new lines are inserted following it).
WRITE_ORDER = ('pick', 'unlock', 'open', 'items', 'equip', 'look', 'talent', 'seen', 'ach', 'achat',
               'stat', 'beat', 'perk', 'tabard', 'pets', 'resets', 'hero')

PER_CLASS = ('unlock', 'open', 'equip', 'look', 'talent', 'beat', 'hero')

# Highest item variant 0.95.0 knows (0..4 = the five set tiers; 5/6 = PvP set from 0.97).
MAX_VARIANT_095 = 4


# ------------------------------------------------------------------------------------- lines

def split_lines(text):
    """Lines without their '\\n'; a save always ends with '\\n'."""
    if not text:
        return []
    lines = text.split('\n')
    if lines[-1] == '':
        lines.pop()
    return lines


def join_lines(lines):
    return ''.join(line + '\n' for line in lines)


def kind_of(line):
    return line.split('|', 1)[0]


def key_of(line):
    """Identity of a record: (kind, class) for per-class records, (kind,) for single records,
    the whole line for anything unknown."""
    f = line.split('|')
    k = f[0]
    if k in PER_CLASS and len(f) > 1:
        return (k, f[1])
    if k in KINDS_095 or k == 'open':
        return (k,)
    return ('?', line)


def _list(field):
    return [x for x in field.split(',') if x] if field else []


def _pairs(field, sep):
    out = []
    for e in _list(field):
        k, _, v = e.rpartition(sep)
        out.append((k, v))
    return out


def _int(s, default=None):
    try:
        return int(s)
    except (TypeError, ValueError):
        return default


def item_variant(item_id):
    """(class, piece, variant) of an item id 1 0 C P V 0, or None."""
    i = _int(item_id)
    if i is None or i < 100000 or i % 10:
        return None
    return (i // 1000 - 100, (i // 100) % 10, (i // 10) % 10)


def legacy_count(zone, zone_order=ZONES_0971):
    """Unlock count for a furthest opened zone: the last old zone at or before it."""
    if zone in LEGACY_ZONES:
        return LEGACY_ZONES.index(zone) + 1
    if zone in zone_order:
        for z in reversed(zone_order[:zone_order.index(zone) + 1]):
            if z in LEGACY_ZONES:
                return LEGACY_ZONES.index(z) + 1
    return None


def zone_rank(zone, zone_order=ZONES_0971):
    """Position for comparing how far a zone is: in `zone_order`, else None (unknown)."""
    return zone_order.index(zone) if zone in zone_order else None


# ------------------------------------------------------------------------------------- detect

def newer_format_reasons(text):
    """Why this plaintext needs a newer game than 0.95.0. Empty = 0.95.0 reads it completely."""
    reasons = []
    for n, line in enumerate(split_lines(text), 1):
        f = line.split('|')
        k = f[0]
        if k == 'open':
            reasons.append('line %d: open-zone record (format from 0.96)' % n)
        elif k not in KINDS_095:
            reasons.append('line %d: unknown record "%s"' % (n, k))
        elif k == 'beat' and len(f) == 3:
            for z in _list(f[2]):
                if z not in LEGACY_ZONES:
                    reasons.append('line %d: beaten zone "%s" unknown to 0.95.0' % (n, z))
        elif k == 'pick' and len(f) > 4 and f[4] not in LEGACY_ZONES:
            reasons.append('line %d: picked zone "%s" unknown to 0.95.0' % (n, f[4]))
        elif k == 'items' and len(f) == 2:
            new = [i for i in _list(f[1]) if (item_variant(i) or (0, 0, 0))[2] > MAX_VARIANT_095]
            if new:
                reasons.append('line %d: %d items of the PvP set (from 0.97)' % (n, len(new)))
    return reasons


# ------------------------------------------------------------------------------------- compat

def compat_view(text, zone_order=ZONES_0971):
    """The save as 0.95.0 can read it: `open` → `unlock` (furthest zone → last old zone at or before
    it), unknown zones left out of `beat`/`pick`, PvP items (variant 5/6) left out of `items` and
    `equip`, unknown records left out. Nothing here is lost: merge() keeps the original's data."""
    out = []
    opened = {}
    for line in split_lines(text):
        f = line.split('|')
        k = f[0]
        if k == 'open' and len(f) == 3:
            n = legacy_count(f[2], zone_order)
            if n is not None:
                opened[f[1]] = max(opened.get(f[1], 0), n)
            continue
        if k == 'unlock' and len(f) == 3 and _int(f[2]) is not None:
            opened[f[1]] = max(opened.get(f[1], 0), min(max(_int(f[2]), 1), len(LEGACY_ZONES)))
            continue
        if k not in KINDS_095:
            continue
        if k == 'beat' and len(f) == 3:
            zs = [z for z in _list(f[2]) if z in LEGACY_ZONES]
            if not zs:
                continue
            line = 'beat|%s|%s' % (f[1], ','.join(zs))
        elif k == 'pick' and len(f) > 4 and f[4] not in LEGACY_ZONES:
            n = legacy_count(f[4], zone_order) or 1
            f[4] = LEGACY_ZONES[n - 1]
            line = '|'.join(f)
        elif k == 'items' and len(f) == 2:
            line = 'items|' + ','.join(i for i in _list(f[1]) if (item_variant(i) or (0, 0, 0))[2] <= MAX_VARIANT_095)
        elif k == 'equip' and len(f) == 3:
            keep = [e for e in _list(f[2]) if (item_variant(e.partition(':')[2]) or (0, 0, 0))[2] <= MAX_VARIANT_095]
            line = 'equip|%s|%s' % (f[1], ','.join(keep))
        out.append(line)
    # unlock lines go right after pick, in the original class order
    order = []
    for line in split_lines(text):
        f = line.split('|')
        if f[0] in ('open', 'unlock') and len(f) == 3 and f[1] in opened and f[1] not in order:
            order.append(f[1])
    pos = 1 if out and kind_of(out[0]) == 'pick' else 0
    for i, c in enumerate(order):
        out.insert(pos + i, 'unlock|%s|%d' % (c, opened[c]))
    return join_lines(out)


# ------------------------------------------------------------------------------------- merge

def _index(lines):
    d = {}
    for i, line in enumerate(lines):
        d.setdefault(key_of(line), i)
    return d


def _insert_by_order(lines, line):
    rank = {k: i for i, k in enumerate(WRITE_ORDER)}
    mine = rank.get(kind_of(line), len(WRITE_ORDER))
    pos = 0
    for i, l in enumerate(lines):
        if rank.get(kind_of(l), len(WRITE_ORDER)) <= mine:
            pos = i + 1
    lines.insert(pos, line)


class MergeError(ValueError):
    pass


def merge(original, given, result, zone_order=ZONES_0971):
    """original = single-player save before the co-op (any version),
    given = what 0.95.0 got (compat_view(original) or original itself for old saves),
    result = what 0.95.0 wrote after the co-op session.
    Returns the original with only the co-op's changes applied; see MERGE-RULES.md."""
    o, g, r = split_lines(original), split_lines(given), split_lines(result)
    gi, ri = _index(g), _index(r)
    out = list(o)
    oi = _index(out)
    report = []

    def put(key, line):
        nonlocal oi
        if key in oi:
            out[oi[key]] = line
        else:
            _insert_by_order(out, line)
        oi = _index(out)

    def fields(lines, idx, key):
        return lines[idx[key]].split('|') if key in idx else None

    for key in list(ri):
        rl = r[ri[key]]
        gl = g[gi[key]] if key in gi else None
        if rl == gl:
            continue  # unchanged by the co-op
        k = key[0]
        rf = rl.split('|')
        gf = gl.split('|') if gl is not None else None
        of = fields(out, oi, key)
        if k == '?':
            continue  # 0.95.0 never writes unknown records
        if k == 'unlock':
            c = key[1]
            n1 = min(max(_int(rf[2], 1), 1), len(LEGACY_ZONES)) if len(rf) == 3 else 1
            n0 = min(max(_int(gf[2], 1), 1), len(LEGACY_ZONES)) if gf and len(gf) == 3 else 0
            if n1 <= n0:
                continue
            zone = LEGACY_ZONES[n1 - 1]
            oo = fields(out, oi, ('open', c))
            if oo is not None and len(oo) == 3:
                ro, rn = zone_rank(oo[2], zone_order), zone_rank(zone, zone_order)
                if ro is not None and rn is not None and rn <= ro:
                    continue
                if ro is None:
                    report.append('class %s: co-op opened %s, original zone %s unknown, kept' % (c, zone, oo[2]))
                    continue
                put(('open', c), 'open|%s|%s' % (c, zone))
                report.append('class %s: opened up to %s' % (c, zone))
            else:
                ou = fields(out, oi, ('unlock', c))
                if ou is not None and len(ou) == 3 and _int(ou[2], 0) >= n1:
                    continue
                put(('unlock', c), 'unlock|%s|%d' % (c, n1))
                report.append('class %s: %d zones open' % (c, n1))
        elif k == 'open':
            # only during a repair: the later save may name its own zone; the further one wins
            oo = fields(out, oi, key)
            if oo is not None and len(oo) == 3 and len(rf) == 3:
                ro, rn = zone_rank(oo[2], zone_order), zone_rank(rf[2], zone_order)
                if ro is None or rn is None or rn <= ro:
                    continue
            put(key, rl)
        elif k == 'stat':
            ov = dict(_pairs(of[1], '=')) if of and len(of) == 2 else {}
            gv = dict(_pairs(gf[1], '=')) if gf and len(gf) == 2 else {}
            keys = [kk for kk, _ in _pairs(of[1], '=')] if of and len(of) == 2 else []
            for kk, v in _pairs(rf[1], '=') if len(rf) == 2 else []:
                if kk not in ov:
                    ov[kk] = v
                    keys.append(kk)
                    continue
                delta = _int(v, 0) - _int(gv.get(kk), 0)
                if delta > 0:
                    ov[kk] = str(_int(ov.get(kk), 0) + delta)
            put(key, 'stat|' + ','.join('%s=%s' % (kk, ov[kk]) for kk in keys))
        elif k == 'items':
            have = _list(of[1]) if of and len(of) == 2 else []
            added = [i for i in _list(rf[1]) if i not in (_list(gf[1]) if gf and len(gf) == 2 else [])]
            ids = sorted(set(have) | set(added), key=lambda x: (_int(x, 0), x))
            if added:
                put(key, 'items|' + ','.join(ids))
                report.append('%d new items' % len(set(added) - set(have)))
        elif k in ('ach', 'achat', 'seen', 'beat'):
            sep = {'ach': None, 'achat': '=', 'seen': '='}.get(k)
            if k == 'beat':
                have = _list(of[2]) if of and len(of) == 3 else []
                new = [z for z in _list(rf[2]) if z not in have]
                if new:
                    put(key, 'beat|%s|%s' % (key[1], ','.join(have + new)))
                continue
            if sep is None:
                have = _list(of[1]) if of and len(of) == 2 else []
                new = [a for a in _list(rf[1]) if a not in have]
                if new:
                    put(key, 'ach|' + ','.join(sorted(have + new)))
                continue
            have = _pairs(of[1], sep) if of and len(of) == 2 else []
            hd = dict(have)
            changed = False
            for kk, v in _pairs(rf[1], sep):
                if kk not in hd:
                    have.append((kk, v))
                    hd[kk] = v
                    changed = True
                elif k == 'seen' and _int(v, 0) > _int(hd[kk], 0):
                    have = [(a, v if a == kk else b) for a, b in have]
                    hd[kk] = v
                    changed = True
            if changed:
                if k == 'achat':
                    have.sort()
                put(key, '%s|%s' % (k, ','.join('%s%s%s' % (a, sep, b) for a, b in have)))
        else:
            # pick, equip, look, talent, hero, perk, pets, tabard, resets: the co-op's version
            put(key, rl)
            if k in ('talent', 'hero', 'equip'):
                report.append('%s of class %s from the co-op' % (k, key[1]))
    text = join_lines(out)
    return text, report


# ------------------------------------------------------------------------------------- damage

def opened_zone_counts(text, zone_order=ZONES_0971):
    """Per class: how far zones are open, as a rank in `zone_order` (None if not stored)."""
    res = {}
    for line in split_lines(text):
        f = line.split('|')
        if len(f) != 3:
            continue
        if f[0] == 'unlock' and _int(f[2]) is not None:
            z = LEGACY_ZONES[min(max(_int(f[2]), 1), len(LEGACY_ZONES)) - 1]
        elif f[0] == 'open':
            z = f[2]
        else:
            continue
        rank = zone_rank(z, zone_order)
        if rank is not None:
            res[f[1]] = max(res.get(f[1], -1), rank)
    return res


def damage_report(current, backup, zone_order=ZONES_0971):
    """Did a co-op write-back lose zones? `backup` = the single-player save before that write-back
    (sp-backup-*.txt), `current` = the save now. Returns (lost: list of str, repaired_text or None).
    Repair = merge(backup, backup, current): the co-op's changes stay, the lost zones come back."""
    if not newer_format_reasons(backup):
        return [], None  # the backup was readable by 0.95.0: nothing could be lost this way
    before, now = opened_zone_counts(backup, zone_order), opened_zone_counts(current, zone_order)
    lost = []
    for c, rank in before.items():
        if now.get(c, -1) < rank:
            lost.append('class %s: zones up to %s, now %s' % (c, zone_order[rank], zone_order[now[c]] if c in now else 'none stored (only Elwynn)'))
    for line in split_lines(backup):
        if kind_of(line) not in KINDS_095 and kind_of(line) != 'open' and line not in split_lines(current):
            lost.append('record "%s" missing' % kind_of(line))
    if not lost:
        return [], None
    repaired, _ = merge(backup, backup, current, zone_order)
    return lost, repaired
