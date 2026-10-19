"""RSE1 container of Azeroth Survivors' characters.txt (reference implementation, stdlib only).

File  = b"RSE1:" + Base64(nonce[16] | ciphertext | tag[20])
tag   = HMAC-SHA1(key, b"tag" | nonce | ciphertext)
block i of the keystream (20 bytes) = HMAC-SHA1(key, b"ks" | nonce | i as u64 little endian)

The key is not stored here. `key_from_exe` finds it in the player's AzerothSurvivors.exe: the game
inlines HMAC-SHA1 with precomputed ipad/opad blocks; each block is set up by
`mov dword [rsp+X], 0xC3D2E1F0` (SHA-1 H4) followed by four rip-relative 16-byte loads, and the
pair (ipad, opad) satisfies ipad ^ 0x36 == opad ^ 0x5c == key. Same key in 0.95.0 and 0.97.1.
"""
import base64
import hashlib
import hmac
import os
import struct

PREFIX = b'RSE1:'
NONCE_LEN = 16
TAG_LEN = 20


class Rse1Error(ValueError):
    pass


def _mac(key, *parts):
    h = hmac.new(key, digestmod=hashlib.sha1)
    for p in parts:
        h.update(p)
    return h.digest()


def _keystream_xor(key, nonce, data):
    # inner/outer states once, then one copy per 20-byte block
    base = hmac.new(key, b'ks' + nonce, hashlib.sha1)
    out = bytearray(data)
    n = len(out)
    for i in range(0, n, 20):
        h = base.copy()
        h.update(struct.pack('<Q', i // 20))
        ks = h.digest()
        chunk = out[i:i + 20]
        out[i:i + 20] = (int.from_bytes(chunk, 'little') ^ int.from_bytes(ks[:len(chunk)], 'little')).to_bytes(len(chunk), 'little')
    return bytes(out)


def unwrap(file_bytes):
    """Prefix and Base64 only (no key): returns the raw sealed bytes."""
    if not file_bytes.startswith(PREFIX):
        raise Rse1Error('not an RSE1 file')
    try:
        raw = base64.b64decode(file_bytes[len(PREFIX):].rstrip(), validate=True)
    except ValueError as e:
        raise Rse1Error('invalid Base64') from e
    if len(raw) < NONCE_LEN + TAG_LEN:
        raise Rse1Error('too short')
    return raw


def open_save(file_bytes, key):
    """Returns (nonce, plaintext str). Raises Rse1Error on a bad tag (wrong key or damaged file)."""
    raw = unwrap(file_bytes)
    nonce, ct, tag = raw[:NONCE_LEN], raw[NONCE_LEN:-TAG_LEN], raw[-TAG_LEN:]
    if not hmac.compare_digest(_mac(key, b'tag', nonce, ct), tag):
        raise Rse1Error('checksum mismatch (wrong key or damaged file)')
    try:
        return nonce, _keystream_xor(key, nonce, ct).decode('utf-8')
    except UnicodeDecodeError as e:
        raise Rse1Error('plaintext is not UTF-8') from e


def seal(text, key, nonce=None):
    """Seals `text`; with the original nonce an unchanged text reproduces the file byte for byte."""
    nonce = nonce if nonce is not None else os.urandom(NONCE_LEN)
    ct = _keystream_xor(key, nonce, text.encode('utf-8'))
    return PREFIX + base64.b64encode(nonce + ct + _mac(key, b'tag', nonce, ct))


# ----------------------------------------------------------------------------------- key search

def _sections(data):
    if data[:2] != b'MZ':
        raise Rse1Error('not a PE file')
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe:pe + 4] != b'PE\0\0':
        raise Rse1Error('not a PE file')
    nsec, optsz = struct.unpack_from('<H', data, pe + 6)[0], struct.unpack_from('<H', data, pe + 20)[0]
    opt = pe + 24
    if struct.unpack_from('<H', data, opt)[0] != 0x20B:
        raise Rse1Error('not a 64-bit PE file')
    base = struct.unpack_from('<Q', data, opt + 24)[0]
    secs = []
    for i in range(nsec):
        s = opt + optsz + i * 40
        name = data[s:s + 8].rstrip(b'\0')
        vsize, va, rsize, raw = struct.unpack_from('<IIII', data, s + 8)
        secs.append((name, va, max(vsize, rsize), raw, rsize))
    return base, secs


def key_candidates_from_bytes(data):
    """All HMAC key blocks (64 bytes) found in an exe image."""
    base, secs = _sections(data)

    def off_to_va(off):
        for _, va, _, raw, rsize in secs:
            if raw <= off < raw + rsize:
                return base + va + off - raw
        return None

    def va_to_off(v):
        r = v - base
        for _, va, size, raw, rsize in secs:
            if va <= r < va + size and r - va < rsize:
                return raw + r - va
        return None

    text = [s for s in secs if s[0] == b'.text']
    lo, hi = (text[0][3], text[0][3] + text[0][4]) if text else (0, len(data))
    blocks = []
    i = data.find(b'\xF0\xE1\xD2\xC3', lo, hi)
    while i != -1:
        start = i - 7
        if start >= lo and data[start:start + 3] == b'\xC7\x84\x24':
            loads, j = [], i + 4
            while j + 7 < min(start + 140, hi) and len(loads) < 4:
                if data[j] == 0x0F and data[j + 1] in (0x28, 0x10) and data[j + 2] & 0xC7 == 0x05:
                    disp = struct.unpack_from('<i', data, j + 3)[0]
                    va = off_to_va(j + 7)
                    o = va_to_off(va + disp) if va is not None else None
                    if o is not None:
                        loads.append(data[o:o + 16])
                    j += 7
                else:
                    j += 1
            if len(loads) == 4:
                blocks.append((start, b''.join(loads)))
        i = data.find(b'\xF0\xE1\xD2\xC3', i + 4, hi)
    keys = []
    for (oa, a), (ob, b) in zip(blocks, blocks[1:]):
        if ob - oa > 4096:
            continue
        ka = bytes(x ^ 0x36 for x in a)
        if ka == bytes(x ^ 0x5C for x in b) and ka not in keys:
            keys.append(ka)
    return keys


def key_from_exe(exe_path, sample=None):
    """The save key from the player's game exe. With `sample` (sealed bytes) the candidate that
    opens it is returned; raises Rse1Error when none is found or none fits."""
    with open(exe_path, 'rb') as f:
        data = f.read()
    keys = key_candidates_from_bytes(data)
    if not keys:
        raise Rse1Error('no save key found in ' + str(exe_path))
    if sample is None:
        return keys[0]
    for k in keys:
        try:
            open_save(sample, k)
            return k
        except Rse1Error:
            continue
    raise Rse1Error('no key from ' + str(exe_path) + ' opens this save')
