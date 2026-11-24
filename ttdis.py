"""Minimal TrueType bytecode disassembler for the minecraft2shell PoC fonts."""
import struct
import sys

# opcode -> (mnemonic, argbytes) ; argbytes>0 means N bytes operand, -1 means count byte
OPS = {
    0x00: ('SVTCA[y]', 0), 0x01: ('SVTCA[x]', 0), 0x02: ('SPVTCA[y]', 0), 0x03: ('SPVTCA[x]', 0),
    0x04: ('SFVTCA[y]', 0), 0x05: ('SFVTCA[x]', 0), 0x06: ('SPVTL[0]', 0), 0x07: ('SPVTL[1]', 0),
    0x08: ('SFVTL[0]', 0), 0x09: ('SFVTL[1]', 0), 0x0A: ('SPVFS', 0), 0x0B: ('SFVFS', 0),
    0x0C: ('GPV', 0), 0x0D: ('GFV', 0), 0x0E: ('SFVTPV', 0), 0x0F: ('ISECT', 0),
    0x10: ('SRP0', 0), 0x11: ('SRP1', 0), 0x12: ('SRP2', 0), 0x13: ('SZP0', 0),
    0x14: ('SZP1', 0), 0x15: ('SZP2', 0), 0x16: ('SZPS', 0), 0x17: ('SLOOP', 0),
    0x18: ('RTG', 0), 0x19: ('RTHG', 0), 0x1A: ('SMD', 0), 0x1B: ('ELSE', 0),
    0x1C: ('JMPR', 0), 0x1D: ('SCVTCI', 0), 0x1E: ('SSWCI', 0), 0x1F: ('SSW', 0),
    0x20: ('DUP', 0), 0x21: ('POP', 0), 0x22: ('CLEAR', 0), 0x23: ('SWAP', 0),
    0x24: ('DEPTH', 0), 0x25: ('CINDEX', 0), 0x26: ('MINDEX', 0), 0x27: ('ALIGNPTS', 0),
    0x29: ('UTP', 0), 0x2A: ('LOOPCALL', 0), 0x2B: ('CALL', 0), 0x2C: ('FDEF', 0),
    0x2D: ('ENDF', 0), 0x2E: ('MDAP[0]', 0), 0x2F: ('MDAP[1]', 0),
    0x30: ('IUP[0]', 0), 0x31: ('IUP[1]', 0), 0x32: ('SHP[0]', 0), 0x33: ('SHP[1]', 0),
    0x34: ('SHC[0]', 0), 0x35: ('SHC[1]', 0), 0x36: ('SHZ[0]', 0), 0x37: ('SHZ[1]', 0),
    0x38: ('SHPIX', 0), 0x39: ('IP', 0), 0x3A: ('MSIRP[0]', 0), 0x3B: ('MSIRP[1]', 0),
    0x3C: ('ALIGNRP', 0), 0x3D: ('RTDG', 0), 0x3E: ('MIAP[0]', 0), 0x3F: ('MIAP[1]', 0),
    0x40: ('NPUSHB', -1), 0x41: ('NPUSHW', -1),
    0x42: ('WS', 0), 0x43: ('RS', 0), 0x44: ('WCVTP', 0), 0x45: ('RCVT', 0),
    0x46: ('GC[0]', 0), 0x47: ('GC[1]', 0), 0x48: ('SCFS', 0), 0x49: ('MD[0]', 0),
    0x4A: ('MD[1]', 0), 0x4B: ('MPPEM', 0), 0x4C: ('MPS', 0), 0x4D: ('FLIPON', 0),
    0x4E: ('FLIPOFF', 0), 0x4F: ('DEBUG', 0),
    0x50: ('LT', 0), 0x51: ('LTEQ', 0), 0x52: ('GT', 0), 0x53: ('GTEQ', 0),
    0x54: ('EQ', 0), 0x55: ('NEQ', 0), 0x56: ('ODD', 0), 0x57: ('EVEN', 0),
    0x58: ('IF', 0), 0x59: ('EIF', 0), 0x5A: ('AND', 0), 0x5B: ('OR', 0), 0x5C: ('NOT', 0),
    0x5D: ('DELTAP1', 0), 0x5E: ('SDB', 0), 0x5F: ('SDS', 0),
    0x60: ('ADD', 0), 0x61: ('SUB', 0), 0x62: ('DIV', 0), 0x63: ('MUL', 0),
    0x64: ('ABS', 0), 0x65: ('NEG', 0), 0x66: ('FLOOR', 0), 0x67: ('CEILING', 0),
    0x68: ('ROUND[0]', 0), 0x69: ('ROUND[1]', 0), 0x6A: ('ROUND[2]', 0), 0x6B: ('ROUND[3]', 0),
    0x6C: ('NROUND[0]', 0), 0x6D: ('NROUND[1]', 0), 0x6E: ('NROUND[2]', 0), 0x6F: ('NROUND[3]', 0),
    0x70: ('WCVTF', 0), 0x71: ('DELTAC1', 0), 0x72: ('DELTAC2', 0), 0x73: ('DELTAC3', 0),
    0x74: ('DELTAP2', 0), 0x75: ('DELTAP3', 0), 0x76: ('SROUND', 0), 0x77: ('S40ROUND', 0),
    0x78: ('JROT', 0), 0x79: ('JROF', 0), 0x7A: ('ROUNDOFF', 0),
    0x7B: ('?', 0), 0x7C: ('SCANCTRL', 0), 0x7D: ('SDPVTL[0]', 0), 0x7E: ('SDPVTL[1]', 0),
    0x7F: ('GETINFO', 0), 0x80: ('IDEF', 0), 0x81: ('ROLL', 0), 0x82: ('MAX', 0),
    0x83: ('MIN', 0), 0x84: ('SCANTYPE', 0), 0x85: ('INSTCTRL', 0),
    0x8E: ('GETADP', 0),
    0xC0: ('MDRP', 0), 0xE0: ('MIRP', 0),
}

RANGES = [
    (0x8B, 0x8B, 'SCANCTRL'), (0x8C, 0x8D, 'SDPVTL'), (0x8E, 0x8E, 'GETINFO'),
    (0x89, 0x89, 'IDEF'), (0x8A, 0x8A, 'ROLL'), (0x8B, 0x8B, 'SCANCTRL'),
]


def disasm(code, base=0):
    out = []
    pc = 0
    n = len(code)
    while pc < n:
        at = pc
        op = code[pc]
        pc += 1
        if 0xB0 <= op <= 0xB7:
            cnt = (op - 0xB0) + 1
            vals = [code[pc + i] for i in range(cnt)]
            pc += cnt
            out.append((at + base, 'PUSHB[%d] %s' % (cnt, ' '.join(map(str, vals)))))
            continue
        if 0xB8 <= op <= 0xBF:
            cnt = (op - 0xB8) + 1
            vals = [struct.unpack('>h', code[pc + 2 * i:pc + 2 * i + 2])[0] for i in range(cnt)]
            pc += 2 * cnt
            out.append((at + base, 'PUSHW[%d] %s' % (cnt, ' '.join(map(str, vals)))))
            continue
        if op == 0x40:  # NPUSHB
            cnt = code[pc]; pc += 1
            vals = [code[pc + i] for i in range(cnt)]
            pc += cnt
            out.append((at + base, 'NPUSHB %d %s' % (cnt, ' '.join(map(str, vals)))))
            continue
        if op == 0x41:  # NPUSHW
            cnt = code[pc]; pc += 1
            vals = [struct.unpack('>h', code[pc + 2 * i:pc + 2 * i + 2])[0] for i in range(cnt)]
            pc += 2 * cnt
            out.append((at + base, 'NPUSHW %d %s' % (cnt, ' '.join(map(str, vals)))))
            continue
        if op == 0x80:  # IDEF
            opd = code[pc]; pc += 1
            out.append((at + base, 'IDEF 0x%02X' % opd))
            continue
        if op == 0x2C:  # FDEF
            opd = code[pc]; pc += 1
            out.append((at + base, 'FDEF %d' % opd))
            continue
        if 0xC0 <= op <= 0xDF:
            out.append((at + base, 'MDRP %02X' % op))
            continue
        if 0xE0 <= op <= 0xFF:
            out.append((at + base, 'MIRP %02X' % op))
            continue
        if op in (0x58,):  # IF
            out.append((at + base, 'IF'))
            continue
        name = OPS.get(op, ('UNK_%02X' % op, 0))[0]
        out.append((at + base, name))
    return out


def parse_sfnt(data):
    ver, num = struct.unpack('>IH', data[:6])
    tables = {}
    off = 12
    for _ in range(num):
        tag, cks, o, l = struct.unpack('>4sIII', data[off:off + 16])
        off += 16
        tables[tag.decode()] = (o, l)
    return tables


def main(path):
    if path.endswith('.zip'):
        import zipfile
        z = zipfile.ZipFile(path)
        data = z.read('assets/ctf/font/deferred-000.ttf')
    else:
        data = open(path, 'rb').read()
    tables = parse_sfnt(data)
    fo, fl = tables['fpgm']
    code = data[fo:fo + fl]
    lines = disasm(code)
    for off, text in lines:
        print('%04x  %s' % (off, text))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'resource-pack.zip')
