"""DOS MZ executables (no PE header)."""
from .base import BinInfo, _unpack


def _mz(buf):
    info = BinInfo()
    info.kind = 'MZ'
    info.desc = 'DOS MZ'
    info.arch = 'x86-16'
    info.bits = 16
    cblp, cp, crlc, cparhdr = _unpack(buf, '<HHHH', 2)
    ip, cs = _unpack(buf, '<HH', 0x14)
    hdr = cparhdr * 16
    entry = hdr + ((cs * 16 + ip) & 0xFFFFF)
    if entry < buf.size:
        info.entry_off = entry
    info.header.append(('DOS MZ executable   header %X bytes   relocs %d' % (hdr, crlc), None))
    info.header.append(('Entry CS:IP %04X:%04X   (file offset %08X)' % (cs, ip, entry),
                        (entry, 'decode') if entry < buf.size else None))
    return info
