"""Executable format detection.

analyze(buf) returns a BinInfo: file-offset <-> virtual-address mapping, sections, symbols
(exports, imports, symtab) and the lines of the F8 header window. One module per format:

    base.py   BinInfo, Section, shared helpers
    pe.py     PE / PE32+        (dotnet.py adds .NET metadata and resources)
    mz.py     DOS MZ
    elf.py    ELF
    macho.py  Mach-O and universal (fat) binaries
"""
from .base import BinInfo, Section
from .elf import _elf
from .macho import _fat, _macho
from .mz import _mz
from .pe import _pe

__all__ = ['analyze', 'BinInfo', 'Section']


def analyze(buf, slice_sel=None):
    head = buf.read(0, 64)
    try:
        if head[:2] == b'MZ':
            r = _pe(buf)
            if r is None:
                r = _mz(buf)
            return r.finish(buf.size)
        if head[:4] == b'\x7fELF':
            return _elf(buf).finish(buf.size)
        if head[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce'):
            return _macho(buf, 0).finish(buf.size)
        if head[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
            r = _fat(buf, slice_sel)
            if r is not None:
                return r.finish(buf.size)
    except Exception as e:  # malformed file: fall back to raw view
        info = BinInfo()
        info.header.append(('Header parse error: %s' % e, None))
        return info
    return BinInfo()
