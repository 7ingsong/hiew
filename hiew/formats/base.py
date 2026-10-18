"""Shared pieces of the format parsers: BinInfo (what the UI shows), Section, read helpers and
the section / import / export lines of the F8 header window."""
import struct


class Section:
    __slots__ = ('name', 'va', 'vsize', 'off', 'size', 'exec_', 'flags', 'raw')

    def __init__(self, name, va, vsize, off, size, exec_=False, flags=''):
        self.name = name
        self.va = va
        self.vsize = vsize
        self.off = off
        self.size = size
        self.exec_ = exec_
        self.flags = flags
        self.raw = size


class BinInfo:
    def __init__(self):
        self.kind = 'raw'
        self.desc = ''
        self.arch = None
        self.bits = 0
        self.endian = '<'
        self.base = 0
        self.entry_va = None
        self.entry_off = None
        self.sections = []
        self.segments = []   # (file_off, file_size, va, vsize)
        self.symbols = {}    # va -> name
        self.imports = []    # (dll, name, iat_va)
        self.exports = []    # (name, va)
        self.header = []     # (text, (offset, mode) or None)
        self.slices = []     # fat Mach-O: (cpu name, offset, size)
        self.slice_warning = None
        self.slice_idx = None
        self.pe_resources = []       # Windows .rsrc: dicts type/name/lang/rva/off/size/codepage/label/lines
        self.dotnet_resources = []
        self.dotnet_job = None       # .NET metadata being read in the background (dotnet.DotnetJob)   # .NET: dicts name/off/va/size/public/data/entries

    def off2va(self, off):
        for o, s, v, _ in self.segments:
            if o <= off < o + s:
                return v + off - o
        return None

    def va2off(self, va):
        for o, s, v, _ in self.segments:
            if v <= va < v + s:
                return o + va - v
        return None

    def finish(self, size):
        self.segments = [(o, min(s, max(0, size - o)), v, vs) for o, s, v, vs in self.segments if o < size]
        if self.entry_off is None and self.entry_va is not None:
            self.entry_off = self.va2off(self.entry_va)
        return self


def _unpack(buf, fmt, off):
    n = struct.calcsize(fmt)
    d = buf.read(off, n)
    if off < 0 or len(d) < n:
        raise ValueError('truncated')
    return struct.unpack(fmt, d)


def _cstr(data, off=0, maxlen=256):
    if isinstance(data, (bytes, bytearray)):
        end = data.find(b'\0', off, off + maxlen)
        s = data[off:end if end >= 0 else off + maxlen]
    else:
        s = data.read(off, maxlen)
        i = s.find(b'\0')
        if i >= 0:
            s = s[:i]
    return s.decode('latin-1')


def _section_lines(info):
    if not info.sections:
        return
    H = info.header
    H.append(('', None))
    H.append(('Sections:  Name              VirtAddr  VirtSize  Offset    Size      Flags', None))
    for s in info.sections:
        H.append(('           %-16s  %08X  %08X  %08X  %08X  %s' % (s.name[:16], s.va, s.vsize, s.off, s.raw, s.flags),
                  (s.off, 'decode' if s.exec_ else 'hex') if s.size else None))


def _export_lines(info):
    if not info.exports:
        return
    H = info.header
    H.append(('', None))
    H.append(('Exports (%d):' % len(info.exports), None))
    for nm, va in sorted(info.exports, key=lambda x: x[1]):
        o = info.va2off(va)
        H.append(('  .%08X  %s' % (va, nm), (o, 'decode') if o is not None else None))


def _import_lines(info):
    if not info.imports:
        return
    H = info.header
    H.append(('', None))
    H.append(('Imports (%d):' % len(info.imports), None))
    for lib, fn, slot in info.imports:
        so = info.va2off(slot)
        H.append(('  .%08X  %-24s %s' % (slot, lib[:24], fn), (so, 'hex') if so is not None else None))
