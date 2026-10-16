"""Executable format detection: PE, ELF, Mach-O (incl. fat), DOS MZ.

Produces a BinInfo with file-offset <-> virtual-address mapping, sections,
symbols (exports, imports, symtab) and the lines for the F8 header window.
"""
import os
import platform
import struct
import time


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


# ---------------------------------------------------------------- PE

PE_MACHINES = {0x14c: ('x86-32', 'i386'), 0x8664: ('x86-64', 'AMD64'), 0x1c0: ('arm', 'ARM'),
               0x1c2: ('thumb', 'Thumb'), 0x1c4: ('thumb', 'ARMv7'), 0xaa64: ('arm64', 'ARM64'),
               0x200: (None, 'IA64')}
PE_SUBSYS = {1: 'Native', 2: 'GUI', 3: 'Console', 9: 'WinCE', 10: 'EFI app', 11: 'EFI boot',
             12: 'EFI runtime', 14: 'Xbox', 16: 'Boot app'}


def _pe(buf):
    (lfanew,) = _unpack(buf, '<I', 0x3c)
    if buf.read(lfanew, 4) != b'PE\0\0':
        return None
    machine, nsec, tstamp, _, _, optsz, chars = _unpack(buf, '<HHIIIHH', lfanew + 4)
    opt = lfanew + 24
    (magic,) = _unpack(buf, '<H', opt)
    pe64 = magic == 0x20b
    (entry_rva,) = _unpack(buf, '<I', opt + 16)
    base = _unpack(buf, '<Q', opt + 24)[0] if pe64 else _unpack(buf, '<I', opt + 28)[0]
    salign, falign = _unpack(buf, '<II', opt + 32)
    size_image, size_headers = _unpack(buf, '<II', opt + 56)
    (subsys,) = _unpack(buf, '<H', opt + 68)
    ndd_off = opt + (108 if pe64 else 92)
    (ndd,) = _unpack(buf, '<I', ndd_off)
    dd = []
    for i in range(min(ndd, 16)):
        try:
            dd.append(_unpack(buf, '<II', ndd_off + 4 + i * 8))
        except ValueError:
            break

    info = BinInfo()
    info.kind = 'PE'
    info.desc = 'PE32+' if pe64 else 'PE32'
    arch, mname = PE_MACHINES.get(machine, (None, '%04X' % machine))
    info.arch = arch
    info.bits = 64 if pe64 else 32
    info.base = base
    info.segments.append((0, size_headers, base, size_headers))
    sec_off = opt + optsz
    for i in range(min(nsec, 256)):
        name, vsize, va, rsize, rptr = _unpack(buf, '<8sIIII', sec_off + i * 40)
        (ch,) = _unpack(buf, '<I', sec_off + i * 40 + 36)
        name = name.rstrip(b'\0').decode('latin-1')
        ex = bool(ch & 0x20000000) or bool(ch & 0x20)
        flags = ('R' if ch & 0x40000000 else '-') + ('W' if ch & 0x80000000 else '-') + ('X' if ex else '-')
        fsz = min(rsize, vsize) if vsize else rsize
        sec = Section(name, base + va, vsize, rptr, fsz, ex, flags)
        sec.raw = rsize
        info.sections.append(sec)
        if fsz and rptr:
            info.segments.append((rptr, fsz, base + va, max(vsize, rsize)))
    if entry_rva:
        info.entry_va = base + entry_rva

    def rva_off(rva):
        return info.va2off(base + rva)

    # imports
    if len(dd) > 1 and dd[1][0]:
        o = rva_off(dd[1][0])
        psz, pfmt, ordflag = (8, '<Q', 1 << 63) if pe64 else (4, '<I', 1 << 31)
        for _ in range(1024):
            if o is None:
                break
            try:
                oft, _, _, name_rva, ft = _unpack(buf, '<IIIII', o)
            except ValueError:
                break
            if not name_rva or not ft:
                break
            no = rva_off(name_rva)
            dll = _cstr(buf, no) if no is not None else '?'
            to = rva_off(oft or ft)
            j = 0
            while to is not None and j < 16384:
                try:
                    (val,) = _unpack(buf, pfmt, to + j * psz)
                except ValueError:
                    break
                if not val:
                    break
                if val & ordflag:
                    fn = 'Ord%d' % (val & 0xffff)
                else:
                    fo = rva_off(val & 0x7fffffff)
                    fn = _cstr(buf, fo + 2) if fo is not None else '?'
                iat = base + ft + j * psz
                info.imports.append((dll, fn, iat))
                info.symbols[iat] = fn
                j += 1
            o += 20

    # exports
    if dd and dd[0][0]:
        exp_rva, exp_size = dd[0]
        o = rva_off(exp_rva)
        if o is not None:
            (_, _, _, _, _, obase, nfunc, nnames, afunc, anames, aord) = _unpack(buf, '<IIHHIIIIIII', o)
            nfunc = min(nfunc, 65536)
            nnames = min(nnames, 65536)
            fo, no, oo = rva_off(afunc), rva_off(anames), rva_off(aord)
            if fo is not None:
                fd = buf.read(fo, nfunc * 4)
                funcs = struct.unpack('<%dI' % (len(fd) // 4), fd[:len(fd) // 4 * 4])
                named = {}
                if no is not None and oo is not None:
                    nd = buf.read(no, nnames * 4)
                    od = buf.read(oo, nnames * 2)
                    cnt = min(len(nd) // 4, len(od) // 2)
                    nrv = struct.unpack('<%dI' % cnt, nd[:cnt * 4])
                    ords = struct.unpack('<%dH' % cnt, od[:cnt * 2])
                    for k in range(cnt):
                        so = rva_off(nrv[k])
                        if so is not None:
                            named[ords[k]] = _cstr(buf, so)
                for k, rva in enumerate(funcs):
                    if not rva or exp_rva <= rva < exp_rva + exp_size:
                        continue
                    nm = named.get(k, 'Ord%d' % (obase + k))
                    info.symbols[base + rva] = nm
                    info.exports.append((nm, base + rva))

    H = info.header
    H.append(('%s  %s   Machine: %04X   Sections: %d' % (info.desc, mname, machine, nsec), None))
    eoff = info.va2off(info.entry_va) if info.entry_va else None
    H.append(('Entry point: .%08X   (file offset %s)' % (info.entry_va or 0, '%08X' % eoff if eoff is not None else '-'),
              (eoff, 'decode') if eoff is not None else None))
    H.append(('Image base:  %08X   Image size: %08X   Headers: %08X' % (base, size_image, size_headers), None))
    H.append(('Align: section %X / file %X   Subsystem: %s' % (salign, falign, PE_SUBSYS.get(subsys, str(subsys))), None))
    try:
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(tstamp))
    except (OverflowError, ValueError, OSError):
        ts = '?'
    H.append(('Timestamp:   %08X  %s   Characteristics: %04X' % (tstamp, ts, chars), None))
    _section_lines(info)
    if info.imports:
        H.append(('', None))
        H.append(('Imports (%d):' % len(info.imports), None))
        for dll, fn, iat in info.imports:
            io = info.va2off(iat)
            H.append(('  .%08X  %-24s %s' % (iat, dll, fn), (io, 'hex') if io is not None else None))
    _export_lines(info)
    return info


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


# ---------------------------------------------------------------- ELF

ELF_MACHINES = {3: 'x86-32', 0x3e: 'x86-64', 0x28: 'arm', 0xb7: 'arm64', 8: 'mips32', 0x14: 'ppc32',
                0x15: 'ppc64', 0xf3: 'riscv64'}
ELF_MNAMES = {3: 'i386', 0x3e: 'x86-64', 0x28: 'ARM', 0xb7: 'AArch64', 8: 'MIPS', 0x14: 'PowerPC',
              0x15: 'PowerPC64', 0xf3: 'RISC-V'}
ELF_TYPES = {0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE'}
PT_NAMES = {0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS',
            0x6474e550: 'EH_FRAME', 0x6474e551: 'STACK', 0x6474e552: 'RELRO', 0x6474e553: 'PROPERTY'}


def _elf(buf):
    ident = buf.read(0, 16)
    is64 = ident[4] == 2
    e = '<' if ident[5] != 2 else '>'
    if is64:
        (etype, mach, _, entry, phoff, shoff, _, _, phent, phnum, shent, shnum, shstrndx) = \
            _unpack(buf, e + 'HHIQQQIHHHHHH', 16)
    else:
        (etype, mach, _, entry, phoff, shoff, _, _, phent, phnum, shent, shnum, shstrndx) = \
            _unpack(buf, e + 'HHIIIIIHHHHHH', 16)
    info = BinInfo()
    info.kind = 'ELF'
    info.desc = 'ELF64' if is64 else 'ELF32'
    info.bits = 64 if is64 else 32
    info.endian = e
    arch = ELF_MACHINES.get(mach)
    if arch == 'mips32' and is64:
        arch = 'mips64'
    if arch == 'riscv64' and not is64:
        arch = 'riscv32'
    if arch == 'arm' and entry & 1:
        arch = 'thumb'
        entry &= ~1
    info.arch = arch
    if entry:
        info.entry_va = entry

    phdrs = []
    if phoff:
        for i in range(min(phnum, 512)):
            o = phoff + i * phent
            try:
                if is64:
                    pt, pf, po, pv, _, pfs, pms, _ = _unpack(buf, e + 'IIQQQQQQ', o)
                else:
                    pt, po, pv, _, pfs, pms, pf, _ = _unpack(buf, e + 'IIIIIIII', o)
            except ValueError:
                break
            phdrs.append((pt, pf, po, pv, pfs, pms))
            if pt == 1 and pfs:
                info.segments.append((po, pfs, pv, pms))

    raw = []
    if shoff:
        for i in range(min(shnum, 8192)):
            o = shoff + i * shent
            try:
                if is64:
                    raw.append(_unpack(buf, e + 'IIQQQQIIQQ', o))
                else:
                    raw.append(_unpack(buf, e + 'IIIIIIIIII', o))
            except ValueError:
                break
    names = b''
    if 0 <= shstrndx < len(raw):
        names = buf.read(raw[shstrndx][4], min(raw[shstrndx][5], 1 << 20))
    for (nm, st, fl, addr, so, ss, *_rest) in raw:
        if st == 0:
            continue
        name = _cstr(names, nm) if nm < len(names) else '?'
        ex = bool(fl & 4)
        flags = ('A' if fl & 2 else '-') + ('W' if fl & 1 else '-') + ('X' if ex else '-')
        info.sections.append(Section(name, addr, ss, so, 0 if st == 8 else ss, ex, flags))

    # symbols (.symtab / .dynsym) and GOT slot names from relocations
    dynsyms = {}
    for idx, (nm, st, fl, addr, so, ss, link, _, _, ent) in enumerate(raw):
        if st not in (2, 11) or not ent or link >= len(raw):
            continue
        strs = buf.read(raw[link][4], min(raw[link][5], 16 << 20))
        data = buf.read(so, min(ss, 32 << 20))
        fmt = e + ('IBBHQQ' if is64 else 'IIIBBH')
        esz = struct.calcsize(fmt)
        for k in range(len(data) // ent):
            if is64:
                sn, sinfo, _, shndx, val, _ = struct.unpack_from(fmt, data, k * ent)
            else:
                sn, val, _, sinfo, _, shndx = struct.unpack_from(fmt, data, k * ent)
            name = _cstr(strs, sn) if sn < len(strs) else ''
            if st == 11:
                dynsyms.setdefault(idx, {})[k] = name
            styp = sinfo & 0xf
            if name and val and shndx != 0 and styp in (0, 1, 2, 10):
                if arch in ('arm', 'thumb') and styp == 2:
                    val &= ~1
                info.symbols.setdefault(val, name)
                if st == 11 and (sinfo >> 4) in (1, 2) and styp in (1, 2, 10):   # global/weak dynamic = export
                    info.exports.append((name, val))
        del esz
    for (nm, st, fl, addr, so, ss, link, _, _, ent) in raw:
        if st not in (4, 9) or not ent or link not in dynsyms:
            continue
        syms = dynsyms[link]
        data = buf.read(so, min(ss, 16 << 20))
        fmt = e + ('QQ' if is64 else 'II')
        for k in range(len(data) // ent):
            r_off, r_info = struct.unpack_from(fmt, data, k * ent)
            si = r_info >> 32 if is64 else r_info >> 8
            name = syms.get(si)
            if name:
                info.symbols.setdefault(r_off, name + '@got')
                info.imports.append(('', name, r_off))

    needed = []
    for (nm, st, fl, addr, so, ss, link, *_r) in raw:
        if st == 6 and link < len(raw):   # SHT_DYNAMIC: DT_NEEDED strings
            strs = buf.read(raw[link][4], min(raw[link][5], 1 << 20))
            d = buf.read(so, min(ss, 1 << 20))
            fmt = e + ('qQ' if is64 else 'iI')
            esz = struct.calcsize(fmt)
            for k in range(len(d) // esz):
                tag, val = struct.unpack_from(fmt, d, k * esz)
                if tag == 0:
                    break
                if tag == 1 and val < len(strs):
                    needed.append(_cstr(strs, val))
    if needed and len(needed) == 1:
        info.imports = [(needed[0], n, a) for _, n, a in info.imports]
    H = info.header
    H.append(('%s %s  %s   Type: %s   Machine: %s' % (info.desc, 'LE' if e == '<' else 'BE', '',
                                                     ELF_TYPES.get(etype, str(etype)), ELF_MNAMES.get(mach, str(mach))), None))
    eoff = info.va2off(entry) if entry else None
    H.append(('Entry point: .%08X   (file offset %s)' % (entry, '%08X' % eoff if eoff is not None else '-'),
              (eoff, 'decode') if eoff is not None else None))
    if phdrs:
        H.append(('', None))
        H.append(('Program headers:  Type       Offset    VirtAddr  FileSize  MemSize   Flags', None))
        for pt, pf, po, pv, pfs, pms in phdrs:
            fl = ('R' if pf & 4 else '-') + ('W' if pf & 2 else '-') + ('X' if pf & 1 else '-')
            H.append(('                  %-10s %08X  %08X  %08X  %08X  %s' %
                      (PT_NAMES.get(pt, '%X' % pt), po, pv, pfs, pms, fl),
                      (po, 'decode' if pf & 1 else 'hex') if pfs and po < buf.size else None))
    _section_lines(info)
    if needed:
        H.append(('', None))
        H.append(('Needed libraries: %s' % ', '.join(needed), None))
    _import_lines(info)
    _export_lines(info)
    return info


# ---------------------------------------------------------------- Mach-O

MACHO_CPU = {7: ('x86-32', 'i386'), 0x01000007: ('x86-64', 'x86_64'), 12: ('arm', 'ARM'),
             0x0100000c: ('arm64', 'ARM64'), 0x0200000c: ('arm64', 'ARM64_32'), 18: ('ppc32', 'PPC'),
             0x01000012: ('ppc64', 'PPC64')}
MACHO_TYPES = {1: 'OBJECT', 2: 'EXECUTE', 6: 'DYLIB', 7: 'DYLINKER', 8: 'BUNDLE', 10: 'DSYM', 11: 'KEXT'}


def _macho(buf, base):
    magic = buf.read(base, 4)
    e = '<' if magic in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe') else '>'
    is64 = magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf')
    _, cpu, _, ftype, ncmds, _, _ = _unpack(buf, e + 'IIIIIII', base)
    info = BinInfo()
    info.kind = 'Mach-O'
    info.desc = 'Mach-O 64' if is64 else 'Mach-O'
    info.bits = 64 if is64 else 32
    info.endian = e
    info.arch, cname = MACHO_CPU.get(cpu, (None, '%X' % cpu))
    o = base + (32 if is64 else 28)
    text_va = None
    entryoff = None
    symtab = None
    dysym = None
    libs = []
    slot_sects = []   # (addr, size, type, reserved1, reserved2) of stub / pointer sections
    segs = []
    for _ in range(min(ncmds, 8192)):
        cmd, csize = _unpack(buf, e + 'II', o)
        if cmd in (1, 0x19):
            if cmd == 0x19:
                sn, vma, vms, fo, fs, _, _, nsect, _ = _unpack(buf, e + '16sQQQQiiII', o + 8)
                so, ssz = o + 72, 80
            else:
                sn, vma, vms, fo, fs, _, _, nsect, _ = _unpack(buf, e + '16sIIIIiiII', o + 8)
                so, ssz = o + 56, 68
            sname = _cstr(sn)
            if fs:
                info.segments.append((base + fo, fs, vma, vms))
            if sname == '__TEXT':
                text_va = vma - fo
            segs.append((sname, vma, vms, fo, fs))
            for j in range(min(nsect, 1024)):
                if is64:
                    sect, _, addr, ss, sof, _, _, _, fl, r1, r2, _ = _unpack(buf, e + '16s16sQQIIIIIIII', so + j * ssz)
                else:
                    sect, _, addr, ss, sof, _, _, _, fl, r1, r2 = _unpack(buf, e + '16s16sIIIIIIIII', so + j * ssz)
                if (fl & 0xff) in (6, 7, 8):   # non-lazy / lazy symbol pointers, symbol stubs
                    slot_sects.append((addr, ss, fl & 0xff, r1, r2))
                ex = bool(fl & 0x80000000) or bool(fl & 0x400)
                zero = (fl & 0xff) in (1, 0xc, 0x12)
                info.sections.append(Section('%s,%s' % (sname, _cstr(sect)), addr, ss, base + sof,
                                             0 if zero or not sof else ss, ex, 'X' if ex else '-'))
        elif cmd == 0x80000028:
            entryoff, _ = _unpack(buf, e + 'QQ', o + 8)
        elif cmd == 2:
            symtab = _unpack(buf, e + 'IIII', o + 8)
        elif cmd == 0xB:
            dysym = _unpack(buf, e + '18I', o + 8)
        elif cmd in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):   # LC_LOAD_DYLIB and friends
            (noff,) = _unpack(buf, e + 'I', o + 8)
            libs.append(_cstr(buf, o + noff, max(0, min(csize - noff, 1024))))
        if csize < 8:
            break
        o += csize
    if entryoff is not None and text_va is not None:
        info.entry_va = text_va + entryoff
    if symtab:
        symoff, nsyms, stroff, strsize = symtab
        strs = buf.read(base + stroff, min(strsize, 32 << 20))
        fmt = e + ('IBBHQ' if is64 else 'IBBHI')
        ent = struct.calcsize(fmt)
        data = buf.read(base + symoff, min(nsyms, 1 << 21) * ent)
        nl = [struct.unpack_from(fmt, data, k * ent) for k in range(len(data) // ent)]
        for strx, ntype, _, desc, val in nl:
            if (ntype & 0xe0) or strx >= len(strs):
                continue   # debug (stab) entries
            kind = ntype & 0x0e
            if kind == 0x0e and val:
                name = _cstr(strs, strx)
                info.symbols.setdefault(val, name)
                if ntype & 0x01:   # N_EXT: exported
                    info.exports.append((name, val))
        # imports: indirect symbol table entries of the stub / pointer sections
        if dysym:
            indoff, nind = dysym[12], dysym[13]
            ind = buf.read(base + indoff, min(nind, 1 << 21) * 4)
            ind = struct.unpack(e + '%dI' % (len(ind) // 4), ind[:len(ind) // 4 * 4])
            psz = 8 if is64 else 4
            seen = set()
            for addr, ss, typ, r1, r2 in sorted(slot_sects, key=lambda t: t[2] != 8):   # stubs first
                step = r2 if typ == 8 else psz
                if not step:
                    continue
                for i in range(ss // step):
                    if r1 + i >= len(ind):
                        break
                    si = ind[r1 + i]
                    if si & 0xC0000000 or si >= len(nl):   # INDIRECT_SYMBOL_LOCAL / ABS
                        continue
                    strx, ntype, _, desc, _ = nl[si]
                    if strx >= len(strs):
                        continue
                    name = _cstr(strs, strx)
                    ordn = (desc >> 8) & 0xff
                    lib = libs[ordn - 1] if 0 < ordn <= len(libs) else {0: 'self', 0xfe: 'dynamic', 0xff: 'main'}.get(ordn, '?')
                    lib = os.path.basename(lib)
                    slot = addr + i * step
                    info.symbols[slot] = name
                    if name not in seen:   # one entry per function: the stub calls go to
                        info.imports.append((lib, name, slot))
                        seen.add(name)

    H = info.header
    H.append(('%s  %s   Type: %s' % (info.desc, cname, MACHO_TYPES.get(ftype, str(ftype))), None))
    eoff = info.va2off(info.entry_va) if info.entry_va is not None else None
    H.append(('Entry point: .%08X   (file offset %s)' % (info.entry_va or 0, '%08X' % eoff if eoff is not None else '-'),
              (eoff, 'decode') if eoff is not None else None))
    if segs:
        H.append(('', None))
        H.append(('Segments:  Name              VirtAddr          VirtSize  Offset    Size', None))
        for sname, vma, vms, fo, fs in segs:
            H.append(('           %-16s  %016X  %08X  %08X  %08X' % (sname, vma, vms, base + fo, fs),
                      (base + fo, 'hex') if fs else None))
    _section_lines(info)
    if libs:
        H.append(('', None))
        H.append(('Libraries (%d):' % len(libs), None))
        for l in libs:
            H.append(('  ' + l, None))
    _import_lines(info)
    _export_lines(info)
    return info


def _import_lines(info):
    if not info.imports:
        return
    H = info.header
    H.append(('', None))
    H.append(('Imports (%d):' % len(info.imports), None))
    for lib, fn, slot in info.imports:
        so = info.va2off(slot)
        H.append(('  .%08X  %-24s %s' % (slot, lib[:24], fn), (so, 'hex') if so is not None else None))


def _fat(buf, slice_sel=None):
    """slice_sel: None = host architecture, an index, or a cpu name like 'x86_64' / 'arm64'."""
    magic, n = _unpack(buf, '>II', 0)
    if n == 0 or n > 32:   # 0xCAFEBABE is also a Java class file
        return None
    is64 = magic == 0xcafebabf
    slices = []
    for i in range(n):
        if is64:
            cpu, sub, off, size, _, _ = _unpack(buf, '>iiQQII', 8 + i * 32)
        else:
            cpu, sub, off, size, _ = _unpack(buf, '>iiIII', 8 + i * 20)
        slices.append((cpu & 0xffffffff, off, size, sub & 0xff))
    names = [('arm64e' if c == 0x0100000c and st == 2 else MACHO_CPU.get(c, ('', '%X' % c))[1])
             for c, _, _, st in slices]
    slices = [s[:3] for s in slices]
    idx = None
    if isinstance(slice_sel, int) and 0 <= slice_sel < n:
        idx = slice_sel
    elif isinstance(slice_sel, str):
        sel = slice_sel.lower().replace('-', '_')
        if sel.isdigit() and int(sel) < n:
            idx = int(sel)
        else:
            alias = {'x64': 'x86_64', 'amd64': 'x86_64', 'aarch64': 'arm64', 'x86': 'i386'}
            want = {sel, alias.get(sel, sel)}
            idx = next((k for k, nm in enumerate(names) if nm.lower() in want), None)
            if idx is None and 'arm64' in want:      # arm64 also selects an arm64e slice
                idx = next((k for k, nm in enumerate(names) if nm.lower().startswith('arm64')), None)
    warn = None
    if idx is None and slice_sel is not None:
        warn = 'No slice "%s" (have: %s), opened the default one' % (slice_sel, ', '.join(
            '%d %s' % (k, nm) for k, nm in enumerate(names)))
    if idx is None:
        host = {'arm64': 0x0100000c, 'aarch64': 0x0100000c, 'x86_64': 0x01000007, 'amd64': 0x01000007}.get(
            platform.machine().lower())
        idx = next((k for k, s in enumerate(slices) if s[0] == host), 0)
    cpu, off, size = slices[idx]
    info = _macho(buf, off)
    info.desc = 'Fat/' + info.desc
    info.slices = [(names[k], o, sz) for k, (_, o, sz) in enumerate(slices)]
    info.slice_idx = idx
    info.slice_warning = warn
    lines = [('Universal binary, %d slices - Enter on a slice switches to it:' % n, None)]
    for k, (c, o, sz) in enumerate(slices):
        lines.append(('  %s %d %-10s offset %08X  size %08X' % ('*' if k == idx else ' ', k, names[k], o, sz),
                      ('slice', k)))
    info.header = lines + [('', None)] + info.header
    return info