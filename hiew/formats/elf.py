"""ELF 32/64, little and big endian: segments, sections, symbols, GOT names, imports, exports."""
import struct

from .base import BinInfo, Section, _cstr, _export_lines, _import_lines, _section_lines, _unpack

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
