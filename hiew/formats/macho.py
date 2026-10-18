"""Mach-O 32/64 and universal (fat) binaries: segments, sections, symbols, imports via the
indirect symbol table, exports, libraries; slice selection for fat files."""
import os
import platform
import struct

from .base import BinInfo, Section, _cstr, _export_lines, _import_lines, _section_lines, _unpack

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
