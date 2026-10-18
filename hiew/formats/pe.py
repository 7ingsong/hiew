"""PE / PE32+ (Windows): sections, imports, exports, header lines. .NET assemblies get extra
details from dotnet.py."""
import struct
import time

from .base import BinInfo, Section, _cstr, _export_lines, _section_lines, _unpack
from .dotnet import add_dotnet
from .peres import parse_resources

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
    if len(dd) > 2 and dd[2][0]:                      # resource directory (.rsrc)
        ro = rva_off(dd[2][0])
        if ro is not None:
            try:
                info.pe_resources = parse_resources(buf.read, ro, rva_off)
            except Exception as e:
                H.append(('', None))
                H.append(('Resources could not be read: %s' % e, None))
        if info.pe_resources:
            kinds = {}
            for r in info.pe_resources:
                kinds[r['label']] = kinds.get(r['label'], 0) + 1
            H.append(('', None))
            H.append(('Resources: %d (%s) - F4 opens the list' % (
                len(info.pe_resources), ', '.join('%s %d' % kv for kv in kinds.items())), None))
    if len(dd) > 14 and dd[14][0] and getattr(buf, 'path', None):   # CLR header: .NET assembly
        add_dotnet(info, buf)
    return info
