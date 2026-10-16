"""Fast code-reference search.

Disassembling every instruction of a big binary in Python takes tens of seconds
(libclang: ~15M instructions). Instead, look only at byte patterns that can encode
a reference to the target and confirm each candidate:

  x86     call/jmp rel32 (E8/E9), jcc rel32 (0F 8x), short jumps (EB, 7x, E0-E3),
          [rip+disp32] (x86-64), absolute 32/64-bit addresses (operands, immediates)
  arm64   B / BL imm26, B.cond / CBZ / CBNZ / LDR-literal imm19, TBZ / TBNZ imm14,
          ADR imm21, ADRP + ADD / LDR / STR page offset pairs (GOT and IAT loads)

Other architectures fall back to the linear sweep.
"""
import re
import struct

FAST_ARCHS = ('x86-32', 'x86-64', 'arm64')
TICK = 0x8000            # call the progress callback every TICK regex matches

_REL32 = re.compile(rb'[\xe8\xe9]|\x0f[\x80-\x8f]', re.S)
_REL8 = re.compile(rb'[\xeb\x70-\x7f\xe0-\xe3]', re.S)
_RIPMODRM = re.compile(rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', re.S)
# top byte of the arm64 instructions that carry a pc-relative offset
_A64 = re.compile(rb'[\x14-\x17\x94-\x97\x54\x34\x35\xb4\xb5\x36\x37\xb6\xb7\x10\x30\x50\x70'
                  rb'\x18\x58\x98\x1c\x5c\x9c\xd8\x90\xb0\xd0\xf0]', re.S)
M64 = 0xFFFFFFFFFFFFFFFF


class Stop(Exception):
    pass


def _sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def _s32(b, p):
    return struct.unpack_from('<i', b, p)[0]


def _a64_target(w, pc):
    """pc-relative target of a single arm64 instruction, or None."""
    if (w & 0x7C000000) == 0x14000000:                       # B / BL
        return pc + _sx(w & 0x3FFFFFF, 26) * 4
    if (w & 0xFF000010) == 0x54000000:                       # B.cond
        return pc + _sx((w >> 5) & 0x7FFFF, 19) * 4
    if (w & 0x7E000000) == 0x34000000:                       # CBZ / CBNZ
        return pc + _sx((w >> 5) & 0x7FFFF, 19) * 4
    if (w & 0x7E000000) == 0x36000000:                       # TBZ / TBNZ
        return pc + _sx((w >> 5) & 0x3FFF, 14) * 4
    if (w & 0x3B000000) == 0x18000000:                       # LDR (literal)
        return pc + _sx((w >> 5) & 0x7FFFF, 19) * 4
    if (w & 0x9F000000) == 0x10000000:                       # ADR
        return pc + _sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21)
    return None


def _a64_pageoff(w, reg):
    """Low 12 bits added by ADD / LDR / STR (unsigned offset) using base register reg, or None."""
    if (w >> 5) & 31 != reg:
        return None
    if (w & 0x7F800000) == 0x11000000 and not (w >> 22) & 1:    # ADD (immediate, shift 0)
        return (w >> 10) & 0xFFF
    if (w & 0x3B000000) == 0x39000000 and (w >> 22) & 3 in (0, 1, 2):   # LDR/STR unsigned imm
        size = w >> 30
        if (w >> 26) & 1:                                    # SIMD&FP registers
            size |= ((w >> 23) & 1) << 2
        return ((w >> 10) & 0xFFF) << size
    return None


def candidates(data, va, arch, targets, tick=None):
    """Yield (position, needs_verify) of possible references inside data (mapped at va)."""
    n = len(data)
    tset = set(targets)
    k = 0
    if arch == 'arm64':
        pages = {t & ~0xFFF for t in tset}
        for m in _A64.finditer(data):
            k += 1
            if tick and k % TICK == 0 and tick(m.start()):
                raise Stop
            p = m.start() - 3
            if p < 0 or p & 3:
                continue
            w = struct.unpack_from('<I', data, p)[0]
            pc = va + p
            if (w & 0x9F000000) == 0x90000000:                 # ADRP: page, then ADD/LDR in the next insns
                imm = _sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21)
                page = ((pc & ~0xFFF) + (imm << 12)) & M64
                if page not in pages:
                    continue
                rd = w & 31
                for q in range(p + 4, min(n - 3, p + 20), 4):
                    off = _a64_pageoff(struct.unpack_from('<I', data, q)[0], rd)
                    if off is not None:
                        if (page + off) & M64 in tset:
                            yield q, False
                        break
                continue
            t = _a64_target(w, pc)
            if t is not None and t & M64 in tset:
                yield p, False
        return
    mask = M64 if arch == 'x86-64' else 0xFFFFFFFF
    for m in _REL32.finditer(data):
        k += 1
        if tick and k % TICK == 0 and tick(m.start()):
            raise Stop
        p = m.start()
        q = p + (1 if data[p] in (0xE8, 0xE9) else 2)
        if q + 4 <= n and (va + q + 4 + _s32(data, q)) & mask in tset:
            yield p, 'at32'          # 4 offset bytes hitting the exact target: practically never by chance
    for m in _REL8.finditer(data):
        k += 1
        if tick and k % TICK == 0 and tick(m.start()):
            raise Stop
        p = m.start()
        if p + 2 <= n:
            r = data[p + 1]
            if (va + p + 2 + (r - 256 if r > 127 else r)) & mask in tset:
                yield p, 'at'
    if arch == 'x86-64':
        for m in _RIPMODRM.finditer(data):
            k += 1
            if tick and k % TICK == 0 and tick(m.start()):
                raise Stop
            p = m.start()
            if p + 5 > n:
                continue
            d = _s32(data, p + 1)
            for imm in (0, 1, 2, 4):
                if (va + p + 5 + imm + d) & mask in tset:
                    yield p, True
                    break
    # absolute addresses: 32-bit (operands, immediates, non-PIE x86-64) and 64-bit (movabs)
    for t in tset:
        pats = []
        if t <= 0xFFFFFFFF:
            pats.append(struct.pack('<I', t))
        if arch == 'x86-64':
            pats.append(struct.pack('<Q', t & M64))
        for pat in pats:
            i = data.find(pat)
            while i >= 0:
                yield i, True
                i = data.find(pat, i + 1)


_HEX = re.compile(r'0x([0-9a-f]+)')
_BRACKET = re.compile(r'\[([^\]]*)\]')
_REG = re.compile(r'[a-z][a-z0-9]*$')


def _keep_absolute(m):
    """Keep a memory operand only if it has no base register (pure address or scaled-index table)."""
    terms = [t.strip() for t in re.split(r'[+-]', m.group(1)) if t.strip()]
    return '' if any(_REG.match(t) for t in terms) else m.group(0)


def _refs(ins, tset, x64=False):
    if ins.kind == 'bad':
        return False
    if ins.target in tset or ins.mem in tset or any(v in tset for v in ins.imms):
        return True
    # any other address in the operands, e.g. a jump table jmp [edx*4 + 0x409154] or an array
    # movsx eax, byte ptr [ecx + 0x40e278]. On x86-64 code addresses data rip-relatively, so there
    # a displacement next to a base register ([rbx + 0x84], [rip + X]) is an offset, not an address.
    ops = _BRACKET.sub(_keep_absolute, ins.ops) if x64 else ins.ops
    return any(int(h, 16) in tset for h in _HEX.findall(ops))


_SYNC = (32, 28, 24, 20, 16, 12)


_WEIRD = {'db', 'in', 'out', 'insb', 'insw', 'insd', 'outsb', 'outsw', 'outsd', 'hlt', 'les', 'lds',
          'bound', 'arpl', 'aaa', 'aas', 'daa', 'das', 'aam', 'aad', 'into', 'iretd', 'iret', 'retf', 'ljmp',
          'lcall', 'sahf', 'lahf', 'salc', 'xlatb', 'cmc', 'std', 'cli', 'sti', 'wait', 'enter', 'icebp',
          'int1', 'sldt', 'str', 'lldt', 'ltr', 'verr', 'verw', 'lmsw', 'clts', 'invd', 'wbinvd', 'rdpmc'}


def _weird(ins):
    m = ins.mnem
    if ins.kind == 'bad' or m in _WEIRD:
        return True
    if m in ('pop', 'push') and ins.ops in ('ss', 'ds', 'es', 'cs'):
        return True
    return False


def _path(dis, data, va, start, until):
    """Instructions decoded from start up to (not including) offset until: list of (offset, ins)."""
    out = []
    for ins in dis.decode(data[start:until + 16], va + start, 64):
        o = start + ins.off
        if o >= until:
            break
        out.append((o, ins))
    return out


def _starts_at(dis, data, va, p):
    """Does a real instruction begin at p?

    Decode from several points well before p; x86 decoding re-synchronises within a few
    instructions, so if any of them lands exactly on p it is an instruction start. If all of
    them see p inside another instruction, compare the two readings of the bytes up to where
    they meet again and keep the one with fewer junk instructions (pop ss, in/out, invalid ...):
    "ff ff 0c | 75 17" is "... jne" not "or al, 75h; pop ss".
    """
    starts = [p - b for b in _SYNC if p - b >= 0]
    if not starts:
        return True
    cover = None
    for start in starts:
        for ins in dis.decode(data[start:p + 16], va + start, 64):
            o = start + ins.off
            if o == p:
                return True
            if o > p:
                break
            if p < o + ins.size:
                cover = (o, start)
                break
    if cover is None:
        return False
    # reading B: from p onwards; reading A: from the covering instruction onwards; find where they meet
    b = _path(dis, data, va, p, p + 48)
    b_starts = {o for o, _ in b}
    a = _path(dis, data, va, cover[0], p + 48)
    meet = next((o for o, _ in a if o > p and o in b_starts), p + 48)   # no meeting point: whole window
    wa = sum(1 for o, ins in a if o < meet and _weird(ins))
    wb = sum(1 for o, ins in b if o < meet and _weird(ins))
    return wb < wa


def _rip_disp(dis, data, va, s, ins, p):
    """x86-64: are the 4 bytes at p really the displacement of a [rip + X] instruction that starts
    1..4 bytes before s and ends where ins ends? ("48 8d 3d" + disp misread as "3d imm32" = cmp eax)"""
    if dis.arch != 'x86-64' or 'rip' in ins.ops:   # a real rip-relative hit is never "inside" another one
        return False
    end = s + ins.size
    for k in range(1, 5):
        if s - k < 0:
            break
        lst = dis.decode(data[s - k:s - k + 16], va + s - k, 1)
        if lst and lst[0].kind != 'bad' and s - k + lst[0].size == end and 'rip' in lst[0].ops:
            return True
    return False


_PREFIXES = {0x66, 0x67, 0xF2, 0xF3, 0xF0, 0x2E, 0x3E, 0x26, 0x36, 0x64, 0x65}


def _prefix_only(data, a, b, rex):
    """Are the bytes in [a, b) a plausible prefix run: legacy prefixes, then at most one REX
    (x86-64) right before the opcode? Compilers never emit two REX bytes, and a REX is only
    used if it comes last, so "4b 40 48 3b" is the tail of the previous instruction + "48 3b"."""
    seq = data[a:b]
    if not 0 < len(seq) <= 4:
        return False
    isrex = [rex and 0x40 <= c <= 0x4F for c in seq]
    if sum(isrex) > 1 or (any(isrex) and not isrex[-1]):
        return False
    if rex and b < len(data) and 0x40 <= data[b] <= 0x4F:
        return False                     # the instruction at b already has its own REX
    return all(r or c in _PREFIXES for c, r in zip(seq, isrex))


def _covering(dis, data, va, p, tset):
    """Start of the instruction that contains byte p and references a target, or None.

    Decoding from a little earlier lands on real instruction boundaries; try a few starting points."""
    votes = {}
    for back in (32, 29, 26, 23, 20, 17):
        start = max(0, p - back)
        for ins in dis.decode(data[start:p + 16], va + start, 64):
            s = start + ins.off
            if s > p:
                break
            if p < s + ins.size:
                if _refs(ins, tset, dis.arch == 'x86-64') and not _rip_disp(dis, data, va, s, ins, p):
                    votes[s] = votes.get(s, 0) + 1
                break
    if not votes:
        return None
    # the start most decodings agree on ...
    best = max(votes, key=lambda s: (votes[s], -s))
    # ... but if some decoding saw the same instruction with its prefix bytes (48 8d 05 .. vs 8d 05 ..),
    # the prefixed form is the real one
    for s in sorted(votes):
        if s < best and _prefix_only(data, s, best, dis.arch == 'x86-64'):
            return s
    return best


def find_refs(dis, data, va, arch, targets, progress=None):
    """Sorted positions (relative to data) of instructions referencing any target.

    progress(pos, nfound) is called now and then; returning True stops the search.
    """
    tset = set(targets)
    found = set()
    tick = (lambda p: progress(p, len(found))) if progress else None
    try:
        for p, need_verify in candidates(data, va, arch, tset, tick):
            if not need_verify:
                found.add(p)
                continue
            if need_verify in ('at', 'at32'):    # branch candidate starting at p
                lst = dis.decode(data[p:p + 16], va + p, 1)
                if lst and lst[0].kind != 'bad' and lst[0].target in tset and \
                        (need_verify == 'at32' or _starts_at(dis, data, va, p)):   # rel8: check the boundary
                    found.add(p)
                continue
            s = _covering(dis, data, va, p, tset)
            if s is not None:
                found.add(s)
    except Stop:
        pass
    return sorted(found)
