"""Disassembler wrapper around capstone (optional) and assembler around keystone (optional)."""
import re

try:
    import capstone as _cs
    HAVE_CS = True
except Exception:  # not installed or broken native lib
    _cs = None
    HAVE_CS = False

import ctypes
import ctypes.util
import os
import sys


def _load_keystone():
    """Load libkeystone directly (the pip package often ships without its native library,
    and its loader does not look in Homebrew's /opt/homebrew/lib)."""
    names = ('keystone.dll',) if sys.platform.startswith('win') else \
        ('libkeystone.dylib', 'libkeystone.0.dylib') if sys.platform == 'darwin' else ('libkeystone.so', 'libkeystone.so.0')
    dirs = [os.environ.get('HIEW_KEYSTONE', '')]
    try:
        import importlib.util
        spec = importlib.util.find_spec('keystone')
        if spec and spec.submodule_search_locations:
            dirs += list(spec.submodule_search_locations)
    except Exception:
        pass
    dirs += [os.path.join(sys.prefix, 'lib'), '/opt/homebrew/lib', '/usr/local/lib', '/usr/lib',
             '/usr/lib/x86_64-linux-gnu', '/usr/lib/aarch64-linux-gnu', '/usr/lib64']
    cands = [d if d.endswith(names) else os.path.join(d, n) for d in dirs if d for n in names]
    found = ctypes.util.find_library('keystone')
    if found:
        cands.append(found)
    for c in cands:
        if os.path.isabs(c) and not os.path.exists(c):
            continue
        try:
            lib = ctypes.CDLL(c)
            lib.ks_open.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
            lib.ks_open.restype = ctypes.c_int
            lib.ks_asm.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64,
                                   ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
                                   ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
            lib.ks_asm.restype = ctypes.c_int
            lib.ks_free.argtypes = [ctypes.c_void_p]
            lib.ks_close.argtypes = [ctypes.c_void_p]
            lib.ks_errno.argtypes = [ctypes.c_void_p]
            lib.ks_errno.restype = ctypes.c_int
            lib.ks_strerror.argtypes = [ctypes.c_int]
            lib.ks_strerror.restype = ctypes.c_char_p
            return lib, c
        except (OSError, AttributeError):
            continue
    return None, None


_ks, KS_PATH = _load_keystone()
HAVE_KS = _ks is not None
if sys.platform == 'darwin':
    KS_HINT = 'brew install keystone'
elif sys.platform.startswith('win'):
    KS_HINT = 'pip install keystone-engine'
else:
    KS_HINT = 'apt install libkeystone0 (or build keystone-engine)'

# keystone constants
_KS_ARCH = {'arm': 1, 'arm64': 2, 'mips': 3, 'x86': 4, 'ppc': 5}
_KS_MODE = {'x86-16': 1 << 1, 'x86-32': 1 << 2, 'x86-64': 1 << 3, 'arm': 1 << 0, 'thumb': 1 << 4,
            'arm64': 0, 'mips32': 1 << 2, 'mips64': 1 << 3, 'ppc32': 1 << 2, 'ppc64': 1 << 3}
_KS_BIG = 1 << 30

ARCHS = ['x86-16', 'x86-32', 'x86-64', 'arm', 'thumb', 'arm64', 'mips32', 'mips64',
         'ppc32', 'ppc64', 'riscv32', 'riscv64']
SHORT = {'x86-16': 'a16', 'x86-32': 'a32', 'x86-64': 'a64', 'arm': 'arm', 'thumb': 'thumb',
         'arm64': 'arm64', 'mips32': 'mips', 'mips64': 'mips64', 'ppc32': 'ppc', 'ppc64': 'ppc64',
         'riscv32': 'rv32', 'riscv64': 'rv64'}
# Ctrl+F1 in decode mode: bitness toggle inside one family
BITS_CYCLE = {'x86-16': 'x86-32', 'x86-32': 'x86-64', 'x86-64': 'x86-16', 'arm': 'thumb', 'thumb': 'arm',
              'mips32': 'mips64', 'mips64': 'mips32', 'ppc32': 'ppc64', 'ppc64': 'ppc32',
              'riscv32': 'riscv64', 'riscv64': 'riscv32'}

RIP_RE = re.compile(r'\[rip ([+-]) (0x[0-9a-f]+|\d+)\]')
ABS_RE = re.compile(r'\[(0x[0-9a-f]+)\]')
HEX_RE = re.compile(r'0x([0-9a-f]+)')
TAIL_IMM_RE = re.compile(r'#?(-?0x[0-9a-f]+|-?\d+)\s*$')
BRACKETS_RE = re.compile(r'\[[^\]]*\]')

ARM_CONDS = ('eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al')


def _cs_mode(arch, big):
    c = _cs
    if arch.startswith('x86'):
        a, m = c.CS_ARCH_X86, {'x86-16': c.CS_MODE_16, 'x86-32': c.CS_MODE_32, 'x86-64': c.CS_MODE_64}[arch]
    elif arch == 'arm':
        a, m = c.CS_ARCH_ARM, c.CS_MODE_ARM
    elif arch == 'thumb':
        a, m = c.CS_ARCH_ARM, c.CS_MODE_THUMB
    elif arch == 'arm64':
        a, m = getattr(c, 'CS_ARCH_ARM64', None) or getattr(c, 'CS_ARCH_AARCH64'), c.CS_MODE_ARM
    elif arch.startswith('mips'):
        a, m = c.CS_ARCH_MIPS, c.CS_MODE_MIPS64 if arch == 'mips64' else c.CS_MODE_MIPS32
    elif arch.startswith('ppc'):
        a, m = c.CS_ARCH_PPC, c.CS_MODE_64 if arch == 'ppc64' else c.CS_MODE_32
    elif arch.startswith('riscv'):
        a = c.CS_ARCH_RISCV
        m = (c.CS_MODE_RISCV64 if arch == 'riscv64' else c.CS_MODE_RISCV32) | getattr(c, 'CS_MODE_RISCVC', 0)
    else:
        raise ValueError('unknown arch ' + arch)
    if big:
        m |= c.CS_MODE_BIG_ENDIAN
    return a, m


class Insn:
    __slots__ = ('off', 'addr', 'size', 'raw', 'mnem', 'ops', 'kind', 'target', 'mem', 'imms')

    def __init__(self, off, addr, raw, mnem, ops):
        self.off = off
        self.addr = addr
        self.size = len(raw)
        self.raw = raw
        self.mnem = mnem
        self.ops = ops
        self.kind = None      # 'jmp' | 'call' | 'ret' | 'int' | 'bad' | None
        self.target = None    # branch target VA
        self.mem = None       # referenced memory VA (x86)
        self.imms = ()        # big immediates (possible pointers)


class Disassembler:
    def __init__(self, arch, big=False):
        self.arch = arch
        self.big = big
        self.cs = None
        self.lite = None
        self.error = None
        self.x86 = arch.startswith('x86')
        self.align = 1 if self.x86 else (2 if arch in ('thumb', 'riscv32', 'riscv64') else 4)
        self.mask = (1 << 64) - 1 if arch in ('x86-64', 'arm64', 'mips64', 'ppc64', 'riscv64') else 0xFFFFFFFF
        if arch == 'x86-16':
            self.mask = 0xFFFF
        if not HAVE_CS:
            self.error = 'capstone not installed: pip install capstone'
            return
        try:
            a, m = _cs_mode(arch, big)
            self.cs = _cs.Cs(a, m)
            self.cs.detail = True
            self.lite = _cs.Cs(a, m)
        except Exception as e:
            self.cs = None
            self.error = 'capstone: %s' % e

    def decode(self, data, addr, maxn):
        """Decode up to maxn instructions; undecodable bytes become 'db' lines."""
        out = []
        pos = 0
        n = len(data)
        while pos < n and len(out) < maxn:
            if self.cs is not None:
                for ins in self.cs.disasm(data[pos:], addr + pos):
                    out.append(self._mk(ins, pos))
                    pos += ins.size
                    if len(out) >= maxn:
                        break
                if len(out) >= maxn or pos >= n:
                    break
            step = min(self.align, n - pos)
            out.append(self._db(data[pos:pos + step], addr + pos, pos))
            pos += step
        return out

    def _db(self, raw, addr, pos):
        i = Insn(pos, addr, bytes(raw), 'db', ', '.join('%02Xh' % b for b in raw))
        i.kind = 'bad'
        return i

    def _mk(self, ins, pos):
        i = Insn(pos, ins.address, bytes(ins.bytes), ins.mnemonic, ins.op_str)
        kind = None
        try:
            g = ins.groups
            if _cs.CS_GRP_CALL in g:
                kind = 'call'
            elif _cs.CS_GRP_RET in g or _cs.CS_GRP_IRET in g:
                kind = 'ret'
            elif _cs.CS_GRP_JUMP in g:
                kind = 'jmp'
            elif _cs.CS_GRP_INT in g:
                kind = 'int'
        except Exception:
            pass
        if kind is None:
            kind = self._heur(i.mnem, i.ops)
        i.kind = kind
        ops = i.ops
        if kind in ('jmp', 'call'):
            tgt = None
            try:
                for op in ins.operands:
                    if op.type == _cs.CS_OP_IMM:
                        tgt = op.imm
            except Exception:
                pass
            if tgt is None and '[' not in ops:
                m = TAIL_IMM_RE.search(ops)
                if m and not self.x86 or (m and ops.startswith('0x')):
                    tgt = int(m.group(1), 0)
            if tgt is not None and not self.arch.startswith('riscv'):
                i.target = tgt & self.mask
        if self.x86:
            m = RIP_RE.search(ops)
            if m:
                d = int(m.group(2), 0)
                i.mem = (i.addr + i.size + (d if m.group(1) == '+' else -d)) & self.mask
            else:
                m = ABS_RE.search(ops)
                if m:
                    i.mem = int(m.group(1), 16)
        if i.target is None:
            rest = BRACKETS_RE.sub('', ops)
            vals = [int(h, 16) for h in HEX_RE.findall(rest)]
            i.imms = tuple(v for v in vals if v >= 0x1000)
        return i

    def _heur(self, m, ops):
        if self.x86:
            if m.startswith('call'):
                return 'call'
            if m.startswith('ret') or m in ('iret', 'iretd', 'iretq'):
                return 'ret'
            if m.startswith('j') or m.startswith('loop'):
                return 'jmp'
            if m.startswith('int'):
                return 'int'
            return None
        base = m.split('.')[0]
        if base in ('bl', 'blx', 'blr', 'jal', 'jalr', 'bctrl', 'bla', 'blraa', 'blrab'):
            return 'call'
        if base in ('ret', 'eret', 'retaa', 'retab', 'blr') or (base in ('bx', 'jr') and ops in ('lr', 'ra', '$ra')):
            return 'ret'
        if base in ('b', 'br', 'bx', 'cbz', 'cbnz', 'tbz', 'tbnz', 'j', 'jr', 'beq', 'bne', 'blt', 'bge', 'bltu',
                    'bgeu', 'beqz', 'bnez', 'blez', 'bgez', 'bltz', 'bgtz', 'bc', 'bdnz', 'bdz'):
            return 'jmp'
        if base.startswith('b') and base[1:3] in ARM_CONDS and len(base) <= 4:
            return 'jmp'
        return None

    def sweep(self, data, addr):
        """Fast linear sweep (no detail) yielding (address, size, mnemonic, op_str)."""
        cs = self.lite
        if cs is None:
            return
        n = len(data)
        pos = 0
        W = 0x10000
        while pos < n:
            lim = min(n, pos + W)
            p = pos
            for a, s, m, o in cs.disasm_lite(data[pos:lim + 16], addr + pos):
                yield a, s, m, o
                p = a - addr + s
                if p >= lim:
                    break
            if p < lim:
                p += self.align
            pos = p


_ASM_NUM = re.compile(r'(?<![\w.$])(0x[0-9a-fA-F]+|[0-9][0-9a-fA-F]*[hHtT]?)(?![\w(])')


def hex_numbers(text):
    """Hiew convention: bare numbers are hex; 10t is decimal, 10h / 0x10 hex."""
    def fix(m):
        t = m.group(1)
        if t.lower().startswith('0x'):
            return t
        if t[-1] in 'tT' and t[:-1].isdigit():
            return t[:-1]
        if t[-1] in 'hH':
            return '0x' + t[:-1]
        return '0x' + t
    return _ASM_NUM.sub(fix, text)


def assemble(arch, text, addr, big=False):
    text = hex_numbers(text)
    if not HAVE_KS:
        raise RuntimeError('assembler needs keystone: ' + KS_HINT)
    if arch not in _KS_MODE:
        raise RuntimeError('no assembler for ' + arch)
    fam = 'x86' if arch.startswith('x86') else 'arm' if arch in ('arm', 'thumb') else \
        'mips' if arch.startswith('mips') else 'ppc' if arch.startswith('ppc') else 'arm64'
    mode = _KS_MODE[arch] | (_KS_BIG if big or fam == 'ppc' else 0)
    h = ctypes.c_void_p()
    err = _ks.ks_open(_KS_ARCH[fam], mode, ctypes.byref(h))
    if err:
        raise RuntimeError(_ks.ks_strerror(err).decode())
    try:
        enc = ctypes.POINTER(ctypes.c_ubyte)()
        size = ctypes.c_size_t()
        count = ctypes.c_size_t()
        if _ks.ks_asm(h, text.encode(), addr, ctypes.byref(enc), ctypes.byref(size), ctypes.byref(count)):
            raise RuntimeError(_ks.ks_strerror(_ks.ks_errno(h)).decode())
        data = bytes(enc[:size.value])
        _ks.ks_free(enc)
    finally:
        _ks.ks_close(h)
    if not data:
        raise RuntimeError('cannot assemble')
    return data
