"""Hiew Alt-/Ctrl-/Shift- commands.

View mode (from HIEW7.HLP):
  Alt-F1 Global   Alt-F2 FilBlk   Alt-F3 CryBlk   Alt-F4 ReLoad   Alt-F6 Strings
  Alt-F7 Direct   Alt-F8 Table    Alt-F10 Leave   Alt-F11 goWHex  Alt-F12 goDHex
  Ctrl-F2 GetBlk  Ctrl-F3 Replace Ctrl-F4 ReRead  Ctrl-F7 / Ctrl-Enter  next match
  Shift-F2 DelBlk Shift-F5 CpyBlk Shift-F6 MovBlk Shift-F7 previous match
  Alt-P  print screen   Alt-=  calculator
Edit mode:
  F3 Undo (restore byte)  F4/F5/F6 bits of byte/word/dword  F7 Crypt  F8 Xor
  F10 Trunc  Ctrl-F7 CrySet  Ctrl-F8 XorSet  Alt-F2 NOPs  Alt-F8 Table  Ctrl-Z undo last change
"""
import ast
import operator
import os
import re

# ------------------------------------------------------------------ keybars per modifier layer

LAYERS = {
    'view': {
        'A': ['Global', 'FilBlk', 'CryBlk', 'ReLoad', '', 'String', 'Direct', 'Table', '', 'Leave', 'WHex', 'DHex'],
        'C': ['', 'GetBlk', 'Replac', 'ReRead', '', '', 'Next', '', '', '', '', ''],
        'S': ['', 'DelBlk', '', '', 'CpyBlk', 'MovBlk', 'Prev', '', '', '', '', ''],
    },
    'edit': {
        'A': ['', 'NOPs', 'CryBlk', '', '', '', '', 'Table', '', '', '', ''],
        'C': ['', 'GetBlk', '', '', '', '', 'CrySet', 'XorSet', '', '', '', ''],
        'S': ['', '', '', '', 'CpyBlk', 'MovBlk', '', '', '', '', '', ''],
    },
}
EDIT_KEYBAR = ['Help', 'Asm', 'Undo', 'Byte', 'Word', 'Dword', 'Crypt', 'Xor', 'Update', 'Trunc', '', '']
LAYER_NAMES = {'A': 'Alt', 'C': 'Ctrl', 'S': 'Shift'}
LAYER_NEXT = {None: 'A', 'A': 'C', 'C': 'S', 'S': None}

SEL_KEYS = ('S-LEFT', 'S-RIGHT', 'S-UP', 'S-DOWN', 'S-PGUP', 'S-PGDN', 'S-HOME', 'S-END')

NOPS = {'x86-16': b'\x90', 'x86-32': b'\x90', 'x86-64': b'\x90', 'arm64': b'\x1f\x20\x03\xd5',
        'arm': b'\x00\xf0\x20\xe3', 'thumb': b'\x00\xbf', 'mips32': b'\x00\x00\x00\x00',
        'mips64': b'\x00\x00\x00\x00', 'ppc32': b'\x00\x00\x00\x60', 'ppc64': b'\x00\x00\x00\x60',
        'riscv32': b'\x13\x00\x00\x00', 'riscv64': b'\x13\x00\x00\x00'}

# ------------------------------------------------------------------ crypt mini-language

_SUB = {}
for _r in 'abcd':
    _SUB[_r + 'l'] = ('r%sx' % _r, 0, 8)
    _SUB[_r + 'h'] = ('r%sx' % _r, 8, 8)
    _SUB[_r + 'x'] = ('r%sx' % _r, 0, 16)
    _SUB['e%sx' % _r] = ('r%sx' % _r, 0, 32)
    _SUB['r%sx' % _r] = ('r%sx' % _r, 0, 64)
for _r in ('si', 'di', 'bp'):
    _SUB[_r] = ('r' + _r, 0, 16)
    _SUB['e' + _r] = ('r' + _r, 0, 32)
    _SUB['r' + _r] = ('r' + _r, 0, 64)
_OPS2 = ('mov', 'xor', 'add', 'sub', 'and', 'or', 'rol', 'ror', 'shl', 'shr', 'sal')
_OPS1 = ('not', 'neg', 'inc', 'dec')


def _num(s):
    s = s.strip().lower()
    if s.endswith('h'):
        return int(s[:-1], 16)
    return int(s, 0)


class Crypt:
    """Hiew crypt routine: a tiny x86 subset run once per data unit.

    At the start of every iteration AL/AX/EAX/RAX holds the data under the pointer;
    at the end its value is written back and the pointer advances. Other registers
    (rbx, rcx, rdx, rsi, rdi, rbp) keep their values, CL starts at 0:
        mov al, cl ; add cl, 1      -> fills the block with 00 01 02 03 ...
    The unit size is set explicitly (F2 in the dialog) or, if not given, by the
    widest a-register used.
    """

    def __init__(self, text, width=None):
        self.text = text
        self.prog = []
        guess = 0
        for stmt in re.split(r'[;\n]', text):
            stmt = re.sub(r'^\s*\d+[.:)]?\s+', '', stmt).strip().lower()   # allow "1 mov al, cl"
            if not stmt:
                continue
            m = re.match(r'([a-z]+)\s*(.*)$', stmt)
            if not m:
                raise ValueError('bad command: ' + stmt)
            op, rest = m.group(1), m.group(2)
            args = [a.strip() for a in rest.split(',')] if rest.strip() else []
            if not (op in _OPS2 and len(args) == 2 or op in _OPS1 and len(args) == 1):
                raise ValueError('bad command: ' + stmt)
            if args[0] not in _SUB:
                raise ValueError('destination must be a register: ' + stmt)
            for a in args:
                if a in _SUB:
                    if _SUB[a][0] == 'rax':
                        guess = max(guess, _SUB[a][2] // 8)
                else:
                    try:
                        _num(a)
                    except ValueError:
                        raise ValueError('bad operand: ' + a)
            self.prog.append((op, args))
        if not self.prog:
            raise ValueError('empty routine')
        self.width = width or guess or 1
        self.reset()

    def reset(self):
        self.regs = dict.fromkeys(('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp'), 0)

    def _get(self, a):
        if a in _SUB:
            r, sh, bits = _SUB[a]
            return (self.regs[r] >> sh) & ((1 << bits) - 1), bits
        return _num(a), 64

    def _set(self, a, v):
        r, sh, bits = _SUB[a]
        mask = ((1 << bits) - 1) << sh
        self.regs[r] = (self.regs[r] & ~mask) | ((v << sh) & mask)

    def run(self, data):
        w = self.width
        unit = (1 << (8 * w)) - 1
        self.regs['rax'] = (self.regs['rax'] & ~unit) | int.from_bytes(data, 'little')
        for op, args in self.prog:
            dv, bits = self._get(args[0])
            m = (1 << bits) - 1
            if op in _OPS2:
                sv = self._get(args[1])[0]
                if op == 'mov':
                    r = sv
                elif op == 'xor':
                    r = dv ^ sv
                elif op == 'add':
                    r = dv + sv
                elif op == 'sub':
                    r = dv - sv
                elif op == 'and':
                    r = dv & sv
                elif op == 'or':
                    r = dv | sv
                elif op in ('shl', 'sal'):
                    r = dv << (sv % bits)
                elif op == 'shr':
                    r = dv >> (sv % bits)
                else:
                    s = sv % bits
                    r = (dv << s) | (dv >> (bits - s)) if op == 'rol' else (dv >> s) | (dv << (bits - s))
            else:
                r = {'not': ~dv, 'neg': -dv, 'inc': dv + 1, 'dec': dv - 1}[op]
            self._set(args[0], r & m)
        return (self.regs['rax'] & unit).to_bytes(w, 'little')


# ------------------------------------------------------------------ calculator

_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.FloorDiv: operator.floordiv,
        ast.Div: operator.floordiv, ast.Mod: operator.mod, ast.BitAnd: operator.and_, ast.BitOr: operator.or_,
        ast.BitXor: operator.xor, ast.LShift: operator.lshift, ast.RShift: operator.rshift, ast.Pow: operator.pow}
_UN = {ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Invert: operator.invert}


def calc_eval(expr, names):
    s = expr.strip()
    if not s:
        raise ValueError('empty')
    s = re.sub(r'\b([0-9][0-9a-fA-F]*)[hH]\b', r'0x\1', s)
    s = s.replace('$', '(cur)')

    def ev(n):
        if isinstance(n, ast.Expression):
            return ev(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.Num):  # Python < 3.8
            return int(n.n)
        if isinstance(n, ast.BinOp) and type(n.op) in _BIN:
            a, b = ev(n.left), ev(n.right)
            if isinstance(n.op, ast.Pow) and b > 256:
                raise ValueError('too big')
            if isinstance(n.op, ast.LShift) and b > 4096:
                raise ValueError('too big')
            return _BIN[type(n.op)](a, b)
        if isinstance(n, ast.UnaryOp) and type(n.op) in _UN:
            return _UN[type(n.op)](ev(n.operand))
        if isinstance(n, ast.Name) and n.id in names:
            return names[n.id]
        raise ValueError('bad expression')
    try:
        return ev(ast.parse(s, mode='eval'))
    except ZeroDivisionError:
        raise ValueError('division by zero')
    except SyntaxError:
        raise ValueError('syntax error')


def _nb(n):
    from .app import nbytes
    return nbytes(n)


# ------------------------------------------------------------------ mixin

class ExtraMixin:
    kb_layer = None
    search_back = False
    crypt = None
    str_min = 5
    calc_expr = ''
    repl_text = ''
    prn_name = 'hiew.prn'

    # ---- dispatch

    def apply_layer(self, k):
        """F11 = sticky Alt/Ctrl/Shift for the next function key (for terminals that don't send them)."""
        if k == 'F11':
            self.kb_layer = LAYER_NEXT[self.kb_layer]
            if self.kb_layer:
                self.set_msg('%s- : press a function key' % LAYER_NAMES[self.kb_layer])
            return None
        layer = self.kb_layer
        self.kb_layer = None
        if layer and (re.match(r'^F\d+$', k) or (k == 'ENTER' and layer == 'C')):
            return layer + '-' + k
        return k

    def keybar_labels(self):
        layer = self.kb_layer or self.held_layer
        if layer:
            return list(LAYERS['edit' if self.edit else 'view'][layer])
        if self.edit:
            return list(EDIT_KEYBAR)
        labels = self.base_keybar_labels()
        labels[10] = 'Alt..'
        return labels

    def handle_view_extra(self, k):
        """Returns True/False if handled (False = quit), None to fall through to the base handler."""
        table = {
            'C-F2': self.get_block, 'A-F2': self.fill_block, 'S-F2': self.del_block, 'A-F3': self.cry_block,
            'C-F3': self.replace, 'A-F4': self.reload, 'C-F4': self.reload, 'A-F6': self.strings_window,
            'A-F7': self.toggle_direction, 'A-F8': self.table_menu, 'A-F11': lambda: self.go_value(2),
            'A-F12': lambda: self.go_value(4), 'S-F5': self.copy_block, 'S-F6': self.move_block,
            'A-p': self.print_screen, 'A-P': self.print_screen, 'A-=': self.calculator, 'F9': self.open_file,
        }
        if k in table:
            table[k]()
            return True
        if k in ('C-F7', 'C-ENTER', 'C-n'):
            self.do_search(backward=self.search_back)
            return True
        if k in ('S-F7', 'C-p'):
            self.do_search(backward=not self.search_back)
            return True
        if k == 'F7':
            if self.search_dialog():
                self.do_search(backward=self.search_back)
            return True
        if k == 'A-F10':
            return self.leave_file()
        if k == '*':
            if self.mode == 'text':
                self.set_mode('hex')
            self.mark_at(self.position())
            return True
        if k in SEL_KEYS and self.buf.size:
            if self.mode == 'text':
                self.set_mode('hex')
            self.select_move(k[2:])
            return True
        return None

    def handle_edit_extra(self, k):
        table = {
            'F3': self.restore_byte, 'C-z': self.undo_last, 'F4': lambda: self.bits_edit(1),
            'F5': lambda: self.bits_edit(2), 'F6': lambda: self.bits_edit(4), 'F7': self.crypt_here,
            'C-F7': self.cry_set, 'F8': self.xor_apply, 'C-F8': self.xor_set, 'F10': self.truncate_here,
            'A-F2': self.nops_here, 'A-F8': self.table_menu, 'A-F3': self.cry_block, 'C-F2': self.get_block,
            'S-F5': self.copy_block, 'S-F6': self.move_block, 'A-=': self.calculator, 'A-p': self.print_screen,
        }
        if k in table:
            table[k]()
            return True
        if k == '*' and not (self.mode == 'hex' and self.ascii_col):
            self.mark_at(self.cur)
            return True
        if k in SEL_KEYS:
            self.select_move(k[2:])
            return True
        if self.mode == 'decode':
            if k == 'ENTER':
                self.asm_here()
                return True
            if len(k) == 1 and k.isalpha() and k.lower() not in 'abcdef':
                self.asm_here(initial=k)   # start typing a mnemonic right away
                return True
        return None

    # ---- blocks: *, Shift+arrows

    def mark_at(self, pos):
        if self.block and self.block_start is None:
            self.block = None
            self.sel_anchor = None
            self.set_msg('Block cleared')
            return
        if self.block_start is None:
            self.block_start = pos
            self.set_msg('Block from %s: move, then * again' % self.fmt_addr(pos))
        else:
            a, b = sorted((self.block_start, pos))
            self.block = (a, b + 1)
            self.block_start = None
            self.set_msg('Block %s; * - clear' % _nb(b + 1 - a))

    def select_move(self, nav):
        """Shift+navigation: grow the block from the anchor to the cursor."""
        cur = self.cur if self.edit or self.mode == 'hex' else self.position()
        if getattr(self, 'sel_anchor', None) is None or self.block != getattr(self, '_sel_block', None):
            self.sel_anchor = cur
        self.block_start = None
        if self.edit:
            if self.mode == 'hex':
                self.nav_hex(nav)
            else:
                self.nav_decode_edit(nav)
            cur = self.cur
            end = cur + 1
        elif self.mode == 'hex':
            self.nav_hex(nav)
            cur = self.cur
            end = cur + 1
        else:
            self.nav_decode(nav)
            if self._dl_top != self.top:
                self.dlines = self.decode_at(self.top, self.rows)
                self._dl_top = self.top
            ins = self.dlines[min(self.dcur, len(self.dlines) - 1)] if self.dlines else None
            cur = ins.off if ins else self.top
            end = cur + (ins.size if ins else 1)
        a = self.sel_anchor
        self.block = (min(a, cur), max(a + 1, end))
        self._sel_block = self.block
        self.set_msg('Block ' + _nb(self.block[1] - self.block[0]))

    # ---- helpers

    def ensure_edit(self):
        if not self.edit:
            self.start_edit()
            self.set_msg('Edit mode: F9 - write, Esc - discard')

    def need_block(self):
        blk = self.block_range()
        if not blk:
            self.set_msg('No block marked (press * at start and end)', True)
        return blk

    def parse_bytes(self, s):
        """'90 90' -> bytes; '"text"' -> encoded text."""
        from .app import parse_hex
        s = s.strip()
        if len(s) >= 2 and s[0] in '"\'' and s[-1] == s[0]:
            return self.encode_str(s[1:-1])
        toks = parse_hex(s, wildcards=False)
        return bytes(toks) if toks else None

    def ask(self, text, hint, keys):
        A = self.A
        while True:
            bw = min(self.w - 2, max(len(text), len(hint)) + 6)
            y0, x0 = (self.h - 5) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, 5, bw, 'Confirm')
            self.put(y0 + 1, x0 + 3, text, A['dlg'])
            self.put(y0 + 3, x0 + 3, hint, A['dlghdr'])
            self.apply_cursor(None)
            self.scr.refresh()
            k = self.getkey()
            if k in ('ESC', 'F10'):
                return 'ESC'
            k = {'н': 'y', 'т': 'n', 'ф': 'a'}.get(k.lower(), k.lower()) if len(k) == 1 else k
            if k in keys:
                return k

    def keep_state(self):
        return (self.mode, self.position(), self.show_va, self.arch, list(self.bookmarks), list(self.jumps))

    def restore_state(self, st):
        mode, pos, show_va, arch, bms, jumps = st
        if arch != self.arch:
            self.arch = arch
            self.make_dis()
        if self.info.segments:
            self.show_va = show_va
        self.bookmarks, self.jumps = bms, jumps
        if self.buf.size:
            self.goto(min(pos, self.buf.size - 1), mode, push=False)

    # ---- view-mode commands

    def reload(self):
        if self.edit and self.buf.modified and not self.confirm('Discard %s of changes?' % _nb(len(self.buf.patches))):
            return
        st = self.keep_state()
        self.load(self.buf.path)
        self.restore_state(st)
        self.set_msg('Reloaded, ' + _nb(self.buf.size))

    def open_file(self):
        s = self.input_dialog('Open file', os.path.dirname(self.buf.path) + os.sep, 70)
        if not s:
            return
        prev = (self.buf.path, self.keep_state())
        try:
            self.load(os.path.expanduser(s))
        except OSError as e:
            self.set_msg(str(e), True)
            return
        if not hasattr(self, 'files_stack'):
            self.files_stack = []
        self.files_stack.append(prev)

    def leave_file(self):
        stack = getattr(self, 'files_stack', [])
        if not stack:
            return False
        path, st = stack.pop()
        try:
            self.load(path)
            self.restore_state(st)
        except OSError as e:
            self.set_msg(str(e), True)
        return True

    def toggle_direction(self):
        self.search_back = not self.search_back
        self.set_msg('Search direction: ' + ('backward' if self.search_back else 'forward'))

    def table_menu(self):
        from .app import ENCODINGS
        items = [('%s %s' % ('*' if e == self.enc else ' ', e), e) for e in ENCODINGS]
        r = self.list_dialog('Translation table', items, sel=ENCODINGS.index(self.enc), filterable=False)
        if r:
            self.enc = r

    def go_value(self, n):
        pos = self.cur if self.edit else self.position()
        d = self.buf.read(pos, n)
        if len(d) < n:
            self.set_msg('End of file', True)
            return
        v = int.from_bytes(d, 'big' if self.info.endian == '>' else 'little')
        off = self.off_of(v) if self.info.segments else None
        if off is None and v < self.buf.size:
            off = v
        if off is None:
            self.set_msg('%0*X is outside the file' % (n * 2, v), True)
            return
        self.goto(off, 'hex')

    def get_block(self):
        name = self.input_dialog('Read file into current position (GetBlk)', '', 60)
        if not name:
            return
        try:
            with open(os.path.expanduser(name), 'rb') as f:
                data = f.read(self.buf.size)
        except OSError as e:
            self.set_msg(str(e), True)
            return
        pos = self.cur if self.edit else self.position()
        self.ensure_edit()
        data = data[:self.buf.size - pos]
        self.buf.write_bytes(pos, data)
        self.block, self.block_start = (pos, pos + len(data)), None
        self.set_msg('Read %s at %s, F9 - write' % (_nb(len(data)), self.fmt_addr(pos)))

    def fill_block(self):
        blk = self.need_block()
        if not blk:
            return
        s = self.input_dialog('Fill block of %s (FilBlk)' % _nb(blk[1] - blk[0]), getattr(self, 'fill_text', '00'), 60,
                              'hex bytes (90 90) or "text" in quotes', select=True)
        if not s:
            return
        pat = self.parse_bytes(s)
        if not pat:
            self.set_msg('Bad fill pattern', True)
            return
        self.fill_text = s
        self.ensure_edit()
        n = blk[1] - blk[0]
        self.buf.write_bytes(blk[0], (pat * (n // len(pat) + 1))[:n])
        self.set_msg('Filled %s, F9 - write' % _nb(n))

    def copy_block(self):
        blk = self.need_block()
        if not blk:
            return
        dst = self.cur if self.edit else self.position()
        data = self.buf.read(blk[0], blk[1] - blk[0])
        self.ensure_edit()
        self.buf.write_bytes(dst, data[:self.buf.size - dst])
        self.block, self.block_start = (dst, min(self.buf.size, dst + len(data))), None
        self.set_msg('Copied %s to %s, F9 - write' % (_nb(len(data)), self.fmt_addr(dst)))

    def move_block(self):
        blk = self.need_block()
        if not blk:
            return
        a, b = blk
        n = b - a
        c = self.cur if self.edit else self.position()
        if a <= c < b:
            self.set_msg('Cursor is inside the block', True)
            return
        if c > a:
            if c + n > self.buf.size:
                self.set_msg('Block does not fit at the cursor', True)
                return
            new = self.buf.read(b, c - a) + self.buf.read(a, n)   # [a, c+n): tail moves left, block lands at c
            start = a
        else:
            new = self.buf.read(a, n) + self.buf.read(c, a - c)   # [c, b): block lands at c, gap moves right
            start = c
        self.ensure_edit()
        self.buf.write_bytes(start, new)
        self.block, self.block_start = (c, c + n), None
        self.set_msg('Moved %s to %s, F9 - write' % (_nb(n), self.fmt_addr(c)))

    def del_block(self):
        blk = self.need_block()
        if not blk:
            return
        if self.buf.modified:
            self.set_msg('Write (F9) or discard changes first', True)
            return
        a, b = blk
        if not self.confirm('Delete %s from the file on disk?' % _nb(b - a)):
            return
        st = self.keep_state()
        try:
            self.buf.delete(a, b)
        except OSError as e:
            self.set_msg(str(e), True)
            return
        self.load(self.buf.path)
        self.restore_state(st)
        self.set_msg('Deleted ' + _nb(b - a))

    def truncate_here(self):
        pos = self.cur
        n = len(self.buf.patches)
        if not self.confirm('Truncate file at %s%s?' % (self.fmt_addr(pos), ' (and write %d changes)' % n if n else '')):
            return
        st = self.keep_state()
        try:
            self.buf.save()
            self.buf.truncate(pos)
        except OSError as e:
            self.set_msg(str(e), True)
            return
        self.end_edit()
        self.load(self.buf.path)
        self.restore_state(st)
        self.set_msg('File truncated at %s' % self.fmt_addr(pos))

    def strings_window(self):
        while True:
            items = self.scan_strings(self.str_min)
            title = 'Strings: %d, min length %d (+/- to change)' % (len(items), self.str_min)
            if not items:
                items = [('no strings of %d+ chars' % self.str_min, None)]
            r = self.list_dialog(title, items, extra_keys=('+', '-'))
            if isinstance(r, tuple) and r[0] == '__key__':
                self.str_min = max(2, self.str_min + (1 if r[1] == '+' else -1))
                continue
            if r is not None:
                self.goto(r, 'hex')
            return

    def scan_strings(self, minlen, limit=64 << 20, cap=50000):
        self.flash('Scanning strings ...')
        rx = re.compile(rb'[\x20-\x7e\t]{%d,}|(?:[\x20-\x7e]\x00){%d,}' % (minlen, minlen))
        size = min(self.buf.size, limit)
        out = []
        pos = 0
        last_end = 0
        CH = 4 << 20
        while pos < size and len(out) < cap:
            data = self.buf.read(pos, CH + 4096)
            for m in rx.finditer(data):
                s = pos + m.start()
                if s >= pos + CH or len(out) >= cap:
                    break
                if s < last_end:
                    continue
                last_end = pos + m.end()
                raw = m.group()
                if len(raw) > 1 and raw[1] == 0:
                    text, kind = raw.decode('utf-16-le', 'replace'), 'U'
                else:
                    text, kind = raw.decode('latin-1'), 'A'
                text = text.replace('\t', ' ')
                out.append(('%s %s %s' % (self.fmt_addr(s), kind, text[:120]), s))
            pos += CH
        self.msg = None
        return out

    def replace(self):
        if not self.search_dialog('Replace: find'):
            return
        s = self.input_dialog('Replace with', self.repl_text, 60, 'hex bytes (90 90) or "text" in quotes', select=True)
        if s is None:
            return
        data = self.parse_bytes(s)
        if not data:
            self.set_msg('Bad replacement', True)
            return
        self.repl_text = s
        rx, plen, desc = self.search
        self.ensure_edit()
        pos = self.cur
        count = 0
        while True:
            off = self.buf.find(rx, plen, pos)
            if off is None:
                break
            self.found = (off, plen)
            self.edit_move(off)
            ans = self.ask('Replace at %s?' % self.fmt_addr(off), 'Y - yes  N - skip  A - all  Esc - stop', 'yna')
            if ans == 'ESC':
                break
            if ans == 'n':
                pos = off + 1
                continue
            if ans == 'a':
                count += self.replace_all(rx, plen, data, off)
                break
            self.buf.write_bytes(off, data[:self.buf.size - off])
            count += 1
            pos = off + max(1, len(data))
        self.found = None
        self.set_msg('Replaced %d, F9 - write, Esc - discard' % count)

    def replace_all(self, rx, plen, data, start):
        """One pass over the file from start: collect matches, confirm, write them as one undo step."""
        import time as _t
        size = self.buf.size
        CH = 4 << 20
        ov = max(plen - 1, 0)
        hits = []
        nxt = start
        step = max(1, len(data))
        last = 0
        c = start
        stopped = False
        self.scr.nodelay(True)
        try:
            while c < size:
                chunk = self.buf.read(c, CH + ov)
                for m in rx.finditer(chunk):
                    o = c + m.start()
                    if o >= c + CH:
                        break
                    if o < nxt:
                        continue
                    hits.append(o)
                    nxt = o + step
                c += CH
                now = _t.time()
                if now - last > 0.2:
                    last = now
                    self.msg = 'Finding matches: %d%%, %d found (Esc - stop)' % (min(100, (c - start) * 100 // max(1, size - start)), len(hits))
                    self.msg_err = False
                    self.draw()
                    self.scr.nodelay(True)
                    try:
                        k = self.scr.getch()
                    except Exception:
                        k = -1
                    if k == 27:
                        stopped = True
                        break
        finally:
            import curses as _c
            from . import keys as _K
            self.scr.timeout(_K.READ_TIMEOUT)
        self.msg = None
        if not hits:
            return 0
        what = '%d matches%s' % (len(hits), ' (search stopped by Esc)' if stopped else '')
        if not self.confirm('Replace %s?' % what):
            return 0
        self.buf.write_many(hits, data)
        self.edit_move(hits[-1])
        return len(hits)

    def print_screen(self):
        name = self.input_dialog('Append screen to file (Alt-P)', self.prn_name, 60, select=True)
        if not name:
            return
        self.msg = None
        self.draw()          # capture the view itself, not the file-name dialog
        lines = []
        for y in range(self.h):
            try:
                raw = self.scr.instr(y, 0, self.w)
            except Exception:
                raw = b''
            lines.append(raw.decode('utf-8', 'replace').rstrip())
        try:
            with open(os.path.expanduser(name), 'a', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n\n')
        except OSError as e:
            self.set_msg(str(e), True)
            return
        self.prn_name = name
        self.set_msg('Screen appended to ' + name)

    def calculator(self):
        from .app import LineEdit
        A = self.A
        le = LineEdit(self.calc_expr)
        while True:
            bw = min(self.w - 2, 66)
            bh = 8
            y0, x0 = (self.h - bh) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, bh, bw, 'Calculator')
            fw = bw - 4
            vis, cx = le.view(fw)
            self.put(y0 + 1, x0 + 2, vis.ljust(fw), A['input'])
            pos = self.cur if self.edit else self.position()
            try:
                v = calc_eval(le.text, {'cur': self.va_of(pos) if self.show_va else pos, 'off': pos, 'size': self.buf.size})
                lines = ['Hex:  %X%s' % (v & ((1 << 64) - 1) if v < 0 else v, '  (as uint64)' if v < 0 else ''),
                         'Dec:  %d    int32: %d' % (v, ((v + (1 << 31)) & 0xFFFFFFFF) - (1 << 31)),
                         'Bin:  %s' % bin(v & 0xFFFFFFFF if v < 0 else v)[2:][-56:],
                         'Chr:  %s' % ''.join(chr(c) if 32 <= c < 127 else '.' for c in
                                              (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big').lstrip(b'\0'))]
            except ValueError as e:
                lines = ['' if not le.text.strip() else str(e)]
            for i, l in enumerate(lines):
                self.put(y0 + 2 + i, x0 + 2, l[:fw], A['dlg'])
            self.put(y0 + 6, x0 + 2, '1Fh/0x1F hex, 31 dec, $ = cursor address, off, size, + - * / % & | ^ ~ << >>'[:fw], A['dlghdr'])
            self.apply_cursor((y0 + 1, x0 + 2 + cx))
            self.scr.refresh()
            k = self.getkey()
            if k in ('ESC', 'F10', 'ENTER'):
                self.calc_expr = le.text
                self.apply_cursor(None)
                return
            le.key(k)

    def cry_set(self):
        s = self.input_dialog('Crypt routine (CrySet)', self.crypt.text if self.crypt else 'xor al, 55h', 66,
                              'al/ax/eax = data; ebx..ebp keep values: xor al,bl ; add bl,3 ; rol al,1', select=True)
        if not s:
            return False
        try:
            self.crypt = Crypt(s)
        except ValueError as e:
            self.set_msg('Crypt: %s' % e, True)
            return False
        self.set_msg('Crypt set, unit %d byte(s): F7 at cursor, Alt-F3 for a block' % self.crypt.width)
        return True

    def cry_block(self):
        blk = self.need_block()
        if not blk or (not self.crypt and not self.cry_set()):
            return
        c = self.crypt
        c.reset()
        a, b = blk
        data = self.buf.read(a, b - a)
        w = c.width
        out = bytearray(data)
        for i in range(0, len(data) - w + 1, w):
            out[i:i + w] = c.run(data[i:i + w])
        self.ensure_edit()
        self.buf.write_bytes(a, bytes(out))
        self.set_msg('Crypted %s, F9 - write' % _nb(b - a))

    # ---- edit-mode commands

    def restore_byte(self):
        off = self.cur
        if off in self.buf.patches:
            self.buf.write(off, self.buf._raw(off, 1)[0])
        self.nib = 0

    def undo_last(self):
        off = self.buf.undo()
        if off is not None:
            self.edit_move(off)

    def crypt_here(self):
        if not self.crypt and not self.cry_set():
            return
        w = self.crypt.width
        d = self.buf.read(self.cur, w)
        if len(d) < w:
            self.set_msg('End of file', True)
            return
        self.buf.write_bytes(self.cur, self.crypt.run(d))
        self.edit_move(min(self.cur + w, self.buf.size - 1))

    def xor_set(self):
        from .app import parse_hex
        s = self.input_dialog('XOR key, hex bytes (XorSet)', self.xor_key, 50, select=True)
        if not s:
            return False
        if not parse_hex(s, wildcards=False):
            self.set_msg('Bad hex key', True)
            return False
        self.xor_key = s
        return True

    def xor_apply(self):
        from .app import parse_hex
        if not self.xor_key and not self.xor_set():
            return
        key = parse_hex(self.xor_key, wildcards=False)
        blk = self.block_range()
        a, b = blk if blk else (self.cur, min(self.buf.size, self.cur + len(key)))
        data = self.buf.read(a, b - a)
        self.buf.write_bytes(a, bytes(v ^ key[i % len(key)] for i, v in enumerate(data)))
        if not blk:
            self.edit_move(min(b, self.buf.size - 1))
        self.set_msg('XOR %s applied to %s, Ctrl-F8 - key' % (self.xor_key, _nb(b - a)))

    def nops_here(self):
        nop = NOPS.get(self.arch, b'\x90')
        if self.info.endian == '>' and len(nop) > 1:
            nop = nop[::-1]
        if self.mode == 'decode':
            lst = self.decode_at(self.cur, 1)
            ins = next((l for l in self.dlines if l.off <= self.cur < l.off + l.size), lst[0] if lst else None)
            if ins is None:
                return
            a, n = ins.off, ins.size
        else:
            a, n = self.cur, len(nop)
        fill = (nop * (n // len(nop) + 1))[:n]
        self.buf.write_bytes(a, fill)
        self.edit_move(min(a + n, self.buf.size - 1))

    def bits_edit(self, n):
        A = self.A
        off = self.cur
        data = self.buf.read(off, n)
        if len(data) < n:
            self.set_msg('End of file', True)
            return
        big = self.info.endian == '>'
        order = 'big' if big else 'little'
        val = int.from_bytes(data, order)
        orig = int.from_bytes(self.buf._raw(off, n), order)
        bits = n * 8
        i = 0   # index from the most significant bit
        while True:
            bw = min(self.w - 2, max(68, bits + bits // 4 + 12))
            y0, x0 = (self.h - 7) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, 7, bw, 'Bits: %s at %s' % ({1: 'byte', 2: 'word', 4: 'dword'}[n], self.fmt_addr(off)))
            xs = x0 + 3
            hdr = ''.join('%-5d' % (bits - 1 - j) if j % 4 == 0 else '' for j in range(bits))
            self.put(y0 + 1, xs, hdr[:bw - 4], A['dlghdr'])
            curx = xs
            for j in range(bits):
                bit = bits - 1 - j
                v = (val >> bit) & 1
                x = xs + j + j // 4
                at = A['input'] if ((orig >> bit) & 1) == v else A['found']
                self.put(y0 + 2, x, str(v), at)
                if j == i:
                    curx = x
            self.put(y0 + 3, xs, 'Hex %0*X   Dec %d   bit %d' % (n * 2, val, val, bits - 1 - i), A['dlg'])
            self.put(y0 + 5, xs, 'Space/F2 invert  0/1 set  F3 restore  Enter apply  Esc cancel'[:bw - 4], A['dlghdr'])
            self.apply_cursor((y0 + 2, curx))
            self.scr.refresh()
            k = self.getkey()
            bit = bits - 1 - i
            if k in ('ESC', 'F10'):
                break
            if k == 'ENTER':
                self.buf.write_bytes(off, val.to_bytes(n, order))
                break
            if k == 'LEFT':
                i = max(0, i - 1)
            elif k == 'RIGHT':
                i = min(bits - 1, i + 1)
            elif k == 'HOME':
                i = 0
            elif k == 'END':
                i = bits - 1
            elif k in (' ', 'F2'):
                val ^= 1 << bit
            elif k in ('0', '1'):
                val = (val & ~(1 << bit)) | (int(k) << bit)
                i = min(bits - 1, i + 1)
            elif k == 'F3':
                val = (val & ~(1 << bit)) | (orig & (1 << bit))
        self.apply_cursor(None)
