"""Hiew curses user interface."""
import curses
import os
import re

from . import keys as K
from .buffer import FileBuffer
from .disasm import ARCHS, BITS_CYCLE, HAVE_KS, HEX_RE, KS_HINT, RIP_RE, SHORT, Disassembler, assemble
from .extra import ExtraMixin
from .formats import analyze
from .mods import ModWatcher, kitty_disable, kitty_enable, translate

from . import __version__ as VERSION
MODES = ('text', 'hex', 'decode')
ENCODINGS = ('utf-8', 'cp437', 'cp866', 'cp1251', 'koi8_r', 'latin-1')
TEXT_LINE_MAX = 0x4000
HEX_CHARS = set('0123456789abcdefABCDEF ?')

KEYBARS = {
    'text': ['Help', 'Wrap', 'Edit', 'Mode', 'Goto', '', 'Search', 'Xlat', 'Files', 'Quit', '', 'Names'],
    'hex': ['Help', 'PutBlk', 'Edit', 'Mode', 'Goto', '', 'Search', 'Header', 'Files', 'Quit', '', 'Names'],
    'decode': ['Help', 'Bits', 'Edit', 'Mode', 'Goto', 'Refer', 'Search', 'Header', 'Files', 'Quit', '', 'Names'],
    'edit': ['Help', 'Asm', 'Undo', '', 'Goto', '', '', 'Xor', 'Update', 'Quit', '', ''],
}

HELP = """\
 Hiew %s - cross-platform Hacker's View. Keys follow https://taviso.github.io/hiewdocs/

 MODES
   Enter                  Text -> Hex -> Code -> Text (address is kept)
   F4                     menu of modes, architectures, encodings and colour themes (hiew,
                          blue, dark, light - remembered); universal (fat) Mach-O - pick slice
   F3                     edit mode (EDITMODE), Esc - leave without saving, F9 - save
   Ctrl+F1                code bitness: 16 / 32 / 64 bit
   Shift+F1               architecture (x86, ARM, ARM64, MIPS, PPC, RISC-V)
   Alt+F1                 addresses: file offset <-> virtual (.VA)

 NAVIGATION
   Ctrl+Home / Ctrl+End   start / end of file
   F5                     goto: 1234 (hex), 123t (dec), .401000 (VA), +100, -10t, name;
                          PgDn in the dialog - history
   F6 / Ctrl+F6           (Code) references to current address / next reference
   1..9, A..Z             (Code) follow the labelled jump (--v1)
   /                      (Code) resync the disassembler at the cursor
   BkSp                   go back
   Shift+F9/F10/F11       jump to dword / qword / word under cursor
   Alt+F11 / Alt+F12      jump to word / dword under cursor

 BOOKMARKS (8 per mode, indicator in the status line)
   +                      save position
   -                      return to the current bookmark (marked ♦)
   Alt+1..Alt+8           go to bookmark by number
   Alt+-                  delete the current bookmark
   Alt+0                  delete all bookmarks

 BLOCKS
   *                      start a block, move the cursor (F5, F7, Ctrl+End... work), * - end;
                          * on a finished block - clear the selection
   Shift+arrows           select a block from the cursor
   Ctrl+*                 whole file as a block
   Alt+*                  move block start to the cursor
   [ / ]                  to block start / end
   Ins                    block operation mode: insert (file grows) / overwrite
   F2                     write block to a file (PutBlk)
   Ctrl+F2                read a file into the position (insert or overwrite)
   Alt+F2                 fill block with a pattern; in Code without a block - NOPs
   Alt+F3                 Crypt: x86-subset routine applied to the block
   Shift+F2               delete block from the file
   Shift+F3               insert N zero bytes
   Shift+F4               print block (hex dump) to a file or the clipboard
   Shift+F5 / Shift+F6    copy / move block to the cursor
   Alt+M / Shift+Alt+M    colour the block (pick colour / random), .cmarkers
   Alt+N / Shift+Alt+N    to next / previous coloured block

 SEARCH
   F7                     search. In the dialog: Tab - Hex/ASCII, F2 - direction,
                          F3 - case, F4 - file/block, F6 - UTF-16 even/odd,
                          F7 - find instruction (assembler), Alt+? - any char,
                          in Hex ?? - any byte; >3 non-hex chars -> ASCII
   Ctrl+Enter, Shift+F7   next match (with no prior search - opens the dialog)
   Alt+F7                 toggle direction (arrow in the status line)
   Alt+F8                 character table: encoding, UTF-16 (unicode)
   Alt+F6                 strings: +/- length, F6 type (ASCII, UTF-16 even/odd),
                          F2 offsets, F9 filter, typing text - filter
   Ctrl+F3                search and replace (Y / N / A)

 EDITING (F3)
   0-9 A-F                hex; Tab - Hex <-> chars (Hex) or line assembler (Code)
   F2, Enter (Code)       assembler (numbers are hex, 10t - decimal); in Code you can
                          start typing a command with g-z (nop, mov, jmp), a-f are hex digits
   F3                     restore original byte       Ctrl+Z - undo last change
   F4 / F5 / F6           bits of byte / word / dword
   F7, Ctrl+F7            Crypt at cursor / define routine
   F8, Ctrl+F8            XOR / set key
   Alt+F2                 NOP the current instruction or fill the block
   F10                    truncate file at the cursor
   F9 / Esc               save / cancel

 FILES, NAMES
   F9                     open file             Tab - next open file
   Ctrl+F11 / Ctrl+F12    previous / next file from the command line
   Ctrl+BkSp              list of open files (Enter, Del)
   Alt+F10                close file and return to the previous one
   Alt+F4, Ctrl+F4        reload file
   F8                     header; in it F5 - entry, F6 - sections, F7 - imports,
                          Enter on a fat-file slice line - switch to it
                          (Enter - find calls, Ctrl+Enter - next), F9 - exports
   F12                    names and comments; in the F12 window - import, Shift+F12 - export
   Shift+F12              name the current location     ; - comment
                          (names and comments are saved to <file>.hnames)

 MISC
   Alt+=                  calculator: hex by default, 10t, 17o, 101i, @b @w @d @q
                          (@B... unsigned), @o / @O address / offset, Up/Down move the window
   Alt+P                  screenshot to a file or the clipboard
   Alt+B                  sound on/off
   Ctrl+Alt (hold)        file and system info (Alt+I - same in a window)
   Ctrl+. / Ctrl+0..8     record macro / play;  Ctrl+- - macro list
   Esc                    quit without touching the file time;  F10 - quit and update it
   F11                    HEM modules are not supported

 IF THE TERMINAL DOES NOT PASS KEY COMBINATIONS
   Ctrl+X, then a key     sticky modifier: Ctrl+X cycles Alt -> Ctrl -> Shift;
                          the bottom bar shows that layer's labels
   Esc, then a key        within 0.5 s - same as Alt+key
   bottom bar             shows the layer's labels while Alt/Ctrl/Shift is held
""" % VERSION


class LineEdit:
    def __init__(self, text=''):
        self.text = text
        self.pos = len(text)

    def set(self, text):
        self.text = text
        self.pos = len(text)

    def key(self, k):
        t, p = self.text, self.pos
        if k == 'LEFT':
            self.pos = max(0, p - 1)
        elif k == 'RIGHT':
            self.pos = min(len(t), p + 1)
        elif k in ('HOME', 'C-a'):
            self.pos = 0
        elif k in ('END', 'C-e'):
            self.pos = len(t)
        elif k == 'BS':
            if p:
                self.text = t[:p - 1] + t[p:]
                self.pos = p - 1
        elif k == 'DEL':
            self.text = t[:p] + t[p + 1:]
        elif k in ('C-u', 'C-y'):
            self.set('')
        elif len(k) == 1 and k.isprintable():
            self.text = t[:p] + k + t[p:]
            self.pos = p + 1
        else:
            return False
        return True

    def view(self, width):
        start = max(0, self.pos - width + 1)
        return self.text[start:start + width], self.pos - start


def parse_hex(s, wildcards=True):
    s = s.replace(' ', '')
    if not s or len(s) % 2:
        return None
    out = []
    for i in range(0, len(s), 2):
        t = s[i:i + 2]
        if t == '??' and wildcards:
            out.append(None)
        elif '?' in t:
            return None
        else:
            out.append(int(t, 16))
    return out


def nbytes(n):
    return '%Xh (%d) bytes' % (n, n) if n >= 10 else '%d byte%s' % (n, '' if n == 1 else 's')


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


class App(ExtraMixin):
    def __init__(self, scr, path, opts):
        self.scr = scr
        self.opts = opts
        self.msg = None
        self.msg_err = False
        self.buf = None
        self.hw_cursor = None
        self._curs = None
        self.enc = 'utf-8'
        self.wrap = False
        self.search = None
        self.search_ascii = ''
        self.search_hex = ''
        self.search_icase = False
        self.search_src = 'ascii'
        self.xor_key = ''
        self._tables = {}
        scr.keypad(True)
        self.held_layer = None
        self.modwatch = ModWatcher()
        self.kitty = getattr(opts, 'kitty', True) and kitty_enable(scr)
        if self.kitty or self.modwatch.available:
            K.READ_TIMEOUT = 60
            scr.timeout(K.READ_TIMEOUT)
        self.init_colors()
        self.mouse = False
        if opts.mouse:
            try:
                curses.mousemask(curses.ALL_MOUSE_EVENTS)
                curses.mouseinterval(0)
                self.mouse = True
            except Exception:
                pass
        self.h, self.w = scr.getmaxyx()
        self.load(path, first=True)

    # ------------------------------------------------------------ setup

    def init_colors(self, theme=None):
        from .themes import PALETTES_256, ROLES, THEMES, load_settings, palette_8
        if theme is None:
            colors = getattr(self.opts, 'colors', 'auto')
            theme = getattr(self.opts, 'theme', None) or {'classic': 'blue'}.get(colors) or \
                load_settings().get('theme') or 'hiew'
        if theme not in THEMES:
            theme = 'hiew'
        self.theme = theme
        A = {}
        if curses.has_colors():
            curses.start_color()
            C = curses
            if curses.COLORS >= 256 and getattr(self.opts, 'colors', 'auto') != '8':
                spec = PALETTES_256[theme]
            else:
                spec = palette_8(theme, C)
            attrs = {'': 0, 'bold': C.A_BOLD}
            for i, n in enumerate(ROLES, 1):
                fg, bg, at = spec[n]
                try:
                    curses.init_pair(i, fg, bg)
                    A[n] = curses.color_pair(i) | attrs[at]
                except curses.error:
                    A[n] = attrs[at]
        else:
            rev = curses.A_REVERSE
            for n in ROLES:
                A[n] = 0
            for n in ('status', 'keylbl', 'cursor', 'block', 'found', 'dlgsel', 'msg', 'err'):
                A[n] = rev
            for n in ('mod', 'jump', 'call', 'name', 'bright'):
                A[n] = curses.A_BOLD
        self.A = A
        self.scr.bkgd(' ', A['norm'])

    def set_theme(self, theme):
        from .themes import save_setting
        self.init_colors(theme)
        save_setting('theme', theme)
        self.set_msg('Theme: %s (saved)' % theme)

    def load(self, path, first=False):
        buf = FileBuffer(path)
        if self.buf is not None:
            self.buf.close()
        self.buf = buf
        if first or getattr(self, '_slice_path', None) != buf.path:
            self.slice_sel = getattr(self.opts, 'slice', None) if first else None
        self._slice_path = buf.path
        self.info = analyze(buf, self.slice_sel)
        self.arch = (first and self.opts.arch) or self.info.arch or 'x86-32'
        self.make_dis()
        self.show_va = bool(self.info.segments)
        maxa = buf.size
        for o, s, v, vs in self.info.segments:
            maxa = max(maxa, v + max(s, vs))
        self.adig = max(8, len('%X' % maxa))
        self.top = self.cur = self.dcur = self.hscroll = 0
        self.dlines = []
        self._dl_top = None
        self.text_anchor = None
        self.found = None
        self.block = None
        self.block_start = None
        self.jumps = []
        self.bookmarks = []
        self.jtargets = {}
        self.edit = False
        self.edit_ret = None
        self.nib = 0
        self.ascii_col = False
        self._names = {}
        self._byname = None
        self.mode = (first and self.opts.mode) or ('text' if self.looks_text() else 'hex')
        if first and self.opts.offset:
            try:
                self.goto(self.parse_target(self.opts.offset), push=False)
            except ValueError as e:
                self.set_msg(str(e), True)
        elif first and self.opts.entry and self.info.entry_off is not None:
            self.goto(self.info.entry_off, 'decode', push=False)
        elif first and self.opts.entry and self.info.slices:
            self.goto(self.info.slices[self.info.slice_idx][1], 'decode', push=False)
        if self.info.slice_warning:
            self.set_msg(self.info.slice_warning, True)

    def make_dis(self):
        self.dis = Disassembler(self.arch, self.info.endian == '>')
        self._names = {}

    def looks_text(self):
        d = self.buf.read(0, 4096)
        if not d:
            return True
        if b'\0' in d:
            return False
        good = sum(1 for b in d if b >= 32 or b in (9, 10, 13))
        return good >= len(d) * 0.95

    # ------------------------------------------------------------ helpers

    def set_msg(self, text, err=False):
        self.msg = text
        self.msg_err = err

    def flash(self, text):
        self.set_msg(text)
        self.draw()

    def put(self, y, x, s, attr=0):
        if y < 0 or y >= self.h or x >= self.w or not s:
            return
        if x < 0:
            s = s[-x:]
            x = 0
        s = s[:self.w - x]
        try:
            self.scr.addstr(y, x, s, attr)
        except curses.error:
            pass

    def apply_cursor(self, pos):
        want = 1 if pos else 0
        if want != self._curs:
            try:
                curses.curs_set(want)
            except curses.error:
                pass
            self._curs = want
        if pos:
            try:
                self.scr.move(pos[0], pos[1])
            except curses.error:
                pass

    def getkey(self, main=False):
        K.ESC_PREFIX = main
        while True:
            k = K.read_key(self.scr)
            if k is None or k == 'MODS':
                self.refresh_mods()
                continue
            if k == 'RESIZE':
                self.h, self.w = self.scr.getmaxyx()
            return k

    def translate_key(self, k):
        return translate(k, self.held_mods(), self.kitty)

    def held_mods(self):
        if self.kitty:
            return frozenset(K.HELD)
        return self.modwatch.poll()

    def refresh_mods(self):
        """Switch the keybar to the Alt/Ctrl/Shift layer while a modifier is held."""
        held = self.held_mods()
        layer = 'C' if 'C' in held else 'A' if 'A' in held else 'S' if 'S' in held else None
        if layer != self.held_layer:
            self.held_layer = layer
            y, x = self.scr.getyx()
            self.draw_keybar()
            try:
                self.scr.move(y, x)
            except curses.error:
                pass
            self.scr.refresh()

    def table(self):
        t = self._tables.get(self.enc)
        if t is None:
            t = []
            for b in range(256):
                if self.enc == 'utf-8':
                    ch = chr(b) if 32 <= b < 127 else '.'
                else:
                    try:
                        ch = bytes([b]).decode(self.enc)
                    except UnicodeDecodeError:
                        ch = '.'
                    if b < 32 or b == 127 or not ch.isprintable():
                        ch = '.'
                t.append(ch)
            self._tables[self.enc] = t
        return t

    def encode_str(self, s):
        return s.encode(self.enc, 'replace')

    def fmt_addr(self, off):
        if self.show_va:
            va = self.info.off2va(off)
            if va is not None:
                return '.%0*X' % (self.adig, va)
        return '%0*X' % (self.adig, off)

    def disp_va(self, va):
        """Format a virtual address the way the address column shows it."""
        if not self.info.segments:
            return '%0*X' % (self.adig, va)
        if self.show_va:
            return '.%0*X' % (self.adig, va)
        off = self.info.va2off(va)
        return '%0*X' % (self.adig, off) if off is not None else '.%X' % va

    def va_of(self, off):
        va = self.info.off2va(off)
        return off if va is None else va

    def off_of(self, va):
        if not self.info.segments:
            return va if 0 <= va < self.buf.size else None
        return self.info.va2off(va)

    def position(self):
        if self.mode == 'hex' or (self.edit and self.mode == 'decode'):
            return self.cur
        if self.mode == 'decode':
            if self._dl_top == self.top and 0 <= self.dcur < len(self.dlines):
                return self.dlines[self.dcur].off
            return self.top
        if self.text_anchor is not None and self.line_start(self.text_anchor) == self.top:
            return self.text_anchor
        return self.top

    def block_range(self):
        if self.block:
            return self.block
        if self.block_start is not None:
            a, b = sorted((self.block_start, self.position()))
            return a, b + 1
        return None

    def bpl(self):
        return 16 if self.w >= self.adig + 3 + 16 * 4 + 1 else 8

    # ------------------------------------------------------------ text mode helpers

    def wrap_len(self, data, width):
        col = 0
        utf8 = self.enc == 'utf-8'
        for i, b in enumerate(data):
            if b == 10:
                return i + 1
            if b == 13 or (utf8 and 0x80 <= b < 0xC0):
                w = 0
            elif b == 9:
                w = 8 - col % 8
            else:
                w = 1
            if w and col + w > width:
                return i or 1
            col += w
        return len(data)

    def next_line(self, off):
        if off >= self.buf.size:
            return self.buf.size
        if self.wrap:
            return off + self.wrap_len(self.buf.read(off, self.w * 4 + 8), self.w)
        d = self.buf.read(off, TEXT_LINE_MAX)
        i = d.find(b'\n')
        return off + (i + 1 if i >= 0 else len(d))

    def line_start(self, off):
        off = clamp(off, 0, max(0, self.buf.size - 1))
        lo = max(0, off - TEXT_LINE_MAX)
        d = self.buf.read(lo, off - lo)
        i = d.rfind(b'\n')
        ls = lo + i + 1 if i >= 0 else lo
        if not self.wrap:
            return ls
        p = ls
        for _ in range(TEXT_LINE_MAX):
            q = self.next_line(p)
            if q > off or q <= p:
                return p
            p = q
        return p

    def prev_line(self, off):
        return self.line_start(off - 1) if off > 0 else 0

    def render_text(self, data):
        enc = self.enc
        s = data.decode(enc, 'replace')
        out = []
        col = 0
        for ch in s:
            if ch in '\r\n':
                continue
            if ch == '\t':
                n = 8 - col % 8
                out.append(' ' * n)
                col += n
                continue
            o = ord(ch)
            if o < 32 or o == 127 or o == 0xFFFD or not ch.isprintable():
                ch = '.'
            out.append(ch)
            col += 1
        return ''.join(out)

    # ------------------------------------------------------------ decode helpers

    def decode_at(self, off, n):
        data = self.buf.read(off, n * 16 + 16)
        lst = self.dis.decode(data, self.va_of(off), n)
        for i in lst:
            i.off += off
        return lst

    def prev_insn(self, off):
        if off <= 0:
            return 0
        al = self.dis.align
        if al > 1 or self.dis.cs is None:
            return max(0, off - al)
        for back in (48, 40, 32, 24, 16, 12, 8):
            start = max(0, off - back)
            prev = None
            for ins in self.decode_at(start, back + 1):
                if ins.off >= off:
                    break
                prev = ins
            if prev is not None and prev.off + prev.size == off:
                return prev.off
        return off - 1

    def name_for(self, va):
        if va in self._names:
            return self._names[va]
        syms = self.info.symbols
        name = syms.get(va)
        if name is None:
            off = self.off_of(va)
            if off is not None:
                lst = self.decode_at(off, 1)
                if lst and lst[0].kind == 'jmp':
                    ins = lst[0]
                    inner = ins.mem if ins.mem is not None else ins.target
                    if inner is not None and inner in syms:
                        name = syms[inner].replace('@got', '') + ('@plt' if self.info.kind == 'ELF' else '')
        self._names[va] = name
        return name

    def string_at(self, va):
        off = self.off_of(va)
        if off is None:
            return None
        d = self.buf.read(off, 80)
        if len(d) >= 8 and d[1] == 0 and d[3] == 0 and 32 <= d[0] < 127:
            chars = []
            for i in range(0, len(d) - 1, 2):
                c = d[i] | (d[i + 1] << 8)
                if c == 0 or not (32 <= c < 0xD800) or not chr(c).isprintable():
                    break
                chars.append(chr(c))
            if len(chars) >= 3:
                s = ''.join(chars)
                return 'L"%s"' % (s[:40] + ('...' if len(s) > 40 else ''))
        n = 0
        while n < len(d) and (32 <= d[n] < 127 or d[n] in (9, 10, 13)):
            n += 1
        if n >= 4 and (n == len(d) or d[n] == 0):
            s = d[:n].decode('latin-1').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
            return '"%s"' % (s[:48] + ('...' if len(s) > 48 else ''))
        return None

    def label_at(self, ins):
        return self.info.symbols.get(ins.addr)

    def comments(self, ins):
        out = []
        if ins.target is not None:
            n = self.name_for(ins.target)
            if n:
                out.append(n)
        if ins.mem is not None:
            n = self.name_for(ins.mem) or self.string_at(ins.mem)
            if n:
                out.append(n)
        if self.info.kind != 'raw':
            for v in ins.imms:
                n = self.info.symbols.get(v) or self.string_at(v)
                if n:
                    out.append(n)
                    break
        return ' ; '.join(out)

    def fmt_ops(self, ins):
        ops = ins.ops
        if ins.target is not None:
            disp = self.disp_va(ins.target)
            ops = re.sub(r'#?-?0x[0-9a-f]+(?=\s*$)', lambda m: disp, ops) if re.search(r'0x[0-9a-f]+\s*$', ops) else ops
        if ins.mem is not None and 'rip' in ops:
            ops = RIP_RE.sub('[%s]' % self.disp_va(ins.mem), ops)
        return ops

    # ------------------------------------------------------------ drawing

    def draw(self, refresh=True):
        self.h, self.w = self.scr.getmaxyx()
        self.rows = max(1, self.h - 2)
        self.hw_cursor = None
        self.scr.erase()
        if self.buf.size:
            getattr(self, 'draw_' + self.mode)()
        else:
            self.put(1, 2, '<empty file>', self.A['bright'])
        self.draw_status()
        self.draw_keybar()
        if refresh:
            self.apply_cursor(self.hw_cursor)
            self.scr.refresh()

    def draw_status(self):
        A = self.A
        name = os.path.basename(self.buf.path)
        if self.mode == 'decode':
            mode = SHORT.get(self.arch, self.arch)
        else:
            mode = self.mode.capitalize()
        flag = 'Edit' if self.edit else ('R/O' if self.buf.readonly else 'View')
        if self.buf.modified:
            flag += '*'
        kind = self.info.desc or ''
        left = ' %s  %s  %s  %s' % (name, flag, mode, kind)
        if self.mode == 'text':
            left += '  %s%s' % (self.enc, ' wrap' if self.wrap else '')
        blk = self.block_range()
        if blk:
            left += '  Blk %s-%s' % (self.fmt_addr(blk[0]).strip(), self.fmt_addr(blk[1] - 1).strip())
        pos = self.position()
        pct = pos * 100 // max(1, self.buf.size - 1) if self.buf.size else 0
        right = ' %s  %3d%%  %X ' % (self.fmt_addr(pos), min(pct, 100), self.buf.size)
        self.put(0, 0, ' ' * self.w, A['status'])
        self.put(0, 0, left, A['status'])
        self.put(0, max(len(left) + 1, self.w - len(right)), right, A['status'])
        if self.msg:
            room = self.w - len(left) - len(right) - 4
            m = ' %s ' % self.msg
            if len(m) <= room:
                x = len(left) + 2
            else:   # long message: cover the file name part instead of cutting the text
                x = 1
                m = m[:max(10, self.w - len(right) - 2)]
                self.put(0, 0, ' ' * max(0, self.w - len(right)), A['status'])
            self.put(0, x, m, A['err'] if self.msg_err else A['msg'])

    def base_keybar_labels(self):
        labels = list(KEYBARS['edit' if self.edit else self.mode])
        if self.mode == 'text' and self.wrap:
            labels[1] = 'Unwrap'
        return labels

    def draw_keybar(self):
        A = self.A
        labels = self.keybar_labels()
        n = 12 if self.w >= 110 else 10
        slot = max(3, self.w // n)
        y = self.h - 1
        self.put(y, 0, ' ' * self.w, A['keylbl'])
        for i in range(n):
            x = i * slot
            num = str(i + 1)
            self.put(y, x, num, A['keynum'])
            self.put(y, x + len(num), labels[i][:slot - len(num)].ljust(slot - len(num)), A['keylbl'])

    def cell_attr(self, off, blk, fnd):
        A = self.A
        if fnd and fnd[0] <= off < fnd[0] + fnd[1]:
            return A['found']
        if blk and blk[0] <= off < blk[1]:
            return A['block']
        if off in self.buf.patches:
            return A['mod']
        return self.marker_attr(off)

    def marker_attr(self, off):
        return self.A['norm']

    def draw_hex(self):
        A = self.A
        b = self.bpl()
        xh = self.adig + 3
        xa = xh + b * 3 + 1
        rows = self.rows
        top = self.top
        data = self.buf.read(top, b * rows)
        tbl = self.table()
        blk = self.block_range()
        fnd = self.found
        for r in range(rows):
            lo = top + r * b
            if lo >= self.buf.size:
                break
            y = r + 1
            self.put(y, 0, self.fmt_addr(lo) + ':', A['addr'])
            line = data[r * b:(r + 1) * b]
            for i, v in enumerate(line):
                off = lo + i
                at = self.cell_attr(off, blk, fnd)
                ha = aa = at
                if off == self.cur:
                    if self.edit:
                        ha, aa = (A['cursor2'], A['cursor']) if self.ascii_col else (A['cursor'], A['cursor2'])
                    else:
                        ha = aa = A['cursor']
                self.put(y, xh + i * 3, '%02X' % v, ha)
                if i < b - 1:
                    self.put(y, xh + i * 3 + 2, '-' if i % 4 == 3 else ' ', A['norm'])
                self.put(y, xa + i, tbl[v], aa)
        if self.edit and top <= self.cur < top + rows * b:
            r, i = divmod(self.cur - top, b)
            self.hw_cursor = (r + 1, xa + i if self.ascii_col else xh + i * 3 + self.nib)

    def draw_text(self):
        A = self.A
        off = self.top
        size = self.buf.size
        for r in range(self.rows):
            if off >= size:
                break
            nxt = self.next_line(off)
            data = self.buf.read(off, min(nxt - off, TEXT_LINE_MAX))
            s = self.render_text(data)
            hs = 0 if self.wrap else self.hscroll
            self.put(r + 1, 0, s[hs:hs + self.w], A['norm'])
            f = self.found
            if f and f[0] < off + len(data) and f[0] + f[1] > off:   # highlight the hit (also across a wrap)
                c0 = len(self.render_text(data[:max(0, f[0] - off)]))
                c1 = len(self.render_text(data[:f[0] - off + f[1]]))
                if c1 > hs:
                    self.put(r + 1, max(0, c0 - hs), s[max(c0, hs):c1][:max(0, self.w - max(0, c0 - hs))], A['found'])
            off = nxt
        self.text_bottom = off

    def draw_decode(self):
        A = self.A
        rows = self.rows
        lines = self.decode_at(self.top, rows)
        self.dlines = lines
        self._dl_top = self.top
        if self.dcur >= len(lines):
            self.dcur = max(0, len(lines) - 1)
        maxb = max(4, min(12, (self.w - 60) // 2))
        xb = self.adig + 3
        xm = xb + maxb * 2 + 1
        self.jtargets = {}
        nj = 1
        blk = self.block_range()
        fnd = self.found
        for r, ins in enumerate(lines):
            y = r + 1
            iscur = r == self.dcur and not self.edit
            cur_at = A['cursor']
            if iscur:
                self.put(y, 0, ' ' * self.w, cur_at)
            self.put(y, 0, self.fmt_addr(ins.off) + ':', cur_at if iscur else A['addr'])
            # bytes column
            shown = ins.raw[:maxb] if len(ins.raw) <= maxb else ins.raw[:maxb - 1]
            for j, bv in enumerate(shown):
                off = ins.off + j
                if iscur:
                    at = cur_at
                elif self.edit and off == self.cur:
                    at = A['cursor']
                else:
                    at = self.cell_attr(off, blk, fnd)
                self.put(y, xb + j * 2, '%02X' % bv, at)
            if len(ins.raw) > maxb:
                self.put(y, xb + len(shown) * 2, '+', cur_at if iscur else A['norm'])
            if self.edit and ins.off <= self.cur < ins.off + ins.size:
                j = self.cur - ins.off
                if j < len(shown):
                    self.hw_cursor = (y, xb + j * 2 + self.nib)
            # instruction
            kat = {'jmp': A['jump'], 'call': A['call'], 'ret': A['ret'], 'bad': A['bad']}.get(ins.kind, A['bright'])
            if iscur:
                kat = cur_at
            ops = self.fmt_ops(ins)
            text = '%-7s %s' % (ins.mnem, ops)
            self.put(y, xm, text, kat)
            x = xm + len(text)
            if ins.target is not None:
                toff = self.off_of(ins.target)
                if toff is not None and nj <= 35:
                    ch = '123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[nj - 1]
                    self.jtargets[ch] = toff
                    mark = ' --%s%s' % ('\u2191' if ins.target <= ins.addr else '\u2193', ch)
                    self.put(y, x, mark, cur_at if iscur else A['name'])
                    x += len(mark)
                    nj += 1
            label = self.label_at(ins)
            com = self.comments(ins)
            if label or com:
                x = max(x + 2, xm + 32) if x + 2 < self.w - 20 else x + 2
                if label:
                    t = '<%s>' % label
                    self.put(y, x, t, cur_at if iscur else A['name'])
                    x += len(t) + 1
                if com:
                    self.put(y, x, '; ' + com, cur_at if iscur else A['comment'])
        if not lines:
            self.put(1, 2, self.dis.error or 'nothing to decode', A['bad'])
        elif self.dis.error and rows > 2:
            self.set_msg(self.dis.error, True)

    # ------------------------------------------------------------ dialogs

    def box(self, y, x, h, w, title=''):
        A = self.A
        self.put(y, x, '\u2554' + '\u2550' * (w - 2) + '\u2557', A['dlgframe'])
        for i in range(1, h - 1):
            self.put(y + i, x, '\u2551', A['dlgframe'])
            self.put(y + i, x + 1, ' ' * (w - 2), A['dlg'])
            self.put(y + i, x + w - 1, '\u2551', A['dlgframe'])
        self.put(y + h - 1, x, '\u255a' + '\u2550' * (w - 2) + '\u255d', A['dlgframe'])
        if title:
            t = ' %s ' % title
            self.put(y, x + max(1, (w - len(t)) // 2), t[:w - 2], A['dlgtitle'])

    def confirm(self, text):
        while True:
            bw = min(self.w - 2, max(len(text) + 6, 30))
            y0, x0 = (self.h - 5) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, 5, bw, 'Confirm')
            self.put(y0 + 1, x0 + 3, text, self.A['dlg'])
            self.put(y0 + 3, x0 + 3, 'Y - yes,  N / Esc - no', self.A['dlghdr'])
            self.apply_cursor(None)
            self.scr.refresh()
            k = self.getkey()
            if k in ('y', 'Y', '\u043d', '\u041d'):   # Y on the Russian layout
                return True
            if k in ('n', 'N', '\u0442', '\u0422', 'ESC', 'F10', 'ENTER'):
                return False

    def input_dialog(self, title, initial='', width=60, hint='', select=False, history=None):
        le = LineEdit(initial)
        fresh = select and bool(initial)
        while True:
            bw = min(self.w - 2, max(width, len(hint) + 4))
            bh = 4 if hint else 3
            y0, x0 = (self.h - bh) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, bh, bw, title)
            fw = bw - 4
            vis, cx = le.view(fw)
            self.put(y0 + 1, x0 + 2, vis.ljust(fw), self.A['input'])
            if hint:
                self.put(y0 + 2, x0 + 2, hint[:fw], self.A['dlghdr'])
            self.apply_cursor((y0 + 1, x0 + 2 + cx))
            self.scr.refresh()
            k = self.getkey()
            if k == 'ENTER':
                self.apply_cursor(None)
                return le.text
            if k in ('ESC', 'F10'):
                self.apply_cursor(None)
                return None
            if k == 'PGDN' and history:
                r = self.list_dialog('History', [(h, h) for h in reversed(history)], filterable=False)
                if r is not None:
                    le.set(r)
                fresh = False
                continue
            if fresh and len(k) == 1 and k.isprintable():
                le.set('')   # typing replaces the suggested value, editing keys keep it
            fresh = False
            le.key(k)

    def list_dialog(self, title, items, sel=0, filterable=True, minw=30, extra_keys=(), skip_headers=False):
        flt = ''
        top = 0
        A = self.A
        while True:
            view = [it for it in items if flt.lower() in it[0].lower()] if flt else items
            longest = max((len(t) for t, _ in view), default=0)
            bw = min(self.w - 2, max(minw, len(title) + 6, longest + 4))
            bh = min(self.h - 2, max(len(view), 1) + 2)
            inner = max(1, bh - 2)
            sel = clamp(sel, 0, max(0, len(view) - 1))
            if sel < top:
                top = sel
            if sel >= top + inner:
                top = sel - inner + 1
            top = clamp(top, 0, max(0, len(view) - inner))
            y0, x0 = (self.h - bh) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, bh, bw, title)
            for i in range(inner):
                j = top + i
                if j >= len(view):
                    break
                t, v = view[j]
                at = A['dlgsel'] if j == sel else (A['dlg'] if v is not None else A['dlghdr'])
                self.put(y0 + 1 + i, x0 + 1, (' ' + t).ljust(bw - 2)[:bw - 2], at)
            if flt:
                self.put(y0 + bh - 1, x0 + 2, ' Filter: %s ' % flt, A['dlgtitle'])
            cnt = ' %d/%d ' % (sel + 1 if view else 0, len(view))
            self.put(y0 + bh - 1, x0 + bw - 1 - len(cnt), cnt, A['dlgframe'])
            self.apply_cursor(None)
            self.scr.refresh()
            k = self.getkey()
            if k in ('ESC', 'F10'):
                return None
            if k == 'ENTER':
                if view and view[sel][1] is not None:
                    return view[sel][1]
            elif k in ('UP', 'DOWN'):
                d = -1 if k == 'UP' else 1
                sel += d
                if skip_headers:   # menus: the cursor jumps over headings and blank lines
                    while 0 <= sel < len(view) and view[sel][1] is None:
                        sel += d
                    if not 0 <= sel < len(view):
                        sel -= d
                        while 0 <= sel < len(view) and view[sel][1] is None:
                            sel -= d
            elif k == 'PGUP':
                sel -= inner
            elif k == 'PGDN':
                sel += inner
            elif k in ('HOME', 'C-HOME'):
                sel = 0
            elif k in ('END', 'C-END'):
                sel = len(view) - 1
            elif k in extra_keys:
                return ('__key__', k, view[sel][1] if view else None)
            elif k == 'BS' and flt:
                flt = flt[:-1]
                sel = top = 0
            elif k == 'MOUSE':
                ev = self.mouse_event()
                if ev:
                    kind, mx, my = ev
                    if kind == 'up':
                        sel -= 3
                    elif kind == 'down':
                        sel += 3
                    elif kind == 'click' and y0 < my < y0 + bh - 1 and x0 < mx < x0 + bw - 1:
                        j = top + my - y0 - 1
                        if j == sel and view and view[sel][1] is not None:
                            return view[sel][1]
                        sel = j
            elif filterable and len(k) == 1 and k.isprintable():
                flt += k
                sel = top = 0

    def search_dialog(self, title='Search'):
        A = self.A
        fa = LineEdit(self.search_ascii)
        fh = LineEdit(self.search_hex)
        act = 0 if self.search_src == 'ascii' else 1
        src = self.search_src
        icase = self.search_icase
        while True:
            bw = min(self.w - 2, 74)
            bh = 6
            y0, x0 = (self.h - bh) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, bh, bw, title)
            fw = bw - 13
            cur = None
            for i, (lbl, le) in enumerate((('ASCII:', fa), ('Hex:', fh))):
                y = y0 + 1 + i
                self.put(y, x0 + 2, lbl, A['dlgtitle'] if act == i else A['dlg'])
                vis, cx = le.view(fw)
                self.put(y, x0 + 10, vis.ljust(fw), A['input'])
                if act == i:
                    cur = (y, x0 + 10 + cx)
            self.put(y0 + 4, x0 + 2, ('Tab: field   F2: ignore case [%s]   Enter: find   Esc: cancel'
                                      % ('x' if icase else ' '))[:bw - 4], A['dlghdr'])
            self.apply_cursor(cur)
            self.scr.refresh()
            k = self.getkey()
            if k in ('ESC', 'F10'):
                self.apply_cursor(None)
                return False
            if k in ('TAB', 'S-TAB', 'UP', 'DOWN'):
                act ^= 1
                continue
            if k == 'F2':
                icase = not icase
                continue
            if k == 'ENTER':
                self.apply_cursor(None)
                self.search_ascii, self.search_hex, self.search_icase, self.search_src = fa.text, fh.text, icase, src
                return self.build_search()
            le = fa if act == 0 else fh
            if act == 1 and len(k) == 1 and k not in HEX_CHARS:
                continue
            old = le.text
            le.key(k)
            if le.text == old:
                continue
            if act == 0:
                fh.set(' '.join('%02X' % b for b in self.encode_str(fa.text)))
                src = 'ascii'
            else:
                toks = parse_hex(fh.text)
                tbl = self.table()
                fa.set(''.join('?' if t is None else tbl[t] for t in toks) if toks else '')
                src = 'hex'

    def build_search(self):
        if self.search_src == 'ascii':
            text = self.search_ascii
            if not text:
                return False
            parts = []
            for ch in text:
                vs = {ch, ch.lower(), ch.upper()} if self.search_icase else {ch}
                encs = sorted({self.encode_str(v) for v in vs})
                if len(encs) > 1:
                    parts.append(b'(?:' + b'|'.join(re.escape(e) for e in encs) + b')')
                else:
                    parts.append(re.escape(encs[0]))
            rx = re.compile(b''.join(parts), re.DOTALL)
            self.search = (rx, len(self.encode_str(text)), '"%s"' % text)
        else:
            toks = parse_hex(self.search_hex)
            if not toks:
                self.set_msg('Bad hex string', True)
                return False
            pat = b''.join(b'.' if t is None else re.escape(bytes([t])) for t in toks)
            self.search = (re.compile(pat, re.DOTALL), len(toks), self.search_hex)
        return True

    # ------------------------------------------------------------ positioning

    def push_pos(self):
        self.jumps.append((self.mode, self.top, self.cur, self.dcur))
        del self.jumps[:-256]

    def pop_pos(self):
        if not self.jumps:
            self.set_msg('Jump stack is empty')
            return
        self.mode, self.top, self.cur, self.dcur = self.jumps.pop()
        self.ensure_cursor()

    def goto(self, off, mode=None, push=True):
        if push:
            self.push_pos()
        if mode:
            self.mode = mode
        off = clamp(off, 0, max(0, self.buf.size - 1))
        if self.mode == 'hex':
            b = self.bpl()
            self.cur = off
            self.top = off - off % b
            self.ensure_cursor()
        elif self.mode == 'decode':
            self.top = off
            self.dcur = 0
        else:
            self.top = self.line_start(off)
            self.hscroll = 0

    def set_mode(self, mode):
        if mode != self.mode:
            pos = self.position()
            if self.mode == 'text' and self.text_anchor is not None and self.line_start(self.text_anchor) == self.top:
                pos = self.text_anchor   # Text shows whole lines; don't lose the exact address (Text->Hex->Decode)
            self.goto(pos, mode, push=False)
            if mode == 'text':
                self.text_anchor = pos

    def ensure_cursor(self):
        if self.mode != 'hex' or not self.buf.size:
            return
        b = self.bpl()
        rows = max(1, self.h - 2)
        self.cur = clamp(self.cur, 0, self.buf.size - 1)
        a = self.top % b
        if self.cur < self.top:
            self.top = max(0, a + ((self.cur - a) // b) * b)
        elif self.cur >= self.top + rows * b:
            self.top = max(0, a + ((self.cur - a) // b - rows + 1) * b)

    def parse_target(self, s):
        s = s.strip()
        if not s:
            raise ValueError('Empty address')
        orig = s
        va = False
        if s[0] == '.':
            va = True
            s = s[1:].strip()
        sign = 0
        if s[:1] in ('+', '-'):
            sign = 1 if s[0] == '+' else -1
            s = s[1:].strip()
        t = s.lower().replace('_', '').replace(' ', '')
        if t.startswith('0x'):
            t = t[2:]
        if t.endswith('h'):
            t = t[:-1]
        try:
            v = int(t, 16)
        except ValueError:
            if self._byname is None:
                self._byname = {n: a for a, n in self.info.symbols.items()}
            a = self._byname.get(orig)
            if a is None:
                raise ValueError('Bad address: ' + orig)
            off = self.off_of(a)
            if off is None:
                raise ValueError('Symbol %s is not in file' % orig)
            return off
        pos = self.position()
        if sign and va:
            off = self.off_of(self.va_of(pos) + sign * v)
        elif sign:
            off = pos + sign * v
        elif va:
            off = self.off_of(v)
        else:
            off = v
        if off is None:
            raise ValueError('Address .%X is not in file' % v)
        if not 0 <= off < max(1, self.buf.size):
            raise ValueError('Offset %X is out of file' % off)
        return off

    # ------------------------------------------------------------ main loop

    def run(self):
        try:
            while True:
                self.draw()
                k = self.getkey(main=True)
                if k == 'RESIZE':
                    continue
                self.msg = None
                if self.handle(k) is False:
                    return
        finally:
            if self.kitty:
                kitty_disable()

    def handle(self, k):
        if k == 'MOUSE':
            return self.handle_mouse()
        k = self.translate_key(k)
        if k is None:
            return True
        k = self.apply_layer(k)
        if k is None:
            return True
        if self.edit:
            r = self.handle_edit_extra(k)
            return r if r is not None else self.handle_edit(k)
        r = self.handle_view_extra(k)
        if r is not None:
            return r
        m = self.mode
        if k in ('F10', 'ESC'):
            return False
        if k == 'F1':
            self.list_dialog('Help', [(l, None) for l in HELP.splitlines()], filterable=True)
        elif k == 'ENTER':
            self.set_mode(MODES[(MODES.index(m) + 1) % 3])
        elif k == 'F4':
            self.mode_menu()
        elif k == 'F3':
            self.start_edit()
        elif k == 'F5':
            s = self.input_dialog('Goto', '', 50, 'hex offset, .VA, +rel, -rel or symbol name')
            if s:
                try:
                    self.goto(self.parse_target(s))
                except ValueError as e:
                    self.set_msg(str(e), True)
        elif k == 'F7':
            if self.search_dialog():
                self.do_search()
        elif k in ('C-F7', 'C-n'):
            self.do_search()
        elif k in ('S-F7', 'C-p'):
            self.do_search(backward=True)
        elif k == 'F8':
            if m == 'text':
                self.enc = ENCODINGS[(ENCODINGS.index(self.enc) + 1) % len(ENCODINGS)]
                self.set_msg('Codepage: ' + self.enc)
            else:
                self.header_window()
        elif k == 'F9':
            s = self.input_dialog('Open file', os.path.dirname(self.buf.path) + os.sep, 70)
            if s:
                try:
                    self.load(os.path.expanduser(s))
                except OSError as e:
                    self.set_msg(str(e), True)
        elif k == 'F12':
            self.names_window()
        elif k in ('A-F1', 'A-a'):
            if self.info.segments:
                self.show_va = not self.show_va
                self.set_msg('Addresses: ' + ('virtual (.VA)' if self.show_va else 'file offsets'))
            else:
                self.set_msg('No virtual addresses in this file')
        elif k == 'BS':
            self.pop_pos()
        elif k == '+':
            self.bookmarks.append((self.mode, self.position()))
            del self.bookmarks[:-16]
            self.set_msg('Bookmark %d set' % len(self.bookmarks))
        elif k == '-':
            self.bookmark_window()
        elif k == '*' and m != 'text':
            self.mark_block()
        elif k == 'F2':
            if m == 'text':
                pos = self.top
                self.wrap = not self.wrap
                self.top = self.line_start(pos)
                self.hscroll = 0
            elif m == 'hex':
                self.put_block()
            else:
                nxt = BITS_CYCLE.get(self.arch)
                if nxt:
                    self.arch = nxt
                    self.make_dis()
                else:
                    self.set_msg('No alternate mode for ' + self.arch)
        elif k == 'F6' and m == 'decode':
            self.refs_window()
        elif m == 'decode' and len(k) == 1 and k.upper() in self.jtargets:
            self.goto(self.jtargets[k.upper()])
        elif self.buf.size:
            getattr(self, 'nav_' + m)(k)
        return True

    # ------------------------------------------------------------ navigation

    def nav_hex(self, k):
        b = self.bpl()
        page = b * self.rows
        size = self.buf.size
        c = self.cur
        if k == 'UP':
            if c - b >= 0:
                self.cur = c - b
        elif k == 'DOWN':
            if c + b < size:
                self.cur = c + b
        elif k in ('LEFT', 'S-TAB'):
            self.cur = c - 1
        elif k in ('RIGHT', 'TAB'):
            self.cur = c + 1
        elif k == 'PGUP':
            self.top = max(0, self.top - page)
            self.cur = max(0, c - page)
        elif k == 'PGDN':
            if self.top + page < size:
                self.top += page
                self.cur = min(size - 1, c + page)
            else:
                self.cur = size - 1
        elif k == 'HOME':
            self.cur = c - (c - self.top) % b
        elif k == 'END':
            self.cur = c - (c - self.top) % b + b - 1
        elif k in ('C-HOME', 'C-PGUP'):
            self.top = self.cur = 0
        elif k in ('C-END', 'C-PGDN'):
            self.cur = size - 1
        elif k == 'C-LEFT':
            if self.top > 0:
                self.top -= 1
                self.cur = max(0, c - 1)
        elif k == 'C-RIGHT':
            if self.top + 1 < size:
                self.top += 1
                self.cur = min(size - 1, c + 1)
        else:
            return False
        self.cur = clamp(self.cur, 0, size - 1)
        self.ensure_cursor()
        return True

    def nav_text(self, k):
        size = self.buf.size
        if k == 'UP':
            self.top = self.prev_line(self.top)
        elif k == 'DOWN':
            n = self.next_line(self.top)
            if n < size:
                self.top = n
        elif k == 'PGUP':
            for _ in range(self.rows):
                self.top = self.prev_line(self.top)
        elif k == 'PGDN':
            if getattr(self, 'text_bottom', size) < size:
                self.top = self.text_bottom
        elif k in ('C-HOME', 'C-PGUP'):
            self.top = 0
            self.hscroll = 0
        elif k in ('C-END', 'C-PGDN'):
            t = self.line_start(size - 1)
            for _ in range(self.rows - 1):
                t = self.prev_line(t)
            self.top = t
        elif k == 'LEFT' and not self.wrap:
            self.hscroll = max(0, self.hscroll - 1)
        elif k == 'RIGHT' and not self.wrap:
            self.hscroll += 1
        elif k == 'C-LEFT' and not self.wrap:
            self.hscroll = max(0, self.hscroll - 20)
        elif k == 'C-RIGHT' and not self.wrap:
            self.hscroll += 20
        elif k == 'HOME':
            self.hscroll = 0
        else:
            return False
        return True

    def nav_decode(self, k):
        lines = self.dlines if self._dl_top == self.top else self.decode_at(self.top, self.rows)
        n = len(lines)
        size = self.buf.size
        if k == 'UP':
            if self.dcur > 0:
                self.dcur -= 1
            else:
                self.top = self.prev_insn(self.top)
        elif k == 'DOWN':
            if self.dcur < n - 1 and self.dcur < self.rows - 1:
                self.dcur += 1
            elif n > 1 and lines[-1].off + lines[-1].size < size:
                self.top = lines[1].off
        elif k == 'PGDN':
            if n and lines[-1].off + lines[-1].size < size:
                self.top = lines[-1].off + lines[-1].size if n < self.rows else lines[-1].off
        elif k == 'PGUP':
            for _ in range(self.rows - 1):
                self.top = self.prev_insn(self.top)
        elif k in ('C-HOME', 'C-PGUP'):
            self.top = 0
            self.dcur = 0
        elif k in ('C-END', 'C-PGDN'):
            t = self.prev_insn(size)
            for _ in range(self.rows - 1):
                t = self.prev_insn(t)
            self.top = t
            self.dcur = self.rows - 1
        elif k == 'C-LEFT':
            self.top = max(0, self.top - 1)
        elif k == 'C-RIGHT':
            self.top = min(size - 1, self.top + 1)
        elif k == 'HOME':
            self.dcur = 0
        elif k == 'END':
            self.dcur = n - 1
        else:
            return False
        return True

    # ------------------------------------------------------------ mouse

    def mouse_event(self):
        try:
            _, mx, my, _, bs = curses.getmouse()
        except curses.error:
            # old ncurses (mouse protocol v1, e.g. macOS system Python) can't encode button 5,
            # so wheel-down arrives as an undecodable event
            return ('down', 0, 0) if not hasattr(curses, 'BUTTON5_PRESSED') else None
        if bs & getattr(curses, 'BUTTON4_PRESSED', 0x80000):
            return 'up', mx, my
        if bs & getattr(curses, 'BUTTON5_PRESSED', 0x200000):
            return 'down', mx, my
        if bs & (curses.BUTTON1_PRESSED | curses.BUTTON1_CLICKED | getattr(curses, 'BUTTON1_DOUBLE_CLICKED', 0)):
            return 'click', mx, my
        return None

    def handle_mouse(self):
        ev = self.mouse_event()
        if not ev:
            return True
        kind, mx, my = ev
        if kind in ('up', 'down'):
            key = 'UP' if kind == 'up' else 'DOWN'
            for _ in range(3):
                if self.mode == 'hex':
                    b = self.bpl()
                    if kind == 'up' and self.top >= b:
                        self.top -= b
                        self.cur -= b
                    elif kind == 'down' and self.top + b * self.rows < self.buf.size:
                        self.top += b
                        self.cur = min(self.buf.size - 1, self.cur + b)
                elif self.mode == 'decode' and not self.edit:
                    if kind == 'up':
                        self.top = self.prev_insn(self.top)
                    else:
                        lines = self.decode_at(self.top, 2)
                        if len(lines) > 1:
                            self.top = lines[1].off
                elif not self.edit:
                    self.nav_text(key)
            return True
        if my == self.h - 1:
            n = 12 if self.w >= 110 else 10
            idx = mx // max(3, self.w // n)
            if idx < n:
                return self.handle('F%d' % (idx + 1))
            return True
        row = my - 1
        if not 0 <= row < self.rows:
            return True
        if self.mode == 'hex':
            b = self.bpl()
            xh = self.adig + 3
            xa = xh + b * 3 + 1
            i = None
            if xh <= mx < xh + b * 3:
                i = (mx - xh) // 3
                if self.edit:
                    self.ascii_col = False
            elif xa <= mx < xa + b:
                i = mx - xa
                if self.edit:
                    self.ascii_col = True
            if i is not None and self.top + row * b + i < self.buf.size:
                self.cur = self.top + row * b + i
                self.nib = 0
        elif self.mode == 'decode':
            if row < len(self.dlines):
                if self.edit:
                    self.cur = self.dlines[row].off
                    self.nib = 0
                else:
                    self.dcur = row
        return True

    # ------------------------------------------------------------ windows

    def mode_menu(self):
        items = [('Text', ('mode', 'text')), ('Hex', ('mode', 'hex')), ('Decode', ('mode', 'decode')),
                 ('', None), ('Decode architecture:', None)]
        for a in ARCHS:
            items.append(('  %s %-8s %s' % ('*' if a == self.arch else ' ', a, SHORT[a]), ('arch', a)))
        items += [('', None), ('Codepage:', None)]
        for e in ENCODINGS:
            items.append(('  %s %s' % ('*' if e == self.enc else ' ', e), ('enc', e)))
        from .themes import THEMES
        items += [('', None), ('Theme:', None)]
        for t in THEMES:
            items.append(('  %s %s' % ('*' if t == self.theme else ' ', t), ('theme', t)))
        r = self.list_dialog('Mode', items, sel=MODES.index(self.mode), filterable=False, skip_headers=True)
        if not r:
            return
        what, val = r
        if what == 'mode':
            self.set_mode(val)
        elif what == 'arch':
            self.arch = val
            self.make_dis()
            self.set_mode('decode')
        elif what == 'theme':
            self.set_theme(val)
        else:
            self.enc = val

    def header_window(self):
        info = self.info
        items = [('File: %s' % self.buf.path, None),
                 ('Size: %d bytes (%X)' % (self.buf.size, self.buf.size), None)]
        if info.entry_off is not None:
            items.append(('Entry: %s  (Enter = go)' % self.fmt_addr(info.entry_off), (info.entry_off, 'decode')))
        items.append(('', None))
        items += info.header or [('Unknown format: raw binary', None)]
        sel = 2 if info.entry_off is not None else 0
        r = self.list_dialog('Header %s' % (info.desc or ''), items, sel=sel)
        if r and r[0] is not None:
            self.goto(r[0], r[1])

    def names_window(self):
        items = []
        for va, nm in sorted(self.info.symbols.items()):
            off = self.off_of(va)
            if off is not None:
                items.append(('%s  %s' % (self.disp_va(va), nm), off))
        if not items:
            self.set_msg('No names in this file')
            return
        r = self.list_dialog('Names (%d) - type to filter' % len(items), items)
        if r is not None:
            self.goto(r, 'decode')

    def bookmark_window(self):
        if not self.bookmarks:
            self.set_msg('No bookmarks (Gray+ to set)')
            return
        items = [('%2d  %-6s %s' % (i + 1, m, self.fmt_addr(o)), (m, o)) for i, (m, o) in enumerate(self.bookmarks)]
        r = self.list_dialog('Bookmarks', items, sel=len(items) - 1, filterable=False)
        if r:
            self.goto(r[1], r[0])

    def refs_window(self):
        if self.dis.lite is None:
            self.set_msg(self.dis.error or 'No disassembler', True)
            return
        target = self.va_of(self.position())
        hexs = '0x%x' % target
        regions = [(s.off, s.size, s.va) for s in self.info.sections if s.exec_ and s.size]
        if not regions:
            regions = [(0, self.buf.size, self.va_of(0))]
        self.flash('Searching references to %s ...' % self.disp_va(target))
        self.msg = None
        refs = []
        x86 = self.dis.x86
        for off, size, sva in regions:
            size = min(size, self.buf.size - off, 64 << 20)
            if size <= 0:
                continue
            data = self.buf.read(off, size)
            for a, s, mn, op in self.dis.sweep(data, sva):
                hit = False
                if hexs in op:
                    hit = any(int(h, 16) == target for h in HEX_RE.findall(op))
                elif x86 and 'rip' in op:
                    m = RIP_RE.search(op)
                    if m:
                        d = int(m.group(2), 0)
                        hit = a + s + (d if m.group(1) == '+' else -d) == target
                if hit:
                    refs.append((off + a - sva, a, mn, op))
                    if len(refs) >= 2000:
                        break
        if not refs:
            self.set_msg('No references to %s' % self.disp_va(target))
            return
        disp = self.disp_va(target)
        items = [('%s  %-7s %s' % (self.disp_va(a), mn, re.sub(r'#?\b%s\b' % hexs, disp, op)), o)
                 for o, a, mn, op in refs]
        r = self.list_dialog('References to %s (%d)' % (self.disp_va(target), len(refs)), items)
        if r is not None:
            self.goto(r, 'decode')

    def mark_block(self):
        pos = self.position()
        if self.block_start is None:
            self.block = None
            self.block_start = pos
            self.set_msg('Block start %s, press * again at the end' % self.fmt_addr(pos))
        else:
            a, b = sorted((self.block_start, pos))
            self.block = (a, b + 1)
            self.block_start = None
            self.set_msg('Block ' + nbytes(b + 1 - a))

    def put_block(self):
        blk = self.block_range()
        if not blk:
            self.set_msg('No block marked (use *)', True)
            return
        name = self.input_dialog('Write block of %s to file' % nbytes(blk[1] - blk[0]), 'block.bin', 60, select=True)
        if not name:
            return
        try:
            with open(os.path.expanduser(name), 'wb') as f:
                pos = blk[0]
                while pos < blk[1]:
                    n = min(1 << 20, blk[1] - pos)
                    f.write(self.buf.read(pos, n))
                    pos += n
            self.set_msg('Written %s to %s' % (nbytes(blk[1] - blk[0]), name))
        except OSError as e:
            self.set_msg(str(e), True)

    def do_search(self, backward=False):
        if not self.search:
            self.set_msg('No search pattern, press F7', True)
            return
        rx, plen, desc = self.search
        pos = self.position()
        if self.found and getattr(self, '_found_at', None) == (self.mode, pos):
            pos = self.found[0]   # continue from the previous hit, not from the line/screen start
        self.flash('Searching %s ...' % desc)
        off = self.buf.find(rx, plen, pos if backward else pos + 1, backward)
        if off is None:
            self.set_msg('Not found: %s' % desc, True)
            return
        self.found = (off, plen)
        self.msg = None
        if self.mode == 'hex':
            self.cur = off
            self.ensure_cursor()
        else:
            self.goto(off, push=False)
        self._found_at = (self.mode, self.position())

    # ------------------------------------------------------------ editing

    def start_edit(self):
        if not self.buf.size:
            self.set_msg('Empty file', True)
            return
        self.edit_ret = self.mode
        if self.mode == 'text':
            self.set_mode('hex')
        if self.mode == 'decode':
            self.cur = self.position()
        self.edit = True
        self.nib = 0
        self.ascii_col = False
        self.found = None
        if self.buf.readonly:
            self.set_msg('Warning: file is read-only, F9 will fail', True)
        elif self.mode == 'decode':
            self.set_msg('0-9 A-F edit bytes; Enter/F2 - assembler; F9 - write; Esc - cancel')

    def end_edit(self):
        self.edit = False
        self.nib = 0
        self._names = {}
        if self.edit_ret == 'text':
            self.set_mode('text')
        elif self.mode == 'decode':
            self.dcur = 0
            for i, ins in enumerate(self.dlines):
                if ins.off <= self.cur < ins.off + ins.size:
                    self.dcur = i

    def handle_edit(self, k):
        size = self.buf.size
        if k in ('ESC', 'F10'):
            if self.buf.modified and not self.confirm('Discard %s of changes?' % nbytes(len(self.buf.patches))):
                return True
            self.buf.discard()
            self.end_edit()
        elif k == 'F9':
            try:
                n = self.buf.save()
                self.set_msg('Updated ' + nbytes(n))
                self.end_edit()
            except OSError as e:
                self.set_msg('Write failed: %s' % e, True)
        elif k == 'F1':
            self.list_dialog('Help', [(l, None) for l in HELP.splitlines()])
        elif k == 'F3':
            off = self.buf.undo()
            if off is not None:
                self.edit_move(off)
        elif k == 'F2':
            self.asm_here()
        elif k == 'F8':
            self.xor_here()
        elif k == 'F5':
            s = self.input_dialog('Goto', '', 50, 'hex offset, .VA, +rel, -rel or symbol name')
            if s:
                try:
                    self.edit_move(self.parse_target(s))
                except ValueError as e:
                    self.set_msg(str(e), True)
        elif k == 'TAB' and self.mode == 'hex':
            self.ascii_col = not self.ascii_col
            self.nib = 0
        elif k == 'BS':
            if self.nib:
                self.nib = 0
            else:
                self.edit_move(self.cur - 1)
        elif self.mode == 'hex' and self.ascii_col and len(k) == 1 and k.isprintable():
            data = self.encode_str(k)
            self.buf.write_bytes(self.cur, data)
            self.edit_move(self.cur + len(data))
        elif len(k) == 1 and k in '0123456789abcdefABCDEF':
            v = int(k, 16)
            old = self.buf.byte(self.cur)
            new = (v << 4) | (old & 0x0F) if self.nib == 0 else (old & 0xF0) | v
            self.buf.write(self.cur, new, merge=self.nib == 1)
            if self.nib == 0:
                self.nib = 1
            else:
                self.nib = 0
                if self.cur + 1 < size:
                    self.edit_move(self.cur + 1)
        elif self.mode == 'hex':
            if self.nav_hex(k):
                self.nib = 0
        else:
            self.nav_decode_edit(k)
        return True

    def edit_move(self, off):
        off = clamp(off, 0, self.buf.size - 1)
        self.cur = off
        self.nib = 0
        if self.mode == 'hex':
            self.ensure_cursor()
            return
        lines = self.dlines if self._dl_top == self.top else self.decode_at(self.top, self.rows)
        if off < self.top:
            for _ in range(32):
                self.top = self.prev_insn(self.top)
                if self.top <= off:
                    return
            self.top = off
        elif lines and off >= lines[-1].off + lines[-1].size and len(lines) >= self.rows:
            if off < lines[-1].off + lines[-1].size + 16 and len(lines) > 1:
                self.top = lines[1].off
            else:
                self.top = off

    def nav_decode_edit(self, k):
        lines = self.dlines if self._dl_top == self.top else self.decode_at(self.top, self.rows)
        idx = next((i for i, l in enumerate(lines) if l.off <= self.cur < l.off + l.size), None)
        if idx is None:
            self.top = self.cur
            return
        col = self.cur - lines[idx].off
        if k == 'LEFT':
            self.edit_move(self.cur - 1)
        elif k == 'RIGHT':
            self.edit_move(self.cur + 1)
        elif k == 'UP':
            if idx > 0:
                p = lines[idx - 1]
                self.edit_move(p.off + min(col, p.size - 1))
            elif self.top > 0:
                self.top = self.prev_insn(self.top)
                p = self.decode_at(self.top, 1)[0]
                self.edit_move(p.off + min(col, p.size - 1))
        elif k == 'DOWN':
            if idx < len(lines) - 1:
                p = lines[idx + 1]
                self.edit_move(p.off + min(col, p.size - 1))
            elif lines[idx].off + lines[idx].size < self.buf.size:
                self.edit_move(lines[idx].off + lines[idx].size)   # scrolls the view by one line
        elif k == 'HOME':
            self.edit_move(lines[idx].off)
        elif k == 'END':
            self.edit_move(lines[idx].off + lines[idx].size - 1)
        elif k == 'PGDN':
            if lines:
                self.top = lines[-1].off
                self.edit_move(self.top)
        elif k == 'PGUP':
            for _ in range(self.rows - 1):
                self.top = self.prev_insn(self.top)
            self.edit_move(self.top)
        elif k in ('C-HOME', 'C-PGUP'):
            self.top = 0
            self.edit_move(0)
        elif k in ('C-LEFT', 'C-RIGHT'):
            self.top = clamp(self.top + (1 if k == 'C-RIGHT' else -1), 0, self.buf.size - 1)
            self.edit_move(max(self.cur, self.top))

    def asm_here(self, initial=None):
        if not HAVE_KS:
            self.set_msg('Assembler needs keystone: ' + KS_HINT, True)
            return
        lst = self.decode_at(self.cur, 1)
        default = ('%s %s' % (lst[0].mnem, lst[0].ops)).strip() if lst and lst[0].kind != 'bad' else ''
        va = self.va_of(self.cur)
        if initial is not None:
            default = initial
        s = self.input_dialog('Assemble at %s' % self.fmt_addr(self.cur), default, 60,
                              'e.g.  jmp 0x401000 ; nop ; xor eax, eax', select=initial is None)
        if not s:
            return
        try:
            code = assemble(self.arch, s, va, self.info.endian == '>')
        except Exception as e:
            self.set_msg('Asm: %s' % e, True)
            return
        self.buf.write_bytes(self.cur, code)
        self.edit_move(self.cur + len(code))

    def xor_here(self):
        s = self.input_dialog('XOR with hex bytes', self.xor_key, 50,
                              'applied to the marked block, or at cursor')
        if not s:
            return
        key = parse_hex(s, wildcards=False)
        if not key:
            self.set_msg('Bad hex key', True)
            return
        self.xor_key = s
        blk = self.block_range()
        if blk:
            a, b = blk
        else:
            a, b = self.cur, min(self.buf.size, self.cur + len(key))
        data = self.buf.read(a, b - a)
        self.buf.write_bytes(a, bytes(v ^ key[i % len(key)] for i, v in enumerate(data)))
        if not blk:
            self.edit_move(min(b, self.buf.size - 1))
        self.set_msg('XOR applied to ' + nbytes(b - a))
