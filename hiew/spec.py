"""Hotkeys as described by the Hiew Documentation Project (https://taviso.github.io/hiewdocs/).

The Hiew class layers these on top of App: blocks (* Ctrl* Alt* AltM AltN [ ] Ins),
bookmarks (+ - Alt- Alt0 Alt1..8), macros (Ctrl. Ctrl0..8 Ctrl-), Ctrl F1 / Shift F1,
F6 / Ctrl F6 references, / resync, Tab / Ctrl F11 / Ctrl F12 / Ctrl BkSp files,
the F7 search dialog keys, Alt F6 strings, ; comments, Shift F12 names, F8 sub-tables,
Alt B, Alt P, Shift F4, Alt =, Ctrl Alt, Esc / F10 timestamps.
"""
import curses
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import time
from collections import deque

from . import keys as K
from .app import App, LineEdit, VERSION, nbytes, parse_hex, clamp, HEX_CHARS
from .disasm import ARCHS, BITS_CYCLE, HAVE_KS, KS_HINT, SHORT, assemble
from .extra import Crypt, EDIT_KEYBAR, LAYER_NAMES, NOPS

# ------------------------------------------------------------------ keybars

VIEW_KEYBARS = {
    'text': ['Help', 'Wrap', 'Edit', 'Mode', 'Goto', '', 'Search', 'Xlat', 'Files', 'Quit', '', 'Names'],
    'hex': ['Help', 'PutBlk', 'Edit', 'Mode', 'Goto', '', 'Search', 'Header', 'Files', 'Quit', '', 'Names'],
    'decode': ['Help', 'PutBlk', 'Edit', 'Mode', 'Goto', 'Refer', 'Search', 'Header', 'Files', 'Quit', '', 'Names'],
}
LAYERS = {
    'view': {
        'A': ['Global', 'FilBlk', 'Crypt', 'ReLoad', '', 'String', 'Direct', 'Table', '', 'Leave', 'WHex', 'DHex'],
        'C': ['OpSize', 'GetBlk', 'Replac', 'ReRead', '', 'NxtRef', 'Next', '', '', '', 'PrvFil', 'NxtFil'],
        'S': ['Arch', 'DelBlk', 'InsByt', 'PrnBlk', 'CpyBlk', 'MovBlk', 'Next', '', 'FolDwd', 'FolQwd', 'FolWrd',
              'Name'],
    },
    'edit': {
        'A': ['', 'NOPs', 'Crypt', '', '', '', '', 'Table', '', '', '', ''],
        'C': ['', 'GetBlk', '', '', '', '', 'CrySet', 'XorSet', '', '', '', ''],
        'S': ['', '', '', '', 'CpyBlk', 'MovBlk', '', '', '', '', '', ''],
    },
}

MARK_COLORS_256 = [160, 28, 94, 92, 30, 166, 25, 95, 125, 64, 130, 61]
MARK_COLORS_8 = [curses.COLOR_RED, curses.COLOR_GREEN, curses.COLOR_YELLOW, curses.COLOR_MAGENTA,
                 curses.COLOR_CYAN, curses.COLOR_WHITE]
MARKER_PAIR0 = 60


def config_dir():
    if sys.platform.startswith('win'):
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
    else:
        base = os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')
    return os.path.join(base, 'hiew')



# ------------------------------------------------------------------ calculator (Hiew syntax)

class CalcError(ValueError):
    pass


_TOKEN = re.compile(r'\s*(?:(@[bBwWdDqQoO])|(\$)|([0-9a-zA-Z_]+)|(<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%~&^|!<>()]))')
_BINARY = [('||',), ('&&',), ('|',), ('^',), ('&',), ('==', '!='), ('<', '<=', '>', '>='), ('<<', '>>'),
           ('+', '-'), ('*', '/', '%')]
MASK64 = (1 << 64) - 1


def parse_number(tok, octal_zero=True):
    """Hiew number: default base hex; 0x.. hex, 0.. octal (calculator only), suffix t dec, h hex, o oct, i bin."""
    t = tok.lower()
    try:
        if t.startswith('0x'):
            return int(t[2:], 16)
        if t.endswith('t') and t[:-1].isdigit():
            return int(t[:-1], 10)
        if t.endswith('h') and len(t) > 1:
            return int(t[:-1], 16)
        if t.endswith('o') and len(t) > 1:
            return int(t[:-1], 8)
        if t.endswith('i') and len(t) > 1 and set(t[:-1]) <= set('01'):
            return int(t[:-1], 2)
        if octal_zero and len(t) > 1 and t[0] == '0' and set(t) <= set('01234567'):
            return int(t, 8)
        return int(t, 16)
    except ValueError:
        raise CalcError('bad number: ' + tok)


class Calc:
    """C-like 64-bit expression evaluator; read(code) supplies @b @B @w @W @d @D @q @Q @o @O."""

    def __init__(self, read, names=None, octal_zero=True):
        self.read = read
        self.names = names or {}
        self.octal_zero = octal_zero

    def eval(self, s):
        self.toks = []
        pos = 0
        s = s.rstrip()
        while pos < len(s):
            m = _TOKEN.match(s, pos)
            if not m or m.end() == pos:
                raise CalcError('unexpected "%s"' % s[pos:pos + 8])
            self.toks.append(m.group(m.lastindex) if m.lastindex else '')
            pos = m.end()
        if not self.toks:
            raise CalcError('empty')
        self.i = 0
        v = self.binary(0)
        if self.i != len(self.toks):
            raise CalcError('unexpected "%s"' % self.toks[self.i])
        return v & MASK64

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self):
        t = self.peek()
        self.i += 1
        return t

    def binary(self, level):
        if level == len(_BINARY):
            return self.unary()
        v = self.binary(level + 1)
        while self.peek() in _BINARY[level]:
            op = self.take()
            r = self.binary(level + 1)
            v = self.apply(op, v, r)
        return v

    @staticmethod
    def apply(op, a, b):
        a &= MASK64
        b &= MASK64
        if op in ('/', '%') and b == 0:
            raise CalcError('division by zero')
        return {
            '||': lambda: int(bool(a) or bool(b)), '&&': lambda: int(bool(a) and bool(b)),
            '|': lambda: a | b, '^': lambda: a ^ b, '&': lambda: a & b,
            '==': lambda: int(a == b), '!=': lambda: int(a != b), '<': lambda: int(a < b),
            '<=': lambda: int(a <= b), '>': lambda: int(a > b), '>=': lambda: int(a >= b),
            '<<': lambda: a << (b & 63), '>>': lambda: a >> (b & 63),
            '+': lambda: a + b, '-': lambda: a - b, '*': lambda: a * b, '/': lambda: a // b, '%': lambda: a % b,
        }[op]() & MASK64

    def unary(self):
        t = self.peek()
        if t in ('-', '+', '~', '!'):
            self.take()
            v = self.unary()
            return {'-': -v, '+': v, '~': ~v, '!': int(not v)}[t] & MASK64
        return self.primary()

    def primary(self):
        t = self.take()
        if t is None:
            raise CalcError('unexpected end')
        if t == '(':
            v = self.binary(0)
            if self.take() != ')':
                raise CalcError('missing )')
            return v
        if t.startswith('@'):
            return self.read(t[1]) & MASK64
        if t == '$':
            return self.names['$'] & MASK64
        if t in self.names:
            return self.names[t] & MASK64
        if t[0].isalnum():
            return parse_number(t, self.octal_zero)
        raise CalcError('unexpected "%s"' % t)


def calc_lines(v):
    s64 = v - (1 << 64) if v >> 63 else v
    lines = ['Hex  %X' % v, 'Dec  %d' % v + ('   signed %d' % s64 if s64 < 0 else ''),
             'Oct  %o' % v, 'Bin  %s' % format(v, 'b')[-64:]]
    raw = v.to_bytes(8, 'big').lstrip(b'\0') or b'\0'
    lines.append('Chr  "%s"' % ''.join(chr(c) if 32 <= c < 127 else '.' for c in raw))
    return lines


# ------------------------------------------------------------------ clipboard

def to_clipboard(text):
    for cmd in (['pbcopy'], ['clip'], ['wl-copy'], ['xclip', '-selection', 'clipboard'], ['xsel', '-ib']):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode('utf-16le' if cmd[0] == 'clip' else 'utf-8'),
                               check=True, timeout=5)
                return True
            except (OSError, subprocess.SubprocessError):
                continue
    return False


# ------------------------------------------------------------------ the application

class Hiew(App):
    def __init__(self, scr, path, opts):
        self.key_queue = deque()
        self.recording = None
        self.replaying = False
        self.macros = {}
        self.beeps = True
        self.ins_mode = False
        self.unicode = False
        self.search_scope = 'file'
        self.search_parity = None
        self.last_find = 'search'
        self.refs = None
        self.files = []
        self.file_states = {}
        self.argv_files = list(getattr(opts, 'files', None) or [path])
        self.argv_idx = 0
        self.goto_history = []
        self.calc_text = ''
        self.calc_y = None
        self.str_kind = 'ascii'
        self.str_offsets = True
        self.last_error = ''
        self._info_shown = False
        self._in_main = False
        self.kb_layer = None
        self.marker_pairs = {}
        self._load_macros()
        App.__init__(self, scr, path, opts)
        self._init_marker_colors()

    # ---------------------------------------------------------- loading / saving side data

    def load(self, path, first=False):
        App.load(self, path, first)
        p = self.buf.path
        if p not in self.files:
            self.files.append(p)
        st = os.stat(p)
        self.orig_times = getattr(self, 'orig_times', {})
        self.orig_times.setdefault(p, (st.st_atime, st.st_mtime))
        self.bms = {'text': [], 'hex': [], 'decode': []}
        self.bm_cur = {'text': -1, 'hex': -1, 'decode': -1}
        self.unames, self.ucomments, self.markers = {}, {}, []
        self.meta_dirty = False
        self.markers_dirty = False
        self.refs = None
        try:
            with open(p + '.hnames', encoding='utf-8') as f:
                d = json.load(f)
            self.unames = {int(k): v for k, v in d.get('names', {}).items()}
            self.ucomments = {int(k): v for k, v in d.get('comments', {}).items()}
        except (OSError, ValueError):
            pass
        try:
            with open(p + '.cmarkers', encoding='utf-8') as f:
                self.markers = [tuple(m) for m in json.load(f)]
        except (OSError, ValueError):
            pass

    def save_side_data(self, ask=True):
        p = self.buf.path
        if self.meta_dirty and (not ask or self.confirm('Save names and comments to %s.hnames?' % os.path.basename(p))):
            try:
                with open(p + '.hnames', 'w', encoding='utf-8') as f:
                    json.dump({'names': self.unames, 'comments': self.ucomments}, f, ensure_ascii=False, indent=1)
            except OSError as e:
                self.set_msg(str(e), True)
        if self.markers_dirty and (not ask or self.confirm('Save block colors to %s.cmarkers?' % os.path.basename(p))):
            try:
                with open(p + '.cmarkers', 'w', encoding='utf-8') as f:
                    json.dump(self.markers, f)
            except OSError as e:
                self.set_msg(str(e), True)
        self.meta_dirty = self.markers_dirty = False

    def _load_macros(self):
        try:
            with open(os.path.join(config_dir(), 'macros.json'), encoding='utf-8') as f:
                self.macros = {int(k): v for k, v in json.load(f).items()}
        except (OSError, ValueError):
            self.macros = {}

    def _save_macros(self):
        try:
            os.makedirs(config_dir(), exist_ok=True)
            with open(os.path.join(config_dir(), 'macros.json'), 'w', encoding='utf-8') as f:
                json.dump(self.macros, f)
        except OSError as e:
            self.set_msg('Cannot save macros: %s' % e, True)

    # ---------------------------------------------------------- input: macros, sticky modifiers, Ctrl+Alt

    def getkey(self, main=False):
        self._in_main = main
        if self.key_queue:
            return self.key_queue.popleft()
        k = App.getkey(self, main)
        if self.recording is not None and not self.replaying and k not in ('RESIZE', 'MOUSE'):
            self.recording.append(k)
        if not self.key_queue:
            self.replaying = False
        return k

    def translate_key(self, k):
        if self.edit and self.ascii_col and len(k) == 1:
            t = k    # typing text: never turn characters into commands
        else:
            t = App.translate_key(self, k)
        if self.recording and self.recording[-1] == k and t is not None:
            self.recording[-1] = t
        return t

    def apply_layer(self, k):
        """Ctrl+X = sticky modifier for the next key: Alt -> Ctrl -> Shift -> off (keybar shows the layer)."""
        if k == 'C-x':
            self.kb_layer = {None: 'A', 'A': 'C', 'C': 'S', 'S': None}[self.kb_layer]
            if self.kb_layer:
                self.set_msg('%s- : press the key (Ctrl+X again: next modifier)' % LAYER_NAMES[self.kb_layer])
            return None
        layer = self.kb_layer
        self.kb_layer = None
        if not layer:
            return k
        if k[:1] == 'F' and k[1:].isdigit():
            return layer + '-' + k
        if layer in 'AC' and (len(k) == 1 or k in ('ENTER', 'BS')):
            return layer + '-' + k
        return k

    def refresh_mods(self):
        App.refresh_mods(self)
        held = self.held_mods()
        both = 'C' in held and 'A' in held
        if both and not self._info_shown and self._in_main:
            self._info_shown = True
            self.info_box()
        elif not both and self._info_shown:
            self._info_shown = False
            self.draw()

    def keybar_labels(self):
        layer = self.kb_layer or self.held_layer
        if layer:
            return list(LAYERS['edit' if self.edit else 'view'][layer])
        if self.edit:
            return list(EDIT_KEYBAR)
        labels = list(VIEW_KEYBARS[self.mode])
        if self.mode == 'text' and self.wrap:
            labels[1] = 'Unwrap'
        return labels

    def set_msg(self, text, err=False):
        App.set_msg(self, text, err)
        if err:
            self.last_error = text
            if self.beeps:
                try:
                    curses.beep()
                except curses.error:
                    pass

    # ---------------------------------------------------------- status bar

    def draw_status(self):
        comment = None
        if not self.msg and not self.edit:
            comment = self.ucomments.get(self.position())
            if comment:
                self.msg, self.msg_err = '; ' + comment, False   # shown in the message area, not over the name
        App.draw_status(self)
        if comment:
            self.msg = None
        ind = []
        if self.recording is not None:
            ind.append('R')
        if self.edit:
            ind.append('EDITMODE')
        else:
            lst, cur = self.bms[self.mode], self.bm_cur[self.mode]
            ind.append(''.join('♦' if i == cur else (str(i + 1) if i < len(lst) else '-') for i in range(8)))
        ind.append('Ins' if self.ins_mode else 'Ovr')
        ind.append('↑' if self.search_back else '↓')
        if self.unicode:
            ind.append('Uni')
        s = ' %s ' % ' '.join(ind)
        pos = self.position()
        right = ' %s  %3d%%  %X ' % (self.fmt_addr(pos), min(pos * 100 // max(1, self.buf.size - 1), 100)
                                     if self.buf.size else 0, self.buf.size)
        x = self.w - len(right) - len(s)
        if x > 30 and (not self.msg or comment):
            self.put(0, x, s, self.A['status'])

    # ---------------------------------------------------------- colours of marked blocks

    def _init_marker_colors(self):
        cols = MARK_COLORS_256 if curses.has_colors() and curses.COLORS >= 256 else MARK_COLORS_8
        self.marker_colors = cols
        for i, c in enumerate(cols):
            try:
                fg = 231 if cols is MARK_COLORS_256 else (curses.COLOR_WHITE if c != curses.COLOR_WHITE else curses.COLOR_BLACK)
                curses.init_pair(MARKER_PAIR0 + i, fg, c)
                self.marker_pairs[i] = curses.color_pair(MARKER_PAIR0 + i)
            except curses.error:
                self.marker_pairs[i] = curses.A_REVERSE

    def marker_attr(self, off):
        for a, b, c in reversed(self.markers):
            if a <= off < b:
                return self.marker_pairs.get(c % max(1, len(self.marker_pairs)), self.A['block'])
        return self.A['norm']

    # ---------------------------------------------------------- names, comments

    def label_at(self, ins):
        return self.unames.get(ins.off) or self.info.symbols.get(ins.addr)

    def adrp_target(self, ins):
        """arm64: address built by a preceding ADRP plus this ADD/LDR/STR (GOT, IAT, strings)."""
        if self.arch != 'arm64' or len(ins.raw) != 4 or not self.dlines:
            return None
        from .xrefs import _a64_pageoff, _sx
        try:
            i = next(j for j, l in enumerate(self.dlines) if l is ins)
        except StopIteration:
            return None
        w = int.from_bytes(ins.raw, 'little')
        for prev in reversed(self.dlines[max(0, i - 4):i]):
            pw = int.from_bytes(prev.raw, 'little') if len(prev.raw) == 4 else 0
            if (pw & 0x9F000000) == 0x90000000:
                off = _a64_pageoff(w, pw & 31)
                if off is None:
                    return None
                imm = _sx((((pw >> 5) & 0x7FFFF) << 2) | ((pw >> 29) & 3), 21)
                return ((prev.addr & ~0xFFF) + (imm << 12) + off) & 0xFFFFFFFFFFFFFFFF
        return None

    def comments(self, ins):
        base = '' if ins.mnem == 'adrp' else App.comments(self, ins)   # a page address alone means nothing
        t = self.adrp_target(ins)
        if t is not None and not base:
            base = self.name_for(t) or self.string_at(t) or ''
        c = self.ucomments.get(ins.off)
        return ('%s ; %s' % (c, base) if base else c) if c else base

    def parse_target(self, s):
        s = s.strip()
        for off, n in self.unames.items():
            if n == s:
                return off
        orig = s
        va = s.startswith('.')
        if va:
            s = s[1:].strip()
        sign = 0
        if s[:1] in ('+', '-'):
            sign = 1 if s[0] == '+' else -1
            s = s[1:].strip()
        try:
            v = self.calc(octal_zero=False).eval(s.replace('`', ''))   # addresses are zero-padded hex
        except CalcError:
            return App.parse_target(self, orig)     # symbol names, error messages
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

    # ---------------------------------------------------------- key dispatch (view mode)

    def handle_view_extra(self, k):
        m = self.mode
        pos = self.position()
        simple = {
            'C-*': self.block_all, 'A-*': self.block_resize, 'A-m': self.color_block, 'A-M': self.color_random,
            'A-n': lambda: self.next_marker(1), 'A-N': lambda: self.next_marker(-1),
            '[': lambda: self.block_edge(0), ']': lambda: self.block_edge(1), 'INS': self.toggle_ins,
            '+': self.bm_add, '-': self.bm_restore, 'A--': self.bm_delete, 'A-0': self.bm_clear,
            'C-.': self.macro_record, 'C--': self.macro_manager,
            'C-F1': self.opcode_size, 'S-F1': self.arch_menu,
            'F6': self.refs_first if m == 'decode' else None, 'C-F6': self.refs_next,
            'TAB': lambda: self.switch_file(1), 'C-F11': lambda: self.argv_file(-1),
            'C-F12': lambda: self.argv_file(1), 'C-BS': self.files_window, 'F9': self.open_file,
            'F7': self.search_cmd, 'C-ENTER': self.find_next, 'S-F7': self.find_next, 'C-F7': self.find_next,
            'C-n': self.find_next, 'C-p': lambda: self.find_next(reverse=True),
            'A-F7': self.toggle_direction, 'A-F8': self.table_menu, 'A-F6': self.strings_window,
            ';': self.comment_here, 'S-F12': self.name_here, 'F12': self.names_window, 'F8': None,
            'F5': self.goto_cmd, 'A-b': self.toggle_beeps, 'A-p': self.screenshot, 'S-F4': self.print_block, 'A-=': self.calculator,
            'F11': lambda: self.set_msg('HEM modules (F11) are not supported'), 'S-F3': self.insert_bytes, 'C-F2': self.get_block, 'S-F5': self.copy_block,
            'S-F6': self.move_block, 'A-F3': self.crypt_dialog, 'A-F2': self.fill_block,
            'S-F9': lambda: self.go_value(4), 'S-F10': lambda: self.go_value(8), 'S-F11': lambda: self.go_value(2),
            '/': self.resync if m == 'decode' else None, 'A-i': self.info_box_wait,
        }
        if k == 'F8' and m != 'text':
            self.header_window()
            return True
        if k == 'F2' and m != 'text':
            self.put_block()
            return True
        if k in ('ESC', 'F10'):
            return self.quit(touch=k == 'F10')
        if len(k) == 3 and k.startswith('A-') and k[2] in '12345678':
            self.bm_go(int(k[2]) - 1)
            return True
        if len(k) == 3 and k.startswith('C-') and k[2] in '012345678':
            self.macro_play(int(k[2]))
            return True
        f = simple.get(k)
        if f:
            f()
            return True
        return super().handle_view_extra(k)

    def handle_edit_extra(self, k):
        if k == 'TAB' and self.mode == 'decode':
            while self.asm_here():   # assembler mode: one instruction after another until Esc
                pass
            return True
        if k == 'A-F2' and self.block_range():
            self.fill_block()
            return True
        if k == 'A-F3':
            self.crypt_dialog()
            return True
        if k == 'C-F7':
            self.crypt_dialog(edit=True)
            return True
        if k == 'INS':
            self.toggle_ins()
            return True
        if k == 'A-=':
            self.calculator()
            return True
        return super().handle_edit_extra(k)

    # ---------------------------------------------------------- quitting, timestamps

    def quit(self, touch=False):
        self.recording = None
        self.save_side_data()
        self.restore_times(touch)
        return False

    def restore_times(self, touch):
        """Esc leaves the file timestamp as it was; F10 updates it (Hiew)."""
        for p, (at, mt) in getattr(self, 'orig_times', {}).items():
            try:
                st = os.stat(p)
                if touch:
                    if st.st_mtime != mt:
                        os.utime(p, None)
                elif st.st_mtime != mt:
                    os.utime(p, (at, mt))
            except OSError:
                pass

    def goto_cmd(self):
        s = self.input_dialog('Goto', '', 50, 'hex: 1234  dec: 123t  VA: .401000  rel: +100 -10t  name   PgDn - history',
                              history=self.goto_history)
        if not s:
            return
        if s in self.goto_history:
            self.goto_history.remove(s)
        self.goto_history.append(s)
        try:
            self.goto(self.parse_target(s))
        except ValueError as e:
            self.set_msg(str(e), True)

    # ---------------------------------------------------------- blocks

    def block_all(self):
        self.block, self.block_start = (0, self.buf.size), None
        self.set_msg('Block = whole file, ' + nbytes(self.buf.size))

    def block_resize(self):
        pos = self.cur if self.edit else self.position()
        if self.block_start is not None:
            self.block_start = pos
        elif self.block:
            a, b = self.block
            self.block = (pos, b) if pos < b else (a, pos + 1)
            self.set_msg('Block ' + nbytes(self.block[1] - self.block[0]))
        else:
            self.set_msg('No block (press *)', True)

    def block_edge(self, end):
        blk = self.block_range()
        if not blk:
            self.set_msg('No block (press *)', True)
            return
        self.goto(blk[1] - 1 if end else blk[0], self.mode if self.mode != 'text' else 'hex')

    def toggle_ins(self):
        self.ins_mode = not self.ins_mode
        self.set_msg('Block operations: ' + ('INSERT (file grows)' if self.ins_mode else 'OVERWRITE'))

    def color_block(self, random_color=False):
        blk = self.need_block()
        if not blk:
            return
        n = len(self.marker_pairs) or 1
        if random_color:
            c = random.randrange(n)
        else:
            c = self.pick_color()
            if c is None:
                return
        self.markers = [m for m in self.markers if not (m[0] == blk[0] and m[1] == blk[1])]
        self.markers.append((blk[0], blk[1], c))
        self.markers_dirty = True
        self.set_msg('Block colored (%d marked blocks; Alt-N next)' % len(self.markers))

    def color_random(self):
        self.color_block(random_color=True)

    def pick_color(self):
        n = len(self.marker_pairs)
        cols = 6
        sel = 0
        while True:
            rows = (n + cols - 1) // cols
            bw, bh = cols * 6 + 4, rows + 4
            y0, x0 = (self.h - bh) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, bh, bw, 'Block color')
            for i in range(n):
                r, c = divmod(i, cols)
                at = self.marker_pairs[i] | (curses.A_REVERSE if i == sel else 0)
                self.put(y0 + 1 + r, x0 + 2 + c * 6, ' %2d  ' % (i + 1) if i != sel else '[%2d] ' % (i + 1), at)
            self.put(y0 + bh - 2, x0 + 2, 'arrows - choose  Enter - set'[:bw - 4], self.A['dlghdr'])
            self.apply_cursor(None)
            self.scr.refresh()
            k = self.getkey()
            if k in ('ESC', 'F10'):
                return None
            if k == 'ENTER':
                return sel
            sel = clamp(sel + {'LEFT': -1, 'RIGHT': 1, 'UP': -cols, 'DOWN': cols}.get(k, 0), 0, n - 1)

    def next_marker(self, d):
        if not self.markers:
            self.set_msg('No colored blocks (Alt-M)', True)
            return
        pos = self.position()
        starts = sorted(set(m[0] for m in self.markers))
        if d > 0:
            nxt = next((s for s in starts if s > pos), starts[0])
        else:
            nxt = next((s for s in reversed(starts) if s < pos), starts[-1])
        self.goto(nxt, self.mode if self.mode != 'text' else 'hex')

    def disk_ready(self):
        if self.buf.modified:
            self.set_msg('Write (F9) or discard (Esc) the edits first', True)
            return False
        return True

    def get_block(self):
        if not self.ins_mode:
            return super().get_block()
        if not self.disk_ready():
            return
        name = self.input_dialog('Insert file at the cursor (ReadBlk, INSERT mode)', '', 60)
        if not name:
            return
        try:
            with open(os.path.expanduser(name), 'rb') as f:
                data = f.read()
        except OSError as e:
            self.set_msg(str(e), True)
            return
        pos = self.cur if self.edit else self.position()
        self.disk_change(lambda: self.buf.insert(pos, data), pos)
        self.block, self.block_start = (pos, pos + len(data)), None
        self.set_msg('Inserted %s from %s' % (nbytes(len(data)), name))

    def copy_block(self):
        if not self.ins_mode:
            return super().copy_block()
        blk = self.need_block()
        if not blk or not self.disk_ready():
            return
        dst = self.cur if self.edit else self.position()
        data = self.buf.read(blk[0], blk[1] - blk[0])
        self.disk_change(lambda: self.buf.insert(dst, data), dst)
        self.block, self.block_start = (dst, dst + len(data)), None
        self.set_msg('Inserted copy, ' + nbytes(len(data)))

    def move_block(self):
        if self.ins_mode:
            return super().move_block()     # delete + insert = the bytes rotate, size stays
        blk = self.need_block()
        if not blk or not self.disk_ready():
            return
        a, b = blk
        dst = self.cur if self.edit else self.position()
        if a <= dst < b:
            self.set_msg('Cursor is inside the block', True)
            return
        if not self.confirm('Overwrite at %s and remove the block from the file?' % self.fmt_addr(dst)):
            return
        data = self.buf.read(a, b - a)[:self.buf.size - dst]

        def op():
            self.buf.write_bytes(dst, data)
            self.buf.save()
            self.buf.delete(a, b)
        self.disk_change(op, dst - (b - a) if dst > a else dst)
        self.block = None
        self.set_msg('Moved ' + nbytes(len(data)))

    def insert_bytes(self):
        if not self.disk_ready():
            return
        s = self.input_dialog('Insert bytes at the cursor (count, hex; 100t = decimal)', '', 50)
        if not s:
            return
        try:
            n = self.calc().eval(s)
        except CalcError as e:
            self.set_msg(str(e), True)
            return
        if not 0 < n <= 1 << 30:
            self.set_msg('Bad count', True)
            return
        pos = self.cur if self.edit else self.position()
        self.disk_change(lambda: self.buf.insert(pos, bytes(n)), pos)
        self.set_msg('Inserted %s of zeros (F3 to edit, Alt-F2 to fill)' % nbytes(n))

    def disk_change(self, op, pos):
        st = self.keep_state()
        try:
            op()
        except OSError as e:
            self.set_msg(str(e), True)
            return
        was_edit = self.edit
        self.edit = False
        markers, unames, ucomments = self.markers, self.unames, self.ucomments
        self.load(self.buf.path)
        self.markers, self.unames, self.ucomments = markers, unames, ucomments
        self.restore_state(st)
        if self.buf.size:
            self.goto(clamp(pos, 0, self.buf.size - 1), push=False)
        if was_edit:
            self.start_edit()

    def fill_block(self):
        if not self.block_range() and self.mode == 'decode':
            self.ensure_edit()           # no block in code view: NOP the current instruction
            self.nops_here()
            return
        return super().fill_block()

    def print_block(self):
        blk = self.need_block()
        if not blk:
            return
        a, b = blk
        lines = []
        tbl = self.table()
        for o in range(a, b, 16):
            d = self.buf.read(o, min(16, b - o))
            lines.append('%s: %-48s %s' % (self.fmt_addr(o), ' '.join('%02X' % x for x in d), ''.join(tbl[x] for x in d)))
            if len(lines) > 200000:
                break
        self.output_text('Print block', '\n'.join(lines) + '\n', 'block.txt')

    # ---------------------------------------------------------- bookmarks (8 per view)

    def bm_state(self):
        return (self.position(), self.top, self.cur, self.dcur)

    def bm_add(self):
        lst = self.bms[self.mode]
        if len(lst) >= 8:
            self.set_msg('8 bookmarks max: Alt-- deletes the current one, Alt-0 clears', True)
            return
        lst.append(self.bm_state())
        self.bm_cur[self.mode] = len(lst) - 1
        self.set_msg('Bookmark %d saved' % len(lst))

    def bm_go(self, i):
        lst = self.bms[self.mode]
        if not 0 <= i < len(lst):
            self.set_msg('No bookmark %d' % (i + 1), True)
            return
        self.bm_cur[self.mode] = i
        pos, top, cur, dcur = lst[i]
        self.push_pos()
        self.top, self.cur, self.dcur = top, cur, dcur
        if self.mode == 'text':
            self.text_anchor = pos
        self.ensure_cursor()

    def bm_restore(self):
        if self.bm_cur[self.mode] < 0:
            self.set_msg('No bookmarks (+ saves one)', True)
            return
        self.bm_go(self.bm_cur[self.mode])

    def bm_delete(self):
        lst, i = self.bms[self.mode], self.bm_cur[self.mode]
        if i < 0:
            self.set_msg('No bookmarks', True)
            return
        del lst[i]
        self.bm_cur[self.mode] = min(i, len(lst) - 1)
        self.set_msg('Bookmark deleted')

    def bm_clear(self):
        self.bms[self.mode] = []
        self.bm_cur[self.mode] = -1
        self.set_msg('Bookmarks cleared')

    # ---------------------------------------------------------- macros

    def macro_record(self):
        if self.recording is None:
            self.recording = []
            self.set_msg('Recording macro... Ctrl-. to stop')
            return
        keys = [k for k in self.recording if k != 'C-.']
        self.recording = None
        if not keys:
            self.set_msg('Empty macro, not saved')
            return
        free = next((i for i in range(9) if i not in self.macros), 0)
        s = self.input_dialog('Save macro (%d keys) to slot 0-8 (play: Ctrl+N)' % len(keys), str(free), 50, select=True)
        if s is None or not s.strip().isdigit() or not 0 <= int(s) <= 8:
            self.set_msg('Macro discarded')
            return
        self.macros[int(s)] = keys
        self._save_macros()
        self.set_msg('Macro saved to Ctrl-%s' % s.strip())

    def macro_play(self, n):
        if self.replaying:
            return   # no recursion
        keys = self.macros.get(n)
        if not keys:
            self.set_msg('No macro %d (Ctrl-. records one)' % n, True)
            return
        self.replaying = True
        self.key_queue.extend(keys)

    def macro_manager(self):
        while True:
            items = [('Ctrl-%d  %3d keys  %s' % (i, len(v), ' '.join(v)[:60]), i) for i, v in sorted(self.macros.items())]
            if not items:
                self.set_msg('No macros: Ctrl-. starts recording')
                return
            r = self.list_dialog('Macros: Enter play, Del delete', items, filterable=False, extra_keys=('DEL',))
            if r is None:
                return
            if isinstance(r, tuple):
                if r[2] is not None:
                    del self.macros[r[2]]
                    self._save_macros()
                continue
            self.macro_play(r)
            return

    # ---------------------------------------------------------- modes, architecture

    def opcode_size(self):
        nxt = BITS_CYCLE.get(self.arch)
        if not nxt:
            self.set_msg('No other opcode size for %s (Shift-F1: architecture)' % self.arch)
            return
        self.arch = nxt
        self.make_dis()
        self.set_msg('Opcode size: ' + SHORT[nxt])

    def arch_menu(self):
        items = [('%s %-8s %s' % ('*' if a == self.arch else ' ', a, SHORT[a]), a) for a in ARCHS]
        r = self.list_dialog('Architecture', items, sel=ARCHS.index(self.arch) if self.arch in ARCHS else 0,
                             filterable=False)
        if r:
            self.arch = r
            self.make_dis()
            self.set_mode('decode')

    def resync(self):
        pos = self.position()
        self.top = pos
        self.dcur = 0
        self.set_msg('Disassembly resynchronized at ' + self.fmt_addr(pos))

    # ---------------------------------------------------------- references (F6 / Ctrl-F6)

    def plt_stub(self, got):
        """ELF: address of the PLT stub that jumps through the GOT slot (calls go to the stub)."""
        if not hasattr(self, '_plt'):
            self._plt = {}
            for sec in self.info.sections:
                if sec.exec_ and sec.size and sec.name.startswith('.plt'):
                    for ins in self.decode_at(sec.off, min(sec.size // 4 + 1, 20000)):
                        if ins.off >= sec.off + sec.size:
                            break
                        if ins.kind == 'jmp' and ins.mem is not None:
                            stub = ins.addr
                            # .plt entries start 0..2 instructions before the jmp (endbr64 / bnd)
                            self._plt.setdefault(ins.mem, stub if not sec.name == '.plt' else (stub & ~0xF))
        return self._plt.get(got)

    def compute_refs(self, targets):
        """Linear sweep of executable code for references to any of targets. Esc cancels."""
        if self.dis.lite is None:
            self.set_msg(self.dis.error or 'No disassembler', True)
            return None
        from .disasm import HEX_RE, RIP_RE
        if isinstance(targets, int):
            targets = [targets]
        tset = set(targets)
        self._refs_stopped = False
        hexs = ['0x%x' % t for t in tset]
        regions = [(s.off, s.size, s.va) for s in self.info.sections if s.exec_ and s.size]
        if not regions:
            regions = [(0, self.buf.size, self.va_of(0))]
        total = sum(min(sz, self.buf.size - o) for o, sz, _ in regions) or 1
        what = ', '.join(self.disp_va(t) for t in targets)
        done = 0
        refs = []
        x86 = self.dis.x86
        last = 0
        self.scr.nodelay(True)
        try:
            from .xrefs import FAST_ARCHS, find_refs
            if self.arch in FAST_ARCHS and self.dis.cs is not None:
                state = {'last': 0.0, 'done': 0}

                def progress(p, nfound):
                    now = time.time()
                    if now - state['last'] > 0.25:
                        state['last'] = now
                        self.msg = 'Searching references to %s: %d%%, %d found (Esc - stop)' % (
                            what, (state['done'] + p) * 100 // total, len(refs) + nfound)
                        self.msg_err = False
                        self.draw()
                        self.scr.nodelay(True)
                        try:
                            c = self.scr.getch()
                            if c == 27:
                                self._refs_stopped = True
                                return True
                            if c != -1:
                                curses.ungetch(c)   # typed ahead: keep it for after the search
                        except curses.error:
                            pass
                    return False
                for off, size, sva in regions:
                    size = min(size, self.buf.size - off)
                    if size <= 0:
                        continue
                    refs += [off + p for p in find_refs(self.dis, self.buf.read(off, size), sva, self.arch,
                                                        tset, progress)]
                    state['done'] += size
                    if self._refs_stopped:
                        break
                self.msg = None
                return refs
            for off, size, sva in regions:
                size = min(size, self.buf.size - off, 256 << 20)
                if size <= 0:
                    continue
                for n, (a, s, mn, op) in enumerate(self.dis.sweep(self.buf.read(off, size), sva)):
                    if n & 0x3FFF == 0:
                        now = time.time()
                        if now - last > 0.25:
                            last = now
                            pct = (done + a - sva) * 100 // total
                            self.msg = 'Searching references to %s: %d%%, %d found (Esc - stop)' % (what, pct, len(refs))
                            self.msg_err = False
                            self.draw()
                            self.scr.nodelay(True)
                            try:
                                k = self.scr.getch()
                            except curses.error:
                                k = -1
                            if k == 27:
                                self.msg = None
                                self._refs_stopped = True
                                return refs
                            if k != -1:
                                curses.ungetch(k)
                    hit = False
                    if any(h in op for h in hexs):
                        hit = any(int(h, 16) in tset for h in HEX_RE.findall(op))
                    elif x86 and 'rip' in op:
                        m = RIP_RE.search(op)
                        if m:
                            d = int(m.group(2), 0)
                            hit = a + s + (d if m.group(1) == '+' else -d) in tset
                    if hit:
                        refs.append(off + a - sva)
                        if len(refs) >= 20000:
                            break
                done += size
        finally:
            self.scr.timeout(K.READ_TIMEOUT)
        self.msg = None
        return refs

    def refs_first(self, target=None):
        if target is None:
            target = self.va_of(self.position())
        targets = [target]
        if self.info.kind == 'ELF':
            stub = self.plt_stub(target)
            if stub is not None:
                targets = [stub, target]   # calls go to the PLT stub, the stub jumps through the GOT slot
        refs = self.compute_refs(targets)
        if refs is None:
            return
        if not refs:
            self.set_msg('No references to %s' % self.disp_va(target), True)
            return
        refs = sorted(set(refs))
        if len(targets) > 1:   # ELF: drop the PLT stub's own jmp through the GOT
            plt = [(sec.off, sec.off + sec.size) for sec in self.info.sections if sec.name.startswith('.plt')]
            refs = [r for r in refs if not any(a <= r < b for a, b in plt)] or refs
        self.refs = [targets[0], refs, 0]
        self.last_find = 'refs'
        self.goto(refs[0], 'decode')
        self.set_msg('Reference 1/%d to %s%s (Ctrl-F6 / Ctrl-Enter next, BkSp back)' % (
            len(refs), self.disp_va(targets[0]), ', search stopped by Esc' if self._refs_stopped else ''))

    def refs_next(self):
        if not self.refs:
            self.set_msg('No reference search (F6)', True)
            return
        target, refs, i = self.refs
        i = (i + (-1 if self.search_back else 1)) % len(refs)
        self.refs[2] = i
        self.goto(refs[i], 'decode', push=refs[i] != self.position())
        self.set_msg('Reference %d/%d to %s' % (i + 1, len(refs), self.disp_va(target)))

    # ---------------------------------------------------------- search

    def encode_str(self, s):
        return s.encode('utf-16-le' if self.unicode else self.enc, 'replace')

    def search_cmd(self):
        if self.search_dialog():
            self.last_find = 'search'
            self.do_search(backward=self.search_back)

    def find_next(self, reverse=False):
        if self.last_find == 'refs' and self.refs:
            return self.refs_next()
        if not self.search:
            return self.search_cmd()   # no previous search: ask for one
        self.do_search(backward=self.search_back != reverse)

    def search_dialog(self, title='Search'):
        """Hex field first (Hiew default). Tab: field, F2 direction, F3 case, F4 scope, F6 even/odd,
        F7 assembler, Alt-? wildcard. More than 3 non-hex characters typed in Hex switch to ASCII."""
        A = self.A
        fa = LineEdit(self.search_ascii)
        fh = LineEdit(self.search_hex)
        act = 1 if self.search_src == 'hex' or not self.search_ascii else 0
        src = self.search_src
        icase = self.search_icase
        while True:
            bw = min(self.w - 2, 76)
            bh = 7
            y0, x0 = (self.h - bh) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, bh, bw, title)
            fw = bw - 13
            cur = None
            for i, (lbl, le) in enumerate((('ASCII:', fa), ('Hex:', fh))):
                y = y0 + 1 + i
                self.put(y, x0 + 2, lbl, A['dlgtitle'] if act == i else A['dlg'])
                vis, cx = le.view(fw)
                self.put(y, x0 + 10, vis.replace('\x01', '?').ljust(fw), A['input'])
                if act == i:
                    cur = (y, x0 + 10 + cx)
            opt = 'F2 dir:%s  F3 case:%s  F4 scope:%s  F6 uni:%s  F7 asm  Alt-? any' % (
                'back' if self.search_back else 'fwd', 'off' if icase else 'on', self.search_scope,
                self.search_parity or 'any')
            self.put(y0 + 4, x0 + 2, opt[:bw - 4], A['dlghdr'])
            self.put(y0 + 5, x0 + 2, ('Tab - field   Enter - find   Esc - cancel   encoding: %s'
                                      % ('UTF-16 (Alt-F8)' if self.unicode else self.enc))[:bw - 4], A['dlghdr'])
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
                self.search_back = not self.search_back
                continue
            if k == 'F3':
                icase = not icase
                continue
            if k == 'F4':
                self.search_scope = 'block' if self.search_scope == 'file' and self.block_range() else 'file'
                continue
            if k == 'F6':
                self.search_parity = {None: 'even', 'even': 'odd', 'odd': None}[self.search_parity]
                continue
            if k == 'F7':
                code = self.asm_text('Search for instruction')
                if code:
                    fh.set(' '.join('%02X' % b for b in code))
                    fa.set(''.join(self.table()[b] for b in code))
                    src, act = 'hex', 1
                continue
            if k == 'ENTER':
                self.apply_cursor(None)
                self.search_ascii, self.search_hex, self.search_icase, self.search_src = fa.text, fh.text, icase, src
                return self.build_search()
            le = fa if act == 0 else fh
            if k in ('A-?', '¿') and act == 0:
                k = '\x01'                       # wildcard: any byte
                le.text = le.text[:le.pos] + k + le.text[le.pos:]
                le.pos += 1
            elif not le.key(k):
                continue
            if act == 1:
                # the Hex field keeps everything typed; more than 3 non-hex characters move it to ASCII
                nonhex = [c for c in fh.text if c not in HEX_CHARS]
                if len(nonhex) > 3:
                    fa.set(fh.text)
                    act = 0
                elif nonhex:
                    fa.set(fh.text)       # not valid hex (yet): it will be searched as text
                    src = 'ascii'
                    continue
                else:
                    toks = parse_hex(fh.text)
                    tbl = self.table()
                    fa.set(''.join('\x01' if t is None else tbl[t] for t in toks) if toks else '')
                    src = 'hex'
                    continue
            fh.set(' '.join('??' if c == '\x01' else ' '.join('%02X' % b for b in self.encode_str(c))
                            for c in fa.text))
            src = 'ascii'

    def build_search(self):
        if self.search_src == 'hex' and self.search_hex.strip() and not parse_hex(self.search_hex):
            # not valid hex (e.g. "abc", odd length): search the typed text
            self.search_src, self.search_ascii = 'ascii', self.search_hex.strip()
        if self.search_src == 'ascii' and '\x01' in self.search_ascii:
            parts = []
            for ch in self.search_ascii:
                if ch == '\x01':
                    parts.append(b'.' * (2 if self.unicode else 1))
                else:
                    vs = {ch, ch.lower(), ch.upper()} if self.search_icase else {ch}
                    encs = sorted({self.encode_str(v) for v in vs})
                    parts.append(b'(?:' + b'|'.join(re.escape(e) for e in encs) + b')')
            self.search = (re.compile(b''.join(parts), re.DOTALL), len(self.encode_str(self.search_ascii)),
                           '"%s"' % self.search_ascii.replace('\x01', '?'))
            return True
        return App.build_search(self)

    def do_search(self, backward=False):
        if not self.search:
            self.set_msg('No search pattern, press F7', True)
            return
        rx, plen, desc = self.search
        pos = self.position()
        if self.found and getattr(self, '_found_at', None) == (self.mode, pos):
            pos = self.found[0]
        lo, hi = 0, self.buf.size
        if self.search_scope == 'block' and self.block_range():
            lo, hi = self.block_range()
        self.flash('Searching %s ...' % desc)
        start = pos if backward else pos + 1
        off = None
        for _ in range(100000):
            off = self.buf.find(rx, plen, start, backward)
            if off is None or off < lo or off + plen > hi:
                if off is not None and not backward and off < lo:
                    start = lo
                    continue
                off = None
                break
            if self.search_parity and (off % 2 == 0) != (self.search_parity == 'even'):
                start = off if backward else off + 1
                continue
            break
        self.msg = None
        if off is None:
            self.set_msg('Not found: %s' % desc, True)
            return
        self.found = (off, plen)
        if self.mode == 'hex':
            self.cur = off
            self.ensure_cursor()
        else:
            self.goto(off, push=False)
        if self.mode == 'text':
            self.text_anchor = off              # status shows the hit, next search starts after it
            if not self.wrap:                   # scroll long lines sideways to the hit
                ls = self.line_start(off)
                col = len(self.render_text(self.buf.read(ls, off - ls)))
                if not self.hscroll <= col < self.hscroll + self.w - 8:
                    self.hscroll = max(0, col - self.w // 3)
        self._found_at = (self.mode, self.position())

    # ---------------------------------------------------------- strings (Alt-F6)

    def strings_window(self):
        kinds = ('ascii', 'uni-even', 'uni-odd')
        flt = ''
        while True:
            items = self.scan_strings2(self.str_min, self.str_kind, flt)
            title = 'Strings %s, min %d, %d found  (+/- length, F6 type, F2 offsets, F9 filter)' % (
                self.str_kind, self.str_min, len(items))
            if not items:
                items = [('no strings', None)]
            r = self.list_dialog(title, items, extra_keys=('+', '-', 'F6', 'F2', 'F9'))
            if isinstance(r, tuple) and r[0] == '__key__':
                k = r[1]
                if k in '+-':
                    self.str_min = max(2, self.str_min + (1 if k == '+' else -1))
                elif k == 'F6':
                    self.str_kind = kinds[(kinds.index(self.str_kind) + 1) % 3]
                elif k == 'F2':
                    self.str_offsets = not self.str_offsets
                elif k == 'F9':
                    s = self.input_dialog('Show strings containing', flt, 50)
                    if s is not None:
                        flt = s
                continue
            if r is not None:
                self.goto(r, 'hex' if self.mode == 'text' else self.mode)
            return

    def scan_strings2(self, minlen, kind, flt='', limit=64 << 20, cap=50000):
        self.flash('Scanning strings ...')
        if kind == 'ascii':
            rx = re.compile(rb'[\x20-\x7e\t]{%d,}' % minlen)
        else:
            rx = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % minlen)
        size = min(self.buf.size, limit)
        out = []
        pos, last_end, CH = 0, 0, 4 << 20
        want = 0 if kind == 'uni-even' else 1
        fl = flt.lower()
        while pos < size and len(out) < cap:
            data = self.buf.read(pos, CH + 4096)
            for m in rx.finditer(data):
                s = pos + m.start()
                if s >= pos + CH or len(out) >= cap:
                    break
                if s < last_end:
                    continue
                if kind != 'ascii' and s % 2 != want:
                    continue
                last_end = pos + m.end()
                text = m.group().decode('utf-16-le' if kind != 'ascii' else 'latin-1', 'replace').replace('\t', ' ')
                if fl and fl not in text.lower():
                    continue
                out.append((('%s  %s' % (self.fmt_addr(s), text[:120])) if self.str_offsets else text[:140], s))
            pos += CH
        self.msg = None
        return out

    # ---------------------------------------------------------- encoding table (Alt-F8)

    def table_menu(self):
        from .app import ENCODINGS
        items = [('%s %s' % ('*' if (e == self.enc and not self.unicode) else ' ', e), e) for e in ENCODINGS]
        items.append(('%s UTF-16LE (unicode: search and text input)' % ('*' if self.unicode else ' '), 'utf-16'))
        r = self.list_dialog('Translation table', items, filterable=False)
        if r == 'utf-16':
            self.unicode = not self.unicode
        elif r:
            self.enc = r
            self.unicode = False

    # ---------------------------------------------------------- files

    def remember_file_state(self):
        self.file_states[self.buf.path] = (self.keep_state(), self.bms, self.bm_cur)

    def open_path(self, path):
        if self.buf.modified:
            self.set_msg('Write (F9) or discard (Esc) the edits first', True)
            return False
        self.save_side_data()
        self.remember_file_state()
        try:
            self.load(os.path.expanduser(path))
        except OSError as e:
            self.set_msg(str(e), True)
            return False
        saved = self.file_states.get(self.buf.path)
        if saved:
            st, self.bms, self.bm_cur = saved
            self.restore_state(st)
        return True

    def open_file(self):
        s = self.input_dialog('Open file', os.path.dirname(self.buf.path) + os.sep, 70)
        if s:
            self.open_path(s)

    def switch_file(self, d):
        if len(self.files) < 2:
            self.set_msg('Only one file open (F9 opens another)')
            return
        i = self.files.index(self.buf.path) if self.buf.path in self.files else 0
        self.open_path(self.files[(i + d) % len(self.files)])

    def argv_file(self, d):
        if len(self.argv_files) < 2:
            self.set_msg('Only one file on the command line')
            return
        self.argv_idx = (self.argv_idx + d) % len(self.argv_files)
        self.open_path(self.argv_files[self.argv_idx])

    def leave_file(self):
        if len(self.files) < 2:
            return self.quit()
        cur = self.buf.path
        i = self.files.index(cur)
        if self.open_path(self.files[i - 1]):
            self.files.remove(cur)
        return True

    def files_window(self):
        while True:
            items = [('%s %-24s %s' % ('*' if p == self.buf.path else ' ', os.path.basename(p), os.path.dirname(p)), p)
                     for p in self.files]
            r = self.list_dialog('Open files: Enter switch, Del close', items, filterable=False, extra_keys=('DEL',))
            if r is None:
                return
            if isinstance(r, tuple):
                p = r[2]
                if p is None or len(self.files) < 2:
                    continue
                if p == self.buf.path:
                    self.leave_file()
                else:
                    self.files.remove(p)
                continue
            if r != self.buf.path:
                self.open_path(r)
            return

    # ---------------------------------------------------------- header sub-tables (F8 then F5/F6/F7/F9)

    def header_window(self):
        info = self.info
        items = [('File: %s' % self.buf.path, None), ('Size: %s' % nbytes(self.buf.size), None)]
        if info.entry_off is not None:
            items.append(('Entry point %s   (F5)' % self.fmt_addr(info.entry_off), (info.entry_off, 'decode')))
        items.append(('Sections F6   Imports F7   Exports F9', None))
        items.append(('', None))
        items += info.header or [('Unknown format: raw binary', None)]
        while True:
            r = self.list_dialog('Header %s' % (info.desc or ''), items, sel=2 if info.entry_off is not None else 0,
                                 extra_keys=('F5', 'F6', 'F7', 'F9'))
            if isinstance(r, tuple) and r[0] == '__key__':
                k = r[1]
                if k == 'F5':
                    if info.entry_off is None:
                        self.set_msg('No entry point', True)
                        return
                    self.goto(info.entry_off, 'decode')
                    return
                sub = {'F6': self.sections_list, 'F7': self.imports_list, 'F9': self.exports_list}[k]()
                if sub == 'done':
                    return
                continue
            if r and r[0] == 'slice':
                self.switch_slice(r[1])
                return
            if r and r[0] is not None:
                self.goto(r[0], r[1])
            return

    def switch_slice(self, idx):
        if self.buf.modified:
            self.set_msg('Write (F9) or discard (Esc) the edits first', True)
            return
        if idx == self.info.slice_idx:
            return
        mode = self.mode
        self.save_side_data()
        self.slice_sel = idx
        self.load(self.buf.path)
        self.slice_sel = idx
        if self.info.entry_off is not None:
            self.goto(self.info.entry_off, 'decode' if mode != 'text' else 'hex', push=False)
        else:
            sl = self.info.slices[idx]
            self.goto(sl[1], mode if mode != 'text' else 'hex', push=False)
        self.set_msg('Slice %d: %s (%s)' % (idx, self.info.slices[idx][0], self.arch))

    def mode_menu(self):
        if not self.info.slices:
            return App.mode_menu(self)
        from .app import MODES
        items = [('Text', 'text'), ('Hex', 'hex'), ('Decode', 'decode'), ('', None),
                 ('Slice (universal binary):', None)]
        for k, (nm, o, sz) in enumerate(self.info.slices):
            items.append(('  %s %d %-10s offset %08X' % ('*' if k == self.info.slice_idx else ' ', k, nm, o), k))
        from .themes import THEMES
        items += [('', None), ('Theme:', None)]
        items += [('  %s %s' % ('*' if t == self.theme else ' ', t), ('theme', t)) for t in THEMES]
        items += [('', None), ('Architecture, codepage ...', 'more')]
        r = self.list_dialog('Mode', items, sel=MODES.index(self.mode), filterable=False, skip_headers=True)
        if r == 'more':
            return App.mode_menu(self)
        if isinstance(r, tuple) and r[0] == 'theme':
            return self.set_theme(r[1])
        if r in MODES:
            self.set_mode(r)
        elif isinstance(r, int):
            self.switch_slice(r)

    def sections_list(self):
        items = [('%-16s .%08X  %08X  off %08X  %s' % (s.name[:16], s.va, s.vsize, s.off, s.flags),
                  (s.off, 'decode' if s.exec_ else 'hex')) for s in self.info.sections if s.size]
        if not items:
            self.set_msg('No sections')
            return None
        r = self.list_dialog('Sections', items)
        if r:
            self.goto(r[0], r[1])
            return 'done'
        return None

    def imports_list(self):
        if not self.info.imports:
            self.set_msg('No imports')
            return None
        items = [('%-24s %-32s .%X' % (dll, fn, iat), iat) for dll, fn, iat in self.info.imports]
        r = self.list_dialog('Imports: Enter = find calls (Ctrl-Enter next)', items)
        if r is not None:
            self.refs_first(r)
            return 'done'
        return None

    def exports_list(self):
        items = [('.%08X  %s' % (va, nm), va) for nm, va in sorted(self.info.exports, key=lambda x: x[1])
                 if self.off_of(va) is not None]
        if not items:
            self.set_msg('No exports')
            return None
        r = self.list_dialog('Exports', items)
        if r is not None:
            self.goto(self.off_of(r), 'decode')
            return 'done'
        return None

    # ---------------------------------------------------------- names (F12, Shift-F12) and comments (;)

    def comment_here(self):
        pos = self.position()
        s = self.input_dialog('Comment at %s (empty = delete)' % self.fmt_addr(pos), self.ucomments.get(pos, ''), 70)
        if s is None:
            return
        if s.strip():
            self.ucomments[pos] = s.strip()
        else:
            self.ucomments.pop(pos, None)
        self.meta_dirty = True

    def name_here(self):
        pos = self.position()
        s = self.input_dialog('Name for %s (empty = delete)' % self.fmt_addr(pos), self.unames.get(pos, ''), 60)
        if s is None:
            return
        if s.strip():
            self.unames[pos] = s.strip()
        else:
            self.unames.pop(pos, None)
        self.meta_dirty = True
        self._names = {}

    def names_window(self):
        while True:
            items = []
            for va, nm in sorted(self.info.symbols.items()):
                off = self.off_of(va)
                if off is not None:
                    items.append((off, '%s  %s' % (self.disp_va(va), nm)))
            for off, nm in self.unames.items():
                items.append((off, '%s  %s' % (self.fmt_addr(off), nm)))
            for off, c in self.ucomments.items():
                items.append((off, '%s  ;%s' % (self.fmt_addr(off), c)))
            items.sort()
            rows = [(t, o) for o, t in items] or [('no names: Shift-F12 names a location, ; adds a comment', None)]
            r = self.list_dialog('Names (%d): type to filter, F12 import, Shift-F12 export' % len(items), rows,
                                 extra_keys=('F12', 'S-F12'))
            if isinstance(r, tuple) and r[0] == '__key__':
                if r[1] == 'F12':
                    self.import_names()
                else:
                    self.export_names()
                continue
            if r is not None:
                self.goto(r, 'decode' if self.mode == 'text' else self.mode)
            return

    def import_names(self):
        name = self.input_dialog('Import names from text file ("address name" or "address *comment")', '', 70)
        if not name:
            return
        n = 0
        try:
            with open(os.path.expanduser(name), encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    addr, _, rest = line.partition(' ')
                    rest = rest.strip()
                    if not rest:
                        continue
                    try:
                        off = self.parse_target(addr.replace('`', ''))
                    except ValueError:
                        continue
                    if rest.startswith('*'):
                        self.ucomments[off] = rest[1:].strip()
                    else:
                        self.unames[off] = rest
                    n += 1
        except OSError as e:
            self.set_msg(str(e), True)
            return
        self.meta_dirty = True
        self.set_msg('Imported %d names/comments' % n)

    def export_names(self):
        name = self.input_dialog('Export names to text file', os.path.basename(self.buf.path) + '.names.txt', 70,
                                 select=True)
        if not name:
            return
        lines = []
        for off, nm in sorted(self.unames.items()):
            lines.append('%s %s' % (self.fmt_addr(off), nm))
        for va, nm in sorted(self.info.symbols.items()):
            off = self.off_of(va)
            if off is not None:
                lines.append('%s %s' % (self.fmt_addr(off), nm))
        for off, c in sorted(self.ucomments.items()):
            lines.append('%s *%s' % (self.fmt_addr(off), c))
        try:
            with open(os.path.expanduser(name), 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n')
        except OSError as e:
            self.set_msg(str(e), True)
            return
        self.set_msg('Exported %d lines to %s' % (len(lines), name))

    # ---------------------------------------------------------- utilities

    def toggle_beeps(self):
        self.beeps = not self.beeps
        self.set_msg('Beeps ' + ('on' if self.beeps else 'off'))

    def output_text(self, title, text, default):
        r = self.list_dialog(title, [('Save to file', 'file'), ('Copy to clipboard', 'clip')], filterable=False)
        if r == 'clip':
            if to_clipboard(text):
                self.set_msg('Copied to clipboard (%d lines)' % text.count('\n'))
            else:
                self.set_msg('No clipboard tool (pbcopy / clip / wl-copy / xclip)', True)
        elif r == 'file':
            name = self.input_dialog(title + ': file', default, 60, select=True)
            if not name:
                return
            try:
                with open(os.path.expanduser(name), 'a', encoding='utf-8') as f:
                    f.write(text + '\n')
                self.set_msg('Written to ' + name)
            except OSError as e:
                self.set_msg(str(e), True)

    def screenshot(self):
        self.msg = None
        self.draw()
        lines = []
        for y in range(self.h):
            try:
                lines.append(self.scr.instr(y, 0, self.w).decode('utf-8', 'replace').rstrip())
            except curses.error:
                lines.append('')
        self.output_text('Screenshot (Alt-P)', '\n'.join(lines), 'hiew.prn')

    def calc(self, octal_zero=True):
        pos = self.cur if self.edit else self.position()

        def read(code):
            if code in 'oO':
                return self.va_of(pos) if code == 'o' else pos
            n = {'b': 1, 'w': 2, 'd': 4, 'q': 8}[code.lower()]
            d = self.buf.read(pos, n).ljust(n, b'\0')
            return int.from_bytes(d, 'little', signed=code.islower())
        return Calc(read, {'$': self.va_of(pos) if self.show_va else pos}, octal_zero)

    def calculator(self):
        A = self.A
        le = LineEdit(self.calc_text)
        while True:
            bw, bh = min(self.w - 2, 72), 10
            if self.calc_y is None:
                self.calc_y = (self.h - bh) // 2
            self.calc_y = clamp(self.calc_y, 0, max(0, self.h - bh))
            y0, x0 = self.calc_y, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, bh, bw, 'Calculator')
            fw = bw - 4
            vis, cx = le.view(fw)
            self.put(y0 + 1, x0 + 2, vis.ljust(fw), A['input'])
            try:
                lines = calc_lines(self.calc().eval(le.text)) if le.text.strip() else ['']
            except CalcError as e:
                lines = [str(e)]
            for i, l in enumerate(lines):
                self.put(y0 + 2 + i, x0 + 2, l[:fw], A['dlg'])
            self.put(y0 + 8, x0 + 2, 'hex default, 10t dec, 17o oct, 101i bin; @b @w @d @q @B @W @D @Q @o @O $ ; '
                     'Up/Down move'[:fw], A['dlghdr'])
            self.apply_cursor((y0 + 1, x0 + 2 + cx))
            self.scr.refresh()
            k = self.getkey()
            if k in ('ESC', 'F10', 'ENTER'):
                self.calc_text = le.text
                self.apply_cursor(None)
                return
            if k == 'UP':
                self.calc_y -= 1
            elif k == 'DOWN':
                self.calc_y += 1
            else:
                le.key(k)

    def info_lines(self):
        st = os.stat(self.buf.path)
        free = '?'
        try:
            if hasattr(os, 'sysconf') and 'SC_AVPHYS_PAGES' in os.sysconf_names:
                free = nbytes(os.sysconf('SC_AVPHYS_PAGES') * os.sysconf('SC_PAGE_SIZE'))
        except (ValueError, OSError):
            pass
        return ['File:     %s' % self.buf.path,
                'Size:     %s' % nbytes(self.buf.size),
                'Modified: %s' % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.st_mtime)),
                'Format:   %s   arch %s' % (self.info.desc or 'raw', self.arch),
                'hiew %s, Python %s, %s %s' % (VERSION, platform.python_version(), platform.system(), platform.machine()),
                'Free memory: %s' % free,
                'Last error: %s' % (self.last_error or '-')]

    def info_box(self):
        lines = self.info_lines()
        bw = min(self.w - 2, max(len(l) for l in lines) + 4)
        bh = len(lines) + 2
        y0, x0 = (self.h - bh) // 2, (self.w - bw) // 2
        y, x = self.scr.getyx()
        self.box(y0, x0, bh, bw, 'Info (Ctrl+Alt)')
        for i, l in enumerate(lines):
            self.put(y0 + 1 + i, x0 + 2, l[:bw - 4], self.A['dlg'])
        try:
            self.scr.move(y, x)
        except curses.error:
            pass
        self.scr.refresh()

    def info_box_wait(self):
        self.list_dialog('Info', [(l, None) for l in self.info_lines()], filterable=False)

    # ---------------------------------------------------------- crypt dialog (Alt-F3 / Ctrl-F7 in edit)

    def crypt_dialog(self, edit=False):
        A = self.A
        lines = [l for l in re.split(r'[;\n]', self.crypt.text)] if self.crypt else ['xor al, 55h']
        lines = [re.sub(r'^\s*\d+[.:)]?\s+', '', l).strip() for l in lines if l.strip()] or ['']
        width = self.crypt.width if self.crypt else 1
        row = 0
        le = LineEdit(lines[0])
        fresh = bool(lines[0])      # first key typed on the suggested line replaces it
        err = ''
        names = {1: 'Byte', 2: 'Word', 4: 'Dword', 8: 'Qword'}
        while True:
            lines[row] = le.text
            bw, bh = min(self.w - 2, 66), min(self.h - 2, len(lines) + 6)
            y0, x0 = (self.h - bh) // 2, (self.w - bw) // 2
            self.draw(refresh=False)
            self.box(y0, x0, bh, bw, 'Crypt: %s (F2 size)' % names[width])
            top = max(0, row - (bh - 6) + 1)
            cur = None
            for i in range(min(len(lines) - top, bh - 5)):
                j = top + i
                self.put(y0 + 1 + i, x0 + 2, '%2d ' % (j + 1), A['dlghdr'])
                vis, cx = (le.view(bw - 9) if j == row else (lines[j][:bw - 9], 0))
                self.put(y0 + 1 + i, x0 + 5, vis.ljust(bw - 9), A['input'])
                if j == row:
                    cur = (y0 + 1 + i, x0 + 5 + cx)
            blk = self.block_range()
            tgt = 'block %Xh' % (blk[1] - blk[0]) if blk and not edit else 'cursor (F7 in edit)'
            self.put(y0 + bh - 3, x0 + 2, (err or 'al/ax/eax/rax = data, cl = 0 at start')[:bw - 4],
                     A['err'] if err else A['dlghdr'])
            self.put(y0 + bh - 2, x0 + 2, ('Enter line  Del  F9 apply: %s' % tgt)[:bw - 4], A['dlghdr'])
            self.apply_cursor(cur)
            self.scr.refresh()
            k = self.getkey()
            if k in ('ESC', 'F10'):
                self.apply_cursor(None)
                return
            if k == 'F2':
                width = {1: 2, 2: 4, 4: 8, 8: 1}[width]
                if fresh and len(lines) == 1:   # untouched suggestion follows the data size
                    le.set('xor %s, 55h' % {1: 'al', 2: 'ax', 4: 'eax', 8: 'rax'}[width])
                continue
            if fresh and len(k) == 1 and k.isprintable():
                le.set('')
            fresh = False
            err = ''
            if k == 'F2':
                pass
            elif k == 'ENTER':
                lines.insert(row + 1, '')
                row += 1
                le = LineEdit('')
            elif k == 'UP' and row > 0:
                row -= 1
                le = LineEdit(lines[row])
            elif k == 'DOWN' and row < len(lines) - 1:
                row += 1
                le = LineEdit(lines[row])
            elif k in ('DEL', 'BS') and not le.text and len(lines) > 1:
                del lines[row]
                row = max(0, row - (k == 'BS'))
                le = LineEdit(lines[row])
            elif k == 'F9':
                text = ' ; '.join(l for l in lines if l.strip())
                try:
                    self.crypt = Crypt(text, width)
                except ValueError as e:
                    err = str(e)
                    continue
                self.apply_cursor(None)
                if blk and not edit:
                    self.cry_block()
                else:
                    self.set_msg('Crypt set (%s): F7 in edit mode applies it' % names[width])
                return
            else:
                le.key(k)

    def cry_set(self):
        self.crypt_dialog(edit=True)
        return self.crypt is not None

    # ---------------------------------------------------------- assembler

    def asm_text(self, title):
        if not HAVE_KS:
            self.set_msg('Assembler needs keystone: ' + KS_HINT, True)
            return None
        s = self.input_dialog(title, '', 60, 'e.g.  jmp 401000h ; call eax ; xor eax, eax')
        if not s:
            return None
        try:
            return assemble(self.arch, s, self.va_of(self.position()), self.info.endian == '>')
        except Exception as e:
            self.set_msg('Asm: %s' % e, True)
            return None

    def asm_here(self, initial=None):
        if not HAVE_KS:
            self.set_msg('Assembler needs keystone: ' + KS_HINT, True)
            return False
        lst = self.decode_at(self.cur, 1)
        default = ('%s %s' % (lst[0].mnem, lst[0].ops)).strip() if lst and lst[0].kind != 'bad' else ''
        s = self.input_dialog('Assemble at %s (Esc - stop)' % self.fmt_addr(self.cur),
                              default if initial is None else initial, 64,
                              'e.g.  jmp 401000h ; nop ; xor eax, eax', select=initial is None)
        if not s:
            return False
        try:
            code = assemble(self.arch, s, self.va_of(self.cur), self.info.endian == '>')
        except Exception as e:
            self.set_msg('Asm: %s' % e, True)
            return False
        self.buf.write_bytes(self.cur, code)
        self.edit_move(min(self.cur + len(code), self.buf.size - 1))
        return True
