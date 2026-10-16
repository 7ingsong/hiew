"""Live Alt / Ctrl / Shift state, so the bottom keybar can switch like in Hiew.

A terminal never sends "Alt pressed" by itself, so two sources are used:
  * the kitty keyboard protocol (kitty, WezTerm, Ghostty, foot, Alacritty, iTerm2 ...):
    the terminal reports modifier press/release events; works over ssh too;
  * otherwise, on a local session, the OS is asked for the physical modifier state:
    macOS CoreGraphics, Windows GetAsyncKeyState, Linux X11 XQueryKeymap.
"""
import ctypes
import ctypes.util
import os
import re
import sys
import time

KITTY_FLAGS = 31   # disambiguate | event types | alternate keys | all keys as escapes | associated text


class ModWatcher:
    def __init__(self):
        self._poll = None
        self.source = None
        if os.environ.get('SSH_CONNECTION') or os.environ.get('SSH_TTY') or os.environ.get('HIEW_NO_MODPOLL'):
            return   # the OS here is not the one with the keyboard
        try:
            if sys.platform == 'darwin':
                self._mac()
            elif sys.platform.startswith('win'):
                self._win()
            elif os.environ.get('DISPLAY'):
                self._x11()
        except Exception:
            self._poll = None
            self.source = None

    @property
    def available(self):
        return self._poll is not None

    def poll(self):
        if self._poll is None:
            return frozenset()
        try:
            return self._poll()
        except Exception:
            self._poll = None
            return frozenset()

    def _mac(self):
        lib = ctypes.cdll.LoadLibrary('/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices')
        f = lib.CGEventSourceFlagsState
        f.restype = ctypes.c_uint64
        f.argtypes = [ctypes.c_int32]

        def poll():
            v = f(0)   # kCGEventSourceStateCombinedSessionState
            return frozenset(m for m, bit in (('S', 0x20000), ('C', 0x40000), ('A', 0x80000)) if v & bit)
        poll()
        self._poll, self.source = poll, 'macOS'

    def _win(self):
        g = ctypes.windll.user32.GetAsyncKeyState
        g.restype = ctypes.c_short
        g.argtypes = [ctypes.c_int]

        def poll():
            return frozenset(m for m, vk in (('S', 0x10), ('C', 0x11), ('A', 0x12)) if g(vk) & 0x8000)
        poll()
        self._poll, self.source = poll, 'Windows'

    def _x11(self):
        x = ctypes.cdll.LoadLibrary(ctypes.util.find_library('X11'))
        x.XOpenDisplay.restype = ctypes.c_void_p
        x.XOpenDisplay.argtypes = [ctypes.c_char_p]
        x.XKeysymToKeycode.restype = ctypes.c_ubyte
        x.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        x.XQueryKeymap.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        d = x.XOpenDisplay(None)
        if not d:
            raise OSError('no X display')
        codes = {m: [x.XKeysymToKeycode(d, s) for s in syms]
                 for m, syms in (('S', (0xffe1, 0xffe2)), ('C', (0xffe3, 0xffe4)), ('A', (0xffe9, 0xffea, 0xffe7)))}
        buf = ctypes.create_string_buffer(32)

        def poll():
            x.XQueryKeymap(d, buf)
            keys = buf.raw
            return frozenset(m for m, kcs in codes.items() if any(kc and keys[kc // 8] >> (kc % 8) & 1 for kc in kcs))
        poll()
        self._poll, self.source = poll, 'X11'


def _write(s):
    try:
        os.write(sys.stdout.fileno(), s.encode())
    except OSError:
        pass


def kitty_enable(scr, wait=0.3):
    """Ask the terminal whether it speaks the kitty keyboard protocol and turn it on. Returns True if on."""
    if sys.platform.startswith('win') or os.environ.get('HIEW_NO_KITTY'):
        return False
    _write('\x1b[?u\x1b[c')   # query kitty flags, then primary DA as a terminator every terminal answers
    got = ''
    scr.timeout(30)
    end = time.time() + wait
    try:
        while time.time() < end:
            try:
                c = scr.get_wch()
            except Exception:
                continue
            if isinstance(c, str):
                got += c
                if re.search(r'\x1b\[\?[\d;]*c', got):
                    break
    finally:
        scr.timeout(-1)
    if not re.search(r'\x1b\[\?\d*u', got):
        return False
    _write('\x1b[>%du' % KITTY_FLAGS)
    return True


def kitty_disable():
    _write('\x1b[<u')


# macOS Terminal.app (default profile) encodes modified function keys VT220-style:
# Option+F1..F12 -> F6..F12, F13..F17 and Shift+F5..F12 -> F13..F20 (Shift+F7 arrives as F15).
_APPLE_ALT = {'F6': 1, 'F7': 2, 'F8': 3, 'F9': 4, 'F10': 5, 'F11': 6, 'F12': 7,
              'VT13': 8, 'VT14': 9, 'VT15': 10, 'VT16': 11, 'VT17': 12}
_APPLE_SHIFT = {'VT13': 5, 'VT14': 6, 'VT15': 7, 'VT16': 8, 'VT17': 9, 'VT18': 10, 'VT19': 11, 'VT20': 12}
APPLE_TERMINAL = os.environ.get('TERM_PROGRAM') == 'Apple_Terminal'
# characters macOS (US layout) types for Option+key when "Use Option as Meta" is off
MAC_OPTION = {'\u00a1': '1', '\u2122': '2', '\u00a3': '3', '\u00a2': '4', '\u221e': '5', '\u00a7': '6',
              '\u00b6': '7', '\u2022': '8', '\u00aa': '9', '\u00ba': '0', '\u2013': '-', '\u2260': '=',
              '\u00b5': 'm', '\u00c2': 'M', '\u03c0': 'p', '\u220f': 'P', '\u222b': 'b', '\u00b0': '*',
              '\u00bf': '?', '\u00f7': '/', '\u02dc': 'N'}


def translate(k, held, kitty=False):
    """Apply physically held modifiers to function keys the terminal sent unmodified."""
    if not k or kitty:
        return k
    if APPLE_TERMINAL or k.startswith('VT'):
        if 'A' in held and k in _APPLE_ALT:
            return 'A-F%d' % _APPLE_ALT[k]
        if 'S' in held and k in _APPLE_SHIFT:
            return 'S-F%d' % _APPLE_SHIFT[k]
        if k.startswith('VT'):   # no modifier info: Option is the common case
            n = _APPLE_ALT.get(k)
            return 'A-F%d' % n if n else None
    if held and len(k) == 1 and not ('C' in held and 'A' in held):   # Ctrl+Alt = AltGr: real text
        if 'C' in held and k in '0123456789.-*/':
            return 'C-' + k
        if 'A' in held:
            base = MAC_OPTION.get(k)
            if base:
                return 'A-' + base
            if k.isascii() and k.isprintable():
                return 'A-' + k
        return k
    if held and k == 'BS' and 'C' in held:
        return 'C-BS'
    if held and (k == 'ENTER' or (k[:1] == 'F' and k[1:].isdigit())):
        pre = 'C-' if 'C' in held else 'A-' if 'A' in held else 'S-'
        if k != 'ENTER' or pre == 'C-':
            return pre + k
    return k


def keytest(scr, opts):
    """hiew --keys: show the raw bytes the terminal sends and what hiew makes of them."""
    import curses
    from . import keys as K
    watch = ModWatcher()
    kitty = getattr(opts, 'kitty', True) and kitty_enable(scr)
    scr.keypad(False)                 # raw bytes, we decode them ourselves
    scr.timeout(60)
    lines = []
    try:
        while True:
            held = frozenset(K.HELD) if kitty else watch.poll()
            h, w = scr.getmaxyx()
            scr.erase()
            info = 'kitty protocol: %s   OS modifier polling: %s   TERM_PROGRAM=%s   TERM=%s' % (
                'on' if kitty else 'off', watch.source or 'off', os.environ.get('TERM_PROGRAM', '-'),
                os.environ.get('TERM', '-'))
            scr.addstr(0, 0, ' hiew key test - press keys, Ctrl+C to quit'[:w - 1], curses.A_REVERSE)
            scr.addstr(1, 0, info[:w - 1])
            scr.addstr(2, 0, ('modifiers held now: %s' % (' '.join(sorted(held)) or '-'))[:w - 1])
            scr.addstr(3, 0, ('%-28s %-12s %-6s %s' % ('raw bytes', 'decoded', 'held', '-> command'))[:w - 1],
                       curses.A_BOLD)
            for i, l in enumerate(lines[-(h - 5):]):
                scr.addstr(4 + i, 0, l[:w - 1])
            scr.refresh()
            try:
                c = scr.get_wch()
            except curses.error:
                continue
            raw = [c]
            scr.timeout(30)
            while True:                     # the rest of an escape sequence arrives together
                try:
                    raw.append(scr.get_wch())
                except curses.error:
                    break
            scr.timeout(60)
            text = ''.join(x if isinstance(x, str) else chr(x) for x in raw)
            if text == '\x03':
                return
            held = frozenset(K.HELD) if kitty else watch.poll()
            if text.startswith('\x1b\x1b') and len(text) > 2 and text[2] in '[O':   # Esc + key = Alt+key
                k = K.parse_csi(text[2:])
                k = 'A-' + k if k and '-' not in k else k
            elif text.startswith('\x1b') and len(text) > 1 and text[1] in '[O':
                k = K.parse_csi(text[1:])
            elif text.startswith('\x1b') and len(text) == 2:
                k = K._alt(text[1]) if len(K._char_key(text[1])) == 1 else 'A-' + K._char_key(text[1])
            elif text == '\x1b':
                k = 'ESC'
            else:
                k = K._char_key(text[0])
            t = translate(k, held, kitty) if k not in (None, 'MODS', 'RELEASE') else k
            lines.append('%-28s %-12s %-6s -> %s' % (repr(text)[1:-1][:28], k, ''.join(sorted(held)) or '-', t))
    finally:
        if kitty:
            kitty_disable()
