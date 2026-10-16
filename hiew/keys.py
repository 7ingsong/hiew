"""Terminal-independent key decoding.

Every key is normalized to a string: 'F7', 'C-F7', 'S-F7', 'A-F1', 'UP', 'C-LEFT',
'ENTER', 'ESC', 'TAB', 'BS', 'A-x', 'C-n', 'MOUSE', 'RESIZE' or a single character.

Fallbacks for terminals that eat function keys (macOS Terminal, tmux, ssh):
Alt+1..Alt+9 = F1..F9, Alt+0 = F10 (Esc then digit works too).
"""
import curses
import sys

WIN = sys.platform.startswith('win')


def _fkey(n):
    if 1 <= n <= 12:
        return 'F%d' % n
    if 13 <= n <= 24:
        return 'S-F%d' % (n - 12)
    if 25 <= n <= 36:
        return 'C-F%d' % (n - 24)
    if 37 <= n <= 48:  # PDCurses: Alt+Fn; xterm: Ctrl+Shift+Fn
        return ('A-F%d' if WIN else 'CS-F%d') % (n - 36)
    if 49 <= n <= 60:
        return 'A-F%d' % (n - 48)
    return None


_BASIC = {}
for _name, _val in (('KEY_UP', 'UP'), ('KEY_DOWN', 'DOWN'), ('KEY_LEFT', 'LEFT'), ('KEY_RIGHT', 'RIGHT'),
                    ('KEY_PPAGE', 'PGUP'), ('KEY_NPAGE', 'PGDN'), ('KEY_HOME', 'HOME'), ('KEY_END', 'END'),
                    ('KEY_ENTER', 'ENTER'), ('KEY_BACKSPACE', 'BS'), ('KEY_DC', 'DEL'), ('KEY_IC', 'INS'),
                    ('KEY_BTAB', 'S-TAB'), ('KEY_RESIZE', 'RESIZE'), ('KEY_MOUSE', 'MOUSE'),
                    ('KEY_SLEFT', 'S-LEFT'), ('KEY_SRIGHT', 'S-RIGHT'), ('KEY_SHOME', 'S-HOME'),
                    ('KEY_SEND', 'S-END'), ('KEY_SR', 'S-UP'), ('KEY_SF', 'S-DOWN'),
                    ('KEY_SPREVIOUS', 'S-PGUP'), ('KEY_SNEXT', 'S-PGDN'), ('KEY_A1', 'HOME'), ('KEY_A3', 'PGUP'), ('KEY_C1', 'END'),
                    ('KEY_C3', 'PGDN'), ('KEY_B2', '5')):
    if hasattr(curses, _name):
        _BASIC[getattr(curses, _name)] = _val

_KEYNAMES = {
    'kLFT5': 'C-LEFT', 'kRIT5': 'C-RIGHT', 'kUP5': 'C-UP', 'kDN5': 'C-DOWN', 'kHOM5': 'C-HOME',
    'kEND5': 'C-END', 'kPRV5': 'C-PGUP', 'kNXT5': 'C-PGDN', 'kDC5': 'C-DEL',
    'kLFT3': 'A-LEFT', 'kRIT3': 'A-RIGHT', 'kUP3': 'A-UP', 'kDN3': 'A-DOWN',
    'kLFT2': 'S-LEFT', 'kRIT2': 'S-RIGHT', 'kUP': 'S-UP', 'kDN': 'S-DOWN',
    # PDCurses (windows-curses)
    'CTL_LEFT': 'C-LEFT', 'CTL_RIGHT': 'C-RIGHT', 'CTL_UP': 'C-UP', 'CTL_DOWN': 'C-DOWN',
    'CTL_HOME': 'C-HOME', 'CTL_END': 'C-END', 'CTL_PGUP': 'C-PGUP', 'CTL_PGDN': 'C-PGDN',
    'PADPLUS': '+', 'PADMINUS': '-', 'PADSTAR': '*', 'PADSLASH': '/', 'PADENTER': 'ENTER',
    'CTL_PADENTER': 'C-ENTER', 'CTL_ENTER': 'C-ENTER', 'ALT_PADENTER': 'ENTER', 'KEY_B2': '5',
    'ALT_LEFT': 'A-LEFT', 'ALT_RIGHT': 'A-RIGHT', 'ALT_UP': 'A-UP', 'ALT_DOWN': 'A-DOWN',
}

_CSI_TILDE = {'1': 'HOME', '2': 'INS', '3': 'DEL', '4': 'END', '5': 'PGUP', '6': 'PGDN', '7': 'HOME',
              '8': 'END', '11': 'F1', '12': 'F2', '13': 'F3', '14': 'F4', '15': 'F5', '17': 'F6',
              '18': 'F7', '19': 'F8', '20': 'F9', '21': 'F10', '23': 'F11', '24': 'F12',
              # VT220 F13..F20: macOS Terminal.app sends these for Option/Shift + F-keys
              '25': 'VT13', '26': 'VT14', '28': 'VT15', '29': 'VT16', '31': 'VT17', '32': 'VT18',
              '33': 'VT19', '34': 'VT20'}
_CSI_FINAL = {'A': 'UP', 'B': 'DOWN', 'C': 'RIGHT', 'D': 'LEFT', 'H': 'HOME', 'F': 'END',
              'P': 'F1', 'Q': 'F2', 'R': 'F3', 'S': 'F4', 'Z': 'S-TAB'}
_MODS = {2: 'S-', 3: 'A-', 4: 'AS-', 5: 'C-', 6: 'CS-', 7: 'CA-', 8: 'CAS-'}


HELD = set()        # modifiers currently held, as reported by the kitty keyboard protocol
ESC_PREFIX = False  # set while the main view reads keys: Esc+key = Alt+key
ESC_WAIT = 500     # ms: a key pressed within this time after a lone Esc becomes Alt+key
CTRL_H_IS_CBS = False   # set at startup when the terminal's Backspace sends DEL (^?)
READ_TIMEOUT = -1   # curses input timeout in ms (-1 = block); the app polls modifiers on timeouts

_KITTY_MODKEYS = {57441: 'S', 57447: 'S', 57442: 'C', 57448: 'C', 57443: 'A', 57449: 'A'}
_KITTY_KEYS = {13: 'ENTER', 9: 'TAB', 27: 'ESC', 127: 'BS', 8: 'BS',
               57409: '.', 57410: '/', 57411: '*', 57412: '-', 57413: '+', 57414: 'ENTER', 57415: '=',
               57417: 'LEFT', 57418: 'RIGHT', 57419: 'UP', 57420: 'DOWN', 57421: 'PGUP', 57422: 'PGDN',
               57423: 'HOME', 57424: 'END', 57425: 'INS', 57426: 'DEL'}
for _i in range(10):
    _KITTY_KEYS[57399 + _i] = str(_i)


def _mods(field):
    """'5' or '5:1' -> (modifier bits shift=1 alt=2 ctrl=4, event type 1 press / 2 repeat / 3 release)."""
    m, _, ev = field.partition(':')
    bits = (int(m) - 1) & 7 if m.isdigit() and int(m) > 0 else 0
    return bits, int(ev) if ev.isdigit() else 1


def _sync_held(bits):
    HELD.clear()
    HELD.update(n for n, b in (('S', 1), ('A', 2), ('C', 4)) if bits & b)


def parse_csi(seq):
    """seq is everything after ESC, e.g. '[1;5D', '[18;5~', 'OP', '[97;1:1;97u' (kitty).

    Returns a key name, 'MODS' (only the modifier state changed) or 'RELEASE' (ignore).
    """
    if len(seq) < 2:
        return None
    if seq[0] == 'O':
        return _CSI_FINAL.get(seq[1])
    body, final = seq[1:-1], seq[-1]
    if body.startswith('?'):
        return 'RELEASE'   # stray terminal reply
    parts = body.split(';')
    bits, ev = _mods(parts[1]) if len(parts) > 1 else (0, 1)
    prefix = _MODS.get(bits + 1, '')
    key0 = parts[0].split(':')
    code = None
    if final == 'u' and key0[0].isdigit():                        # CSI 97;5u  (kitty / fixterms)
        code = int(key0[0])
        if code in _KITTY_MODKEYS:
            m = _KITTY_MODKEYS[code]
            if ev == 3:
                HELD.discard(m)
            else:
                HELD.add(m)
            return 'MODS'
        if len(parts) > 1:
            _sync_held(bits)
        if ev == 3:
            return 'RELEASE'
        if 57344 <= code <= 63743 and code not in _KITTY_KEYS:
            return 'RELEASE'   # caps lock, media keys ...
        base = _KITTY_KEYS.get(code)
        if base:
            return prefix + base if len(base) > 1 else base
        text = ''
        if len(parts) > 2:
            text = ''.join(chr(int(c)) for c in parts[2].split(':') if c.isdigit())
        if text and not bits & 6:
            return text[0]
        if bits & 1 and len(key0) > 1 and key0[1].isdigit():
            code = int(key0[1])          # shifted key from "report alternate keys"
        if code < 32 or code > 0x10FFFF:
            return None
        ch = chr(code)
        if bits & 1 and not (len(key0) > 1 and key0[1]):
            ch = ch.upper()
        if bits & 4:
            return ('CA-' if bits & 2 else 'C-') + ch.lower()
        if bits & 2:
            return 'A-' + ch
        return ch
    if final == '~' and parts[0] == '27' and len(parts) == 3:    # CSI 27;5;13~ (xterm modifyOtherKeys)
        code = int(parts[2]) if parts[2].isdigit() else 0
        base = {13: 'ENTER', 9: 'TAB', 27: 'ESC', 127: 'BS', 8: 'BS'}.get(code)
        if base:
            return prefix + base
        if 32 <= code <= 0x10FFFF:
            ch = chr(code)
            if bits & 4:
                return 'C-' + ch.lower()
            return ('A-' + ch) if bits & 2 else ch
        return None
    if len(parts) > 1 and ':' in parts[1]:
        _sync_held(bits)
        if ev == 3:
            return 'RELEASE'
    if final == '~':
        base = _CSI_TILDE.get(key0[0])
    else:
        base = _CSI_FINAL.get(final)
    if not base:
        return None
    return prefix + base


def int_key(k):
    if k == getattr(curses, 'KEY_BACKSPACE', -1) and CTRL_H_IS_CBS:
        return 'C-BS'
    if curses.KEY_F0 < k <= curses.KEY_F0 + 63:
        return _fkey(k - curses.KEY_F0)
    if k in _BASIC:
        return _BASIC[k]
    try:
        name = curses.keyname(k).decode('ascii', 'replace')
    except Exception:
        return None
    if name in _KEYNAMES:
        return _KEYNAMES[name]
    if name.startswith('ALT_') and len(name) == 5:
        return _alt(name[4].lower())
    return None


def _alt(ch):
    return 'A-' + ch


def _char_key(c):
    if c == '\r' or (c == '\n' and WIN):
        return 'ENTER'
    if c == '\n':          # Ctrl+Enter / Ctrl+J (curses runs in nonl mode)
        return 'C-ENTER'
    if c == '\t':
        return 'TAB'
    if c == '\x7f' or (c == '\x08' and WIN):
        return 'BS'
    if c == '\x08':
        return 'C-BS' if CTRL_H_IS_CBS else 'BS'
    if c == '\x1f':
        return 'C--'       # Ctrl+- / Ctrl+_
    o = ord(c)
    if o < 32:
        return 'C-' + chr(o + 96)
    return c


def _getc(win):
    try:
        return win.get_wch()
    except curses.error:
        return None


def read_key(win):
    k = _getc(win)
    if k is None:
        return None
    if isinstance(k, int):
        return int_key(k)
    if k != '\x1b':
        return _char_key(k)
    # ESC: plain Escape, Alt+key, or an escape sequence curses didn't decode
    win.nodelay(True)
    try:
        k2 = _getc(win)
        if k2 is None and not ESC_PREFIX:
            return 'ESC'
        if k2 is None:
            # a lone Esc: wait a little - Esc, then F6 means Alt+F6 (terminals without Alt+Fn)
            win.timeout(ESC_WAIT)
            k2 = _getc(win)
            win.nodelay(True)
            if k2 is None:
                return 'ESC'
            if k2 == '\x1b':
                return 'ESC'   # Esc Esc - immediate Escape
        if isinstance(k2, int):
            nk = int_key(k2)
            return ('A-' + nk) if nk and len(nk) > 1 and '-' not in nk else nk
        if k2 == '\x1b':
            # Esc, Esc+F-key  ->  Alt+F-key (for terminals that don't send Alt+Fn)
            k3 = _getc(win)
            if k3 is None:
                return 'ESC'
            if isinstance(k3, int):
                nk = int_key(k3)
            elif k3 in ('[', 'O'):
                seq = k3
                for _ in range(64):
                    c = _getc(win)
                    if not isinstance(c, str):
                        break
                    seq += c
                    if (k3 == 'O' and len(seq) == 2) or (len(seq) > 1 and '@' <= c <= '~'):
                        break
                nk = parse_csi(seq)
            else:
                return 'ESC'
            if nk in ('RELEASE', 'MODS'):
                return None if nk == 'RELEASE' else nk
            if nk and '-' not in nk:
                return 'A-' + nk
            return nk
        if k2 in ('[', 'O'):
            seq = k2
            if k2 == 'O':
                c = _getc(win)
                if isinstance(c, str):
                    seq += c
            else:
                for _ in range(64):
                    c = _getc(win)
                    if not isinstance(c, str):
                        break
                    seq += c
                    if '@' <= c <= '~':
                        break
            r = parse_csi(seq)
            if r is None and seq in ('[', 'O'):
                return _alt(seq)
            return None if r == 'RELEASE' else r
        return _alt(k2) if len(_char_key(k2)) == 1 else 'A-' + _char_key(k2)
    finally:
        win.nodelay(False)
        win.timeout(READ_TIMEOUT)
