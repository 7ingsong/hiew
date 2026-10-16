"""Colour themes. Each role maps to (foreground, background, extra attribute name).

256-colour palettes are fixed xterm indexes, so they look the same in every terminal;
the 8-colour variants are used when the terminal has fewer colours.
"""
import json
import os
import sys

THEMES = ('hiew', 'blue', 'dark', 'light')

ROLES = ('norm', 'bright', 'addr', 'status', 'keynum', 'keylbl', 'cursor', 'cursor2', 'mod', 'block',
         'found', 'jump', 'call', 'ret', 'comment', 'name', 'bad', 'dlg', 'dlgframe', 'dlgtitle',
         'dlgsel', 'dlghdr', 'input', 'msg', 'err')


def _hiew(bg):
    CYAN, LCYAN, DCYAN, WHITE, BLACK, YEL, GRN, MAG, RED, GREY = 44, 87, 37, 231, 16, 227, 120, 213, 196, 250
    return {
        'norm': (LCYAN, bg, ''), 'bright': (WHITE, bg, ''), 'addr': (CYAN, bg, ''),
        'status': (BLACK, DCYAN, ''), 'keynum': (WHITE, BLACK, ''), 'keylbl': (BLACK, DCYAN, ''),
        'cursor': (BLACK, DCYAN, ''), 'cursor2': (WHITE, BLACK, ''), 'mod': (YEL, bg, ''),
        'block': (bg, GREY, ''), 'found': (BLACK, YEL, ''), 'jump': (WHITE, bg, 'bold'),
        'call': (YEL, bg, ''), 'ret': (MAG, bg, ''), 'comment': (GRN, bg, ''),
        'name': (YEL, bg, ''), 'bad': (RED, bg, ''), 'dlg': (BLACK, DCYAN, ''),
        'dlgframe': (17, DCYAN, ''), 'dlgtitle': (BLACK, DCYAN, 'bold'), 'dlgsel': (WHITE, BLACK, ''),
        'dlghdr': (17, DCYAN, ''), 'input': (WHITE, bg, ''), 'msg': (YEL, 23, 'bold'),
        'err': (WHITE, 124, 'bold'),
    }


PALETTES_256 = {
    'hiew': _hiew(17),     # deep navy
    'blue': _hiew(19),     # DOS blue #0000AF
    'dark': {
        'norm': (252, 234, ''), 'bright': (255, 234, ''), 'addr': (244, 234, ''),
        'status': (252, 238, ''), 'keynum': (255, 232, ''), 'keylbl': (250, 238, ''),
        'cursor': (16, 74, ''), 'cursor2': (255, 238, ''), 'mod': (214, 234, ''),
        'block': (255, 24, ''), 'found': (16, 220, ''), 'jump': (255, 234, 'bold'),
        'call': (221, 234, ''), 'ret': (176, 234, ''), 'comment': (108, 234, ''),
        'name': (179, 234, ''), 'bad': (203, 234, ''), 'dlg': (252, 237, ''),
        'dlgframe': (245, 237, ''), 'dlgtitle': (221, 237, 'bold'), 'dlgsel': (16, 74, ''),
        'dlghdr': (249, 237, ''), 'input': (255, 235, ''), 'msg': (221, 238, 'bold'),
        'err': (255, 124, 'bold'),
    },
    'light': {
        'norm': (236, 255, ''), 'bright': (16, 255, ''), 'addr': (244, 255, ''),
        'status': (16, 152, ''), 'keynum': (255, 24, ''), 'keylbl': (16, 152, ''),
        'cursor': (255, 25, ''), 'cursor2': (16, 250, ''), 'mod': (160, 255, 'bold'),
        'block': (16, 153, ''), 'found': (231, 166, 'bold'), 'jump': (16, 255, 'bold'),
        'call': (130, 255, ''), 'ret': (90, 255, ''), 'comment': (28, 255, ''),
        'name': (94, 255, 'bold'), 'bad': (160, 255, ''), 'dlg': (16, 153, ''),
        'dlgframe': (24, 153, ''), 'dlgtitle': (17, 153, 'bold'), 'dlgsel': (255, 25, ''),
        'dlghdr': (238, 153, ''), 'input': (16, 231, ''), 'msg': (124, 152, 'bold'),
        'err': (255, 160, 'bold'),
    },
}


def palette_8(theme, C):
    """8-colour variant (terminal has fewer than 256 colours)."""
    if theme == 'dark':
        bg, fg, hi, panel = C.COLOR_BLACK, C.COLOR_WHITE, C.COLOR_WHITE, C.COLOR_WHITE
        return {
            'norm': (fg, bg, ''), 'bright': (hi, bg, 'bold'), 'addr': (C.COLOR_CYAN, bg, ''),
            'status': (C.COLOR_BLACK, panel, ''), 'keynum': (C.COLOR_WHITE, C.COLOR_BLACK, 'bold'),
            'keylbl': (C.COLOR_BLACK, panel, ''), 'cursor': (C.COLOR_BLACK, C.COLOR_CYAN, ''),
            'cursor2': (C.COLOR_WHITE, C.COLOR_BLUE, ''), 'mod': (C.COLOR_YELLOW, bg, 'bold'),
            'block': (C.COLOR_WHITE, C.COLOR_BLUE, ''), 'found': (C.COLOR_BLACK, C.COLOR_YELLOW, ''),
            'jump': (C.COLOR_WHITE, bg, 'bold'), 'call': (C.COLOR_YELLOW, bg, ''), 'ret': (C.COLOR_MAGENTA, bg, ''),
            'comment': (C.COLOR_GREEN, bg, ''), 'name': (C.COLOR_YELLOW, bg, 'bold'), 'bad': (C.COLOR_RED, bg, ''),
            'dlg': (C.COLOR_BLACK, panel, ''), 'dlgframe': (C.COLOR_BLACK, panel, ''),
            'dlgtitle': (C.COLOR_BLUE, panel, 'bold'), 'dlgsel': (C.COLOR_WHITE, C.COLOR_BLUE, 'bold'),
            'dlghdr': (C.COLOR_BLUE, panel, ''), 'input': (C.COLOR_WHITE, C.COLOR_BLACK, 'bold'),
            'msg': (C.COLOR_YELLOW, C.COLOR_BLACK, 'bold'), 'err': (C.COLOR_WHITE, C.COLOR_RED, 'bold'),
        }
    if theme == 'light':
        bg, fg = C.COLOR_WHITE, C.COLOR_BLACK
        return {
            'norm': (fg, bg, ''), 'bright': (fg, bg, 'bold'), 'addr': (C.COLOR_BLUE, bg, ''),
            'status': (C.COLOR_WHITE, C.COLOR_BLUE, ''), 'keynum': (C.COLOR_WHITE, C.COLOR_BLACK, 'bold'),
            'keylbl': (C.COLOR_WHITE, C.COLOR_BLUE, ''), 'cursor': (C.COLOR_WHITE, C.COLOR_BLUE, ''),
            'cursor2': (C.COLOR_BLACK, C.COLOR_CYAN, ''), 'mod': (C.COLOR_RED, bg, 'bold'),
            'block': (C.COLOR_BLACK, C.COLOR_CYAN, ''), 'found': (C.COLOR_BLACK, C.COLOR_YELLOW, ''),
            'jump': (fg, bg, 'bold'), 'call': (C.COLOR_RED, bg, ''), 'ret': (C.COLOR_MAGENTA, bg, ''),
            'comment': (C.COLOR_BLUE, bg, 'bold'), 'name': (C.COLOR_RED, bg, 'bold'), 'bad': (C.COLOR_RED, bg, ''),
            'dlg': (C.COLOR_BLACK, C.COLOR_CYAN, ''), 'dlgframe': (C.COLOR_BLUE, C.COLOR_CYAN, ''),
            'dlgtitle': (C.COLOR_BLACK, C.COLOR_CYAN, 'bold'), 'dlgsel': (C.COLOR_WHITE, C.COLOR_BLUE, 'bold'),
            'dlghdr': (C.COLOR_BLUE, C.COLOR_CYAN, ''), 'input': (C.COLOR_BLACK, C.COLOR_WHITE, 'bold'),
            'msg': (C.COLOR_YELLOW, C.COLOR_BLUE, 'bold'), 'err': (C.COLOR_WHITE, C.COLOR_RED, 'bold'),
        }
    B = C.COLOR_BLUE   # hiew / blue
    return {
        'norm': (C.COLOR_CYAN, B, 'bold'), 'bright': (C.COLOR_WHITE, B, 'bold'), 'addr': (C.COLOR_CYAN, B, ''),
        'status': (C.COLOR_BLACK, C.COLOR_CYAN, ''), 'keynum': (C.COLOR_WHITE, C.COLOR_BLACK, 'bold'),
        'keylbl': (C.COLOR_BLACK, C.COLOR_CYAN, ''), 'cursor': (C.COLOR_BLACK, C.COLOR_CYAN, ''),
        'cursor2': (C.COLOR_WHITE, C.COLOR_BLACK, ''), 'mod': (C.COLOR_YELLOW, B, 'bold'),
        'block': (B, C.COLOR_WHITE, ''), 'found': (C.COLOR_BLACK, C.COLOR_YELLOW, ''),
        'jump': (C.COLOR_WHITE, B, 'bold'), 'call': (C.COLOR_YELLOW, B, 'bold'), 'ret': (C.COLOR_MAGENTA, B, 'bold'),
        'comment': (C.COLOR_GREEN, B, 'bold'), 'name': (C.COLOR_YELLOW, B, 'bold'), 'bad': (C.COLOR_MAGENTA, B, 'bold'),
        'dlg': (C.COLOR_BLACK, C.COLOR_CYAN, ''), 'dlgframe': (B, C.COLOR_CYAN, ''),
        'dlgtitle': (C.COLOR_BLACK, C.COLOR_CYAN, 'bold'), 'dlgsel': (C.COLOR_WHITE, C.COLOR_BLACK, 'bold'),
        'dlghdr': (B, C.COLOR_CYAN, ''), 'input': (C.COLOR_WHITE, B, 'bold'),
        'msg': (C.COLOR_YELLOW, B, 'bold'), 'err': (C.COLOR_WHITE, C.COLOR_RED, 'bold'),
    }


def _settings_path():
    if sys.platform.startswith('win'):
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
    else:
        base = os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')
    return os.path.join(base, 'hiew', 'settings.json')


def load_settings():
    try:
        with open(_settings_path(), encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_setting(key, value):
    d = load_settings()
    d[key] = value
    try:
        os.makedirs(os.path.dirname(_settings_path()), exist_ok=True)
        with open(_settings_path(), 'w', encoding='utf-8') as f:
            json.dump(d, f, indent=1)
    except OSError:
        pass
