import argparse
import glob
import locale
import os
import sys


def main(argv=None):
    p = argparse.ArgumentParser(prog='hiew', description="Hiew - cross-platform Hacker's View: hex viewer, editor and disassembler")
    from . import __version__
    p.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
    p.add_argument('files', nargs='*', help='file(s) to open; Ctrl+F11 / Ctrl+F12 switch between them')
    p.add_argument('--keys', action='store_true', help='key test: show how key presses are recognised')
    p.add_argument('-m', '--mode', choices=('text', 'hex', 'decode'), help='start mode')
    p.add_argument('-o', '--offset', help='start position: hex offset, .VA or symbol name')
    p.add_argument('-e', '--entry', action='store_true', help='start at the entry point in decode mode')
    p.add_argument('-a', '--arch', help='disassembler architecture (x86-16/32/64, arm, thumb, arm64, mips32, ...)')
    p.add_argument('-s', '--slice', help='universal (fat) Mach-O: slice to open, by cpu name (x86_64, arm64) or number')
    p.add_argument('--no-mouse', dest='mouse', action='store_false', help='do not capture the mouse')
    p.add_argument('-t', '--theme', choices=('hiew', 'blue', 'dark', 'light'),
                   help='colour theme (default: the last one chosen in F4, else hiew); F4 switches it live')
    p.add_argument('--colors', choices=('auto', 'classic', '8'), default='auto',
                   help='auto: 256-colour palette; classic: DOS blue; 8: 8-colour variant of the theme')
    p.add_argument('--no-modpoll', dest='modpoll', action='store_false',
                   help='do not read Alt/Ctrl/Shift state from the OS (live keybar)')
    p.add_argument('--no-kitty', dest='kitty', action='store_false',
                   help='do not enable the kitty keyboard protocol (live Alt/Ctrl keybar over ssh)')
    opts = p.parse_args(argv)

    files = []
    for f in opts.files:
        files += sorted(glob.glob(f)) if any(c in f for c in '*?[') else [f]
    opts.files = files
    if not opts.keys and not files:
        p.error('a file is required')
    for f in files if not opts.keys else []:
        if not os.path.isfile(f):
            p.error('not a file: %s' % f)
    opts.file = files[0] if files else None
    from .disasm import ARCHS
    if opts.arch and opts.arch not in ARCHS:
        p.error('unknown arch %s, choose from: %s' % (opts.arch, ', '.join(ARCHS)))

    if not opts.modpoll:
        os.environ['HIEW_NO_MODPOLL'] = '1'
    try:   # Backspace sends DEL -> a ^H can only be Ctrl+Backspace
        import termios
        from . import keys as K
        K.CTRL_H_IS_CBS = termios.tcgetattr(sys.stdin.fileno())[6][termios.VERASE] in (b'\x7f', 127)
    except Exception:
        pass
    locale.setlocale(locale.LC_ALL, '')
    os.environ.setdefault('ESCDELAY', '25')
    try:
        import curses
    except ImportError:
        sys.exit('curses is missing. On Windows run: pip install windows-curses')
    from .spec import Hiew

    def run(scr):
        try:
            curses.set_escdelay(25)  # novermin (Python 3.9+, guarded)
        except Exception:
            pass
        try:
            curses.raw()
            curses.nonl()   # keep Enter (\r) and Ctrl+Enter / Ctrl+J (\n) apart
        except curses.error:
            pass
        if opts.keys:
            from .mods import keytest
            keytest(scr, opts)
        else:
            Hiew(scr, opts.file, opts).run()

    try:
        curses.wrapper(run)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
