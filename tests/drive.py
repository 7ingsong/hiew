"""Drive hiew in a pty and dump the pyte screen after each key batch.
usage: drive.py FILE 'key1|key2|...' [args...]   keys: names below or literal text
"""
import os, pty, sys, time, select, struct, fcntl, termios
import pyte
KEYS = {'A-1':'\x1b1','A-2':'\x1b2','A-0':'\x1b0','A--':'\x1b-','A-*':'\x1b*','A-m':'\x1bm','A-M':'\x1bM','A-n':'\x1bn','A-b':'\x1bb','C-.':'\x1b[46;5u','C-1':'\x1b[49;5u','C--':'\x1f','C-*':'\x1b[42;5u','INS':'\x1b[2~','C-F1':'\x1b[1;5P','S-F1':'\x1b[1;2P','C-F6':'\x1b[17;5~','C-F11':'\x1b[23;5~','C-F12':'\x1b[24;5~','C-BS':'\x08','S-F3':'\x1b[1;2R','S-F4':'\x1b[1;2S','S-F9':'\x1b[20;2~','S-F12':'\x1b[24;2~','DEL':'\x1b[3~','C-x':'\x18','F12':'\x1b[24~','F11':'\x1b[23~','C-ENTER':'\n','S-F7':'\x1b[18;2~','C-F2':'\x1b[1;5Q','S-F2':'\x1b[1;2Q','S-F5':'\x1b[15;2~','S-F6':'\x1b[17;2~','A-F2':'\x1b[1;3Q','A-F3':'\x1b[1;3R','A-F6':'\x1b[17;3~','A-F7':'\x1b[18;3~','A-F8':'\x1b[19;3~','A-=':'\x1b=','A-p':'\x1bp','F1':'\x1bOP','F2':'\x1bOQ','F3':'\x1bOR','F4':'\x1bOS','F5':'\x1b[15~','F6':'\x1b[17~','F7':'\x1b[18~',
 'F8':'\x1b[19~','F9':'\x1b[20~','F10':'\x1b[21~','F12':'\x1b[24~','C-F7':'\x1b[18;5~','S-F7':'\x1b[18;2~','A-F1':'\x1b[1;3P',
 'UP':'\x1b[A','DOWN':'\x1b[B','RIGHT':'\x1b[C','LEFT':'\x1b[D','PGDN':'\x1b[6~','PGUP':'\x1b[5~','HOME':'\x1b[H','END':'\x1b[F',
 'C-HOME':'\x1b[1;5H','C-END':'\x1b[1;5F','C-RIGHT':'\x1b[1;5C','C-LEFT':'\x1b[1;5D','ENTER':'\r','ESC':'\x1b','TAB':'\t','BS':'\x7f','SHOW':None,'S-RIGHT':'[1;2C','S-DOWN':'[1;2B','S-LEFT':'[1;2D','ESCF6':'[17~','F6':'[17~','A-F2':'\x1b[1;3Q','C-F2':'\x1b[1;5Q','S-F2':'\x1b[1;2Q','A-F3':'\x1b[1;3R','C-F3':'\x1b[1;5R','A-F4':'\x1b[1;3S','A-F6':'\x1b[17;3~','A-F7':'\x1b[18;3~','A-F8':'\x1b[19;3~','C-F8':'\x1b[19;5~','A-F10':'\x1b[21;3~','A-F11':'\x1b[23;3~','A-F12':'\x1b[24;3~','S-F5':'\x1b[15;2~','S-F6':'\x1b[17;2~','C-ENTER':'\n','A-=':'\x1b=','A-p':'\x1bp','F11':'\x1b[23~','C-z':'\x1a','SPACE':' ','ESCF2':'\x1b\x1bOQ','A-F1':'\x1b[1;3P'}
KEYS.update({**{'A-%d'%i:'\x1b%d'%i for i in range(10)},**{'C-%d'%i:'\x1b[%d;5u'%(48+i) for i in range(10)},
 'A-N':'\x1bN','A-?':'\x1b?','A-i':'\x1bi','A-a':'\x1ba','S-F10':'\x1b[21;2~','S-F11':'\x1b[23;2~','C-F4':'\x1b[1;5S','A-F5':'\x1b[15;3~',
 'C-n':'\x0e','C-p':'\x10','S-UP':'\x1b[1;2A','PLUS':'+','MINUS':'-','STAR':'*','PIPE':'|','A-F9':'\x1b[20;3~','C-F9':'\x1b[20;5~','C-F5':'\x1b[15;5~','C-F10':'\x1b[21;5~'})
W,H=int(os.environ.get('COLS','100')),int(os.environ.get('ROWS','30'))
f=sys.argv[1]; seq=sys.argv[2].split('|') if len(sys.argv)>2 and sys.argv[2] else []
pid,fd=pty.fork()
if pid==0:
    os.environ['TERM']='xterm-256color'
    os.environ['HIEW_NO_MODPOLL']='1'   # deterministic: ignore keys held in other apps
    os.environ['HOME']=os.environ.get('QAHOME',os.environ['HOME'])
    os.execv(sys.executable,[sys.executable,'-m','hiew',f]+sys.argv[3:])
fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',H,W,0,0))
RAW=[]
import re as _re
MARG=[1,int(os.environ.get('ROWS','30'))]
def fix(d):
    out=b''; pos=0
    for m in _re.finditer(rb'\x1b\[(\d*);?(\d*)([rST])',d):
        out+=d[pos:m.start()]; pos=m.end()
        a,b,c=m.group(1),m.group(2),m.group(3)
        if c==b'r':
            MARG[0]=int(a or 1); MARG[1]=int(b or H); out+=m.group(0)
        else:
            n=int(a or 1)
            if c==b'S': out+=b'\x1b7\x1b[%d;1H'%MARG[1]+b'\x1bD'*n+b'\x1b8'
            else: out+=b'\x1b7\x1b[%d;1H'%MARG[0]+b'\x1bM'*n+b'\x1b8'
    return out+d[pos:]
scr=pyte.Screen(W,H); st=pyte.ByteStream(scr)
def pump(t=0.6):
    end=time.time()+t
    while time.time()<end:
        r,_,_=select.select([fd],[],[],0.05)
        if r:
            try: d=os.read(fd,65536)
            except OSError: return False
            if not d: return False
            RAW.append(d); st.feed(fix(d)); end=max(end,time.time()+0.15)
    return True
def show(tag):
    print('==== %s (cursor %d,%d)'%(tag,scr.cursor.y,scr.cursor.x))
    for l in scr.display: print(l.rstrip())
def showattr():
    from collections import Counter
    print('==== attr')
    for y in range(H):
        row=scr.buffer[y]; c=Counter((row[x].bg,row[x].reverse) for x in range(W)); dom=c.most_common(1)[0][0]
        out='';inb=False
        for x in range(W):
            ch=row[x]; o=(ch.bg,ch.reverse)!=dom
            if o and not inb: out+='['; inb=True
            if not o and inb: out+=']'; inb=False
            out+=ch.data
        if inb: out+=']'
        print(out.rstrip())
pump(float(os.environ.get('START','2.5')))
for k in seq:
    if k=='SHOW': show('state'); continue
    if k=='CELLS':
        for y,x in ((0,1),(2,0),(2,14),(H-1,1),(H-1,3)):
            c=scr.buffer[y][x]; print('cell',y,x,repr(c.data),'fg',c.fg,'bg',c.bg,'bold',c.bold)
        continue
    if k.startswith('WAIT'): pump(float(k[4:] or 2)); continue
    if k=='RAWMARK': open('raw.bin','wb').write(b''.join(RAW)); RAW.clear(); continue
    if k=='ATTR': showattr(); continue
    if k.startswith('BG') and k[2:].isdigit():
        y=int(k[2:]); row=scr.buffer[y]; prev=None; out=[]
        for x in range(W):
            c=(row[x].fg,row[x].bg,row[x].reverse)
            if c!=prev: out.append('%d:%s/%s%s'%(x,c[0],c[1],'R' if c[2] else '')); prev=c
        print('row',y,' '.join(out)); continue
    if k.startswith('SLEEP'): pump(float(k[5:])); continue
    wt=None
    if '@' in k and k.rsplit('@',1)[0] in KEYS:
        try: k,wt=k.rsplit('@',1); wt=float(wt)
        except ValueError: wt=None
    try: os.write(fd,(KEYS[k] if k in KEYS else k).encode())
    except OSError: show('DIED at '+k); sys.exit()
    pump(wt if wt is not None else float(os.environ.get('KW','0.6')))
show('final'); open('raw2.bin','wb').write(b''.join(RAW))
import signal
for _ in range(3):
    try: os.write(fd,b'[21~')
    except OSError: break
    if not pump(0.4): break
try: os.kill(pid, signal.SIGKILL)
except OSError: pass
os.waitpid(pid,0)
