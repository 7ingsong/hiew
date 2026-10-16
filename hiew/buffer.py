"""File access layer: memory-mapped read-only view plus an in-memory patch set.

Edits never touch the disk until save() is called (F9 in Hiew), so Esc in
edit mode simply drops the patches.
"""
import bisect
import mmap
import os


class FileBuffer:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.patches = {}   # offset -> new byte value
        self._keys = []     # sorted patch offsets (rebuilt lazily)
        self._dirty = False
        self.history = []   # undo groups: [[(offset, previous patch or None), ...], ...]
        self._f = None
        self._mm = None
        self._open()

    def _open(self):
        self._f = open(self.path, 'rb')
        self.size = os.fstat(self._f.fileno()).st_size
        self._mm = None
        if self.size:
            try:
                self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
            except (OSError, ValueError):
                self._mm = None
        self.readonly = not os.access(self.path, os.W_OK)

    def close(self):
        if self._mm is not None:
            self._mm.close()
            self._mm = None
        if self._f is not None:
            self._f.close()
            self._f = None

    def _raw(self, off, n):
        if self._mm is not None:
            return self._mm[off:off + n]
        self._f.seek(off)
        return self._f.read(n)

    def read(self, off, n):
        if off < 0:
            n += off
            off = 0
        end = min(self.size, off + n)
        if n <= 0 or off >= end:
            return b''
        data = self._raw(off, end - off)
        if self.patches:
            if self._dirty:
                self._keys = sorted(self.patches)
                self._dirty = False
            keys = self._keys
            i = bisect.bisect_left(keys, off)
            j = bisect.bisect_left(keys, end, i)
            if i < j:
                ba = bytearray(data)
                p = self.patches
                for o in keys[i:j]:
                    ba[o - off] = p[o]
                data = bytes(ba)
        return data

    def byte(self, off):
        d = self.read(off, 1)
        return d[0] if d else 0

    def is_mod(self, off):
        return off in self.patches

    @property
    def modified(self):
        return bool(self.patches)

    def _set(self, off, value, group):
        self._dirty = True
        group.append((off, self.patches.get(off)))
        if self._raw(off, 1)[0] == value:
            self.patches.pop(off, None)
        else:
            self.patches[off] = value

    def write(self, off, value, merge=False):
        """merge=True folds the change into the previous undo step for the same byte (second nibble)."""
        if 0 <= off < self.size:
            if merge and self.history and len(self.history[-1]) == 1 and self.history[-1][0][0] == off:
                self._set(off, value & 0xFF, [])
                return
            group = []
            self._set(off, value & 0xFF, group)
            self.history.append(group)

    def write_bytes(self, off, data):
        group = []
        for i, b in enumerate(data):
            if 0 <= off + i < self.size:
                self._set(off + i, b, group)
        if group:
            self.history.append(group)

    def write_many(self, offsets, data):
        """Write data at every offset as one undo step (replace all)."""
        group = []
        for off in offsets:
            for i, b in enumerate(data):
                if off + i < self.size:
                    self._set(off + i, b, group)
        if group:
            self.history.append(group)

    def undo(self):
        """Revert the last edit group; returns its first offset or None."""
        if not self.history:
            return None
        self._dirty = True
        group = self.history.pop()
        for off, prev in reversed(group):
            if prev is None:
                self.patches.pop(off, None)
            else:
                self.patches[off] = prev
        return group[0][0]

    def discard(self):
        self._dirty = True
        self.patches.clear()
        self.history.clear()

    def save(self):
        """Write patches to disk. Returns the number of bytes written."""
        if not self.patches:
            return 0
        items = sorted(self.patches.items())
        self.close()
        try:
            with open(self.path, 'r+b') as f:
                start = prev = None
                run = bytearray()
                for off, v in items + [(None, None)]:
                    if off is not None and prev is not None and off == prev + 1:
                        run.append(v)
                    else:
                        if run:
                            f.seek(start)
                            f.write(run)
                        if off is None:
                            break
                        start = off
                        run = bytearray([v])
                    prev = off
        finally:
            self._open()
        self.patches.clear()
        self._dirty = True
        self.history.clear()
        return len(items)

    def insert(self, off, data):
        """Insert bytes at off on disk (the tail moves right)."""
        self.close()
        try:
            with open(self.path, 'r+b') as f:
                f.seek(0, 2)
                pos = f.tell()
                n = len(data)
                CH = 1 << 20
                while pos > off:
                    c = min(CH, pos - off)
                    f.seek(pos - c)
                    d = f.read(c)
                    f.seek(pos - c + n)
                    f.write(d)
                    pos -= c
                f.seek(off)
                f.write(data)
        finally:
            self._open()
        self.discard()

    def truncate(self, size):
        self.close()
        try:
            with open(self.path, 'r+b') as f:
                f.truncate(size)
        finally:
            self._open()
        self.discard()

    def delete(self, a, b):
        """Remove bytes [a, b) from the file on disk (shifts the tail left in place)."""
        self.close()
        try:
            with open(self.path, 'r+b') as f:
                src, dst = b, a
                while True:
                    f.seek(src)
                    d = f.read(1 << 20)
                    if not d:
                        break
                    f.seek(dst)
                    f.write(d)
                    src += len(d)
                    dst += len(d)
                f.truncate(dst)
        finally:
            self._open()
        self.discard()

    def find(self, rx, plen, start, backward=False, chunk=1 << 22):
        """Regex search over the (patched) file in chunks. Returns offset or None."""
        ov = max(plen - 1, 0)
        if not backward:
            pos = max(0, start)
            while pos < self.size:
                m = rx.search(self.read(pos, chunk + ov))
                if m:
                    return pos + m.start()
                pos += chunk
            return None
        end = min(start, self.size)
        while end > 0:
            lo = max(0, end - chunk)
            last = None
            for m in rx.finditer(self.read(lo, end - lo + ov)):
                if lo + m.start() >= end:
                    break
                last = m.start()
            if last is not None:
                return lo + last
            end = lo
        return None
