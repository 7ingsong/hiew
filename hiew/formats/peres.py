"""Windows PE resources (.rsrc).

parse_resources() walks the resource directory tree (type / name / language) and returns one dict per
resource: type, name, lang, rva, off (file offset), size, codepage, a short text preview and, where it
helps, decoded lines:

    RT_VERSION   fixed file/product version and the StringFileInfo strings (CompanyName, ...)
    RT_MANIFEST  the XML text
    RT_STRING    the strings of the table block with their ids
    RT_GROUP_*   the icons / cursors of the group

export() turns a resource into a file someone can open: a group icon or cursor becomes a .ico / .cur
with all its images, a single RT_ICON / RT_CURSOR a one-image .ico / .cur, RT_BITMAP a .bmp, the
manifest a .xml, version info a .txt; anything else is written as raw bytes.
"""
import struct

RT_NAMES = {1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON', 4: 'RT_MENU', 5: 'RT_DIALOG', 6: 'RT_STRING',
            7: 'RT_FONTDIR', 8: 'RT_FONT', 9: 'RT_ACCELERATOR', 10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE',
            12: 'RT_GROUP_CURSOR', 14: 'RT_GROUP_ICON', 16: 'RT_VERSION', 17: 'RT_DLGINCLUDE', 19: 'RT_PLUGPLAY',
            20: 'RT_VXD', 21: 'RT_ANICURSOR', 22: 'RT_ANIICON', 23: 'RT_HTML', 24: 'RT_MANIFEST'}
RT_CURSOR, RT_BITMAP, RT_ICON, RT_STRING, RT_GROUP_CURSOR, RT_GROUP_ICON, RT_VERSION, RT_MANIFEST, RT_HTML = \
    1, 2, 3, 6, 12, 14, 16, 24, 23
MAX_ENTRIES = 20000
MAX_DECODE = 1 << 20          # don't decode huge resources for previews


def type_label(t):
    return RT_NAMES.get(t, str(t)) if isinstance(t, int) else str(t)


def parse_resources(read, rsrc_off, rva2off):
    """read(off, n) -> bytes; rsrc_off = file offset of the resource directory; rva2off(rva) -> offset."""
    out = []
    seen = set()

    def u16(o):
        d = read(o, 2)
        return struct.unpack('<H', d)[0] if len(d) == 2 else 0

    def name_of(v):
        if v & 0x80000000:                     # named entry: offset of a counted UTF-16 string
            o = rsrc_off + (v & 0x7FFFFFFF)
            return read(o + 2, 2 * u16(o)).decode('utf-16-le', 'replace')
        return v & 0xFFFF

    def walk(dir_off, path):
        if len(path) > 3 or dir_off in seen or len(out) >= MAX_ENTRIES:
            return
        seen.add(dir_off)
        hdr = read(dir_off, 16)
        if len(hdr) < 16:
            return
        named, ids = struct.unpack_from('<HH', hdr, 12)
        ents = read(dir_off + 16, 8 * min(named + ids, 4096))
        for i in range(len(ents) // 8):
            name, ptr = struct.unpack_from('<II', ents, 8 * i)
            key = name_of(name)
            if ptr & 0x80000000:
                walk(rsrc_off + (ptr & 0x7FFFFFFF), path + [key])
                continue
            de = read(rsrc_off + ptr, 16)
            if len(de) < 16:
                continue
            rva, size, cp, _ = struct.unpack('<IIII', de)
            keys = (path + [key] + [None, None, None])[:3]
            if len(path) < 2:                   # shallow tree: the last key is the name, no language
                keys = (path + [key, None, None])[:3]
            out.append({'type': keys[0], 'name': keys[1], 'lang': keys[2], 'rva': rva, 'off': rva2off(rva),
                        'size': size, 'codepage': cp})

    walk(rsrc_off, [])
    for r in out:
        r['label'] = type_label(r['type'])
        data = read(r['off'], min(r['size'], MAX_DECODE)) if r['off'] is not None else b''
        try:
            r['lines'] = describe(r, data, out, read)
        except Exception:                      # odd resource data: just no preview
            r['lines'] = []
    return out


# ---------------------------------------------------------------- previews

def describe(r, data, all_res, read):
    t = r['type']
    if t == RT_VERSION:
        return version_lines(data)
    if t in (RT_MANIFEST, RT_HTML):
        return [l.rstrip() for l in data.decode('utf-8', 'replace').splitlines() if l.strip()][:200]
    if t == RT_STRING and isinstance(r['name'], int):
        return ['%-6d "%s"' % (i, s.replace('\r', '\\r').replace('\n', '\\n')) for i, s in string_table(data, r['name'])]
    if t in (RT_GROUP_ICON, RT_GROUP_CURSOR):
        return ['%dx%d, %d bpp, image #%d (%d bytes)' % (w, h, bpp, iid, n) for w, h, bpp, n, iid in group_entries(data)]
    if t in (RT_ICON, RT_CURSOR):
        img = data[4:] if t == RT_CURSOR else data
        w, h, bpp = image_size(img)
        return ['%dx%d, %d bpp%s' % (w, h, bpp, ', PNG' if img[:4] == b'\x89PNG' else '')] if w else []
    if t == RT_BITMAP and len(data) >= 16:
        _, w, h, _, bpp = struct.unpack_from('<IiiHH', data, 0)
        return ['%dx%d, %d bpp' % (w, abs(h), bpp)]
    return []


def _block(data, p, end):
    """One VS_VERSIONINFO-style block -> (key, value, children, next position)."""
    length, vlen, vtype = struct.unpack_from('<HHH', data, p)
    stop = min(p + length, end) if length else end
    q = p + 6
    k = q
    while k + 1 < stop and data[k:k + 2] != b'\0\0':
        k += 2
    key = data[q:k].decode('utf-16-le', 'replace')
    q = k + 2
    q += (-q) % 4
    if vtype == 1:                              # text value, vlen counts characters
        raw = data[q:q + 2 * vlen]
        value = raw.decode('utf-16-le', 'replace').rstrip('\0')
        q += 2 * vlen
    else:
        value = data[q:q + vlen]
        q += vlen
    q += (-q) % 4
    children = []
    while q + 6 <= stop:
        ck, cv, cc, nq = _block(data, q, stop)
        children.append((ck, cv, cc))
        if nq <= q:
            break
        q = nq + ((-nq) % 4)
    return key, value, children, stop


def version_lines(data):
    if len(data) < 6:
        return []
    key, value, children, _ = _block(data, 0, len(data))
    lines = []
    if isinstance(value, (bytes, bytearray)) and len(value) >= 52 and \
            struct.unpack_from('<I', value, 0)[0] == 0xFEEF04BD:
        fms, fls, pms, pls = struct.unpack_from('<IIII', value, 8)
        lines.append('FileVersion (fixed)    %d.%d.%d.%d' % (fms >> 16, fms & 0xFFFF, fls >> 16, fls & 0xFFFF))
        lines.append('ProductVersion (fixed) %d.%d.%d.%d' % (pms >> 16, pms & 0xFFFF, pls >> 16, pls & 0xFFFF))
    for ck, cv, cc in children:
        if ck == 'StringFileInfo':
            for tk, _, strings in cc:             # one table per language/codepage, e.g. 040904B0
                for sk, sv, _ in strings:
                    lines.append('%-22s %s' % (sk, sv if isinstance(sv, str) else ''))
        elif ck == 'VarFileInfo':
            for vk, vv, _ in cc:
                if vk == 'Translation' and isinstance(vv, (bytes, bytearray)):
                    pairs = struct.unpack('<%dH' % (len(vv) // 2), vv[:len(vv) // 2 * 2])
                    lines.append('Translation            %s' % ' '.join(
                        '%04X/%04X' % (pairs[i], pairs[i + 1]) for i in range(0, len(pairs) - 1, 2)))
    return lines


def string_table(data, block_id):
    """RT_STRING block N holds strings (N-1)*16 .. (N-1)*16+15, each a counted UTF-16 string."""
    out = []
    p = 0
    for i in range(16):
        if p + 2 > len(data):
            break
        n = struct.unpack_from('<H', data, p)[0]
        p += 2
        if n:
            out.append(((block_id - 1) * 16 + i, data[p:p + 2 * n].decode('utf-16-le', 'replace')))
        p += 2 * n
    return out


def group_entries(data):
    """GRPICONDIR -> [(width, height, bpp, bytes, image id)]"""
    if len(data) < 6:
        return []
    _, kind, count = struct.unpack_from('<HHH', data, 0)
    out = []
    for i in range(min(count, 256)):
        o = 6 + 14 * i
        if o + 14 > len(data):
            break
        w, h, colors, _, planes, bpp, size, iid = struct.unpack_from('<BBBBHHIH', data, o)
        if kind == 2:                           # cursor groups store width, height*2 as words
            w, h = struct.unpack_from('<HH', data, o)
            h //= 2
            bpp = struct.unpack_from('<H', data, o + 6)[0]
        out.append((w or 256, h or 256, bpp, size, iid))
    return out


def image_size(img):
    """(width, height, bpp) of an icon image: a PNG or a DIB with a doubled height."""
    if img[:8] == b'\x89PNG\r\n\x1a\n' and len(img) >= 26:
        w, h = struct.unpack('>II', img[16:24])
        return w, h, img[24] * (4 if img[25] == 6 else 3 if img[25] == 2 else 1)
    if len(img) >= 16:
        hs, w, h, _, bpp = struct.unpack_from('<IiiHH', img, 0)
        if hs in (12, 40, 108, 124):
            return w, abs(h) // 2, bpp
    return 0, 0, 0


# ---------------------------------------------------------------- export to standalone files

def _find(all_res, rtype, rid, lang):
    best = None
    for r in all_res:
        if r['type'] == rtype and r['name'] == rid:
            if r['lang'] == lang:
                return r
            best = best or r
    return best


def _ico(entries, cursor=False):
    """entries: [(width, height, bpp, image bytes, hotspot)] -> .ico / .cur file bytes"""
    head = struct.pack('<HHH', 0, 2 if cursor else 1, len(entries))
    dirs = b''
    imgs = b''
    off = 6 + 16 * len(entries)
    for w, h, bpp, img, hot in entries:
        a, b = hot if cursor else (1, bpp)
        dirs += struct.pack('<BBBBHHII', w if w < 256 else 0, h if h < 256 else 0, 0, 0, a, b, len(img), off + len(imgs))
        imgs += img
    return head + dirs + imgs


def export(r, all_res, read):
    """(file extension, bytes) for saving resource r as a file; damaged data is saved raw."""
    if r['off'] is None:
        return None, None
    data = read(r['off'], r['size'])
    try:
        return _export(r, all_res, read, data)
    except Exception:
        return '.bin', data


def _export(r, all_res, read, data):
    t = r['type']
    if t in (RT_GROUP_ICON, RT_GROUP_CURSOR):
        cur = t == RT_GROUP_CURSOR
        parts = []
        for w, h, bpp, _, iid in group_entries(data):
            img_res = _find(all_res, RT_CURSOR if cur else RT_ICON, iid, r['lang'])
            if img_res is None or img_res['off'] is None:
                continue
            img = read(img_res['off'], img_res['size'])
            hot = (0, 0)
            if cur:                                 # RT_CURSOR starts with the hotspot
                hot = struct.unpack_from('<HH', img, 0)
                img = img[4:]
            parts.append((w, h, bpp, img, hot))
        if parts:
            return ('.cur' if cur else '.ico'), _ico(parts, cur)
    if t in (RT_ICON, RT_CURSOR):
        cur = t == RT_CURSOR
        hot = struct.unpack_from('<HH', data, 0) if cur else (0, 0)
        img = data[4:] if cur else data
        w, h, bpp = image_size(img)
        if w:
            return ('.cur' if cur else '.ico'), _ico([(w, h, bpp, img, hot)], cur)
    if t == RT_BITMAP and len(data) >= 40:
        hs, _, _, _, bpp, comp = struct.unpack_from('<IiiHHI', data, 0)
        used = struct.unpack_from('<I', data, 32)[0] if hs >= 36 else 0
        colors = used or (1 << bpp if bpp <= 8 else 0)
        masks = 12 if comp == 3 and hs == 40 else 0
        bits = 14 + hs + masks + 4 * colors
        return '.bmp', b'BM' + struct.pack('<IHHI', 14 + len(data), 0, 0, bits) + data
    if t in (RT_MANIFEST,):
        return '.xml', data
    if t == RT_HTML:
        return '.html', data
    if t == RT_VERSION:
        return '.txt', ('\n'.join(version_lines(data)) + '\n').encode('utf-8')
    if t == RT_STRING and isinstance(r['name'], int):
        return '.txt', ''.join('%d\t%s\n' % (i, s) for i, s in string_table(data, r['name'])).encode('utf-8')
    return '.bin', data
