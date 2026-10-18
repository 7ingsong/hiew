""".NET (CLR) assemblies inside PE files, read with dnfile (a pefile extension).

Adds to the BinInfo of a PE file:
  * header lines: runtime version, CLR flags, assembly name and version, managed entry point,
    referenced assemblies, metadata table counts;
  * the manifest resources in info.dotnet_resources (name, file offset, size, data, and the entries of
    System.Resources sets with their offsets); the UI shows them in a window opened from F8 with F4;
  * method names (Namespace.Type::Method) for every method body, shown in F12 and as comments.

dnfile is optional at runtime: without it a .NET file is still a normal PE.
"""
import logging

try:
    import dnfile
    HAVE_DNFILE = True
except Exception:   # not installed or broken
    dnfile = None
    HAVE_DNFILE = False

# dnfile/pefile log parse problems; with no handler they would be printed over the curses screen.
# They are shown as header lines instead (get_warnings()).
for _name in ('dnfile', 'pefile'):
    _log = logging.getLogger(_name)
    _log.addHandler(logging.NullHandler())
    _log.propagate = False

MAX_METHOD_NAMES = 300000
CLR_FLAGS = ('CLR_ILONLY', 'CLR_32BITREQUIRED', 'CLR_IL_LIBRARY', 'CLR_STRONGNAMESIGNED', 'CLR_NATIVE_ENTRYPOINT',
             'CLR_TRACKDEBUGDATA', 'CLR_PREFER_32BIT')


def _s(x):
    return '' if x is None else str(x)


def _version(row):
    return '%d.%d.%d.%d' % (row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber)


def _type_names(tables):
    """method row index -> 'Namespace.Type' of the TypeDef that owns it"""
    owner = {}
    for td in tables.TypeDef or []:
        ns, name = _s(td.TypeNamespace), _s(td.TypeName)
        full = '%s.%s' % (ns, name) if ns else name
        for idx in td.MethodList or []:
            owner[idx.row_index] = full
    return owner


SYNC_LIMIT = 2 << 20      # bigger assemblies are read in a background thread (dnfile needs seconds)


class _Result:
    def __init__(self):
        self.header = []
        self.symbols = {}
        self.resources = []
        self.is_net = False


def _collect(path, base, va2off):
    R = _Result()
    try:
        _fill(R, path, base, va2off)
    except Exception as e:      # damaged metadata: the PE view stays as it is
        R.header.append(('.NET metadata could not be read: %s' % e, None))
    return R


def _merge(info, R, at):
    """Put R into info, replacing header line at (the placeholder) with R's lines."""
    info.header[at:at + 1] = R.header
    for va, name in R.symbols.items():
        info.symbols.setdefault(va, name)
    info.dotnet_resources = R.resources
    if R.is_net:
        info.desc += ' .NET'
        info.dotnet = True


class DotnetJob:
    """Background reading of a large assembly. The UI calls merge() (cheap, non-blocking) now and then,
    or wait() when it needs the data (F8, F4, F12)."""

    def __init__(self, info, path, at):
        import threading
        self.info, self.at = info, at
        self.result = None
        self.merged = False
        self.thread = threading.Thread(target=self._run, args=(path, info.base, info.va2off), daemon=True)
        self.thread.start()

    def _run(self, path, base, va2off):
        self.result = _collect(path, base, va2off)

    @property
    def done(self):
        return self.result is not None

    def merge(self):
        if self.merged or self.result is None:
            return False
        _merge(self.info, self.result, self.at)
        self.merged = True
        return True

    def wait(self):
        self.thread.join()
        return self.merge()


def add_dotnet(info, buf):
    """Called by pe.py for a PE file with a CLR (COM descriptor) data directory.
    Any problem in the .NET part leaves the plain PE view intact."""
    H = info.header
    H.append(('', None))
    if not HAVE_DNFILE:
        H.append(('.NET assembly - install dnfile for metadata and resources (pip install dnfile)', None))
        return
    H.append(('.NET metadata: reading ...', None))      # placeholder, replaced by the real lines
    if buf.size <= SYNC_LIMIT:
        _merge(info, _collect(buf.path, info.base, info.va2off), len(H) - 1)
    else:
        info.dotnet_job = DotnetJob(info, buf.path, len(H) - 1)


def _fill(R, path, base, va2off):
    """Read the .NET metadata of path into R (never touches the BinInfo: may run in a thread)."""
    H = R.header
    pe = dnfile.dnPE(path)
    net = pe.net
    warnings = [w for w in pe.get_warnings() if 'metadata' in w.lower() or 'stream' in w.lower()][:3]
    for w in warnings:
        H.append(('.NET warning: %s' % w[:100], None))
    if net is None or net.mdtables is None:
        H.append(('.NET header present, metadata unreadable', None))
        return
    R.is_net = True
    s = net.struct
    tables = net.mdtables
    flags = [f[4:] for f in CLR_FLAGS if getattr(net.Flags, f, False)]
    runtime = ''
    try:
        runtime = net.metadata.struct.Version.rstrip(b'\0').decode('latin-1')
    except Exception:
        pass
    H.append(('.NET: runtime %s, CLR header %d.%d, flags %s' % (runtime or '?', s.MajorRuntimeVersion,
                                                              s.MinorRuntimeVersion, ' '.join(flags) or '-'), None))
    if tables.Assembly:
        a = tables.Assembly[0]
        H.append(('Assembly: %s %s' % (_s(a.Name), _version(a)), None))

    # method names for every method body
    owner = _type_names(tables)
    methods = tables.MethodDef or []
    names = {}
    for i, m in enumerate(methods[:MAX_METHOD_NAMES], 1):
        name = '%s::%s' % (owner.get(i, '?'), _s(m.Name))
        names[i] = name
        if m.Rva:
            R.symbols.setdefault(base + m.Rva, name)

    # managed entry point: a MethodDef token (table 0x06) unless the entry point is native
    tok = s.EntryPointTokenOrRva
    if tok and not getattr(net.Flags, 'CLR_NATIVE_ENTRYPOINT', False) and tok >> 24 == 0x06:
        row = tok & 0xFFFFFF
        if 0 < row <= len(methods):
            rva = methods[row - 1].Rva
            off = va2off(base + rva) if rva else None
            H.append(('Managed entry point: %s  (token %08X, IL at .%08X)' % (names.get(row, '?'), tok, base + rva),
                      (off, 'hex') if off is not None else None))
    refs = tables.AssemblyRef or []
    if refs:
        H.append(('References: %s' % ', '.join('%s %s' % (_s(r.Name), _version(r)) for r in refs), None))
    counts = [(k, len(getattr(tables, k) or [])) for k in ('TypeDef', 'MethodDef', 'Field', 'TypeRef', 'MemberRef')]
    H.append(('Metadata: ' + ', '.join('%s %d' % kv for kv in counts), None))

    # manifest resources: end up in BinInfo.dotnet_resources for the F8 -> F4 window; the header gets a summary
    for r in net.resources or []:
        data = bytes(r.data) if isinstance(r.data, (bytes, bytearray)) else None
        size = r.size or (len(data) if data is not None else 0)
        va = base + r.rva if r.rva else None
        off = va2off(va) if va is not None else None
        res = {'name': _s(r.name), 'off': off, 'va': va, 'size': size, 'public': bool(r.public),
               'data': data, 'entries': []}
        if off is not None and size:            # decode .resources sets ourselves
            try:
                parsed = parse_resource_set(data if data is not None else pe.get_data(r.rva, size))
            except Exception:
                parsed = None
            for e in parsed or []:
                res['entries'].append({'name': e['name'], 'type': e['type'], 'value': e['value'], 'data': e['data'],
                                       'off': off + e['rel'] if e['rel'] is not None else None})
        R.resources.append(res)
    if R.resources:
        n = len(R.resources)
        ne = sum(len(r['entries']) for r in R.resources)
        H.append(('.NET resources: %d%s - F4 opens the list (view, save)' % (n, ', %d entries' % ne if ne else ''),
                  None))


# ---------------------------------------------------------------- System.Resources (.resources) sets
# dnfile mis-reads strings longer than 127 bytes (2-byte 7-bit length), so the set is decoded here.

RES_MAGIC = 0xBEEFCACE
RES_TYPES = {0: 'null', 1: 'System.String', 2: 'System.Boolean', 3: 'System.Char', 4: 'System.Byte',
             5: 'System.SByte', 6: 'System.Int16', 7: 'System.UInt16', 8: 'System.Int32', 9: 'System.UInt32',
             10: 'System.Int64', 11: 'System.UInt64', 12: 'System.Single', 13: 'System.Double',
             14: 'System.Decimal', 15: 'System.DateTime', 16: 'System.TimeSpan', 32: 'System.Byte[]',
             33: 'System.IO.Stream'}
_FIXED = {2: 1, 3: 2, 4: 1, 5: 1, 6: 2, 7: 2, 8: 4, 9: 4, 10: 8, 11: 8, 12: 4, 13: 8, 14: 16, 15: 8, 16: 8}


def _7bit(b, p):
    """.NET 7-bit encoded int at p -> (value, next position)"""
    v = shift = 0
    while True:
        c = b[p]
        p += 1
        v |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80 or shift > 35:
            return v, p


def parse_resource_set(blob):
    """Entries of a System.Resources set: dicts name/type/value/data/rel (offset of the data in blob).
    Returns None if blob is not a set this parser understands."""
    import struct
    if len(blob) < 12 or struct.unpack_from('<I', blob, 0)[0] != RES_MAGIC:
        return None
    skip = struct.unpack_from('<i', blob, 8)[0]
    p = 12 + skip                                # reader / set type names
    version, count, ntypes = struct.unpack_from('<iii', blob, p)
    p += 12
    types = []
    for _ in range(ntypes):
        n, p = _7bit(blob, p)
        types.append(blob[p:p + n].decode('utf-8', 'replace'))
        p += n
    p += (-p) % 8                               # PAD to 8 bytes
    p += 4 * count                              # name hashes
    positions = struct.unpack_from('<%di' % count, blob, p)
    p += 4 * count
    data_section = struct.unpack_from('<i', blob, p)[0]
    names_start = p + 4
    out = []
    for pos in positions:
        q = names_start + pos
        n, q = _7bit(blob, q)
        name = blob[q:q + n].decode('utf-16-le', 'replace')
        q += n
        rel = data_section + struct.unpack_from('<i', blob, q)[0]
        tc, d = _7bit(blob, rel)
        e = {'name': name, 'value': None, 'data': None, 'rel': None}
        if version == 1:                        # type index into the type table
            e['type'] = types[tc] if 0 <= tc < len(types) else '?'
            if e['type'].startswith('System.String'):
                n, d = _7bit(blob, d)
                e['data'], e['rel'] = blob[d:d + n], d
                e['value'] = e['data'].decode('utf-8', 'replace')
                e['type'] = 'System.String'
        elif tc == 1:                           # string: 7-bit length + UTF-8
            n, d = _7bit(blob, d)
            e.update(type='System.String', data=blob[d:d + n], rel=d)
            e['value'] = e['data'].decode('utf-8', 'replace')
        elif tc in (32, 33):                    # byte[] / stream: int32 length + bytes
            n = struct.unpack_from('<i', blob, d)[0]
            e.update(type=RES_TYPES[tc], data=blob[d + 4:d + 4 + n], rel=d + 4)
        elif tc in _FIXED:
            n = _FIXED[tc]
            e.update(type=RES_TYPES[tc], data=blob[d:d + n], rel=d)
        else:                                   # null or a serialized user type (index tc - 64)
            e['type'] = RES_TYPES.get(tc) or (types[tc - 64] if 0 <= tc - 64 < len(types) else 'type %d' % tc)
        out.append(e)
    return out
