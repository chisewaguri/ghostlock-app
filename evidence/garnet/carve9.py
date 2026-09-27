import io, struct, urllib.request, zipfile, collections, lzma, hashlib

URL = "https://cdnorg.d.miui.com/OS1.0.5.0.UNRIDXM/miui_GARNETIDGlobal_OS1.0.5.0.UNRIDXM_b8e2b1e78a_14.0.zip"
class HttpFile(io.RawIOBase):
    def __init__(self, url):
        self.url = url; self.pos = 0
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req) as r: self.len = int(r.headers["Content-Length"])
    def read(self, n=-1):
        if n == -1: n = self.len - self.pos
        if n <= 0: return b""
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={self.pos}-{min(self.pos+n, self.len)-1}"})
        with urllib.request.urlopen(req) as r: data = r.read()
        self.pos += len(data); return data
    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else (self.pos + off if whence == 1 else self.len + off); return self.pos
    def tell(self): return self.pos
    def seekable(self): return True
    def readable(self): return True

def fields(buf):
    i = 0
    while i < len(buf):
        tag = 0; shift = 0
        while True:
            b = buf[i]; i += 1; tag |= (b & 0x7f) << shift; shift += 7
            if not (b & 0x80): break
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v = 0; shift = 0
            while True:
                b = buf[i]; i += 1; v |= (b & 0x7f) << shift; shift += 7
                if not (b & 0x80): break
            yield fn, wt, v
        elif wt == 2:
            l = 0; shift = 0
            while True:
                b = buf[i]; i += 1; l |= (b & 0x7f) << shift; shift += 7
                if not (b & 0x80): break
            yield fn, wt, buf[i:i+l]; i += l
        elif wt == 5:
            yield fn, wt, buf[i:i+4]; i += 4
        else:
            raise ValueError(f"wt {wt}")

f = HttpFile(URL)
z = zipfile.ZipFile(f)
info = z.getinfo("payload.bin")
f.seek(info.header_offset)
lh = f.read(30)
name_len, extra_len = struct.unpack("<HH", lh[26:30])
data_off = info.header_offset + 30 + name_len + extra_len
f.seek(data_off)
ph = f.read(24)
version, manifest_size, mss = struct.unpack(">QQI", ph[4:24])
manifest = f.read(manifest_size)
blob0 = data_off + 24 + manifest_size + mss

partitions = {}
for fn, wt, val in fields(manifest):
    if fn != 13 or wt != 2: continue
    d = collections.defaultdict(list)
    for f2, w2, v2 in fields(val):
        d[f2].append(v2)
    partitions[d[1][0].decode()] = d

for pname, outname in (("boot", "evidence/garnet/boot-manual.img"),
                       ("xbl_config", "evidence/garnet/xbl_config-manual.img")):
    d = partitions[pname]
    ops = d[8]
    out = bytearray()
    sha_ok = 0
    for i, op in enumerate(ops):
        od = collections.defaultdict(list)
        for f2, w2, v2 in fields(op):
            od[f2].append(v2)
        t = od[1][0]
        doff = od[2][0]     # data_offset
        dlen = od[3][0]     # data_length
        # dst extents may span more than one submsg; sum them
        dst = None
        nbytes = 0
        for ext in od[6]:
            esub = {}
            for sf, sw, sv in fields(ext):
                esub[sf] = sv
            start, blocks = esub[1], esub[2]
            if dst is None:
                dst = start * 4096
            nbytes += blocks * 4096
        f.seek(blob0 + doff)
        data = f.read(dlen)
        if hashlib.sha256(data).digest() == od[8][0]:
            sha_ok += 1
        if t == 8:
            dec = lzma.decompress(data)
        elif t == 0:
            dec = data
        elif t == 6:
            dec = b"\x00" * nbytes
        elif t == 1:
            import bz2
            dec = bz2.decompress(data)
        elif t == 4:  # SOURCE_COPY: no blob
            continue
        else:
            raise SystemExit(f"{pname} op{i} unhandled type {t} at op {i}")
        assert len(dec) == nbytes, (i, len(dec), nbytes)
        if len(out) < dst + len(dec):
            out.extend(b"\x00" * (dst + len(dec) - len(out)))
        out[dst:dst+len(dec)] = dec
    open(outname, "wb").write(out)
    print(f"{pname}: {len(out)} bytes, sha verified {sha_ok}/{len(ops)} -> {outname}")
