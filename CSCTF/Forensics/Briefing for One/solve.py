#!/usr/bin/env python3
"""
Briefing for One (CSCTF 2026 - Forensics).

Recover the operator card's briefing token by reconstructing, as DATA only, the
.lnk -> PowerShell -> WebDAV -> 7z chain. Nothing is executed and no captured
address is contacted.

The .lnk (analysed separately, see writeup) runs a hidden PowerShell that:
  * reads MachineGuid from HKLM\\SOFTWARE\\Microsoft\\Cryptography
  * derives the 7z password = HMAC-SHA256(key = base64("eyy//ntonkO5y+zE61CW4ddRSUWiWBgzwe3ra1tENd8="),
                                          "csctf26/briefing-for-one/v1" || 0x00 || lower(guid))  (hex)
  * downloads ops/route-update.7z over WebDAV, 7z-extracts route-table.json
  * the JSON carries "briefing_token": "CSCTF{...}"

This script does the forensic equivalent offline:
  1. parse MachineGuid out of the saved Cryptography registry subkey (machine-cryptography.hiv)
  2. derive the password
  3. reassemble the GET /ops/route-update.7z response body from egress.pcapng (chunked/plain HTTP)
  4. decrypt it with py7zr and read route-table.json

Requires: py7zr  (pip install py7zr).  Stdlib otherwise.
"""
import sys, struct, hmac, hashlib, base64, collections, io, json

HIVE = sys.argv[1] if len(sys.argv) > 1 else "machine-cryptography.hiv"
PCAP = sys.argv[2] if len(sys.argv) > 2 else "egress.pcapng"
KEY = base64.b64decode("eyy//ntonkO5y+zE61CW4ddRSUWiWBgzwe3ra1tENd8=")
INFO = b"csctf26/briefing-for-one/v1"


# ---- 1. MachineGuid from the saved regf subkey ----------------------------
def machine_guid(path):
    d = open(path, "rb").read()
    assert d[:4] == b"regf"
    cell = lambda off: d[0x1000 + off + 4:]          # skip the int32 cell size
    def walk(off):
        c = cell(off); assert c[:2] == b"nk"
        nval, = struct.unpack("<I", c[0x24:0x28]); vlist, = struct.unpack("<I", c[0x28:0x2C])
        nsub, = struct.unpack("<I", c[0x14:0x18]); sub, = struct.unpack("<I", c[0x1C:0x20])
        for i in range(nval):
            vo, = struct.unpack("<I", cell(vlist)[4*i:4*i+4])
            v = cell(vo); assert v[:2] == b"vk"
            vnl, size, doff, typ, vfl = struct.unpack("<HIIIH", v[2:18])
            name = v[0x14:0x14+vnl]
            name = name.decode("latin1") if vfl & 1 else name.decode("utf-16le")
            data = struct.pack("<I", doff)[:size & 0x7fffffff] if size & 0x80000000 else cell(doff)[:size]
            if name == "MachineGuid":
                return data.decode("utf-16le").rstrip("\x00")
        if nsub:                                      # recurse into subkeys
            sc = cell(sub); sig, n = sc[:2], struct.unpack("<H", sc[2:4])[0]
            step = 8 if sig in (b"lf", b"lh") else 4
            for i in range(n):
                g = walk(struct.unpack("<I", sc[4+step*i:8+step*i])[0])
                if g:
                    return g
    return walk(struct.unpack("<I", d[0x24:0x28])[0])


# ---- 2. password derivation ----------------------------------------------
def prov_password(guid):
    return hmac.new(KEY, INFO + b"\x00" + guid.lower().encode(), hashlib.sha256).hexdigest()


# ---- 3. pull the route-update.7z body out of the HTTP capture -------------
def http_object(path):
    d = open(path, "rb").read(); i = 0; end = "<"; ifs = []; pkts = []
    while i < len(d):                                 # minimal pcapng reader
        bt = struct.unpack(end + "I", d[i:i+4])[0]
        if bt == 0x0A0D0D0A:
            end = "<" if d[i+8:i+12] == b"\x4d\x3c\x2b\x1a" else ">"
        bl = struct.unpack(end + "I", d[i+4:i+8])[0]; body = d[i+8:i+bl-4]
        if bt == 1:
            ifs.append(struct.unpack(end + "H", body[:2])[0])
        elif bt == 6:
            iid, _a, _b, cap, _o = struct.unpack(end + "IIIII", body[:20]); pkts.append((ifs[iid], body[20:20+cap]))
        i += bl
    streams = collections.defaultdict(dict)           # client-port -> {seq: data} for server->client
    for link, fr in pkts:
        p = fr[14:] if link == 1 else fr
        if (p[0] >> 4) != 4 or p[9] != 6:
            continue
        ihl = (p[0] & 0xF) * 4; tot = struct.unpack(">H", p[2:4])[0]; seg = p[ihl:tot]
        sp, dp, seq, _ack, o2 = struct.unpack(">HHIIH", seg[:14]); hl = (o2 >> 12) * 4
        data = bytes(seg[hl:])
        if data and sp == 80:
            streams[dp].setdefault(seq, data)
    for cp, segd in streams.items():
        buf = b""; nxt = min(segd)
        for s in sorted(segd):
            buf += segd[s][max(0, nxt-s):]; nxt = max(nxt, s + len(segd[s]))
        while buf:
            head, sep, rest = buf.partition(b"\r\n\r\n")
            if not sep:
                break
            hd = {}
            for ln in head.decode("latin1").split("\r\n")[1:]:
                if ":" in ln:
                    k, vv = ln.split(":", 1); hd[k.lower().strip()] = vv.strip()
            if hd.get("transfer-encoding", "").lower() == "chunked":
                body = b""
                while True:
                    ln, _, rest = rest.partition(b"\r\n"); n = int(ln.split(b";")[0], 16)
                    body += rest[:n]; rest = rest[n+2:]
                    if n == 0:
                        break
            else:
                n = int(hd.get("content-length", 0)); body, rest = rest[:n], rest[n:]
            if hd.get("content-type", "").startswith("application/octet-stream") and len(body) > 1000:
                return body
            buf = rest
    return None


def main():
    guid = machine_guid(HIVE)
    pw = prov_password(guid)
    print("MachineGuid =", guid)
    print("7z password =", pw)
    blob = http_object(PCAP)
    assert blob, "route-update.7z not found in capture"
    assert hashlib.sha256(blob).hexdigest() == \
        "d29a06795dd5e2346ea5c8a107c2c5b4b916dcabd7cf0011fe600fa3b13ae4c2", "object hash mismatch"
    import py7zr, tempfile, os
    out = tempfile.mkdtemp(prefix="bfo-")
    with py7zr.SevenZipFile(io.BytesIO(blob), password=pw) as z:
        z.extractall(out)
    data = open(os.path.join(out, "route-table.json"), encoding="utf-8").read()
    print(data)
    print(json.loads(data)["briefing_token"])


if __name__ == "__main__":
    main()
