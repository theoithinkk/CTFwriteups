#!/usr/bin/env python3
"""
Interlock Witness (CSCTF 2026 - ICS/OT).

Reconstruct the accepted Modbus/TCP writes that violate the offline response-cell
interlock policy, then derive the incident witness:

    W = SHA-256( P || T )
    P = b"INTERLOCK-WITNESS/1\x00"          (19 ASCII bytes + a trailing NUL)
    T = for each UNSAFE accepted FC16 target write, in normal-response order:
            request PDU (function-code || data, no MBAP) || paired normal-response PDU

A "target" write is FC16, quantity 1, start address 0x0013 (trip_limit) or
0x0014 (restore_delay). It is UNSAFE when, immediately before its normal
response, any of maintenance_permit(0x0A)==1, isolation_state(0x0B)==1,
protection_armed(0x0C)==1 is false.

Pure stdlib; no tshark. Parses the pcapng, reassembles both TCP directions by
sequence number, walks the MBAP-framed PDUs and replays the policy.
"""
import struct, sys, hashlib, collections

CAP = sys.argv[1] if len(sys.argv) > 1 else "interlock.pcapng"
SERVER_PORT = 502
P = b"INTERLOCK-WITNESS/1\x00"
MAPPED = {0x0A, 0x0B, 0x0C, 0x13, 0x14}   # words the policy tracks


# ---- pcapng: yield (pkt_no, link_type, raw_frame) -------------------------
def pcapng_packets(path):
    d = open(path, "rb").read()
    i = 0
    end = "<"
    ifaces = []
    n = 0
    while i < len(d):
        bt = struct.unpack(end + "I", d[i:i+4])[0]
        if bt == 0x0A0D0D0A:                       # Section Header: fix byte order
            end = "<" if d[i+8:i+12] == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack(end + "I", d[i+4:i+8])[0]
        body = d[i+8:i+blen-4]
        if bt == 1:                                 # Interface Description
            ifaces.append(struct.unpack(end + "H", body[:2])[0])
        elif bt == 6:                               # Enhanced Packet Block
            iid, _th, _tl, cap, _orig = struct.unpack(end + "IIIII", body[:20])
            n += 1
            yield n, ifaces[iid], body[20:20+cap]
        elif bt == 3:                               # Simple Packet Block
            orig = struct.unpack(end + "I", body[:4])[0]
            n += 1
            yield n, ifaces[0], body[4:4+orig]
        i += blen


def tcp_of(link, frame):
    """Return dict(sp,dp,seq,flags,data) for an IPv4/TCP frame, else None."""
    if link == 1:                                   # Ethernet
        et = struct.unpack(">H", frame[12:14])[0]; off = 14
        while et in (0x8100, 0x88A8):               # VLAN tags
            et = struct.unpack(">H", frame[off+2:off+4])[0]; off += 4
        if et != 0x0800:
            return None
        p = frame[off:]
    elif link in (101, 228):                        # raw IP
        p = frame
    else:
        return None
    if (p[0] >> 4) != 4 or p[9] != 6:               # IPv4, proto TCP
        return None
    ihl = (p[0] & 0xF) * 4
    tot = struct.unpack(">H", p[2:4])[0]
    seg = p[ihl:tot]
    sp, dp, seq, _ack, off2 = struct.unpack(">HHIIH", seg[:14])
    hl = (off2 >> 12) * 4
    return dict(sp=sp, dp=dp, seq=seq, flags=off2 & 0x1FF, data=bytes(seg[hl:]))


# ---- reassemble each direction and cut into MBAP frames -------------------
segs = collections.defaultdict(list)                # 'c2s'/'s2c' -> [(pkt,seq,data)]
isn = {}
for n, link, frame in pcapng_packets(CAP):
    t = tcp_of(link, frame)
    if not t:
        continue
    d = "c2s" if t["dp"] == SERVER_PORT else "s2c"
    if t["flags"] & 0x02:                           # SYN -> initial seq
        isn[d] = (t["seq"] + 1) & 0xFFFFFFFF
    if t["data"]:
        segs[d].append((n, t["seq"], t["data"]))


def frames(d):
    """Reassemble a direction by seq, then split into MBAP PDUs.
    Each frame records 'done' = pkt number at which its last byte arrived,
    so request/response can be ordered on the wire."""
    buf, arrive = {}, {}
    for n, seq, data in segs[d]:
        for i, b in enumerate(data):
            off = (seq - isn[d] + i) & 0xFFFFFFFF
            if off not in buf:
                buf[off] = b; arrive[off] = n
    stream = bytes(buf[i] for i in range(len(buf)))
    out, i = [], 0
    while i + 7 <= len(stream):
        tid, pid, ln, uid = struct.unpack(">HHHB", stream[i:i+7])
        pdu = stream[i+7:i+6+ln]
        out.append(dict(tid=tid, pid=pid, uid=uid, pdu=pdu, done=arrive[i+5+ln], d=d))
        i += 6 + ln
    return out


events = sorted(frames("c2s") + frames("s2c"),
                key=lambda f: (f["done"], f["d"] == "s2c"))   # request before its response

state = {}
pending = None
witness = b""
unsafe = []
for f in events:
    if f["d"] == "c2s":
        pending = f
        continue
    q, r = pending, f
    pending = None
    if q is None or q["pid"] != 0 or q["uid"] != 1:
        continue
    hdr_ok = ((r["tid"], r["pid"], r["uid"]) == (q["tid"], q["pid"], q["uid"])
              and r["pdu"][:1] == q["pdu"][:1])
    fc = q["pdu"][0]
    if fc == 0x03:                                  # read holding registers
        addr, qty = struct.unpack(">HH", q["pdu"][1:5])
        if not hdr_ok or r["pdu"][1] != 2 * qty or len(r["pdu"]) != 2 + 2 * qty:
            continue
        for k in range(qty):                        # reads update the tracked state
            if addr + k in MAPPED:
                state[addr + k] = struct.unpack(">H", r["pdu"][2+2*k:4+2*k])[0]
    elif fc == 0x10:                                # write multiple registers
        addr, qty, bc = struct.unpack(">HHB", q["pdu"][1:6])
        vals = q["pdu"][6:]
        if bc != 2 * qty or len(vals) != bc:
            continue
        if not hdr_ok or r["pdu"][1:5] != q["pdu"][1:5] or len(r["pdu"]) != 5:
            continue                                # exception / malformed echo -> no state change
        if qty == 1 and addr in (0x13, 0x14):       # a TARGET write
            pre = (state.get(0x0A), state.get(0x0B), state.get(0x0C))
            if pre != (1, 1, 1):                     # UNSAFE
                unsafe.append((q["tid"], addr, vals.hex(), pre))
                witness += q["pdu"] + r["pdu"]
        for k in range(qty):                        # accepted write updates state after its response
            if addr + k in MAPPED:
                state[addr + k] = struct.unpack(">H", vals[2*k:2*k+2])[0]

# format self-check from witness-format.md
assert hashlib.sha256(P + bytes.fromhex("100013000102002a1000130001")).hexdigest() == \
    "b6e58fa962e382b112eb596e416d5680495fc4bd02141f2389797f194df34786"

print("unsafe target writes:", len(unsafe))
for tid, addr, v, pre in unsafe:
    print("  tid=%d addr=%#06x val=%s pre(permit,iso,armed)=%s" % (tid, addr, v, pre))
print("CSCTF{%s}" % hashlib.sha256(P + witness).hexdigest())
