#!/usr/bin/env python3
"""Carve the fragmented PNG out of recorder-sectors.img and verify it."""
import struct, zlib, sys
img = open(sys.argv[1] if len(sys.argv) > 1 else "recorder-sectors.img", "rb").read()
S = lambda a, b: img[a*512:(b+1)*512]          # inclusive sector range
head = S(52, 67)                                # PNG header + first part of IDAT
frags = {"A": S(3, 20), "B": S(35, 41), "C": S(44, 47)}   # remaining data, C holds IEND
png = None
for order in ("ABC", "BAC"):
    cand = head + b"".join(frags[k] for k in order)
    length = struct.unpack(">I", cand[33:37])[0]          # IDAT length
    idat = cand[41:41+length]
    crc = struct.unpack(">I", cand[41+length:45+length])[0]
    ok = zlib.crc32(b"IDAT" + idat) == crc
    print(order, "IDAT CRC ok:", ok)
    if ok:
        png = cand[:45+length+12]                         # + IEND chunk
        break
open("recovered_chart_frame.png", "wb").write(png)
print("wrote", len(png), "bytes")
