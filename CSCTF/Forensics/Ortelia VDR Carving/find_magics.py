#!/usr/bin/env python3
"""List PNG / IEND / JPEG magic offsets and their 512-byte sector in a raw dump.
usage: python find_magics.py recorder-sectors.img"""
import re, sys
d = open(sys.argv[1] if len(sys.argv) > 1 else "recorder-sectors.img", "rb").read()
print(f"{len(d)} bytes = {len(d)//512} sectors x 512 B")
for name, pat in (("PNG magic", rb"\x89PNG\r\n\x1a\n"), ("IEND", rb"IEND"), ("JPEG magic", rb"\xff\xd8\xff")):
    for m in re.finditer(pat, d):
        o = m.start()
        print(f"{name:<11} @ {o:#07x}  (sector {o//512})")
