#!/usr/bin/env python3
"""
Operation Dawn: Radio Recovery (CSCTF 2026 - Reverse engineering).

firmware.bin is a custom "DWFW" container:

    header: "DWFW" | u16 version | u16 entry_count | then entry_count entries of
    entry : name[8] | u32 offset | u32 size | u32 crc32      (20 bytes each)

Entries: loader, ubootenv (2x 8 KiB U-Boot env copies), msgcat, rootfs.
  * rootfs is zlib-compressed with a PRESET DICTIONARY; the dictionary is msgcat
    (its adler32 == the dictid in the zlib header). Inflating gives a newc cpio.
  * the cpio holds /etc/config/radio with admin_token=<hex> and the real key is
    derived at boot by S40admin: key = token XOR (ethaddr-without-colons, repeating).
  * ethaddr comes from the ACTIVE U-Boot env copy (the one with the valid CRC /
    newer flag byte), which is 3c:22:fb:4a:1d:90.

Pure stdlib (struct, zlib, binascii).
"""
import sys, struct, zlib, binascii

FW = sys.argv[1] if len(sys.argv) > 1 else "firmware.bin"
d = open(FW, "rb").read()
assert d[:4] == b"DWFW"
_ver, n = struct.unpack("<HH", d[4:8])
ent = {}
for i in range(n):
    e = d[8 + 20 * i:28 + 20 * i]
    name = e[:8].rstrip(b"\x00").decode()
    off, size, crc = struct.unpack("<III", e[8:20])
    blob = d[off:off + size]
    assert binascii.crc32(blob) == crc, "crc mismatch for %s" % name
    ent[name] = blob

# --- active U-Boot env copy -> ethaddr -------------------------------------
env = ent["ubootenv"]
mac = None
for o in (0, 0x2000):                                   # two 8 KiB copies
    c = env[o:o + 0x2000]
    if binascii.crc32(c[5:]) == struct.unpack("<I", c[:4])[0]:   # crc(4) + flag(1) + vars
        for v in c[5:].split(b"\x00"):
            if v.startswith(b"ethaddr="):
                m = v.split(b"=", 1)[1].decode()                 # last valid copy wins (newest)
                mac = bytes.fromhex(m.replace(":", ""))
assert mac, "no active ethaddr"

# --- rootfs: zlib with msgcat as preset dictionary -> newc cpio ------------
rootfs = zlib.decompressobj(zdict=ent["msgcat"]).decompress(ent["rootfs"])

token = None
i = 0
while i + 110 <= len(rootfs):                           # newc cpio
    h = rootfs[i:i + 110]
    assert h[:6] == b"070701"
    fsz = int(h[54:62], 16)
    nsz = int(h[94:102], 16)
    name = rootfs[i + 110:i + 110 + nsz - 1].decode()
    i = (i + 110 + nsz + 3) & ~3
    data = rootfs[i:i + fsz]
    i = (i + fsz + 3) & ~3
    if name == "TRAILER!!!":
        break
    if name == "etc/config/radio":
        for ln in data.decode().splitlines():
            if ln.startswith("admin_token="):
                token = bytes.fromhex(ln.split("=", 1)[1])
assert token, "admin_token not found"

key = bytes(b ^ mac[idx % len(mac)] for idx, b in enumerate(token))
print("ethaddr =", ":".join("%02x" % x for x in mac))
print(key.decode())
