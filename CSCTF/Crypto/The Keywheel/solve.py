#!/usr/bin/env python3
"""Solver: recover the pre-window standing order from key-unit-journal.cbor
(MT19937 register -> invert the twist -> derive tx 155 key -> SHA-256 CTR-style XOR)."""
import struct, hashlib, sys

PATH = sys.argv[1] if len(sys.argv) > 1 else "key-unit-journal.cbor"
d = open(PATH, "rb").read()

def parse(i):                      # minimal CBOR decoder
    b = d[i]; mt = b >> 5; ai = b & 31; i += 1
    if ai < 24: v = ai
    elif ai == 24: v = d[i]; i += 1
    elif ai == 25: v = struct.unpack(">H", d[i:i+2])[0]; i += 2
    elif ai == 26: v = struct.unpack(">I", d[i:i+4])[0]; i += 4
    elif ai == 27: v = struct.unpack(">Q", d[i:i+8])[0]; i += 8
    if mt == 0: return v, i
    if mt == 1: return -1 - v, i
    if mt == 2: return d[i:i+v], i + v
    if mt == 3: return d[i:i+v].decode(), i + v
    if mt == 4:
        l = []
        for _ in range(v):
            x, i = parse(i); l.append(x)
        return l, i
    if mt == 5:
        m = {}
        for _ in range(v):
            k, i = parse(i); x, i = parse(i); m[k] = x
        return m, i
    raise ValueError(mt)

o, _ = parse(0)
reg = o["register"]
print("[1] CBOR structure")
for k in ("device", "scheme", "window_opens_tx"):
    print(f"  {k}: {o[k]}")
print(f"  register: {len(reg)} x uint32  (= {len(reg)//8} tx worth of 8-word keys)")
for t in o["traffic"]:
    print(f"  traffic tx={t['tx']:<4} role={t['role']:<14} sealed={len(t['sealed'])} bytes")

# ---- MT19937 helpers
def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    t = y
    for _ in range(5): t = y ^ ((t << 7) & 0x9D2C5680)
    y = t; t = y
    for _ in range(3): t = y ^ (t >> 11)
    return t & 0xffffffff
def temper(y):
    y ^= y >> 11; y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000; y ^= y >> 18
    return y & 0xffffffff
def twist(s):
    s = s[:]
    for i in range(624):
        y = (s[i] & 0x80000000) | (s[(i+1) % 624] & 0x7fffffff)
        s[i] = s[(i+397) % 624] ^ (y >> 1) ^ (0x9908b0df if y & 1 else 0)
    return s

st = [untemper(x) for x in reg[:624]]
ok = [temper(x) for x in twist(st)] == reg[624:1248]
print("\n[2] Generator identification")
print("  untempered first 624 outputs -> state; twist(state) tempered == outputs 624..1247 ?", ok)

# ---- invert the twist (recover the previous 624-word block)
def getY(t):
    if t & 0x80000000:
        t ^= 0x9908b0df
        return ((t << 1) | 1) & 0xffffffff
    return (t << 1) & 0xffffffff
hi = [0]*624; lo = [0]*624
for i in range(623, 226, -1):          # new[i] = new[i-227] ^ f(y_i)
    y = getY(st[i] ^ st[i-227])
    hi[i] = y & 0x80000000
    lo[(i+1) % 624 if i < 623 else 0] = y & 0x7fffffff
P = [hi[i] | lo[i] for i in range(624)]
prev8 = [temper(P[i]) for i in range(616, 624)]
print("\n[3] Turn the key wheel back (last 8 outputs before the window)")
print("  ", " ".join(f"{w:08x}" for w in prev8))

def dec(words, ct):
    key = b"".join(struct.pack(">I", w) for w in words)
    ks, i = b"", 0
    while len(ks) < len(ct):
        ks += hashlib.sha256(key + struct.pack(">I", i)).digest(); i += 1
    return bytes(a ^ b for a, b in zip(ct, ks))

tx = {t["tx"]: t["sealed"] for t in o["traffic"]}
print("\n[4] Decrypt")
print("  tx 156 (in-window, reg[0:8])  ->", dec(reg[0:8], tx[156]).decode())
print("  tx 155 (pre-window, recovered) ->", dec(prev8, tx[155]).decode())
