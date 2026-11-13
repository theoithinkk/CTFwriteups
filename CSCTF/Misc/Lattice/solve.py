#!/usr/bin/env python3
"""
Lattice: invert the toy 8-byte / 16-round ECB cipher from the handout to recover
the sealed passphrase, then (optionally) speak it to the vault.

Every primitive is public and reversible: LCG-seeded Fisher-Yates S-box (+ inverse),
per-round add/xor round keys, and a whole-block rotl64 (-> rotr64). Reverse the rounds
15..0, strip PKCS#7.

Usage:
    python -I solve.py                 # print recovered passphrase
    python -I solve.py --send HOST PORT  # also send it to the vault, print the flag
"""
import sys
MASK64 = (1 << 64) - 1

def _lcg(state):
    while True:
        state = (state * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        yield state

def _build_sbox():
    g = _lcg(0x1A2B3C4D); box = list(range(256))
    for i in range(255, 0, -1):
        j = next(g) % (i + 1); box[i], box[j] = box[j], box[i]
    return box

SBOX = _build_sbox()
INV = [0]*256
for i, v in enumerate(SBOX): INV[v] = i

def _build_keys():
    g = _lcg(0xCAFEB0BA)
    return [[next(g) & 0xFF for _ in range(8)] for _ in range(16)]

RKEYS = _build_keys()

def _rotr64(x, k):
    k &= 63
    return ((x >> k) | (x << (64 - k))) & MASK64

def _rot_amount(r):
    return (7 * r + 11) % 63 + 1

def decrypt_block(block):
    s = list(block)
    for r in range(15, -1, -1):
        x = int.from_bytes(bytes(s), "big")
        x = _rotr64(x, _rot_amount(r))
        s = list(x.to_bytes(8, "big"))
        s = [INV[b] for b in s]
        rk = RKEYS[r]
        if r % 2 == 0:
            s = [(s[i] - rk[i]) & 0xFF for i in range(8)]
        else:
            s = [s[i] ^ rk[i] for i in range(8)]
    return bytes(s)

TARGET = (b'\xc4\x02\xfb,T3g6\xe6\xce\x04\xc5\x9ba\x0c\xa2\x95\xa9\xa9\x04\xbbX+\xd2'
          b'\xe6\x11L\xcf\xc7\xbd<\x0b\xba;@\x8f\xb5\xd4\xbfbNE\x80\x8f\xb1;\x06K')

def recover():
    pt = b"".join(decrypt_block(TARGET[i:i+8]) for i in range(0, len(TARGET), 8))
    return pt[:-pt[-1]]  # strip PKCS#7

def main():
    secret = recover()
    print("[+] passphrase:", secret.decode())
    if len(sys.argv) >= 4 and sys.argv[1] == "--send":
        import socket, time
        host, port = sys.argv[2], int(sys.argv[3])
        s = socket.create_connection((host, port), timeout=10)
        time.sleep(0.5)
        try: sys.stdout.write(s.recv(4096).decode("latin1"))
        except Exception: pass
        s.sendall(secret + b"\n")
        s.settimeout(8); buf = b""
        try:
            while True:
                d = s.recv(4096)
                if not d: break
                buf += d
        except Exception: pass
        sys.stdout.write(buf.decode("latin1"))

if __name__ == "__main__":
    main()
