#!/usr/bin/env python3
"""
Ghost in the Historian (CSCTF 2026 - Forensics).

A campaign encrypted a substation historian's config and deleted the encryptor.
The encryptor (an ELF recovered from unallocated blocks of the ext4 image -- see
writeup) is a stream cipher:

    seed  = 0xA5A5A5A5 if (time == pid) else ((time ^ pid) * 0x9E3779B1) mod 2^32
    per 4-byte word:  s = xorshift32(s);  plaintext ^= little-endian bytes(s)
    xorshift32(s):    s ^= s<<13;  s ^= s>>17;  s ^= s<<5    (mod 2^32)

The same operation encrypts and decrypts (pure XOR keystream). The encryptor runs
scandir() order (alphabetical) over /var/historian and the keystream STATE CARRIES
from one file to the next, so the files must be decrypted in that same order.

It also utime()s each .enc to the sweep start time, so each ciphertext's own mtime
IS the `time` fed to the seed. From the image: mtime = 0x6ABF2F51 (2026-10-02
12:13:05 UTC) and the pid comes from /var/log/historian.log (historian_enc[2764964]).
"""
import sys, glob, os

T = 0x6ABF2F51          # encryptor RTC time (the .enc mtime set by utime())
PID = 2764964           # from historian.log: "historian_enc[2764964]: starting encryption sweep"
EVID = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "evidence")
M = 0xFFFFFFFF


def seed(t, pid):
    t &= M
    return 0xA5A5A5A5 if t == pid else ((t ^ pid) * 0x9E3779B1) & M


def xorshift(s):
    s ^= (s << 13) & M
    s ^= s >> 17
    s ^= (s << 5) & M
    return s & M


def crypt(data, s):
    out = bytearray(data)
    for i in range(0, len(out), 4):
        s = xorshift(s)
        for j, k in enumerate(s.to_bytes(4, "little")):
            if i + j < len(out):
                out[i + j] ^= k
    return bytes(out), s


# self-check: the operation is an involution and carries state
_p = b"hello historian!!"
_c, _s1 = crypt(_p, 1234)
assert crypt(_c, 1234)[0] == _p and _s1 != 1234

names = sorted(os.path.basename(p) for p in glob.glob(os.path.join(EVID, "*.enc")))  # scandir order
s = seed(T, PID)
for n in names:
    pt, s = crypt(open(os.path.join(EVID, n), "rb").read(), s)
    print("===== " + n)
    print(pt.decode("latin1"))
