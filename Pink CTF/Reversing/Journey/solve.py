"""Journey (Pink CTF): peel 9 nested programs without running any of them.

Go -> C -> Python -> Rust -> Haskell -> Java -> Brainfuck -> Ruby -> Emojicode -> flag
Each layer's decoder is reimplemented here from reading its source.

Usage: python solve.py gogogo.journey      (needs numpy + pycryptodome; ~1 min, layer 2 is a pure-Python loop)
"""
import base64, gzip, hashlib, io, re, struct, sys, zlib
from functools import reduce

import numpy as np
from Crypto.Cipher import AES

xaa = lambda hx, k=0xAA: bytes(b ^ k for b in bytes.fromhex(hx)).decode()  # every layer hides its strings this way
ror1 = lambda a: ((a >> 1) | (a << 7)).astype(np.uint8)
take_len = lambda b: b[4:4 + int.from_bytes(b[:4], "big")]                  # 4-byte big-endian length prefix


def go(src):  # pt = ror1(((ct - (i^2 + 31i + binbash)) * ain) & 0xFF)
    ct = np.frombuffer(bytes.fromhex(re.search(r'gogogo = "([0-9a-f]+)"', src).group(1)), np.uint8)
    i = np.arange(len(ct), dtype=np.uint64)
    key = int(re.search(r"binbash = (\d+)", src).group(1)); ain = int(re.search(r"ain = (\d+)", src).group(1))
    b = ((i * i + 31 * i + key) & 0xFF).astype(np.uint8)
    return take_len(ror1(((ct - b).astype(np.uint16) * ain & 0xFF).astype(np.uint8)).tobytes())


def c(src):  # per-line xorshift32 keystream with a per-line salt
    M = 0xFFFFFFFF
    arr = lambda n: [int(x, 0) for x in re.findall(r"0x[0-9A-Fa-f]+|\d+", re.search(n + r"\[\]\s*=\s*\{([^}]*)\}", src).group(1))]
    body = {int(m.group(1)): m.group(2) for m in re.finditer(r"static const u8 L(\d+)\[\] = \{([^}]*)\}", src)}
    order = re.findall(r"\bL(\d+)\b", re.search(r"Q_LINES\[\]\s*=\s*\{([^}]*)\}", src).group(1))
    salts, out = arr("Q_SALT"), []
    for li, ln in enumerate(order):
        data = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body[int(ln)]))
        salt = salts[li]
        st = (0xC0FFEE00 ^ ((li * 0x9E3779B9) & M) ^ len(data) ^ (salt << 24)) & M
        st ^= (st << 13) & M; st ^= st >> 7
        line = bytearray()
        for j, b in enumerate(data):
            st ^= (st << 13) & M; st ^= st >> 17; st ^= (st << 5) & M
            t = (b - salt) & 0xFF; t = ((t >> 3) | (t << 5)) & 0xFF
            line.append(((t ^ ((st ^ li * 131 ^ j) & 0xFF)) - ((j + li) & 0xFF)) & 0xFF)
        out.append(bytes(line))
    return b"\n".join(out) + b"\n"


def python(src):  # 10 rounds of zlib.decompress then XOR with sha256(s + [r] + s)
    get = lambda n: re.search(rf'^{n} = "?([0-9a-f]+)"?$', src, re.M).group(1)
    s, y = bytes.fromhex(get("Q0")), bytes.fromhex(get("Q1"))
    for r in reversed(range(int(get("Q2")))):
        y = zlib.decompress(y)
        k = np.frombuffer(hashlib.sha256(s + bytes([r]) + s).digest(), np.uint8)
        y = (np.frombuffer(y, np.uint8) ^ np.resize(k, len(y))).tobytes()
    return take_len(y)


def rust(src):  # ror1(b ^ (131i & 0xFF) ^ key[i % len])
    key = np.frombuffer(re.search(r'Z1: &str = "([^"]+)"', src).group(1).encode(), np.uint8)
    blob = np.frombuffer(bytes.fromhex("".join(re.findall(r'"([0-9a-f]+)"', re.search(r"Z2: &\[&str\] = &\[(.*?)\];", src, re.S).group(1)))), np.uint8)
    i = np.arange(len(blob), dtype=np.uint64)
    return take_len(ror1(blob ^ ((i * 131) & 0xFF).astype(np.uint8) ^ np.resize(key, len(blob))).tobytes())


def haskell(src):  # only d4 matters: byte - (i+1); r1/r6/r8/r9 are identities
    k1 = np.frombuffer(bytes.fromhex("".join(re.findall(r'"([0-9a-f]+)"', re.search(r"zz =\s*\[(.*?)\]", src, re.S).group(1)))), np.uint8)
    i = np.arange(1, len(k1) + 1, dtype=np.uint64)
    return take_len(((k1.astype(np.uint64) - i) % 256).astype(np.uint8).tobytes())


def java(src):  # AES-256-GCM, PBKDF2-HMAC-SHA256("espresso-beans-42", salt, 9541 iters), AAD = output name
    field = lambda n: re.search(rf'String {n} =\s*"([^"]*)"', src).group(1)
    b64 = "".join(v for _, v in sorted(re.findall(r'String (cappuccino_\d{3}) =\s*"([^"]*)"', src)))
    if len(b64) > 10 and b64.startswith("Zm"): b64 = b64[2:] + "=="
    blob = base64.b64decode(b64)
    key = hashlib.pbkdf2_hmac("sha256", b"espresso-beans-42", base64.b64decode(field("latte")), 7000 + 2048 + 17 * 29, 32)
    cip = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(field("espresso")))
    cip.update(xaa(field("cappuccino_brunello")).encode())
    return cip.decrypt_and_verify(blob[:-16], blob[-16:])  # raises if the tag is wrong


def brainfuck(src):  # no loops, no input: just run + - < > .
    tape, p, out = [0] * 30000, 0, bytearray()
    for ch in src.decode():
        if ch == "+": tape[p] = (tape[p] + 1) & 255
        elif ch == "-": tape[p] = (tape[p] - 1) & 255
        elif ch == ">": p += 1
        elif ch == "<": p -= 1
        elif ch == ".": out.append(tape[p])
        elif ch in "[],": raise ValueError("unexpected op " + ch)
    return base64.b64decode(out.decode().split("\n\n", 1)[1])  # "mine rubies" line, then base64 Ruby


def ruby(src):  # JRNYv2 header -> N rounds XOR sha256(salt + N)[:klen] -> gunzip
    src = src.decode()
    heredoc = lambda n: base64.b64decode("".join(re.search(rf"{n} = <<~B64\n(.*?)\nB64", src, re.S).group(1).split()))
    h = io.BytesIO(heredoc("marrakesh"))
    assert h.read(8) == b"JRNYv2\0\0"
    rounds, klen, slen = h.read(3); salt = h.read(slen); gz = h.read(1)[0]; size = struct.unpack(">I", h.read(4))[0]
    v = heredoc("valparaiso")
    for r in range(rounds - 1, -1, -1):
        k = np.frombuffer(hashlib.sha256(salt + struct.pack(">I", r)).digest()[:klen], np.uint8)
        v = (np.frombuffer(v, np.uint8) ^ np.resize(k, len(v))).tobytes()
    v = gzip.decompress(v) if gz & 1 else v
    assert len(v) == size
    return v


def emojicode(src):  # each block: char = table[const ^ all fruit constants]
    s = src.decode("utf-8").replace("\r\n", "\n")
    consts = {n: int(v) for v, n in re.findall(r"^  (\d+) ➡️ (\w+)$", s, re.M)}
    out = ""
    for blk in re.split(r"\n  ↪️ 1 \U0001f64c 1 \U0001f347\n", s)[1:]:
        start, var = re.search(r"(\d+) ➡️ \U0001f58d\U0001f195 (\w+)", blk).groups()
        v = reduce(lambda a, n: a ^ consts[n], re.findall(rf"{var} ⬅️❌ (\w+)", blk), int(start))
        out += dict((int(n), t) for n, t in re.findall(rf"{var} \U0001f64c (\d+) \U0001f347 \U0001f600 \U0001f524(.*?)\U0001f524", blk))[v]
    return out


if __name__ == "__main__":
    data = open(sys.argv[1]).read()
    for name, step, as_text in ((" Go", go, True), (" C", c, True), (" Python", python, True), (" Rust", rust, True),
                                (" Haskell", haskell, True), (" Java", java, False), (" Brainfuck", brainfuck, False),
                                (" Ruby", ruby, False), (" Emojicode", emojicode, None)):
        data = step(data)
        print(f"peeled{name:<11} -> {len(data):>9} bytes")
        if as_text: data = data.decode()
    print(data)
    assert data == "PINK{Th3_J0urn3y_m4y_n3v3r_3nd!!}"
