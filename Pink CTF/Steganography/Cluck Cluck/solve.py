"""Cluck Cluck solver.

Usage: python -I solve.py chicken.wav

1. Read the 2 least significant bits of every 16-bit sample (low bit first)
   and pack them little-endian into bytes.
2. Parse the hidden container: b'CHKN' + uint32 length + payload.
3. The payload is a program in the Chicken esolang. Running it prints a decoy
   banner; the flag sits in code blocks the program always jumps over.
"""
import struct
import sys
import wave

import numpy as np


def extract_payload(path):
    with wave.open(path) as w:
        s = np.frombuffer(w.readframes(w.getnframes()), dtype='<i2').astype(np.int32)
    bits = np.stack([s & 1, (s >> 1) & 1], axis=1).reshape(-1).astype(np.uint8)
    raw = np.packbits(bits[:len(bits) // 8 * 8], bitorder='little').tobytes()
    if raw[:4] != b'CHKN':
        raise ValueError(f'no CHKN header, got {raw[:4]!r}')
    (n,) = struct.unpack('<I', raw[4:8])
    return raw[8:8 + n].decode('ascii')


def opcodes(src):
    # One instruction per line; the opcode is how many times "chicken" appears.
    return [line.split().count('chicken') for line in src.split('\n')]


def run(code, inp=''):
    """Chicken interpreter. Returns (output, set of executed stack indices)."""
    def add(a, b):  # reference implementation is JavaScript: '+' concatenates strings
        return str(a) + str(b) if isinstance(a, str) or isinstance(b, str) else a + b

    st = [None, inp] + code + [0]  # [0]=stack itself, [1]=input, program, final axe
    st[0] = st
    ip, seen = 2, set()
    while True:
        seen.add(ip)
        op = st[ip]
        ip += 1
        if op == 0: break                                                # axe
        elif op == 1: st.append('chicken')                               # chicken
        elif op == 2: b, a = st.pop(), st.pop(); st.append(add(a, b))    # add
        elif op == 3: b, a = st.pop(), st.pop(); st.append(a - b)        # fox
        elif op == 4: b, a = st.pop(), st.pop(); st.append(a * b)        # rooster
        elif op == 5: b, a = st.pop(), st.pop(); st.append(a == b)       # compare
        elif op == 6:                                                    # pick (2 wide)
            sel = st[ip]; seen.add(ip); ip += 1
            st.append((st if sel == 0 else st[1])[st.pop()])
        elif op == 7:                                                    # peck
            addr, val = st.pop(), st.pop()
            st.extend([None] * (addr + 1 - len(st)))
            st[addr] = val
        elif op == 8:                                                    # fr
            off, cond = st.pop(), st.pop()
            if cond: ip += off
        elif op == 9: st.append(chr(st.pop()))                           # BBQ
        else: st.append(op - 10)                                         # push n-10
    return st[-1], seen


def hidden_text(code, seen):
    """Printable push literals inside never-executed blocks that sit behind an
    unconditional jump ("push 1, push offset, fr"). Conditional dead blocks are
    the program's own FAIL messages and are left out."""
    op = lambda i: code[i - 2]
    dead = [i for i in range(2, 2 + len(code)) if i not in seen]
    blocks = []
    for i in dead:
        if blocks and i == blocks[-1][-1] + 1: blocks[-1].append(i)
        else: blocks.append([i])
    out = ''
    for blk in blocks:
        a = blk[0]
        if a - 3 >= 2 and op(a - 3) == 11 and op(a - 1) == 8:
            # Dead code never runs, so a "pick" there does not swallow the next line.
            out += ''.join(chr(op(i) - 10) for i in blk if 42 <= op(i) < 137)
    return out


if __name__ == '__main__':
    # self-check: push 72 'H', BBQ, push 105 'i', BBQ, add -> "Hi"
    assert run([82, 9, 115, 9, 2])[0] == 'Hi'

    code = opcodes(extract_payload(sys.argv[1]))
    banner, seen = run(code)
    print(banner)
    print('Hidden in skipped code:', hidden_text(code, seen))
