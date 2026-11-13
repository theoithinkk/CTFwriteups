"""Emanation solver: second-order CPA on masked, randomly delayed AES-128 traces.

Usage: python -I solve.py path/to/emanation/

1. Undo the random delay: every trace has one large marker spike; align on it.
2. After the marker, 17 leak samples sit at offsets 3, 5, ..., 35:
   slot 0 = HW(mask), slots 1..16 = HW(Sbox(p_j ^ k_j) ^ mask).
3. Second-order CPA: the centered product slot0 * slot(j+1) correlates with
   HW(Sbox(p_j ^ k)) only for the right key byte k.
4. Decrypt sealed_order.hex with AES-128-CTR, all-zero initial counter block.
"""
import sys

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def sbox():
    # Build the AES S-box from GF(2^8) inverses plus the affine map (avoids a 256-entry table).
    def mul(a, b):
        r = 0
        while b:
            if b & 1: r ^= a
            a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
            b >>= 1
        return r
    inv = [0] + [next(y for y in range(1, 256) if mul(x, y) == 1) for x in range(1, 256)]
    rot = lambda v, n: ((v << n) | (v >> (8 - n))) & 0xFF
    return np.array([v ^ rot(v, 1) ^ rot(v, 2) ^ rot(v, 3) ^ rot(v, 4) ^ 0x63 for v in inv])


def recover_key(traces, pts):
    d = traces.argmax(1)                                   # marker position = random delay
    pad = np.pad(traces, ((0, 0), (0, 40)))
    aligned = pad[np.arange(len(traces))[:, None], d[:, None] + np.arange(40)]
    slots = aligned[:, 3:37:2]                             # 17 leak samples
    z = (slots - slots.mean(0)) / slots.std(0)

    S, hw = sbox(), np.array([bin(i).count('1') for i in range(256)])
    key = []
    for j in range(16):
        prod = z[:, 0] * z[:, j + 1]
        prod -= prod.mean()
        model = hw[S[pts[:, j, None] ^ np.arange(256)]].astype(float)
        model -= model.mean(0)
        corr = np.abs(prod @ model) / (np.linalg.norm(prod) * np.linalg.norm(model, axis=0))
        key.append(int(corr.argmax()))
    return bytes(key)


if __name__ == '__main__':
    assert sbox()[0x00] == 0x63 and sbox()[0x53] == 0xED   # FIPS-197 spot checks
    base = sys.argv[1].rstrip('/\\') + '/'
    traces = np.load(base + 'traces.npy', allow_pickle=False).astype(float)
    pts = np.load(base + 'plaintexts.npy', allow_pickle=False)
    key = recover_key(traces, pts)
    ct = bytes.fromhex(open(base + 'sealed_order.hex').read().strip())
    dec = Cipher(algorithms.AES(key), modes.CTR(bytes(16))).decryptor()
    print('key  :', key.hex())
    print('order:', (dec.update(ct) + dec.finalize()).decode())
