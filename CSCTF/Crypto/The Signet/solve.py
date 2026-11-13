#!/usr/bin/env python3
"""The Signet: recover the ECDSA private key from six signatures whose nonces form
an arithmetic progression (k_i = a + i*b mod n), then HKDF+AES-GCM-decrypt the seal.
usage: python3 solve.py sealed-orders.der [case-note.txt]
pure DER walk + stdlib crypto; only the AES-GCM step uses the `cryptography` package."""
import sys, hashlib, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# secp256k1 group order (SEC 2)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def tlv(d, i):
    """Return (tag, content_bytes, next_index) for the DER element at d[i]."""
    tag = d[i]; i += 1
    l = d[i]; i += 1
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(d[i:i+n], 'big'); i += n
    return tag, d[i:i+l], i + l

def seq(content):
    """Split a SEQUENCE body into its elements as (tag, content) pairs."""
    out, i = [], 0
    while i < len(content):
        t, c, i = tlv(content, i)
        out.append((t, c))
    return out

def uint(b):  # INTEGER content -> non-negative int
    return int.from_bytes(b, 'big')

def solve(der_path):
    d = open(der_path, 'rb').read()
    _, body, end = tlv(d, 0)
    assert end == len(d), "trailing bytes after the bundle"
    version, signer, orders, seal = seq(body)
    assert uint(version[1]) == 1

    # orders: SEQUENCE OF SignedOrder{ seq, message OCTET STRING, ECDSA-Sig{r,s} }
    sigs = []
    for _, so in seq(orders[1]):
        fields = seq(so)
        s_seq, msg, sig = fields[0], fields[1], fields[2]
        r, s = seq(sig[1])
        z = int.from_bytes(hashlib.sha256(msg[1]).digest(), 'big') % N
        sigs.append((uint(s_seq[1]), uint(r[1]), uint(s[1]), z))
    sigs.sort()
    assert [x[0] for x in sigs] == list(range(6)), "need seq 0..5"

    # k_i = s_i^-1 (z_i + r_i d) = A_i d + B_i, and k_i = a + i b.
    # => A_i d - a - i b = -B_i. Solve the 3x3 system (i=0,1,2) mod N for (d,a,b).
    rows = []
    for i, (_, r, s, z) in enumerate(sigs[:3]):
        si = pow(s, -1, N)
        A = (si * r) % N          # coeff of d
        B = (si * z) % N          # constant
        rows.append([A % N, (-1) % N, (-i) % N, (-B) % N])  # [d, a, b | rhs]

    # Gaussian elimination mod N
    M = [row[:] for row in rows]
    for col in range(3):
        p = next(rr for rr in range(col, 3) if M[rr][col] % N)
        M[col], M[p] = M[p], M[col]
        inv = pow(M[col][col], -1, N)
        M[col] = [(x * inv) % N for x in M[col]]
        for rr in range(3):
            if rr != col and M[rr][col]:
                f = M[rr][col]
                M[rr] = [(a - f * b) % N for a, b in zip(M[rr], M[col])]
    d_priv, a, b = M[0][3], M[1][3], M[2][3]

    # Overdetermined check: the same d, a, b must reproduce all six nonces.
    for i, (_, r, s, z) in enumerate(sigs):
        si = pow(s, -1, N)
        k = (si * (z + r * d_priv)) % N
        assert k == (a + i * b) % N, f"nonce model fails at i={i}"

    # Seal: salt, nonce, ciphertext, tag
    salt, nonce, ct, tag = (f[1] for f in seq(seal[1]))
    ikm = d_priv.to_bytes(32, 'big')
    # HKDF-SHA256 (extract + expand, L=32 so one expand block)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    info = b"CSCTF26/TheSignet/v1/standing-order"
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    flag = AESGCM(okm).decrypt(nonce, ct + tag, None).decode()

    print("recovered private key d =", hex(d_priv))
    print("nonce start a           =", hex(a))
    print("nonce stride b          =", hex(b))
    print("all 6 nonce checks      = OK")
    print("FLAG:", flag)
    return flag

if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "sealed-orders.der")
