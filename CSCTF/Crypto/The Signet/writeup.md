Challenge: The Signet — Crypto / Easy / 120 pts / author: Terminal43 (CSCTF 2026)
Flag: CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}
Category: Cryptography (ECDSA nonce recovery — arithmetic-progression nonces on secp256k1)
Tools used: Python 3 (hand-written DER walk, stdlib hashlib/hmac), cryptography (AES-256-GCM only), solve.py

Brief: a dispatch signet signed six orders on secp256k1 while its entropy sampler was faulty, then sealed a seventh
"standing order" with a key derived from the signer's private key. case-note.txt documents the exact formats (a DER
SignetBundle) and states the fault: each signing nonce was the previous one plus a fixed additive stride modulo the
group order. Recover the private key and decrypt the sealed standing order.

Steps:
1. Start point: read case-note.txt.
   - What I found: the bundle is DER with six SignedOrder records (seq 0..5, each an exact message OCTET STRING plus
     an ECDSA r,s) and one SealedOrder (salt, nonce, ciphertext, tag). The curve is secp256k1, hash SHA-256,
     z_i = int_be(SHA256(message_i)) mod n. The sealed order is AES-256-GCM under
     key = HKDF-SHA256(IKM = the private key d as 32 big-endian bytes, salt = seal.salt,
     info = "CSCTF26/TheSignet/v1/standing-order", L = 32).
   - Thinking: "same additive stride modulo the curve order" across consecutive signatures is the whole challenge.
     The nonces are an arithmetic progression k_i = a + i*b (mod n), with a (start) and b (stride) unknown and
     unlogged. That is a linear relation I can exploit without ever guessing a or b.

2. Pivot: turn each signature into a linear equation in the unknowns.
   - For each signature, s_i = k_i^-1 (z_i + r_i d), so k_i = s_i^-1 z_i + s_i^-1 r_i d. Writing A_i = s_i^-1 r_i and
     B_i = s_i^-1 z_i gives k_i = A_i d + B_i. Setting that equal to a + i*b:
         A_i d - a - i*b = -B_i   (mod n)
   - There are three unknowns (d, a, b), all mod n. The first three records (i = 0,1,2) give a 3x3 linear system I
     solve by Gaussian elimination modulo n (every division is a modular inverse).

3. Pivot: recover d and verify it is really right.
   - What I did: solved the system, then used the recovered (d, a, b) to recompute k_i = s_i^-1(z_i + r_i d) for ALL
     six records and checked each equals a + i*b (mod n). All six matched, which is a strong internal proof: three
     equations fixed the unknowns, the other three confirm the model is the true one, not a coincidence.
   - Result: d = 0x79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f.

4. Pivot: open the seal.
   - IKM = d as 32 unsigned big-endian bytes. HKDF-SHA256 with the note's salt and info (L = 32 is a single expand
     block, so HMAC(PRK, info || 0x01)). AES-256-GCM over seal.ciphertext with seal.tag, seal.nonce, empty AAD.
   - Result: the plaintext is the flag, verbatim.

Flag: CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}

Reproduce: `python3 solve.py sealed-orders.der`
Key insight: nonces that step by a constant stride make each ECDSA signature a linear equation in (d, start, stride);
three signatures are enough to solve for the private key, and the rest verify it.
Defensive takeaways:
- ECDSA security rests entirely on unpredictable, independent per-signature nonces (k). A biased or structured k —
  reuse, a counter, an LCG, or here a fixed stride — leaks the long-term private key from a handful of signatures.
  Use deterministic nonces (RFC 6979) or an audited RNG, and never sign with a degraded entropy source.
- Deriving a data-encryption key from the signing key ties two duties to one secret: cracking the signatures also
  unsealed the data. Keep signing keys and encryption keys separate.
Screenshots:
- screenshots/01_solve_run.png   solve.py recovering d, verifying all six nonces, and decrypting the seal (live re-run)
Note: the screenshot is a live re-run of solve.py against the challenge's own sealed-orders.der; it reproduces the
documented flag above.
