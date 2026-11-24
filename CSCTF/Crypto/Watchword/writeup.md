Flag: CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}
Category: Crypto (AES-GCM nonce reuse)
Tools used: Python, pycryptodome
Challenge: Watchword (CSCTF 2026, Crypto, Medium, 270 pts, author: Michalina Moszyńska)

Steps:

1. Start point: the handout, watchword.zip
   - What I did: unzipped it and read README.txt and intercepts.json.
   - What I found: the README says a SABRELINK unit reused one AES-128-GCM nonce across a run of dispatches after a
     firmware fault, and that a "sealed master order" was encrypted separately with AES-128-CTR (all-zero IV) under
     the link's per-nonce tag mask E_K(J0). intercepts.json held three authenticated dispatches (ciphertext plus a
     16-byte GCM tag, all under the one nonce, empty AAD) and the sealed master order ciphertext.
   - Thinking: this is the classic GCM nonce-reuse ("forbidden attack") setup. A reused nonce means one fixed,
     unknown GHASH key H and one fixed tag mask S = E_K(J0) across all three messages, and S is also the key for
     the master order.

2. Pivot: XORing two tags cancels the mask
   - What I found: each ciphertext was at most 16 bytes, so GHASH covers one ciphertext block C and one length
     block L:
     - GHASH_H(C) = C·H² ⊕ L·H
     - tag = C·H² ⊕ L·H ⊕ S
   - What I did: XORed the tag equations of dispatches 1 and 2, and of dispatches 1 and 3. Each XOR cancels S and
     leaves a quadratic in H with known coefficients.
   - Thinking: the true H is a root of both quadratics. Solving a quadratic in characteristic 2 is messy, but their
     polynomial GCD over GF(2^128) isolates the shared linear factor (x ⊕ H) directly.

3. Dead end: the GCD hung on a wrong field identity
   - What I did: wrote GHASH-style gmul (bit-reflected GF(2^128) multiplication with the reduction polynomial
     written as 0xE1000...0), inversion by exponentiation, and polynomial long division and Euclidean GCD over that
     field.
   - Dead end: the first run hung. gpow() seeded its accumulator with the integer 1, but in GCM's bit-reflected
     convention the multiplicative identity is 1 << 127. Every computed inverse was wrong, so division never
     reduced the remainder's degree and looped forever.
   - Thinking: a GCD on polynomials of degree at most 2 has to finish, so a hang (not a crash) pointed at a
     remainder that wasn't shrinking, which means the field arithmetic itself.
   - Result: I set GF_ONE = 1 << 127, checked that gmul(a, GF_ONE) == a and gmul(a, ginv(a)) == GF_ONE held for
     random field elements, and reran.

4. Pivot: the GCD gives H and the tags give S
   - What I did: ran the fixed solver. The GCD of the two quadratics came back degree 1, so its root is the GHASH
     key, H = 0x730426f0d054fc7539d26145168be28a.
   - What I found: putting H back into each dispatch's tag = GHASH_H(C) ⊕ S gave the same tag mask from all three
     dispatches independently, S = 0x66b18782c578d8b27ec249a6298dfeb2.
   - Thinking: a wrong H could not produce one consistent S across three independent ciphertexts, so the agreement
     confirms both values.

5. Flag: decrypting the sealed master order
   - What I did: decrypted sealed_master_order_ctr_hex with AES-128-CTR under S as the 16-byte key and an all-zero
     counter, using pycryptodome's AES.new(S, AES.MODE_CTR, nonce=b'', initial_value=0).
   - Result: CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}
   - Thinking: the plaintext came out as the flag verbatim, so no further decoding was needed.

Key insight: AES-GCM nonce reuse breaks the authenticator, not just confidentiality: tags under one nonce share H and S, so a polynomial GCD over GF(2^128) recovers both without the AES key. Once S is known, anything keyed off that same per-nonce value falls too, here a second payload encrypted under E_K(J0).
Defensive takeaways: Treat a repeated GCM nonce under one key as a full loss of authenticity, since anyone holding H and S can compute valid tags. Enforce unique nonces in firmware, and never reuse an internal value such as E_K(J0) as a key for anything else.
Note: The challenge input files are not in this repo, so there is no reproduction capture.
