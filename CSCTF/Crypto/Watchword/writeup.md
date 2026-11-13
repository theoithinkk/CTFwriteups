Challenge: Watchword — Crypto / Medium / 270 pts / author: Michalina Moszyńska (CSCTF 2026)
Flag: CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}
Category: Cryptography (AES-GCM nonce reuse / "Forbidden Attack")
Tools used: Python 3 (custom GF(2^128) arithmetic), pycryptodome (AES-CTR decrypt)

Steps:

1. Start point: handout `watchword.zip`
   - What I did / What I found: Unzipped the handout and read `README.txt` and
     `intercepts.json`. The README stated a SABRELINK unit reused one AES-128-GCM nonce
     across a run of dispatches due to a firmware fault, and that a "sealed master order"
     was encrypted separately with AES-128-CTR (IV = all-zero) under the link's per-nonce
     tag mask `E_K(J0)` — the same GCM internal value that produces a valid auth tag.
     `intercepts.json` held three authenticated dispatches (ciphertext + 16-byte GCM tag,
     all under the one reused nonce, empty AAD) plus the sealed master order ciphertext.
   - Result: Identified this as a classic GCM nonce-reuse ("forbidden attack") scenario —
     reused nonce means a fixed, unknown GHASH key `H` and fixed tag mask `S = E_K(J0)`
     across all three messages.
   - Thinking: With `H` and `S` unknown but constant, and all three (ciphertext, tag) pairs
     visible, the standard approach is to eliminate `S` by XORing pairs of tag equations,
     leaving polynomial equations in `H` alone that can be solved algebraically.

2. Pivot: build the algebra
   - What I did / What I found: Each ciphertext was ≤16 bytes (one GHASH block + one
     length block), so `GHASH_H(C) = C·H² ⊕ L·H`, giving `tag = C·H² ⊕ L·H ⊕ S`. XORing
     two such equations cancels `S` and leaves a quadratic in `H` with known coefficients.
     With three dispatches I built two independent quadratics (dispatch 1 vs 2, and 1 vs 3).
   - Result: The true `H` is a common root of both quadratics, i.e. the GCD of the two
     polynomials over GF(2^128).
   - Thinking: Rather than solving each quadratic separately (messy in characteristic 2),
     computing the polynomial GCD directly isolates the shared linear factor `(x ⊕ H)`.

3. Pivot: implement GF(2^128) field arithmetic + polynomial GCD
   - What I did / What I found: Implemented GHASH-style `gmul` (bit-reflected GF(2^128)
     multiplication with reduction polynomial `0xE1000...0`), field inversion via
     exponentiation, and polynomial long division / Euclidean GCD over that field. First
     run hung indefinitely — tracing it down, `gpow()`'s accumulator was seeded with the
     integer `1`, but in GCM's bit-reflected convention the multiplicative identity is
     `1 << 127`, not `1`. That made every computed "inverse" wrong, so polynomial
     division never reduced the remainder's degree and looped forever.
   - Result: Fixed the identity element (`GF_ONE = 1 << 127`), verified `gmul(a, GF_ONE)
     == a` and `gmul(a, ginv(a)) == GF_ONE` held for random field elements, then reran.
   - Thinking: Field-level correctness bugs are the thing to suspect first when a provably
     finite algorithm (GCD on degree-≤2 polynomials) doesn't terminate — the shape of the
     bug (infinite loop, not a crash) pointed straight at "remainder isn't actually
     shrinking," i.e. the division arithmetic itself.

4. Pivot: solve for H and S
   - What I did / What I found: Ran the fixed solver — the GCD of the two quadratics came
     back degree 1, giving `H = 0x730426f0d054fc7539d26145168be28a` directly from its root.
     Plugging `H` back into each dispatch's `tag = GHASH_H(C) ⊕ S` recovered
     `S = 0x66b18782c578d8b27ec249a6298dfeb2` from all three dispatches independently.
   - Result: All three dispatches agreed on the same `S`, which is the confirmation that
     `H` (and therefore `S`) was recovered correctly.
   - Thinking: Cross-checking `S` across every message is a free correctness proof — a
     wrong `H` would not reproduce a consistent tag mask across independent ciphertexts.

5. Pivot: decrypt the sealed master order
   - What I did / What I found: Per the README, the master order is AES-128-CTR encrypted
     (IV = all-zero) under `S` itself as the 16-byte key. Decrypted
     `sealed_master_order_ctr_hex` with `AES.new(S, AES.MODE_CTR, nonce=b'', initial_value=0)`.
   - Result: Plaintext recovered: `CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}`.
   - Thinking: The challenge collapses the "find the hidden key" step and the "flag" step
     into one — the recovered plaintext *is* the flag, so no further decoding was needed.

_(No reproduction capture: the challenge input files are not in this repo.)_

Key insight: Nonce reuse in AES-GCM doesn't just risk confidentiality (reused keystream) —
it breaks the authenticator entirely. Two or more (ciphertext, tag) pairs under one reused
nonce give enough algebraic structure (GHASH is linear in `H` once the AAD/ciphertext
blocks are fixed) to solve for both the GHASH subkey `H` and the per-message tag mask `S`
via polynomial GCD over GF(2^128), without ever touching the AES key itself. Once `S` is
known, anything "protected" by that same per-nonce value — here, a second payload
deliberately keyed off `E_K(J0)` — falls immediately.
