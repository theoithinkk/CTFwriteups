Flag: CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}
Category: Crypto (PRNG state recovery / backward prediction)
Target: key-unit-journal.cbor (7,037 bytes, SHA-256 bb14ef0ef3b6c21080a1eef9d34b1a38da4c8407e1dc0dcb29312fb639b2c159)
Tools used: Python 3 (hand-written CBOR decoder, hashlib, struct)

Challenge: A seized "Ash Army key unit" journal holds several sealed dispatches from Rovenqara's resupply
traffic. The standing order was sent before the recorded output window, so its key is not in the file.
Recover that standing order. (Fictional scenario; the CBOR is the author's artifact.)

Steps:
1. Recon.
   - Hash matches the one given. The top-level CBOR map has: device, scheme, window_opens_tx = 156,
     register (1248 x uint32) and traffic (5 sealed messages: tx 155 "standing order", tx 156/157/158/161
     "field dispatch").
   - scheme: TX t uses register outputs [8t, 8t+8); key = concat uint32be(word);
     keystream = concat SHA-256(key || uint32be(i)) for i = 0,1,...; plain = ciphertext ^ keystream.
   - 1248 words = 156 x 8, so the register covers tx 156 onward (window_opens_tx = 156). The tx 155 key
     would be the 8 outputs immediately BEFORE the first recorded word.
   (screenshots/01-cbor-structure.png)

2. Identified the generator.
   - 1248 = 2 x 624, which suggests MT19937. Untempered the first 624 outputs to rebuild the state, applied
     one twist, tempered the result, and it matched outputs 624..1247 exactly. The register is a plain
     Mersenne Twister output stream.
   (screenshots/02-mt19937-identified.png)

3. Turned the key wheel back.
   - Sanity check: tx 156 decrypts with reg[0:8] to a cover message that says the standing order "went out
     one cycle before this journal's window opens; its key is not in this register. turn the key wheel
     back". This confirms both the scheme and the plan.
   - Inverted the MT twist to recover the previous 624-word block P. In-place twist gives
     new[i] = X ^ (y >> 1) ^ (y & 1 ? 0x9908b0df : 0) with X = new[i-227] for i >= 227. So for
     i = 623..227, new[i] ^ new[i-227] reveals y_i, i.e. the top bit of P[i] and the low 31 bits of
     P[i+1]. That fully recovers P[397..623], which includes P[616..623].
   - Tempering P[616..623] gives the 8 outputs just before the window:
     37ea0460 e9b9d7fc 8b1c2a45 4f33e6f3 e7f2f198 313cf5d5 e8f0c5ec 480a2ab1
   (screenshots/03-key-wheel-turned-back.png)

4. Decrypted the standing order.
   - Key = those 8 words as uint32be, keystream = SHA-256(key || counter), XOR with the tx 155 ciphertext:
     CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}
   (screenshots/04-decrypt-flag.png)

Reproduce: `python3 solve.py key-unit-journal.cbor` (no third-party packages; prints each stage above).

Key insight: MT19937 is invertible. Any 624 consecutive outputs reveal the whole state, and the twist can be
run backward as easily as forward, so "earlier" keys are as exposed as "later" ones. Deriving key material
directly from a non-cryptographic PRNG breaks forward AND backward secrecy. Use a CSPRNG/KDF with
independent per-message keys, e.g. HKDF from a secret with a per-message nonce.

Screenshots:
Real Windows Terminal captures of solve.py run on key-unit-journal.cbor, one per stage (output sliced with Select-Object).
