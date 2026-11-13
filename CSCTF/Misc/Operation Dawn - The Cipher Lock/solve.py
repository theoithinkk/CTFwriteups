#!/usr/bin/env python3
"""
Operation Dawn: The Cipher Lock  (CSCTF 2026, Misc / Hard, by Terminal43)

Correlation Power Analysis (CPA) against a constructed power-trace corpus.

The cipher lock checks an entered pass-code against a stored code one byte at a
time, computing  sbox[entered_byte XOR stored_byte]  per position. Its power
draw leaks the Hamming weight of that S-box output. With 1500 traces taken
under known entered codes, a textbook CPA recovers every stored byte.

Usage:  python -I solve.py path/to/traces.npz
"""
import sys
import numpy as np

HW = np.array([bin(b).count("1") for b in range(256)], dtype=np.float64)  # Hamming weight LUT


def cpa(npz_path):
    # allow_pickle=False: a .npz can smuggle pickled objects that execute code on load.
    data = np.load(npz_path, allow_pickle=False)
    traces = data["traces"].astype(np.float64)   # (n_traces, n_samples)
    pts    = data["plaintexts"]                   # (n_traces, n_bytes) entered codes
    sbox   = data["sbox"].astype(np.int64)        # (256,)
    assert sbox[0] == 0x63, "not a standard AES S-box"

    n_traces, n_samples = traces.shape
    n_bytes = pts.shape[1]
    print(f"[*] {n_traces} traces x {n_samples} samples, {n_bytes} code bytes")

    # Pre-centre the traces once (CPA = Pearson r between a model column and each sample column).
    T = traces - traces.mean(axis=0, keepdims=True)
    T_ss = np.sqrt((T * T).sum(axis=0))           # per-sample norm

    recovered = bytearray(n_bytes)
    for pos in range(n_bytes):
        pt = pts[:, pos].astype(np.int64)
        best_guess, best_corr = 0, -1.0
        for guess in range(256):
            model = HW[sbox[pt ^ guess]]          # predicted leakage for this stored byte
            m = model - model.mean()
            m_ss = np.sqrt((m * m).sum())
            if m_ss == 0:
                continue
            corr = np.abs((m[:, None] * T).sum(axis=0) / (m_ss * T_ss))  # |r| at every sample
            peak = corr.max()
            if peak > best_corr:
                best_corr, best_guess = peak, guess
        recovered[pos] = best_guess
        print(f"    byte {pos:2d}: 0x{best_guess:02x} '{chr(best_guess) if 32<=best_guess<127 else '.'}'  r={best_corr:.3f}")

    flag = bytes(recovered)
    print("\n[+] Stored code:", flag.decode("latin-1"))
    return flag


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -I solve.py path/to/traces.npz")
    cpa(sys.argv[1])
# Flag: CSCTF{12_the_depot_is_unguarded_at_noon_7d3e90}
