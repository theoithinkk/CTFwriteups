import wave, sys, numpy as np
w = wave.open(sys.argv[1] if len(sys.argv) > 1 else 'tone-burst.wav')
fs = w.getframerate()
x = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(float)
on = np.where(np.abs(x) > 3000)[0]; s = on[0]
n = fs // 50                                                       # 20 ms symbols (50 baud)
t = np.arange(n)
def mag(seg, f): return abs((seg * np.exp(-2j*np.pi*f*t/fs)).sum())
bits = ''
for i in range((on[-1] - s) // n + 1):
    seg = x[s + i*n: s + (i+1)*n]
    if len(seg) < n: break
    bits += '1' if mag(seg, 2000) > mag(seg, 1000) else '0'        # 2 kHz = 1, 1 kHz = 0
print('bits:', bits)
i = bits.find('01111110')                                          # 0x7E frame flag after preamble
by = [bits[k:k+8] for k in range(i+8, len(bits)-7, 8)]
print(''.join(chr(int(q, 2)) for q in by))
