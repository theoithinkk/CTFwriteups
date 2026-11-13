import wave, sys, numpy as np
from scipy.signal import butter, filtfilt
w = wave.open(sys.argv[1] if len(sys.argv) > 1 else 'telltale.wav')
fs = w.getframerate()
x = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(float)
b, a = butter(2, 100/(fs/2), 'high'); y = filtfilt(b, a, x)      # drop ambient/drift
on = np.where(np.abs(y) > 3000)[0]; s, t = on[0], on[-1]          # burst extent
z = y[s:t+1]; sg = (z > 0).astype(int)
st = np.where(np.diff(sg) != 0)[0][0] + 1                          # first edge
HB = fs // 2000                                                    # 24 samples = 0.5 ms half-bit
n = (t - st) // HB
h = ''.join(str(sg[min(st + i*HB + HB//2, len(sg)-1)]) for i in range(n))
for off, inv in [(o, v) for o in (0, 1) for v in (0, 1)]:           # try both half-bit phases and polarities
    hi, lo = ('01', '10') if inv else ('10', '01')                   # Manchester pair -> bit
    bits = ''.join('1' if h[i:i+2] == hi else '0' if h[i:i+2] == lo else 'X'
                   for i in range(off, len(h)-1, 2))
    for sh in range(8):
        bs = bits[sh:]
        txt = ''.join(chr(int(bs[k:k+8], 2)) if 'X' not in bs[k:k+8] and 32 <= int(bs[k:k+8], 2) < 127 else '.'
                      for k in range(0, len(bs)-7, 8))
        if 'CSCTF{' in txt:
            print(f'half-bit offset={off} inverted={inv} bit shift={sh}'); print(txt[txt.find('CSCTF{'):txt.find('}')+1])
