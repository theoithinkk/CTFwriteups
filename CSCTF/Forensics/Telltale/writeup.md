Flag: CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}
Category: Forensics (optical LED covert channel)
Target: telltale.wav (48 kHz, mono, 16-bit, 46656 samples = 0.972 s)
Tools used: Python (wave, numpy, scipy, matplotlib)

Challenge: "The berth-allocation console sits in a secure room with no network of any kind. The watch
reported nothing unusual: the chassis status LED looks steadily lit. Someone clamped a photodiode over that
LED for just under a second and sampled it at 48 kHz." Anything switching faster than ~60 Hz blurs into steady
light, so the LED is the unwatched output. Recover what is being exfiltrated.

Steps:
1. Recon.
   - Capture is unipolar photodiode data (all samples positive, mean ~10400) on a slowly drifting baseline.
     The spectrum is dominated by 1-5 Hz drift and 50 Hz mains, i.e. ambient light, not data.
   - Spectrum also shows strong lines at 500 Hz and 750 Hz and odd harmonics (1500/2500 Hz), which hints at a
     square-wave source rather than sine tones.
   - Screenshot 01.

2. Isolated the burst.
   - A 100 Hz high-pass removes the drift and mains. A clean burst appears from ~0.25 s to ~0.73 s
     (~0.47 s, samples 11960-34690); outside it there is only noise.
   - Spectrogram (screenshot 02): a pure 500 Hz tone with odd harmonics first, then a spread of
     500-1250 Hz energy. That is what a bit stream looks like, not several tones.

3. Identified the line code.
   - Zero-crossing run lengths inside the burst are only ever 48 or 24 samples (1 ms or 0.5 ms at 48 kHz).
   - The first 64 runs are all 48 samples, a 500 Hz square wave. In Manchester coding, alternating bits
     1,0,1,0 give exactly this, so it is a 32-bit clock-sync preamble.
   - After that, runs of 24 and 48 samples mix, which is Manchester at 1000 bit/s (0.5 ms half-bits).
   - Screenshot 03: 03a is the preamble, 03b is payload with both run lengths.

4. Decoded.
   - Sampled the signal sign at the centre of every 24-sample half-bit, then paired half-bits
     (Manchester: one pair value is a 1, the other a 0).
   - The right alignment is the half-bit offset after the first edge (offset 1) with inverted polarity
     ("01" = 1, "10" = 0). Then, with a bit shift of 7, the bytes read as ASCII:
     CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}
   - The other three polarity/offset combinations give "X" (invalid Manchester pairs) or garbage, which is how
     I picked this one. Screenshot 04.

Reproduce: python3 solve.py telltale.wav (needs numpy and scipy).

Key insight: A steady-looking status LED is not a quiet output. Keying it at 1 kHz is invisible to the eye and
to anyone watching, but a photodiode sees it plainly. Mitigations: cover or remove status LEDs on air-gapped
machines, or drive them from a fixed low-pass or lit-state signal that firmware on the host cannot modulate.

Screenshots: screenshots/01_raw_and_burst.png, 02_spectrogram.png, 03_manchester_zoom.png, 04_decode.png
