Flag: CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}
Category: Forensics (audio FSK decoding)
Target: tone-burst.wav (8 kHz, mono, 16-bit, 73600 samples = 9.2 s)
Tools used: Python (wave, numpy, matplotlib)

Note: this was uploaded by mistake while solving the LED-photodiode challenge (the correct file there was
telltale.wav, see "(DONE) telltale"). It still decodes to a valid CSCTF{...} flag, so it is written up here.
It is NOT the file the berth-allocation / LED description refers to: this one is 8 kHz audio, not a 48 kHz
photodiode capture.

Steps:
1. Recon.
   - FFT shows exactly two strong tones, 1000 Hz and 2000 Hz. Two tones plus bursts of signal in time means
     binary FSK.
   - Screenshot 01.

2. Found the framing.
   - Signal starts at sample 1921 (~0.24 s). Alternating tone changes every 20 ms (160 samples), i.e.
     50 baud. Screenshot 03 (spectrogram) shows the 1 kHz / 2 kHz alternation.

3. Demodulated.
   - For each 160-sample window compare the energy at 2000 Hz vs 1000 Hz (a single-bin DFT per tone).
     2 kHz = 1, 1 kHz = 0.
   - Bit stream starts with 32 bits of 10101010 (clock-sync preamble), then the frame flag 01111110 (0x7E),
     then the payload.

4. Decoded.
   - Reading the payload after 0x7E as 8-bit ASCII, MSB first:
     CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}
   - Screenshot 04.

Reproduce: python3 solve.py tone-burst.wav

Key insight: A repeating preamble plus an HDLC-style 0x7E flag tells you the frame boundary. Always look for
the sync pattern before trying to guess byte alignment.

Screenshots: screenshots/01_waveform_spectrum.png, 03_spectrogram.png, 04_decode.png
