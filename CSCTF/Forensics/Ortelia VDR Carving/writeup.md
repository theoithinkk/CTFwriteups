Flag: CSCTF{flotsam_0e91019a8e70267f550895930247d088}
Category: Forensics (fragmented PNG carving)
Target: recorder-sectors.img (35,840 bytes, 70 x 512-byte sectors, raw chip-off flash dump, no filesystem)
Tools used: Python (re, struct, zlib, PIL), xxd-style hex inspection

Challenge: The voyage data recorder from MV Ortelia was read chip-off, so the allocation tables are gone.
Somewhere in the dump is a PNG chart frame showing the vessel's last fix, with a recovery key printed on it.
Hint: "A file that opens is not the same as a file that is whole."

Steps:
1. Recon.
   - Walked the image in 512-byte sectors. Sectors 0-2 and 48-51 are NMEA text ($GPRMC lines), sectors
     22-33 start with a JPEG header (FF D8 FF E0, JFIF), sector 52 starts with the PNG magic, and sectors 21,
     34, 42-43 and 68-69 are all zeros. The rest is high-entropy data.
   - Searching for magics: PNG header at 0x6800 (sector 52), but the only IEND is at 0x5E97 (sector 47),
     i.e. BEFORE the header. That alone says the PNG is fragmented. The JPEG is a decoy.
   (screenshots/01_magics_and_fragmentation.png, screenshots/02_sector_map.png)

2. Naive carve (the trap).
   - Cutting from the PNG header to the end of the dump (sectors 52-67, 16 sectors of data, then zeros)
     gives a file that opens: 760x520 with a viewer that tolerates truncation. But the bottom is black and the
     recovery key is missing. This is the "opens but is not whole" case.
   - Parsing the chunks showed IHDR (13 bytes) followed by ONE IDAT of 22,630 bytes. The PNG needs
     8 + 25 + 22,642 + 12 = 22,687 bytes = 45 sectors, but only 16 sit after the header. 29 sectors are elsewhere.
   (screenshots/03_naive_carve.png)

3. Rebuild the fragment chain.
   - Counting the non-zero, non-text, non-JPEG runs gives exactly 29 sectors: A = 3-20 (18), B = 35-41 (7),
     C = 44-47 (4, ends with the IEND chunk). The zero sectors are the gaps between fragments.
   - Head (52-67) followed by A, B, C in some order. Because the IDAT chunk has a CRC32, the order can be
     checked: head+A+B+C gives a matching CRC32 over IDAT+data, head+B+A+C does not.
   - Trimmed to 22,687 bytes (the IEND trailer ends mid-sector 47, 159 bytes in).
   (screenshots/03b_crc_check.png)

4. Read the key.
   - Opened the reassembled PNG: "VDR CHART FRAME - RECOVERED", a track with a LAST FIX marker, and the
     footer line "RECOVERY KEY (transcribe exactly)": CSCTF{flotsam_0e91019a8e70267f550895930247d088}
   (screenshots/04_recovered_chart_frame.png)

Reproduce: python3 solve.py recorder-sectors.img (tries both fragment orders, keeps the one whose IDAT CRC
matches, writes recovered_chart_frame.png).

Key insight: Header and footer carving fails on fragmented files. When the flash is read raw, a file's sectors
can be scattered, so "header to next IEND" or "header to end of data" gives a truncated or wrong file.
Use the format's own integrity data (PNG chunk lengths and CRC32) to confirm reassembly, and count how many
sectors the file should occupy to know how much is missing. The sector 21/34/42/43 zero gaps were the clue that
the file was split.

Screenshots:
  screenshots/01_magics_and_fragmentation.png  - magic/IEND offsets (python find_magics.py recorder-sectors.img)
  screenshots/02_sector_map.png                - sector layout and fragment colours
  screenshots/03_naive_carve.png               - truncated carve, key missing
  screenshots/03b_crc_check.png                - CRC verification
  screenshots/04_recovered_chart_frame.png     - complete frame with the recovery key
