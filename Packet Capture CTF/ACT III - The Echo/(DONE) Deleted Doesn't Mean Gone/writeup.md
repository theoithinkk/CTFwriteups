Flag: PacketCapture{RECOVERED_DOCUMENT}
Category: Forensics (disk file carving)
Tools used: strings, Python (zipfile)

Steps:
1. Start point: evidence.dd (17 KB disk image).
   - What I found: almost all high-entropy noise with no filesystem structure, which is what a wiped or damaged
     volume looks like.
   - Thinking: when the filesystem is gone, ignore it and carve by file signature.

2. Pivot: carving for signatures.
   - What I did: searched the raw bytes for common magic numbers.
   - Result: a ZIP local file header (PK\x03\x04) at offset 12800 (0x3200). Its central directory and end record
     (PK\x01\x02 / PK\x05\x06) are intact right after, so the archive is complete. It holds one file: confidential_report.txt (484 bytes, deflate).
   - Thinking: with no filesystem left, the signatures are the only landmarks, and an intact central directory and end record mean the whole archive can be read.

     ![Signature scan: a complete ZIP at offset 12800](screenshots/01_signature_carve.png)

3. Decode: extract the ZIP at offset 12800
   - What I did: opened the ZIP from that offset with Python's zipfile and read the file.
   - Thinking: the carved ZIP is the only structured data in the image, so opening it from that offset is the direct way to read it.
   - Result: "CLASSIFIED - INTERNAL INCIDENT REPORT, Case Ref: CIRT-2291-ECHO". The report says the Node-7 backup
     array was wiped at 03:14 UTC, but remnants "survived in unallocated space". The last line is
     FLAG: PacketCapture{RECOVERED_DOCUMENT}

     ![Extracted confidential_report.txt with the flag](screenshots/02_recovered_report.png)

Key insight: Wiping the file table doesn't erase the data: carving by the PK signature found an intact ZIP at offset 12800 of the image. Signature-based carving (PK, %PDF, JPEG FFD8,
etc.) finds intact files in unallocated space without any filesystem metadata.
