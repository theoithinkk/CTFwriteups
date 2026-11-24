Flag: CSCTF{03_at_platform_two_6f57d7}
Category: Forensics (Android SQLite WAL recovery)
Tools used: xxd, Python (zlib, tarfile, sqlite3, struct), sqlite3
Challenge: Operation Dawn - The Medic's Phone (CSCTF 2026, Forensics, Medium, 270 pts, author: Terminal43)

Steps:
1. Start point: unpack the Android backup
   - What I did: looked at the handout, an Android backup file, with xxd. The header reads ANDROID BACKUP, version 5, compressed, encryption none.
   - What I did: skipped the four header lines, zlib-decompressed the rest and extracted the resulting tar.
   - What I found: three apps: org.unit43.courier (messages.db plus a messages.db-wal), org.unit43.fieldnotes and org.unit43.radioset.
   - Thinking: the challenge text says the medic's messaging app now shows only a notice where the message was, so the courier app's message store was the place to look, and the leftover -wal file next to it stood out most.

2. Pivot: decode the live message database
   - What I did: opened messages.db and found each row stores a protobuf blob. I wrote a small protobuf walker and inflated field 5, the message body, which is raw deflate.
   - What I found: message 14 (from signals) reads "This message was withdrawn by the sender and is no longer available.", the notice the challenge describes. The original text is not in the live database.
   - Thinking: withdrawing the message overwrote its row, but SQLite keeps page images in the write-ahead log, so the original might still be in messages.db-wal.

3. Flag: recover the original message from the WAL
   - What I did: parsed messages.db-wal frame by frame (a single 4096-byte frame holding page 4) and searched the page for protobuf field-5 values that inflate to ASCII.
   - What I found: the WAL page holds an earlier version of the messages, including the original message 14: "Movement order. Board the hospital train. Assignment follows: CSCTF{03_at_platform_two_6f57d7} Acknowledge on receipt and destroy this message."
   - What I found: the frame's commit field is 0, so it does not look like a committed transaction frame and SQLite would not apply it, which fits the live database showing only the notice.
   - Thinking: editing a row in the app does not scrub the log, so the assignment (annex entry 03, platform two) was still there, readable once inflated.
   - Result: CSCTF{03_at_platform_two_6f57d7}

Key insight: Withdrawing the message only rewrote the live SQLite row, while the write-ahead log still held an older page with the original deflated text. Parsing the WAL by hand and inflating the protobuf bodies brought it back.
Defensive takeaways: An app-level withdraw or delete does not scrub SQLite WAL files, and this Android backup was unencrypted (encryption none), so anyone holding the backup file could read the withdrawn order.
Note: there are no screenshots or solve.py for this one, because the challenge input files are not in this repo.
