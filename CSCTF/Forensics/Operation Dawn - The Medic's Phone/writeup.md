Challenge: Operation Dawn - The Medic's Phone, Forensics / Medium / 270 pts / author: Terminal43 (CSCTF 2026)
Flag: CSCTF{03_at_platform_two_6f57d7}
Category: Forensics (Android SQLite WAL recovery)
Tools used: xxd, Python (zlib, tarfile, sqlite3, struct), sqlite3

Steps:
1. Start point: unpack the Android backup
   - What I did / What I found: xxd showed ANDROID BACKUP / version 5 / compressed / encryption none. Skipped the four header lines, ran zlib decompress on the remainder, and extracted the resulting tar.
   - Result: Three apps in the backup: org.unit43.courier (messages.db plus a messages.db-wal), org.unit43.fieldnotes and org.unit43.radioset.
   - Thinking: The brief says the app now shows only a notice, so the courier app's message store is the place to look. The leftover -wal file next to it is the most interesting item.

_(No reproduction capture: the challenge input files are not in this repo.)_

2. Pivot: decode the live message database
   - What I did / What I found: Opened messages.db. Each row stores a protobuf blob; field 5 is the message body, compressed with raw deflate. Wrote a small protobuf walker and inflated every body.
   - Result: Message 14 (from signals) reads: "This message was withdrawn by the sender and is no longer available." This is the notice the brief describes. The original text is not in the live database.
   - Thinking: Withdrawing a message overwrote the row. SQLite keeps older page images in the write-ahead log, so the original may still be in messages.db-wal.


3. Pivot: recover the original message from the WAL
   - What I did / What I found: Parsed messages.db-wal frame by frame (one 4096-byte page, page 4) and searched the page for protobuf field-5 values that inflate to ASCII.
   - Result: The WAL page holds the earlier version of the messages, including the original message 14: "Movement order. Board the hospital train. Assignment follows: CSCTF{03_at_platform_two_6f57d7} Acknowledge on receipt and destroy this message." The frame appears not to be a committed transaction frame (commit field is 0), so SQLite would not apply it, which is why the live database shows only the notice.
   - Thinking: Deleting or editing a row in an app does not scrub the log. The assignment (annex entry 03, platform two) was still sitting in the log, readable once decompressed.


Key insight: The app-level withdrawal only changed the live row. The SQLite write-ahead log kept an older copy of the page, so the withdrawn message survived in the backup and could be recovered by parsing the WAL and inflating the message bodies.
