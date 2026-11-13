Challenge: Silent Orbit - Network / Easy / 120 pts / author: Cosmin Gorea (CSCTF 2026)
Flag: CSCTF{280069000107020800000000000000C0000000050000000600000013000000140000002300000024000000330000003400000044000000450000005300000054000000650000006600000077000000780000008A0000008B0000009A0000009B000000AB000000AC000000BB000000BC}
Category: Network (CCSDS and CFDP NAK reconstruction)
Tools used: unzip, sha256sum, xxd, Python 3 (struct), custom parser solve.py

Brief: silent-orbit-cfdp.zip holds a README, a mission profile and a raw recording (civil_downlink.bin). The relay was altered to suppress a recovery record, and I had to reconstruct the exact CFDP NAK PDU the normal relay would emit.

Steps:
1. Start point: silent-orbit-cfdp.zip
   - What I did: listed the archive (README.txt, mission-profile.txt, civil_downlink.bin, SHA256SUMS) and ran sha256sum -c SHA256SUMS. All three files verified OK. mission-profile.txt defines the filtering and state rules.
   - Thinking: the profile is effectively a spec for the normal relay, so the answer is whatever that state machine outputs. No guessing, just implement every rule exactly.
   - Result: task defined, replay the relay logic over civil_downlink.bin and serialize the NAK.

2. Pivot: split the raw recording into Space Packets and filter
   - What I did: the recording is raw concatenated CCSDS Space Packets (6-byte primary header, then packet-data-length + 1 user-data bytes). I walked it with struct.unpack('>HHH') and got 188 packets with no truncation. I kept only PVN 0, type 0 (telemetry), secondary-header flag 0, APID 0x321, sequence flags 11. The first packet (APID 0x012) is dropped by this filter.
   - Thinking: packet sequence counts are explicitly diagnostic only, so they must not be used to infer missing file bytes.
   - Result: candidate CFDP PDUs extracted from packet user data.

3. Pivot: isolate the target CFDP transaction
   - What I did: parsed each CFDP PDU header: version 001, direction toward receiver, acknowledged, no CRC, small-file, 1-byte entity and sequence IDs, and tuple source/seq/dest = 0x01/0x07/0x02. A decoy transaction (for example 0x03/0x09/0x02) shares APID 0x321 and is ignored.
   - Dead end: CFDP's data-field length excludes the 4-byte fixed header and the ID fields, so total PDU length is 7 + length. Using 4 + length silently rejects everything.
   - Thinking: anything before Metadata is permanently discarded, so ordering matters.
   - Result: the first valid Metadata (packet at offset 0x4B) gives file size 0xC0 = 192 bytes and moves the state machine from WAIT_METADATA to COLLECT.

4. Exploit: build coverage, snapshot at the first valid EOF, emit the NAK
   - What I did: in COLLECT, target File Data (seg-control 0, metadata flag 0) adds [offset, offset+len) if it fits within 192, and overlaps merge. The first accepted EOF (directive 0x04, no-error, null checksum, size 192) snapshots coverage. The complement over [0,192) is twelve 1-byte holes at 5, 19, 35, 51, 68, 83, 101, 119, 138, 154, 171, 187. The NAK PDU is header 28 (ver 001, directive, toward sender, acknowledged), length 0069, 00 01 07 02, directive 08, scope [0,192), then 12 start/end pairs, 112 bytes in total (declared length 0x69 + 7 = 112, verified).
   - Thinking: missing intervals must be maximal and ascending, and Metadata is never requested.
   - Result: python -I solve.py reports 188 packets, meta size 192, EOF accepted, the twelve holes, and prints the hex PDU wrapped as the flag above.

Key insight: The suppressed record is fully determined by the relay's published state machine. Strict adherence to the rules (APID and flag filtering, tuple match, Metadata before data, snapshot at the first valid EOF, and the CFDP header-length convention) yields the exact NAK PDU, and the decoy transaction and out-of-state PDUs are what make a naive parser get it wrong.

Defensive takeaways: A relay that silently drops recovery records breaks the reliability guarantee of the file transfer without any visible error, so integrity monitoring should compare what a reference implementation would emit against what the relay actually sent. Publishing the state machine in a mission profile is good for auditability, and it also lets an independent party verify the relay's behaviour from a recording.
