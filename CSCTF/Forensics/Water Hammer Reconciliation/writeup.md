Flag: CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}
Category: Forensics (Modbus/TCP capture reconciliation)
Tools used: Python (struct, hashlib, base64)
Brief: The evidence zip water-hammer-reconciliation.zip held reserve-header.pcapng, station-profile.txt and capture-manifest.txt. I had to reconstruct the complete confirmed Modbus/TCP control history of a fictional water-reserve header and submit the reconciliation identifier the profile defines. A write acknowledgement alone is not a confirmed snapshot, because the profile requires a matched FC3 readback.

Steps:

1. Start point: the handout's station-profile.txt
   - What I did: unzipped water-hammer-reconciliation.zip (reserve-header.pcapng, station-profile.txt, capture-manifest.txt) and read the profile before touching the capture.
   - What I found: scope is client 192.0.2.10:<ephemeral> -> 192.0.2.20:502, unit 17. Registers (0-based): 0x1000 pump target, 0x1001 gate permille, 0x1002 armed, 0x1003 ramp_us.
   - What I found: a candidate is an FC16 request with start >= 0x1000, quantity 1..4, correct MBAP length and byte count. It confirms only if all three hold:
     - it has exactly one normal, matching echo response
     - the very next client ADU is FC3 03 1000 0004
     - that FC3 has a unique normal 8-byte response
   - Thinking: the profile defines "confirmed" strictly, so the rule had to be coded exactly as written. It also says exactly 64 snapshots are expected, which gives me a way to check myself.

2. Pivot: reassemble the TCP stream
   - What I did: parsed the pcapng by hand (Enhanced Packet Blocks) and found one TCP connection (536 packets, 269 client-to-server, 267 server-to-client). I reassembled each direction by sequence number and de-duplicated retransmissions.
   - Thinking: the profile says TCP segment boundaries and timestamps do not matter, so framing Modbus per packet would create false events. Reassembly has to come first.
   - Result: 134 client ADUs and 133 server ADUs, all well-formed (protocol ID 0, Length = remaining bytes). Events are ordered by the capture position of the packet that completes each ADU.

3. Pivot: the confirmation rule leaves 64 snapshots
   - What I did: ran every FC16 request through the three-part rule.
   - What I found: three kinds of decoy fail it:
     - FC16 exception, transaction 57600 (0xE100): an exception never confirms
     - unanswered FC16 request, transaction 57601 (0xE101), the final write
     - plain FC3 reads outside a write-then-readback sequence
   - Thinking: each snapshot's registers (P, G, A, R) must come from the FC3 readback, not the write, since only the readback shows what the controller held. The report's tid is the FC16 response's transaction ID, not the FC3's.
   - Result: 64 snapshots remain, tids 0x2000 to 0x242F, matching the expected count.

4. Pivot: safety screen with exact integers
   - What I did: computed, per snapshot, in integer arithmetic:
     - E = floor(P*G/1000), V = floor(E*1e6/70686)
     - Q = 998*1065*|V - V_prev|, with V_-1 from the initial tuple (80,500,0,60000)
     - T_US = floor(2*20000*1e6/1065000) = 37558
     - UNSAFE = 1 iff A=1 and R < T_US and Q > 9000*100000
   - Thinking: the identifier is a hash, so any arithmetic or formatting slip gives a wrong flag with no feedback. The profile publishes a synthetic test vector, so I checked my arithmetic and encoder against it first.
   - What I found: my code reproduces the test vector's Base32 IAO7QJHG2XIJQ5I2PR7OA6WYEEPRHF7OO6M6QOA exactly.
   - Result: unsafe mask M (bit 63 = row 0) is D3FC7C00A3060000.

5. Flag: build the report and hash it
   - What I did: built the canonical report R with LF endings and no final LF: header line water-hammer-reconciliation-v2, the initial tuple, n=64, 64 lines of the form i=..;tid=....;p=..;g=..;a=..;r=.., then unsafe-mask=D3FC7C00A3060000.
   - Thinking: the identifier is a hash of the exact bytes, so one stray newline would change the flag. That is why the encoder was validated on the test vector first.
   - Result: SHA-256(R) = 5ed614c21145f080d0a30043752cfa210f61a29903351dde2485f0da0564b8f3. Base32 (RFC 4648, no padding) of the first 24 bytes is the 39-character identifier, so the flag is CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}.

     ![solve.py output: 536 packets in one flow, 134 requests and 133 responses, the two decoy tids, 64 confirmed snapshots with first and last rows, the matching test vector, the unsafe mask and the flag](screenshots/01-modbus-reconstruction-and-testvector.png)

Key insight: Only an FC16 write whose echo is followed by a matching FC3 readback counts as confirmed state, so the exception and unanswered writes drop out and exactly 64 snapshots remain. An acknowledgement is not state, and reassembling TCP before framing Modbus keeps packet boundaries from creating false events.
Defensive takeaways: When reconstructing ICS history from captures, treat a write acknowledgement as a claim, not proof of state, and require a readback before reporting what a controller held. Log and alert on Modbus exception responses and unanswered writes, since they are exactly what an attacker or a flaky device leaves behind. Capture at the stream level and keep reassembly deterministic so evidence holds up in an incident review.
Reproduce: python -I solve.py reserve-header.pcapng
Note: the capture is only parsed, never replayed.
