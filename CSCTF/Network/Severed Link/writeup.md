Challenge: Severed Link - Network / Easy / 120 pts / author: Teodor Giurgica (CSCTF 2026)
Flag: CSCTF{DI6e585qT6CTnVa0M8eIhppD}
Category: Network (MAVLink 2 signing key leak)
Tools used: pymavlink, Python (stdlib: socket, hashlib), solve.py

Brief: A reconnaissance drone takes orders from its field station over a signed MAVLink 2 link, and mid-mission the operator rotated the signing key and pushed the new key over that same link while it was recorded. I had the recording (mission.tlog and mission.pcap) and the operator's notes (ops_notes.txt), and had to show an outsider can take the operator's place on the live uplink at w03.ctf.chronos-security.ro:34100 (raw MAVLink over TCP).

Steps:
1. Start point: read the notes and the recording
   - What I found: ops_notes.txt says MAVLink 2 per-frame signing is on, the operator station is sysid 255 and the drone is sysid 1. The signing key was rotated mid-mission, and the rotation was pushed in band over the same console link instead of the out-of-band provisioning channel it should have used, over a link that was being captured. The station is still online with the same config.
   - Thinking: signing appends a 13-byte block per frame (link_id 1 byte, timestamp 6 bytes in 10 us units since 2015-01-01, signature 6 bytes), and sig6 = SHA-256(secret_key(32) || frame bytes through CRC || link_id || timestamp)[:6]. So authenticity rests entirely on the key staying secret. A key pushed in band is a SETUP_SIGNING message (msgid 256), whose payload carries the 32-byte secret key in cleartext, so anyone holding the capture holds the key.
   - Result: the thing to find is the SETUP_SIGNING message in the recording.

2. Pivot: recover the key from the capture
   - What I did: parsed mission.tlog with pymavlink. The message mix was HEARTBEAT, GPS and position telemetry, 3 COMMAND_LONG, 1 COMMAND_INT, and exactly one SETUP_SIGNING (sys 255 to target 1).
   - Result: secret_key = 8f2b4e71a6c3d05f9217bc84e63a1d57f0482c6b9e13a7d5c84f26019bd3ea60. Frames before SETUP_SIGNING used the old key, and frames after it use this new key, which the live gateway now enforces.

3. Pivot: verify the key and signing math against the capture
   - What I did: took the last signed COMMAND_LONG after the rotation (link_id 0, timestamp 1445) and recomputed its signature with the recovered key.
   - Thinking: checking offline avoids burning attempts on the live server with a wrong key.
   - Result: the computed signature e9daeb05837c equals the captured one, so the key and algorithm are confirmed. The offline part of solve.py prints the key and "signature check vs capture: True". Run later, the live step fails with a connection refused error because the server is gone.

4. Pivot: probe the live gateway and let it state its own policy
   - What I did: connected over TCP and sent a signed command. The gateway replies with STATUSTEXT messages that coach the attack: "DENIED: frame is not authenticated under the link key", then "SB-7 uplink gateway online. Authenticate as operator: signed COMMAND_INT DO_REPOSITION from sysid 255 under the fleet link key. Replayed frames are refused, the signing timestamp must be current", and "REJECTED: send a HEARTBEAT first".
   - Dead end: reusing the capture's tiny timestamps (about 1445) fails, because they are treated as replays.
   - Thinking: that gives two rules, the signing timestamp must be current, and a signed HEARTBEAT must bring the link up before a command.
   - Result: a clear recipe for a valid session.

5. Exploit: impersonate the operator
   - What I did: used source identity sysid 255 and compid 190 (same as the operator station), the recovered key, link_id 0, and a timestamp equal to the real current time in 10 us units since 2015, kept strictly monotonic across frames. Sent a signed HEARTBEAT, then a signed COMMAND_INT DO_REPOSITION (command 192) echoing the operator's own parameters from the capture.
   - Result: the gateway answered "OPERATOR AUTHENTICATED. Reposition accepted." and "Audit receipt: CSCTF{DI6e585qT6CTnVa0M8eIhppD}". Reproduction needs the live challenge server, which is now unavailable.

Key insight: Signing only buys authenticity while the key is secret, and the operator distributed the new key over the very channel it protects, where it was recorded. Capturing the key beats breaking the crypto, since no cryptographic weakness is needed, just the leaked 32 bytes. The gateway's replay protection (monotonic, current timestamps) and heartbeat-first handshake work correctly and are irrelevant once the key is in the attacker's hands, because they just sign fresh frames like the real operator.

Defensive takeaways: Key distribution is the whole game, so rotate and provision signing keys strictly out of band (a separate provisioning channel, physical loading, or an authenticated key exchange), never in cleartext over the link the key secures and never over a link that might be recorded, which should always be assumed. A SETUP_SIGNING capability that travels over the data link is a single point of total compromise, so gate it behind something a recording cannot reveal or remove in-band key transport entirely. Treat every recorded mission link as burned key material until the key is retired everywhere, and remember that timestamp and replay controls stop replay but not forgery, so pair signing with key secrecy and anomaly detection on the uplink (new sources, unexpected reposition commands) to flag a fresh but hostile operator session.

Reproduce: python solve.py w03.ctf.chronos-security.ro 34100 parses mission.tlog beside the script for the SETUP_SIGNING key, verifies it against a captured signature, then opens the live link and sends a signed HEARTBEAT and COMMAND_INT DO_REPOSITION with a current, monotonic timestamp, and prints the audit receipt. It requires pymavlink.
