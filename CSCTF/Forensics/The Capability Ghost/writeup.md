Challenge: The Capability Ghost, Forensics / Easy / 120 pts / author: Mohamed Amine Mzoughi (CSCTF 2026)
Flag: CSCTF{fg6_x7i9b6b3nn_bj7sj}
Category: Forensics (PAX xattrs and journal triage)
Tools used: Python 3 (stdlib tarfile/zipfile/hmac/hashlib), binary string triage, solve.py

Brief: a build runner for rail-signalling software was tampered with. Responders kept the runner's filesystem archive
(with stored xattrs) and its systemd journal. Recover the sealed recovery marker, reading the records as data only -
do not run the binaries or restore capabilities.

Steps:
1. Start point: unzip the handout and read the records as data.
   - What I found: capability-ghost.zip holds runner-fs.tar.gz, runner.journal and a manifest. The tar carries PAX
     extended attributes. /root/.bash_history is the whole story in miniature:
         setcap cap_dac_read_search+ep /usr/local/bin/hc-probe
         TAG=$(head -c8 /dev/urandom | xxd -p)
         setfattr -n user.build_seal -v "0x$TAG" /usr/local/bin/hc-probe
         EPOCH=$(date +%s)
         /usr/local/bin/hc-probe --seal "$TAG" "$EPOCH" /etc/solunet/signaling-cfg /etc/solunet/signaling-cfg.sealed
         shred -u /etc/solunet/signaling-cfg
   - Thinking: the plaintext config was shredded, so the marker only survives inside signaling-cfg.sealed (27 bytes).
     To unseal it I need the TAG, the EPOCH, and hc-probe's sealing algorithm. The "capability" theme (CAP_DAC_READ_
     SEARCH on hc-probe) is a decoy about how the file was read; the real key material is the TAG xattr and the EPOCH.

2. Pivot: read the stored xattrs straight from the tar's PAX headers (no extraction, no root).
   - What I found: on /usr/local/bin/hc-probe, PAX record SCHILY.xattr.user.build_seal = 8 raw bytes 509df6cd8e103fa5.
     That is the TAG (the history wrote it as "0x$TAG"). The security.capability xattrs are present but are not key
     material.

3. Pivot: get the EPOCH from the journal.
   - What I found: scanning runner.journal (a real systemd journal; readable as data) the hc-probe event carries a
     custom field X_SEAL_EPOCH=1793294042, with MESSAGE "health probe sealed result written". The brief warns this is
     the seal epoch, not the entry's own timestamp, so I take X_SEAL_EPOCH exactly.

4. Pivot: recover the sealing algorithm from hc-probe itself (static only).
   - What I did: carved hc-probe out of the tar and read its strings. The binary documents its own cipher in its help
     text: "key = HMAC-SHA256(key = raw_bytes(tag_hex), msg = ascii_decimal_string(seal_epoch))" and
     "out[i] = in[i] XOR key[i mod 32]" (and notes --seal and --unseal are the same XOR operation). So I never run it.
   - Result: key = HMAC-SHA256(key = bytes.fromhex(TAG), msg = b"1793294042"); XOR that 32-byte keystream, repeating,
     over the 27 sealed bytes. Plaintext is the marker.

Flag: CSCTF{fg6_x7i9b6b3nn_bj7sj}

Reproduce: python3 solve.py capability-ghost.zip
Key insight: The marker's key was hiding in plain metadata, the TAG in a PAX user xattr and the EPOCH in a journal field, and the cipher was spelled out in the binary's own --help, so the whole thing unseals statically without root.

Defensive takeaways: Extended attributes and journal custom fields travel with archives and images, so treat them as evidence and, defensively, as a place secrets leak: a shredded plaintext was still recoverable because its key lived in xattrs and logs. Deriving a seal key from a short tag plus a timestamp, both recorded alongside the ciphertext, is not protection. Keys belong in a KMS or HSM, not in file metadata and logs next to the data they protect.

Note: the screenshot is a live re-run of solve.py against the challenge's own capability-ghost.zip; it reproduces the
documented flag.
