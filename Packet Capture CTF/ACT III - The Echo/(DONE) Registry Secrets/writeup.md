Flag: PacketCapture{VOLATILE_MEMORY}
Category: Forensics (memory dump XOR decode)
Tools used: strings, Python

Steps:
1. Start point: node7_memdump.raw
   - What I found: a 2.7 KB dump ("MEMDUMP-SIM v2 :: Node-7 volatile capture :: 03:14:02 UTC") of random filler bytes with readable records in between: [PROC] entries (explorer.exe, svchost.exe,
     chrome.exe, update_helper.exe, cirt_agent.exe, winlogon.exe), ENV: lines, a NETSCAN section, and
     "CONFIG: MEM_XOR_SEED=90".
   - Thinking: the readable records between the filler are the evidence, so I matched the processes to the network section to find the one worth decoding.

2. Pivot: the suspicious process.
   - What I found: NETSCAN shows PID 6672 cirt_agent.exe, running from %LOCALAPPDATA%\Temp with "--sync", holding an
     ESTABLISHED connection to 185.220.101.7:4444. Port 4444 is the classic reverse-shell / Metasploit port.
   - What I found: its environment holds two blocks:
     - MEM_BLOCK_A=0a3b39313f2e193b2a2e2f283f210c15
     - MEM_BLOCK_B=161b0e13161f05171f1715080327
   - Thinking: a process running from a temp folder with an established connection to port 4444 is the one whose blocks matter.
   - Dead end: update_helper.exe also has MEM_BLOCK_A/B values, but it has no network connection and its blocks don't
     decode with the seed, so it is a decoy.

     ![Process list, environment blocks, NETSCAN and the XOR seed](screenshots/01_memdump_records.png)

3. Decode: XOR both blocks with 0x5A
   - Thinking: the config line hands over the key. MEM_XOR_SEED=90 is decimal 90 = 0x5A.
   - What I did: hex-decoded A + B and XORed every byte with 0x5A.
   - Result: block A = "PacketCapture{VO", block B = "LATILE_MEMORY}", joined = PacketCapture{VOLATILE_MEMORY}.

     ![cirt_agent.exe blocks XORed with 0x5A](screenshots/02_xor_blocks.png)

Key insight: The flag was split across two hex blocks in cirt_agent.exe's environment and XORed with MEM_XOR_SEED=90 (0x5A) from the dump's config line. Tie the process list to network activity first: the process talking to a known-bad port is the one whose
data matters. Read "90" as decimal (0x5A), not hex.
