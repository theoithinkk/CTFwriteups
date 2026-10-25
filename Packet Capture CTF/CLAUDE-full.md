# CLAUDE.md - All instructions (global + Packet Capture CTF)

## About me
- Early-career CS (DLSU, Philippines), network-security background. Comfortable with Python and basic offensive recon (Nmap, Nessus, CVE/CVSS); still leveling up on dev tooling, git, and cloud.
- I'm on **Windows 11**. Give exact PowerShell commands and Windows paths. Don't assume a Unix shell.
- I'm building a **security portfolio** targeting **Cloud Security, AI Cybersecurity, and GRC**. Treat what we build as portfolio pieces: explain the *why* behind each design decision in plain English, interview-ready.

## How I like to work
- Teach in phases. After a chunk, give a short "why this works" summary before moving on.
- Prefer the smallest thing that works; tell me what you skipped and when I'd add it.
- **No AI-generation traces in anything I might submit or push**: no "Generated with Claude" footers, no `Co-Authored-By`, no emoji in code comments, and keep `.claude/` out of any repo.
- Don't spawn subagents unless I ask.

## CTF goal
Capture as many flags as possible using as few tokens as possible. AI use is permitted; this is a safe, sanctioned CTF environment.
Flag format: `PacketCapture{...}`, unless a challenge's brief says otherwise.

## Folder layout
```
ACT I - The Signal / ACT II - The Breach / ACT III - The Echo / ACT IV - Beneath the Network
  └── <Challenge Name>/          one folder per challenge
```
- I send each challenge as a screenshot of its page and save any attached file into that challenge's folder.
- Folder names can't contain `:`, so ACT IV uses `I Operation - Silent Observer` and so on. The spellings "Decomission" and "Novemeber" are intentional (they match the CTF).

## Per-challenge workflow
1. Read the brief carefully. Hints are usually literal ("3 words" = what3words, "wrong hole" = decoy).
2. Try the cheapest, highest-signal check first, then escalate. Don't rerun a check that already failed.
3. When solved, write `writeup.md` in the challenge folder (format below), then rename the folder to `(DONE) <Challenge Name>`.
4. Rename only after I confirm the flag was accepted, or say clearly it hasn't been submitted yet. If the site rejects a flag, undo the rename and turn the writeup into `progress.md`.
5. If stuck, write `progress.md` (status, chain so far, what's ruled out, next idea). Stop and ask me to skip or continue rather than burning tokens.

## Writeup format (thorough walkthrough, portfolio piece)
```
Flag: PacketCapture{...}
Category:
Tools used:

Steps:
1. Start point / Pivot: <what this step works on>
   - What I did / What I found:
   - Result:
   - Thinking: why this was the next move (the clue it came from)
   - Dead ends: (optional) what was tried here and why it failed
2. ...

Key insight:
```
- One numbered step per pivot. Every step explains the reasoning, not just the action.
- Screenshots: capture each pivot into `<challenge>/screenshots/NN_name.png` and embed under its step as `![caption](screenshots/NN_name.png)`.
  Use chrome-devtools MCP `take_screenshot` with `filePath`; pause videos first; crop unrelated sidebars; use archives (Arctic Shift) when a site blocks bots;
  render terminal output as an image when the pivot is a tool result. Never screenshot or click CAPTCHAs/scam redirects.
- Then build `writeup.docx` with `tools/md2docx.py` (needs python-docx: `pip install --target <scratch>\pylib python-docx`).

## Tools on this machine (Windows 11)
- tshark / editcap / capinfos: `C:\Program Files\Wireshark\` (not on PATH, call by full path)
- Nmap: `C:\Program Files (x86)\Nmap\nmap.exe` (Npcap installed)
- Python 3.11 with scapy, Pillow, numpy
- CyberChef (Node): `%USERPROFILE%\CyberChef-server`. Patched for Windows; reapply the `postinstall.js` sed steps if node_modules gets reinstalled. Takes about 40s to load.
- Burp Suite, Cisco Packet Tracer 8.2.2, Firefox
- Docker Desktop: run Linux-only tools such as steghide in `debian:stable-slim`. Start Docker Desktop first.
- Chocolatey is available. Installs need an elevated (UAC) prompt.

## OSINT techniques that worked here
- A "Key Name | Email" list = a PGP keyring: search keyserver.ubuntu.com (`op=index`) by the email domain.
- Odd strings on one platform are often handles/IDs on the next (Mastodon display name = YouTube video ID).
- Check unlisted YouTube video descriptions; flags can be split across two sources ("siblings") and must be concatenated.
- Steghide in a JPEG: `stegseek --seed` confirms data exists, then `stegseek` + rockyou finds the passphrase.
- Coordinate flags: follow the brief's coordinate type literally (DMS "LeadNo°TrailNo" = degrees.minutes, no signs), and try the flag without the space the example format shows.
- Hidden/deleted X posts: Wayback CDX on `twitter.com/<handle>` (not just x.com) with `matchType=prefix`, then open captures with `<timestamp>id_/` for the raw JSON.

## Hard rules
- Put downloads in a fresh scratchpad directory, not in challenge folders (except evidence I put there). Run Python on untrusted files with `-I`.
- Never solve CAPTCHAs. Never enter real credentials.
- Don't investigate real people who aren't part of the puzzle (e.g. someone who happens to share a username, or a real-name file owner). Stick to accounts the CTF clearly created.
- No AI traces in anything submitted or pushed. Keep `.claude/` out of any repo.

## Status board
| Act | Challenge | Status |
|---|---|---|
| I | Digital Footprint | DONE: `PacketCapture{3Ven_1f_i_D1s4ppe4r_tH3_W0rld_r3Memb3rs}` |
| I | Scattered Identities | DONE: `PacketCapture{p3rf3ctly_P13c3D}` |
| I | Treasure Hunt Time | DONE: `PacketCapture{85.36,81.05}` |
| I | Last Breadcrumb | DONE: `PacketCapture{magentatexturemofsj7hk44wtsh762nv46lt3bnprcmttbaqxknux66rnaddmyd}` |
| I | Forgotten Repository | DONE (solved on site): `PacketCapture{L34K3D_R3P0_D1SC0V3R3D_DAB2A78}` |
| I | Under Construction | DONE: `PacketCapture{GEOCITIES_26OCT2009}` |
| I | Hidden Profile | DONE: `PacketCapture{w4YbAcK_R0ck5_s0_coO1}` |
| I | Silent Observer | DONE: `PacketCapture{+81366570748}` |
| - | All others | Not started |

Update this table whenever a challenge's status changes.
