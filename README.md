# CTF Writeups

Writeups for the CTFs I've played. Each one walks through how I got the flag, step by step, with the reasoning behind each move and the dead ends I hit along the way. Where I scripted the solve, my `solve.py` sits next to the writeup.

Read them on the web at **[writeups.theoith.ink](https://writeups.theoith.ink)**.

## Events

| Event | Writeups | Categories |
|---|---|---|
| [Packet Capture CTF](#packet-capture-ctf) | 16 | Forensics, Network, OSINT, Steganography, Web |
| [CSCTF 2026](#csctf-2026) | 44 | Crypto, Forensics, Misc, AI Security, Network, Pwn, Reverse Engineering, Web |
| [Pink CTF](#pink-ctf) | 8 | Crypto, OSINT, Reverse Engineering, Steganography, Web |

## Packet Capture CTF

### Act I: The Signal

| Challenge | Category | Technique |
|---|---|---|
| [Digital Footprint](Packet%20Capture%20CTF/ACT%20I%20-%20The%20Signal/%28DONE%29%20Digital%20Footprint/writeup.md) | OSINT |  |
| [Forgotten Repository](Packet%20Capture%20CTF/ACT%20I%20-%20The%20Signal/%28DONE%29%20Forgotten%20Repository/writeup.md) | OSINT |  |
| [Hidden Profile](Packet%20Capture%20CTF/ACT%20I%20-%20The%20Signal/%28DONE%29%20Hidden%20Profile/writeup.md) | OSINT |  |
| [Last Breadcrumb](Packet%20Capture%20CTF/ACT%20I%20-%20The%20Signal/%28DONE%29%20Last%20Breadcrumb/writeup.md) | OSINT |  |
| [Scattered Identities](Packet%20Capture%20CTF/ACT%20I%20-%20The%20Signal/%28DONE%29%20Scattered%20Identities/writeup.md) | OSINT |  |
| [Silent Observer](Packet%20Capture%20CTF/ACT%20I%20-%20The%20Signal/%28DONE%29%20Silent%20Observer/writeup.md) | OSINT | Medium |
| [Treasure Hunt Time](Packet%20Capture%20CTF/ACT%20I%20-%20The%20Signal/%28DONE%29%20Treasure%20Hunt%20Time/writeup.md) | OSINT |  |
| [Under Construction](Packet%20Capture%20CTF/ACT%20I%20-%20The%20Signal/%28DONE%29%20Under%20Construction/writeup.md) | OSINT | internet history |

### Act II: The Breach

| Challenge | Category | Technique |
|---|---|---|
| [Forgotten Router](Packet%20Capture%20CTF/ACT%20II%20-%20The%20Breach/%28DONE%29%20Forgotten%20Router/writeup.md) | Web | information disclosure / exposed file |
| [Internal Trouble](Packet%20Capture%20CTF/ACT%20II%20-%20The%20Breach/%28DONE%29%20Internal%20Trouble/writeup.md) | Web | SSRF |

### Act III: The Echo

| Challenge | Category | Technique |
|---|---|---|
| [Deleted Doesn't Mean Gone](Packet%20Capture%20CTF/ACT%20III%20-%20The%20Echo/%28DONE%29%20Deleted%20Doesn%27t%20Mean%20Gone/writeup.md) | Forensics | disk file carving |
| [Hidden Within](Packet%20Capture%20CTF/ACT%20III%20-%20The%20Echo/%28DONE%29%20Hidden%20Within/writeup.md) | Steganography |  |
| [Last Packet](Packet%20Capture%20CTF/ACT%20III%20-%20The%20Echo/%28DONE%29%20Last%20Packet/writeup.md) | Network |  |
| [Memory Echoes](Packet%20Capture%20CTF/ACT%20III%20-%20The%20Echo/%28DONE%29%20Memory%20Echoes/writeup.md) | Forensics |  |
| [Registry Secrets](Packet%20Capture%20CTF/ACT%20III%20-%20The%20Echo/%28DONE%29%20Registry%20Secrets/writeup.md) | Forensics | Memory |
| [USB Secrets](Packet%20Capture%20CTF/ACT%20III%20-%20The%20Echo/%28DONE%29%20USB%20Secrets/writeup.md) | Forensics |  |

## CSCTF 2026

### Crypto

| Challenge | Technique |
|---|---|
| [Emanation](CSCTF/Crypto/Emanation/writeup.md) · [solve.py](CSCTF/Crypto/Emanation/solve.py) |  |
| [The Keywheel](CSCTF/Crypto/The%20Keywheel/writeup.md) · [solve.py](CSCTF/Crypto/The%20Keywheel/solve.py) | PRNG state recovery / backward prediction |
| [The Signet](CSCTF/Crypto/The%20Signet/writeup.md) · [solve.py](CSCTF/Crypto/The%20Signet/solve.py) | ECDSA nonce recovery |
| [Watchword](CSCTF/Crypto/Watchword/writeup.md) | AES-GCM nonce reuse / "Forbidden Attack" |

### Forensics

| Challenge | Technique |
|---|---|
| [Briefing for One](CSCTF/Forensics/Briefing%20for%20One/writeup.md) · [solve.py](CSCTF/Forensics/Briefing%20for%20One/solve.py) | LNK, WebDAV pcap, 7z recovery |
| [Ghost in the Historian](CSCTF/Forensics/Ghost%20in%20the%20Historian/writeup.md) · [solve.py](CSCTF/Forensics/Ghost%20in%20the%20Historian/solve.py) | ext4 carving, xorshift decryptor |
| [Interlock Witness](CSCTF/Forensics/Interlock%20Witness/writeup.md) · [solve.py](CSCTF/Forensics/Interlock%20Witness/solve.py) | Modbus/TCP policy replay |
| [Last Buffer](CSCTF/Forensics/Last%20Buffer/writeup.md) · [solve.py](CSCTF/Forensics/Last%20Buffer/solve.py) | Vim swap file correlation |
| [Last Commit](CSCTF/Forensics/Last%20Commit/writeup.md) · [solve.py](CSCTF/Forensics/Last%20Commit/solve.py) | SQLite WAL reconstruction |
| [Operation Dawn - The Medic's Phone](CSCTF/Forensics/Operation%20Dawn%20-%20The%20Medic%27s%20Phone/writeup.md) | Android SQLite WAL recovery |
| [Ortelia VDR Carving](CSCTF/Forensics/Ortelia%20VDR%20Carving/writeup.md) · [solve.py](CSCTF/Forensics/Ortelia%20VDR%20Carving/solve.py) | fragmented PNG carving |
| [Polyglot Requiem](CSCTF/Forensics/Polyglot%20Requiem/writeup.md) · [solve.py](CSCTF/Forensics/Polyglot%20Requiem/solve.py) | git, PNG polyglot, SQLite carving |
| [Recon Plate](CSCTF/Forensics/Recon%20Plate/writeup.md) · [solve.py](CSCTF/Forensics/Recon%20Plate/solve.py) | bit-plane steganography |
| [Redline](CSCTF/Forensics/Redline/writeup.md) · [solve.py](CSCTF/Forensics/Redline/solve.py) | DOCX tracked-change recovery |
| [Relay Capture](CSCTF/Forensics/Relay%20Capture/writeup.md) · [solve.py](CSCTF/Forensics/Relay%20Capture/solve.py) | cropped PNG recovery |
| [Shadow-Dispatch](CSCTF/Forensics/Shadow-Dispatch/writeup.md) | Lambda layer pyc analysis |
| [Silent Breaker](CSCTF/Forensics/Silent%20Breaker/writeup.md) · [solve.py](CSCTF/Forensics/Silent%20Breaker/solve.py) | IEC-104 and SS7 correlation |
| [Telltale](CSCTF/Forensics/Telltale/writeup.md) · [solve.py](CSCTF/Forensics/Telltale/solve.py) | optical LED covert channel |
| [The Capability Ghost](CSCTF/Forensics/The%20Capability%20Ghost/writeup.md) · [solve.py](CSCTF/Forensics/The%20Capability%20Ghost/solve.py) | PAX xattrs and journal triage |
| [The Layer That Wouldn't Die](CSCTF/Forensics/The%20Layer%20That%20Wouldn%27t%20Die/writeup.md) | OCI layer whiteout recovery |
| [Tone Burst](CSCTF/Forensics/Tone%20Burst/writeup.md) · [solve.py](CSCTF/Forensics/Tone%20Burst/solve.py) | audio FSK decoding |
| [Water Hammer Reconciliation](CSCTF/Forensics/Water%20Hammer%20Reconciliation/writeup.md) · [solve.py](CSCTF/Forensics/Water%20Hammer%20Reconciliation/solve.py) | Modbus/TCP capture reconciliation |

### Misc

| Challenge | Technique |
|---|---|
| [Lattice](CSCTF/Misc/Lattice/writeup.md) · [solve.py](CSCTF/Misc/Lattice/solve.py) | inverting a home-built block cipher |
| [Operation Dawn - The Cipher Lock](CSCTF/Misc/Operation%20Dawn%20-%20The%20Cipher%20Lock/writeup.md) · [solve.py](CSCTF/Misc/Operation%20Dawn%20-%20The%20Cipher%20Lock/solve.py) | power analysis on AES S-box |
| [Warden](CSCTF/Misc/Warden/writeup.md) · [solve.py](CSCTF/Misc/Warden/solve.py) | CPython audit hook sandbox escape |

### AI Security

| Challenge | Technique |
|---|---|
| [Dispatch Authenticator](CSCTF/ML/Dispatch%20Authenticator/writeup.md) · [solve.py](CSCTF/ML/Dispatch%20Authenticator/solve.py) | federated learning gradient leakage |

### Network

| Challenge | Technique |
|---|---|
| [Ghost Signal](CSCTF/Network/Ghost%20Signal/writeup.md) · [solve.py](CSCTF/Network/Ghost%20Signal/solve.py) | SS7 Diameter billing correlation |
| [Grid-Watch](CSCTF/Network/Grid-Watch/writeup.md) · [solve.py](CSCTF/Network/Grid-Watch/solve.py) | MAVLink 2 signing key re-provisioning |
| [Severed Link](CSCTF/Network/Severed%20Link/writeup.md) · [solve.py](CSCTF/Network/Severed%20Link/solve.py) | MAVLink 2 signing key leak |
| [Silent Orbit](CSCTF/Network/Silent%20Orbit/writeup.md) · [solve.py](CSCTF/Network/Silent%20Orbit/solve.py) | CCSDS and CFDP NAK reconstruction |

### Pwn

| Challenge | Technique |
|---|---|
| [Echo Chamber](CSCTF/Pwn/Echo%20Chamber/writeup.md) · [solve.py](CSCTF/Pwn/Echo%20Chamber/solve.py) | echo-oracle info leak |

### Reverse Engineering

| Challenge | Technique |
|---|---|
| [Command Authority](CSCTF/Reverse%20Engineering/Command%20Authority/writeup.md) · [solve.py](CSCTF/Reverse%20Engineering/Command%20Authority/solve.py) |  |
| [Fence Shift](CSCTF/Reverse%20Engineering/Fence%20Shift/writeup.md) |  |
| [Operation Dawn - Radio Recovery](CSCTF/Reverse%20Engineering/Operation%20Dawn%20-%20Radio%20Recovery/writeup.md) · [solve.py](CSCTF/Reverse%20Engineering/Operation%20Dawn%20-%20Radio%20Recovery/solve.py) | custom firmware container |

### Web

| Challenge | Technique |
|---|---|
| [Apogee](CSCTF/Web/Apogee/writeup.md) · [solve.py](CSCTF/Web/Apogee/solve.py) | ZIP duplicate-name + symlink parser-differential writes... |
| [Corridor Transit Gate](CSCTF/Web/Corridor%20Transit%20Gate/writeup.md) · [solve.py](CSCTF/Web/Corridor%20Transit%20Gate/solve.py) | API gateway broken access control |
| [Cutover](CSCTF/Web/Cutover/writeup.md) · [solve.py](CSCTF/Web/Cutover/solve.py) | Node.js |
| [Helioform Relay](CSCTF/Web/Helioform%20Relay/writeup.md) · [solve.py](CSCTF/Web/Helioform%20Relay/solve.py) | ICS/OT-themed) (open agent wire |
| [Interlock](CSCTF/Web/Interlock/writeup.md) | parser-confusion chain: path-authz bypass + Unicode... |
| [Key Custody](CSCTF/Web/Key%20Custody/writeup.md) · [solve.py](CSCTF/Web/Key%20Custody/solve.py) | JWT HS256 `kid` key-injection |
| [Operation Dawn - The Dispatch Console](CSCTF/Web/Operation%20Dawn%20-%20The%20Dispatch%20Console/writeup.md) · [solve.py](CSCTF/Web/Operation%20Dawn%20-%20The%20Dispatch%20Console/solve.py) | second-order SQL injection + WAF bypass |
| [Operation Dawn - The Standing Order](CSCTF/Web/Operation%20Dawn%20-%20The%20Standing%20Order/writeup.md) · [solve.py](CSCTF/Web/Operation%20Dawn%20-%20The%20Standing%20Order/solve.py) | signed-cookie forgery via SHA-1 hash length extension |
| [Two-Key Turn](CSCTF/Web/Two-Key%20Turn/writeup.md) · [solve.py](CSCTF/Web/Two-Key%20Turn/solve.py) | race condition |
| [Vesper Quay Board](CSCTF/Web/Vesper%20Quay%20Board/writeup.md) · [solve.py](CSCTF/Web/Vesper%20Quay%20Board/solve.py) | parser-differential RCE + Ed25519 signing with the... |

## Pink CTF

### Crypto

| Challenge | Technique |
|---|---|
| [99](Pink%20CTF/Crypto/99/writeup.md) · [solve.py](Pink%20CTF/Crypto/99/solve.py) | QWERTZ-99 factoring |

### OSINT

| Challenge | Technique |
|---|---|
| [Soeder Swim](Pink%20CTF/OSINT/Soeder%20Swim/writeup.md) · [solve.py](Pink%20CTF/OSINT/Soeder%20Swim/solve.py) | reverse image geolocation |

### Reverse Engineering

| Challenge | Technique |
|---|---|
| [Journey](Pink%20CTF/Reversing/Journey/writeup.md) · [solve.py](Pink%20CTF/Reversing/Journey/solve.py) | nine-language decoder chain |

### Steganography

| Challenge | Technique |
|---|---|
| [Cluck Cluck](Pink%20CTF/Steganography/Cluck%20Cluck/writeup.md) · [solve.py](Pink%20CTF/Steganography/Cluck%20Cluck/solve.py) | WAV LSB and Chicken esolang |
| [Suspicious Numbers](Pink%20CTF/Steganography/Suspicious%20Numbers/writeup.md) · [solve.py](Pink%20CTF/Steganography/Suspicious%20Numbers/solve.py) | atomic number encoding |
| [TNS2](Pink%20CTF/Steganography/TNS2/writeup.md) | TI-Nspire hidden in geometry |

### Web

| Challenge | Technique |
|---|---|
| [Escaped](Pink%20CTF/Web/Escaped/writeup.md) · [solve.py](Pink%20CTF/Web/Escaped/solve.py) | multibyte SQL injection |
| [SQL Injection](Pink%20CTF/Web/SQL%20Injection/writeup.md) · [solve.py](Pink%20CTF/Web/SQL%20Injection/solve.py) | multibyte SQL injection |

## What's in a folder

```
<Event>/<Act or Category>/<Challenge>/
  writeup.md      the walkthrough
  solve.py        my solve script, where there is one
  screenshots/    the evidence for each step
```

The challenge files themselves (captures, disk images, binaries) belong to each event's organisers, so they aren't in this repo.
