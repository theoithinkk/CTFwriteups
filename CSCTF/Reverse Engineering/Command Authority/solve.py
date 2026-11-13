#!/usr/bin/env python3
# Command Authority - real solve. Usage: ca_solve.py <id_photo.jpg> <field_verifier> <pass.token>
import sys, base64
jpg, verifier, token = sys.argv[1], sys.argv[2], sys.argv[3]

# 1) archive key appended after JPEG EOI
d = open(jpg, "rb").read()
i = d.rfind(b"\xff\xd9")
trailer = d[i+2:].decode("latin1")
key = trailer.split(":", 1)[1].strip()
print(f"[1] JPEG EOI at {i} (file {len(d)} bytes) -> trailer {trailer!r}")
print(f"    archive password = {key}")

# 2) the supplied token is a STANDARD-CORRIDOR civilian record (decoded prefix)
tok = open(token, "rb").read()
try:
    dec = base64.b64decode(tok).decode("latin1", "replace")
except Exception:
    dec = ""
print(f"[2] pass.token decodes to: {dec[:48]!r} ... (not RESTRICTED)")

# 3) recover restricted clearance: embedded bytes are XOR-obfuscated with 0x41
data = open(verifier, "rb").read()
HEX = set(b"0123456789abcdef")
best = ""
run = []
for b in data:
    c = b ^ 0x41
    if c in HEX:
        run.append(c)
    else:
        if len(run) > len(best): best = bytes(run).decode()
        run = []
if len(run) > len(best): best = bytes(run).decode()
print(f"[3] XOR-0x41 scan of field_verifier -> longest hex run ({len(best)} chars): {best}")
print(f"[+] FLAG: CSCTF{{{best}}}")
