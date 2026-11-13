#!/usr/bin/env python3
"""
Ghost Signal (CSCTF 2026 - Network).

Three records of one incident: SS7 (MAP over M3UA), Diameter, and the billing
export. One subscriber identity threads all three. Flag =
first 8 lowercase hex of SHA-256("<IMSI>:<SESSION_ID>:<FIRST_ANOMALOUS_BILLING_TIMESTAMP>"),
values taken exactly as written in the evidence.

The intruder's IMSI is the odd one out: every normal subscriber uses a 16-digit
IMSI (2260120140002xxx); the attacker's is the single 15-digit 226012014000001.
Every billing event with an "anomaly" field belongs to that IMSI and to one
session hss.eastern-tele.ro;1723740150;49211. This script confirms the IMSI
appears in both captures (SS7 stores it TBCD/nibble-swapped), then builds the hash.
"""
import sys, os, json, re, hashlib, collections

D = os.path.dirname(__file__)
BILL = sys.argv[1] if len(sys.argv) > 1 else os.path.join(D, "billing_events.json")
SS7 = sys.argv[2] if len(sys.argv) > 2 else os.path.join(D, "ss7_capture.pcap")
DIA = sys.argv[3] if len(sys.argv) > 3 else os.path.join(D, "diameter_capture.pcap")


def tbcd(b):  # telephony BCD: swap nibbles, drop 'f' padding
    return "".join("%x%x" % (x & 0xF, x >> 4) for x in b).rstrip("f")


# --- SS7: find IMSIs encoded as MAP IMSI (tag 0x04, len 8, TBCD) ------------
ss7 = open(SS7, "rb").read()
ss7_imsis = collections.Counter()
for m in re.finditer(rb"\x04\x08(.{8})", ss7, re.S):
    v = tbcd(m.group(1))
    if re.fullmatch(r"\d{14,16}", v):
        ss7_imsis[v] += 1

# --- Diameter: raw IMSI strings --------------------------------------------
dia = open(DIA, "rb").read()
dia_imsis = collections.Counter(x.decode() for x in re.findall(rb"22601\d{9,11}", dia))

# --- Billing: the anomalous subscriber/session -----------------------------
events = json.load(open(BILL))["events"]
anom = [e for e in events if "anomaly" in e]
ids = {(e["imsi"], e["session_id"]) for e in anom}
assert len(ids) == 1, ids
imsi, session = next(iter(ids))
first_ts = min(e["timestamp"] for e in anom)            # first anomalous billing timestamp

assert ss7_imsis.get(imsi), "attacker IMSI not found in SS7"
assert dia_imsis.get(imsi), "attacker IMSI not found in Diameter"
print("IMSI    =", imsi, "(SS7 x%d, Diameter x%d)" % (ss7_imsis[imsi], dia_imsis[imsi]))
print("Session =", session)
print("First anomalous billing timestamp =", first_ts)

s = "%s:%s:%s" % (imsi, session, first_ts)
print(s)
print("CSCTF{%s}" % hashlib.sha256(s.encode()).hexdigest()[:8])
