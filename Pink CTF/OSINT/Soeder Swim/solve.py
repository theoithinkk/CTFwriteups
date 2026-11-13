"""Submit the geolocated coordinates to the Galaxus/OSINT map checker and print the flag.

The OSINT work (reverse image search -> 1. FC Nürnberg "Clubbad") is in writeup.md. The only thing the
server needs is the coordinates of that pool; it replies with the flag for the right spot.

Usage: python -I solve.py [https://osint.pink.bayern/2/]
"""
import json
import re
import sys
import urllib.parse
import urllib.request

# 1. FC Nürnberg Freibad "Clubbad", Valznerweiherstraße 200, 90480 Nürnberg
LAT, LON = 49.4339899, 11.1318245


def submit(base):
    body = urllib.parse.urlencode({"lat": LAT, "lon": LON}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/?check=1", data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    return json.loads(urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace"))


def demo():
    """Self-check: the server's success shape is {"ok": true, "message": "PINK{...}"}."""
    sample = {"ok": True, "message": "PINK{example_flag}"}
    assert sample["ok"] and re.search(r"PINK\{.*\}", sample["message"]), "response shape changed"
    print("demo ok: a correct guess returns ok=true with a PINK{...} message")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo(); sys.exit()
    base = sys.argv[1] if len(sys.argv) > 1 else "https://osint.pink.bayern/2/"
    res = submit(base)
    if res.get("ok"):
        print("flag:", res["message"])
    else:
        print("rejected:", res.get("message"))
