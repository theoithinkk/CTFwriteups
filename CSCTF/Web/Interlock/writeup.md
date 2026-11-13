Challenge: Interlock — Web / Hard / 593 pts / author: Mohamed Amine Mzoughi (CSCTF 2026)
Flag: CSCTF{BlZ4Nmk2FatBdbynwVvJr1Vo}
Category: Web (parser-confusion chain)
Tools used: curl (--path-as-is), Python 3 (hashlib, unicodedata), the app's own /api/v1/schema
Brief: a forged protection setting-group was loaded into the Keld Ridge substation cluster on Velmara's eastern interconnection, set to trip 2.1 GW and split the grid. A compromised engineer account also put Keld Ridge on the dispatcher's quarantine list, so the dispatcher refuses to send the cluster anything. My observer desk is read-only. A dispatchable isolation order needs dual control — a requester and an approver, both on the engineer roster and not the same principal. When an order reaches the substation gateway, the gateway returns an isolation receipt carrying the clearance code. The reliability console links the operations API schema at /api/v1/schema, and the brief warns to use a client that sends the path exactly as typed (curl --path-as-is). Every gate in this app trusts a DIFFERENT interpretation of the same bytes; the solve is four stacked parser bugs, each one living in the gap between the component that checks a string and the component that acts on it.

Steps:
1. Start point: read /api/v1/schema from the reliability console at the edge root.
   - What I found: the privileged operations live under /ops/* (create delegate, raise order, approve, dispatch).
     The edge proxy denies /ops/* to my read-only desk by matching the literal received path. The backend, behind the
     edge, routes on the normalized path.
   - Thinking: an edge that authorizes on the raw path and a backend that routes on the normalized path is a classic
     path-confusion split — and the brief's `--path-as-is` hint is pointing right at it.

2. Pivot (bug 1): edge path-authorization bypass with a dot-segment.
   - What I did: requested `/./ops/...` with `curl --path-as-is` so the `/.` is sent literally. The edge sees a path
     that does not start with `/ops`, so its deny rule misses and it forwards the request. The backend collapses the
     `/.` dot-segment and routes to the real `/ops/...` endpoint. A normal client would rewrite `/.` before sending,
     which is exactly why the brief tells you not to. Now I can reach the /ops/* actions.

3. Pivot (bug 2): defeat dual control with an NFKC-vs-casefold normalization mismatch.
   - What I found: creating a delegate is checked two different ways. The roster membership check folds the submitted
     name with NFKC + casefold before comparing to the real engineer roster; the delegate-uniqueness check folds with
     plain casefold only.
   - What I did: registered delegates with fullwidth homoglyph names — `ｒ.mendal` and `ａ.torvo`. Under NFKC+casefold
     a fullwidth `ｒ`/`ａ` normalizes to ASCII `r`/`a`, so each name folds onto a real engineer and is accepted as
     on-roster AND counts as a distinct principal. Under plain casefold the fullwidth name is NOT equal to the real
     one, so the uniqueness check does not reject it as a duplicate. That yields two "roster" principals I control —
     one to request the isolation order and one to approve it — satisfying "requester and approver, both on the
     roster, not the same principal" while really being one analyst (me).

4. Pivot (bug 3): bypass the quarantine with a fast-uri vs WHATWG host-parser mismatch.
   - What I found: before dispatching, the app checks the destination host against the quarantine list using fast-uri
     3.1.2; the outbound fetch then parses the same URL with Node's WHATWG URL. The two parsers disagree on a
     backslash.
   - What I did: targeted `http://sg-kr.grid.test\dispatch`. fast-uri reads the host as the whole
     `sg-kr.grid.test\dispatch` (which is not the quarantined entry `sg-kr.grid.test`, so the quarantine check
     passes), but WHATWG URL converts `\` to `/`, yielding host `sg-kr.grid.test` with path `/dispatch` — so the
     dispatcher connects straight to the quarantined Keld Ridge gateway anyway.

5. Exploit (bug 4): satisfy the release interlock and read the receipt.
   - What I found: the gateway withholds the isolation receipt until the dispatch carries the correct interlock
     digest, `sha256("interlock|<order_id>|<buses,comma-joined>")`, and hits the gateway's `/dispatch` endpoint.
   - What I did: for order `ord-5` isolating buses KR-B1,KR-B2 the digest is
     `sha256("interlock|ord-5|KR-B1,KR-B2")`. Sending the dispatch (via the `\dispatch` host trick) with that digest
     to `/dispatch` returned the isolation receipt and the clearance code.
   - Result: the receipt's clearance code is the flag, CSCTF{BlZ4Nmk2FatBdbynwVvJr1Vo}.

Key insight: four components each parse the same bytes differently — fast-uri vs WHATWG for the host, NFKC vs plain casefold for the identity, raw vs normalized for the path. The attacker lives in every gap: a string that looks safe to the checker and dangerous to the executor. The fix is parser unanimity — authorize on, and act on, the exact same canonical value.
Defensive takeaways: Normalize once, at the edge, and route/authorize on that same canonical path; never let the proxy and the app disagree about what the path is. Use ONE Unicode normalization (NFKC+casefold) for both "is this on the roster" and "is this a duplicate"; identity and uniqueness must fold the same way, and dual control must bind to immutable account IDs, not display names. Extract the host with the very parser the outbound fetch uses (or reject backslashes and control chars outright) so a security check and the action it guards can never read a different host.
Reproduce: chain against a live instance — read /api/v1/schema; curl --path-as-is to /./ops/...; register delegates ｒ.mendal and ａ.torvo; raise + approve order ord-5; dispatch to http://sg-kr.grid.test\dispatch with body carrying sha256("interlock|ord-5|KR-B1,KR-B2"); read the clearance code from the receipt.
Note: no fresh screenshot — the practice instance was unavailable for a post-event capture (organizer-side restarts).
