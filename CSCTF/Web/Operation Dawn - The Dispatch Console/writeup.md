Challenge: Operation Dawn: The Dispatch Console — Web / Medium / 271 pts / author: Terminal43 (CSCTF 2026)
Flag: CSCTF{3nMaMxjZiiRPQydvXZlxKo7G}
Category: Web (second-order SQL injection)
Tools used: curl, Python 3 (stdlib urllib), solve.py
Brief: a captured Ash field dispatch console was stood back up. A plain visitor can read and file dispatches, but the command net is locked and its standing order with it. Everything is "run past a sanitiser before it touches the database." Recover command's standing order (the flag).

Steps:
1. Start point: map the app (AshNet-Dispatch 4.3).
   - What I did: mapped the endpoints — GET /dispatches?callsign= (read a callsign's log), POST /post (file a
     dispatch: callsign + body), GET /digest (per-callsign roll-up of the whole unit log), and a token-gated
     GET /report?token=&fmt= whose fmt default is a Python str.format template `dispatch {dispatch.ref}:
     {dispatch.body}`. The unit net shows EMBER/CINDER/WARDEN; the command standing order is filtered out.
   - What I found: there is a global WAF. Any request whose input contains `union`, `select` or `--`
     (case-insensitive substring) is rejected with 403, before anything else. It does NOT block `'`, `||` or
     Python format dunders.

2. Pivot: test the obvious sink, /dispatches callsign — and rule it out.
   - What I did: boolean tests. `EMBER' OR '1'='1` returns "no dispatches", not the whole unit net; `EMBER' AND
     '1'='1` also returns nothing; `EMB'||'ER` doesn't rebuild "EMBER"; a backslash/multibyte (GBK) addslashes
     bypass does nothing; heavy-compute SQLite burners show no timing delta. So the callsign read is fully
     parameterised. /digest takes no injectable parameter either.
   - Thinking: the WAF exists, so a SQL sink exists — but the first-order reads/writes are all bound parameters.
     That points at second order: a value stored safely, then re-used unsafely by a later query the WAF never sees.

3. Pivot: find the second-order sink in /digest.
   - What I found: /post stores the callsign with a bound parameter (filing `SOTB','extra` is accepted but creates
     no readable row — the signature of a value stored literally, not of a broken INSERT). But /digest re-reads each
     stored callsign back into a concatenated per-group query, roughly `... WHERE callsign='<stored callsign>'`.
     Proof: I filed callsign `FPA'||'ZZ`; the digest then showed that group as "0 dispatch(es)", because SQLite
     evaluated `'FPA'||'ZZ'` -> `FPAZZ` (string concat) which matches nothing — whereas a quote-breaking callsign
     made that group error out and vanish. So the injection is SQLite, inside /digest, and the WAF only inspected my
     original /post input, never the digest's internal query.

4. Exploit: dump the command standing order through the digest.
   - What I did: filed a dispatch with callsign `DMP' OR '1'='1`. It passes the WAF (no union/select/--). On the next
     /digest, that group's lookup becomes `WHERE callsign='DMP' OR '1'='1'`, which matches every row in the table —
     including the locked command-net standing order — and the digest prints each matched body. The standing order
     body is the flag. (If the standing order had lived in a separate table I would have pivoted to boolean-blind
     extraction using the digest's per-group row count as the oracle, still with no select/union needed.)
   - Result: the dumped command row carried the flag, CSCTF{3nMaMxjZiiRPQydvXZlxKo7G}.

Key insight: the sanitiser and WAF only guarded the front door (the /post write and the /dispatches read). The /digest report re-used the stored callsign in a concatenated query, so a value that was stored safely became a SQL injection the second time it was read — classic second-order, invisible to the request-time WAF.
Defensive takeaways: A WAF that inspects inbound requests does nothing for second-order injection, where the dangerous query is built later from stored data — parameterise EVERY query, including the ones that read your own tables, not just the ones that take direct user input. Don't rely on denylisting union/select/--; the exploit used none of them, `' OR '1'='1` was enough. The command "lock" was only a WHERE filter in one query path, so access control for sensitive rows must be enforced at the data layer for every path, not by hoping one report query happens to exclude them.
Reproduce: python3 solve.py http://HOST:PORT (files the OR-callsign, then reads /digest)
Note: no fresh screenshot — the practice instance was being restarted organizer-side during this write-up, so no post-event capture was taken; solve.py reproduces the chain against a live instance.
