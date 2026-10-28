Flag: PacketCapture{r0ut3_99_bb6cfead}
Category: Web Exploitation (information disclosure / exposed file)
Tools used: curl (Burp Suite equivalent for crafting HTTP requests)

Steps:
1. Start point: https://router.challs.packetcapture.xyz
   - What I did / What I found: GET / returned `302 Found -> /cgi-bin/login.cgi`. The login page is a
     fake router admin console: "vRouter 0.1-beta - Admin Console", footer "vRouter v0.1-beta; 0566.23.2
     firmware". The server only allows GET/HEAD/POST (501 "The requested method is not recognized" for
     anything else - classic embedded httpd behaviour).
   - Result: Identified a CGI-based router web UI with a login gate.
   - Thinking: The brief - "its firmware still listens for a request that can finally end its misery" -
     means there is one specific HTTP request the device responds to. That could be an auth bypass, but
     first rule out the cheapest thing: a file the firmware image left exposed at the web root.

2. Pivot: enumerate endpoints behind the login
   - What I did / What I found: login.cgi (POST) only returns `alert('Invalid credentials')`; no SQLi,
     no command injection, no cookie/header/XFF auth bypass. `index.cgi` and `diagnostics.cgi` both
     302-redirect to login (auth-gated). Then I fuzzed the web root for leftover files.
   - Result: `GET /flag.txt` returned `200 OK` with a 33-byte text/plain body.
   - Thinking: Embedded firmware builds routinely ship stray files packed into the web root. If the gated
     CGI pages are the "front door", the exposed static file is the forgotten side door the brief points at.

3. Pivot: read the exposed file
   - What I did / What I found: `curl https://router.challs.packetcapture.xyz/flag.txt` ->
     `PacketCapture{r0ut3_99_bb6cfead}`. Re-fetched twice: identical content and a stable Last-Modified,
     confirming it is a real static file and not a per-request decoy.
   - Result: Flag recovered without ever authenticating to the router.

Key insight: The login/diagnostics CGI is a distraction. The actual vulnerability is a plain information
disclosure - the flag file was left readable at the web root (`/flag.txt`), bypassing the entire
authentication gate. "A request that can finally end its misery" is literally one GET request to the
file the firmware forgot to protect.
