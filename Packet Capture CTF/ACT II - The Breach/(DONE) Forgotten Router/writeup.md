Flag: PacketCapture{r0ut3_99_bb6cfead}
Category: Web (exposed file at web root)
Tools used: curl

Steps:
1. Start point: router.challs.packetcapture.xyz
   - What I did: sent GET / to https://router.challs.packetcapture.xyz.
   - What I found: it returned 302 Found to /cgi-bin/login.cgi. The login page is a fake router admin console: "vRouter 0.1-beta - Admin Console", footer "vRouter v0.1-beta; 0566.23.2 firmware". The server only allows GET/HEAD/POST (501 "The requested method is not recognized" for anything else, which is classic embedded httpd behaviour).
   - Result: a CGI-based router web UI with a login gate.
   - Thinking: The brief ("its firmware still listens for a request that can finally end its misery") means there is one specific HTTP request the device responds to. That could be an auth bypass, but first rule out the cheapest thing: a file the firmware image left exposed at the web root.

2. Pivot: look past the login for leftover files
   - What I did: tested login.cgi (POST), index.cgi and diagnostics.cgi, then fuzzed the web root for leftover files.
   - What I found: login.cgi only returns alert('Invalid credentials'), with no SQLi, no command injection and no cookie, header or XFF auth bypass. index.cgi and diagnostics.cgi both 302-redirect to login (auth-gated).
   - Result: GET /flag.txt returned 200 OK with a 33-byte text/plain body.
   - Thinking: Embedded firmware builds routinely ship stray files packed into the web root. If the gated CGI pages are the front door, the exposed static file is the forgotten side door the brief points at.

3. Flag: read the exposed file
   - What I did: ran curl https://router.challs.packetcapture.xyz/flag.txt, then re-fetched it twice.
   - What I found: PacketCapture{r0ut3_99_bb6cfead}, with identical content and a stable Last-Modified both times.
   - Thinking: identical re-fetches show it is a real static file and not a per-request decoy.
   - Result: PacketCapture{r0ut3_99_bb6cfead}, recovered without ever authenticating to the router.

Key insight: The flag file /flag.txt was left readable at the web root, so one unauthenticated GET bypassed the whole login gate. The login and diagnostics CGI pages were a distraction: "a request that can finally end its misery" is literally one GET request to the file the firmware forgot to protect.
