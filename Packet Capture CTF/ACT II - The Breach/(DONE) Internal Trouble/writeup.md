Flag: PacketCapture{y0u_d1dNt_s33_th4T_c0m1ng_fd23bace}
Category: Web Exploitation (SSRF)
Tools used: Burp Suite / curl (HTTP request crafting), base64 decoder

Steps:
1. Start point: the challenge page at https://internal.challs.packetcapture.xyz
   - What I did / What I found: The landing page is an "Is Website Down?" checker with a form that
     submits to `/check?url=`. Reading the client-side JS in the result page showed the real work
     happens at a backend API: `POST /fetch` with JSON body `{"url": "..."}`, which returns
     `{"status":"ok","msg":"<base64 PNG/JPEG screenshot>"}` on success, or `{"status":"error","msg":...}`.
   - Result: Identified `/fetch` as a server-side URL fetcher that renders a screenshot of whatever
     URL you give it - a classic SSRF surface.
   - Thinking: The brief says "all 3001 systems" and "the troubles beeping within" - 3001 is a port,
     and "within" means an internal service only reachable from the server itself. A tool that takes a
     URL and fetches it server-side is the way in.

2. Pivot: probe the internal service on port 3001 via /fetch
   - What I did / What I found: Sent `POST /fetch` with `{"url":"http://localhost:3001"}` and
     `http://127.0.0.1:3001`. Both returned `{"status":"error","msg":"Unauthorized."}`.
   - Result: The app has an SSRF filter that blocks obvious loopback addresses.
   - Thinking: "Unauthorized" only comes back if the request is being inspected and rejected - the
     service exists, it's just filtered. Need a filter bypass.

3. Pivot: bypass the SSRF allow/deny filter
   - What I did / What I found: Tried several loopback representations against `/fetch`:
     - `http://0.0.0.0:3001` -> Unauthorized
     - `http://127.1:3001` -> Unauthorized
     - `http://2130706433:3001` (decimal IP) -> Unauthorized
     - `http://[::1]:3001` (IPv6 loopback) -> **ok**, returned a base64 screenshot
     - `http://127.0.0.1.nip.io:3001` (DNS wildcard -> 127.0.0.1) -> **ok**
     - `http://localtest.me:3001` -> **ok**
   - Result: The blocklist only covered IPv4 literal loopback forms. IPv6 `[::1]` and hostnames that
     resolve to 127.0.0.1 slipped straight through and reached the internal dashboard on port 3001.
   - Thinking: SSRF denylists that string-match `127.0.0.1`/`localhost` almost always miss IPv6 and
     resolver tricks. `[::1]` is the same machine by a name the filter didn't list.

4. Pivot: extract the flag from the returned screenshot
   - What I did / What I found: The internal dashboard screenshot came back base64-encoded. The flag
     was present both as readable text rendered in the image and, more directly, stored in the image's
     EXIF metadata. The EXIF description field contained the base64 string
     `UGFja2V0Q2FwdHVyZXt5MHVfZDFkTnRfczMzX3RoNFRfYzBtMW5nX2ZkMjNiYWNlfQ==`, which decodes to the flag.
   - Result: Flag recovered.
   - Thinking: When a challenge hands back an image, always decode it and check its metadata - the
     flag is usually planted in EXIF or rendered pixels rather than the page body.

![Internal dashboard rendered via SSRF to [::1]:3001](screenshots/01_internal_dashboard.jpg)

Key insight: The "Is Website Down?" checker is an SSRF primitive. The internal monitor on port 3001
is only reachable from the server and is protected by a weak loopback denylist that matches IPv4
literals only. Reaching it as `http://[::1]:3001` (or any hostname resolving to 127.0.0.1) bypasses the
filter, and the dashboard screenshot carries the flag in its EXIF data.
