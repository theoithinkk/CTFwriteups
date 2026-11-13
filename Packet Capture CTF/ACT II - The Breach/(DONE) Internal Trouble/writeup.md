Flag: PacketCapture{y0u_d1dNt_s33_th4T_c0m1ng_fd23bace}
Category: Web (SSRF)
Tools used: Burp Suite / curl (HTTP request crafting), base64 decoder

Steps:
1. Start point: the challenge page at https://internal.challs.packetcapture.xyz
   - What I did: read the landing page, an "Is Website Down?" checker with a form that submits to /check?url=, and then the client-side JS in the result page.
   - What I found: the real work happens at a backend API: POST /fetch with JSON body {"url": "..."}, which returns {"status":"ok","msg":"<base64 PNG/JPEG screenshot>"} on success, or {"status":"error","msg":...}.
   - Result: /fetch is a server-side URL fetcher that renders a screenshot of whatever URL you give it, a classic SSRF surface.
   - Thinking: The brief says "all 3001 systems" and "the troubles beeping within". 3001 is a port, and "within" means an internal service only reachable from the server itself. A tool that takes a URL and fetches it server-side is the way in.

2. Pivot: probe the internal service on port 3001 via /fetch
   - What I did: sent POST /fetch with {"url":"http://localhost:3001"} and http://127.0.0.1:3001.
   - What I found: both returned {"status":"error","msg":"Unauthorized."}.
   - Result: the app has an SSRF filter that blocks obvious loopback addresses.
   - Thinking: "Unauthorized" only comes back if the request is being inspected and rejected, so the service exists, it is just filtered. I needed a filter bypass.

3. Pivot: bypass the SSRF allow/deny filter
   - What I did: tried several loopback representations against /fetch.
      - http://0.0.0.0:3001 gave Unauthorized
      - http://127.1:3001 gave Unauthorized
      - http://2130706433:3001 (decimal IP) gave Unauthorized
      - http://[::1]:3001 (IPv6 loopback) worked and returned a base64 screenshot
      - http://127.0.0.1.nip.io:3001 (DNS wildcard to 127.0.0.1) worked
      - http://localtest.me:3001 worked
   - Result: the blocklist only covered IPv4 literal loopback forms. IPv6 [::1] and hostnames that resolve to 127.0.0.1 slipped straight through and reached the internal dashboard on port 3001.
   - Thinking: SSRF denylists that string-match 127.0.0.1 or localhost almost always miss IPv6 and resolver tricks. [::1] is the same machine by a name the filter did not list.

4. Pivot: extract the flag from the returned screenshot
   - What I found: the internal dashboard screenshot came back base64-encoded. The flag was present both as readable text rendered in the image and, more directly, stored in the image's EXIF metadata. The EXIF description field contained the base64 string UGFja2V0Q2FwdHVyZXt5MHVfZDFkTnRfczMzX3RoNFRfYzBtMW5nX2ZkMjNiYWNlfQ== which decodes to the flag.
   - Result: flag recovered.
   - Thinking: when a challenge hands back an image, always decode it and check its metadata. The flag is usually planted in EXIF or rendered pixels rather than the page body.

     ![Internal dashboard rendered via SSRF to [::1]:3001](screenshots/01_internal_dashboard.jpg)

Key insight: The "Is Website Down?" checker is an SSRF primitive. The internal monitor on port 3001 is only reachable from the server and is protected by a weak loopback denylist that matches IPv4 literals only. Reaching it as http://[::1]:3001 (or any hostname resolving to 127.0.0.1) bypasses the filter, and the dashboard screenshot carries the flag in its EXIF data.
