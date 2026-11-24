Flag: CSCTF{b6b0881524852112e5d422f75053d324}
Category: Forensics (Lambda layer pyc analysis)
Tools used: unzip, diff, Python (marshal, dis, hashlib, re)
Challenge: Shadow-Dispatch (CSCTF 2026, Forensics, Hard, 592 pts, author: Marius Merai)

Steps:

1. Start point: the authorizer's version history
   - What I did: listed the incident bundle (Lambda function and layer exports, IAM, CloudWatch log streams) and summarized function-versions.json for the authorizer function: every version's CodeSha256 and attached layers.
   - What I found: the function code hash is identical across every version (and $LATEST). What differs between versions is the attached layers: auth-utils 1 to 10, plus observability-common and dispatch-runtime.
   - Thinking: engineers report no unauthorized changes, and that matches the function code. If anything changed, it is inside the layers. I started with auth-utils because the authorizer imports its log helper and the odd telemetry comes from that path.

2. Pivot: the auth-utils .pyc doesn't match its .py
   - What I did: extracted all 10 auth-utils layer zips and diffed _authlog.py. The sources are byte-identical except for a # build comment, but the layer zip sizes differ, so I compared the __pycache__/_authlog.cpython-312.pyc files.
   - What I found: versions 4, 6, 8 and 10 have a larger pyc (3571 or 3576 bytes versus 2788) that does not match the source. The pyc header flag is 1, a hash-based pyc with check_source unset, so Python runs it without comparing it to _authlog.py.
   - Thinking: this is why a source review shows nothing. The .py is clean; the .pyc is what runs.

3. Pivot: disassemble the malicious pyc
   - What I did: loaded the pyc with marshal, disassembled _beacon with dis, and read the module constants for each bad version.
   - What I found: on every order where order_id % _EVERY == 0, the code reads one of four SSM parameters (/gridlink/portal-session-secret, order-hmac-key, db-readonly-password, metrics-api-token), picks one with a constant _PICK, and emits a slice of the secret in the correlation= token of the telemetry log line. Otherwise it emits a hash of the file itself. _PICK is 0 for v4, 2 for v6, 1 for v8 and 3 for v10.
   - Thinking: _PICK 1 means version 8 leaks _NAMES[1], the order-hmac-key. That name says it signs orders, so version 8's tokens are the ones to decode.

4. Decode: the telemetry tokens
   - What I did: worked out the token layout from the code: idx(1) | ct(2) | crc16(2) | salt(11), with ct = chunk XOR sha256(request_id + salt)[:2]. I parsed every "telemetry order_id=... correlation=..." line in the CloudWatch streams, took the request ID and function version from the START line, decrypted each token and checked its CRC.
   - What I found: 1,174 tokens parsed with all CRCs valid. For each function version, tokens from orders divisible by 5 give a consistent 2-byte chunk for each index 0 to 7. For version 8 the chunks are b6b0 8815 2485 2112 e5d4 22f7 5053 d324.
   - Thinking: a CRC that checks on every token tells me the decryption is right without needing the real secret to compare against.

5. Flag: confirm it is the signing key
   - What I did: checked the signer function source for which SSM parameter it signs with.
   - What I found: signer_function.py sets KEY_PARAM = "/gridlink/order-hmac-key" and uses it in hmac.new(key, body, sha256).
   - Thinking: the flag format asks for 32 lowercase hex characters, which is exactly the 16-byte key from the eight version-8 chunks written as hex.
   - Result: the joined key is the flag, CSCTF{b6b0881524852112e5d422f75053d324}.

Key insight: A poisoned Lambda layer shipped a hash-based, unchecked .pyc that did not match its clean .py, and it leaked SSM secrets 2 bytes at a time through the telemetry correlation field. Nothing in the function code changed, and each chunk was encrypted with a key derived from the request ID.
Defensive takeaways: Treat all four SSM secrets as compromised and rotate them, remove auth-utils layer versions 4, 6, 8 and 10, and note that $LATEST (version 10) is poisoned. A layer swap never changes the function's CodeSha256, so track layer versions too, and review the .pyc a layer ships, not just its .py.
Note: there is no solve.py or reproduction capture because the challenge input files are not in this repo.
