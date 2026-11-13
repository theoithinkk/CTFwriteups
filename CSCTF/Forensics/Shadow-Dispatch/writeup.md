Challenge: Shadow-Dispatch, Forensics / Hard / 592 pts / author: Marius Merai (CSCTF 2026)
Flag: CSCTF{b6b0881524852112e5d422f75053d324}
Category: Forensics (Lambda layer pyc analysis)
Tools used: unzip, Python (marshal, dis, hashlib, re), diff, manual review of Lambda function/layer/IAM/CloudWatch exports

Steps:
1. Start point: work out what changed
   - What I did / What I found: Listed the bundle and summarized function-versions.json for the authorizer function: every version's CodeSha256 and attached layers.
   - Result: The function code hash is identical across every version (and $LATEST). What differs between versions is the attached layers: auth-utils 1 to 10, plus observability-common and dispatch-runtime.
   - Thinking: Engineers report no unauthorized changes, and that matches the function code. If anything changed, it is inside the layers. I started with auth-utils because the authorizer imports its log helper and the odd telemetry comes from that path.

_(No reproduction capture: the challenge input files are not in this repo.)_

2. Pivot: diff the layers
   - What I did / What I found: Extracted all 10 auth-utils layer zips and diffed _authlog.py. The sources are byte-identical except for a # build comment. But the layer zip sizes differ, so compared the __pycache__/_authlog.cpython-312.pyc files.
   - Result: Versions 4, 6, 8 and 10 have a larger pyc (3571 or 3576 bytes versus 2788) that does not match the source. The pyc header flag is 1, a hash-based pyc with check_source unset, which means Python runs it without comparing it to _authlog.py.
   - Thinking: This is why a source review shows nothing. The .py is clean; the .pyc is what runs.


3. Pivot: disassemble the malicious pyc
   - What I did / What I found: Loaded the pyc with marshal and disassembled _beacon. Read the module constants for each bad version.
   - Result: On every order where order_id % _EVERY == 0, the code reads one of four SSM parameters (/gridlink/portal-session-secret, order-hmac-key, db-readonly-password, metrics-api-token), picks one with a constant _PICK, and emits a slice of the secret in the correlation= token of the telemetry log line. _PICK is 0 for v4, 2 for v6, 1 for v8 and 3 for v10. Otherwise it emits a hash of the file itself.
   - Thinking: Version 8 leaks _NAMES[1], the order-hmac-key, which is the key that signs load-shedding orders.


4. Pivot: decode the telemetry tokens
   - What I did / What I found: Worked out the token layout from the code: idx(1) | ct(2) | crc16(2) | salt(11), with ct = chunk XOR sha256(request_id + salt)[:2]. Parsed every telemetry order_id=... correlation=... line in the CloudWatch streams, took request ID and function version from the START line, decrypted each token and verified the CRC.
   - Result: 1,174 tokens parsed with all CRCs valid. For each function version, tokens from orders divisible by 5 give a consistent 2-byte chunk for each index 0 to 7. For version 8 the chunks are b6b0 8815 2485 2112 e5d4 22f7 5053 d324.
   - Thinking: A CRC that checks on every token tells me the decryption is right without needing the real secret to compare against.


5. Result: confirm it is the signing key and assemble the flag
   - What I did / What I found: Checked the signer function source for which SSM parameter it signs with.
   - Result: signer_function.py sets KEY_PARAM = "/gridlink/order-hmac-key" and uses it in hmac.new(key, body, sha256). Joining the eight version-8 chunks gives the 16-byte key as 32 hex characters.
   - Thinking: The flag format asks for 32 lowercase hex characters, which is exactly this key encoded as hex.


Key insight: Nothing in the function code changed. A poisoned Lambda layer shipped a hash-based, unchecked .pyc that did not match its .py source. It read SSM secrets and leaked them 2 bytes at a time through the telemetry "correlation" field, encrypted with a key derived from the request ID. Remediation: treat all four SSM secrets as compromised and rotate them, remove layer versions 4, 6, 8 and 10, and note that $LATEST (version 10) is poisoned.
