Challenge: Command Authority — offline clearance verifier
Flag: CSCTF{f96f4417c75121c3d27b039d}
Category: Reverse Engineering (archive forensics)
Tools used: unzip, Python byte inspection / Base64, strings, objdump
Brief: recover the restricted clearance value accepted by the offline verifier. The evidence packet command-authority-evidence.zip contains a personnel image (id_photo.jpg) and a password-protected archive (pass_bundle.zip).

Steps:
1. Inspect the JPEG for appended data.
   - What I found: the JPEG ends at its normal EOI marker (FF D9) before the physical end of file. Bytes after the
     marker contain the ASCII marker `ARCHIVE-KEY:` followed by the archive password. This is appended metadata, not
     visible image content.

     ![JPEG trailer reveals the archive key; pass_bundle.zip extracts](screenshots/01_unlock.png)

2. Unlock the nested archive.
   - What I did: use the recovered key to extract pass_bundle.zip. It contains pass.token and a stripped x86-64 ELF
     named field_verifier.

3. Inspect the verifier.
   - What I found: the program's usage string is `field_verifier <token_file_b64>`. Static strings reveal the
     accepted route distinction (RESTRICTED versus STANDARD-CORRIDOR) and the success message. The supplied token
     decodes to a standard-corridor civilian record, so it is not the restricted clearance.

4. Recover the restricted clearance constant.
   - What I did: inspect the verifier's embedded comparison data. The encoded byte sequence is XOR-obfuscated with
     0x41. XOR each byte with 0x41 to recover the exact 24-character clearance value: f96f4417c75121c3d27b039d. The
     required submission wraps that value in the challenge flag format.
   - Result: the XOR-0x41 scan of field_verifier recovers the 24-character restricted clearance and the flag
     CSCTF{f96f4417c75121c3d27b039d}.

     ![XOR-0x41 scan recovers the clearance and the flag](screenshots/02_clearance_flag.png)

Key insight: the JPEG's displayed pixels are not the whole file: data can be appended after the JPEG end marker. The nested archive then provides the verifier, while static analysis of its embedded comparison reveals the restricted clearance value.
Reproduce: python -I solve.py (reproduces the solve against the supplied artifacts; rerun to verify)
Note: the captures are of the real solve, reproduced by solve.py against the supplied artifacts. The personnel photo itself is intentionally not reproduced.
