#!/usr/bin/env python3
"""The Capability Ghost: recover the sealed marker from a runner fs archive + journal.
The tar carries a PAX xattr user.build_seal (the probe tag) on /usr/local/bin/hc-probe;
the journal carries X_SEAL_EPOCH. hc-probe's own help text documents the cipher:
  key = HMAC-SHA256(key=raw_bytes(tag_hex), msg=ascii_decimal(seal_epoch))
  out[i] = in[i] XOR key[i % 32]
usage: python3 solve.py capability-ghost.zip
Records are read as data only; nothing is executed and no capability is applied."""
import sys, re, zipfile, io, tarfile, hmac, hashlib

def solve(zip_path):
    z = zipfile.ZipFile(zip_path)
    tgz = z.read('runner-fs.tar.gz')
    journal = z.read('runner.journal')

    t = tarfile.open(fileobj=io.BytesIO(tgz))
    tag = sealed = None
    for m in t.getmembers():
        for k, v in (m.pax_headers or {}).items():
            if k.endswith('user.build_seal'):
                tag = v.encode('utf-8', 'surrogateescape')      # 8 raw tag bytes
        if m.name.endswith('signaling-cfg.sealed'):
            sealed = t.extractfile(m).read()

    # X_SEAL_EPOCH is a plain field in the journal's event records.
    epoch = re.search(rb'X_SEAL_EPOCH=(\d+)', journal).group(1)   # ascii decimal bytes

    print(f"probe tag (user.build_seal xattr): {tag.hex()}")
    print(f"seal epoch (journal X_SEAL_EPOCH): {epoch.decode()}")
    print(f"sealed bytes: {sealed.hex()}")

    key = hmac.new(tag, epoch, hashlib.sha256).digest()
    flag = bytes(c ^ key[i % 32] for i, c in enumerate(sealed)).decode()
    print("FLAG:", flag)
    return flag

if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "capability-ghost.zip")
