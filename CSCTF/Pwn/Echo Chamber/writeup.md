Challenge: Echo Chamber — Pwn / Hard / 540 pts / author: Iulian Schifirnet (CSCTF 2026)
Flag: CSCTF{Wy682FM0Dujh2fOOZ0uHXcWo}
Challenge name: echo_chamber  (Pwn / Hard / 540 pts, 190 solves, by Iulian Schifirnet)
Category: Pwn / binary exploitation (echo-oracle info leak -> hard ret2libc with only leave;ret)
Tools used: Python (stdlib: socket, struct), solve.py

Challenge (echo_chamber): Ash Army forward units abandoned a signals relay - an echo node that repeats every
transmission back to you, word for word, and nothing more. "The operators were careless about how much they
copy before they speak." Reach the node, make it repeat something it was never meant to be holding, and take
the process. Attachment: echo_chamber.tar.gz. Host: w01.ctf.chronos-security.ro:37605 (per-launch instance).
See screenshots/01_challenge_briefing.jpg.

The bug: chamber() reads 0x70 bytes into an 0x50 buffer, then echoes it with printf("echo: %s", buf). The read
overflows by 0x20 - exactly through the saved return address, so there is only room to pivot, not to drop a full
ROP chain in one shot. The %s echo stops at the first NUL, which makes it a byte-precise leak oracle.

Frame (buf = rbp-0x50):  canary @ buf+0x58, saved rbp @ buf+0x60, saved return @ buf+0x68.

The chain (two-stage, defeating canary + PIE + ASLR with no good gadgets):

1. Leak the canary.
   - The canary's least-significant byte is 0x00, which normally terminates the echo. Overwrite just that NUL
     with a non-zero byte; printf then runs on and prints the remaining 7 canary bytes. Prepend the 0x00 back
     to recover the full canary value. "Make it repeat something it was never meant to be holding" = this leak.

2. Leak the stack and the PIE base.
   - Extend the same trick to buf+0x60 and buf+0x68: the echo spills the saved rbp (a stack address) and the
     saved return into the PIE image. pie_base = leaked_return - 0x137e.

3. Leak libc (the pivot trick, because there are no gadgets but leave;ret).
   - The binary has nothing useful to ROP with except a leave;ret. So: overflow to set a fake rbp pointing into
     main's frame (main_rbp+0x68) and return into chamber's OWN echo printf at pie+0x1332. With rbp pointed
     there, the printf prints [main_rbp+8] = main's saved return, which lives in libc. libc_base = leak - 0x29d90.
   - Re-entering the echo printf also drops back into the read/echo loop, now reading into a known stack buffer
     B = main_rbp+8 whose exact address we hold.

4. Pop a shell.
   - Overflow B, use leave;ret to pivot rsp onto it, and run the only ROP we need:
       pop rdi ; ret  ->  "/bin/sh"  ->  system
     all resolved against the leaked libc base. Shell as the service user.
   - id -> uid=10001(ctf); /flag is a symlink to /tmp/flag:
       CSCTF{Wy682FM0Dujh2fOOZ0uHXcWo}

Reproduce: python solve.py w01.ctf.chronos-security.ro 37605
   (pure stdlib sockets: walks the echo oracle to leak canary/stack/PIE, pivots rbp into main and re-enters the
   echo printf to leak libc, then leave;ret-pivots into a known buffer and ROPs pop rdi;"/bin/sh";system.
   Offsets are constants at the top of the file - retune per binary build.)
   Note: the live instance is required; the CTF has ended, so the container no longer serves.

Key insight: a %s echo is a leak oracle whenever you can control where its NUL terminator falls - overwriting one
known zero byte turns "harmless echo" into an arbitrary adjacent-memory read, and repeating it peels the canary,
the stack cookie's neighbours, the PIE return and (via an rbp pivot back into the same printf) a libc pointer.
When the only gadget is leave;ret, you still win by pivoting rbp/rsp into a buffer whose address you just leaked
and ROPing from there in a second stage. A single 0x20-byte overflow is enough.

Defensive takeaways (pwn / secure-coding angle):
- Never reflect a buffer you just read into with %s unless the input length is bounded and NUL-terminated by you.
  An echo of attacker data past its intended end is an information-disclosure primitive, canary included.
- Bound the copy to the destination size (read at most sizeof(buf)-1 and NUL-terminate). The root cause here is
  reading 0x70 into an 0x50 buffer - classic "careless about how much they copy."
- Stack canaries, PIE and ASLR only raise the cost; they fall together once one reliable leak exists. Fuzz for
  over-reads, not just over-writes, and treat any length-controllable echo as a leak during review.
